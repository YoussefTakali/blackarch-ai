"""The orchestrator: plan a goal, run the agents, queue the operations.

It turns a user objective into a task plan (one step per agent), runs the
agents in dependency order while feeding shared context forward, maps each
agent's recommended steps to registered operations, and routes those:

* passive/low, in scope, fully specified  → run now (in "auto-safe" mode);
* intrusive/high-impact                    → the approval queue (pending);
* out of scope / above ceiling             → blocked;
* missing a required parameter             → needs_params (advisory).

The user reviews the queue and approves or rejects each operation; approving
runs it through the execution engine. The orchestrator never bypasses scope or
the approval requirement — it only automates the safe, already-authorized part.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Literal

from blackarch_ai.agents.bus import MessageBus
from blackarch_ai.agents.consult import Consultation, consult
from blackarch_ai.agents.directory import AgentDirectory
from blackarch_ai.core.context import ContextStore
from blackarch_ai.execution.engine import ExecutionEngine, ExecutionError
from blackarch_ai.execution.operations import OperationError, ValidationError
from blackarch_ai.llm.gateway import GatewayError, ModelGateway
from blackarch_ai.llm.rewriter import COMPLIANCE_CONTEXT, rewrite
from blackarch_ai.orchestrator.plan import PlanOutput, validate_plan
from blackarch_ai.security.permissions import Permission
from blackarch_ai.security.scope import Scope
from blackarch_ai.storage.models import Engagement, Plan, ProposedOperation, utcnow
from blackarch_ai.tools.registry import Registry

Mode = Literal["auto_safe", "auto_intrusive", "auto_all", "manual", "plan_only"]


def _auto_runs(mode: Mode, permission: str) -> bool:
    """Whether an in-scope operation at this level runs automatically in `mode`."""
    p = Permission(permission)
    if mode == "auto_safe":
        return not p.needs_approval               # passive, low
    if mode == "auto_intrusive":
        return p.rank < Permission.HIGH_IMPACT.rank  # passive, low, intrusive
    if mode == "auto_all":
        return True                               # everything, incl. high_impact
    return False                                  # manual / plan_only: queue all

ORCH_PLAN_PROMPT = """\
You are the orchestrator of BlackArch AI, planning an AUTHORIZED security \
assessment. Break the user's objective into a focused task plan: one step per \
specialist agent, in a sensible order, with dependencies where a step needs an \
earlier step's results.

Rules:
- Use only these agents (id: domain): {agents}
- Each step: the agent id, a concrete objective for that agent, and depends_on \
(1-based indices of earlier steps it relies on).
- Keep it to 2–6 steps. Start with passive/low reconnaissance; put intrusive \
work later and make it depend on the recon. Do not plan anything outside scope.
- Do not invent targets. Plan only within the authorized scope.
- """ + COMPLIANCE_CONTEXT + """

{engagement}"""


@dataclass
class ProposedOpResult:
    id: int
    operation: str
    target: str | None
    permission: str
    status: str
    note: str
    source_agent: str
    execution_id: int | None = None


@dataclass
class OrchestrationResult:
    plan_id: int
    consultations: list[Consultation] = field(default_factory=list)
    proposed: list[ProposedOpResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def by_status(self, status: str) -> list[ProposedOpResult]:
        return [p for p in self.proposed if p.status == status]


class Orchestrator:
    def __init__(
        self,
        *,
        directory: AgentDirectory,
        engine: ExecutionEngine,
        bus: MessageBus,
        gateway: ModelGateway,
        registry: Registry,
        engagement: Engagement | None,
        scope: Scope | None,
    ) -> None:
        self.directory = directory
        self.engine = engine
        self.bus = bus
        self.gateway = gateway
        self.registry = registry
        self.engagement = engagement
        self.scope = scope
        self.store = engine.store
        self.catalogue = engine.catalogue
        self.context = ContextStore(self.store, engagement.id if engagement else None)

    # ------------------------------------------------------------ planning

    def _engagement_block(self) -> str:
        if self.engagement is None or self.scope is None:
            return ("No engagement selected: produce methodology only and do not plan "
                    "steps against specific targets.")
        return (f"Engagement: {self.engagement.name}\n"
                f"Objective: {self.engagement.objective or '(not stated)'}\n"
                f"Authorized scope — {self.scope.summary()}")

    async def make_plan(self, objective: str) -> tuple[Plan, PlanOutput, list[str]]:
        roster = "\n".join(f"- {a.id}: {a.description} (ceiling {a.max_permission.value})"
                           for a in self.directory.all())
        system = ORCH_PLAN_PROMPT.format(agents=roster, engagement=self._engagement_block())
        result = await self.gateway.complete(
            [{"role": "system", "content": system},
             {"role": "user", "content": f"Objective: {rewrite(objective)}"}],
            role="orchestrator", response_model=PlanOutput,
        )
        plan_out: PlanOutput = result.parsed
        warnings = validate_plan(plan_out, set(self.directory.ids()))
        row = Plan(engagement_id=self.engagement.id if self.engagement else None,
                   objective=objective, summary=plan_out.summary,
                   steps=[s.model_dump() for s in plan_out.steps], model=result.model)
        with self.store.session() as s, s.begin():
            s.add(row)
        self.store.audit("orchestrator", "plan.create",
                         {"plan": row.id, "steps": len(plan_out.steps), "objective": objective},
                         engagement_id=row.engagement_id)
        return row, plan_out, warnings

    # ------------------------------------------------------------ step → operation

    def _candidate_operation(self, tool: str, permission: Permission):
        """Pick the registered operation that best matches an agent's tool + level."""
        pkg = tool
        rec = self.registry.get(tool)
        if rec is not None:
            pkg = rec.name
        candidates = self.catalogue.for_tool(pkg)
        if not candidates:
            return None
        # Prefer the same permission, else the highest level not exceeding the step's.
        exact = [o for o in candidates if o.permission == permission]
        if exact:
            return exact[0]
        under = [o for o in candidates if not o.permission.exceeds(permission)]
        if under:
            return max(under, key=lambda o: o.permission.rank)
        return min(candidates, key=lambda o: o.permission.rank)

    def _propose(self, step, source_agent: str, plan_id: int,
                 source_task_id: int | None) -> ProposedOperation | None:
        if not step.tool:
            return None
        op = self._candidate_operation(step.tool, step.permission)
        row = ProposedOperation(
            engagement_id=self.engagement.id if self.engagement else None, plan_id=plan_id,
            source_agent=source_agent, source_task_id=source_task_id,
            target=step.target, params={}, rationale=step.purpose[:500],
        )
        if op is None:
            row.operation = step.tool
            row.permission = step.permission.value
            row.status = "needs_params"
            row.note = f"no registered operation for {step.tool!r}; run manually or add one"
            self._save_proposal(row)
            return row
        row.operation = op.id
        try:
            plan = self.engine.plan(op.id, {}, step.target,
                                    engagement_id=row.engagement_id, scope=self.scope)
        except (OperationError, ValidationError) as exc:
            row.permission = op.permission.value
            row.status = "needs_params"
            row.note = str(exc)[:300]
            self._save_proposal(row)
            return row
        row.permission = plan.permission.value
        row.argv = plan.argv
        if plan.blocked:
            row.status = "blocked"
            row.note = plan.block_reason
        else:
            row.status = "pending"
        self._save_proposal(row)
        return row

    def _save_proposal(self, row: ProposedOperation) -> None:
        with self.store.session() as s, s.begin():
            s.add(row)

    def _dedupe_key(self, row: ProposedOperation) -> tuple:
        return (row.operation, row.target, tuple(sorted(row.params.items())))

    # ------------------------------------------------------------ running the plan

    async def run(
        self,
        plan_row: Plan,
        plan_out: PlanOutput,
        *,
        mode: Mode = "auto_safe",
        follow_help: bool = False,
        on_event: Callable[[str], None] | None = None,
    ) -> OrchestrationResult:
        note = on_event or (lambda _m: None)
        result = OrchestrationResult(plan_id=plan_row.id)
        self._set_status(plan_row.id, "running")
        seen: set[tuple] = set()

        for i, step in enumerate(plan_out.steps, 1):
            agent = step.agent_id
            note(f"step {i}/{len(plan_out.steps)}: {agent} — {step.objective[:60]}")
            digest = self.context.digest()
            task = step.objective + (f"\n\n{digest}" if digest else "")
            try:
                c = await consult(self.directory, self.bus, agent, task,
                                  engagement=self.engagement, scope=self.scope,
                                  requested_by="orchestrator", follow_help=follow_help)
            except GatewayError as exc:
                result.warnings.append(f"step {i} ({agent}) failed: {exc}")
                continue
            result.consultations.append(c)
            if not c.ok:
                result.warnings.append(f"step {i} ({agent}) failed: {c.error}")
                continue

            self._record_findings(c, plan_row.id)
            for rec in c.report.steps:
                if rec.blocked or not rec.tool:
                    continue
                row = self._propose(rec, agent, plan_row.id, c.task_id)
                if row is None:
                    continue
                key = self._dedupe_key(row)
                if key in seen:
                    continue
                seen.add(key)
                if row.status == "pending" and _auto_runs(mode, row.permission):
                    await self._auto_run(row, note)
                # Re-read: _auto_run updated the row in a separate session.
                result.proposed.append(self._summary(self.get_proposal(row.id)))

        self._set_status(plan_row.id, "done")
        self.store.audit("orchestrator", "plan.done",
                         {"plan": plan_row.id,
                          "proposed": len(result.proposed),
                          "executed": len(result.by_status("executed"))},
                         engagement_id=plan_row.engagement_id)
        return result

    def _record_findings(self, c: Consultation, plan_id: int) -> None:
        for h in c.report.hypotheses:
            self.context.add_finding(h.statement, description=h.basis, confidence=h.confidence,
                                     agent=c.agent_id, plan_id=plan_id, source_task_id=c.task_id)
        for rec in c.report.steps:
            if rec.target and rec.scope_status == "in_scope":
                kind = "url" if "://" in rec.target else ("network" if "/" in rec.target else "host")
                self.context.add_asset(kind, rec.target, source=c.agent_id)

    async def _auto_run(self, row: ProposedOperation, note: Callable[[str], None]) -> None:
        note(f"auto-running {row.operation} on {row.target} ({row.permission})")
        try:
            plan = self.engine.plan(row.operation, row.params, row.target,
                                    engagement_id=row.engagement_id, scope=self.scope)
            res = await self.engine.run(plan, requested_by="orchestrator")
        except (ExecutionError, OperationError, ValidationError) as exc:
            self._update(row.id, status="blocked", note=str(exc)[:300])
            return
        self._update(row.id, status="executed", execution_id=res.execution_id,
                     decided_by="auto")
        self.context.add_finding(
            f"{row.operation} on {row.target}: {res.status} (exit {res.exit_code})",
            description=res.stdout[:400], severity="info", confidence="high",
            verified=True, agent="orchestrator", plan_id=row.plan_id)

    # ------------------------------------------------------------ approval queue

    def pending(self, plan_id: int | None = None) -> list[ProposedOperation]:
        from sqlalchemy import select

        with self.store.session() as s:
            q = select(ProposedOperation).where(ProposedOperation.status == "pending")
            if self.engagement is not None:
                q = q.where(ProposedOperation.engagement_id == self.engagement.id)
            if plan_id is not None:
                q = q.where(ProposedOperation.plan_id == plan_id)
            return list(s.scalars(q.order_by(ProposedOperation.id)).all())

    def get_proposal(self, op_id: int) -> ProposedOperation | None:
        with self.store.session() as s:
            return s.get(ProposedOperation, op_id)

    async def approve(self, op_id: int, *, decided_by: str = "user"):
        row = self.get_proposal(op_id)
        if row is None:
            raise ExecutionError(f"no proposed operation #{op_id}")
        if row.status not in ("pending",):
            raise ExecutionError(f"operation #{op_id} is {row.status}, not pending")
        plan = self.engine.plan(row.operation, row.params, row.target,
                                engagement_id=row.engagement_id, scope=self.scope)
        if plan.blocked:
            self._update(op_id, status="blocked", note=plan.block_reason)
            raise ExecutionError(plan.block_reason)
        approval = self.engine.record_approval(plan, "approved", decided_by=decided_by,
                                               reason=f"proposed #{op_id}")
        res = await self.engine.run(plan, requested_by=decided_by, approval=approval)
        self._update(op_id, status="executed", execution_id=res.execution_id,
                     decided_by=decided_by)
        if self.engagement is not None:
            self.context.add_finding(
                f"{row.operation} on {row.target}: {res.status} (exit {res.exit_code})",
                description=res.stdout[:400], confidence="high", verified=True,
                agent="orchestrator", plan_id=row.plan_id)
        return res

    def reject(self, op_id: int, *, decided_by: str = "user") -> ProposedOperation:
        row = self.get_proposal(op_id)
        if row is None:
            raise ExecutionError(f"no proposed operation #{op_id}")
        self._update(op_id, status="rejected", decided_by=decided_by)
        self.engine.store.audit(decided_by, "proposal.reject",
                                {"proposed": op_id, "operation": row.operation},
                                engagement_id=row.engagement_id)
        return self.get_proposal(op_id)

    # ------------------------------------------------------------ helpers

    def _summary(self, row: ProposedOperation) -> ProposedOpResult:
        return ProposedOpResult(id=row.id, operation=row.operation, target=row.target,
                                permission=row.permission, status=row.status, note=row.note,
                                source_agent=row.source_agent, execution_id=row.execution_id)

    def _set_status(self, plan_id: int, status: str) -> None:
        with self.store.session() as s, s.begin():
            p = s.get(Plan, plan_id)
            p.status = status
            if status in ("done", "failed"):
                p.finished_at = utcnow()

    def _update(self, op_id: int, **fields) -> None:
        with self.store.session() as s, s.begin():
            row = s.get(ProposedOperation, op_id)
            for k, v in fields.items():
                setattr(row, k, v)
