"""The execution engine: the only path from an operation to a running process.

Flow (spec section 8):
  request → input validation → scope validation → permission check →
  user approval → execution → output capture → evidence storage → audit

Guarantees:
* commands run via ``asyncio.create_subprocess_exec`` with an argv list and
  ``stdin`` closed — never a shell, so values cannot inject commands;
* the executable is resolved to an absolute path from the installed registry;
* a target must be inside the engagement scope;
* intrusive and high-impact operations do not run without an approval record;
* output is byte-capped, the process is time-limited, and it runs in its own
  session so the whole process group can be killed (cancel / emergency stop);
* every run is persisted with its evidence and written to the audit log.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path

from blackarch_ai.config import Settings, data_dir
from blackarch_ai.execution.operations import (
    Operation,
    OperationCatalogue,
    ValidationError,
)
from blackarch_ai.security.permissions import Permission, highest
from blackarch_ai.security.scope import Scope
from blackarch_ai.storage.models import Approval, Evidence, ToolExecution, utcnow
from blackarch_ai.storage.store import Store
from blackarch_ai.tools.registry import Registry

MAX_OUTPUT_BYTES = 5 * 1024 * 1024
_SECRETISH = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD")


class ExecutionError(RuntimeError):
    pass


class NotApproved(ExecutionError):
    pass


@dataclass
class ExecutionPlan:
    operation: Operation
    exe_path: str
    argv: list[str]
    target: str | None
    permission: Permission
    scope_status: str          # in_scope | out_of_scope | no_engagement | none
    scope_reason: str
    blocked: bool
    block_reason: str
    engagement_id: int | None

    @property
    def needs_approval(self) -> bool:
        return self.permission.needs_approval

    @property
    def command_line(self) -> str:
        """Human-readable preview (display only; not used to execute)."""
        return " ".join(_shquote(a) for a in self.argv)


@dataclass
class ExecutionResult:
    execution_id: int
    status: str                # success | failed | timeout | cancelled | error
    exit_code: int | None
    duration_s: float
    stdout: str
    stderr: str
    truncated: bool
    evidence: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "success"


def _shquote(arg: str) -> str:
    return arg if arg and all(c.isalnum() or c in "-_./:=,@%+" for c in arg) else repr(arg)


def _clean_env() -> dict[str, str]:
    """Drop secret-looking variables so a spawned tool can't read API keys."""
    return {k: v for k, v in os.environ.items()
            if not any(s in k.upper() for s in _SECRETISH)}


class ExecutionEngine:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        registry: Registry,
        catalogue: OperationCatalogue,
        *,
        evidence_root: Path | None = None,
        max_concurrent: int = 3,
    ) -> None:
        self.settings = settings
        self.store = store
        self.registry = registry
        self.catalogue = catalogue
        self.evidence_root = evidence_root or (data_dir() / "evidence")
        self._sem = asyncio.Semaphore(max_concurrent)
        self._running: dict[int, asyncio.subprocess.Process] = {}

    # ------------------------------------------------------------ planning

    def _resolve_exe(self, op: Operation) -> str:
        if op.host:
            # Runs on the host via `flatpak-spawn --host`; the host resolves the
            # binary on its own PATH, so don't require it in the toolbox registry.
            return op.exe_name
        tool = self.registry.get(op.tool)
        if tool is None:
            # An op flagged `unpackaged` (e.g. a pip/pipx-installed tool like
            # mitmproxy that pacman doesn't know) resolves straight off the PATH.
            if op.unpackaged:
                found = shutil.which(op.exe_name)
                if found:
                    return found
            raise ExecutionError(
                f"{op.tool!r} is not installed (operation {op.id!r}); run `tools scan`")
        wanted = op.exe_name
        for path in tool.executables:
            if path.rsplit("/", 1)[-1] == wanted:
                return path
        found = shutil.which(wanted)
        if found:
            return found
        raise ExecutionError(f"executable {wanted!r} for operation {op.id!r} not found")

    def plan(
        self,
        op_id: str,
        params: dict[str, object],
        target: str | None,
        *,
        engagement_id: int | None,
        scope: Scope | None,
    ) -> ExecutionPlan:
        op = self.catalogue.get(op_id)
        exe = self._resolve_exe(op)
        argv = op.render_argv(exe, params, target)  # raises ValidationError on bad input

        # Operation permission, raised to high_impact if the tool itself is.
        permission = op.permission
        tool = self.registry.get(op.tool)
        if tool is not None and tool.permission == "high_impact":
            permission = highest(permission, Permission.HIGH_IMPACT)

        scope_status, scope_reason, blocked, block_reason = "none", "", False, ""
        if target and (op.target is not None):
            if scope is None:
                scope_status, blocked = "no_engagement", True
                block_reason = "no engagement scope; create/select one to run against a target"
            else:
                ok, reason = scope.check(target)
                scope_status = "in_scope" if ok else "out_of_scope"
                scope_reason = reason
                if not ok:
                    blocked, block_reason = True, f"target out of scope: {reason}"
        elif op.needs_target and not target:
            blocked, block_reason = True, "this operation requires a --target"

        return ExecutionPlan(
            operation=op, exe_path=exe, argv=argv, target=target, permission=permission,
            scope_status=scope_status, scope_reason=scope_reason, blocked=blocked,
            block_reason=block_reason, engagement_id=engagement_id,
        )

    # ------------------------------------------------------------ approval

    def record_approval(self, plan: ExecutionPlan, decision: str, *, decided_by: str = "user",
                        reason: str = "") -> Approval:
        appr = Approval(engagement_id=plan.engagement_id, operation=plan.operation.id,
                        argv=plan.argv, target=plan.target, permission=plan.permission.value,
                        decision=decision, decided_by=decided_by, reason=reason)
        with self.store.session() as s, s.begin():
            s.add(appr)
        self.store.audit(decided_by, f"approval.{decision}",
                         {"operation": plan.operation.id, "target": plan.target,
                          "permission": plan.permission.value, "reason": reason},
                         engagement_id=plan.engagement_id)
        return appr

    # ------------------------------------------------------------ execution

    async def run(
        self,
        plan: ExecutionPlan,
        *,
        requested_by: str = "user",
        approval: Approval | None = None,
    ) -> ExecutionResult:
        if plan.blocked:
            raise ExecutionError(plan.block_reason)
        if plan.needs_approval and (approval is None or approval.decision != "approved"):
            raise NotApproved(
                f"operation {plan.operation.id!r} is {plan.permission.value} and needs "
                "an approved decision before it can run")

        execution = ToolExecution(
            engagement_id=plan.engagement_id,
            approval_id=approval.id if approval else None, requested_by=requested_by,
            operation=plan.operation.id, tool=plan.operation.tool, argv=plan.argv,
            target=plan.target, permission=plan.permission.value, status="running",
        )
        with self.store.session() as s, s.begin():
            s.add(execution)
        exec_id = execution.id
        self.store.audit(requested_by, "exec.start",
                         {"id": exec_id, "operation": plan.operation.id, "argv": plan.argv,
                          "target": plan.target, "permission": plan.permission.value},
                         engagement_id=plan.engagement_id)

        work = self._work_dir(plan.engagement_id, exec_id)
        async with self._sem:
            result = await self._execute(plan, exec_id, work)

        self._persist(exec_id, plan, result, work)
        self.store.audit(requested_by, f"exec.{result.status}",
                         {"id": exec_id, "exit_code": result.exit_code,
                          "seconds": round(result.duration_s, 1)},
                         engagement_id=plan.engagement_id)
        return result

    def _work_dir(self, engagement_id: int | None, exec_id: int) -> Path:
        root = self.evidence_root / (f"engagement-{engagement_id}" if engagement_id else "adhoc")
        work = root / f"exec-{exec_id}"
        work.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        os.chmod(work, 0o700)
        return work

    async def _execute(self, plan: ExecutionPlan, exec_id: int, work: Path) -> ExecutionResult:
        started = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *plan.argv, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                cwd=str(work), env=_clean_env(), start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            return ExecutionResult(exec_id, "error", None, time.monotonic() - started,
                                   "", "", False, error=f"could not start: {exc}")

        self._running[exec_id] = proc
        out = bytearray()
        err = bytearray()
        truncated = False
        try:
            async with asyncio.timeout(plan.operation.timeout):
                t1, t2 = (asyncio.create_task(_read_capped(proc.stdout, out)),
                          asyncio.create_task(_read_capped(proc.stderr, err)))
                truncated = any(await asyncio.gather(t1, t2))
                await proc.wait()
            status = "success" if proc.returncode == 0 else "failed"
            code = proc.returncode
        except TimeoutError:
            await self._terminate(proc)
            status, code = "timeout", None
        except asyncio.CancelledError:
            await self._terminate(proc)
            self._store_output(work, out, err)
            self._running.pop(exec_id, None)
            raise
        finally:
            self._running.pop(exec_id, None)

        return ExecutionResult(
            exec_id, status, code, time.monotonic() - started,
            out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), truncated,
        )

    async def _terminate(self, proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except TimeoutError:
                os.killpg(pgid, signal.SIGKILL)
                await proc.wait()
        except (ProcessLookupError, PermissionError):
            pass

    async def stop_all(self) -> int:
        """Emergency stop: terminate every running process. Returns how many."""
        procs = list(self._running.items())
        for _, proc in procs:
            await self._terminate(proc)
        self.store.audit("user", "exec.emergency_stop", {"count": len(procs)})
        return len(procs)

    @property
    def running_ids(self) -> list[int]:
        return list(self._running)

    # ------------------------------------------------------------ persistence

    def _store_output(self, work: Path, out: bytearray, err: bytearray) -> list[tuple[str, Path, int, str]]:
        files = []
        for kind, data in (("stdout", out), ("stderr", err)):
            path = work / f"{kind}.txt"
            path.write_bytes(bytes(data))
            os.chmod(path, 0o600)
            files.append((kind, path, len(data), hashlib.sha256(bytes(data)).hexdigest()))
        return files

    def _persist(self, exec_id: int, plan: ExecutionPlan, result: ExecutionResult,
                 work: Path) -> None:
        raw = self._store_output(work, bytearray(result.stdout.encode("utf-8", "replace")),
                                 bytearray(result.stderr.encode("utf-8", "replace")))
        with self.store.session() as s, s.begin():
            ex = s.get(ToolExecution, exec_id)
            ex.status = result.status
            ex.exit_code = result.exit_code
            ex.duration_s = result.duration_s
            ex.stdout_bytes = raw[0][2]
            ex.stderr_bytes = raw[1][2]
            ex.truncated = result.truncated
            ex.error = result.error
            ex.finished_at = utcnow()
            for kind, path, size, digest in raw:
                s.add(Evidence(execution_id=exec_id, engagement_id=plan.engagement_id,
                               kind=kind, path=str(path), size_bytes=size, sha256=digest))
        result.evidence = [str(p) for _, p, _, _ in raw]


async def _read_capped(stream: asyncio.StreamReader | None, buf: bytearray) -> bool:
    """Read into `buf` up to MAX_OUTPUT_BYTES. Returns True if truncated."""
    if stream is None:
        return False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return False
        if len(buf) + len(chunk) > MAX_OUTPUT_BYTES:
            buf.extend(chunk[: MAX_OUTPUT_BYTES - len(buf)])
            return True
        buf.extend(chunk)
