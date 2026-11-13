"""Deterministic recon: run the standard discovery chain directly via the engine.

This does not depend on the LLM emitting runnable steps. Given an engagement
scope it runs, in order:

  1. host discovery (nmap-ping-sweep) on each in-scope network,
  2. service/version scan (nmap-service-scan) on each live, in-scope host,
  3. follow-ups driven by the open ports found: httpx-probe on web ports,
     enum4linux-ng on SMB ports.

Everything it finds is written to the engagement context (assets + verified
findings) so `report` can assemble it. Operations run under the same scope and
permission rules as any other execution; intrusive steps are auto-approved here
because the caller already chose the deterministic (auto) path.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from blackarch_ai.core.context import ContextStore
from blackarch_ai.execution.engine import ExecutionEngine, ExecutionError, NotApproved
from blackarch_ai.execution.operations import OperationError, ValidationError
from blackarch_ai.security.scope import Scope
from blackarch_ai.storage.models import Engagement

_HOST_RE = re.compile(r"Nmap scan report for (?:[^\s(]+ \()?(\d+\.\d+\.\d+\.\d+)\)?")
_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.MULTILINE)

WEB_PORTS = {80, 8080, 8000, 8888}
TLS_PORTS = {443, 8443}
SMB_PORTS = {139, 445}


class ReconRunner:
    def __init__(
        self,
        engine: ExecutionEngine,
        scope: Scope | None,
        engagement: Engagement | None,
        *,
        on_event: Callable[[str], None] | None = None,
    ) -> None:
        self.engine = engine
        self.scope = scope
        self.engagement = engagement
        self.eng_id = engagement.id if engagement else None
        self.context = ContextStore(engine.store, self.eng_id)
        self.note = on_event or (lambda _m: None)
        self.executions: list[int] = []

    async def _run(self, op_id: str, target: str, params: dict | None = None):
        try:
            plan = self.engine.plan(op_id, params or {}, target,
                                    engagement_id=self.eng_id, scope=self.scope)
        except (OperationError, ValidationError, ExecutionError) as exc:
            self.note(f"skip {op_id} on {target}: {exc}")
            return None
        if plan.blocked:
            self.note(f"blocked {op_id} on {target}: {plan.block_reason}")
            return None
        approval = None
        if plan.needs_approval:
            approval = self.engine.record_approval(
                plan, "approved", decided_by="auto-recon", reason="deterministic recon")
        try:
            res = await self.engine.run(plan, requested_by="recon", approval=approval)
        except (ExecutionError, NotApproved) as exc:
            self.note(f"failed {op_id} on {target}: {exc}")
            return None
        self.executions.append(res.execution_id)
        return res

    async def discover_hosts(self) -> list[str]:
        if self.scope is None:
            return []
        nets = [e.raw for e in self.scope.include if e.kind in ("network", "host")]
        hosts: set[str] = set()
        for net in nets:
            sweep = net
            # A wide network (/16, /8 …) is 65k+ addresses and sweeps for many
            # minutes; narrow to the host's own /24 segment, where the devices
            # on a directly-connected LAN actually live. Found hosts are still
            # scope-checked, so this never scans outside the engagement.
            if "/" in net:
                try:
                    if int(net.split("/")[1]) < 24:
                        from blackarch_ai.cli.auto_engage import host_slash24_in
                        narrowed = host_slash24_in(net)
                        if narrowed:
                            sweep = narrowed
                            self.note(f"  narrowed {net} → {sweep} (local segment)")
                except (ValueError, IndexError):
                    pass
            self.note(f"host discovery on {sweep}")
            res = await self._run("nmap-ping-sweep", sweep)
            if res and res.ok:
                found = set(_HOST_RE.findall(res.stdout))
                in_scope = {h for h in found if self.scope.check(h)[0]}
                hosts |= in_scope
                self.note(f"  {len(in_scope)} live host(s) in scope on {net}")
        for h in sorted(hosts, key=_ip_key):
            self.context.add_asset("host", h, source="recon")
            self.context.add_finding(f"host {h} is up", severity="info",
                                     confidence="high", verified=True, agent="recon")
        return sorted(hosts, key=_ip_key)

    async def scan_host(self, host: str) -> None:
        res = await self._run("nmap-service-scan", host, {"ports": "1-1000"})
        if not res or not res.ok:
            return
        ports = _PORT_RE.findall(res.stdout)
        if not ports:
            return
        svc = ", ".join(f"{p}/{s}" for p, s in ports)
        self.context.add_finding(f"{host}: open ports — {svc}", description=res.stdout[:800],
                                 severity="info", confidence="high", verified=True,
                                 agent="network")
        nums = {int(p) for p, _ in ports}
        for scheme, group in (("http", WEB_PORTS), ("https", TLS_PORTS)):
            if nums & group:
                r = await self._run("httpx-probe", f"{scheme}://{host}")
                if r and r.ok and r.stdout.strip():
                    self.context.add_finding(f"{host}: web service ({scheme})",
                                             description=r.stdout[:500], severity="info",
                                             confidence="high", verified=True, agent="web")
        if nums & SMB_PORTS:
            r = await self._run("enum4linux-ng", host)
            if r and r.ok:
                self.context.add_finding(f"{host}: SMB/RPC enumeration",
                                         description=r.stdout[:800], severity="info",
                                         confidence="high", verified=True, agent="smb")

    async def run(self, *, max_hosts: int = 25) -> list[str]:
        self.note("deterministic recon: host discovery → service scan → web/SMB follow-ups")
        hosts = await self.discover_hosts()
        if not hosts:
            self.note("no live hosts found in scope")
            return []
        scanned = hosts[:max_hosts]
        if len(hosts) > max_hosts:
            self.note(f"{len(hosts)} hosts up; scanning the first {max_hosts} "
                      "(raise with max_hosts)")
        for i, h in enumerate(scanned, 1):
            self.note(f"service scan {h} ({i}/{len(scanned)})")
            await self.scan_host(h)
        self.note(f"recon done: {len(hosts)} host(s) up, {len(scanned)} scanned, "
                  f"{len(self.executions)} operation(s) run")
        return hosts


def _ip_key(ip: str) -> tuple:
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (0,)
