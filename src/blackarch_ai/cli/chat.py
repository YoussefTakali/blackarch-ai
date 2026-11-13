"""Interactive orchestrator chat."""

from __future__ import annotations

import asyncio
import contextlib
import re
import signal
import sys
import time

from pydantic import BaseModel, Field
from rich.box import ROUNDED
from rich.console import Group
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

# Visual theme — a single accent so panels, prompt and markers read as one UI.
ACCENT = "red"
MUTED = "grey50"
DOT = "●"

from blackarch_ai import __version__
from blackarch_ai.cli.common import Context, console, fmt_cost, fmt_tokens, fmt_totals, not_yet
from blackarch_ai.cli.views import agents_table, models_table, providers_table
from blackarch_ai.core.conversation import Conversation
from blackarch_ai.llm.gateway import GatewayError, LLMResult, ModelGateway, StreamInterrupted
from blackarch_ai.storage.models import Engagement
from blackarch_ai.storage.store import StoreError

# command -> (description, available now?)
COMMANDS: dict[str, tuple[str, bool]] = {
    "/help": ("Show this help", True),
    "/agents": ("Agents and the BlackArch categories they own", True),
    "/ask <agent> <task>": ("Give a specialist agent a task (e.g. /ask web review login flow)", True),
    "/models": ("Model routing, fallbacks and provider keys", True),
    "/scope": ("Authorized scope of the current engagement", True),
    "/status": ("Session, engagement, model and token/cost totals", True),
    "/history [n]": ("Show the last n messages of this session (default 20)", True),
    "/sessions": ("Recent chat sessions (resume with --resume ID)", True),
    "/clear": ("Clear the screen", True),
    "/exit": ("Leave (also /quit or Ctrl+D)", True),
    "/tools [text]": ("Per-agent tool counts, or search installed tools by purpose", True),
    "/ops [tool]": ("List registered operations the engine can run", True),
    "/run <op> [-t target] [k=v]": ("Run an operation (asks approval if intrusive)", True),
    "/stop": ("Emergency stop: kill every running operation", True),
    "/plan <objective>": ("Orchestrate: plan a goal, run agents, queue operations", True),
    "/recon": ("Deterministic sweep of the engagement scope (discovery→scan→enum), no LLM", True),
    "/assess": ("Full auto assessment: discover → scan → test logins for default creds (asks)", True),
    "/sniff": ("Capture traffic: passive, see what a device talks to, or MITM (asks which)", True),
    "/attack": ("Run an attack on a device (password brute-force) — asks which, approval-gated", True),
    "/decrypt": ("Decrypt a device's HTTPS via mitmproxy (own devices; non-pinned apps)", True),
    "/auto [on|off]": ("Auto-run objectives you type (intrusive auto, high-impact asks)", True),
    "/queue": ("Show operations awaiting approval", True),
    "/approve <id>": ("Approve and run a queued operation", True),
    "/reject <id>": ("Reject a queued operation", True),
    "/report [md|html|json]": ("Write an engagement report (md/html/json)", True),
}

_PENDING: dict[str, tuple[str, str]] = {}


_PERM = {"passive": "green", "low": "cyan", "intrusive": "yellow", "high_impact": "bold red"}

# Objective vs. question classification for auto-trigger.
_QUESTION_RE = re.compile(
    r"^\s*(?:what|why|how|when|who|which|where|is|are|was|were|do|does|did|can|could|"
    r"would|should|will|explain|describe|define|tell\s+me|remind|help)\b",
    re.IGNORECASE,
)
_ACTION_RE = re.compile(
    r"\b(?:scan|hack|enumerate|enum|discover|map|probe|assess|audit|pentest|"
    r"exploit|attack|brute[\s-]*force|crack|recon|sweep|fingerprint|compromise|"
    r"capture|extract|dump|spray|owasp|pwn|find|"
    r"test\s+(?:the|all|for)|check\s+(?:for|the)|look\s+for|go\s+after)\b",
    re.IGNORECASE,
)
# Packet-sniffing intent → interactive sniff menu (passive capture / MITM).
_SNIFF_RE = re.compile(
    r"\b(?:sniff(?:ing|er|s)?|eavesdrop\w*|wireshark|tcpdump|"
    r"packet[\s-]*captur\w*|captur\w*\s+packets|"
    r"m\.?i\.?t\.?m\.?|man[\s-]in[\s-]the[\s-]middle|arp[\s-]?spoof\w*|"
    r"intercept\w*\s+(?:the\s+|their\s+|its\s+|network\s+)?traffic|"
    r"see\s+(?:their|the|its|everyone'?s?)\s+traffic|listen\s+to\s+traffic)\b",
    re.IGNORECASE,
)
# Brute-force / password-attack intent → interactive attack menu.
_ATTACK_RE = re.compile(
    r"\b(?:brute[\s-]*forc\w*|bruteforce|crack\w*\s+(?:the\s+)?password|"
    r"password\s+(?:attack|guess\w*|spray\w*)|guess\s+(?:the\s+)?password|"
    r"dictionary\s+attack)\b",
    re.IGNORECASE,
)
# Offensive intent ("hack/pwn/get credentials") — with a network scope this
# triggers the deterministic full assessment (recon → credential checks).
_PWN_RE = re.compile(
    r"\b(?:hack\w*|pwn\w*|compromise\w*|breach\w*|break[\s-]*in\w*|take[\s-]*over|"
    r"own\s+(?:them|everyone|all)|get\s+(?:in|into|access|credential|password)|"
    r"credential\w*|passwords?|exploit\w*)\b",
    re.IGNORECASE,
)
# Network-wide discovery intent → deterministic recon (real scans, no LLM).
_RECON_RE = re.compile(
    r"\b(?:network|wifi|wi-fi|lan|subnet|everyone|everybody|all\s+(?:hosts?|devices?|"
    r"machines?|ips?)|whole\s+network|the\s+network)\b",
    re.IGNORECASE,
)


def _clean_capture(text: str) -> tuple[str, int]:
    """Tidy raw capture output for display: drop ettercap progress bars/spinner,
    count-and-collapse the repetitive 'SEND L3 ERROR' forwarding failures, and
    fold consecutive duplicate lines. Returns (cleaned_text, forward_error_count).
    """
    fwd_errors = 0
    kept: list[str] = []
    for raw in (text or "").replace("\r", "\n").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if "|" in line and ("=>" in line or "%" in line):  # progress bar / spinner
            continue
        if "SEND L3 ERROR" in line:
            fwd_errors += 1
            continue
        base = kept[-1].rsplit(" ×", 1)[0] if kept else None
        if base == line:
            n = int(kept[-1].rsplit("×", 1)[1]) + 1 if " ×" in kept[-1] else 2
            kept[-1] = f"{line} ×{n}"
        else:
            kept.append(line)
    return "\n".join(kept), fwd_errors


_DNS_Q_RE = re.compile(r"\b(?:A|AAAA|CNAME|HTTPS)\?\s+([A-Za-z0-9._-]+?)\.?\s*(?:\(|$)")
_HTTPS_DST_RE = re.compile(r">\s+(\d{1,3}(?:\.\d{1,3}){3})\.443:")


def _parse_connections(text: str) -> tuple[list[str], list[str]]:
    """From tcpdump output, pull the DNS names a device looked up and the IPs it
    opened HTTPS (443) connections to. Returns (domains, https_ips), deduped."""
    domains: list[str] = []
    ips: list[str] = []
    for line in (text or "").splitlines():
        for m in _DNS_Q_RE.finditer(line):
            d = m.group(1).rstrip(".").lower()
            if "." in d and d not in domains:
                domains.append(d)
        m = _HTTPS_DST_RE.search(line)
        if m and m.group(1) not in ips:
            ips.append(m.group(1))
    return domains, ips


async def _reverse_names(ips: list[str], limit: int = 15) -> dict[str, str]:
    """Best-effort reverse-DNS (PTR) for HTTPS destination IPs — the PTR often
    names the CDN/host (e.g. instagram.c10r.facebook.com)."""
    import socket

    async def one(ip: str) -> tuple[str, str]:
        try:
            host = await asyncio.wait_for(
                asyncio.to_thread(lambda: socket.gethostbyaddr(ip)[0]), timeout=1.5)
            return ip, host
        except Exception:
            return ip, ""

    pairs = await asyncio.gather(*(one(ip) for ip in ips[:limit]))
    return {ip: name for ip, name in pairs if name}


def _orch_digest(result, names: dict[str, str]) -> str:
    lines = ["Orchestration result:"]
    for c in result.consultations:
        label = names.get(c.agent_id, c.agent_id)
        lines.append(f"- {label}: {c.report.summary if c.ok else 'failed: ' + (c.error or '')}")
    for p in result.proposed:
        lines.append(f"- operation {p.operation} on {p.target or '-'} [{p.permission}]: "
                     f"{p.status}" + (f" (execution #{p.execution_id})" if p.execution_id else ""))
    pend = result.by_status("pending")
    if pend:
        lines.append(f"{len(pend)} operation(s) awaiting approval (/queue, /approve <id>).")
    return "\n".join(lines)


def _digest(c, names: dict[str, str]) -> str:
    """Plain-text summary of a consultation for the chat history."""
    def one(x, prefix: str) -> list[str]:
        label = names.get(x.agent_id, x.agent_id)
        if not x.ok:
            return [f"{prefix}{label} agent (task #{x.task_id}) failed: {x.error}"]
        r = x.report
        out = [f"{prefix}{label} agent report (task #{x.task_id}): {r.summary}"]
        for i, s in enumerate(r.steps, 1):
            flags = "BLOCKED" if s.blocked else ("needs approval" if s.requires_approval else "ok")
            out.append(f"  {i}. {s.title} — tool: {s.tool or '-'}, target: {s.target or '-'}, "
                       f"{s.permission.value}, {flags}")
        for h in r.hypotheses:
            out.append(f"  hypothesis ({h.confidence}, unverified): {h.statement}")
        return out
    lines = one(c, "")
    for reply in c.replies:
        lines += one(reply, "↳ ")
    return "\n".join(lines)


class _Thinking:
    """Live spinner that shows elapsed time and the tail of the model's reasoning."""

    def __init__(self) -> None:
        self.started = time.monotonic()
        self.reasoning = ""
        self.label = "waiting for model"

    def __rich__(self) -> Spinner:
        secs = int(time.monotonic() - self.started)
        tail = " ".join(self.reasoning.split())[-90:]
        text = Text.assemble((f"{self.label} · {secs}s", "cyan"))
        if tail:
            text.append(f"  …{tail}", style="dim italic")
        return Spinner("dots", text=text)


_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"  # braille spinner frames (Claude-style)


def _trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


_HYDRA_HIT_RE = re.compile(r"login:\s*\S+\s+password:\s*\S+", re.IGNORECASE)


def _hydra_hit(text: str) -> bool:
    """True if hydra output shows a successful login (a login:/password: pair)."""
    return bool(_HYDRA_HIT_RE.search(text or ""))


_OUI_DB: dict[str, str] | None = None


def _oui_vendor(mac: str) -> str:
    """Map a MAC address to its vendor via nmap's prefix DB (e.g. 'Xiaomi')."""
    global _OUI_DB
    if _OUI_DB is None:
        _OUI_DB = {}
        import pathlib
        for p in ("/usr/share/nmap/nmap-mac-prefixes",):
            try:
                for line in pathlib.Path(p).read_text(errors="replace").splitlines():
                    if line[:6].isalnum() and " " in line:
                        pref, _, vendor = line.partition(" ")
                        _OUI_DB[pref.upper()] = vendor.strip()
            except OSError:
                pass
    pref = mac.replace(":", "").replace("-", "").upper()[:6]
    return _OUI_DB.get(pref, "")


def _host_macs() -> dict[str, str]:
    """IP → MAC from the kernel neighbour (ARP) cache (populated by the ping
    sweep). Unprivileged; works in the toolbox via the shared net namespace."""
    import subprocess
    out = ""
    try:
        out = subprocess.run(["ip", "neigh", "show"], capture_output=True,
                             text=True, timeout=5).stdout
    except Exception:
        return {}
    macs: dict[str, str] = {}
    for line in out.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})", line)
        if m:
            macs[m.group(1)] = m.group(2).lower()
    return macs


# objective keyword → vendor-name substrings that identify that kind of device
_VENDOR_ALIASES: dict[str, tuple[str, ...]] = {
    "xiaomi": ("xiaomi", "redmi", "poco"),
    "apple": ("apple", "iphone", "ipad", "macbook", "imac", "ios", "airpods"),
    "samsung": ("samsung", "galaxy"),
    "google": ("google", "pixel", "nest", "chromecast"),
    "huawei": ("huawei", "honor"),
    "oneplus": ("oneplus",),
    "amazon": ("amazon", "echo", "alexa", "kindle", "fire tv", "firetv"),
    "sony": ("sony", "playstation"),
    "lg": ("lg electronics",),
    "tp-link": ("tp-link", "tplink"),
    "oppo": ("oppo",), "vivo": ("vivo",), "realme": ("realme",),
    "intel": ("intel",), "dell": ("dell",), "raspberry": ("raspberry",),
}


# Assessment playbook: for each service nmap reports, the specialist operations
# to run against it (op_id, how-to-build-target). "host" → the IP; "url" → a
# scheme://host[:port] built from the port. Low/passive ops auto-run as
# enumeration; intrusive/high_impact ops run after one approval.
_PLAYBOOK: dict[str, list[tuple[str, str]]] = {
    "http":         [("whatweb", "url"), ("nikto-scan", "url"), ("nuclei-scan", "url")],
    "https":        [("whatweb", "url"), ("sslscan", "host"), ("nuclei-scan", "url")],
    "ssh":          [("defaultcreds-ssh", "host")],
    "ftp":          [("defaultcreds-ftp", "host")],
    "telnet":       [("defaultcreds-telnet", "host")],
    "microsoft-ds": [("enum4linux-ng", "host"), ("smbmap-enum", "host"), ("netexec-smb", "host")],
    "netbios-ssn":  [("enum4linux-ng", "host"), ("netexec-smb", "host")],
}


def _norm_service(svc: str) -> str:
    """Map an nmap service name to a playbook key."""
    s = svc.lower()
    if "https" in s or "ssl" in s or s == "https-alt":
        return "https"  # nmap reports TLS web as https / ssl/http / ssl/https
    if s.startswith("http") or s in ("www", "http-alt", "http-proxy"):
        return "http"
    return s  # ssh/ftp/telnet/microsoft-ds/netbios-ssn match keys directly


class _ActionPick(BaseModel):
    """One operation the model decided to run next."""
    op_id: str
    target: str | None = None
    params: dict[str, str] = Field(default_factory=dict)
    why: str = ""


class _NextMove(BaseModel):
    """The model's decision for the next wave of a running assessment."""
    done: bool = False
    reason: str = ""
    actions: list[_ActionPick] = Field(default_factory=list)


class _Activity:
    """Claude-style live activity block: a ● action line, the shell command on a
    ⎿ sub-line, and a live spinner + elapsed timer that becomes a ✓/✗ result."""

    def __init__(self, action: str, command: str) -> None:
        self.action = action
        self.command = command
        self.started = time.monotonic()
        self.done = False
        self.ok = False
        self.summary = ""

    def finish(self, ok: bool, summary: str) -> None:
        self.done, self.ok, self.summary = True, ok, summary

    def __rich__(self) -> Group:
        elapsed = time.monotonic() - self.started
        dot_style = ACCENT if not self.done else ("green" if self.ok else "red")
        head = Text.assemble((DOT, dot_style), " ", (self.action, "bold"))
        cmd = Text("  ⎿ ", style=MUTED)
        cmd.append(f"$ {_trunc(self.command, 80)}", style="dim")
        if not self.done:
            frame = _SPIN[int(elapsed * 10) % len(_SPIN)]
            tail = Text(f"    {frame} ", style=ACCENT)
            tail.append(f"running… ({elapsed:.0f}s · Ctrl+C stops)", style=MUTED)
        else:
            glyph, style = ("✓", "green") if self.ok else ("✗", "red")
            tail = Text(f"    {glyph} ", style=style)
            tail.append(f"{self.summary} ({elapsed:.1f}s)", style="dim")
        return Group(head, cmd, tail)


class ChatApp:
    def __init__(self, ctx: Context, engagement: Engagement | None, session_id: int,
                 *, plain: bool, registry=None) -> None:
        self.ctx = ctx
        self.engagement = engagement
        self.session_id = session_id
        self.plain = plain or not console.is_terminal
        eng_id = engagement.id if engagement else None
        self.gateway = ModelGateway(
            ctx.settings, recorder=ctx.store.recorder(engagement_id=eng_id, session_id=session_id)
        )
        self.convo = Conversation(ctx.store, self.gateway, ctx.domains, session_id=session_id,
                                  engagement=engagement,
                                  max_history=ctx.settings.chat.max_history_messages,
                                  registry=registry)
        self.registry = registry
        self._prompt = None
        self._directory = None
        self._bus = None
        self._engine = None
        self._orch = None
        # Full-auto: objective-like messages run the pipeline; intrusive ops
        # auto-run, high_impact asks once. Toggle with /auto.
        self.auto_trigger = True
        self.auto_mode = "auto_intrusive"

    # ------------------------------------------------------------ input

    async def _read(self) -> str | None:
        """Return a line, '' on Ctrl+C, or None on EOF."""
        if self.plain or not sys.stdin.isatty():
            try:
                return await asyncio.to_thread(input, "you> ")
            except EOFError:
                return None
            except KeyboardInterrupt:
                return ""
        if self._prompt is None:
            from prompt_toolkit import PromptSession
            from prompt_toolkit.history import FileHistory

            hist = self.ctx.settings.db_path.parent / "prompt_history"
            hist.parent.mkdir(parents=True, exist_ok=True)
            self._prompt = PromptSession(history=FileHistory(str(hist)))
        try:
            return await self._prompt.prompt_async([("ansibrightred bold", "❯ ")])
        except EOFError:
            return None
        except KeyboardInterrupt:
            return ""

    # ------------------------------------------------------------ output

    def banner(self) -> None:
        cands = self.gateway.candidates("orchestrator")
        model = cands[0].split("/")[-1] if cands else "[red]none configured[/]"
        fb = f" [dim](+{len(cands) - 1} fallback)[/]" if len(cands) > 1 else ""
        eng = (f"[bold]{self.engagement.name}[/] [dim]— "
               f"{escape(self.ctx.store.scope_of(self.engagement).summary())}[/]"
               if self.engagement else "[dim]none — say what network to work on[/]")
        auto = ("[green]on[/] [dim]— intrusive auto, high-impact asks[/]" if self.auto_trigger
                else "[yellow]off[/] [dim]— /plan to run, /auto on to enable[/]")

        def row(label: str, value: str) -> Text:
            line = Text()
            line.append(f"  {label:<11}", style=MUTED)
            line.append_text(Text.from_markup(value))
            return line

        if self.plain:
            console.print(Text.from_markup(
                f"BlackArch AI {__version__} · {eng} · {model}{fb}"))
            return
        body = Group(
            Text.from_markup(f"[bold {ACCENT}]✻ BlackArch AI[/] [dim]v{__version__}[/]"),
            Text(""),
            row("engagement", eng),
            row("model", f"{model}{fb}"),
            row("auto-run", auto),
            row("session", f"[dim]#{self.session_id}[/]"),
            Text(""),
            Text.from_markup("  [dim]/recon  /sniff  /attack  /report  ·  /help all "
                             "commands  ·  Ctrl+C cancels[/]"),
        )
        console.print(Panel(body, box=ROUNDED, border_style=ACCENT, expand=False,
                            padding=(0, 1)))

    def footer(self, r: LLMResult, elapsed: float) -> None:
        tokens = (f"{fmt_tokens(r.usage.prompt_tokens)} in / "
                  f"{fmt_tokens(r.usage.completion_tokens)} out"
                  + (" (est.)" if r.usage.estimated else ""))
        bits = [r.model, tokens, fmt_cost(r.cost_usd), f"{elapsed:.1f}s"]
        if r.fell_back:
            bits.append("[yellow]fallback used[/]")
        if r.redactions:
            bits.append(f"[magenta]{sum(r.redactions.values())} secret(s) redacted[/]")
        console.print(Text.from_markup("[dim]" + " · ".join(bits) + "[/]"))

    # ------------------------------------------------------------ auto-engage

    def _auto_engage(self, text: str) -> bool:
        """Create an engagement from natural-language targets. Returns True if created."""
        if self.engagement is not None:
            return False
        from blackarch_ai.cli.auto_engage import extract_targets

        targets, exclusions, name = extract_targets(text)
        if not targets:
            return False
        from blackarch_ai.security.scope import Scope, ScopeError

        try:
            scope = Scope.build(targets, exclusions)
        except ScopeError as exc:
            console.print(f"[yellow]Could not auto-scope: {exc}[/]")
            return False
        existing = self.ctx.store.list_engagements()
        # Reuse an engagement that already covers exactly this scope.
        want = scope.summary()
        for e in existing:
            if self.ctx.store.scope_of(e).summary() == want:
                self.engagement = e
                self.convo.engagement = e
                self.gateway._recorder = self.ctx.store.recorder(
                    engagement_id=e.id, session_id=self.session_id,
                )
                self._orch = self._engine = self._directory = self._bus = None
                console.print(f"[green]✓ Using existing engagement[/] [bold]{e.name}[/] — {want}")
                return True
        # Otherwise pick a free name (local-net, local-net-2, …).
        taken = {e.name for e in existing}
        if name in taken:
            n = 2
            while f"{name}-{n}" in taken:
                n += 1
            name = f"{name}-{n}"
        eng = self.ctx.store.create_engagement(
            name, scope, objective=text.strip()[:200], authorized_by="auto-detect",
        )
        self.engagement = eng
        self.convo.engagement = eng
        self.gateway._recorder = self.ctx.store.recorder(
            engagement_id=eng.id, session_id=self.session_id,
        )
        self._orch = None
        self._engine = None
        self._directory = None
        self._bus = None
        parts = [f"[green]✓ Auto-engaged[/] [bold]{name}[/] — {scope.summary()}"]
        if exclusions:
            parts.append(f"  [dim]excluded: {', '.join(exclusions)} (gateway)[/]")
        console.print("\n".join(parts))
        self.ctx.store.audit("auto", "engagement.auto_create",
                             {"name": name, "targets": targets, "exclusions": exclusions},
                             engagement_id=eng.id, session_id=self.session_id)
        return True

    # ------------------------------------------------------------ chat turn

    async def _stream_rich(self, text: str) -> LLMResult | None:
        from rich.live import Live

        thinking = _Thinking()
        answer: list[str] = []
        result: LLMResult | None = None
        with Live(thinking, console=console, refresh_per_second=8,
                  vertical_overflow="visible") as live:
            async for ev in self.convo.send(text):
                if ev.type == "reasoning":
                    thinking.label = "thinking"
                    thinking.reasoning += ev.text
                elif ev.type == "text":
                    answer.append(ev.text)
                    live.update(Group(
                        Text.from_markup(f"[{ACCENT}]{DOT}[/] [dim]orchestrator[/]"),
                        Markdown("".join(answer)),
                    ), refresh=False)
                elif ev.type == "attempt_failed":
                    live.console.print(f"[yellow]⚠ {ev.model} failed: {ev.error} — trying next[/]")
                    thinking.started, thinking.reasoning = time.monotonic(), ""
                elif ev.type == "done":
                    result = ev.result
                    if not answer and thinking.reasoning.strip():
                        # Model emitted only reasoning, no final answer — salvage it
                        # rather than showing a blank reply.
                        live.update(Group(
                            Text.from_markup(f"[{ACCENT}]{DOT}[/] [dim]orchestrator "
                                             "(no final answer — showing its reasoning)[/]"),
                            Markdown(thinking.reasoning.strip()),
                        ))
                    elif not answer:
                        live.update(Text("(empty response)", style="dim"))
        return result

    async def _stream_plain(self, text: str) -> LLMResult | None:
        result: LLMResult | None = None
        said_thinking = False
        got_text = False
        reasoning: list[str] = []
        async for ev in self.convo.send(text):
            if ev.type == "reasoning":
                reasoning.append(ev.text)
                if not said_thinking:
                    print("[thinking…]", flush=True)
                    said_thinking = True
            elif ev.type == "text":
                got_text = True
                sys.stdout.write(ev.text)
                sys.stdout.flush()
            elif ev.type == "attempt_failed":
                print(f"\n[warning] {ev.model} failed: {ev.error} — trying next", flush=True)
            elif ev.type == "done":
                result = ev.result
        if not got_text and "".join(reasoning).strip():
            print("(no final answer — showing its reasoning)\n" + "".join(reasoning).strip())
        print()
        return result

    async def turn(self, text: str) -> None:
        started = time.monotonic()
        task = asyncio.ensure_future(
            self._stream_plain(text) if self.plain else self._stream_rich(text)
        )
        loop = asyncio.get_running_loop()
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signal.SIGINT, task.cancel)
        try:
            result = await task
            if result is not None:
                self.footer(result, time.monotonic() - started)
        except asyncio.CancelledError:
            console.print("[yellow]⏹ cancelled — partial reply kept in history[/]")
        except StreamInterrupted as exc:
            console.print(f"[red]✗ {exc}[/]\n[dim]Partial reply kept in history.[/]")
        except GatewayError as exc:
            console.print(f"[red]✗ {exc}[/]")
        finally:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.remove_signal_handler(signal.SIGINT)

    # ------------------------------------------------------------ commands

    def cmd_help(self, _: str) -> None:
        t = Table(show_header=False, box=None, padding=(0, 2))
        for cmd, (desc, ready) in COMMANDS.items():
            t.add_row(f"[bold]{cmd}[/]" if ready else f"[dim]{cmd}[/]",
                      desc if ready else f"[dim]{desc}[/]")
        console.print(t)

    def cmd_scope(self, _: str) -> None:
        if self.engagement is None:
            console.print("No engagement selected. Start chat with "
                          "[bold]blackarch-ai -e NAME[/] to work within a scope.")
            return
        scope = self.ctx.store.scope_of(self.engagement)
        t = Table(title=f"Scope — {self.engagement.name}", title_justify="left")
        t.add_column("")
        t.add_column("Entry")
        t.add_column("Type")
        for e in scope.include:
            t.add_row("[green]include[/]", e.raw, e.kind)
        for e in scope.exclude:
            t.add_row("[red]exclude[/]", e.raw, e.kind)
        console.print(t)
        if self.engagement.objective:
            console.print(f"Objective: {self.engagement.objective}")

    def cmd_status(self, _: str) -> None:
        store = self.ctx.store
        cands = self.gateway.candidates("orchestrator")
        console.print(f"Session #{self.session_id} · engagement: "
                      f"{self.engagement.name if self.engagement else 'none'}")
        console.print(f"Model chain (usable): {' → '.join(cands) or '[red]none[/]'}")
        console.print(f"This session: {fmt_totals(store.usage_totals(session_id=self.session_id))}")
        if self.engagement:
            console.print("This engagement: "
                          + fmt_totals(store.usage_totals(engagement_id=self.engagement.id)))
        from blackarch_ai.agents.bus import MessageBus

        tasks = MessageBus(store, self.engagement.id if self.engagement else None).tasks(5)
        console.print(f"Agents: {len(self.ctx.domains.agents)} defined · recent tasks: "
                      + (", ".join(f"#{t.id} {t.agent_id} ({t.status})" for t in tasks) or "none"))

    def cmd_history(self, arg: str) -> None:
        n = int(arg) if arg.strip().isdigit() else 20
        msgs = self.ctx.store.messages(self.session_id)[-n:]
        if not msgs:
            console.print("[dim]No messages in this session yet.[/]")
            return
        for m in msgs:
            who = "[bold red]you[/]" if m.role == "user" else f"[bold cyan]orchestrator[/] [dim]{m.model or ''}[/]"
            flag = " [yellow](interrupted)[/]" if m.interrupted else ""
            console.print(f"{who} [dim]{m.created_at:%H:%M}[/]{flag}")
            console.print(Markdown(m.content) if m.role == "assistant" else Text(m.content))
            console.print()

    def cmd_sessions(self, _: str) -> None:
        eng_id = self.engagement.id if self.engagement else None
        t = Table(title="Recent sessions", title_justify="left")
        for col in ("ID", "Started", "Messages", "Title"):
            t.add_column(col)
        for cs, n in self.ctx.store.list_chat_sessions(eng_id):
            mark = " [green]●[/]" if cs.id == self.session_id else ""
            t.add_row(f"{cs.id}{mark}", f"{cs.created_at:%Y-%m-%d %H:%M}", str(n), cs.title)
        console.print(t)

    async def ask(self, arg: str) -> None:
        from blackarch_ai.agents.consult import consult
        from blackarch_ai.agents.directory import UnknownAgent
        from blackarch_ai.cli.agent_views import print_consultation

        agent_id, _, task_text = arg.partition(" ")
        if not agent_id or not task_text.strip():
            console.print("Usage: /ask <agent> <task>   — agent ids: "
                          + ", ".join(a.id for a in self.ctx.domains.agents))
            return
        if self._directory is None:
            self._directory, self._bus = self.ctx.agents_for(self.engagement,
                                                            session_id=self.session_id)
        try:
            agent = self._directory.get(agent_id.lower())
        except UnknownAgent as exc:
            console.print(f"[red]{exc.args[0]}[/]")
            return
        scope = self.ctx.store.scope_of(self.engagement) if self.engagement else None
        task = asyncio.ensure_future(consult(self._directory, self._bus, agent.id, task_text,
                                             engagement=self.engagement, scope=scope))
        loop = asyncio.get_running_loop()
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signal.SIGINT, task.cancel)
        try:
            with console.status(f"{agent.name} agent working… (Ctrl+C cancels)"):
                result = await task
        except asyncio.CancelledError:
            console.print("[yellow]⏹ cancelled[/]")
            return
        finally:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.remove_signal_handler(signal.SIGINT)
        names = {a.id: a.name for a in self.ctx.domains.agents}
        print_consultation(console, result, names)
        # Keep a compact record in the chat so the orchestrator can refer to it.
        self.ctx.store.add_message(self.session_id, "user",
                                   f"(asked the {agent.name} agent) {task_text}")
        self.ctx.store.add_message(self.session_id, "assistant", _digest(result, names),
                                   model=result.result.model if result.result else None)

    def _ensure_orch(self):
        if self._orch is None:
            if self.registry is None:
                return None
            scope = self.ctx.store.scope_of(self.engagement) if self.engagement else None
            self._orch = self.ctx.orchestrator_for(self.engagement, scope,
                                                   session_id=self.session_id)
        return self._orch

    async def recon(self, arg: str) -> None:
        """Deterministic recon over the engagement scope — runs real ops, no LLM."""
        from blackarch_ai.orchestrator.recon import ReconRunner

        if self.engagement is None:
            console.print("[yellow]Select an engagement first: start with -e NAME.[/]")
            return
        engine = self._ensure_engine()
        if engine is None:
            console.print("[yellow]Execution needs the tool registry, which is unavailable.[/]")
            return
        max_hosts = int(arg.strip()) if arg.strip().isdigit() else 25
        scope = self.ctx.store.scope_of(self.engagement)
        runner = ReconRunner(engine, scope, self.engagement,
                             on_event=lambda m: console.print(f"  [grey50]⎿[/] [dim]{escape(m)}[/]"))
        console.print(f"[{ACCENT}]{DOT}[/] [bold]Recon[/] on {escape(scope.summary())} "
                      "[dim](Ctrl+C stops; evidence is saved as it runs)[/]")
        task = asyncio.ensure_future(runner.run(max_hosts=max_hosts))
        loop = asyncio.get_running_loop()
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signal.SIGINT, task.cancel)
        try:
            hosts = await task
        except asyncio.CancelledError:
            await engine.stop_all()
            console.print("[yellow]⏹ stopped — partial results kept[/]")
            return
        finally:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.remove_signal_handler(signal.SIGINT)
        console.print(f"[green]✓ recon complete[/] — {len(hosts)} host(s) up, "
                      f"{len(runner.executions)} operation(s) run. "
                      f"[dim]/report to write it up.[/]")
        self.ctx.store.add_message(self.session_id, "user", "(ran deterministic recon)")
        self.ctx.store.add_message(
            self.session_id, "assistant",
            f"Deterministic recon over {scope.summary()}: {len(hosts)} hosts up, "
            f"{len(runner.executions)} operations executed. Hosts: {', '.join(hosts[:30])}")

    async def assess(self, objective: str = "") -> None:
        """Autonomous assessment loop with a pentester's methodology:
        discover → service-scan → dispatch the right specialist per service
        (web scanners, SMB enum, credential tests…). Safe enumeration auto-runs;
        intrusive/exploit steps run after one approval. Real tools, no LLM."""
        from blackarch_ai.core.context import ContextStore
        from blackarch_ai.orchestrator.recon import ReconRunner

        if self.engagement is None:
            console.print("[yellow]No engagement yet — say what network to work on first.[/]")
            return
        engine = self._ensure_engine()
        if engine is None:
            console.print("[yellow]Execution needs the tool registry, which is unavailable.[/]")
            return
        scope = self.ctx.store.scope_of(self.engagement)
        console.print(f"[{ACCENT}]{DOT}[/] [bold]Full assessment[/] on "
                      f"{escape(scope.summary())} [dim]— discover → scan → test logins. "
                      "Ctrl+C stops; evidence saved as it runs.[/]")
        # Phase 1: discovery + service scan (deterministic, reliable).
        runner = ReconRunner(engine, scope, self.engagement,
                             on_event=lambda m: console.print(f"  [grey50]⎿[/] [dim]{escape(m)}[/]"))
        task = asyncio.ensure_future(runner.run(max_hosts=25))
        loop = asyncio.get_running_loop()
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signal.SIGINT, task.cancel)
        try:
            hosts = await task
        except asyncio.CancelledError:
            await engine.stop_all()
            console.print("[yellow]⏹ stopped — partial results kept[/]")
            return
        finally:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.remove_signal_handler(signal.SIGINT)
        if not hosts:
            console.print("[yellow]No live hosts found — nothing to assess.[/]")
            return
        # Phase 2: seed facts from the scan, then run the reactive decision loop.
        cx = ContextStore(engine.store, self.engagement.id)
        facts = {"svc": set(), "tech": set(), "cred": set()}
        for ip, port, svc in self._open_services(cx):
            facts["svc"].add((ip, port, svc))
        console.print(f"[green]✓ Scan done[/] — {len(hosts)} host(s) up, "
                      f"{len(facts['svc'])} open service(s).")
        if not facts["svc"]:
            console.print("[dim]No TCP services exposed (normal for phones / hardened hosts) — "
                          "nothing to work with. /report for the host list.[/]")
            return
        # One decision: may it run active steps (vuln scans, credential tests)?
        console.print("[bold]I'll work the objective adaptively[/] — enumerate, read each "
                      "result, and decide the next move until I find a way in or run out of "
                      "leads. [dim]Safe enumeration runs automatically; active attacks need "
                      "your OK.[/]")
        active_ok = (await self._read_line(
            "Authorize active attacks (vuln scans + credential tests) for this run? [y/N] "
            )).strip().lower() in ("y", "yes")

        objective = objective.strip() or "find a way into the devices on this network"
        done: set = set()
        ran = skipped_active = 0
        MAX_WAVES, MAX_OPS = 8, 40
        wave = 0
        for wave in range(MAX_WAVES):
            # Decide the next move: the model reasons over the facts + catalogue;
            # the deterministic rules are the fallback if it returns nothing usable.
            with console.status(f"[dim]thinking about the next move (wave {wave + 1})…[/]"):
                move = await self._llm_next_actions(objective, facts, done)
            if move is not None and move.done:
                console.print(f"[green]decided: done[/] [dim]— {escape(move.reason)}[/]")
                break
            candidate = self._actions_from_move(move) if move else []
            source = "model" if candidate else "rules"
            if not candidate:
                candidate = self._react(facts)
            actions = [a for a in candidate if a["key"] not in done]
            if not actions:
                break
            runnable = [a for a in actions
                        if a["perm"] in ("passive", "low") or active_ok]
            skipped_active += len(actions) - len(runnable)
            if not runnable:
                break
            console.print(f"[dim]— wave {wave + 1} ({source} decided {len(runnable)} "
                          "action(s)):[/]")
            for a in runnable:
                if ran >= MAX_OPS:
                    break
                done.add(a["key"])
                ran += 1
                console.print(f"  [grey50]⎿[/] [dim]{escape(a['why'])}[/]")
                res = await self._run_assess_step(engine, scope, a)
                if res and res.ok:
                    for k, v in self._parse_facts(a, res).items():
                        facts[k] |= v
            if ran >= MAX_OPS:
                console.print("[yellow]reached the step budget for this run[/]")
                break

        creds = facts["cred"]
        console.print(f"[green]✓ Assessment complete[/] — {len(hosts)} host(s), "
                      f"{ran} action(s) run across {wave + 1} wave(s).")
        if creds:
            console.print(f"[bold red]{DOT} Way in found![/] "
                          f"{len(creds)} credential(s):")
            for ip, svc, cred in list(creds)[:15]:
                console.print(f"  [grey50]⎿[/] [bold]{ip}[/] [dim]{svc}[/] → {escape(cred)}")
        else:
            console.print("[dim]No credentials/way-in found with the current leads.[/]")
        if skipped_active and not active_ok:
            console.print(f"[dim]{skipped_active} active step(s) were skipped — re-run and "
                          "authorize to let it try them.[/]")
        console.print("[dim]/report to write it up.[/]")

    def _react(self, facts: dict) -> list[dict]:
        """The decision function: given everything known so far, return the next
        candidate actions. New facts (a discovered web tech, a found credential)
        unlock new actions on later waves — that's the adaptive loop."""
        cat = self.ctx.catalogue
        actions: list[dict] = []

        def add(op_id, why, *, target=None, params=None):
            op = cat.get(op_id)
            if op is None:
                return
            key = (op_id, target or "", tuple(sorted((params or {}).items())))
            actions.append({"op_id": op_id, "target": target, "params": params or {},
                            "perm": op.permission.value, "why": why, "key": key})

        for ip, port, svc in facts["svc"]:
            skey = _norm_service(svc)
            for op_id, how in _PLAYBOOK.get(skey, []):
                if how == "host":
                    add(op_id, f"{op_id} on {ip}", target=ip)
                else:
                    url = (f"{'https' if skey == 'https' else 'http'}://{ip}"
                           + ("" if port in ("80", "443") else f":{port}"))
                    add(op_id, f"{op_id} on {url}", target=url)
        # Reactive rules: facts discovered by earlier waves unlock specialists.
        for url, tech in facts["tech"]:
            if tech == "wordpress":
                add("wpscan", f"WordPress at {url} → scan plugins/users",
                    params={"url_flag": url})
        return actions

    def _catalogue_brief(self) -> str:
        lines = []
        for op in self.ctx.catalogue.all():
            tgt = op.target.kind if op.target else "none"
            ps = ",".join(p.name + ("*" if p.required else "") for p in op.params) or "-"
            lines.append(f"{op.id} [{op.permission.value}] target={tgt} params={ps}: {op.summary}")
        return "\n".join(lines)

    @staticmethod
    def _facts_brief(facts: dict) -> str:
        svc = "; ".join(f"{ip}:{port}/{s}" for ip, port, s in sorted(facts["svc"])) or "none"
        tech = "; ".join(f"{t}@{u}" for u, t in facts["tech"]) or "none"
        cred = "; ".join(f"{ip} {sv} {c}" for ip, sv, c in facts["cred"]) or "none"
        return f"- services: {svc}\n- web tech: {tech}\n- credentials: {cred}"

    async def _llm_next_actions(self, objective: str, facts: dict,
                                done: set) -> _NextMove | None:
        """Ask the model to choose the next operations from the registered
        catalogue — the general 'think, then act' decision step. Returns None on
        any failure so the caller falls back to the deterministic rules."""
        scope = self.ctx.store.scope_of(self.engagement).summary()
        system = (
            "You are an autonomous penetration tester driving a tool framework during an "
            "AUTHORIZED assessment. You act ONLY by choosing registered operations — you "
            "cannot type shell commands. Choose the next 1-5 operations that best progress "
            "the objective. Use only op_id values from the catalogue, and targets drawn from "
            "the known hosts/services (a host IP, or a URL you can form from a web service). "
            "Enumerate before attacking. Do not repeat operations already run. Set done=true "
            "when the objective is met (e.g. a credential/way-in is found) or no useful action "
            "remains.")
        done_brief = ", ".join(sorted({k[0] for k in done})) or "nothing yet"
        user = (f"Objective: {objective}\nAuthorized scope: {scope}\n\n"
                f"Known facts:\n{self._facts_brief(facts)}\n\n"
                f"Operation types already run: {done_brief}\n\n"
                f"Operations available:\n{self._catalogue_brief()}\n\n"
                "Reply as JSON: {\"done\": bool, \"reason\": str, \"actions\": "
                "[{\"op_id\": str, \"target\": str|null, \"params\": {}, \"why\": str}]}")
        try:
            res = await self.gateway.complete(
                [{"role": "system", "content": system}, {"role": "user", "content": user}],
                role="orchestrator", response_model=_NextMove)
            return res.parsed
        except Exception:  # noqa: BLE001 - any failure → deterministic fallback
            return None

    def _actions_from_move(self, move: _NextMove) -> list[dict]:
        """Validate the model's picks against the catalogue; drop unknown op_ids."""
        from blackarch_ai.execution.operations import OperationError
        cat = self.ctx.catalogue
        out: list[dict] = []
        for p in move.actions:
            try:
                op = cat.get(p.op_id)
            except OperationError:
                continue  # model hallucinated an op_id — drop it
            params = {k: str(v) for k, v in (p.params or {}).items()}
            key = (p.op_id, p.target or "", tuple(sorted(params.items())))
            out.append({"op_id": p.op_id, "target": p.target, "params": params,
                        "perm": op.permission.value, "why": p.why or p.op_id, "key": key})
        return out

    def _parse_facts(self, action: dict, res) -> dict:
        """Read an operation's output into new facts that drive the next wave."""
        new = {"svc": set(), "tech": set(), "cred": set()}
        out = f"{res.stdout or ''}\n{res.stderr or ''}"
        if action["op_id"] in ("whatweb", "nuclei-scan", "nikto-scan") \
                and "wordpress" in out.lower() and action.get("target"):
            new["tech"].add((action["target"], "wordpress"))
        if _hydra_hit(out):
            m = _HYDRA_HIT_RE.search(out)
            target = action.get("target") or "host"
            new["cred"].add((target, action["op_id"].replace("defaultcreds-", ""),
                             m.group(0) if m else "found"))
        return new

    def _open_services(self, cx) -> list[tuple[str, str, str]]:
        """From recon's '<host>: open ports — 22/ssh, 80/http' findings, list
        (host, port, service) triples."""
        out: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str]] = set()
        for f in cx.findings(limit=500):
            m = re.match(r"(\d+\.\d+\.\d+\.\d+): open ports — (.+)", f.title)
            if not m:
                continue
            host = m.group(1)
            for pair in m.group(2).split(","):
                parts = pair.strip().split("/")
                if len(parts) < 2:
                    continue
                port, svc = parts[0].strip(), parts[1].strip().lower()
                if (host, port) in seen:
                    continue
                seen.add((host, port))
                out.append((host, port, svc))
        return out

    async def _run_assess_step(self, engine, scope, step):
        """Run one decided action behind a live activity block (auto-approving
        intrusive/high steps, since the user authorized active attacks)."""
        from blackarch_ai.execution.engine import ExecutionError
        from blackarch_ai.execution.operations import OperationError, ValidationError
        try:
            plan = engine.plan(step["op_id"], step.get("params") or {}, step.get("target"),
                               engagement_id=self.engagement.id, scope=scope)
        except (OperationError, ValidationError, ExecutionError) as exc:
            console.print(f"[red]{escape(str(exc))}[/]")
            return None
        if plan.blocked:
            console.print(f"[red]blocked: {escape(plan.block_reason)}[/]")
            return None
        approval = None
        if plan.needs_approval:
            approval = engine.record_approval(plan, "approved", decided_by="assess",
                                              reason="assessment playbook (user approved)")

        def summarize(res, cancelled, err):
            if cancelled:
                return False, "stopped"
            if err is not None:
                return False, _trunc(str(err), 60)
            if res is None:
                return False, "no result"
            if res.ok and _hydra_hit(res.stdout or ""):
                return True, "DEFAULT/WEAK LOGIN FOUND"
            if res.ok:
                return True, f"exit {res.exit_code} · #{res.execution_id}"
            return False, f"{res.status} · exit {res.exit_code}"

        res, _c, _e = await self._run_op_live(
            engine, engine.run(plan, requested_by="assess", approval=approval),
            action=f"{step['op_id']} on {step['target']}", command=" ".join(plan.argv),
            summarize=summarize)
        return res

    async def sniff(self, _text: str = "") -> None:
        """Interactive packet-sniffing: pick passive capture or MITM a device.

        Capture runs on the host (host=true ops via flatpak-spawn) because a
        rootless toolbox can't get CAP_NET_RAW on the physical interface.
        """
        from blackarch_ai.cli.auto_engage import detect_gateway, detect_primary_iface
        from blackarch_ai.orchestrator.recon import ReconRunner

        if self.engagement is None:
            console.print("[yellow]No engagement yet — say what network to work on first.[/]")
            return
        engine = self._ensure_engine()
        if engine is None:
            console.print("[yellow]Execution needs the tool registry, which is unavailable.[/]")
            return
        iface = detect_primary_iface()
        if not iface:
            console.print("[yellow]Couldn't detect your network interface.[/]")
            return
        gw = detect_gateway()
        scope = self.ctx.store.scope_of(self.engagement)
        console.print(f"[bold]Sniffing[/] on [bold]{iface}[/] "
                      f"[dim](scope: {escape(scope.summary())})[/]")
        # Discover devices first so the user can pick a target by sight.
        console.print("[dim]scanning for devices first…[/]")
        runner = ReconRunner(engine, scope, self.engagement,
                             on_event=lambda m: console.print(f"  [grey50]⎿[/] [dim]{escape(m)}[/]"))
        task = asyncio.ensure_future(runner.discover_hosts())
        loop = asyncio.get_running_loop()
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signal.SIGINT, task.cancel)
        try:
            hosts = await task
        except asyncio.CancelledError:
            await engine.stop_all()
            hosts = self._known_hosts()
        finally:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.remove_signal_handler(signal.SIGINT)
        hosts = [h for h in hosts if h != gw]
        console.print(f"[green]{len(hosts)} device(s) found.[/]")
        console.print("  [cyan]1[/] [bold]Passive capture[/] (safe) — watch broadcast/discovery "
                      "traffic. Shows who's on the network; sends nothing, disrupts nothing.")
        console.print("  [cyan]2[/] [bold]What does a device talk to?[/] — show the DNS names "
                      "and servers one device connects to (metadata, not content).")
        console.print("  [bold red]3[/] [bold]MITM[/] (high-impact) — ARP-spoof a device (or all) "
                      "and read raw traffic. Disruptive; content is encrypted.")
        console.print("  [dim]4 Cancel[/]")
        choice = (await self._read_line("Choose [1/2/3/4]: ")).strip()
        if choice == "1":
            await self._sniff_passive(engine, scope, iface)
        elif choice == "2":
            target = await self._pick_device(hosts, gw)
            if target:
                await self._sniff_domains(engine, scope, iface, gw, target)
        elif choice == "3":
            await self._sniff_mitm(engine, scope, iface, gw, hosts)
        else:
            console.print("[dim]cancelled[/]")

    async def _pick_device(self, hosts: list[str], gw: str | None) -> str | None:
        """Shared device picker: number from the list, or a typed IP."""
        if hosts:
            console.print("[bold]Which device?[/]")
            for i, h in enumerate(hosts[:40], 1):
                console.print(f"  [cyan]{i}[/] {h}")
            console.print("  [dim]or type an IP · blank cancels[/]")
        ans = (await self._read_line("Device [#/IP]: ")).strip()
        if ans.isdigit() and 1 <= int(ans) <= len(hosts[:40]):
            return hosts[int(ans) - 1]
        return ans or None

    async def attack(self, _text: str = "") -> None:
        """Interactive attack menu: discover devices, then run a chosen attack
        (currently password brute-force) against one, approval-gated."""
        from blackarch_ai.orchestrator.recon import ReconRunner

        if self.engagement is None:
            console.print("[yellow]No engagement yet — say what network to work on first.[/]")
            return
        engine = self._ensure_engine()
        if engine is None:
            console.print("[yellow]Execution needs the tool registry, which is unavailable.[/]")
            return
        scope = self.ctx.store.scope_of(self.engagement)
        hosts = self._known_hosts()
        if not hosts:
            console.print("[dim]scanning for devices first…[/]")
            runner = ReconRunner(engine, scope, self.engagement,
                                 on_event=lambda m: console.print(f"  [grey50]⎿[/] [dim]{escape(m)}[/]"))
            task = asyncio.ensure_future(runner.discover_hosts())
            loop = asyncio.get_running_loop()
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(signal.SIGINT, task.cancel)
            try:
                hosts = await task
            except asyncio.CancelledError:
                await engine.stop_all()
                hosts = self._known_hosts()
            finally:
                with contextlib.suppress(NotImplementedError, RuntimeError):
                    loop.remove_signal_handler(signal.SIGINT)
        console.print("[bold]Attack[/] — what do you want to try? [dim](on your own "
                      "network only)[/]")
        console.print("  [cyan]1[/] [bold]Check default passwords[/] — is a device still on its "
                      "factory login? [dim](great first check)[/]")
        console.print("  [bold red]2[/] Brute-force a [bold]login[/] (SSH/FTP/Telnet/RDP/SMB/MySQL)")
        console.print("  [bold red]3[/] [bold]Password spray[/] — one password across many users "
                      "(lockout-safer)")
        console.print("  [bold red]4[/] Test a website for [bold]SQL injection[/]")
        console.print("  [dim]5 Cancel[/]")
        kind = (await self._read_line("Choose [1/2/3/4/5]: ")).strip()
        if kind == "1":
            await self._attack_defaultcreds(engine, scope, hosts)
        elif kind == "2":
            await self._attack_bruteforce(engine, scope, hosts)
        elif kind == "3":
            await self._attack_spray(engine, scope, hosts)
        elif kind == "4":
            await self._attack_sqli(engine, scope)
        else:
            console.print("[dim]cancelled[/]")

    _DEFAULTCRED_SERVICES = [
        ("SSH", "defaultcreds-ssh"), ("Telnet (IoT/routers)", "defaultcreds-telnet"),
        ("FTP", "defaultcreds-ftp"),
    ]

    async def _attack_defaultcreds(self, engine, scope, hosts: list[str]) -> None:
        console.print("[bold]Check which service for factory passwords?[/]")
        for i, (label, _op) in enumerate(self._DEFAULTCRED_SERVICES, 1):
            console.print(f"  [cyan]{i}[/] {label}")
        sel = (await self._read_line(f"Service [1-{len(self._DEFAULTCRED_SERVICES)}]: ")).strip()
        if not (sel.isdigit() and 1 <= int(sel) <= len(self._DEFAULTCRED_SERVICES)):
            console.print("[dim]cancelled[/]")
            return
        svc_label, op_id = self._DEFAULTCRED_SERVICES[int(sel) - 1]
        target = await self._pick_device(hosts, None)
        if not target:
            console.print("[dim]cancelled[/]")
            return
        ok, reason = scope.check(target)
        if not ok:
            console.print(f"[red]refused — {escape(target)} is out of scope: {escape(reason)}[/]")
            return
        console.print(f"[bold]Default-credential check[/] on [bold]{escape(target)}[/] "
                      f"({escape(svc_label)}) — tries known factory login:password pairs. "
                      "[dim]Active login attempts, but a small known list. Authorized "
                      "targets only.[/]")
        if (await self._read_line("Proceed? [y/N] ")).strip().lower() not in ("y", "yes"):
            console.print("[dim]skipped[/]")
            return
        await self._run_sniff_op(engine, scope, op_id, target=target, params={},
                                 label=f"default-creds check {svc_label} on {target}")

    # service label → operation id, shown in order
    _BRUTE_SERVICES = [
        ("SSH", "hydra-ssh"), ("FTP", "hydra-ftp"), ("Telnet", "hydra-telnet"),
        ("RDP (Windows)", "hydra-rdp"), ("SMB (Windows/NAS)", "hydra-smb"),
        ("MySQL", "hydra-mysql"),
    ]

    async def _attack_bruteforce(self, engine, scope, hosts: list[str]) -> None:
        console.print("[bold]Which service?[/]")
        for i, (label, _op) in enumerate(self._BRUTE_SERVICES, 1):
            console.print(f"  [cyan]{i}[/] {label}")
        sel = (await self._read_line(f"Service [1-{len(self._BRUTE_SERVICES)}]: ")).strip()
        if not (sel.isdigit() and 1 <= int(sel) <= len(self._BRUTE_SERVICES)):
            console.print("[dim]cancelled[/]")
            return
        svc_label, op_id = self._BRUTE_SERVICES[int(sel) - 1]
        target = await self._pick_device(hosts, None)
        if not target:
            console.print("[dim]cancelled[/]")
            return
        ok, reason = scope.check(target)
        if not ok:
            console.print(f"[red]refused — {escape(target)} is out of scope: {escape(reason)}[/]")
            return
        user = (await self._read_line("Username to try [admin]: ")).strip() or "admin"
        console.print(f"[bold red]Brute-force {escape(svc_label)}[/] on [bold]{escape(target)}[/] "
                      f"as user [bold]{escape(user)}[/] with the top-99 common passwords. "
                      "[dim]Active + noisy; it can lock the account. Only on a device you "
                      "own/are authorized to test.[/]")
        if (await self._read_line("Proceed? [y/N] ")).strip().lower() not in ("y", "yes"):
            console.print("[dim]skipped[/]")
            return
        await self._run_sniff_op(engine, scope, op_id, target=target,
                                 params={"user": user},
                                 label=f"brute-force {svc_label} on {target} (user {user})")

    _SPRAY_SERVICES = [("SSH", "spray-ssh"), ("SMB (Windows/AD)", "spray-smb")]

    async def _attack_spray(self, engine, scope, hosts: list[str]) -> None:
        console.print("[bold]Spray which service?[/]")
        for i, (label, _op) in enumerate(self._SPRAY_SERVICES, 1):
            console.print(f"  [cyan]{i}[/] {label}")
        sel = (await self._read_line(f"Service [1-{len(self._SPRAY_SERVICES)}]: ")).strip()
        if not (sel.isdigit() and 1 <= int(sel) <= len(self._SPRAY_SERVICES)):
            console.print("[dim]cancelled[/]")
            return
        svc_label, op_id = self._SPRAY_SERVICES[int(sel) - 1]
        target = await self._pick_device(hosts, None)
        if not target:
            console.print("[dim]cancelled[/]")
            return
        ok, reason = scope.check(target)
        if not ok:
            console.print(f"[red]refused — {escape(target)} is out of scope: {escape(reason)}[/]")
            return
        password = (await self._read_line("Password to spray (e.g. Winter2025!): ")).strip()
        if not password:
            console.print("[dim]cancelled — need a password[/]")
            return
        console.print(f"[bold red]Password spray {escape(svc_label)}[/] on "
                      f"[bold]{escape(target)}[/] — trying [bold]{escape(password)}[/] against "
                      "17 common usernames. [dim]One try per user keeps it under most lockout "
                      "thresholds, but it is still an active attack. Authorized targets only.[/]")
        if (await self._read_line("Proceed? [y/N] ")).strip().lower() not in ("y", "yes"):
            console.print("[dim]skipped[/]")
            return
        await self._run_sniff_op(engine, scope, op_id, target=target,
                                 params={"password": password},
                                 label=f"password spray {svc_label} on {target}")

    async def _attack_sqli(self, engine, scope) -> None:
        url = (await self._read_line("Target URL (e.g. http://192.168.0.5/page?id=1): ")).strip()
        if not url:
            console.print("[dim]cancelled[/]")
            return
        console.print(f"[bold red]SQL injection test[/] on [bold]{escape(url)}[/]. "
                      "[dim]Sends crafted requests to detect injectable parameters "
                      "(read-only at this level). Only on sites you're authorized to test.[/]")
        if (await self._read_line("Proceed? [y/N] ")).strip().lower() not in ("y", "yes"):
            console.print("[dim]skipped[/]")
            return
        await self._run_sniff_op(engine, scope, "sqlmap-test", target=url,
                                 params={}, label=f"SQL injection test on {url}")

    @staticmethod
    def _free_port(start: int) -> int:
        """First free TCP port at or above `start` (so we don't clash with the
        user's own services, e.g. Docker published on 8080)."""
        import socket
        for p in range(start, start + 50):
            with socket.socket() as sk:
                try:
                    sk.bind(("0.0.0.0", p))
                    return p
                except OSError:
                    continue
        return start

    async def decrypt(self, _text: str = "") -> None:
        """Run mitmproxy as an explicit proxy to decrypt a device's HTTPS. The
        device must point its WiFi proxy here and trust the mitmproxy CA. Only
        works for apps/sites that don't pin their certificate."""
        from blackarch_ai.cli.auto_engage import detect_primary_ip

        if self.engagement is None:
            console.print("[yellow]No engagement yet — say what network to work on first.[/]")
            return
        engine = self._ensure_engine()
        if engine is None:
            console.print("[yellow]Execution needs the tool registry, which is unavailable.[/]")
            return
        scope = self.ctx.store.scope_of(self.engagement)
        ip = detect_primary_ip() or "<this-host-ip>"
        port = self._free_port(8080)
        ca = "~/.mitmproxy/mitmproxy-ca-cert.pem"
        console.print(Panel(
            Text.from_markup(
                "[bold]HTTPS decryption[/] via mitmproxy — [bold]your own devices only.[/]\n\n"
                "On the device you want to inspect:\n"
                f"  [bold]1.[/] WiFi settings → Proxy → Manual → host [bold]{ip}[/], "
                f"port [bold]{port}[/]\n"
                f"  [bold]2.[/] Open [bold]http://mitm.it[/] in its browser and install the "
                "certificate\n     (Android: save as a [bold]CA certificate[/]), or install "
                f"{ca}\n\n"
                "[dim]Decrypted requests will stream below. Apps that pin their certificate "
                "(Instagram, banking, WhatsApp…) will NOT decrypt and may stop working until "
                "you remove the proxy — that's expected.[/]"),
            title="set up the device", box=ROUNDED, border_style=ACCENT, padding=(0, 1)))
        if (await self._read_line(
                "Proxy set and CA installed on the device? Start the proxy? [y/N] "
                )).strip().lower() not in ("y", "yes"):
            console.print("[dim]skipped[/]")
            return
        await self._run_sniff_op(engine, scope, "mitm-proxy-decrypt", target=None,
                                 params={"port": port},
                                 label=f"HTTPS decrypt proxy on {ip}:{port}")

    async def _sniff_passive(self, engine, scope, iface: str) -> None:
        count = 100
        ans = (await self._read_line(f"How many packets to capture? [{count}] ")).strip()
        if ans.isdigit():
            count = max(1, min(100000, int(ans)))
        await self._run_sniff_op(
            engine, scope, "wifi-sniff-passive", target=None,
            params={"iface": iface, "count": count},
            label=f"passive capture on {iface} ({count} packets)")

    async def _sniff_domains(self, engine, scope, iface: str, gw: str | None,
                             target: str) -> None:
        """Show which servers a device talks to: ARP-spoof it so its traffic flows
        through us, capture its DNS lookups + HTTPS destinations, then stop."""
        from blackarch_ai.core.context import ContextStore
        from blackarch_ai.execution.engine import ExecutionError, NotApproved
        from blackarch_ai.execution.operations import OperationError, ValidationError

        if not gw:
            console.print("[yellow]Couldn't detect the gateway — needed to route traffic.[/]")
            return
        ok, reason = scope.check(target)
        if not ok:
            console.print(f"[red]refused — {escape(target)} is out of scope: {escape(reason)}[/]")
            return
        console.print(f"[bold]Mapping what {escape(target)} talks to[/] — I'll ARP-spoof it via "
                      f"{gw} so its traffic flows through this machine, then read its DNS lookups "
                      "and HTTPS destinations. [dim]This briefly intercepts the device (high-"
                      "impact). Use the device now (open Instagram, browse) so there's traffic.[/]")
        if (await self._read_line("Proceed? [y/N] ")).strip().lower() not in ("y", "yes"):
            console.print("[dim]skipped[/]")
            return
        # Start the ARP spoof in the background so the capture can see the traffic.
        try:
            spoof = engine.plan("mitm-sniff", {"iface": iface, "gateway": gw}, target,
                                engagement_id=self.engagement.id, scope=scope)
        except (OperationError, ValidationError, ExecutionError) as exc:
            console.print(f"[red]{escape(str(exc))}[/]")
            return
        if spoof.blocked:
            console.print(f"[red]blocked: {escape(spoof.block_reason)}[/]")
            return
        appr = engine.record_approval(spoof, "approved", decided_by="sniff-menu",
                                      reason="domains mode: route target traffic")
        spoof_task = asyncio.ensure_future(
            engine.run(spoof, requested_by="sniff", approval=appr))
        loop = asyncio.get_running_loop()
        res = None
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signal.SIGINT, spoof_task.cancel)
        try:
            await asyncio.sleep(2)  # let the ARP poisoning establish
            cap = engine.plan("device-connections", {"iface": iface, "count": 400}, target,
                              engagement_id=self.engagement.id, scope=scope)
            with console.status(f"capturing {target}'s connections (up to 60s)… "
                                "[dim]use the device now; Ctrl+C stops[/]"):
                res = await engine.run(cap, requested_by="sniff")
        except asyncio.CancelledError:
            console.print("[yellow]⏹ stopped[/]")
        except (ExecutionError, NotApproved) as exc:
            console.print(f"[red]{escape(str(exc))}[/]")
        finally:
            spoof_task.cancel()
            with contextlib.suppress(Exception):
                await spoof_task
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.remove_signal_handler(signal.SIGINT)
        if res is None:
            return
        err = (res.stderr or "").lower()
        if not res.ok and ("permission" in err or "cap_net_raw" in err):
            console.print("[yellow]Capture denied — host tools need capture rights once:[/]\n"
                          "  [bold]sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump[/]")
            return
        domains, ips = _parse_connections(res.stdout or "")
        names = await _reverse_names(ips)
        if not domains and not ips:
            console.print("[yellow]No DNS or HTTPS seen.[/] The device may have been idle, or it "
                          "uses encrypted DNS (DoH/DoT) so lookups are hidden. Try again while "
                          "actively using the app.")
        rows = []
        if domains:
            rows.append("[bold]Domains it looked up:[/]")
            rows += [f"  • {escape(d)}" for d in domains[:40]]
        if ips:
            rows.append("[bold]HTTPS servers it connected to:[/]")
            for ip in ips[:20]:
                tag = f"  [dim]({escape(names[ip])})[/]" if ip in names else ""
                rows.append(f"  • {ip}{tag}")
        if rows:
            console.print(Panel("\n".join(rows), title=f"what {escape(target)} talks to",
                                box=ROUNDED, border_style=ACCENT, padding=(0, 1)))
        cx = ContextStore(engine.store, self.engagement.id)
        summary = (f"{target} connected to: "
                   + ", ".join(domains[:10] or [names.get(i, i) for i in ips[:10]]))
        cx.add_finding(f"device connections: {target}", description=summary[:800],
                       severity="info", confidence="high", verified=True, agent="network")
        console.print("[dim]Note: this is metadata (who it talks to). The content is TLS-"
                      "encrypted and not shown. /report to write it up.[/]")

    def _known_hosts(self) -> list[str]:
        from blackarch_ai.core.context import ContextStore
        cx = ContextStore(self.ctx.store, self.engagement.id)
        return [a.value for a in cx.assets(limit=200) if a.kind == "host"]

    async def _sniff_mitm(self, engine, scope, iface: str, gw: str | None,
                          hosts: list[str] | None = None) -> None:
        if not gw:
            console.print("[yellow]Couldn't detect the gateway — needed for MITM. Aborting.[/]")
            return
        hosts = [h for h in (hosts if hosts is not None else self._known_hosts()) if h != gw]
        console.print("[bold]MITM target?[/]")
        console.print("  [bold red]a[/] ALL devices (whole segment — very disruptive, can break "
                      "the network)")
        for i, h in enumerate(hosts[:40], 1):
            console.print(f"  [cyan]{i}[/] {h}")
        console.print("  [dim]or type an IP · blank cancels[/]")
        ans = (await self._read_line("Target [a/#/IP]: ")).strip()

        if ans.lower() in ("a", "all"):
            console.print(f"[bold red]MITM ALL devices[/] on {iface} (gateway {gw}). "
                          "[dim]This ARP-spoofs every host on the segment and routes their "
                          "traffic through you — it is noisy and can disrupt the whole network. "
                          "Only on a network you are authorized to test.[/]")
            if (await self._read_line("Proceed? [y/N] ")).strip().lower() not in ("y", "yes"):
                console.print("[dim]skipped[/]")
                return
            await self._run_sniff_op(
                engine, scope, "mitm-sniff-all", target=None,
                params={"iface": iface, "gateway": gw}, label="MITM all devices (segment-wide)")
            return

        target = None
        if ans.isdigit() and 1 <= int(ans) <= len(hosts[:40]):
            target = hosts[int(ans) - 1]
        elif ans:
            target = ans
        if not target:
            console.print("[dim]cancelled[/]")
            return
        ok, reason = scope.check(target)
        if not ok:
            console.print(f"[red]refused — {escape(target)} is out of scope: {escape(reason)}[/]")
            return
        console.print(f"[bold red]MITM[/] [bold]{escape(target)}[/] via {iface} "
                      f"(gateway {gw}). [dim]This poisons the target's ARP cache and can "
                      "disrupt its connectivity. Only on networks you're authorized to test.[/]")
        if (await self._read_line("Proceed? [y/N] ")).strip().lower() not in ("y", "yes"):
            console.print("[dim]skipped[/]")
            return
        await self._run_sniff_op(
            engine, scope, "mitm-sniff", target=target,
            params={"iface": iface, "gateway": gw}, label=f"MITM {target}")

    async def _run_op_live(self, engine, coro, *, action, command, summarize):
        """Run an operation behind a Claude-style live activity block: a ● action
        line, the shell command on a ⎿ sub-line, and a spinner+timer that resolves
        to a ✓/✗ result. Returns (result, cancelled, error)."""
        from rich.live import Live

        task = asyncio.ensure_future(coro)
        loop = asyncio.get_running_loop()
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signal.SIGINT, task.cancel)
        res = cancelled = None
        err = None
        try:
            if self.plain:
                print(f"$ {command}", flush=True)
                try:
                    res = await task
                except asyncio.CancelledError:
                    cancelled = True
                except Exception as exc:  # noqa: BLE001 - surfaced to the user
                    err = exc
                ok, summary = summarize(res, cancelled, err)
                print(f"{'✓' if ok else '✗'} {summary}", flush=True)
            else:
                act = _Activity(action, command)
                with Live(act, console=console, refresh_per_second=12):
                    try:
                        res = await task
                    except asyncio.CancelledError:
                        cancelled = True
                    except Exception as exc:  # noqa: BLE001 - surfaced to the user
                        err = exc
                    ok, summary = summarize(res, cancelled, err)
                    act.finish(ok, summary)
        finally:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.remove_signal_handler(signal.SIGINT)
        if cancelled:
            with contextlib.suppress(Exception):
                await engine.stop_all()
        if err is not None:
            console.print(f"[red]{escape(str(err))}[/]")
        return res, cancelled, err

    async def _run_sniff_op(self, engine, scope, op_id: str, *, target, params, label) -> None:
        from blackarch_ai.core.context import ContextStore
        from blackarch_ai.execution.engine import ExecutionError
        from blackarch_ai.execution.operations import OperationError, ValidationError

        try:
            plan = engine.plan(op_id, params, target,
                               engagement_id=self.engagement.id, scope=scope)
        except (OperationError, ValidationError, ExecutionError) as exc:
            console.print(f"[red]{escape(str(exc))}[/]")
            return
        if plan.blocked:
            console.print(f"[red]blocked: {escape(plan.block_reason)}[/]")
            return
        approval = None
        if plan.needs_approval:
            approval = engine.record_approval(plan, "approved", decided_by="sniff-menu",
                                              reason="user chose from sniff menu")
        # A live MITM/proxy runs until stopped, so hitting the time limit is the
        # normal end, not a failure — report it as a completed capture window.
        continuous = op_id.startswith("mitm")

        def summarize(res, cancelled, err):
            if cancelled:
                return False, "stopped — evidence kept"
            if err is not None:
                return False, _trunc(str(err), 70)
            if res is None:
                return False, "no result"
            if res.ok:
                return True, f"exit {res.exit_code} · execution #{res.execution_id}"
            if continuous and res.status == "timeout":
                return True, (f"captured, stopped at the time limit · "
                              f"execution #{res.execution_id}")
            return False, f"{res.status} · exit {res.exit_code} · execution #{res.execution_id}"

        res, cancelled, err = await self._run_op_live(
            engine, engine.run(plan, requested_by="sniff", approval=approval),
            action=label, command=" ".join(plan.argv), summarize=summarize)
        if cancelled or err is not None or res is None:
            return
        out = (res.stdout or "").strip()
        err_txt = (res.stderr or "").strip()
        if not res.ok and ("permission" in err_txt.lower() or "cap_net_raw" in err_txt.lower()
                           or "operation not permitted" in err_txt.lower()):
            console.print("[yellow]Capture was denied — the host tools need capture rights once. "
                          "Run this on the host (it'll ask your password):[/]\n"
                          "  [bold]sudo setcap cap_net_raw,cap_net_admin+eip "
                          "/usr/bin/tcpdump[/]  [dim](and /usr/bin/ettercap, one per line)[/]")
            return
        cleaned_out, fwd_a = _clean_capture(out)
        cleaned_err, fwd_b = _clean_capture(err_txt)
        fwd_errors = fwd_a + fwd_b
        err = err_txt
        body = cleaned_out or cleaned_err
        if body:
            snippet = "\n".join(body.splitlines()[:15])
            console.print(Panel(escape(snippet), title=f"{label} — output",
                                box=ROUNDED, border_style=MUTED, padding=(0, 1)))
        if fwd_errors:
            iface = params.get("iface", "wlp0s20f3")
            console.print(
                f"[yellow]⚠ {fwd_errors} packet(s) couldn't be forwarded.[/] The ARP spoof "
                "worked — you intercepted traffic — but your NIC's segmentation offload hands "
                "ettercap oversized frames it can't re-send, so the target loses connectivity "
                "and the output fills with errors. One-time fix on the host (asks your "
                f"password):\n  [bold]sudo ethtool -K {escape(iface)} gro off gso off tso off[/]"
                "\n[dim]then run the MITM again.[/]")
        cx = ContextStore(engine.store, self.engagement.id)
        cx.add_finding(label, description=(body or out or err)[:800],
                       severity="info", confidence="high", verified=True, agent="network")
        console.print("[dim]/report to write it up.[/]")

    def _looks_like_objective(self, text: str) -> bool:
        """True if a plain message should run the pipeline rather than just chat."""
        t = text.strip()
        if not t or t.endswith("?") or _QUESTION_RE.match(t):
            return False
        return bool(_ACTION_RE.search(t))

    async def orchestrate(self, objective: str, *, auto: bool | None = None) -> None:
        from blackarch_ai.cli.orch_views import plan_table, print_orchestration
        from blackarch_ai.llm.gateway import GatewayError
        from blackarch_ai.orchestrator.plan import PlanError

        if not objective:
            console.print("Usage: /plan <objective>  (e.g. /plan map services on the lab network)")
            return
        orch = self._ensure_orch()
        if orch is None:
            console.print("[yellow]Orchestration needs the tool registry, which is unavailable.[/]")
            return
        auto = self.auto_trigger if auto is None else auto
        mode = self.auto_mode if auto else "auto_safe"
        names = {a.id: a.name for a in self.ctx.domains.agents}
        try:
            with console.status("planning…"):
                plan_row, plan_out, warnings = await orch.make_plan(objective)
        except (GatewayError, PlanError) as exc:
            console.print(f"[red]planning failed: {exc}[/]")
            return
        console.print(f"[dim]{escape(plan_out.summary)}[/]")
        console.print(plan_table(plan_out, names))
        for w in warnings:
            console.print(f"[yellow]⚠ {escape(w)}[/]")
        if not auto:
            answer = (await self._read_line(
                "Run this plan? passive/low auto-run, intrusive/high queued [Y/n] ")).strip().lower()
            if answer in ("n", "no"):
                console.print("Kept the plan; nothing ran.")
                return
        else:
            lvl = {"auto_safe": "passive/low auto; intrusive+ queued",
                   "auto_intrusive": "up to intrusive auto; high-impact asks",
                   "auto_all": "everything auto (incl. high-impact)"}[mode]
            console.print(f"[dim]auto-running in scope — {lvl}. Ctrl+C stops.[/]")
        task = asyncio.ensure_future(orch.run(plan_row, plan_out, mode=mode,
                                              on_event=lambda m: console.print(f"  [grey50]⎿[/] [dim]{escape(m)}[/]")))
        loop = asyncio.get_running_loop()
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signal.SIGINT, task.cancel)
        try:
            result = await task
        except asyncio.CancelledError:
            await orch.engine.stop_all()
            console.print("[yellow]⏹ stopped[/]")
            return
        finally:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.remove_signal_handler(signal.SIGINT)
        print_orchestration(console, result, names)
        if auto:
            await self._confirm_high_impact(orch)
        self.ctx.store.add_message(self.session_id, "user", f"(orchestrated: {objective})")
        self.ctx.store.add_message(self.session_id, "assistant", _orch_digest(result, names))

    async def _confirm_high_impact(self, orch) -> None:
        """After an auto run, ask once per queued high-impact operation."""
        from blackarch_ai.execution.engine import ExecutionError

        pend = [r for r in orch.pending() if r.permission == "high_impact"]
        if not pend:
            return
        console.print(f"[bold red]{len(pend)} high-impact operation(s) need confirmation.[/]")
        for row in pend:
            console.print(f"[bold red]HIGH-IMPACT[/] [bold]{row.operation}[/] on "
                          f"{escape(row.target or '—')} — [dim]{escape(' '.join(row.argv))}[/]")
            ans = (await self._read_line("Run it? [y/N] ")).strip().lower()
            if ans not in ("y", "yes"):
                orch.reject(row.id)
                console.print(f"[dim]skipped #{row.id}[/]")
                continue
            task = asyncio.ensure_future(orch.approve(row.id))
            loop = asyncio.get_running_loop()
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(signal.SIGINT, task.cancel)
            try:
                with console.status(f"running {row.operation}…"):
                    res = await task
            except asyncio.CancelledError:
                await orch.engine.stop_all()
                console.print("[yellow]⏹ stopped[/]")
                return
            except ExecutionError as exc:
                console.print(f"[red]{exc}[/]")
                continue
            finally:
                with contextlib.suppress(NotImplementedError, RuntimeError):
                    loop.remove_signal_handler(signal.SIGINT)
            colour = "green" if res.ok else "yellow"
            console.print(f"[{colour}]{res.status}[/] · exit {res.exit_code} · execution "
                          f"#{res.execution_id}")

    def cmd_report(self, arg: str) -> None:
        from datetime import UTC, datetime

        from blackarch_ai.config import data_dir
        from blackarch_ai.reports.render import render_html, render_json, render_markdown
        from blackarch_ai.reports.report import build_report

        if self.engagement is None:
            console.print("[yellow]Select an engagement first: start with -e NAME.[/]")
            return
        fmt = (arg.strip() or "md").lower()
        if fmt not in ("md", "html", "json"):
            console.print("Usage: /report [md|html|json]")
            return
        data = build_report(self.ctx.store, self.engagement)
        render = {"md": render_markdown, "html": render_html, "json": render_json}[fmt]
        path = data_dir() / "reports" / \
            f"{self.engagement.name}-{datetime.now(UTC):%Y%m%d-%H%M%S}.{fmt}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(data))
        c = data.counts
        console.print(f"[green]✓[/] {c['verified']} verified, {c['hypotheses']} to verify, "
                      f"{c['executions']} operations → {path}")
        console.print("[dim]Add an AI summary with: blackarch-ai report "
                      f"{self.engagement.name} --summary[/]")

    def cmd_queue(self) -> None:
        from blackarch_ai.cli.orch_views import proposals_table

        orch = self._ensure_orch()
        if orch is None:
            console.print("[yellow]Registry unavailable.[/]")
            return
        rows = orch.pending()
        if not rows:
            console.print("[dim]Approval queue is empty.[/]")
            return
        console.print(proposals_table(rows, "Approval queue (pending)"))
        console.print("[dim]/approve <id> to run · /reject <id> to drop[/]")

    async def decide(self, line: str) -> None:
        from blackarch_ai.execution.engine import ExecutionError

        orch = self._ensure_orch()
        if orch is None:
            console.print("[yellow]Registry unavailable.[/]")
            return
        verb, _, arg = line.partition(" ")
        if not arg.strip().isdigit():
            console.print(f"Usage: {verb} <id>  (see /queue)")
            return
        op_id = int(arg.strip())
        if verb.lower().startswith("/reject"):
            try:
                orch.reject(op_id)
                console.print(f"[dim]rejected #{op_id}[/]")
            except ExecutionError as exc:
                console.print(f"[red]{exc}[/]")
            return
        row = orch.get_proposal(op_id)
        if row is None:
            console.print(f"[red]no proposed operation #{op_id}[/]")
            return
        console.print(f"[bold]{row.operation}[/] on {escape(row.target or '—')} "
                      f"[{_PERM.get(row.permission, 'white')}]{row.permission}[/] — "
                      f"[dim]{escape(' '.join(row.argv))}[/]")
        task = asyncio.ensure_future(orch.approve(op_id))
        loop = asyncio.get_running_loop()
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signal.SIGINT, task.cancel)
        try:
            with console.status(f"running {row.operation}…"):
                res = await task
        except asyncio.CancelledError:
            await orch.engine.stop_all()
            console.print("[yellow]⏹ stopped[/]")
            return
        except ExecutionError as exc:
            console.print(f"[red]{exc}[/]")
            return
        finally:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.remove_signal_handler(signal.SIGINT)
        colour = "green" if res.ok else "yellow"
        console.print(f"[{colour}]{res.status}[/] · exit {res.exit_code} · execution "
                      f"#{res.execution_id}")
        if res.stdout.strip():
            console.print(res.stdout.rstrip()[:4000], markup=False, highlight=False)

    def _ensure_engine(self):
        if self._engine is None:
            if self.registry is None:
                return None
            self._engine = self.ctx.engine()
        return self._engine

    def cmd_ops(self, arg: str) -> None:
        cat = self.ctx.catalogue
        ops = cat.for_tool(arg.strip()) if arg.strip() else cat.all()
        t = Table(title=f"Registered operations ({len(ops)})", title_justify="left")
        for c in ("Operation", "Tool", "Level", "Summary"):
            t.add_column(c)
        for op in ops:
            style = {"passive": "green", "low": "cyan", "intrusive": "yellow",
                     "high_impact": "bold red"}.get(op.permission.value, "white")
            t.add_row(op.id, op.tool, f"[{style}]{op.permission.value}[/]", op.summary)
        console.print(t)
        console.print("[dim]/run <op> -t <target> [name=value]  — intrusive/high_impact ask "
                      "for approval first.[/]")

    async def run_op(self, arg: str) -> None:
        from blackarch_ai.execution.engine import ExecutionError, NotApproved
        from blackarch_ai.execution.operations import OperationError, ValidationError

        engine = self._ensure_engine()
        if engine is None:
            console.print("[yellow]Execution needs the tool registry, which is unavailable.[/]")
            return
        tokens = arg.split()
        if not tokens:
            console.print("Usage: /run <op> [-t target] [name=value] …  — see /ops")
            return
        op_id, target, params = tokens[0], None, {}
        rest = tokens[1:]
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok in ("-t", "--target"):
                target = rest[i + 1] if i + 1 < len(rest) else None
                i += 2
            elif "=" in tok:
                k, _, v = tok.partition("=")
                params[k] = v
                i += 1
            else:
                console.print(f"[red]don't understand {tok!r}[/] (use -t TARGET or name=value)")
                return
        scope = self.ctx.store.scope_of(self.engagement) if self.engagement else None
        try:
            plan = engine.plan(op_id, params, target,
                               engagement_id=self.engagement.id if self.engagement else None,
                               scope=scope)
        except (OperationError, ValidationError, ExecutionError) as exc:
            console.print(f"[red]{exc}[/]")
            return
        lvl = plan.permission.value
        console.print(f"[bold]{plan.operation.id}[/] [{_PERM[lvl]}]{lvl}[/] — "
                      f"[dim]{escape(plan.command_line)}[/]")
        if plan.target:
            sstyle = "green" if plan.scope_status == "in_scope" else "red"
            console.print(f"Target {escape(plan.target)}: [{sstyle}]{plan.scope_status}[/] "
                          f"[dim]{plan.scope_reason}[/]")
        if plan.blocked:
            console.print(f"[bold red]✗ blocked:[/] {plan.block_reason}")
            return
        approval = None
        if plan.needs_approval:
            answer = (await self._read_line(f"Approve this {lvl} operation? [y/N] ")).strip().lower()
            if answer not in ("y", "yes"):
                engine.record_approval(plan, "rejected")
                console.print("Rejected; nothing ran.")
                return
            approval = engine.record_approval(plan, "approved", reason="chat")
        task = asyncio.ensure_future(engine.run(plan, approval=approval))
        loop = asyncio.get_running_loop()
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signal.SIGINT, task.cancel)
        try:
            with console.status(f"running {plan.operation.id} (Ctrl+C cancels)…"):
                result = await task
        except asyncio.CancelledError:
            console.print("[yellow]⏹ cancelled — partial output kept as evidence[/]")
            return
        except NotApproved as exc:
            console.print(f"[red]{exc}[/]")
            return
        finally:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.remove_signal_handler(signal.SIGINT)
        colour = {"success": "green", "failed": "yellow"}.get(result.status, "red")
        console.print(f"[{colour}]{result.status}[/] · exit {result.exit_code} · "
                      f"{result.duration_s:.1f}s · execution #{result.execution_id}")
        if result.stdout.strip():
            console.print(result.stdout.rstrip()[:6000], markup=False, highlight=False)
        if result.stderr.strip():
            console.print("[dim]stderr:[/] " + result.stderr.rstrip()[:1500], markup=False)
        # Record a compact note so the orchestrator can discuss the result.
        self.ctx.store.add_message(self.session_id, "user",
                                   f"(ran operation {plan.operation.id} on {plan.target or '-'})")
        self.ctx.store.add_message(
            self.session_id, "assistant",
            f"Execution #{result.execution_id} {plan.operation.id} → {result.status} "
            f"(exit {result.exit_code}). Output:\n{result.stdout[:4000]}")

    async def _read_line(self, prompt: str) -> str:
        if self.plain or self._prompt is None:
            return await asyncio.to_thread(input, prompt)
        return await self._prompt.prompt_async(prompt)

    async def stop(self) -> None:
        engine = self._engine
        if engine is None or not engine.running_ids:
            console.print("[dim]Nothing is running.[/]")
            return
        n = await engine.stop_all()
        console.print(f"[red]⏹ emergency stop: terminated {n} running operation(s)[/]")

    def cmd_tools(self, arg: str) -> None:
        if self.registry is None:
            console.print("[yellow]Tool registry unavailable (pacman not found).[/]")
            return
        if arg.strip():
            hits = self.registry.search(arg, 10)
            if not hits:
                console.print("No matching installed tools.")
                return
            t = Table(title=f"Installed tools matching {arg.strip()!r}", title_justify="left")
            t.add_column("Tool", no_wrap=True)
            t.add_column("Version")
            t.add_column("Description")
            for h in hits:
                t.add_row(h.tool.name, h.tool.version, escape(h.tool.description))
            console.print(t)
            return
        counts = self.registry.agent_counts()
        scan = self.registry.last_scan()
        t = Table(title=f"Installed tools per agent ({self.registry.count()} total)",
                  title_justify="left")
        t.add_column("Agent")
        t.add_column("Tools", justify="right")
        for a in self.ctx.domains.agents:
            if a.categories or a.keywords:
                t.add_row(a.name, str(counts.get(a.id, 0)))
        t.add_row("Shared", str(counts.get("shared", 0)))
        console.print(t)
        if scan:
            console.print(f"[dim]Last scan {scan.finished_at:%Y-%m-%d %H:%M}. "
                          "/tools <what you want to do> searches by purpose.[/]")

    def handle_command(self, line: str) -> bool:
        """Run a slash command. Returns False when the user wants to exit."""
        cmd, _, arg = line.strip().partition(" ")
        cmd = cmd.lower()
        if cmd in ("/exit", "/quit"):
            return False
        if cmd in _PENDING:
            console.print(not_yet(*_PENDING[cmd]))
        elif cmd == "/tools":
            self.cmd_tools(arg)
        elif cmd == "/ops":
            self.cmd_ops(arg)
        elif cmd == "/queue":
            self.cmd_queue()
        elif cmd == "/report":
            self.cmd_report(arg)
        elif cmd == "/help":
            self.cmd_help(arg)
        elif cmd == "/agents":
            table, warnings = agents_table(self.ctx)
            console.print(table)
            for w in warnings:
                console.print(f"[yellow]⚠ {w}[/]")
        elif cmd == "/models":
            console.print(models_table(self.ctx))
            console.print(providers_table())
        elif cmd == "/scope":
            self.cmd_scope(arg)
        elif cmd == "/status":
            self.cmd_status(arg)
        elif cmd == "/history":
            self.cmd_history(arg)
        elif cmd == "/sessions":
            self.cmd_sessions(arg)
        elif cmd == "/clear":
            console.clear()
        elif cmd == "/auto":
            self.cmd_auto(arg)
        else:
            console.print(f"[red]Unknown command {cmd}[/] — try /help")
        return True

    def cmd_auto(self, arg: str) -> None:
        a = arg.strip().lower()
        if a in ("on", "yes", "true"):
            self.auto_trigger = True
        elif a in ("off", "no", "false"):
            self.auto_trigger = False
        elif a:
            console.print("Usage: /auto [on|off]")
            return
        state = "[green]on[/]" if self.auto_trigger else "[yellow]off[/]"
        console.print(f"Auto-run is {state}. When on, an objective you type "
                      "plans and runs automatically (up to intrusive; high-impact asks). "
                      "Questions are still just answered.")

    # ------------------------------------------------------------ main loop

    async def run(self) -> None:
        self.banner()
        # Show the tail of a resumed session so the user has context.
        if self.ctx.store.messages(self.session_id):
            console.print("[dim]Resumed — last messages:[/]")
            self.cmd_history("4")
        while True:
            line = await self._read()
            if line is None:
                break
            if not line.strip():
                continue
            stripped = line.strip()
            low = stripped.lower()
            if low.startswith("/ask"):
                await self.ask(stripped[4:].strip())
                continue
            if low == "/run" or low.startswith("/run "):
                await self.run_op(stripped[4:].strip())
                continue
            if low == "/stop":
                await self.stop()
                continue
            if low == "/plan" or low.startswith("/plan "):
                self._auto_engage(stripped[5:].strip())
                await self.orchestrate(stripped[5:].strip())
                continue
            if low == "/recon" or low.startswith("/recon "):
                self._auto_engage(stripped)
                await self.recon(stripped[6:].strip())
                continue
            if low == "/sniff" or low.startswith("/sniff "):
                self._auto_engage(stripped)
                await self.sniff(stripped[6:].strip())
                continue
            if low == "/attack" or low.startswith("/attack "):
                self._auto_engage(stripped)
                await self.attack(stripped[7:].strip())
                continue
            if low == "/decrypt" or low.startswith("/decrypt "):
                self._auto_engage(stripped)
                await self.decrypt(stripped[8:].strip())
                continue
            if low == "/assess" or low.startswith("/assess "):
                self._auto_engage(stripped)
                await self.assess(stripped[7:].strip())
                continue
            if low.startswith("/approve") or low.startswith("/reject"):
                await self.decide(stripped)
                continue
            if stripped.startswith("/"):
                if not self.handle_command(line):
                    break
                continue
            self._auto_engage(line)
            # Sniffing intent → interactive sniff menu (checked before recon, since
            # "sniff everyone on my network" also matches the network pattern).
            if (self.engagement is not None and self.registry is not None
                    and _SNIFF_RE.search(stripped)):
                await self.sniff(stripped)
                continue
            # Brute-force / password-attack intent → interactive attack menu.
            if (self.engagement is not None and self.registry is not None
                    and _ATTACK_RE.search(stripped)):
                await self.attack(stripped)
                continue
            # Decryption intent → mitmproxy setup flow.
            if (self.engagement is not None and self.registry is not None
                    and re.search(r"\bdecrypt\w*\b", stripped, re.IGNORECASE)):
                await self.decrypt(stripped)
                continue
            # Offensive network-wide intent ("hack everyone", "get their
            # credentials") → deterministic full assessment that actually runs
            # (recon → credential checks with approval), not the chatty LLM path.
            if (self.engagement is not None and self.registry is not None
                    and _PWN_RE.search(stripped)
                    and (_RECON_RE.search(stripped)
                         or any(w in low for w in ("everyone", "them", "their", "all ")))):
                await self.assess(stripped)
                continue
            if (self.auto_trigger and self.engagement is not None
                    and self.registry is not None and self._looks_like_objective(stripped)):
                # Network-wide discovery → deterministic recon (real scans, no LLM);
                # anything else → the LLM-planned pipeline.
                if _RECON_RE.search(stripped):
                    console.print("[dim]network discovery objective — running deterministic "
                                  "recon (real scans). /plan for the LLM pipeline instead.[/]")
                    await self.recon("")
                else:
                    await self.orchestrate(stripped, auto=True)
            else:
                await self.turn(line)
        self.ctx.store.audit("user", "chat.end", {}, session_id=self.session_id,
                             engagement_id=self.engagement.id if self.engagement else None)
        console.print("[dim]bye[/]")


def start_chat(ctx: Context, engagement_name: str | None, resume: str | None,
               plain: bool) -> int:
    if not ModelGateway(ctx.settings).candidates("orchestrator"):
        console.print("[red]No model is usable: none of the configured models has an API key.[/]\n"
                      "Run [bold]blackarch-ai setup[/] or add a key to "
                      "~/.config/blackarch-ai/.env")
        return 1
    store = ctx.store
    try:
        engagement = store.get_engagement(engagement_name) if engagement_name else None
    except StoreError as exc:
        console.print(f"[red]{exc}[/] — see [bold]blackarch-ai engagement list[/]")
        return 1
    eng_id = engagement.id if engagement else None

    if resume:
        try:
            if resume == "last":
                cs = store.latest_chat_session(eng_id)
                if cs is None:
                    raise StoreError("no previous session to resume")
            else:
                cs = store.get_chat_session(int(resume))
        except (StoreError, ValueError) as exc:
            console.print(f"[red]{exc}[/]")
            return 1
        if engagement is None and cs.engagement_id is not None:
            engagement = store.get_engagement(cs.engagement_id)
        elif engagement is not None and cs.engagement_id != engagement.id:
            console.print("[red]That session belongs to a different engagement.[/]")
            return 1
        session_id = cs.id
    else:
        session_id = store.create_chat_session(eng_id).id

    registry = ctx.registry if ctx.ensure_registry() else None
    app = ChatApp(ctx, engagement, session_id, plain=plain, registry=registry)
    asyncio.run(app.run())
    return 0
