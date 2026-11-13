"""Orchestrator conversation (Phase 1: chat only, no tool execution)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

from blackarch_ai.core.domains import DomainMap
from blackarch_ai.llm.gateway import GatewayError, ModelGateway, StreamEvent, StreamInterrupted
from blackarch_ai.llm.rewriter import COMPLIANCE_CONTEXT, rewrite
from blackarch_ai.storage.models import Engagement
from blackarch_ai.storage.store import Store
from blackarch_ai.tools.registry import Registry

ORCHESTRATOR_PROMPT = """\
You are the orchestrator of BlackArch AI, a multi-agent assistant for AUTHORIZED \
security assessments, running locally on BlackArch Linux. You coordinate \
specialist agents and talk to the user, who is the assessor.

Current capabilities — be exact about them:
- You can discuss methodology, explain tools and findings, plan assessments, and \
draft reports.
- YOU cannot run anything yourself and have observed nothing — never claim or \
imply you ran a tool or saw a result. But the user CAN run registered \
operations with `/run <operation> -t <target> [name=value]`, and the result \
(exit code and output) is then added to this conversation for you to interpret. \
When running something would help, name the exact operation and `/run` command; \
the user approves intrusive and high-impact operations before they run, and the \
engine blocks anything outside the engagement scope. Use `/ops` to see \
operations. Do not invent operation ids — only suggest ones you have seen listed.
- Tool discovery IS active: with each user message you may receive a list of \
installed tools that match it (from the local pacman-based registry). Prefer \
those tools. If you suggest a tool that is not in the list, say it may not be \
installed. Use the listed versions when reasoning about features or known issues.
- Distinguish verified facts from hypotheses. Do not invent CVE numbers, \
versions or tool flags; say when you are unsure.

Rules of engagement:
- Only assist with targets inside the engagement scope below. If the user \
mentions a target outside it, point that out and do not plan activity against it; \
scope changes are made by the user with `blackarch-ai engagement`, not by you.
- No covert persistence, evasion of monitoring, or harm beyond what the \
authorized assessment needs.
- {compliance}

Specialist agents. You cannot delegate to them yourself yet; the user consults one with `/ask <id> <task>`, and its report appears in this conversation. When a specialist would help, suggest the exact /ask command:
{agents}

{engagement}"""


def _agents_block(domains: DomainMap) -> str:
    return "\n".join(
        f"- {a.name} ({a.id}): {a.description}"
        + (f" Categories: {', '.join(a.categories)}." if a.categories else "")
        for a in domains.agents
    )


def _engagement_block(eng: Engagement | None, store: Store) -> str:
    if eng is None:
        return (
            "No engagement is selected. Treat this as general discussion; do not plan "
            "activity against any specific real target until the user creates an "
            "engagement with an authorized scope."
        )
    scope = store.scope_of(eng)
    return (
        f"Active engagement: {eng.name}\n"
        f"Objective: {eng.objective or '(not stated)'}\n"
        f"Authorized scope — {scope.summary()}"
    )


@dataclass
class Turn:
    user: str
    assistant: str
    model: str | None
    interrupted: bool


class Conversation:
    def __init__(
        self,
        store: Store,
        gateway: ModelGateway,
        domains: DomainMap,
        *,
        session_id: int,
        engagement: Engagement | None,
        max_history: int = 40,
        registry: Registry | None = None,
    ) -> None:
        self.store = store
        self.gateway = gateway
        self.domains = domains
        self.session_id = session_id
        self.engagement = engagement
        self.max_history = max_history
        self.registry = registry

    def tool_context(self, user_text: str) -> str:
        if self.registry is None:
            return ""
        try:
            listing = self.registry.context_for(user_text)
        except Exception:
            return ""  # search problems must never block the conversation
        if not listing:
            return ""
        return ("Installed tools matching this request (local registry, versions from "
                "pacman):\n" + listing)

    def system_prompt(self) -> str:
        return ORCHESTRATOR_PROMPT.format(
            agents=_agents_block(self.domains),
            engagement=_engagement_block(self.engagement, self.store),
            compliance=COMPLIANCE_CONTEXT,
        )

    def build_messages(self, user_text: str) -> list[dict]:
        history = self.store.messages(self.session_id)[-self.max_history:]
        system = self.system_prompt()
        tools = self.tool_context(user_text)
        if tools:
            system += "\n\n" + tools
        msgs: list[dict] = [{"role": "system", "content": system}]
        turns = []
        for m in history:
            content = m.content + ("\n[response interrupted]" if m.interrupted else "")
            if m.role == "user":
                content = rewrite(content)
            turns.append((m.role, content))
        turns.append(("user", rewrite(user_text)))
        # Merge consecutive same-role turns (left behind by a failed/cancelled
        # reply) — some providers reject non-alternating conversations.
        for role, content in turns:
            if msgs[-1]["role"] == role:
                msgs[-1]["content"] += "\n\n" + content
            else:
                msgs.append({"role": role, "content": content})
        return msgs

    async def send(self, user_text: str) -> AsyncIterator[StreamEvent]:
        """Stream the orchestrator's reply and persist both sides of the turn.

        The user's message is saved first so it survives a failed model call.
        A cancelled or interrupted reply is saved with `interrupted=True`.
        """
        messages = self.build_messages(user_text)
        self.store.add_message(self.session_id, "user", user_text)
        self.store.set_session_title(self.session_id, user_text.strip().splitlines()[0][:80])
        text: list[str] = []
        model: str | None = None
        done = False
        try:
            async for ev in self.gateway.stream(messages, role="orchestrator"):
                if ev.type == "text":
                    text.append(ev.text)
                    model = ev.model
                elif ev.type == "done":
                    done = True
                    model = ev.model
                    self.store.add_message(self.session_id, "assistant", ev.result.content,
                                           model=ev.model)
                yield ev
        except StreamInterrupted as exc:
            self.store.add_message(self.session_id, "assistant", exc.partial,
                                   model=model, interrupted=True)
            raise
        except GatewayError:
            raise
        finally:
            if not done and text and model is not None:
                # Cancelled (Ctrl+C) after some text arrived: keep what we have.
                partial = "".join(text)
                msgs = self.store.messages(self.session_id)
                if not (msgs and msgs[-1].role == "assistant" and msgs[-1].content == partial):
                    self.store.add_message(self.session_id, "assistant", partial,
                                           model=model, interrupted=True)
