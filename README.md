# BlackArch AI

A local-first, multi-agent assistant for **authorized** security assessments on
BlackArch Linux. You talk to one orchestrator; it plans the work, hands it to
specialist agents, and (in later phases) runs approved BlackArch tools locally
under a policy the LLM cannot override.

Cloud models do the reasoning. Execution, scope, approvals, evidence and the
audit log stay on your machine.

> **Status: Phases 1–6 done — the core framework is complete.** Chat, scoped
> engagements, the model gateway, persistence, auditing, the tool registry, 12
> specialist agents, the scope/approval-gated execution engine, the orchestrator
> (plan → run agents → approval queue → execute) and the consolidated report
> (Markdown/HTML/JSON) all work. 123 tests pass. Phase 7 (optimization/polish)
> is optional future work.

## Install

BlackArch AI runs inside the `blackarch` toolbox (that's where pacman and the
tools live). From the repository:

```bash
toolbox run -c blackarch bash -c '
  cd ~/blackarch-ai &&
  python3 -m venv --system-site-packages .venv &&
  .venv/bin/pip install -e ".[dev]"'
ln -s ~/blackarch-ai/bin/blackarch-ai ~/.local/bin/blackarch-ai
```

`bin/blackarch-ai` runs the app inside the toolbox when called from the host,
and directly when already inside a container. Set `BLACKARCH_AI_TOOLBOX` to use
a different container name.

## Setup

```bash
blackarch-ai setup --keys     # writes config, prompts for missing API keys (hidden input)
blackarch-ai setup --test     # sends one tiny request per role through the real gateway
```

| File | Purpose |
|---|---|
| `~/.config/blackarch-ai/config.toml` | model routing, retries, pricing, redaction |
| `~/.config/blackarch-ai/.env` | API keys only, mode 0600 (`.env.example` lists the variables) |
| `~/.local/share/blackarch-ai/blackarch-ai.db` | SQLite: engagements, chats, model usage, audit log |

Override locations with `BLACKARCH_AI_CONFIG_DIR` / `BLACKARCH_AI_DATA_DIR`.

### Models

Every role has a model chain, tried in order; models whose provider has no
key are skipped. Roles: `orchestrator`, `agent` (default for all agents), or a
specific agent id (`web`, `network`, …) for a per-agent override.

| Provider | LiteLLM prefix | Key |
|---|---|---|
| NVIDIA API Catalog (default) | `nvidia_nim/` | `NVIDIA_NIM_API_KEY` |
| Anthropic | `anthropic/` | `ANTHROPIC_API_KEY` |
| OpenAI | `openai/` | `OPENAI_API_KEY` |
| Google Gemini | `gemini/` | `GEMINI_API_KEY` |

Defaults were chosen with a benchmark (JSON output, tool calling, security
knowledge and latency) run on the free NVIDIA endpoint on 2026-11-11:

| Role | Primary | Fallbacks |
|---|---|---|
| orchestrator | `stepfun-ai/step-5-preview` (~5–25 s) | Nemotron 3.5 Lightning, Mistral Large 4, MiniMax M3.1, then Anthropic/OpenAI/Gemini if keyed |
| agent | `nvidia/nemotron-3.5-lightning-30b-a3b` (~2–5 s) | Step-5, Mistral Large 4, MiniMax M3.1, then Anthropic/OpenAI/Gemini if keyed |

Not used: Nemotron 3 Ultra returned empty or garbled output unless
`chat_template_kwargs.enable_thinking` was set, and skipped tool calls even
with it set. DeepSeek V4.1 Flash and GLM 5.3 Flash timed out. Kimi K2.6,
Nemotron 3 Super and Gemma 4 returned "not found" for this key.
Free-endpoint latency varies with load. Re-test with `blackarch-ai models test`.

LiteLLM has no prices for these models, so cost shows as *unknown*. Add
`[llm.pricing."<model>"]` to config.toml to track it.

## Usage

```bash
# Define what you're authorized to test (asks you to confirm authorization)
blackarch-ai engagement create homelab -t 10.0.0.0/24 -t '*.lab.example' -x 10.0.0.1 \
    -o "Quarterly home-lab review" --authorized-by "me"
blackarch-ai engagement list
blackarch-ai engagement show homelab        # scope, usage, recent audit events
blackarch-ai engagement check homelab 10.0.0.7 8.8.8.8

# Chat
blackarch-ai                 # general chat, no engagement
blackarch-ai -e homelab      # chat inside an engagement's scope
blackarch-ai -r last         # resume the latest session (or -r <id>)
blackarch-ai --plain         # plain output for basic terminals / pipes

blackarch-ai tools scan                      # rebuild the tool registry (~2 s)
blackarch-ai tools list --agent web          # installed tools, per agent or --category
blackarch-ai tools show nmap                 # version, commands, agents, man summary (--man for the page)
blackarch-ai tools search smb share enumeration   # find installed tools by purpose

blackarch-ai agents list     # agents, their categories and installed-tool counts
blackarch-ai agents show web --prompt -e homelab   # ceiling, model chain, full prompt
blackarch-ai agents ask web "review the login flow on http://10.0.0.20" -e homelab
blackarch-ai agents tasks -e homelab               # history; --show ID for one report

# Run real tools (scope- and approval-gated)
blackarch-ai ops list                              # registered operations; ops show ID for details
blackarch-ai run nmap-tcp-connect -t 10.0.0.5 -p ports=22,80,443 -e homelab
blackarch-ai run nmap-service-scan -t 10.0.0.5 -e homelab          # intrusive → asks to approve
blackarch-ai run nikto-scan --target http://10.0.0.5 -e homelab -y # -y pre-approves
blackarch-ai exec list -e homelab                  # execution history; exec show ID for evidence

# Orchestrate: plan a goal, run agents, queue/run operations
blackarch-ai orchestrate "map services on the lab and flag outdated web servers" -e homelab
blackarch-ai plan queue -e homelab                 # operations awaiting approval
blackarch-ai plan approve 3 -e homelab             # run a queued operation
blackarch-ai plan reject 4 -e homelab
blackarch-ai plan list -e homelab

# Report the engagement (Markdown / HTML / JSON)
blackarch-ai report homelab --format all --summary   # --summary adds an AI exec summary
blackarch-ai report homelab -f md --stdout
blackarch-ai models list     # routing, keys, pricing
blackarch-ai models test
```

In chat: `/help /agents /ask <agent> <task> /ops [tool] /run <op> [-t target]
[name=value] /stop /plan <objective> /queue /approve <id> /reject <id>
/report [md|html|json] /models /tools [text] /scope /status /history [n]
/sessions /clear /exit`. `/plan` orchestrates a goal; `/queue`, `/approve` and
`/reject` work the approval queue; `/run` executes one operation; `/stop` is the
emergency stop; `/report` writes the engagement report. `/ask`, `/run` and
`/plan` results are saved to the chat history, so the orchestrator can discuss
them. `/plan /approve /reject /report` are listed but say
that they arrive in later phases. With each message, the orchestrator gets the
installed tools that match it, so it recommends tools you actually have. **Ctrl+C** cancels a reply in progress (the
partial text is kept and marked interrupted); **Ctrl+D** exits.

## Agents and BlackArch categories

All 52 `blackarch-*` package groups are assigned to an agent (or the shared
pool) in [`src/blackarch_ai/data/agents.toml`](src/blackarch_ai/data/agents.toml).
`agents list` checks the mapping against pacman and warns about any upstream
category that isn't assigned.

| Agent | Categories |
|---|---|
| Recon & OSINT | recon, reocn¹, social, fingerprint |
| Network | networking, scanner, sniffer, spoof, tunnel, proxy, dos, voip |
| Web Application | webapp, fuzzer, database |
| Wireless & RF | wireless, bluetooth, radio, nfc, drone, automobile |
| System | windows, config |
| Exploitation | exploitation, backdoor, keylogger, automation |
| Credentials & Crypto | cracker, crypto, wordlist, gpu, stego |
| Reverse Engineering & Hardware | reversing, binary, disassembler, decompiler, debugger, packer, unpacker, malware, firmware, hardware, mobile |
| Forensics & Defense | forensic, anti-forensic, defensive, ids, honeypot |
| Vulnerability Intelligence | code-audit, threat-model, ai |
| Cloud Security | none upstream; claims tools by keyword (aws, azure, gcp, k8s…) |
| Reporting | none; works from findings |
| *Shared (all agents)* | misc |

¹ `reocn` is an upstream typo of "recon"; it is mapped so its tool isn't lost.

`backdoor`, `keylogger`, `anti-forensic` and `dos` are marked **high-impact**:
once execution exists, their tools will always require explicit per-operation
approval.

## Agents

Each domain in `data/agents.toml` becomes an instance of `agents/base.py:Agent`
with its own model profile (`[llm.profiles.<id>]`, default `agent`). A task
returns a structured report: summary, analysis, recommended steps (tool,
target, purpose, permission level), unverified hypotheses with confidence,
out-of-scope notes, and help requests to other agents.

**Local checks run on every report, independent of the model:**

| Check | Effect |
|---|---|
| Tool not in the registry | flagged `not installed` |
| Tool owned by another agent | noted |
| Tool from a high-impact category | step raised to `high_impact` |
| Step touches a target but claims `passive` | raised to `low` (passive = no contact) |
| Target outside scope, or no engagement | step **blocked** |
| Network target overlapping exclusions | allowed, reason lists what must be skipped |
| Step above the agent's ceiling | step **blocked** |
| `intrusive` / `high_impact` | `needs approval` |
| CVE IDs anywhere in the report | issue: cited from memory, verify against NVD/vendor |
| Hypotheses | always `verified = false` |
| Help request to self, unknown or disabled agent, or more than 3 | dropped |

Permission ceilings: forensics, vulnintel and reporting are `passive`; recon,
reversing and cloud are `low`; network, web, wireless, system and credentials
are `intrusive`; exploitation is `high_impact`.

**Collaboration:** agents talk only through the message bus (`agent_message`
table: task → result, help_request → help_reply). An agent's help requests are
delivered to the peers concurrently, one hop deep, and their answers are shown
with the original report. A later task for an agent includes the replies
addressed to it. Every task is stored in `agent_task` with its parent.

**Configuration** (`config.toml`):

```toml
[agents.exploitation]
enabled = false                 # leave an agent out entirely
[agents.web]
max_permission = "low"          # can lower the ceiling, never raise it
extra_instructions = "The client forbids authenticated testing."
[llm.profiles.vulnintel]         # give one agent its own model
model = "nvidia_nim/mistralai/mistral-large-4-1t-a52b"
```

A specialised class can replace the default for one id with
`@register_agent("web")`.

## Reporting

`report <engagement>` (or `/report` in chat) consolidates the engagement into a
**Markdown, HTML or JSON** file (`--format md|html|json|all`, `--out <path>`,
`--stdout`). It is assembled deterministically from the database
(`reports/report.py` → `reports/render.py`) and keeps three kinds of statement
apart, as the spec requires:

- **Verified results** — facts produced by executed tools, with evidence;
- **Hypotheses to verify** — the agents' unverified reasoning, by confidence,
  explicitly *not* confirmed vulnerabilities;
- **Assets** and an **operations log** with evidence file paths and SHA-256.

`--summary` adds an **executive summary written by the model** from only that
data, clearly labelled as AI-generated and advisory — it never becomes a
confirmed finding. The HTML is a self-contained themed page (light/dark). JSON
is for feeding another tool. Findings come from orchestrated runs (agent
hypotheses + auto-run results); a one-off `run` records an execution but no
finding, so its report shows the operation without a finding.

## Orchestration

`orchestrate "<objective>"` (or `/plan <objective>` in chat) runs the full loop:

1. **Plan** — the orchestrator model turns the objective into a task plan: one
   step per specialist agent, ordered, with dependencies. The plan is validated
   locally (unknown/disabled agents and forward/dangling dependencies are
   dropped) and saved.
2. **Run agents** — each agent runs in dependency order (Phase 3), and the
   **shared context** (`core/context.py`: assets and findings in the `asset`
   and `finding` tables) flows forward, so later agents see what earlier ones
   found. Agent hypotheses become unverified findings; in-scope targets become
   assets.
3. **Map to operations** — each recommended step is matched to a registered
   operation for that tool and validated through the engine (scope, arguments).
4. **Route**, by mode:
   - *auto-safe* (default): passive/low, in-scope, fully-specified operations
     run immediately; intrusive/high-impact go to the **approval queue**;
   - *--manual*: everything is queued;
   - *--plan-only*: agents run, nothing is executed.
   Out-of-scope or above-ceiling steps are dropped by the agent's own checks;
   operations missing a required parameter are listed as `needs_params`
   (advisory). An auto-run result is recorded as a verified finding, feeding
   later steps.
5. **Approve** — `plan queue` lists pending operations; `plan approve <id>`
   re-checks scope, records an approval and runs it through the engine;
   `plan reject <id>` drops it. The orchestrator never bypasses scope or the
   approval requirement — it only automates the already-authorized safe part.

## Execution engine

The engine (`execution/engine.py`) is the only path from an operation to a
running process. Nothing else may spawn a tool, and the LLM never does.

**Operations, not shell.** The engine runs only operations registered in
[`data/operations.toml`](src/blackarch_ai/data/operations.toml). An operation
is a tool plus a fixed argument template with typed, validated parameters
(string/int/enum/bool, choices, ranges, regex). It renders to an **argv list**
passed to `create_subprocess_exec` — there is no shell, so a parameter value
can neither inject a command nor smuggle an extra flag (values that start with
`-`, contain control characters, or fail their pattern are rejected). Add your
own operations — including offensive ones — to the TOML; set `permission`
honestly.

**The run pipeline** (spec §8): validate inputs → resolve the executable to an
absolute path from the registry → check the target against the engagement scope
→ check permission → **require an approval record for intrusive/high-impact** →
run in its own process session with a timeout and a 5 MB per-stream output cap →
store stdout/stderr as evidence (with SHA-256) → write the audit log. A blocked
plan (out of scope, no engagement, missing target) never runs. `--dry-run`
shows the plan and exits.

**Approval.** `run` previews the exact argv; a passive/low operation runs
immediately, an intrusive/high-impact one asks you to confirm (or `-y`), and the
decision is recorded in the `approval` table. Approval doesn't restrict which
tools can run — you can register and approve anything — it just means a human
confirms the intrusive ones.

**Emergency stop.** Ctrl+C cancels the operation in progress (partial output is
kept as evidence); `/stop` in chat kills every running process group. Every run
is persisted in `tool_execution` with its `evidence` rows.

Shipped operations (starter set — extend in the TOML): `dns-lookup`, `whois`,
`nmap-ping-sweep`, `nmap-tcp-connect`, `nmap-service-scan`, `whatweb`,
`wafw00f`, `sslscan`, `nikto-scan`, `gobuster-dir`, `smb-list-shares`.

## Tool discovery

`tools scan` builds the registry from pacman metadata. **It never runs a tool
binary.** It reads:

- installed members of every `blackarch-*` group (category = group name), plus
  Arch-repo security tools listed in
  [`data/extra_tools.toml`](src/blackarch_ai/data/extra_tools.toml) (nmap,
  sqlmap, hashcat, aircrack-ng… which BlackArch doesn't group);
- `pacman -Qi`: version, description, URL, groups;
- `pacman -Ql`: executables in `/usr/bin` and English man pages (sections 1, 5, 8);
- man pages rendered with `man` into a SQLite FTS5 index (porter stemming,
  with name/description weighted above man-page text) for `tools search`.

Each tool records its categories, owning agents (the Cloud agent claims tools
by keyword) and a permission class: `high_impact` for tools in high-impact
categories, otherwise `unclassified` until operations are defined. The registry
scans itself the first time it's used, and warns when pacman's database has
changed since the last scan.

## Security model (what exists today)

- **Scope** (`security/scope.py`): IPs, CIDRs, hostnames, `*.domain`
  wildcards and URLs, with exclusions that win over inclusions. IPv4 ranges
  broader than /16 (IPv6 /48) and TLD-wide wildcards are refused unless
  `--allow-broad`. Hostnames never match raw IPs (no DNS assumptions).
  Creating an engagement requires confirming authorization, which is audited.
- **Redaction** (`security/redaction.py`): before anything is sent to a cloud
  model, private keys, provider/GitHub/Slack/AWS tokens, JWTs, bearer headers,
  URL credentials, `password=`/`token:`-style values, the literal values of
  secret-looking environment variables and your own `extra_patterns` are
  replaced with `[REDACTED]`. The local database keeps the original.
- **Honest capabilities**: the orchestrator's system prompt states that it
  cannot execute anything yet and must not claim results; it is given the
  engagement scope and told to refuse out-of-scope targets.
- **Audit log**: engagement creation, chat start/end, setup and every model
  call (model, tokens, cost, latency, error, redaction counts).

## Architecture

```
src/blackarch_ai/
├── main.py                 entry point
├── config.py               defaults + config.toml + .env
├── cli/                    Typer commands, Rich chat UI, setup
├── core/
│   ├── conversation.py     orchestrator chat turn handling + persistence
│   └── domains.py          agent ↔ category map loader/validator
├── agents/
│   ├── base.py             Agent: prompt, model call, local policy checks
│   ├── schema.py           AgentReport (model output) / CheckedReport (after checks)
│   ├── directory.py        registration, config overrides, custom classes
│   ├── bus.py              message bus + task log (SQLite)
│   └── consult.py          run an agent, deliver help requests one hop
├── execution/
│   ├── operations.py       operation definitions + argv rendering/validation
│   └── engine.py           scope/approval-gated subprocess execution + evidence
├── orchestrator/
│   ├── plan.py             task-plan schema + validation
│   └── orchestrator.py     plan → run agents → map ops → approval queue
├── core/context.py         shared assets/findings + digest for agents
├── reports/
│   ├── report.py           assemble report data from the store (deterministic)
│   ├── render.py           Markdown / JSON / self-contained HTML
│   └── summary.py          optional model-written executive summary
├── llm/
│   ├── gateway.py          routing, retry, fallback, streaming, JSON output, usage
│   ├── pricing.py          cost estimation (unknown stays unknown)
│   └── providers/          provider registry and key detection
├── security/               scope, redaction, permission levels
├── storage/                SQLAlchemy models + Store
├── tools/
│   ├── pacman.py           read-only pacman queries and parsers
│   ├── discovery.py        installed packages → ToolRecords (no binaries run)
│   ├── documentation.py    man page rendering and summaries
│   └── registry.py         persisted registry, FTS search, LLM context
├── data/extra_tools.toml   Arch-repo security tools → categories
└── data/agents.toml        agent domains
```

Gateway behaviour worth knowing:

- Transient errors (rate limit, timeout, connection, 5xx) are retried
  `max_retries` times with exponential backoff, then the next model is tried.
  Permanent errors (bad key, bad request) skip straight to the next model.
- While streaming, fallback only happens if the failing model hasn't produced
  answer text yet. Otherwise the partial reply is kept and the error shown —
  it never silently stitches two models' answers together.
- Structured output: the JSON schema of a Pydantic model is sent with the
  request, the reply is parsed (code fences/prose tolerated) and validated,
  with one repair round on failure.
- `reasoning_effort` and other parameters are sent with LiteLLM's
  `drop_params`, so unsupported ones are dropped per provider.

## Tests

```bash
toolbox run -c blackarch bash -c 'cd ~/blackarch-ai && .venv/bin/python -m pytest'
```

Tests use a scripted fake model and temporary directories; they never call a
real provider or touch your config. Use `blackarch-ai models test` for a live
check.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 1 | CLI, config, model gateway, chat, persistence | **done** |
| 2 | Tool discovery: pacman packages, executables, versions, man indexing, tool registry | **done** |
| 3 | Agent framework: base agent, registration, prompts, structured messaging, per-agent models | **done** |
| 5 | Execution engine: validated operations, process manager, permissions, emergency stop | **done** |
| 4 | Orchestrator: planning, shared context, agent delegation, approval queue | **done** |
| 6 | Reporting (Markdown/HTML/JSON) from findings and evidence | **done** |
| 7 | Concurrency, cost optimization, memory management, UI polish | optional |

### Known gaps

- Conversation memory is a sliding window of the last 40 messages, with no summarization.
- Redaction is pattern-based. It won't catch every secret format, and it doesn't hide target
  IPs or hostnames, which the model needs for reasoning.
- No `/engagement` switch inside chat; restart with `-e NAME`.
- Engagements can't be edited or archived from the CLI yet.
- Cost is unknown for models LiteLLM has no price for (including the defaults)
  until you add a pricing entry.
- `--help` output isn't captured. Running arbitrary binaries isn't safe without
  the sandboxed execution engine (Phase 5). Only 57 of 391 tools ship man pages,
  so the rest are found through their name and pacman description only.
- No runnable operations are defined yet (input schemas and per-operation
  permission levels). That's still to be designed, together with Phase 5.
- Tool versions are package versions (`pacman -Q`), which can differ from the
  version a tool reports about itself.
- Agents are consulted by you (`agents ask`, `/ask`). The orchestrator can't
  delegate on its own yet, and help requests only go one hop deep.
- Vulnerability intelligence comes from model memory, so it's unverified. In
  testing, models named CVEs that don't apply to the version asked about, and
  got release dates wrong. Every CVE ID is flagged, but checking against
  NVD/vendor data needs a real data source (planned).
- Shared engagement context has no assets or findings yet. Agents see the
  scope, objective and earlier replies addressed to them.
- Free-endpoint latency: one agent consult takes roughly 20–120 s, and a
  consult with help requests adds a second round.
- The orchestrator auto-runs only passive/low, in-scope operations; everything
  intrusive/high-impact waits in the approval queue for you. Agents are
  consulted one hop deep (no recursive delegation), and the whole run is
  sequential, so a multi-agent plan against the slow free endpoint can take
  several minutes.
- Step→operation mapping is by tool name against the starter catalogue; a step
  whose tool has no registered operation, or needs a parameter the orchestrator
  can't fill (e.g. a wordlist), is listed as advisory (`needs_params`), not run.
- Findings are the agents' hypotheses (unverified) plus auto-run results
  (verified). There's no parsing of tool output into structured assets yet.
- The operation catalogue is a starter set (recon/scan/web/SMB). Add more in
  `data/operations.toml`; nothing auto-generates operations from `--help`.
- Output is capped at 5 MB per stream and tools run with a per-operation
  timeout; a long scan can hit it (raise `timeout` in the operation).
