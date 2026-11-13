"""Render a ReportData to Markdown, JSON and self-contained HTML."""

from __future__ import annotations

import json
from html import escape

from blackarch_ai.reports.report import FindingRef, ReportData

DISCLAIMER = (
    "This report is for an authorized security assessment. Hypotheses are "
    "unverified AI-generated reasoning and must be confirmed before being "
    "treated as vulnerabilities."
)


def _ts(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "—"


# ---------------------------------------------------------------- Markdown

def render_markdown(r: ReportData) -> str:
    c = r.counts
    out: list[str] = [f"# Security assessment — {r.engagement_name}", ""]
    out += [f"- **Objective:** {r.objective or '—'}",
            f"- **Authorized by:** {r.authorized_by or '—'}",
            f"- **Scope:** {r.scope}",
            f"- **Status:** {r.status}",
            f"- **Engagement created:** {_ts(r.engagement_created)}",
            f"- **Report generated:** {_ts(r.generated_at)}", ""]
    out += [f"**Summary:** {c['assets']} assets · {c['verified']} verified results · "
            f"{c['hypotheses']} hypotheses to verify · {c['executions']} operations run "
            f"({c['executions_ok']} succeeded).", ""]

    if r.summary:
        out += ["## Executive summary", "",
                f"> _AI-generated from the data below ({r.summary.model}); advisory, "
                "not a confirmed finding._", "", r.summary.overview, ""]
        if r.summary.recommendations:
            out += ["### Recommendations", ""]
            out += [f"{i}. {rec}" for i, rec in enumerate(r.summary.recommendations, 1)]
            out += [""]

    out += ["## Assets", ""]
    if r.assets:
        out += ["| Kind | Value | Source |", "|------|-------|--------|"]
        out += [f"| {a.kind} | {a.value} | {a.source or '—'} |" for a in r.assets]
    else:
        out += ["_None recorded._"]
    out += [""]

    out += ["## Verified results", "",
            "_Facts produced by executed tools (see Evidence)._", ""]
    out += _md_findings(r.verified) + [""]

    out += ["## Hypotheses to verify", "",
            "_Unverified AI reasoning. Confirm before acting._", ""]
    out += _md_findings(r.hypotheses, show_conf=True) + [""]

    out += ["## Operations run", ""]
    if r.executions:
        out += ["| # | Operation | Target | Level | Status | Exit | Evidence |",
                "|---|-----------|--------|-------|--------|------|----------|"]
        for e in r.executions:
            ev = "<br>".join(f"{x.kind}: `{x.path}`" for x in e.evidence) or "—"
            out.append(f"| {e.id} | {e.operation} | {e.target or '—'} | {e.permission} | "
                       f"{e.status} | {e.exit_code if e.exit_code is not None else '—'} | {ev} |")
    else:
        out += ["_No operations were executed._"]
    out += [""]

    if r.plans:
        out += ["## Plans", ""]
        out += [f"- #{p.id} ({p.status}, {len(p.steps or [])} steps): {p.objective}"
                for p in r.plans]
        out += [""]

    u = r.usage
    out += ["## Model usage", "",
            f"- Calls: {u.calls} ({u.failed} failed)",
            f"- Tokens: {u.prompt_tokens} in / {u.completion_tokens} out",
            f"- Estimated cost: "
            + (f"${u.cost_usd:.4f}" if u.unpriced_calls == 0 else "unknown (unpriced models)"),
            "", "---", "", f"_{DISCLAIMER}_", ""]
    return "\n".join(out)


def _md_findings(items: list[FindingRef], show_conf: bool = False) -> list[str]:
    if not items:
        return ["_None._"]
    lines = []
    for f in items:
        tag = f"**[{f.severity}]**" + (f" _{f.confidence} confidence_" if show_conf else "")
        who = f" ({f.agent})" if f.agent else ""
        lines.append(f"- {tag} {f.title}{who}")
        if f.description:
            lines.append(f"  - {f.description}")
    return lines


# ---------------------------------------------------------------- JSON

def render_json(r: ReportData) -> str:
    def finding(f: FindingRef) -> dict:
        return {"title": f.title, "description": f.description, "severity": f.severity,
                "confidence": f.confidence, "verified": f.verified, "agent": f.agent}

    data = {
        "engagement": {"name": r.engagement_name, "objective": r.objective,
                       "authorized_by": r.authorized_by, "scope": r.scope, "status": r.status,
                       "created": r.engagement_created.isoformat() if r.engagement_created else None},
        "generated_at": r.generated_at.isoformat(),
        "disclaimer": DISCLAIMER,
        "counts": r.counts,
        "executive_summary": (
            {"overview": r.summary.overview, "recommendations": r.summary.recommendations,
             "model": r.summary.model, "ai_generated": True} if r.summary else None),
        "assets": [{"kind": a.kind, "value": a.value, "source": a.source} for a in r.assets],
        "verified_results": [finding(f) for f in r.verified],
        "hypotheses": [finding(f) for f in r.hypotheses],
        "operations": [
            {"id": e.id, "operation": e.operation, "tool": e.tool, "target": e.target,
             "permission": e.permission, "status": e.status, "exit_code": e.exit_code,
             "argv": e.argv, "created_at": e.created_at.isoformat(),
             "evidence": [{"kind": x.kind, "path": x.path, "size_bytes": x.size_bytes,
                           "sha256": x.sha256} for x in e.evidence]}
            for e in r.executions],
        "plans": [{"id": p.id, "objective": p.objective, "status": p.status,
                   "steps": len(p.steps or [])} for p in r.plans],
        "model_usage": {"calls": r.usage.calls, "failed": r.usage.failed,
                        "prompt_tokens": r.usage.prompt_tokens,
                        "completion_tokens": r.usage.completion_tokens,
                        "cost_usd": r.usage.cost_usd if r.usage.unpriced_calls == 0 else None},
    }
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------- HTML

_SEV_COLOR = {"critical": "#b3123b", "high": "#d7263d", "medium": "#e08a00",
              "low": "#2a7ab0", "info": "#5a6b7b"}


def _badge(text: str, color: str) -> str:
    return (f'<span class="badge" style="background:{color}">{escape(text)}</span>')


def _html_findings(items: list[FindingRef], show_conf: bool) -> str:
    if not items:
        return '<p class="muted">None.</p>'
    rows = []
    for f in items:
        conf = f' {_badge(f.confidence + " confidence", "#444")}' if show_conf else ""
        who = f' <span class="muted">({escape(f.agent)})</span>' if f.agent else ""
        desc = f'<div class="desc">{escape(f.description)}</div>' if f.description else ""
        rows.append(f'<li>{_badge(f.severity, _SEV_COLOR.get(f.severity, "#5a6b7b"))}{conf} '
                    f'{escape(f.title)}{who}{desc}</li>')
    return '<ul class="findings">' + "".join(rows) + "</ul>"


def render_html(r: ReportData) -> str:
    c = r.counts
    rows = []
    for e in r.executions:
        ev = "<br>".join(f'{escape(x.kind)}: <code>{escape(x.path)}</code>'
                         for x in e.evidence) or "—"
        status_cls = "ok" if e.status == "success" else "warn"
        rows.append(
            f"<tr><td>{e.id}</td><td>{escape(e.operation)}</td><td>{escape(e.target or '—')}</td>"
            f"<td>{escape(e.permission)}</td><td class='{status_cls}'>{escape(e.status)}</td>"
            f"<td>{e.exit_code if e.exit_code is not None else '—'}</td><td>{ev}</td></tr>")
    exec_table = (
        "<table><thead><tr><th>#</th><th>Operation</th><th>Target</th><th>Level</th>"
        "<th>Status</th><th>Exit</th><th>Evidence</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>" if r.executions
        else '<p class="muted">No operations were executed.</p>')

    assets = ("<table><thead><tr><th>Kind</th><th>Value</th><th>Source</th></tr></thead><tbody>"
              + "".join(f"<tr><td>{escape(a.kind)}</td><td>{escape(a.value)}</td>"
                        f"<td>{escape(a.source or '—')}</td></tr>" for a in r.assets)
              + "</tbody></table>" if r.assets else '<p class="muted">None recorded.</p>')

    summary_html = ""
    if r.summary:
        recs = "".join(f"<li>{escape(x)}</li>" for x in r.summary.recommendations)
        summary_html = (
            f'<section><h2>Executive summary</h2>'
            f'<p class="ai-note">AI-generated from the data below '
            f'({escape(r.summary.model)}); advisory, not a confirmed finding.</p>'
            f'<p>{escape(r.summary.overview)}</p>'
            + (f"<h3>Recommendations</h3><ol>{recs}</ol>" if recs else "") + "</section>")

    u = r.usage
    cost = f"${u.cost_usd:.4f}" if u.unpriced_calls == 0 else "unknown (unpriced models)"
    return _HTML_TEMPLATE.format(
        title=escape(f"Assessment — {r.engagement_name}"),
        name=escape(r.engagement_name), objective=escape(r.objective or "—"),
        authorized_by=escape(r.authorized_by or "—"), scope=escape(r.scope),
        status=escape(r.status), created=_ts(r.engagement_created),
        generated=_ts(r.generated_at),
        n_assets=c["assets"], n_verified=c["verified"], n_hyp=c["hypotheses"],
        n_exec=c["executions"], n_ok=c["executions_ok"],
        summary=summary_html, assets=assets,
        verified=_html_findings(r.verified, False),
        hypotheses=_html_findings(r.hypotheses, True),
        executions=exec_table,
        calls=u.calls, failed=u.failed, tok_in=u.prompt_tokens, tok_out=u.completion_tokens,
        cost=cost, disclaimer=escape(DISCLAIMER),
    )


_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ --bg:#f6f7f9; --card:#fff; --fg:#1b2430; --muted:#5a6b7b; --line:#e2e6ea;
  --accent:#b3123b; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#11151a; --card:#1a2028;
  --fg:#e6eaef; --muted:#90a0b0; --line:#2a333d; --accent:#ff5c7a; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
.wrap {{ max-width:900px; margin:0 auto; padding:16px; }}
header {{ border-left:4px solid var(--accent); padding:4px 0 4px 14px; margin:18px 0; }}
h1 {{ font-size:1.5rem; margin:.2em 0; }} h2 {{ font-size:1.2rem; margin-top:1.6em;
  border-bottom:1px solid var(--line); padding-bottom:.2em; }}
h3 {{ font-size:1rem; margin-top:1.2em; }}
section {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
  padding:4px 18px 18px; margin:14px 0; }}
.meta {{ list-style:none; padding:0; }} .meta li {{ padding:2px 0; }}
.meta b {{ color:var(--muted); font-weight:600; display:inline-block; min-width:150px; }}
.cards {{ display:flex; flex-wrap:wrap; gap:10px; margin:12px 0; }}
.card {{ flex:1 1 120px; background:var(--card); border:1px solid var(--line);
  border-radius:10px; padding:12px; text-align:center; }}
.card .n {{ font-size:1.6rem; font-weight:700; }} .card .l {{ color:var(--muted);
  font-size:.8rem; }}
table {{ width:100%; border-collapse:collapse; margin:10px 0; font-size:.92rem; }}
th,td {{ text-align:left; padding:7px 9px; border-bottom:1px solid var(--line);
  vertical-align:top; }}
th {{ color:var(--muted); font-weight:600; }}
code {{ background:rgba(127,127,127,.15); padding:1px 5px; border-radius:4px;
  font-size:.85em; word-break:break-all; }}
.badge {{ color:#fff; border-radius:5px; padding:1px 7px; font-size:.75rem;
  font-weight:600; margin-right:6px; white-space:nowrap; }}
ul.findings {{ list-style:none; padding:0; }}
ul.findings li {{ padding:9px 0; border-bottom:1px solid var(--line); }}
.desc {{ color:var(--muted); font-size:.9rem; margin:4px 0 0 6px; }}
.muted {{ color:var(--muted); }} .ok {{ color:#1d9a52; }} .warn {{ color:var(--accent); }}
.ai-note {{ color:var(--muted); font-style:italic; font-size:.88rem; }}
.disclaimer {{ color:var(--muted); font-size:.85rem; border-top:1px solid var(--line);
  margin-top:24px; padding-top:12px; }}
</style></head><body><div class="wrap">
<header><h1>Security assessment — {name}</h1>
<span class="muted">Generated {generated}</span></header>
<section><ul class="meta">
<li><b>Objective</b> {objective}</li>
<li><b>Authorized by</b> {authorized_by}</li>
<li><b>Scope</b> {scope}</li>
<li><b>Status</b> {status}</li>
<li><b>Engagement created</b> {created}</li></ul></section>
<div class="cards">
<div class="card"><div class="n">{n_assets}</div><div class="l">assets</div></div>
<div class="card"><div class="n">{n_verified}</div><div class="l">verified results</div></div>
<div class="card"><div class="n">{n_hyp}</div><div class="l">to verify</div></div>
<div class="card"><div class="n">{n_ok}/{n_exec}</div><div class="l">operations ok</div></div>
</div>
{summary}
<section><h2>Assets</h2>{assets}</section>
<section><h2>Verified results</h2>
<p class="muted">Facts produced by executed tools (see Operations for evidence).</p>
{verified}</section>
<section><h2>Hypotheses to verify</h2>
<p class="muted">Unverified AI reasoning — confirm before acting.</p>
{hypotheses}</section>
<section><h2>Operations run</h2>{executions}</section>
<section><h2>Model usage</h2>
<p>{calls} calls ({failed} failed) · {tok_in} in / {tok_out} out tokens · cost {cost}</p>
</section>
<p class="disclaimer">{disclaimer}</p>
</div></body></html>
"""
