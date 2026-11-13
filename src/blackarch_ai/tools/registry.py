"""Tool registry: the persisted result of discovery, plus full-text search.

The registry describes what is installed. It does not make anything
executable — runnable operations are defined separately and go through the
execution engine (Phase 5).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import delete, select, text

from blackarch_ai.storage.models import Tool, ToolScan
from blackarch_ai.storage.store import Store
from blackarch_ai.tools.discovery import ScanResult
from blackarch_ai.tools.pacman import local_db_mtime

_FTS_DDL = """
CREATE VIRTUAL TABLE IF NOT EXISTS tool_fts USING fts5(
    name, description, executables, categories, summary, doc,
    tokenize = 'porter unicode61'
)
"""

_STOPWORDS = set("""
a an and are as at be but by can do does for from how i in is it me my of on or so
that the this to use using what which with you your tool tools should want need
please run find show tell give best way check about there their them
""".split())


@dataclass
class SearchHit:
    tool: Tool
    score: float
    snippet: str


def fts_query(text_: str, max_terms: int = 12) -> str | None:
    """Turn free text into a safe FTS5 OR-query of quoted terms."""
    terms = []
    for t in re.findall(r"[A-Za-z0-9][A-Za-z0-9._+-]*", text_.lower()):
        t = t.strip("._+-")
        if len(t) < 2 or t in _STOPWORDS or t in terms:
            continue
        terms.append(t)
    if not terms:
        return None
    return " OR ".join('"' + t.replace('"', "") + '"' for t in terms[:max_terms])


class Registry:
    def __init__(self, store: Store) -> None:
        self.store = store
        with store.engine.begin() as conn:
            conn.execute(text(_FTS_DDL))

    # -- writing

    def save(self, result: ScanResult) -> ToolScan:
        """Replace the registry contents with a new scan, atomically."""
        with self.store.session() as s, s.begin():
            s.execute(delete(Tool))
            s.execute(text("DELETE FROM tool_fts"))
            for t in result.tools:
                s.add(Tool(
                    name=t.name, version=t.version, description=t.description, url=t.url,
                    source=t.source, categories=t.categories, agents=t.agents,
                    executables=t.executables, man_pages=t.man_pages,
                    permission=t.permission, summary=t.summary,
                ))
                s.execute(
                    text("INSERT INTO tool_fts(name, description, executables, categories, "
                         "summary, doc) VALUES (:n, :d, :e, :c, :s, :doc)"),
                    {"n": t.name, "d": t.description,
                     "e": " ".join(p.rsplit("/", 1)[-1] for p in t.executables),
                     "c": " ".join(t.categories), "s": t.summary, "doc": t.doc_text},
                )
            scan = ToolScan(
                duration_s=result.duration_s, tools=len(result.tools),
                executables=sum(len(t.executables) for t in result.tools),
                man_pages=sum(len(t.man_pages) for t in result.tools),
                pacman_db_mtime=result.pacman_db_mtime, warnings=result.warnings,
            )
            s.add(scan)
        self.store.audit("system", "tools.scan",
                         {"tools": scan.tools, "executables": scan.executables,
                          "man_pages": scan.man_pages, "seconds": round(scan.duration_s, 1)})
        return scan

    # -- reading

    def last_scan(self) -> ToolScan | None:
        with self.store.session() as s:
            return s.scalars(select(ToolScan).order_by(ToolScan.id.desc()).limit(1)).first()

    def is_stale(self) -> bool:
        """True if never scanned, or packages changed since the last scan."""
        scan = self.last_scan()
        if scan is None:
            return True
        current = local_db_mtime()
        return (current is not None and scan.pacman_db_mtime is not None
                and current > scan.pacman_db_mtime + 1)

    def count(self) -> int:
        with self.store.session() as s:
            return len(s.scalars(select(Tool.id)).all())

    def get(self, name: str) -> Tool | None:
        """By package name, or by the name of one of its executables."""
        with self.store.session() as s:
            tool = s.scalars(select(Tool).where(Tool.name == name)).first()
            if tool is not None:
                return tool
            for t in s.scalars(select(Tool)).all():
                if any(p.rsplit("/", 1)[-1] == name for p in t.executables):
                    return t
        return None

    def list(self, *, agent: str | None = None, category: str | None = None,
             commands_only: bool = False) -> list[Tool]:
        with self.store.session() as s:
            tools = list(s.scalars(select(Tool).order_by(Tool.name)).all())
        if agent:
            tools = [t for t in tools if agent in t.agents]
        if category:
            tools = [t for t in tools if category in t.categories]
        if commands_only:
            tools = [t for t in tools if t.executables]
        return tools

    def search(self, query: str, limit: int = 10, *, agent: str | None = None) -> list[SearchHit]:
        q = fts_query(query)
        if q is None:
            return []
        # Name/description/executable matches outweigh a passing mention in a man page.
        sql = text(
            "SELECT name, bm25(tool_fts, 10.0, 4.0, 8.0, 3.0, 2.0, 1.0) AS score, "
            "snippet(tool_fts, 5, '«', '»', '…', 12) AS snip "
            "FROM tool_fts WHERE tool_fts MATCH :q ORDER BY score LIMIT :lim"
        )
        with self.store.session() as s:
            rows = s.execute(sql, {"q": q, "lim": limit * 3 if agent else limit}).all()
            by_name = {t.name: t for t in s.scalars(
                select(Tool).where(Tool.name.in_([r.name for r in rows]))).all()}
        hits = []
        for r in rows:
            tool = by_name.get(r.name)
            if tool is None or (agent and agent not in tool.agents):
                continue
            hits.append(SearchHit(tool, float(r.score), " ".join((r.snip or "").split())))
        return hits[:limit]

    def agent_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for t in self.list():
            for a in t.agents:
                counts[a] = counts.get(a, 0) + 1
        return counts

    def context_for(self, query: str, limit: int = 8) -> str:
        """Compact, LLM-ready list of installed tools relevant to `query`."""
        hits = self.search(query, limit)
        lines = []
        for h in hits:
            t = h.tool
            exes = ", ".join(p.rsplit("/", 1)[-1] for p in t.executables[:4]) or "no command"
            lines.append(f"- {t.name} {t.version} [{', '.join(t.categories)}] "
                         f"(commands: {exes}): {t.description}")
        return "\n".join(lines)
