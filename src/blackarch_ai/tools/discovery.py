"""Discover installed security tools from pacman metadata.

Sources:
* installed members of blackarch-* groups (category = group suffix), and
* installed Arch packages listed in data/extra_tools.toml.

For each package we record version/description/URL (pacman -Qi), the
executables it puts in /usr/bin and its English man pages (pacman -Ql), the
categories and owning agents, and a plain-text rendering of its man pages for
search. No tool binary is executed.
"""

from __future__ import annotations

import os
import re
import time
import tomllib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from blackarch_ai.core.domains import DomainMap
from blackarch_ai.tools import documentation as docs
from blackarch_ai.tools.pacman import (
    PacmanRunner,
    default_runner,
    installed_group_members,
    installed_packages,
    local_db_mtime,
    parse_qi,
    parse_ql,
)

BIN_DIRS = ("/usr/bin/",)
MAX_MAN_PAGES_PER_TOOL = 8


@dataclass
class ToolRecord:
    name: str  # pacman package name
    version: str
    description: str
    url: str
    source: str  # "blackarch" | "arch"
    categories: list[str]
    agents: list[str]
    executables: list[str]  # absolute paths
    man_pages: list[str]
    permission: str  # "high_impact" | "unclassified"
    summary: str = ""  # NAME/SYNOPSIS of the primary man page
    doc_text: str = field(default="", repr=False)  # rendered man pages for search

    @property
    def kind(self) -> str:
        return "command" if self.executables else "data/library"


@dataclass
class ScanResult:
    tools: list[ToolRecord]
    duration_s: float
    pacman_db_mtime: float | None
    warnings: list[str] = field(default_factory=list)


def load_extra_tools(path: Path | None = None) -> dict[str, list[str]]:
    if path is None:
        text = resources.files("blackarch_ai").joinpath("data/extra_tools.toml").read_text()
    else:
        text = path.read_text()
    return {k: list(v) for k, v in tomllib.loads(text).get("packages", {}).items()}


def _keyword_agents(domains: DomainMap, text: str) -> list[str]:
    hits = []
    low = text.lower()
    for a in domains.agents:
        if any(re.search(rf"(?<![a-z0-9]){re.escape(k)}(?![a-z0-9])", low) for k in a.keywords):
            hits.append(a.id)
    return hits


def _executables(paths: list[str], root: Path) -> list[str]:
    out = []
    for p in paths:
        if p.endswith("/") or not p.startswith(BIN_DIRS):
            continue
        real = root / p.lstrip("/")
        if real.is_file() and os.access(real, os.X_OK):
            out.append(p)
    return sorted(out)


def _man_pages(package: str, paths: list[str], executables: list[str]) -> list[str]:
    pages = [p for p in paths if docs.is_english_man_page(p)]
    exe_names = {Path(e).name for e in executables}

    def key(p: str) -> tuple[bool, bool, str]:
        stem = Path(p).name.split(".")[0]
        # The package's own page first, then pages for its other commands.
        return (stem != package, stem not in exe_names, p)

    pages.sort(key=key)
    return pages[:MAX_MAN_PAGES_PER_TOOL]


class Discovery:
    def __init__(
        self,
        domains: DomainMap,
        *,
        runner: PacmanRunner = default_runner,
        man_renderer: docs.ManRenderer = docs.render_man,
        root: Path = Path("/"),
        extra_tools: dict[str, list[str]] | None = None,
        workers: int = 8,
    ) -> None:
        self.domains = domains
        self.runner = runner
        self.render = man_renderer
        self.root = root
        self.extra = load_extra_tools() if extra_tools is None else extra_tools
        self.workers = workers

    def scan(self, progress: Callable[[str, int, int], None] | None = None) -> ScanResult:
        started = time.monotonic()
        warnings: list[str] = []
        note = progress or (lambda *_: None)

        note("reading package groups", 0, 0)
        cats: dict[str, set[str]] = {}
        for cat, pkgs in installed_group_members(self.runner).items():
            for p in pkgs:
                cats.setdefault(p, set()).add(cat)
        blackarch_pkgs = set(cats)

        installed = installed_packages(self.runner)
        for pkg, extra_cats in self.extra.items():
            if pkg in installed:
                cats.setdefault(pkg, set()).update(extra_cats)

        unknown = {c for cs in cats.values() for c in cs} - self.domains.all_categories()
        if unknown:
            warnings.append("categories not mapped to an agent: " + ", ".join(sorted(unknown)))

        names = sorted(cats)
        if not names:
            return ScanResult([], time.monotonic() - started, local_db_mtime(), warnings)

        note("reading package metadata", 0, len(names))
        info = parse_qi(self.runner(["-Qi", *names]))
        files = parse_ql(self.runner(["-Ql", *names]))

        tools: list[ToolRecord] = []
        for name in names:
            pi = info.get(name)
            if pi is None:
                warnings.append(f"no metadata for {name}")
                continue
            categories = sorted(cats[name])
            agents = sorted({self.domains.owner[c] for c in categories if c in self.domains.owner}
                            | set(_keyword_agents(self.domains, f"{name} {pi.description}")))
            exes = _executables(files.get(name, []), self.root)
            permission = ("high_impact" if set(categories) & self.domains.high_impact
                          else "unclassified")
            tools.append(ToolRecord(
                name=name, version=pi.version, description=pi.description, url=pi.url,
                source="blackarch" if name in blackarch_pkgs else "arch",
                categories=categories, agents=agents, executables=exes,
                man_pages=_man_pages(name, files.get(name, []), exes), permission=permission,
            ))

        self._render_docs(tools, note)
        return ScanResult(tools, time.monotonic() - started, local_db_mtime(), warnings)

    def _render_docs(self, tools: list[ToolRecord], note: Callable[[str, int, int], None]) -> None:
        jobs = [(t, p) for t in tools for p in t.man_pages]
        rendered: dict[str, str | None] = {}
        done = 0
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for path, text in zip((p for _, p in jobs), pool.map(self.render, (p for _, p in jobs))):
                rendered[path] = text
                done += 1
                note("rendering man pages", done, len(jobs))
        for t in tools:
            texts = [rendered[p] for p in t.man_pages if rendered.get(p)]
            if texts:
                t.summary = docs.summarize(texts[0])
                t.doc_text = "\n\n".join(texts)[: docs.MAX_DOC_CHARS]
