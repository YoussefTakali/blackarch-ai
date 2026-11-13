"""Local documentation: render man pages to plain text and summarize them.

Only `man` runs here (to format a page file); tool binaries are never run
during discovery. Capturing `--help` output needs the sandboxed execution
engine and is deferred to Phase 5.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable

MAX_DOC_CHARS = 60_000

# Sections 1 (commands), 5 (file formats) and 8 (admin commands); section 3
# (library APIs) would flood the index with C/Perl/Python function docs.
_MAN_PAGE = re.compile(r"^/usr/share/man/man([158])[a-z]*/[^/]+\.\1[a-z]*(\.gz|\.bz2|\.xz|\.zst)?$")
_OVERSTRIKE = re.compile(r".\x08")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_HEADING = re.compile(r"^[A-Z][A-Z0-9 /&-]+$")

ManRenderer = Callable[[str], str | None]


def is_english_man_page(path: str) -> bool:
    """True for /usr/share/man/manN/... (localized pages live in /usr/share/man/<lang>/)."""
    return bool(_MAN_PAGE.match(path))


def clean(text: str) -> str:
    text = _ANSI.sub("", _OVERSTRIKE.sub("", text))
    text = text.replace("‐", "-")  # groff hyphen
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def render_man(path: str, timeout: float = 15.0) -> str | None:
    """Plain-text rendering of a man page file, or None if it can't be rendered."""
    exe = shutil.which("man")
    if exe is None:
        return None
    env = {**os.environ, "MANWIDTH": "100", "MANPAGER": "cat", "PAGER": "cat",
           "GROFF_NO_SGR": "1", "LC_ALL": "C.UTF-8"}
    try:
        proc = subprocess.run(
            [exe, "-l", "-P", "cat", "--", path], capture_output=True, timeout=timeout,
            env=env, stdin=subprocess.DEVNULL, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    return clean(proc.stdout.decode("utf-8", "replace"))[:MAX_DOC_CHARS]


def sections(text: str) -> dict[str, str]:
    """Split rendered man text into {HEADING: body}."""
    out: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        if _HEADING.match(line) and not line.startswith(" "):
            current = line.strip()
            out.setdefault(current, [])
        elif current is not None:
            out[current].append(line)
    return {k: "\n".join(v).strip() for k, v in out.items()}


def summarize(text: str, limit: int = 600) -> str:
    """NAME + SYNOPSIS, compacted — enough for an agent to pick a tool."""
    sec = sections(text)
    parts = []
    if sec.get("NAME"):
        parts.append(" ".join(sec["NAME"].split()))
    if sec.get("SYNOPSIS"):
        synopsis = " ".join(sec["SYNOPSIS"].split())
        parts.append("Synopsis: " + synopsis)
    return "\n".join(parts)[:limit]
