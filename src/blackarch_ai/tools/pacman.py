"""Read BlackArch package groups from pacman (read-only queries)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable
from collections import defaultdict
from dataclasses import dataclass

GROUP_PREFIX = "blackarch-"


class PacmanUnavailable(RuntimeError):
    pass


@dataclass
class GroupInventory:
    available: dict[str, set[str]]  # category -> packages in the sync repos
    installed: dict[str, set[str]]  # category -> installed packages


def pacman_env() -> dict[str, str]:
    """Environment for parseable pacman output.

    * C.UTF-8 keeps field names in English ("Version", "Groups") while still
      handling UTF-8 descriptions (plain "C" mangles them).
    * COLUMNS is removed: pacman wraps long values to $COLUMNS even when writing
      to a pipe, and its wrapping drops the rest of a line at a multi-byte
      character (e.g. curly quotes), silently truncating descriptions.
    """
    env = {k: v for k, v in os.environ.items() if k not in ("COLUMNS", "LINES")}
    env["LC_ALL"] = "C.UTF-8"
    return env


def _pacman(args: list[str], timeout: float) -> str:
    exe = shutil.which("pacman")
    if exe is None:
        raise PacmanUnavailable(
            "pacman not found — run BlackArch AI inside the BlackArch toolbox"
        )
    proc = subprocess.run(
        [exe, *args], capture_output=True, text=True, timeout=timeout, check=False,
        env=pacman_env(), stdin=subprocess.DEVNULL,
    )
    # -Qg exits 1 when no installed package belongs to a group; that's not an error.
    if proc.returncode != 0 and proc.stdout == "":
        if args[0] == "-Qg" and not proc.stderr.strip():
            return ""
        raise PacmanUnavailable(f"pacman {args[0]} failed: {proc.stderr.strip()[:200]}")
    return proc.stdout


def _groups(flag: str, timeout: float) -> dict[str, set[str]]:
    if flag == "-Sg":
        # Without arguments `pacman -Sg` prints only group names; ask for members.
        names = [
            n for n in _pacman(["-Sg"], timeout).split()
            if n.startswith(GROUP_PREFIX)
        ]
        if not names:
            raise PacmanUnavailable("no blackarch-* groups in the sync databases")
        return parse_group_listing(_pacman(["-Sg", *names], timeout))
    return parse_group_listing(_pacman(["-Qg"], timeout))


def parse_group_listing(text: str) -> dict[str, set[str]]:
    """Parse `pacman -Sg`/`-Qg` output ("group package" per line)."""
    out: dict[str, set[str]] = defaultdict(set)
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[0].startswith(GROUP_PREFIX):
            continue
        out[parts[0][len(GROUP_PREFIX):]].add(parts[1])
    return dict(out)


def group_inventory(timeout: float = 30.0) -> GroupInventory:
    return GroupInventory(available=_groups("-Sg", timeout), installed=_groups("-Qg", timeout))


# ------------------------------------------------------------ package metadata

PacmanRunner = Callable[[list[str]], str]


def default_runner(args: list[str]) -> str:
    return _pacman(args, timeout=120.0)


@dataclass
class PackageInfo:
    name: str
    version: str
    description: str
    url: str
    groups: list[str]


_FIELD = re.compile(r"^([A-Za-z][A-Za-z ]*?)\s*: (.*)$")


def parse_qi(text: str) -> dict[str, PackageInfo]:
    """Parse `LC_ALL=C pacman -Qi pkg...` output (blank-line separated blocks)."""
    out: dict[str, PackageInfo] = {}
    for block in re.split(r"\n\s*\n", text.strip()):
        fields: dict[str, str] = {}
        last = None
        for line in block.splitlines():
            m = _FIELD.match(line)
            if m:
                last = m.group(1).strip()
                fields[last] = m.group(2).strip()
            elif last and line.startswith(" "):
                fields[last] += " " + line.strip()  # wrapped value
        name = fields.get("Name")
        if not name:
            continue
        groups = fields.get("Groups", "None")
        out[name] = PackageInfo(
            name=name,
            version=fields.get("Version", ""),
            description=fields.get("Description", ""),
            url=fields.get("URL", "") if fields.get("URL") != "None" else "",
            groups=[] if groups == "None" else groups.split(),
        )
    return out


def parse_ql(text: str) -> dict[str, list[str]]:
    """Parse `pacman -Ql pkg...` output into package -> file paths."""
    out: dict[str, list[str]] = defaultdict(list)
    for line in text.splitlines():
        pkg, _, path = line.partition(" ")
        if path:
            out[pkg].append(path)
    return dict(out)


def installed_packages(runner: PacmanRunner = default_runner) -> set[str]:
    return {line.split()[0] for line in runner(["-Q"]).splitlines() if line.strip()}


def installed_group_members(runner: PacmanRunner = default_runner) -> dict[str, set[str]]:
    """category -> installed packages, for blackarch-* groups only."""
    return parse_group_listing(runner(["-Qg"]))


def local_db_mtime(path: str = "/var/lib/pacman/local") -> float | None:
    """Changes whenever packages are installed/removed; used to detect stale scans."""
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None
