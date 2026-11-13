"""Auto-detect targets from user input and create engagements on the fly.

When the user starts chatting without an engagement and says something that
implies targets ("hack my network", "scan 10.0.0.5", etc.), this module
figures out what they mean, resolves "my network" / "my wifi" to actual
subnets from `ip addr`, and creates the engagement automatically so the
user never has to run `engagement create` by hand.
"""

from __future__ import annotations

import re
import subprocess


def _ip_to_int(ip_str: str) -> int:
    return sum(int(x) << (24 - 8 * i) for i, x in enumerate(ip_str.split(".")))


def _int_to_ip(n: int) -> str:
    return ".".join(str((n >> (24 - 8 * i)) & 0xFF) for i in range(4))


def _network_of(ip_str: str, prefix: int) -> str:
    """Network address string for an IP at the given prefix (no /prefix suffix)."""
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return _int_to_ip(_ip_to_int(ip_str) & mask)


def detect_local_networks() -> list[str]:
    """Return local subnets (e.g. ['192.168.1.0/24']) from active interfaces.

    A directly-connected interface may carry a very wide mask (e.g. a DHCP
    /16), but the real devices sit in the host's own /24 segment. Sweeping a
    whole /16 is 65k addresses and takes many minutes, so anything wider than a
    /24 is narrowed to the /24 that contains the host's address. Narrower
    assignments (/24, /25, …) are kept as-is.
    """
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:
        return []
    subnets: list[str] = []
    for line in out.splitlines():
        # "2: wlp0s20f3    inet 192.168.0.86/24 brd ... scope global ..."
        parts = line.split()
        iface = parts[1] if len(parts) > 1 else ""
        if _is_virtual_iface(iface):
            continue  # skip docker/bridge/vpn/tunnel interfaces, not the real LAN
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m:
            ip_str, prefix = m.group(1), int(m.group(2))
            # Narrow anything wider than a /24 to the host's own /24 segment.
            eff_prefix = max(prefix, 24)
            cidr = f"{_network_of(ip_str, eff_prefix)}/{eff_prefix}"
            if cidr not in subnets:
                subnets.append(cidr)
    return subnets


def host_slash24_in(cidr: str) -> str | None:
    """Given a scope network (e.g. '172.26.0.0/16'), return the host's own /24
    within it (e.g. '172.26.0.0/24'), or None if the host has no address there.

    Used to keep host discovery fast on a reused engagement whose scope still
    holds a wide network: scan the segment the host actually lives on.
    """
    try:
        net_str, prefix_str = cidr.split("/")
        prefix = int(prefix_str)
    except (ValueError, AttributeError):
        return None
    if prefix >= 24:
        return None  # already /24 or narrower — nothing to narrow
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:
        return None
    net_at_prefix = _network_of(net_str, prefix)
    for line in out.splitlines():
        parts = line.split()
        iface = parts[1] if len(parts) > 1 else ""
        if _is_virtual_iface(iface):
            continue
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        ip_str = m.group(1)
        if _network_of(ip_str, prefix) == net_at_prefix:
            return f"{_network_of(ip_str, 24)}/24"
    return None


_VIRTUAL_IFACE_RE = re.compile(
    r"^(docker|br-|veth|virbr|zt|tun|tap|wg|tailscale|cni|flannel|cali|lo\b)", re.IGNORECASE
)


def _is_virtual_iface(iface: str) -> bool:
    """True for Docker/bridge/VPN/tunnel interfaces that aren't the physical LAN."""
    return bool(_VIRTUAL_IFACE_RE.match(iface))


def detect_primary_iface() -> str | None:
    """Return the interface of the default route (the real LAN/wifi NIC)."""
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:
        return None
    m = re.search(r"\bdev\s+(\S+)", out)
    return m.group(1) if m else None


def detect_primary_ip() -> str | None:
    """Return this host's own IPv4 on the default-route interface."""
    iface = detect_primary_iface()
    if not iface:
        return None
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface, "scope", "global"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:
        return None
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", out)
    return m.group(1) if m else None


def detect_gateway() -> str | None:
    """Return the default gateway IP."""
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:
        return None
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


_NET_KW = re.compile(
    r"\b(?:"
    r"my\s+(?:network|wifi|wi-fi|lan|subnet|home\s*(?:lab|network))|"
    r"(?:the|this)\s+(?:local\s+)?(?:network|wifi|wi-fi|lan|subnet)|"
    r"(?:all|every)\s+(?:hosts?|devices?|machines?|clients?)\s+"
    r"(?:on|in)\s+(?:my|the|this)\s+(?:network|wifi|wi-fi|lan|subnet)|"
    r"local\s+network"
    r")\b",
    re.IGNORECASE,
)

_LOCALHOST_KW = re.compile(
    r"\b(?:localhost|this\s+machine|this\s+host|this\s+box|this\s+server|127\.0\.0\.1)\b",
    re.IGNORECASE,
)

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b")

_DOMAIN_RE = re.compile(r"\b((?:[a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b")

_SKIP_DOMAINS = {
    "e.g", "i.e", "etc.com", "example.com", "example.org", "example.net",
}
_SKIP_SUFFIXES = (".py", ".toml", ".json", ".yaml", ".yml", ".md", ".txt", ".html", ".css", ".js")


def extract_targets(text: str) -> tuple[list[str], list[str], str]:
    """Parse targets from user text.

    Returns (targets, exclusions, suggested_engagement_name).
    """
    targets: list[str] = []
    exclusions: list[str] = []
    name = "auto"

    if _NET_KW.search(text):
        nets = detect_local_networks()
        gw = detect_gateway()
        if nets:
            targets.extend(nets)
            if gw:
                exclusions.append(gw)
            name = "local-net"

    if _LOCALHOST_KW.search(text):
        if "127.0.0.1" not in targets:
            targets.append("127.0.0.1")
        if name == "auto":
            name = "localhost"

    for m in _IP_RE.finditer(text):
        ip = m.group(1)
        if ip not in targets and not ip.startswith("127."):
            parts = ip.split("/")[0].split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                targets.append(ip)
                if name == "auto":
                    name = "target"

    for m in _DOMAIN_RE.finditer(text):
        d = m.group(1).lower().rstrip(".")
        if d in _SKIP_DOMAINS or d.endswith(_SKIP_SUFFIXES):
            continue
        if d not in targets:
            targets.append(d)
            if name == "auto":
                name = d.split(".")[0]

    return targets, exclusions, name
