"""Engagement scope: what the user is authorized to assess.

Scope checks are plain local code; the LLM can never widen the scope. A target
is in scope when it matches an included entry and no excluded entry.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

# Networks broader than this need an explicit override to be put in scope.
MIN_IPV4_PREFIX = 16
MIN_IPV6_PREFIX = 48

_HOST_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOSTNAME = re.compile(rf"^(\*\.)?({_HOST_LABEL}\.)*{_HOST_LABEL}\.?$", re.IGNORECASE)

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address


class ScopeError(ValueError):
    pass


class ScopeEntry(BaseModel):
    kind: Literal["network", "host", "domain"]
    value: str  # normalized: CIDR string, lowercase hostname, or "*.example.com"
    raw: str

    @property
    def is_wildcard(self) -> bool:
        return self.kind == "domain"


def _host_from(target: str) -> str:
    """Strip scheme, credentials, port and path from a URL-ish target."""
    t = target.strip()
    if "://" in t:
        host = urlsplit(t).hostname
        if not host:
            raise ScopeError(f"cannot find a host in URL: {target!r}")
        return host
    # Bracketed IPv6 with optional port: [::1]:443
    m = re.fullmatch(r"\[([0-9a-fA-F:.]+)\](?::\d+)?", t)
    if m:
        return m.group(1)
    # host:port (but not a bare IPv6 address, which has several colons)
    if t.count(":") == 1:
        host, port = t.split(":")
        if port.isdigit():
            return host
    return t


def parse_entry(raw: str, *, allow_broad: bool = False) -> ScopeEntry:
    text = raw.strip()
    if not text:
        raise ScopeError("empty scope entry")

    if "/" in text and "://" not in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ScopeError(f"invalid network {raw!r}: {exc}") from None
        limit = MIN_IPV4_PREFIX if net.version == 4 else MIN_IPV6_PREFIX
        if net.prefixlen < limit and not allow_broad:
            raise ScopeError(
                f"{net} is broader than /{limit}; pass allow_broad to confirm "
                "you are authorized for a range this large"
            )
        return ScopeEntry(kind="network", value=str(net), raw=raw)

    host = _host_from(text)
    try:
        addr = ipaddress.ip_address(host)
        return ScopeEntry(kind="network", value=str(ipaddress.ip_network(addr)), raw=raw)
    except ValueError:
        pass

    host = host.lower().rstrip(".")
    if not _HOSTNAME.match(host):
        raise ScopeError(f"not an IP, network, hostname or URL: {raw!r}")
    if host.startswith("*."):
        if host.count(".") < 2 and not allow_broad:
            raise ScopeError(f"wildcard {host!r} covers a whole TLD; refusing")
        return ScopeEntry(kind="domain", value=host, raw=raw)
    return ScopeEntry(kind="host", value=host, raw=raw)


def _matches(entry: ScopeEntry, host: str, addr: IPAddr | None) -> bool:
    if entry.kind == "network":
        return addr is not None and addr in ipaddress.ip_network(entry.value)
    if addr is not None:
        return False  # hostnames don't match raw IPs (no DNS assumptions)
    if entry.kind == "host":
        return host == entry.value
    suffix = entry.value[1:]  # ".example.com"
    return host.endswith(suffix) or host == suffix[1:]


class Scope(BaseModel):
    include: list[ScopeEntry] = Field(default_factory=list)
    exclude: list[ScopeEntry] = Field(default_factory=list)

    @classmethod
    def build(
        cls,
        include: list[str],
        exclude: list[str] | None = None,
        *,
        allow_broad: bool = False,
    ) -> Scope:
        if not include:
            raise ScopeError("scope must contain at least one target")
        return cls(
            include=[parse_entry(t, allow_broad=allow_broad) for t in include],
            # Exclusions can be as broad as the user likes.
            exclude=[parse_entry(t, allow_broad=True) for t in (exclude or [])],
        )

    def _check_network(self, target: str) -> tuple[bool, str]:
        """A CIDR target is allowed only if it lies entirely inside one included network.

        Exclusions inside it don't block it, but are reported so the caller (the
        execution engine, later) must skip them; a target that is wholly inside an
        exclusion is refused.
        """
        try:
            net = ipaddress.ip_network(target.strip(), strict=False)
        except ValueError:
            return False, f"not a valid target: {target!r}"
        container = None
        for e in self.include:
            if e.kind == "network":
                inc = ipaddress.ip_network(e.value)
                if inc.version == net.version and net.subnet_of(inc):
                    container = e
                    break
        if container is None:
            return False, "not entirely inside the authorized scope"
        must_skip = []
        for e in self.exclude:
            if e.kind != "network":
                continue
            exc = ipaddress.ip_network(e.value)
            if exc.version != net.version or not net.overlaps(exc):
                continue
            if net.subnet_of(exc):
                return False, f"excluded by {e.raw!r}"
            must_skip.append(e.raw)
        reason = f"in scope via {container.raw!r}"
        if must_skip:
            reason += f"; must skip {', '.join(must_skip)}"
        return True, reason

    def exclusions_within(self, target: str) -> list[str]:
        """Excluded entries that fall inside a network target (to pass as skips)."""
        try:
            net = ipaddress.ip_network(target.strip(), strict=False)
        except ValueError:
            return []
        return [e.value for e in self.exclude if e.kind == "network"
                and ipaddress.ip_network(e.value).version == net.version
                and net.overlaps(ipaddress.ip_network(e.value))]

    def check(self, target: str) -> tuple[bool, str]:
        """Return (allowed, reason). Never raises for malformed targets."""
        if "/" in target and "://" not in target:
            return self._check_network(target)
        try:
            host = _host_from(target).lower().rstrip(".")
        except ScopeError as exc:
            return False, str(exc)
        try:
            addr: IPAddr | None = ipaddress.ip_address(host)
        except ValueError:
            addr = None
            if not _HOSTNAME.match(host) or host.startswith("*."):
                return False, f"not a valid target: {target!r}"
        for e in self.exclude:
            if _matches(e, host, addr):
                return False, f"excluded by {e.raw!r}"
        for e in self.include:
            if _matches(e, host, addr):
                return True, f"in scope via {e.raw!r}"
        return False, "not in the authorized scope"

    def contains(self, target: str) -> bool:
        return self.check(target)[0]

    def summary(self) -> str:
        inc = ", ".join(e.raw for e in self.include) or "(none)"
        exc = ", ".join(e.raw for e in self.exclude)
        return f"include: {inc}" + (f"; exclude: {exc}" if exc else "")
