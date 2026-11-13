import pytest

from blackarch_ai.security.scope import Scope, ScopeError, parse_entry


@pytest.mark.parametrize(
    "raw,kind,value",
    [
        ("10.0.0.0/24", "network", "10.0.0.0/24"),
        ("10.0.0.7/24", "network", "10.0.0.0/24"),  # host bits tolerated
        ("192.168.1.5", "network", "192.168.1.5/32"),
        ("2001:db8::/64", "network", "2001:db8::/64"),
        ("Example.COM.", "host", "example.com"),
        ("*.example.com", "domain", "*.example.com"),
        ("https://user:pw@app.example.com:8443/login", "host", "app.example.com"),
        ("app.example.com:8080", "host", "app.example.com"),
        ("[2001:db8::1]:443", "network", "2001:db8::1/128"),
    ],
)
def test_parse_entry(raw, kind, value):
    e = parse_entry(raw)
    assert (e.kind, e.value) == (kind, value)


@pytest.mark.parametrize("raw", ["", "not a host!", "10.0.0.0/33", "http://", "*.com"])
def test_parse_entry_rejects(raw):
    with pytest.raises(ScopeError):
        parse_entry(raw)


def test_broad_networks_need_override():
    with pytest.raises(ScopeError, match="broader"):
        parse_entry("0.0.0.0/0")
    with pytest.raises(ScopeError):
        parse_entry("10.0.0.0/8")
    assert parse_entry("10.0.0.0/8", allow_broad=True).value == "10.0.0.0/8"


def test_scope_matching_and_exclusions():
    s = Scope.build(["10.0.0.0/24", "*.example.com", "api.other.org"],
                    exclude=["10.0.0.1", "vpn.example.com"])
    assert s.contains("10.0.0.50")
    assert s.contains("http://10.0.0.50:8080/x")
    assert not s.contains("10.0.0.1")           # excluded
    assert not s.contains("10.0.1.1")           # outside network
    assert s.contains("www.example.com")
    assert s.contains("example.com")            # wildcard includes apex
    assert not s.contains("vpn.example.com")    # excluded
    assert not s.contains("evilexample.com")    # suffix must be a label boundary
    assert s.contains("API.other.org")
    assert not s.contains("other.org")
    assert not s.contains("93.184.216.34")      # IPs never match hostnames


def test_check_reason_and_garbage():
    s = Scope.build(["10.0.0.0/24"])
    ok, reason = s.check("10.0.0.9")
    assert ok and "10.0.0.0/24" in reason
    assert s.check("$(rm -rf /)") == (False, "not a valid target: '$(rm -rf /)'")
    assert not s.contains("*.10.0.0.1")


def test_empty_scope_rejected():
    with pytest.raises(ScopeError):
        Scope.build([])


def test_roundtrip_serialization():
    s = Scope.build(["10.0.0.0/24"], exclude=["10.0.0.1"])
    s2 = Scope.model_validate(s.model_dump())
    assert s2.contains("10.0.0.2") and not s2.contains("10.0.0.1")


def test_network_targets():
    s = Scope.build(["10.0.0.0/24", "*.example.com"], exclude=["10.0.0.1", "10.0.0.128/25"])
    ok, reason = s.check("10.0.0.0/24")
    assert ok and "must skip 10.0.0.1, 10.0.0.128/25" in reason
    assert s.check("10.0.0.0/26") == (True, "in scope via '10.0.0.0/24'; must skip 10.0.0.1")
    assert s.check("10.0.0.64/26") == (True, "in scope via '10.0.0.0/24'")
    assert s.check("10.0.0.0/23")[0] is False            # larger than the scope
    assert s.check("10.0.1.0/24")[0] is False            # elsewhere
    assert s.check("10.0.0.192/26") == (False, "excluded by '10.0.0.128/25'")
    assert s.check("2001:db8::/64")[0] is False          # other IP version
    assert s.check("10.0.0.0/33")[0] is False            # garbage
    assert s.exclusions_within("10.0.0.0/25") == ["10.0.0.1/32"]
