import importlib
import os

import pytest
from typer.testing import CliRunner

from blackarch_ai.core.domains import load_domains
from blackarch_ai.storage.store import Store
from blackarch_ai.tools import documentation as docs
from blackarch_ai.tools.discovery import Discovery
from blackarch_ai.tools.pacman import parse_qi, parse_ql
from blackarch_ai.tools.registry import Registry, fts_query

QG = """\
blackarch-scanner portprobe
blackarch-webapp webpoke
blackarch-fuzzer webpoke
blackarch-backdoor shadyshell
blackarch-misc wordbag
blackarch-defensive cloudaudit
"""
Q = "portprobe 1.0-1\nwebpoke 2.3-1\nshadyshell 0.1-1\nwordbag 5-1\ncloudaudit 3-1\nnmap 7.99-1\ncoreutils 9.5-1\n"


def qi_block(name, version, desc, groups="None", url="https://example.org"):
    return (f"Name            : {name}\nVersion         : {version}\n"
            f"Description     : {desc}\nArchitecture    : x86_64\nURL             : {url}\n"
            f"Groups          : {groups}\nDepends On      : glibc  libpcap\n"
            f"                  openssl\n")


QI = "\n".join([
    qi_block("portprobe", "1.0-1", "Fast TCP port prober", "blackarch blackarch-scanner"),
    qi_block("webpoke", "2.3-1", "HTTP directory brute forcer", "blackarch blackarch-webapp blackarch-fuzzer"),
    qi_block("shadyshell", "0.1-1", "Reverse shell generator", "blackarch blackarch-backdoor"),
    qi_block("wordbag", "5-1", "Collection of wordlists", "blackarch blackarch-misc", url="None"),
    qi_block("cloudaudit", "3-1", "Audit AWS and Azure accounts for misconfigurations", "blackarch blackarch-defensive"),
    qi_block("nmap", "7.99-1", "Utility for network discovery and security auditing"),
])

QL = """\
portprobe /usr/bin/
portprobe /usr/bin/portprobe
portprobe /usr/share/man/man1/portprobe.1.gz
portprobe /usr/share/man/de/man1/portprobe.1.gz
webpoke /usr/bin/webpoke
webpoke /usr/bin/webpoke-helper.conf
shadyshell /usr/bin/shadyshell
wordbag /usr/share/wordbag/common.txt
cloudaudit /usr/bin/cloudaudit
nmap /usr/bin/ncat
nmap /usr/bin/nmap
nmap /usr/share/man/man1/ncat.1.gz
nmap /usr/share/man/man1/nmap.1.gz
nmap /usr/share/man/man3/libfoo.3.gz
"""

MAN = {
    "/usr/share/man/man1/portprobe.1.gz":
        "NAME\n       portprobe - probe TCP ports quickly\n\nSYNOPSIS\n       portprobe [-p ports] host\n\n"
        "DESCRIPTION\n       Sends SYN packets to discover open services and banners.\n",
    "/usr/share/man/man1/nmap.1.gz":
        "NAME\n       nmap - Network exploration tool and security / port scanner\n\nSYNOPSIS\n"
        "       nmap [Scan Type...] [Options] {target specification}\n\nDESCRIPTION\n"
        "       Nmap detects TLS ciphers with ssl-enum-ciphers and does OS fingerprinting.\n",
    "/usr/share/man/man1/ncat.1.gz": "NAME\n       ncat - Concatenate and redirect sockets\n",
}


def fake_runner(args):
    if args == ["-Qg"]:
        return QG
    if args == ["-Q"]:
        return Q
    if args[0] == "-Qi":
        return QI
    if args[0] == "-Ql":
        return QL
    raise AssertionError(args)


@pytest.fixture
def fake_root(tmp_path):
    root = tmp_path / "root"
    for path, mode in [("usr/bin/portprobe", 0o755), ("usr/bin/webpoke", 0o755),
                       ("usr/bin/webpoke-helper.conf", 0o644), ("usr/bin/shadyshell", 0o755),
                       ("usr/bin/cloudaudit", 0o755), ("usr/bin/nmap", 0o755),
                       ("usr/bin/ncat", 0o755)]:
        f = root / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("#!/bin/sh\n")
        os.chmod(f, mode)
    return root


def make_discovery(root):
    return Discovery(load_domains(), runner=fake_runner, root=root,
                     man_renderer=lambda p: MAN.get(p), extra_tools={"nmap": ["scanner"]},
                     workers=2)


@pytest.fixture
def scan(fake_root):
    return make_discovery(fake_root).scan()


def by_name(result):
    return {t.name: t for t in result.tools}


def test_parse_qi_handles_wrapped_fields_and_none():
    info = parse_qi(QI)
    assert info["webpoke"].groups == ["blackarch", "blackarch-webapp", "blackarch-fuzzer"]
    assert info["nmap"].groups == [] and info["wordbag"].url == ""
    assert info["portprobe"].version == "1.0-1"


def test_parse_ql():
    files = parse_ql(QL)
    assert "/usr/bin/nmap" in files["nmap"] and files["wordbag"] == ["/usr/share/wordbag/common.txt"]


def test_discovery_records(scan):
    tools = by_name(scan)
    assert set(tools) == {"portprobe", "webpoke", "shadyshell", "wordbag", "cloudaudit", "nmap"}
    assert "coreutils" not in tools  # not a security package

    pp = tools["portprobe"]
    assert pp.source == "blackarch" and pp.agents == ["network"]
    assert pp.executables == ["/usr/bin/portprobe"]
    assert pp.man_pages == ["/usr/share/man/man1/portprobe.1.gz"]  # German page skipped
    assert "probe TCP ports" in pp.summary and "Synopsis:" in pp.summary

    wp = tools["webpoke"]
    assert wp.categories == ["fuzzer", "webapp"] and wp.agents == ["web"]
    assert wp.executables == ["/usr/bin/webpoke"]  # non-executable file ignored

    assert tools["shadyshell"].permission == "high_impact"
    assert tools["portprobe"].permission == "unclassified"
    assert tools["wordbag"].kind == "data/library" and tools["wordbag"].agents == ["shared"]
    assert set(tools["cloudaudit"].agents) == {"forensics", "cloud"}  # keyword match

    nm = tools["nmap"]
    assert nm.source == "arch" and nm.agents == ["network"]
    # The package's own page wins over its other commands; man3 is excluded.
    assert nm.man_pages == ["/usr/share/man/man1/nmap.1.gz", "/usr/share/man/man1/ncat.1.gz"]
    assert nm.summary.startswith("nmap - Network exploration")


def test_registry_roundtrip_and_search(scan, tmp_path):
    reg = Registry(Store(tmp_path / "r.db"))
    saved = reg.save(scan)
    assert saved.tools == 6 and reg.count() == 6
    assert reg.get("ncat").name == "nmap"  # lookup by executable
    assert reg.get("nope") is None
    assert [t.name for t in reg.list(agent="web")] == ["webpoke"]
    assert [t.name for t in reg.list(category="scanner")] == ["nmap", "portprobe"]
    assert "wordbag" not in [t.name for t in reg.list(commands_only=True)]

    assert reg.search("tls ciphers")[0].tool.name == "nmap"  # found via man page text
    assert reg.search("directory brute force")[0].tool.name == "webpoke"
    assert [h.tool.name for h in reg.search("probe", agent="web")] == []
    assert reg.search("the and of") == []

    ctx = reg.context_for("scan open ports")
    assert "portprobe 1.0-1" in ctx and "commands: portprobe" in ctx

    # Rescan replaces rather than duplicates.
    reg.save(scan)
    assert reg.count() == 6 and len(reg.search("portprobe")) == 1


def test_fts_query_is_safe():
    # Quotes stripped, operators/stopwords dropped, every term quoted.
    assert fts_query('nmap" OR 1=1; DROP') == '"nmap" OR "drop"'
    assert fts_query('sql-injection NEAR(x)') == '"sql-injection" OR "near"'
    assert fts_query("?? !!") is None


def test_stale_detection(scan, tmp_path, monkeypatch):
    import blackarch_ai.tools.registry as regmod

    reg = Registry(Store(tmp_path / "s.db"))
    assert reg.is_stale()
    scan.pacman_db_mtime = 1000.0
    reg.save(scan)
    monkeypatch.setattr(regmod, "local_db_mtime", lambda: 1000.0)
    assert not reg.is_stale()
    monkeypatch.setattr(regmod, "local_db_mtime", lambda: 5000.0)
    assert reg.is_stale()


def test_documentation_helpers():
    assert docs.is_english_man_page("/usr/share/man/man8/foo.8.gz")
    assert not docs.is_english_man_page("/usr/share/man/de/man1/foo.1.gz")
    assert not docs.is_english_man_page("/usr/share/man/man3/foo.3.gz")
    assert docs.clean("N\x08NA\x08AM\x08ME\x08E\n\x1b[1mbold\x1b[0m") == "NAME\nbold"
    s = docs.sections("NAME\n   x - y\n\nOPTIONS\n   -a  all\n")
    assert s == {"NAME": "x - y", "OPTIONS": "-a  all"}


def test_cli_tools_commands(fake_root, monkeypatch):
    import blackarch_ai.tools.discovery as disc_mod

    class FakeDiscovery(Discovery):
        def __init__(self, domains, **kw):
            super().__init__(domains, runner=fake_runner, root=fake_root,
                             man_renderer=lambda p: MAN.get(p), extra_tools={"nmap": ["scanner"]})

    monkeypatch.setattr(disc_mod, "Discovery", FakeDiscovery)
    import blackarch_ai.cli.app as mod

    app = importlib.reload(mod).app
    runner = CliRunner()

    r = runner.invoke(app, ["tools", "list"])  # auto-scans on first use
    assert r.exit_code == 0, r.output
    assert "No tool registry yet" in r.output and "portprobe" in r.output

    r = runner.invoke(app, ["tools", "list", "--agent", "web"])
    assert "webpoke" in r.output and "portprobe" not in r.output
    assert runner.invoke(app, ["tools", "list", "--agent", "bogus"]).exit_code == 2

    r = runner.invoke(app, ["tools", "show", "ncat"])
    assert r.exit_code == 0 and "nmap" in r.output and "Network" in r.output

    r = runner.invoke(app, ["tools", "show", "shadyshell"])
    assert "high-impact" in r.output

    r = runner.invoke(app, ["tools", "search", "tls", "ciphers"])
    assert r.exit_code == 0 and "nmap" in r.output

    assert runner.invoke(app, ["tools", "show", "missing"]).exit_code == 1

    r = runner.invoke(app, ["tools", "scan"])
    assert r.exit_code == 0 and "6 tools" in r.output


def test_pacman_env_avoids_wrapping(monkeypatch):
    from blackarch_ai.tools.pacman import pacman_env

    monkeypatch.setenv("COLUMNS", "110")
    env = pacman_env()
    assert "COLUMNS" not in env and env["LC_ALL"] == "C.UTF-8"
