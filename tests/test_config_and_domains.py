import pytest

from blackarch_ai.config import DEFAULT_CONFIG_TOML, config_dir, load_settings
from blackarch_ai.core.domains import DomainConfigError, load_domains
from blackarch_ai.tools.pacman import parse_group_listing

# The 52 blackarch-* groups present when this project was created (2026-11).
BLACKARCH_CATEGORIES = set("""
ai anti-forensic automation automobile backdoor binary bluetooth code-audit config
cracker crypto database debugger decompiler defensive disassembler dos drone
exploitation fingerprint firmware forensic fuzzer gpu hardware honeypot ids keylogger
malware misc mobile networking nfc packer proxy radio recon reocn reversing scanner
sniffer social spoof stego threat-model tunnel unpacker voip webapp windows wireless
wordlist""".split())


def test_defaults_without_file():
    s = load_settings()
    assert s.llm.profile_for("orchestrator").model.startswith("nvidia_nim/")
    assert s.llm.profile_for("web") is s.llm.profiles["agent"]


def test_default_config_file_parses_and_overrides():
    path = config_dir() / "config.toml"
    path.parent.mkdir(parents=True)
    path.write_text(DEFAULT_CONFIG_TOML + '\n[llm.profiles.web]\nmodel = "openai/gpt-5.5"\n')
    s = load_settings()
    assert s.llm.profile_for("web").chain() == ["openai/gpt-5.5"]
    assert s.llm.profile_for("network").model == s.llm.profiles["agent"].model


def test_user_profile_replaces_default_fallbacks():
    path = config_dir() / "config.toml"
    path.parent.mkdir(parents=True)
    path.write_text('[llm.profiles.orchestrator]\nmodel = "anthropic/claude-sonnet-5-5"\n')
    assert load_settings().llm.profile_for("orchestrator").fallbacks == []


def test_invalid_reasoning_effort():
    path = config_dir() / "config.toml"
    path.parent.mkdir(parents=True)
    path.write_text('[llm.profiles.orchestrator]\nmodel = "x/y"\nreasoning_effort = "max"\n')
    with pytest.raises(ValueError):
        load_settings()


def test_every_blackarch_category_assigned_exactly_once():
    d = load_domains()
    assert d.all_categories() == BLACKARCH_CATEGORIES
    assert d.owner["webapp"] == "web" and d.owner["misc"] == "shared"
    assert d.high_impact <= d.all_categories()


def test_duplicate_category_rejected(tmp_path):
    p = tmp_path / "a.toml"
    p.write_text('[[agent]]\nid="a"\nname="A"\ncategories=["x"]\n'
                 '[[agent]]\nid="b"\nname="B"\ncategories=["x"]\n')
    with pytest.raises(DomainConfigError, match="both"):
        load_domains(p)


def test_parse_group_listing():
    text = "blackarch-webapp sqlmap\nblackarch-webapp nikto\nbase-devel gcc\nblackarch nmap\n"
    assert parse_group_listing(text) == {"webapp": {"sqlmap", "nikto"}}
