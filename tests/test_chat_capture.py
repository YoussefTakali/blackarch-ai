from blackarch_ai.cli.chat import _ATTACK_RE, _SNIFF_RE, _clean_capture, _parse_connections


def test_attack_menu_op_ids_all_registered():
    from blackarch_ai.cli.chat import ChatApp
    from blackarch_ai.execution.operations import load_operations
    cat = load_operations()
    ids = set(cat.ids())
    menu = (ChatApp._BRUTE_SERVICES + ChatApp._SPRAY_SERVICES
            + ChatApp._DEFAULTCRED_SERVICES)
    for _label, op_id in menu:
        assert op_id in ids, f"{op_id} missing from operations.toml"
    assert "sqlmap-test" in ids


def test_norm_service_maps_web_variants():
    from blackarch_ai.cli.chat import _norm_service
    assert _norm_service("http-proxy") == "http"
    assert _norm_service("https-alt") == "https"
    assert _norm_service("ssl/http") == "https"
    assert _norm_service("ssh") == "ssh"
    assert _norm_service("microsoft-ds") == "microsoft-ds"


def test_playbook_dispatches_specialists_per_service():
    # the playbook must cover web, smb and login services with real op ids
    from blackarch_ai.cli.chat import _PLAYBOOK
    from blackarch_ai.execution.operations import load_operations
    ids = set(load_operations().ids())
    for svc, steps in _PLAYBOOK.items():
        assert steps, f"{svc} has no playbook steps"
        for op_id, how in steps:
            assert op_id in ids, f"{op_id} ({svc}) not a registered op"
            assert how in ("host", "url")


def test_actions_from_move_drops_hallucinated_ops():
    from blackarch_ai.cli.chat import ChatApp, _NextMove
    from blackarch_ai.cli.common import Context
    app = object.__new__(ChatApp)
    app.ctx = Context()
    mv = _NextMove.model_validate({"actions": [
        {"op_id": "whatweb", "target": "http://10.0.0.5"},
        {"op_id": "rm-rf-everything"},            # not registered → must be dropped
    ]})
    acts = app._actions_from_move(mv)
    assert [a["op_id"] for a in acts] == ["whatweb"]


def test_assess_loop_reacts_to_new_facts():
    # The decision loop must unlock new actions when a fact is discovered:
    # finding WordPress on a web service should add a wpscan action.
    from blackarch_ai.cli.chat import ChatApp
    from blackarch_ai.cli.common import Context
    app = object.__new__(ChatApp)
    app.ctx = Context()
    facts = {"svc": {("10.0.0.5", "80", "http")}, "tech": set(), "cred": set()}
    wave1 = {a["op_id"] for a in app._react(facts)}
    assert "whatweb" in wave1 and "wpscan" not in wave1
    facts["tech"].add(("http://10.0.0.5", "wordpress"))   # discovered mid-run
    wave2 = {a["op_id"] for a in app._react(facts)}
    assert "wpscan" in wave2


def test_parse_facts_extracts_wordpress_and_creds():
    from types import SimpleNamespace
    from blackarch_ai.cli.chat import ChatApp
    app = object.__new__(ChatApp)
    res = SimpleNamespace(stdout="Detected: WordPress 6.4", stderr="")
    f = app._parse_facts({"op_id": "whatweb", "target": "http://10.0.0.5"}, res)
    assert ("http://10.0.0.5", "wordpress") in f["tech"]
    res2 = SimpleNamespace(stdout="[22][ssh] host: 10.0.0.5 login: root password: toor", stderr="")
    f2 = app._parse_facts({"op_id": "defaultcreds-ssh", "target": "10.0.0.5"}, res2)
    assert f2["cred"]


def test_hydra_hit_detector():
    from blackarch_ai.cli.chat import _hydra_hit
    assert _hydra_hit("[22][ssh] host: 10.0.0.5   login: root   password: calvin")
    assert not _hydra_hit("0 valid passwords found")
    assert not _hydra_hit("")


def test_pwn_intent_triggers_assessment():
    from blackarch_ai.cli.chat import _PWN_RE, _RECON_RE
    def assess(msg):
        low = msg.lower()
        return bool(_PWN_RE.search(msg)) and (
            bool(_RECON_RE.search(msg))
            or any(w in low for w in ("everyone", "them", "their", "all ")))
    assert assess("can you hack everyone on my network")
    assert assess("hacking all devices here")
    assert assess("get their credentials")
    assert not assess("scan my network")          # discovery only → recon
    assert not assess("what services are running?")


def test_attack_regex_matches_brute_force_intent():
    assert _ATTACK_RE.search("brute force the ssh login on 192.168.0.5")
    assert _ATTACK_RE.search("crack the password for admin")
    assert _ATTACK_RE.search("try a dictionary attack")
    assert not _ATTACK_RE.search("what is the password policy?")
    assert not _ATTACK_RE.search("scan the network")


def test_parse_connections_extracts_dns_and_https():
    out = (
        "12:00:01.1 IP 192.168.0.79.54321 > 192.168.0.1.53: 1+ A? instagram.com. (33)\n"
        "12:00:01.2 IP 192.168.0.79.54322 > 192.168.0.1.53: 2+ AAAA? scontent.cdninstagram.com. (40)\n"
        "12:00:01.3 IP 192.168.0.79.40001 > 157.240.1.35.443: Flags [S], seq 1\n"
        "12:00:01.4 IP 192.168.0.79.40002 > 157.240.1.35.443: Flags [.], ack 1\n"
        "12:00:01.5 IP 192.168.0.79.40003 > 31.13.70.7.443: Flags [S]\n"
    )
    domains, ips = _parse_connections(out)
    assert domains == ["instagram.com", "scontent.cdninstagram.com"]
    assert ips == ["157.240.1.35", "31.13.70.7"]  # deduped, order preserved


def test_parse_connections_empty():
    assert _parse_connections("") == ([], [])


def test_clean_capture_drops_progress_and_counts_forward_errors():
    raw = (
        "Listening on:\n"
        "  wlp0s20f3 -> 76:CF:E3:CF:A5:2E\n"
        "/ |=>                |   0.39 %\r- |==>               |   2.35 %\r"
        "SEND L3 ERROR: 2828 byte packet destined to 192.168.0.79 was not forwarded\n"
        "SEND L3 ERROR: 2828 byte packet destined to 192.168.0.79 was not forwarded\n"
        "SEND L3 ERROR: 2828 byte packet destined to 192.168.0.79 was not forwarded\n"
    )
    cleaned, fwd = _clean_capture(raw)
    assert fwd == 3
    assert "SEND L3 ERROR" not in cleaned
    assert "%" not in cleaned  # progress spinner stripped
    assert "Listening on:" in cleaned
    assert "76:CF:E3:CF:A5:2E" in cleaned


def test_clean_capture_folds_consecutive_duplicates():
    cleaned, _ = _clean_capture("ARP reply\nARP reply\nARP reply\nDHCP\n")
    assert cleaned == "ARP reply ×3\nDHCP"


def test_clean_capture_empty():
    assert _clean_capture("") == ("", 0)
    assert _clean_capture(None) == ("", 0)


def test_sniff_regex_matches_intent_not_questions():
    assert _SNIFF_RE.search("sniff all devices on my wifi")
    assert _SNIFF_RE.search("mitm the router")
    assert _SNIFF_RE.search("capture packets on the network")
    assert not _SNIFF_RE.search("what services are running?")
    assert not _SNIFF_RE.search("scan my network")
