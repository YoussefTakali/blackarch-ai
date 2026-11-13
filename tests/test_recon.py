from blackarch_ai.orchestrator.recon import _HOST_RE, _PORT_RE, _ip_key


def test_host_regex_parses_ping_sweep():
    out = (
        "Nmap scan report for 172.26.0.1\nHost is up (0.01s latency).\n"
        "Nmap scan report for router.lan (172.26.0.2)\nHost is up.\n"
        "Nmap scan report for 172.26.0.218\nHost is up (0.013s latency).\n"
    )
    assert _HOST_RE.findall(out) == ["172.26.0.1", "172.26.0.2", "172.26.0.218"]


def test_port_regex_parses_service_scan():
    out = (
        "PORT     STATE SERVICE VERSION\n"
        "22/tcp   open  ssh     OpenSSH 9.6\n"
        "80/tcp   open  http    nginx 1.24\n"
        "443/tcp  open  https\n"
        "3306/tcp closed mysql\n"
    )
    assert _PORT_RE.findall(out) == [("22", "ssh"), ("80", "http"), ("443", "https")]


def test_ip_key_sorts_numerically():
    ips = ["172.26.0.100", "172.26.0.9", "172.26.0.21"]
    assert sorted(ips, key=_ip_key) == ["172.26.0.9", "172.26.0.21", "172.26.0.100"]
