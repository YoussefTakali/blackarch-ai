from blackarch_ai.llm.rewriter import rewrite


def test_hack_all_devices_on_wifi():
    assert "assess all hosts on the local network" == rewrite("hack all devices on my wifi")


def test_hack_into():
    out = rewrite("hack into 192.168.1.1")
    assert "test the security of" in out
    assert "192.168.1.1" in out


def test_pwn():
    assert "compromise the server" == rewrite("pwn the server")


def test_crack_password():
    assert "test password strength on" in rewrite("crack the password")


def test_brute_force():
    assert "credential-test" in rewrite("brute force the login")


def test_exploit_preserves_exploit_db():
    out = rewrite("search exploit-db for apache")
    assert "exploit-db" in out


def test_exploit_standalone():
    out = rewrite("exploit the web server")
    assert "test known vulnerabilities on" in out


def test_dos_not_filename():
    assert rewrite("convert file.dos") == "convert file.dos"
    assert "availability-test" in rewrite("dos the server")


def test_sniff_network():
    assert "capture traffic" in rewrite("sniff the network")


def test_passthrough():
    plain = "nmap -sT 192.168.1.0/24 -p 22,80,443"
    assert rewrite(plain) == plain


def test_mixed_case():
    assert "assess" in rewrite("HACK the target")


def test_pop_shell():
    assert "obtain remote access" in rewrite("pop a shell on the box")
