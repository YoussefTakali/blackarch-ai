from blackarch_ai.security.redaction import MASK, Redactor


def r(text, **kw):
    return Redactor(secret_values=[], **kw).redact(text)


def test_provider_tokens():
    for token in [
        "sk-ant-api03-" + "a" * 40,
        "sk-proj-" + "b" * 40,
        "nvapi-" + "C" * 50,
        "AIza" + "d" * 35,
        "ghp_" + "e" * 36,
        "AKIAABCDEFGHIJKLMNOP",
    ]:
        out = r(f"key is {token} ok")
        assert token not in out.text and MASK in out.text, token


def test_private_key_block():
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----"
    out = r(f"here:\n{pem}\nend")
    assert "abc" not in out.text and out.counts["private_key"] == 1


def test_assignments_keep_key_name():
    out = r('password=hunter22 and api_key: "s3cr3tvalue" token=abcd1234')
    assert "hunter22" not in out.text and "s3cr3tvalue" not in out.text
    assert "password=" in out.text and 'api_key: "' in out.text
    assert out.counts["assignment"] == 3


def test_url_credentials_and_bearer():
    out = r("curl -H 'Authorization: Bearer abc.def.ghi' https://admin:pa55@host/x")
    assert "pa55" not in out.text and "abc.def.ghi" not in out.text
    assert "https://[REDACTED]@host/x" in out.text


def test_env_secret_literals():
    red = Redactor(secret_values=["supersecretvalue123"])
    out = red.redact("leaked supersecretvalue123 here")
    assert out.text == f"leaked {MASK} here" and out.counts["env_secret"] == 1


def test_custom_patterns_and_clean_text_unchanged():
    out = r("employee id EMP-12345", extra_patterns=[r"EMP-\d+"])
    assert out.text == f"employee id {MASK}"
    clean = "nmap -sV 10.0.0.5 found nginx 1.24 on port 443"
    assert r(clean).text == clean


def test_redact_messages_does_not_mutate_input():
    msgs = [{"role": "user", "content": "password=hunter22"},
            {"role": "user", "content": [{"type": "text", "text": "token=abcd1234"}]}]
    out, counts = Redactor(secret_values=[]).redact_messages(msgs)
    assert msgs[0]["content"] == "password=hunter22"
    assert "hunter22" not in out[0]["content"]
    assert "abcd1234" not in out[1]["content"][0]["text"]
    assert sum(counts.values()) == 2
