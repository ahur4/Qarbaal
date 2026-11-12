from __future__ import annotations

from qarbaal import IOCType, defang, refang


def test_refang_reference_rules() -> None:
    text = (
        "hxxps://evil[.]example[.]com hxxp://a(dot)b{dot}c "
        "admin[at]corp[.]com fxp://x [://] [:] a dot b"
    )
    assert refang(text) == "https://evil.example.com http://a.b.c admin@corp.com ftp://x :// : a.b"


def test_refang_at_variants_and_case() -> None:
    assert refang("a[@]b (@)c [at]d (at)e") == "a@b @c @d @e"
    assert refang("HXXPS://A[DOT]B") == "https://A.B"
    assert refang("FXP://A[.]B") == "ftp://A.B"
    assert refang("{dot} (dot) [dot] {.} (.) [.]") == ". . . . . ."
    assert refang("a\tdot\tb") == "a.b"


def test_defang_url_email_and_ip() -> None:
    assert defang("https://evil.example/a.b", "url") == "hxxps://evil[.]example/a[.]b"
    assert defang("ftp://evil.example", IOCType.URL) == "fxp://evil[.]example"
    assert defang("a.b@c.d", "email") == "a[.]b[at]c[.]d"
    assert defang("1.2.3.4", "") == "1[.]2[.]3[.]4"


def test_defang_then_refang_round_trip() -> None:
    url = "https://evil.example/a.b"
    email = "analyst@corp.example"
    assert refang(defang(url, "url")) == url
    assert refang(defang(email, "email")) == email
    assert refang(defang("8.8.8.8")) == "8.8.8.8"


def test_custom_refang_pattern_runs_first() -> None:
    assert refang("evil[dotdot]com", extra=[(r"\[dotdot\]", ".")]) == "evil.com"
