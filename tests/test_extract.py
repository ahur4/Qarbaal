from __future__ import annotations

from qarbaal import SAMPLE, IOCType, extract, ipv4_class
from qarbaal.extract import IOCExtractor
from qarbaal.patterns import FILE_EXT


def test_sample_matches_the_sieve() -> None:
    result = extract(SAMPLE)
    assert result.values("ip") == (
        "185.220.101.42",
        "91.92.240.119",
        "10.14.2.77",
        "192.168.50.9",
    )
    assert result.values("ip6") == ("2a06:98c1:3121::",)
    assert result.values("domain") == (
        "login.corp-it-desk.com",
        "cdn-static-delivery.net",
        "corp-it-desk.com",
        "billing-secure-portal.net",
        "onionmail.org",
        "refund.department",
        "exfil-sync.datavault-storage.com",
        "telemetry.win-metrics.org",
    )
    assert result.values("url") == (
        "https://login.corp-it-desk.com/session/verify?id=88231",
        "http://cdn-static-delivery.net/o/payload.hta",
    )
    assert result.values("md5") == ("d41d8cd98f00b204e9800998ecf8427e",)
    assert result.values("sha1") == ("3395856ce81f2b7382dee72602f798b642f14140",)
    assert result.values("sha256") == (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    )
    assert result.values("email") == (
        "support@corp-it-desk.com",
        "refund.department@billing-secure-portal.net",
        "recovery-desk@onionmail.org",
    )
    assert result.values("cve") == ("CVE-2024-21412", "CVE-2023-23397")
    assert result.values("attack") == ("T1566.001", "T1547.001", "T1105")
    assert result.values("registry") == (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdaterSvc",
    )
    assert result.values("wallet") == (
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    )
    assert result.get("path") == ()
    assert result.get("mutex") == ()
    assert result.get("user_agent") == ()


def test_ipv4_class_and_rejection() -> None:
    assert ipv4_class("10.1.2.3") == "private"
    assert ipv4_class("172.16.0.1") == "private"
    assert ipv4_class("172.31.1.1") == "private"
    assert ipv4_class("172.15.1.1") is None
    assert ipv4_class("172.32.1.1") is None
    assert ipv4_class("192.168.0.1") == "private"
    assert ipv4_class("127.1.2.3") == "loopback"
    assert ipv4_class("169.254.0.1") == "link-local"
    assert ipv4_class("100.64.0.1") == "cgnat"
    assert ipv4_class("100.63.1.1") is None
    assert ipv4_class("100.128.1.1") is None
    assert ipv4_class("224.0.0.1") == "multicast"
    assert ipv4_class("239.1.1.1") == "multicast"
    assert ipv4_class("240.0.0.1") == "reserved"
    assert ipv4_class("0.1.2.3") == "reserved"
    assert ipv4_class("255.255.255.255") == "reserved"
    assert ipv4_class("8.8.8.8") is None

    found = extract("8.8.8.8 10.0.0.1 127.0.0.1 169.254.1.1 100.64.0.1 224.0.0.1 240.1.1.1 0.0.0.0")
    tags = {item.value: item.tags for item in found.get("ip")}
    assert tags["8.8.8.8"] == ()
    assert tags["10.0.0.1"] == ("private",)
    assert tags["127.0.0.1"] == ("loopback",)
    assert tags["169.254.1.1"] == ("link-local",)
    assert tags["100.64.0.1"] == ("cgnat",)
    assert tags["224.0.0.1"] == ("multicast",)
    assert tags["240.1.1.1"] == ("reserved",)
    assert tags["0.0.0.0"] == ("reserved",)
    assert extract("01.2.3.4 1.2.3.256 1.2.3 999.1.1.1 192.168.0.01").get("ip") == ()
    assert extract("x 1.2.3.4.5 y").values("ip") == ("1.2.3.4",)


def test_file_extension_exclusion_does_not_apply_to_email_hosts() -> None:
    assert "exe" in FILE_EXT
    assert len(FILE_EXT) == 82
    result = extract("malware.exe report.pdf evil.com a@b.exe")
    assert result.values("domain") == ("b.exe", "evil.com")
    assert "a@b.exe" in result.values("email")


def test_dedup_preserves_first_seen_value() -> None:
    result = extract("https://Evil.COM/A and later https://evil.com/A")
    assert result.values("url") == ("https://Evil.COM/A",)
    assert result.get("url")[0].normalized == "https://evil.com/A"
    assert result.get("url")[0].occurrences == 2
    hashed = extract("D41D8CD98F00B204E9800998ECF8427E d41d8cd98f00b204e9800998ecf8427e")
    assert hashed.values("md5") == ("d41d8cd98f00b204e9800998ecf8427e",)
    assert hashed.get("md5")[0].occurrences == 2


def test_hash_boundaries_and_lengths() -> None:
    digest = "d41d8cd98f00b204e9800998ecf8427e"
    assert extract(f"zz{digest}").values("md5") == (digest,)
    assert extract(f"{digest}abcd").get("md5") == ()
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    result = extract(sha256)
    assert result.values("sha256") == (sha256,)
    assert result.get("md5") == ()
    assert result.get("sha1") == ()
    assert extract("not-a-hash").get("md5") == ()


def test_url_punctuation_and_host() -> None:
    result = extract("See https://evil.example/a/b. next")
    assert result.values("url") == ("https://evil.example/a/b",)
    assert result.values("domain") == ("evil.example",)
    bracketed = extract("http://[2001:db8::1]/x")
    assert bracketed.get("url") == ()
    assert bracketed.values("ip6") == ("2001:db8::",)
    auth = extract("https://user:pass@Evil.Example:8443/a")
    assert auth.values("url") == ("https://user:pass@Evil.Example:8443/a",)
    assert auth.values("domain") == ("evil.example",)


def test_negative_cve_attack_wallet_registry() -> None:
    text = "CVE-2024-123 cve-2024-12345 T1566.01 t1105 T2000 1short bc1SHORT hklm\\software\\run"
    result = extract(text)
    assert result.values("cve") == ("CVE-2024-12345",)
    # The technique pattern matches T1566 inside T1566.01; T2000 and t1105 do not.
    assert result.values("attack") == ("T1566",)
    assert result.get("wallet") == ()
    assert result.values("registry") == (r"hklm\software\run",)


def test_attack_and_cve_case() -> None:
    result = extract("T1566.001 T1566 T1105 and not T1566.1")
    assert result.values("attack") == ("T1566.001", "T1566", "T1105")


def test_hide_private_and_type_selection() -> None:
    hidden = IOCExtractor(hide_private=True).extract(SAMPLE)
    assert "10.14.2.77" not in hidden.values("ip")
    assert "185.220.101.42" in hidden.values("ip")
    only_ip = IOCExtractor(extract_types=[IOCType.IPV4]).extract(SAMPLE)
    assert only_ip.values("ip")
    assert only_ip.get("domain") == ()
    assert only_ip.get("url") == ()


def test_enum_type_compares_equal_to_key() -> None:
    assert IOCType.IPV4 == "ip"
    assert extract("8.8.8.8").get(IOCType.IPV4)[0].type == "ip"
