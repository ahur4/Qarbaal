from __future__ import annotations

from qarbaal import SAMPLE, IOCType, extract, ipv4_class
from qarbaal.extract import IOCExtractor
from qarbaal.patterns import FILE_EXT


def test_sample_matches_the_sieve() -> None:
    result = extract(SAMPLE)
    assert result.values(IOCType.IPV4) == (
        "185.220.101.42",
        "91.92.240.119",
        "10.14.2.77",
        "192.168.50.9",
    )
    assert result.values(IOCType.IPV6) == ("2a06:98c1:3121::",)
    assert result.values(IOCType.DOMAIN) == (
        "login.corp-it-desk.com",
        "cdn-static-delivery.net",
        "corp-it-desk.com",
        "billing-secure-portal.net",
        "onionmail.org",
        "refund.department",
        "exfil-sync.datavault-storage.com",
        "telemetry.win-metrics.org",
    )
    assert result.values(IOCType.URL) == (
        "https://login.corp-it-desk.com/session/verify?id=88231",
        "http://cdn-static-delivery.net/o/payload.hta",
    )
    assert result.values(IOCType.MD5) == ("d41d8cd98f00b204e9800998ecf8427e",)
    assert result.values(IOCType.SHA1) == ("3395856ce81f2b7382dee72602f798b642f14140",)
    assert result.values(IOCType.SHA256) == (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    )
    assert result.values(IOCType.EMAIL) == (
        "support@corp-it-desk.com",
        "refund.department@billing-secure-portal.net",
        "recovery-desk@onionmail.org",
    )
    assert result.values(IOCType.CVE) == ("CVE-2024-21412", "CVE-2023-23397")
    assert result.values(IOCType.ATTACK) == ("T1566.001", "T1547.001", "T1105")
    assert result.values(IOCType.REGISTRY) == (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdaterSvc",
    )
    assert result.values(IOCType.WALLET) == (
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    )
    assert result.get(IOCType.PATH) == ()
    assert result.get(IOCType.MUTEX) == ()
    assert result.get(IOCType.USER_AGENT) == ()


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
    tags = {item.value: item.tags for item in found.get(IOCType.IPV4)}
    assert tags["8.8.8.8"] == ()
    assert tags["10.0.0.1"] == ("private",)
    assert tags["127.0.0.1"] == ("loopback",)
    assert tags["169.254.1.1"] == ("link-local",)
    assert tags["100.64.0.1"] == ("cgnat",)
    assert tags["224.0.0.1"] == ("multicast",)
    assert tags["240.1.1.1"] == ("reserved",)
    assert tags["0.0.0.0"] == ("reserved",)
    assert extract("01.2.3.4 1.2.3.256 1.2.3 999.1.1.1 192.168.0.01").get(IOCType.IPV4) == ()
    assert extract("x 1.2.3.4.5 y").values(IOCType.IPV4) == ("1.2.3.4",)


def test_file_extension_exclusion_does_not_apply_to_email_hosts() -> None:
    assert "exe" in FILE_EXT
    assert len(FILE_EXT) == 82
    result = extract("malware.exe report.pdf evil.com a@b.exe")
    assert result.values(IOCType.DOMAIN) == ("b.exe", "evil.com")
    assert "a@b.exe" in result.values(IOCType.EMAIL)


def test_dedup_preserves_first_seen_value() -> None:
    result = extract("https://Evil.COM/A and later https://evil.com/A")
    assert result.values(IOCType.URL) == ("https://Evil.COM/A",)
    assert result.get(IOCType.URL)[0].normalized == "https://evil.com/A"
    assert result.get(IOCType.URL)[0].occurrences == 2
    hashed = extract("D41D8CD98F00B204E9800998ECF8427E d41d8cd98f00b204e9800998ecf8427e")
    assert hashed.values(IOCType.MD5) == ("d41d8cd98f00b204e9800998ecf8427e",)
    assert hashed.get(IOCType.MD5)[0].occurrences == 2


def test_hash_boundaries_and_lengths() -> None:
    digest = "d41d8cd98f00b204e9800998ecf8427e"
    assert extract(f"zz{digest}").values(IOCType.MD5) == (digest,)
    assert extract(f"{digest}abcd").get(IOCType.MD5) == ()
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    result = extract(sha256)
    assert result.values(IOCType.SHA256) == (sha256,)
    assert result.get(IOCType.MD5) == ()
    assert result.get(IOCType.SHA1) == ()
    assert extract("not-a-hash").get(IOCType.MD5) == ()


def test_url_punctuation_and_host() -> None:
    result = extract("See https://evil.example/a/b. next")
    assert result.values(IOCType.URL) == ("https://evil.example/a/b",)
    assert result.values(IOCType.DOMAIN) == ("evil.example",)
    bracketed = extract("http://[2001:db8::1]/x")
    assert bracketed.get(IOCType.URL) == ()
    assert bracketed.values(IOCType.IPV6) == ("2001:db8::",)
    auth = extract("https://user:pass@Evil.Example:8443/a")
    assert auth.values(IOCType.URL) == ("https://user:pass@Evil.Example:8443/a",)
    assert auth.values(IOCType.DOMAIN) == ("evil.example",)


def test_negative_cve_attack_wallet_registry() -> None:
    text = "CVE-2024-123 cve-2024-12345 T1566.01 t1105 T2000 1short bc1SHORT hklm\\software\\run"
    result = extract(text)
    assert result.values(IOCType.CVE) == ("CVE-2024-12345",)
    # The technique pattern matches T1566 inside T1566.01; T2000 and t1105 do not.
    assert result.values(IOCType.ATTACK) == ("T1566",)
    assert result.get(IOCType.WALLET) == ()
    assert result.values(IOCType.REGISTRY) == (r"hklm\software\run",)


def test_attack_and_cve_case() -> None:
    result = extract("T1566.001 T1566 T1105 and not T1566.1")
    assert result.values(IOCType.ATTACK) == ("T1566.001", "T1566", "T1105")


def test_hide_private_and_type_selection() -> None:
    hidden = IOCExtractor(hide_private=True).extract(SAMPLE)
    assert "10.14.2.77" not in hidden.values(IOCType.IPV4)
    assert "185.220.101.42" in hidden.values(IOCType.IPV4)
    only_ip = IOCExtractor(extract_types=[IOCType.IPV4]).extract(SAMPLE)
    assert only_ip.values(IOCType.IPV4)
    assert only_ip.get(IOCType.DOMAIN) == ()
    assert only_ip.get(IOCType.URL) == ()


def test_indicator_type_is_the_enum() -> None:
    indicator = extract("8.8.8.8").get(IOCType.IPV4)[0]
    assert indicator.type is IOCType.IPV4
    assert indicator.type.value == "ip"
