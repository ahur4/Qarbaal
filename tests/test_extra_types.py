from __future__ import annotations

import re

from qarbaal.extract import IOCExtractor
from qarbaal.patterns import PatternSpec


def test_sha512_is_not_also_a_shorter_hash() -> None:
    digest = "ab" * 64
    result = IOCExtractor().extract(digest)
    assert result.values("sha512") == (digest,)
    assert result.get("sha256") == ()
    assert result.get("sha1") == ()
    assert result.get("md5") == ()


def test_cidr_keeps_the_embedded_address() -> None:
    result = IOCExtractor().extract("pivot 192.168.1.5/24 and 2001:db8::/32")
    assert result.values("cidr") == ("192.168.1.5/24", "2001:db8::/32")
    assert result.get("cidr")[0].tags == ("private",)
    assert result.get("cidr")[0].normalized == "192.168.1.0/24"
    assert "192.168.1.5" in result.values("ip")
    assert result.get("cidr")[1].normalized == "2001:db8::/32"


def test_mac_and_asn() -> None:
    result = IOCExtractor().extract("mac AA-BB-CC-DD-EE-FF peer AS13335 and as13335 AS0")
    assert result.values("mac") == ("AA-BB-CC-DD-EE-FF",)
    assert result.get("mac")[0].normalized == "aa:bb:cc:dd:ee:ff"
    assert result.values("asn") == ("AS13335",)
    assert extract_invalid_asn().valid is False


def extract_invalid_asn():
    return IOCExtractor().extract("AS4294967296").get("asn")[0]


def test_colon_mac_is_not_also_ipv6() -> None:
    mac = "00:1A:2B:3C:4D:5E"
    address = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    bare = IOCExtractor().extract(mac)
    assert bare.values("mac") == (mac,)
    assert bare.get("ip6") == ()

    every_type = IOCExtractor(extract_types=["all"]).extract(mac)
    assert every_type.values("mac") == (mac,)
    assert every_type.get("ip6") == ()

    ipv6 = IOCExtractor().extract(f"{address} and 2001:db8::1 and 2001:db8::/32")
    assert ipv6.get("mac") == ()
    assert ipv6.values("ip6") == (address.lower(), "2001:db8::")
    assert ipv6.values("cidr") == ("2001:db8::/32",)

    both = IOCExtractor().extract(f"nic {mac} host {address}")
    assert both.values("mac") == (mac,)
    assert both.values("ip6") == (address.lower(),)


def test_mac_does_not_eat_a_seventh_octet() -> None:
    assert IOCExtractor().extract("00:11:22:33:44:55:66").get("mac") == ()
    assert IOCExtractor().extract("00:11:22:33:44").get("mac") == ()


def test_ja3_ja3s_and_jarm_are_independent() -> None:
    ja3 = "d41d8cd98f00b204e9800998ecf8427e"
    ja3s = "e3b0c44298fc1c149afbf4c8996fb924"
    jarm = "ab" * 31
    text = f"JA3: {ja3}\nJA3S={ja3s}\nJARM: {jarm}\n{jarm}"
    result = IOCExtractor().extract(text)
    assert result.values("ja3") == (ja3,)
    assert result.values("ja3s") == (ja3s,)
    assert result.values("jarm") == (jarm,)
    assert ja3 in result.values("md5")
    assert jarm not in result.values("sha256")


def test_noisy_types_are_opt_in() -> None:
    text = "\n".join(
        [
            r"C:\Windows\System32\cmd.exe",
            r"\\files\share\payload.exe",
            "/usr/local/bin/nc",
            r"Global\WinDefendScan",
            "User-Agent: Mozilla/5.0 (compatible)",
            "C:\\notes.txt",
            "/tmp/x",
        ]
    )
    assert IOCExtractor().extract(text).get("path") == ()
    assert IOCExtractor().extract(text).get("mutex") == ()
    assert IOCExtractor().extract(text).get("user_agent") == ()
    opted = IOCExtractor(extract_types=["path", "mutex", "user_agent"]).extract(text)
    paths = set(opted.values("path"))
    assert r"C:\Windows\System32\cmd.exe" in paths
    assert r"\\files\share\payload.exe" in paths
    assert "/usr/local/bin/nc" in paths
    assert r"C:\notes.txt" not in paths
    assert "/tmp/x" not in paths
    assert opted.values("mutex") == (r"Global\WinDefendScan",)
    assert opted.values("user_agent") == ("Mozilla/5.0 (compatible)",)


def test_hash_alias_and_unknown_type() -> None:
    selected = IOCExtractor(extract_types=["hash"]).types
    assert selected == ("md5", "sha1", "sha256", "sha512")
    try:
        IOCExtractor(extract_types=["not-a-type"])
    except ValueError as exc:
        assert "not-a-type" in str(exc)
    else:
        raise AssertionError("unknown type was accepted")


def test_custom_pattern() -> None:
    spec = PatternSpec("case", r"\bCASE-\d{4}\b", flags=re.IGNORECASE, folds="upper")
    result = IOCExtractor(custom_patterns=[spec]).extract("ticket case-1042 today")
    assert result.values("case") == ("CASE-1042",)
    assert result.get("case")[0].valid is True
