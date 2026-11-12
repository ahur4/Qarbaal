from __future__ import annotations

from qarbaal.extract import IOCExtractor
from qarbaal.patterns import PatternSpec
from qarbaal.types import IOCType


def test_sha512_is_not_also_a_shorter_hash() -> None:
    digest = "ab" * 64
    result = IOCExtractor().extract(digest)
    assert result.values(IOCType.SHA512) == (digest,)
    assert result.get(IOCType.SHA256) == ()
    assert result.get(IOCType.SHA1) == ()
    assert result.get(IOCType.MD5) == ()


def test_cidr_keeps_the_embedded_address() -> None:
    result = IOCExtractor().extract("pivot 192.168.1.5/24 and 2001:db8::/32")
    assert result.values(IOCType.CIDR) == ("192.168.1.5/24", "2001:db8::/32")
    assert result.get(IOCType.CIDR)[0].tags == ("private",)
    assert result.get(IOCType.CIDR)[0].normalized == "192.168.1.0/24"
    assert "192.168.1.5" in result.values(IOCType.IPV4)
    assert result.get(IOCType.CIDR)[1].normalized == "2001:db8::/32"


def test_mac_and_asn() -> None:
    result = IOCExtractor().extract("mac AA-BB-CC-DD-EE-FF peer AS13335 and as13335 AS0")
    assert result.values(IOCType.MAC) == ("AA-BB-CC-DD-EE-FF",)
    assert result.get(IOCType.MAC)[0].normalized == "aa:bb:cc:dd:ee:ff"
    assert result.values(IOCType.ASN) == ("AS13335",)
    assert extract_invalid_asn().valid is False


def extract_invalid_asn():
    return IOCExtractor().extract("AS4294967296").get(IOCType.ASN)[0]


def test_colon_mac_is_not_also_ipv6() -> None:
    mac = "00:1A:2B:3C:4D:5E"
    address = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    bare = IOCExtractor().extract(mac)
    assert bare.values(IOCType.MAC) == (mac,)
    assert bare.get(IOCType.IPV6) == ()

    every_type = IOCExtractor(extract_types=["all"]).extract(mac)
    assert every_type.values(IOCType.MAC) == (mac,)
    assert every_type.get(IOCType.IPV6) == ()

    ipv6 = IOCExtractor().extract(f"{address} and 2001:db8::1 and 2001:db8::/32")
    assert ipv6.get(IOCType.MAC) == ()
    assert ipv6.values(IOCType.IPV6) == (address.lower(), "2001:db8::")
    assert ipv6.values(IOCType.CIDR) == ("2001:db8::/32",)

    both = IOCExtractor().extract(f"nic {mac} host {address}")
    assert both.values(IOCType.MAC) == (mac,)
    assert both.values(IOCType.IPV6) == (address.lower(),)


def test_mac_does_not_eat_a_seventh_octet() -> None:
    assert IOCExtractor().extract("00:11:22:33:44:55:66").get(IOCType.MAC) == ()
    assert IOCExtractor().extract("00:11:22:33:44").get(IOCType.MAC) == ()


def test_ja3_ja3s_and_jarm_are_independent() -> None:
    ja3 = "d41d8cd98f00b204e9800998ecf8427e"
    ja3s = "e3b0c44298fc1c149afbf4c8996fb924"
    jarm = "ab" * 31
    text = f"JA3: {ja3}\nJA3S={ja3s}\nJARM: {jarm}\n{jarm}"
    result = IOCExtractor().extract(text)
    assert result.values(IOCType.JA3) == (ja3,)
    assert result.values(IOCType.JA3S) == (ja3s,)
    assert result.values(IOCType.JARM) == (jarm,)
    assert ja3 in result.values(IOCType.MD5)
    assert jarm not in result.values(IOCType.SHA256)


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
    assert IOCExtractor().extract(text).get(IOCType.PATH) == ()
    assert IOCExtractor().extract(text).get(IOCType.MUTEX) == ()
    assert IOCExtractor().extract(text).get(IOCType.USER_AGENT) == ()
    opted = IOCExtractor(extract_types=[IOCType.PATH, IOCType.MUTEX, IOCType.USER_AGENT]).extract(
        text
    )
    paths = set(opted.values(IOCType.PATH))
    assert r"C:\Windows\System32\cmd.exe" in paths
    assert r"\\files\share\payload.exe" in paths
    assert "/usr/local/bin/nc" in paths
    assert r"C:\notes.txt" not in paths
    assert "/tmp/x" not in paths
    assert opted.values(IOCType.MUTEX) == (r"Global\WinDefendScan",)
    assert opted.values(IOCType.USER_AGENT) == ("Mozilla/5.0 (compatible)",)


def test_hash_alias_and_unknown_type() -> None:
    selected = IOCExtractor(extract_types=["hash"]).types
    assert selected == (IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.SHA512)
    try:
        IOCExtractor(extract_types=["not-a-type"])
    except ValueError as exc:
        assert "not-a-type" in str(exc)
    else:
        raise AssertionError("unknown type was accepted")


def test_custom_pattern() -> None:
    spec = PatternSpec(IOCType.MUTEX, r"mutex\{([^}]+)\}")
    result = IOCExtractor(custom_patterns=[spec]).extract("saw mutex{WinDefend} today")
    assert result.values(IOCType.MUTEX) == ("WinDefend",)
    assert result.get(IOCType.MUTEX)[0].valid is True
    assert IOCExtractor().extract("saw mutex{WinDefend} today").get(IOCType.MUTEX) == ()
