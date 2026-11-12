"""Enrichment links. qarbaal builds the URLs and does not open them."""

from __future__ import annotations

from urllib.parse import quote

from qarbaal.types import IOCType


def pivots_for(kind: str, value: str) -> tuple[tuple[str, str], ...]:
    """Return ``(name, url)`` pivots for one indicator.

    The set matches the sieve for the original types: VirusTotal, AbuseIPDB,
    Shodan, urlscan, WHOIS, MalwareBazaar, NVD, MITRE, and Blockchain.com.
    Added types get a pivot only where a stable public search URL exists.

    Args:
        kind: Type key.
        value: Sieve value, not the defanged form.

    Returns:
        Zero or more links. Email addresses and registry keys have none.
    """

    key = kind.strip().lower()
    encoded = _encode(value)
    if key == IOCType.IPV4.value:
        return (
            ("VT", f"https://www.virustotal.com/gui/ip-address/{value}"),
            ("AbuseIPDB", f"https://www.abuseipdb.com/check/{value}"),
            ("Shodan", f"https://www.shodan.io/host/{value}"),
        )
    if key == IOCType.IPV6.value:
        return (
            ("VT", f"https://www.virustotal.com/gui/ip-address/{value}"),
            ("Shodan", f"https://www.shodan.io/host/{value}"),
        )
    if key == IOCType.DOMAIN.value:
        return (
            ("VT", f"https://www.virustotal.com/gui/domain/{value}"),
            ("urlscan", f"https://urlscan.io/search/#page.domain%3A{value}"),
            ("WHOIS", f"https://who.is/whois/{value}"),
        )
    if key == IOCType.URL.value:
        url_query = _encode(f'page.url:"{value}"')
        return (
            ("VT", f"https://www.virustotal.com/gui/search/{encoded}"),
            ("urlscan", f"https://urlscan.io/search/#{url_query}"),
        )
    if key == IOCType.MD5.value:
        return _hash_pivots("md5", value)
    if key == IOCType.SHA1.value:
        return _hash_pivots("sha1", value)
    if key == IOCType.SHA256.value:
        return _hash_pivots("sha256", value)
    if key == IOCType.SHA512.value:
        return _hash_pivots("sha512", value)
    if key == IOCType.CVE.value:
        return (
            ("NVD", f"https://nvd.nist.gov/vuln/detail/{value}"),
            ("MITRE", f"https://www.cve.org/CVERecord?id={value}"),
        )
    if key == IOCType.ATTACK.value:
        technique = value.replace(".", "/", 1)
        return (("ATT&CK", f"https://attack.mitre.org/techniques/{technique}/"),)
    if key == IOCType.WALLET.value:
        return (("Blockchain", f"https://www.blockchain.com/explorer/search?search={value}"),)
    if key == IOCType.ASN.value:
        return (("BGP", f"https://bgp.he.net/{value}"),)
    if key == IOCType.CIDR.value:
        return (("Shodan", f"https://www.shodan.io/search?query=net%3A{encoded}"),)
    if key == IOCType.JA3.value:
        return (("VT", f"https://www.virustotal.com/gui/search/{_encode('ja3:' + value)}"),)
    if key == IOCType.JA3S.value:
        return (("VT", f"https://www.virustotal.com/gui/search/{_encode('ja3s:' + value)}"),)
    if key == IOCType.JARM.value:
        return (("Shodan", f"https://www.shodan.io/search?query=ssl.jarm%3A{encoded}"),)
    return ()


def _hash_pivots(algorithm: str, value: str) -> tuple[tuple[str, str], ...]:
    return (
        ("VT", f"https://www.virustotal.com/gui/file/{value}"),
        ("MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search={algorithm}%3A{value}"),
    )


def _encode(value: str) -> str:
    """Match JavaScript ``encodeURIComponent``."""

    return quote(value, safe="-_.!~*'()")
