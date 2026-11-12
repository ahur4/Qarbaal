"""Structural validation and the deterministic confidence heuristic.

Confidence is not a probability and it is not a model score. It is a fixed
function of the type, the validation result, and noise tags. The same indicator
always receives the same score.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from qarbaal.tlds import tld_recognized
from qarbaal.types import HASH_TYPES, IOCType

_HASH_WIDTH = {
    IOCType.MD5.value: 32,
    IOCType.SHA1.value: 40,
    IOCType.SHA256.value: 64,
    IOCType.SHA512.value: 128,
    IOCType.JA3.value: 32,
    IOCType.JA3S.value: 32,
    IOCType.JARM.value: 62,
}
_HEX = re.compile(r"^[0-9a-f]+$")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SCHEMES = {"http", "https", "ftp"}


def ipv4_class(ip: str) -> str | None:
    """Classify an IPv4 address the way the sieve tags noise.

    Args:
        ip: Dotted IPv4 address. Octets are not re-validated here.

    Returns:
        ``private``, ``loopback``, ``link-local``, ``cgnat``, ``multicast``,
        ``reserved``, or ``None`` for an ordinary public address.
    """

    octets = [int(part) for part in ip.split(".")]
    first, second = octets[0], octets[1]
    if first == 10 or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168):
        return "private"
    if first == 127:
        return "loopback"
    if first == 169 and second == 254:
        return "link-local"
    if first == 100 and 64 <= second <= 127:
        return "cgnat"
    if 224 <= first <= 239:
        return "multicast"
    if first == 0 or first >= 240:
        return "reserved"
    return None


def ipv6_tags(address: ipaddress.IPv6Address) -> tuple[str, ...]:
    """Return a single noise tag for an IPv6 address, or an empty tuple.

    Tags come from :mod:`ipaddress`: loopback, link-local, multicast, private
    (unique-local), then reserved or unspecified.
    """

    if address.is_loopback:
        return ("loopback",)
    if address.is_link_local:
        return ("link-local",)
    if address.is_multicast:
        return ("multicast",)
    if address.is_private:
        return ("private",)
    if address.is_reserved or address.is_unspecified:
        return ("reserved",)
    return ()


def validation_notes(kind: str, normalized: str) -> tuple[str, ...]:
    """Return reason codes for a normalized value. Empty means structurally valid.

    Args:
        kind: Type key.
        normalized: Canonical value.

    Returns:
        A tuple of stable codes such as ``tld-not-recognized``.
    """

    key = kind.strip().lower()
    if key == IOCType.IPV4.value:
        return _ip_notes(normalized, 4)
    if key == IOCType.IPV6.value:
        return _ip_notes(normalized, 6)
    if key == IOCType.CIDR.value:
        return _cidr_notes(normalized)
    if key == IOCType.DOMAIN.value:
        return domain_notes(normalized)
    if key == IOCType.EMAIL.value:
        return _email_notes(normalized)
    if key == IOCType.URL.value:
        return _url_notes(normalized)
    if key in _HASH_WIDTH:
        return _hash_notes(key, normalized)
    if key == IOCType.CVE.value:
        return _cve_notes(normalized)
    if key == IOCType.ASN.value:
        return _asn_notes(normalized)
    if key == IOCType.MAC.value:
        return _mac_notes(normalized)
    if key == IOCType.USER_AGENT.value:
        if "/" not in normalized:
            return ("weak-user-agent",)
        return ()
    return ()


def domain_notes(domain: str) -> tuple[str, ...]:
    """Validate a host name against label rules and the bundled TLD list.

    Args:
        domain: Normalized host name.

    Returns:
        Reason codes. ``tld-not-recognized`` means the last label is neither in
        the bundled root-zone list nor in the small special-use set.
    """

    if not domain or len(domain) > 253 or ".." in domain:
        return ("malformed-domain",)
    labels = domain.split(".")
    if len(labels) < 2:
        return ("malformed-domain",)
    for label in labels:
        if label.startswith("xn--"):
            rest = label[4:]
            if len(rest) < 1 or not rest.replace("-", "").isalnum():
                return ("malformed-domain",)
            continue
        if _LABEL.fullmatch(label) is None:
            return ("malformed-domain",)
    if not tld_recognized(labels[-1]):
        return ("tld-not-recognized",)
    return ()


def confidence_for(*, kind: str, valid: bool | None, tags: tuple[str, ...]) -> float:
    """Score an indicator from its validation result and noise tags.

    The result is rounded to two decimals and clamped to 0.01-0.99.

    - Invalid: ``0.25``
    - Validation skipped: ``0.55``
    - Valid: ``0.80``
    - Tagged IP, IPv6, or CIDR: subtract ``0.15``
    - Valid untagged IP or IPv6: add ``0.10``
    - Valid hash, JA3, JA3S, or JARM: add ``0.10``

    Args:
        kind: Type key.
        valid: Validation result, or ``None`` when validation did not run.
        tags: Noise tags.

    Returns:
        A heuristic score. It is not a probability.
    """

    if valid is False:
        score = 0.25
    elif valid is None:
        score = 0.55
    else:
        score = 0.80
    if tags and kind in {IOCType.IPV4.value, IOCType.IPV6.value, IOCType.CIDR.value}:
        score -= 0.15
    elif valid is True and kind in {IOCType.IPV4.value, IOCType.IPV6.value} and not tags:
        score += 0.10
    if valid is True and kind in set(HASH_TYPES) | {
        IOCType.JA3.value,
        IOCType.JA3S.value,
        IOCType.JARM.value,
    }:
        score += 0.10
    return round(min(0.99, max(0.01, score)), 2)


def _ip_notes(value: str, version: int) -> tuple[str, ...]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return ("unparsed-ipv6",) if version == 6 else ("unparsed-ipv4",)
    if address.version != version:
        return ("unparsed-ipv6",) if version == 6 else ("unparsed-ipv4",)
    return ()


def _cidr_notes(value: str) -> tuple[str, ...]:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return ("unparsed-cidr",)
    return ()


def _email_notes(value: str) -> tuple[str, ...]:
    local, separator, domain = value.partition("@")
    if not separator or not local or len(local) > 64:
        return ("malformed-email",)
    notes = domain_notes(domain)
    if "malformed-domain" in notes:
        return ("malformed-email",)
    if "tld-not-recognized" in notes:
        return ("tld-not-recognized",)
    return ()


def _url_notes(value: str) -> tuple[str, ...]:
    parts = urlsplit(value)
    if parts.scheme.lower() not in _SCHEMES or not parts.hostname:
        return ("malformed-url",)
    host = parts.hostname
    try:
        ipaddress.ip_address(host)
        return ()
    except ValueError:
        pass
    notes = domain_notes(host)
    if notes:
        return ("malformed-url",) if "malformed-domain" in notes else notes
    return ()


def _hash_notes(kind: str, value: str) -> tuple[str, ...]:
    width = _HASH_WIDTH[kind]
    if len(value) != width or _HEX.fullmatch(value) is None:
        return ("malformed-hash",)
    return ()


def _cve_notes(value: str) -> tuple[str, ...]:
    match = re.fullmatch(r"CVE-(\d{4})-\d{4,7}", value)
    if match is None:
        return ("malformed-cve",)
    year = int(match.group(1))
    if year < 1999 or year > 2099:
        return ("bad-cve-year",)
    return ()


def _asn_notes(value: str) -> tuple[str, ...]:
    match = re.fullmatch(r"AS(\d+)", value)
    if match is None:
        return ("bad-asn",)
    number = int(match.group(1))
    if not 1 <= number <= 4_294_967_295:
        return ("bad-asn",)
    return ()


def _mac_notes(value: str) -> tuple[str, ...]:
    if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", value) is None:
        return ("malformed-mac",)
    return ()
