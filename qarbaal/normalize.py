"""Canonical forms for indicator values.

Normalization never replaces the original sieve value. Callers keep both.
The steps are Unicode NFKC, refanging, trimming, and a type-specific rewrite.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit

from qarbaal.refang import refang
from qarbaal.types import HASH_TYPES, IOCType

_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}
_WHITESPACE = re.compile(r"\s+")


def normalize_value(kind: str, value: str) -> str:
    """Return the canonical form of one indicator value.

    Args:
        kind: Type key such as ``ip``, ``domain``, or ``url``.
        value: Sieve value or raw text. Defanged text is refanged first.

    Returns:
        The normalized value. Unparseable addresses are still cleaned
        (case, surrounding space) and returned.
    """

    text = unicodedata.normalize("NFKC", value).strip()
    text = refang(text)
    key = kind.strip().lower()
    if key in HASH_TYPES or key in {IOCType.JA3.value, IOCType.JA3S.value, IOCType.JARM.value}:
        return _WHITESPACE.sub("", text).lower()
    if key == IOCType.IPV4.value:
        return _normalize_ip(text, 4)
    if key == IOCType.IPV6.value:
        return _normalize_ip(text, 6)
    if key == IOCType.CIDR.value:
        return _normalize_cidr(text)
    if key == IOCType.DOMAIN.value:
        return fold_domain(text)
    if key == IOCType.EMAIL.value:
        return _normalize_email(text)
    if key == IOCType.URL.value:
        return _normalize_url(text)
    if key == IOCType.CVE.value:
        return _WHITESPACE.sub("", text).upper()
    if key == IOCType.ATTACK.value:
        return _WHITESPACE.sub("", text).upper()
    if key == IOCType.MAC.value:
        return _normalize_mac(text)
    if key == IOCType.ASN.value:
        return _normalize_asn(text)
    if key == IOCType.REGISTRY.value:
        return text.replace("/", "\\").casefold()
    if key == IOCType.WALLET.value:
        if text.lower().startswith("bc1"):
            return _WHITESPACE.sub("", text).lower()
        return _WHITESPACE.sub("", text)
    if key == IOCType.USER_AGENT.value:
        return _WHITESPACE.sub(" ", text).strip()
    if key in {IOCType.PATH.value, IOCType.MUTEX.value}:
        return text.strip()
    return text.strip()


def fold_domain(value: str) -> str:
    """Lower-case a domain, drop a trailing dot, and encode it with IDNA.

    Args:
        value: A host name. It may contain Unicode labels.

    Returns:
        An ASCII punycode host when IDNA accepts it, otherwise the lower-case name.
    """

    text = unicodedata.normalize("NFKC", value).strip().rstrip(".").lower()
    text = refang(text)
    if not text:
        return text
    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError:
        return text


def apply_input_nfkc(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Apply NFKC per character and record original spans.

    Compatibility characters such as full-width dots become their ASCII
    equivalents. Each output character maps back to the source character that
    produced it, so later offset tracking still points at the input.

    Args:
        text: Original input.

    Returns:
        Normalized text and one ``(start, end)`` span per output character.
    """

    pieces: list[str] = []
    spans: list[tuple[int, int]] = []
    for index, char in enumerate(text):
        mapped = unicodedata.normalize("NFKC", char)
        pieces.append(mapped)
        spans.extend([(index, index + 1)] * len(mapped))
    return "".join(pieces), spans


def _normalize_ip(text: str, version: int) -> str:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return text.lower()
    if address.version != version:
        return text.lower()
    return address.compressed.lower() if version == 6 else str(address)


def _normalize_cidr(text: str) -> str:
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return text.lower()
    return network.with_prefixlen.lower() if network.version == 6 else network.with_prefixlen


def _normalize_email(text: str) -> str:
    local, separator, domain = text.partition("@")
    if not separator:
        return text.lower()
    return f"{local.strip().lower()}@{fold_domain(domain)}"


def _normalize_url(text: str) -> str:
    parts = urlsplit(text)
    if not parts.scheme or parts.hostname is None:
        return text
    scheme = parts.scheme.lower()
    host = fold_domain(parts.hostname)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = parts.port
    default = _DEFAULT_PORTS.get(scheme)
    netloc = host
    if port and port != default:
        netloc = f"{host}:{port}"
    if parts.username:
        auth = parts.username
        if parts.password is not None:
            auth = f"{auth}:{parts.password}"
        netloc = f"{auth}@{netloc}"
    return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))


def _normalize_mac(text: str) -> str:
    compact = _WHITESPACE.sub("", text).lower().replace("-", ":")
    return compact


def _normalize_asn(text: str) -> str:
    digits = text.strip()[2:] if text.strip().upper().startswith("AS") else text.strip()
    try:
        number = int(digits)
    except ValueError:
        return text.strip().upper()
    return f"AS{number}"
