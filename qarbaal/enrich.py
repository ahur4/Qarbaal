"""Local enrichment. Nothing in this module contacts the network."""

from __future__ import annotations

import ipaddress
from urllib.parse import parse_qs, urlsplit

from qarbaal.tlds import split_domain
from qarbaal.types import HASH_TYPES, Enrichment, IOCType
from qarbaal.validate import ipv4_class

_HASH_NAMES = {
    IOCType.MD5.value: "MD5",
    IOCType.SHA1.value: "SHA-1",
    IOCType.SHA256.value: "SHA-256",
    IOCType.SHA512.value: "SHA-512",
    IOCType.JA3.value: "JA3",
    IOCType.JA3S.value: "JA3S",
    IOCType.JARM.value: "JARM",
}
_LENGTH_NAMES = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
_HIVES = {
    "hkey_local_machine": "HKEY_LOCAL_MACHINE",
    "hkey_current_user": "HKEY_CURRENT_USER",
    "hkey_classes_root": "HKEY_CLASSES_ROOT",
    "hkey_users": "HKEY_USERS",
    "hkey_current_config": "HKEY_CURRENT_CONFIG",
    "hklm": "HKEY_LOCAL_MACHINE",
    "hkcu": "HKEY_CURRENT_USER",
    "hkcr": "HKEY_CLASSES_ROOT",
    "hku": "HKEY_USERS",
    "hkcc": "HKEY_CURRENT_CONFIG",
}


def enrich(kind: str, value: str, normalized: str, tags: tuple[str, ...]) -> Enrichment:
    """Build local enrichment for one indicator.

    IP flags come from :mod:`ipaddress` plus the sieve's CGNAT tag. Domain and
    URL host splits use :func:`qarbaal.tlds.split_domain`. Hash names prefer the
    indicator type, then the digest length.

    Args:
        kind: Type key.
        value: Sieve value.
        normalized: Canonical value.
        tags: Noise tags already assigned by the sieve.

    Returns:
        An :class:`~qarbaal.types.Enrichment` instance.
    """

    key = kind.strip().lower()
    if key == IOCType.IPV4.value:
        return _ip(normalized, 4, tags)
    if key == IOCType.IPV6.value:
        return _ip(normalized, 6, tags)
    if key == IOCType.CIDR.value:
        return _cidr(normalized, tags)
    if key == IOCType.DOMAIN.value:
        return _domain(normalized)
    if key == IOCType.EMAIL.value:
        _local, _sep, host = normalized.partition("@")
        base = _domain(host)
        return base
    if key == IOCType.URL.value:
        return _url(value, normalized)
    if key in _HASH_NAMES:
        algorithm = _HASH_NAMES[key]
        if key in HASH_TYPES:
            algorithm = _LENGTH_NAMES.get(len(normalized), algorithm)
        return Enrichment(hash_algorithm=algorithm)
    if key == IOCType.ASN.value and normalized.startswith("AS") and normalized[2:].isdigit():
        return Enrichment(asn_number=int(normalized[2:]))
    if key == IOCType.MAC.value:
        return _mac(normalized)
    if key == IOCType.WALLET.value:
        form = "bech32" if normalized.startswith("bc1") else "legacy"
        return Enrichment(wallet_format=form)
    if key == IOCType.REGISTRY.value:
        hive = normalized.split("\\", 1)[0].casefold()
        return Enrichment(registry_hive=_HIVES.get(hive))
    if key == IOCType.PATH.value:
        return Enrichment(file_extension=_extension(normalized.replace("\\", "/")))
    return Enrichment()


def _ip(value: str, version: int, tags: tuple[str, ...]) -> Enrichment:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return Enrichment(ip_version=version, is_cgnat="cgnat" in tags)
    return Enrichment(
        ip_version=address.version,
        is_private=address.is_private,
        is_global=address.is_global,
        is_multicast=address.is_multicast,
        is_reserved=address.is_reserved,
        is_loopback=address.is_loopback,
        is_link_local=address.is_link_local,
        is_cgnat="cgnat" in tags,
    )


def _cidr(value: str, tags: tuple[str, ...]) -> Enrichment:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return Enrichment(is_cgnat="cgnat" in tags)
    address = network.network_address
    cgnat = False
    if address.version == 4:
        cgnat = ipv4_class(str(address)) == "cgnat"
    return Enrichment(
        ip_version=network.version,
        is_private=network.is_private if hasattr(network, "is_private") else None,
        is_global=bool(getattr(network, "is_global", False)),
        is_multicast=address.is_multicast,
        is_reserved=address.is_reserved,
        is_loopback=address.is_loopback,
        is_link_local=address.is_link_local,
        is_cgnat=cgnat or "cgnat" in tags,
        cidr_prefix=network.prefixlen,
        cidr_network=network.with_prefixlen,
    )


def _domain(host: str) -> Enrichment:
    tld, registered, subdomain = split_domain(host)
    return Enrichment(tld=tld, registered_domain=registered, subdomain=subdomain)


def _url(value: str, normalized: str) -> Enrichment:
    parts = urlsplit(normalized or value)
    host = parts.hostname
    domain = _domain(host) if host else Enrichment()
    host_is_ip = False
    if host:
        try:
            ipaddress.ip_address(host)
            host_is_ip = True
        except ValueError:
            host_is_ip = False
    query = parse_qs(parts.query, keep_blank_values=True)
    parameters = tuple((key, tuple(values)) for key, values in query.items())
    port = parts.port
    if port is None and parts.scheme in {"http", "https", "ftp"}:
        port = {"http": 80, "https": 443, "ftp": 21}[parts.scheme]
    extension = _extension(parts.path)
    return Enrichment(
        tld=None if host_is_ip else domain.tld,
        registered_domain=None if host_is_ip else domain.registered_domain,
        subdomain=None if host_is_ip else domain.subdomain,
        scheme=parts.scheme or None,
        port=port,
        path=parts.path or None,
        host=host,
        host_is_ip=host_is_ip,
        query_parameters=parameters,
        file_extension=extension,
    )


def _mac(value: str) -> Enrichment:
    octets = value.split(":")
    if not octets or not octets[0]:
        return Enrichment()
    try:
        first = int(octets[0], 16)
    except ValueError:
        return Enrichment()
    return Enrichment(mac_multicast=bool(first & 1), mac_locally_administered=bool(first & 2))


def _extension(path: str) -> str | None:
    name = path.rsplit("/", 1)[-1]
    if "." not in name or name.startswith("."):
        return None
    extension = name.rsplit(".", 1)[-1].lower()
    if not extension or len(extension) > 8 or not extension.isalnum():
        return None
    return extension
