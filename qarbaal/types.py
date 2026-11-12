"""Indicator types, sightings, and extraction results.

Results are pydantic models. :class:`IOCType` is the type you pass and the
type you get back.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, PrivateAttr, computed_field


class IOCType(str, Enum):
    """Supported indicator types.

    Pass members, not strings: ``IOCType.IPV4``, ``IOCType.EMAIL``,
    ``IOCType.URL``. The value of each member is the short key used in
    exports (``IOCType.IPV4.value == "ip"``).
    """

    IPV4 = "ip"
    IPV6 = "ip6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    EMAIL = "email"
    CVE = "cve"
    ATTACK = "attack"
    REGISTRY = "registry"
    WALLET = "wallet"
    CIDR = "cidr"
    MAC = "mac"
    ASN = "asn"
    JA3 = "ja3"
    JA3S = "ja3s"
    JARM = "jarm"
    MUTEX = "mutex"
    PATH = "path"
    USER_AGENT = "user_agent"


# Display and export order. The first twelve match the original sieve order.
OUTPUT_ORDER: tuple[str, ...] = (
    IOCType.IPV4.value,
    IOCType.IPV6.value,
    IOCType.DOMAIN.value,
    IOCType.URL.value,
    IOCType.MD5.value,
    IOCType.SHA1.value,
    IOCType.SHA256.value,
    IOCType.EMAIL.value,
    IOCType.CVE.value,
    IOCType.ATTACK.value,
    IOCType.REGISTRY.value,
    IOCType.WALLET.value,
    IOCType.SHA512.value,
    IOCType.CIDR.value,
    IOCType.MAC.value,
    IOCType.ASN.value,
    IOCType.JA3.value,
    IOCType.JA3S.value,
    IOCType.JARM.value,
    IOCType.MUTEX.value,
    IOCType.PATH.value,
    IOCType.USER_AGENT.value,
)

# High-precision types enabled unless the caller passes ``extract_types``.
DEFAULT_TYPES: tuple[str, ...] = tuple(
    key
    for key in OUTPUT_ORDER
    if key not in {IOCType.MUTEX.value, IOCType.PATH.value, IOCType.USER_AGENT.value}
)

# Noisy types. They stay out of the default set.
OPT_IN_TYPES: tuple[str, ...] = (
    IOCType.MUTEX.value,
    IOCType.PATH.value,
    IOCType.USER_AGENT.value,
)

HASH_TYPES: tuple[str, ...] = (
    IOCType.MD5.value,
    IOCType.SHA1.value,
    IOCType.SHA256.value,
    IOCType.SHA512.value,
)

TYPE_LABELS: dict[str, str] = {
    IOCType.IPV4.value: "IPv4 addresses",
    IOCType.IPV6.value: "IPv6 addresses",
    IOCType.DOMAIN.value: "Domains",
    IOCType.URL.value: "URLs",
    IOCType.MD5.value: "MD5 hashes",
    IOCType.SHA1.value: "SHA-1 hashes",
    IOCType.SHA256.value: "SHA-256 hashes",
    IOCType.SHA512.value: "SHA-512 hashes",
    IOCType.EMAIL.value: "Email addresses",
    IOCType.CVE.value: "CVE identifiers",
    IOCType.ATTACK.value: "MITRE ATT&CK techniques",
    IOCType.REGISTRY.value: "Registry keys",
    IOCType.WALLET.value: "Crypto wallets",
    IOCType.CIDR.value: "CIDR ranges",
    IOCType.MAC.value: "MAC addresses",
    IOCType.ASN.value: "AS numbers",
    IOCType.JA3.value: "JA3 fingerprints",
    IOCType.JA3S.value: "JA3S fingerprints",
    IOCType.JARM.value: "JARM fingerprints",
    IOCType.MUTEX.value: "Mutexes",
    IOCType.PATH.value: "File paths",
    IOCType.USER_AGENT.value: "User-Agent strings",
}


def parse_type(value: str) -> IOCType:
    """Return the enum member whose export key is ``value``."""

    for member in IOCType:
        if member.value == value:
            return member
    raise ValueError(f"unknown indicator type: {value}")


def type_key(value: IOCType | str) -> str:
    """Return the canonical string key for a type name or enum member."""

    if isinstance(value, IOCType):
        return value.value
    return value.strip().lower()


class Sighting(BaseModel):
    """One place an indicator was observed.

    Attributes:
        source: Source label, usually a file name or a caller-supplied name.
        line: 1-based line number in that source.
        offset: Start offset in characters, 0-based, in the source text.
        end_offset: End offset, exclusive, in the source text.
        page: Page number for paged documents such as PDF. ``None`` otherwise.
    """

    model_config = ConfigDict(frozen=True)

    source: str
    line: int
    offset: int
    end_offset: int
    page: int | None = None


class Enrichment(BaseModel):
    """Local facts derived from an indicator. No network calls.

    Fields that do not apply are ``None`` or empty. :meth:`as_dict` drops those.
    Registered-domain and subdomain splits are a best-effort heuristic. They are
    not a Public Suffix List. See the enrichment guide.
    """

    model_config = ConfigDict(frozen=True)

    ip_version: int | None = None
    is_private: bool | None = None
    is_global: bool | None = None
    is_multicast: bool | None = None
    is_reserved: bool | None = None
    is_loopback: bool | None = None
    is_link_local: bool | None = None
    is_cgnat: bool | None = None
    tld: str | None = None
    registered_domain: str | None = None
    subdomain: str | None = None
    scheme: str | None = None
    port: int | None = None
    path: str | None = None
    host: str | None = None
    host_is_ip: bool | None = None
    query_parameters: tuple[tuple[str, tuple[str, ...]], ...] = ()
    file_extension: str | None = None
    hash_algorithm: str | None = None
    asn_number: int | None = None
    cidr_prefix: int | None = None
    cidr_network: str | None = None
    mac_multicast: bool | None = None
    mac_locally_administered: bool | None = None
    wallet_format: str | None = None
    registry_hive: str | None = None

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-ready mapping with empty fields removed."""

        payload: dict[str, object] = {}
        for key, value in self.model_dump().items():
            if value is None or value in ((), [], {}):
                continue
            if key == "query_parameters" and isinstance(value, list):
                payload[key] = {str(name): list(values) for name, values in value}
                continue
            payload[key] = value
        return payload


class Indicator(BaseModel):
    """One deduplicated indicator and every place it was seen.

    ``value`` keeps the first-seen sieve form (hashes lower case, CVE identifiers
    upper case, domains lower case). ``raw`` is the exact source slice, which
    may still be defanged. ``normalized`` is the canonical form used for the
    fingerprint. Neither field overwrites the other.

    Attributes:
        type: :class:`IOCType` member, for example ``IOCType.IPV4``.
        value: First-seen sieve value.
        normalized: Canonical value. Equal to ``value`` when normalization is off.
        raw: Exact slice of the original source for the first sighting.
        tags: Noise tags such as ``private`` or ``loopback``. Empty when none apply.
        fingerprint: SHA-256 hex digest of the type and the correlation key.
        valid: ``True`` or ``False`` when validation ran, otherwise ``None``.
        confidence: Deterministic heuristic in the range 0.01 to 0.99.
        validation_notes: Stable reason codes. Empty when nothing failed.
        enrichment: Local enrichment. Never fetched from the network.
        sightings: Every observation, first seen first.
    """

    model_config = ConfigDict(frozen=True)

    type: IOCType
    value: str
    normalized: str
    raw: str
    tags: tuple[str, ...]
    fingerprint: str
    valid: bool | None
    confidence: float
    validation_notes: tuple[str, ...]
    enrichment: Enrichment
    sightings: tuple[Sighting, ...]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def occurrences(self) -> int:
        """Number of sightings, including repeats inside one source."""

        return len(self.sightings)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source(self) -> str:
        """Source label of the first sighting, or an empty string."""

        if not self.sightings:
            return ""
        return self.sightings[0].source

    @computed_field  # type: ignore[prop-decorator]
    @property
    def line(self) -> int | None:
        """Line number of the first sighting."""

        if not self.sightings:
            return None
        return self.sightings[0].line

    @computed_field  # type: ignore[prop-decorator]
    @property
    def offset(self) -> int | None:
        """Character offset of the first sighting."""

        if not self.sightings:
            return None
        return self.sightings[0].offset

    @computed_field  # type: ignore[prop-decorator]
    @property
    def end_offset(self) -> int | None:
        """Exclusive end offset of the first sighting."""

        if not self.sightings:
            return None
        return self.sightings[0].end_offset

    @computed_field  # type: ignore[prop-decorator]
    @property
    def page(self) -> int | None:
        """Page number of the first sighting, when the source has pages."""

        if not self.sightings:
            return None
        return self.sightings[0].page

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sources(self) -> tuple[str, ...]:
        """Distinct source labels in first-seen order."""

        seen: list[str] = []
        for sighting in self.sightings:
            if sighting.source not in seen:
                seen.append(sighting.source)
        return tuple(seen)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pivots(self) -> tuple[tuple[str, str], ...]:
        """Enrichment links for this indicator. The links are not fetched."""

        from qarbaal.pivots import pivots_for

        return pivots_for(self.type, self.value)


class ExtractionStats(BaseModel):
    """Counts for one extraction or a merged set of extractions.

    Attributes:
        counts: Unique indicators per type. Missing keys mean zero.
        total: Number of unique indicators.
        sightings: Number of observations, counting repeats.
        input_characters: Characters actually scanned.
        truncated: ``True`` when a size limit cut the input short.
        match_limit_hit: ``True`` when a per-type match cap stopped the scan.
        sources: Source labels included in the result.
    """

    model_config = ConfigDict(frozen=True)

    counts: Mapping[str, int]
    total: int
    sightings: int
    input_characters: int
    truncated: bool
    match_limit_hit: bool
    sources: tuple[str, ...]


class Extraction(BaseModel):
    """Indicators produced by one extract call or a merge of several.

    Iterate the extraction to walk indicators in export order. :meth:`get`
    and :meth:`values` take an :class:`IOCType` member. :meth:`shared` returns
    indicators that showed up in at least two sources.
    """

    model_config = ConfigDict(frozen=True)

    indicators: tuple[Indicator, ...]
    stats: ExtractionStats
    _grouped: dict[IOCType, tuple[Indicator, ...]] = PrivateAttr(default_factory=dict)

    def model_post_init(self, context: Any) -> None:
        grouped: dict[IOCType, list[Indicator]] = {}
        for indicator in self.indicators:
            grouped.setdefault(indicator.type, []).append(indicator)
        self._grouped = {key: tuple(value) for key, value in grouped.items()}

    def __iter__(self) -> Iterator[Indicator]:  # type: ignore[override]
        return iter(self.indicators)

    def __len__(self) -> int:
        return len(self.indicators)

    def __repr__(self) -> str:
        return (
            f"Extraction(total={self.stats.total}, sightings={self.stats.sightings}, "
            f"truncated={self.stats.truncated})"
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def truncated(self) -> bool:
        """Whether a size limit cut the input short."""

        return self.stats.truncated

    def get(self, kind: IOCType) -> tuple[Indicator, ...]:
        """Return indicators of one type, in first-seen order.

        Args:
            kind: Indicator type, for example ``IOCType.IPV4``.
        """

        return self._grouped.get(_as_type(kind), ())

    def values(self, kind: IOCType) -> tuple[str, ...]:
        """Return the sieve values of one type, in first-seen order.

        Args:
            kind: Indicator type, for example ``IOCType.DOMAIN``.
        """

        return tuple(indicator.value for indicator in self.get(kind))

    def shared(self) -> tuple[Indicator, ...]:
        """Return indicators observed in two or more sources."""

        return tuple(indicator for indicator in self.indicators if len(set(indicator.sources)) >= 2)


def _as_type(kind: IOCType | str) -> IOCType:
    """Accept an enum member, or the matching export key."""

    if isinstance(kind, IOCType):
        return kind
    return parse_type(type_key(kind))
