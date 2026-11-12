"""Indicator extraction.

:class:`IOCExtractor` is the configurable entry point. :func:`extract` runs it
with the defaults: normalization, validation, and deduplication on, and the
noisy types (file paths, user agents, mutexes) left out.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from qarbaal.enrich import enrich
from qarbaal.exceptions import InputTooLargeError
from qarbaal.ingest import load_document
from qarbaal.normalize import apply_input_nfkc, fold_domain, normalize_value
from qarbaal.patterns import (
    ASN_RE,
    ATTACK_RE,
    CVE_RE,
    DOMAIN_RE,
    EMAIL_RE,
    FILE_EXT,
    IPV4_CIDR_RE,
    IPV4_HOST_RE,
    IPV4_RE,
    IPV6_CIDR_RE,
    IPV6_RE,
    IPV6_TIME_RE,
    JA3_RE,
    JA3S_RE,
    JARM_RE,
    MAC_RE,
    MAX_TOKEN_LENGTH,
    MD5_RE,
    MUTEX_RE,
    REGISTRY_RE,
    SHA1_RE,
    SHA256_RE,
    SHA512_RE,
    TRAILING_URL_PUNCT_RE,
    UNC_PATH_RE,
    UNIX_PATH_RE,
    URL_RE,
    USER_AGENT_RE,
    WALLET_RE,
    WINDOWS_PATH_RE,
    PatternSpec,
)
from qarbaal.refang import refang_tracked
from qarbaal.types import (
    DEFAULT_TYPES,
    HASH_TYPES,
    OUTPUT_ORDER,
    Enrichment,
    Extraction,
    ExtractionStats,
    Indicator,
    IOCType,
    Sighting,
    type_key,
)
from qarbaal.validate import confidence_for, ipv4_class, ipv6_tags, validation_notes

logger = logging.getLogger("qarbaal.extract")

Validator = Callable[[Indicator], bool]
PageSpan = tuple[int, int, int]
_ALIAS = {
    "ipv4": "ip",
    "ip4": "ip",
    "ipv6": "ip6",
    "hashes": "hash",
    "sha-1": "sha1",
    "sha-256": "sha256",
    "sha-512": "sha512",
    "e-mail": "email",
    "mail": "email",
    "cves": "cve",
    "mitre": "attack",
    "att&ck": "attack",
    "technique": "attack",
    "reg": "registry",
    "registry-key": "registry",
    "btc": "wallet",
    "bitcoin": "wallet",
    "crypto": "wallet",
    "mac-address": "mac",
    "as": "asn",
    "autonomous-system": "asn",
    "file": "path",
    "file-path": "path",
    "filepath": "path",
    "paths": "path",
    "ua": "user_agent",
    "user-agent": "user_agent",
    "useragent": "user_agent",
}
_KNOWN = set(OUTPUT_ORDER)


@dataclass(frozen=True, slots=True)
class _Hit:
    type: str
    value: str
    start: int
    end: int
    tags: tuple[str, ...] = ()


@dataclass
class _Draft:
    type: str
    value: str
    normalized: str
    raw: str
    tags: tuple[str, ...]
    fingerprint: str
    enrichment: Enrichment
    notes: list[str]
    sightings: list[Sighting]


def resolve_types(
    requested: Sequence[str] | None,
    custom: Sequence[str] = (),
) -> tuple[str, ...]:
    """Resolve ``extract_types`` into an ordered list of type keys.

    ``None`` selects :data:`~qarbaal.types.DEFAULT_TYPES` plus any custom
    pattern names. ``hash`` expands to MD5, SHA-1, SHA-256, and SHA-512.
    ``all`` also enables file paths, user agents, and mutexes.

    Args:
        requested: Names, aliases, or :class:`~qarbaal.types.IOCType` members.
        custom: Custom pattern type names that are legal in an explicit list.

    Returns:
        Type keys, de-duplicated, in the requested order.

    Raises:
        ValueError: A name is not a known type or a custom pattern.
    """

    custom_names = set(custom)
    if requested is None:
        selected = list(DEFAULT_TYPES)
        for name in custom:
            if name not in selected:
                selected.append(name)
        return tuple(selected)
    selected = []
    allowed = _KNOWN | custom_names | {"hash", "all", "*"}
    for raw in requested:
        key = _ALIAS.get(type_key(raw), type_key(raw))
        if key in {"all", "*"}:
            for name in OUTPUT_ORDER:
                if name not in selected:
                    selected.append(name)
            continue
        if key == "hash":
            for name in HASH_TYPES:
                if name not in selected:
                    selected.append(name)
            continue
        if key not in allowed:
            raise ValueError(f"unknown indicator type: {raw}")
        if key not in selected:
            selected.append(key)
    return tuple(selected)


def extract(
    text: str,
    *,
    source: str | None = None,
    hide_private: bool = False,
) -> Extraction:
    """Extract indicators with the default :class:`IOCExtractor` settings.

    Normalization, validation, and deduplication are on. File paths, user
    agents, and mutexes are not extracted. Pass an :class:`IOCExtractor` when
    you need those types or different limits.

    Args:
        text: Report, log, or any other text. Defanged indicators are refanged.
        source: Label stored on each sighting. Defaults to ``<input>``.
        hide_private: Drop IPv4, IPv6, and CIDR values that carry a noise tag.

    Returns:
        An :class:`~qarbaal.types.Extraction`.
    """

    return IOCExtractor(hide_private=hide_private).extract(text, source=source)


def merge(extractions: Sequence[Extraction]) -> Extraction:
    """Merge extractions that were produced with the same settings.

    Indicators with the same fingerprint become one indicator. Sightings are
    concatenated and the first-seen value is kept. Input character counts are
    summed. Use :meth:`IOCExtractor.extract_many` when you still have the text.

    Args:
        extractions: Results to combine, in source order.

    Returns:
        One extraction. An empty input returns an empty extraction.
    """

    if not extractions:
        return _empty_extraction()
    if len(extractions) == 1:
        return extractions[0]
    order: list[str] = []
    grouped: dict[str, Indicator] = {}
    for extraction in extractions:
        for indicator in extraction.indicators:
            current = grouped.get(indicator.fingerprint)
            if current is None:
                grouped[indicator.fingerprint] = indicator
                order.append(indicator.fingerprint)
                continue
            seen = {(item.source, item.offset, item.end_offset) for item in current.sightings}
            extra = [
                item
                for item in indicator.sightings
                if (item.source, item.offset, item.end_offset) not in seen
            ]
            grouped[indicator.fingerprint] = replace(
                current, sightings=current.sightings + tuple(extra)
            )
    indicators = _sort_indicators(tuple(grouped[key] for key in order))
    chars = sum(item.stats.input_characters for item in extractions)
    sources: list[str] = []
    for item in extractions:
        for name in item.stats.sources:
            if name not in sources:
                sources.append(name)
    return _pack(
        indicators,
        input_characters=chars,
        truncated=any(item.stats.truncated for item in extractions),
        match_limit_hit=any(item.stats.match_limit_hit for item in extractions),
        sources=tuple(sources),
    )


@dataclass
class IOCExtractor:
    """Configurable IOC processor.

    The default instance extracts the high-precision types, refangs defanged
    text, normalizes values, validates them, and deduplicates by fingerprint.
    File paths, user agents, and mutexes are opt-in through ``extract_types``.

    Args:
        extract_types: Type names to extract. ``None`` uses the default set.
        normalize: Canonicalize values and apply NFKC before the sieve.
        validate: Record structural validation notes and a confidence score.
        deduplicate: Merge repeats that share a fingerprint.
        hide_private: Omit tagged IPv4, IPv6, and CIDR results.
        drop_invalid: Omit indicators that fail validation.
        max_input_chars: Maximum characters scanned from one source.
        max_matches_per_type: Cap on raw matches for a single type.
        strict_limits: Raise :class:`~qarbaal.exceptions.InputTooLargeError`
            instead of truncating.
        allow: Glob patterns. When set, an indicator must match one of them.
        deny: Glob patterns. A match drops the indicator.
        defang_patterns: Extra ``(regex, replacement)`` refang rules, applied
            before the built-in rules.
        custom_patterns: Extra regular expressions. See :class:`~qarbaal.patterns.PatternSpec`.
        validators: Callables that receive an :class:`~qarbaal.types.Indicator`
            and return ``False`` to mark it invalid.
        chunk_overlap: Characters kept between streaming windows. Keep this
            larger than the longest indicator you care about. The default is
            8192, twice the 4096-character token cap.
        chunk_size: Read size used by :meth:`extract_path` for plain text.
    """

    extract_types: Sequence[str] | None = None
    normalize: bool = True
    validate: bool = True
    deduplicate: bool = True
    hide_private: bool = False
    drop_invalid: bool = False
    max_input_chars: int = 2_000_000
    max_matches_per_type: int = 20_000
    strict_limits: bool = False
    allow: Sequence[str] | None = None
    deny: Sequence[str] | None = None
    defang_patterns: Sequence[tuple[str, str]] | None = None
    custom_patterns: Sequence[PatternSpec] | None = None
    validators: Sequence[Validator] | None = None
    chunk_overlap: int = 8192
    chunk_size: int = 1_048_576
    _types: tuple[str, ...] = field(init=False, repr=False)
    _custom: tuple[tuple[PatternSpec, re.Pattern[str]], ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.max_input_chars < 1:
            raise ValueError("max_input_chars must be positive")
        if self.max_matches_per_type < 1:
            raise ValueError("max_matches_per_type must be positive")
        if self.chunk_overlap < 0:
            raise ValueError("chunk_overlap must be non-negative")
        if self.chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        compiled: list[tuple[PatternSpec, re.Pattern[str]]] = []
        for spec in self.custom_patterns or ():
            compiled.append((spec, spec.compile()))
        self._custom = tuple(compiled)
        self._types = resolve_types(
            self.extract_types,
            custom=tuple(spec.type_name for spec, _pattern in self._custom),
        )
        if self.chunk_overlap < MAX_TOKEN_LENGTH:
            logger.warning(
                "event=short_overlap overlap=%s token_cap=%s",
                self.chunk_overlap,
                MAX_TOKEN_LENGTH,
            )

    @property
    def types(self) -> tuple[str, ...]:
        """Type keys this extractor will emit, in selection order."""

        return self._types

    def extract(
        self,
        text: str,
        *,
        source: str | None = None,
        pages: Sequence[PageSpan] | None = None,
        truncated: bool = False,
    ) -> Extraction:
        """Extract indicators from one string.

        Args:
            text: Source text.
            source: Sighting label. Defaults to ``<input>``.
            pages: Optional ``(page, start, end)`` spans into ``text``.
            truncated: Set when a loader already cut the text to the size limit.

        Returns:
            Indicators, provenance, and statistics for this source.

        Raises:
            InputTooLargeError: ``strict_limits`` is set and ``text`` is too long.
        """

        label = source if source is not None else "<input>"
        scanned, was_truncated = self._limit(text, truncated)
        hits, limited = self._hits_for_text(scanned)
        indicators = self._indicators(
            hits,
            original=scanned,
            source=label,
            pages=tuple(pages or ()),
            base=0,
            newlines_before=0,
        )
        return _pack(
            self._filter(indicators),
            input_characters=len(scanned),
            truncated=was_truncated,
            match_limit_hit=limited,
            sources=(label,),
        )

    def extract_iter(
        self,
        chunks: Iterable[str],
        *,
        source: str | None = None,
    ) -> Extraction:
        """Extract from a stream of text chunks.

        Only the overlap window is retained between chunks, so a large file does
        not have to sit in memory as one string. Offsets and line numbers are
        counted from the start of the stream. A match that straddles a chunk
        boundary is kept when it fits in ``chunk_overlap``.

        Args:
            chunks: Pieces of one source, in order.
            source: Sighting label. Defaults to ``<stream>``.

        Returns:
            One extraction for the whole stream.

        Raises:
            InputTooLargeError: ``strict_limits`` is set and the stream is too long.
        """

        label = source if source is not None else "<stream>"
        buffer = ""
        base = 0
        newlines = 0
        total = 0
        truncated = False
        drafts: dict[str, _Draft] = {}
        order: list[str] = []
        limited = False
        iterator = iter(chunks)
        while True:
            try:
                chunk = next(iterator)
            except StopIteration:
                chunk = None
            if chunk is not None:
                room = self.max_input_chars - total
                if room <= 0:
                    truncated = True
                    chunk = None
                elif len(chunk) > room:
                    if self.strict_limits:
                        raise InputTooLargeError(total + len(chunk), self.max_input_chars)
                    chunk = chunk[:room]
                    truncated = True
                    logger.warning(
                        "event=input_truncated limit=%s",
                        self.max_input_chars,
                    )
                if chunk is not None:
                    total += len(chunk)
                    buffer += chunk
            last = chunk is None
            if not buffer and last:
                break
            overlap = self.chunk_overlap
            if last:
                safe = len(buffer)
            elif len(buffer) <= overlap:
                continue
            else:
                safe = len(buffer) - overlap
            prepared, spans = self._prepare(buffer)
            hits, window_limited = _scan(
                prepared,
                set(self._types),
                self._custom,
                {},
                self.max_matches_per_type,
            )
            limited = limited or window_limited
            kept, cut = _commit_hits(hits, spans, safe, last)
            if cut == 0 and not last:
                # The open match starts at the beginning of the buffer. Read more
                # before committing so a long indicator is not split.
                continue
            self._absorb(drafts, order, kept, buffer, spans, label, (), base, newlines)
            if last or cut >= len(buffer):
                break
            newlines += buffer[:cut].count("\n")
            base += cut
            buffer = buffer[cut:]
            if truncated:
                prepared, spans = self._prepare(buffer)
                hits, window_limited = _scan(
                    prepared,
                    set(self._types),
                    self._custom,
                    {},
                    self.max_matches_per_type,
                )
                limited = limited or window_limited
                self._absorb(drafts, order, hits, buffer, spans, label, (), base, newlines)
                break
        indicators = self._finish_drafts(drafts, order)
        return _pack(
            self._filter(indicators),
            input_characters=total,
            truncated=truncated,
            match_limit_hit=limited,
            sources=(label,),
        )

    def extract_many(
        self,
        sources: Mapping[str, str] | Sequence[tuple[str, str]],
    ) -> Extraction:
        """Extract several named sources and correlate them.

        Args:
            sources: A mapping or a sequence of ``(name, text)`` pairs.

        Returns:
            One extraction. Indicators seen in more than one source are returned
            by :meth:`~qarbaal.types.Extraction.shared`.
        """

        items = list(sources.items()) if isinstance(sources, Mapping) else list(sources)
        parts = [self.extract(text, source=name) for name, text in items]
        return merge(parts)

    def extract_path(self, path: str | Path, *, parser: str | None = None) -> Extraction:
        """Extract indicators from a file.

        Plain text (``.txt``, ``.log``, ``.md``, and files without a suffix) is
        read in chunks. Other formats are parsed by :func:`qarbaal.ingest.load_document`
        up to ``max_input_chars``.

        Args:
            path: File to read.
            parser: Optional parser name that overrides the suffix.

        Returns:
            An extraction whose source label is the path.
        """

        file_path = Path(path)
        suffix = file_path.suffix.lower()
        if parser is None and suffix in {".txt", ".log", ".md", ".text", ""}:
            return self.extract_iter(_iter_file(file_path, self.chunk_size), source=str(file_path))
        document = load_document(file_path, parser=parser, max_chars=self.max_input_chars)
        return self.extract(
            document.text,
            source=str(file_path),
            pages=document.pages,
            truncated=document.truncated,
        )

    def _limit(self, text: str, already: bool) -> tuple[str, bool]:
        if len(text) <= self.max_input_chars:
            return text, already
        if self.strict_limits:
            raise InputTooLargeError(len(text), self.max_input_chars)
        logger.warning(
            "event=input_truncated limit=%s original=%s",
            self.max_input_chars,
            len(text),
        )
        return text[: self.max_input_chars], True

    def _prepare(self, text: str) -> tuple[str, list[tuple[int, int]]]:
        if self.normalize:
            current, spans = apply_input_nfkc(text)
        else:
            current = text
            spans = [(index, index + 1) for index in range(len(text))]
        refanged, mapped = refang_tracked(current, self.defang_patterns)
        if not self.normalize:
            return refanged, mapped
        # ``mapped`` indexes the NFKC string. Compose it back to the original.
        composed: list[tuple[int, int]] = []
        for start, end in mapped:
            if not spans:
                composed.append((0, 0))
                continue
            left = min(start, len(spans) - 1)
            right = min(max(end - 1, left), len(spans) - 1)
            composed.append((spans[left][0], spans[right][1]))
        return refanged, composed

    def _hits_for_text(self, text: str) -> tuple[list[_Hit], bool]:
        prepared, _spans = self._prepare(text)
        return _scan(prepared, set(self._types), self._custom, {}, self.max_matches_per_type)

    def _indicators(
        self,
        hits: list[_Hit],
        *,
        original: str,
        source: str,
        pages: tuple[PageSpan, ...],
        base: int,
        newlines_before: int,
    ) -> tuple[Indicator, ...]:
        _prepared, spans = self._prepare(original)
        drafts: dict[str, _Draft] = {}
        order: list[str] = []
        self._absorb(drafts, order, hits, original, spans, source, pages, base, newlines_before)
        return self._finish_drafts(drafts, order)

    def _absorb(
        self,
        drafts: dict[str, _Draft],
        order: list[str],
        hits: Sequence[_Hit],
        original: str,
        spans: Sequence[tuple[int, int]],
        source: str,
        pages: tuple[PageSpan, ...],
        base: int,
        newlines_before: int,
    ) -> None:
        for hit in hits:
            if not hit.value or len(hit.value) > MAX_TOKEN_LENGTH:
                continue
            origin_start, origin_end = _span_of(spans, hit.start, hit.end)
            absolute_start = base + origin_start
            absolute_end = base + origin_end
            raw = original[origin_start:origin_end]
            normalized = normalize_value(hit.type, hit.value) if self.normalize else hit.value
            correlation = normalized if self.normalize else hit.value.casefold()
            fingerprint = _fingerprint(hit.type, correlation)
            line = newlines_before + original.count("\n", 0, origin_start) + 1
            sighting = Sighting(
                source=source,
                line=line,
                offset=absolute_start,
                end_offset=absolute_end,
                page=_page_at(absolute_start, pages),
            )
            current = drafts.get(fingerprint)
            if current is None or not self.deduplicate:
                key = (
                    fingerprint
                    if self.deduplicate
                    else f"{fingerprint}:{absolute_start}:{len(order)}"
                )
                notes = list(validation_notes(hit.type, normalized)) if self.validate else []
                drafts[key] = _Draft(
                    type=hit.type,
                    value=hit.value,
                    normalized=normalized,
                    raw=raw,
                    tags=hit.tags,
                    fingerprint=fingerprint,
                    enrichment=enrich(hit.type, hit.value, normalized, hit.tags),
                    notes=notes,
                    sightings=[sighting],
                )
                order.append(key)
                continue
            if all(
                item.offset != sighting.offset or item.end_offset != sighting.end_offset
                for item in current.sightings
            ):
                current.sightings.append(sighting)

    def _finish_drafts(self, drafts: dict[str, _Draft], order: list[str]) -> tuple[Indicator, ...]:
        indicators: list[Indicator] = []
        for key in order:
            draft = drafts[key]
            valid = not draft.notes if self.validate else None
            indicator = Indicator(
                type=draft.type,
                value=draft.value,
                normalized=draft.normalized,
                raw=draft.raw,
                tags=draft.tags,
                fingerprint=draft.fingerprint,
                valid=valid,
                confidence=confidence_for(kind=draft.type, valid=valid, tags=draft.tags),
                validation_notes=tuple(draft.notes),
                enrichment=draft.enrichment,
                sightings=tuple(draft.sightings),
            )
            if self.validate and self.validators:
                notes = list(indicator.validation_notes)
                for callback in self.validators:
                    if callback(indicator):
                        continue
                    name = getattr(callback, "__name__", "custom")
                    notes.append(f"rejected-by:{name}")
                if len(notes) != len(indicator.validation_notes):
                    indicator = replace(
                        indicator,
                        valid=False,
                        validation_notes=tuple(dict.fromkeys(notes)),
                    )
                    indicator = replace(
                        indicator,
                        confidence=confidence_for(
                            kind=indicator.type,
                            valid=False,
                            tags=indicator.tags,
                        ),
                    )
            indicators.append(indicator)
        return _sort_indicators(tuple(indicators))

    def _filter(self, indicators: Sequence[Indicator]) -> tuple[Indicator, ...]:
        allow = tuple(self.allow or ())
        deny = tuple(self.deny or ())
        kept: list[Indicator] = []
        for indicator in indicators:
            if self.drop_invalid and indicator.valid is False:
                continue
            if (
                self.hide_private
                and indicator.tags
                and indicator.type
                in {
                    IOCType.IPV4.value,
                    IOCType.IPV6.value,
                    IOCType.CIDR.value,
                }
            ):
                continue
            if allow and not _glob_any(indicator, allow):
                continue
            if deny and _glob_any(indicator, deny):
                continue
            kept.append(indicator)
        return tuple(kept)


def _scan(
    text: str,
    enabled: set[str],
    custom: Sequence[tuple[PatternSpec, re.Pattern[str]]],
    counts: dict[str, int],
    limit: int,
) -> tuple[list[_Hit], bool]:
    hits: list[_Hit] = []
    limited = False

    def add(hit: _Hit) -> None:
        nonlocal limited
        if hit.type not in enabled:
            return
        used = counts.get(hit.type, 0)
        if used >= limit:
            limited = True
            return
        counts[hit.type] = used + 1
        hits.append(hit)

    if IOCType.SHA512.value in enabled:
        for match in SHA512_RE.finditer(text):
            add(_Hit(IOCType.SHA512.value, match.group(0).lower(), match.start(), match.end()))
    if IOCType.SHA256.value in enabled:
        for match in SHA256_RE.finditer(text):
            add(_Hit(IOCType.SHA256.value, match.group(0).lower(), match.start(), match.end()))
    if IOCType.SHA1.value in enabled:
        for match in SHA1_RE.finditer(text):
            add(_Hit(IOCType.SHA1.value, match.group(0).lower(), match.start(), match.end()))
    if IOCType.MD5.value in enabled:
        for match in MD5_RE.finditer(text):
            add(_Hit(IOCType.MD5.value, match.group(0).lower(), match.start(), match.end()))

    want_url = IOCType.URL.value in enabled
    want_domain = IOCType.DOMAIN.value in enabled
    if want_url or want_domain:
        for match in URL_RE.finditer(text):
            raw_url = TRAILING_URL_PUNCT_RE.sub("", match.group(0))
            if not raw_url:
                continue
            if want_url:
                add(_Hit(IOCType.URL.value, raw_url, match.start(), match.start() + len(raw_url)))
            if want_domain:
                host = _url_host(raw_url)
                if host and IPV4_HOST_RE.fullmatch(host) is None:
                    folded = fold_domain(host)
                    found = raw_url.lower().find(host.lower())
                    if found < 0:
                        add(
                            _Hit(
                                IOCType.DOMAIN.value,
                                folded,
                                match.start(),
                                match.start() + len(raw_url),
                            )
                        )
                    else:
                        add(
                            _Hit(
                                IOCType.DOMAIN.value,
                                folded,
                                match.start() + found,
                                match.start() + found + len(host),
                            )
                        )

    if IOCType.IPV4.value in enabled:
        for match in IPV4_RE.finditer(text):
            ip = match.group(0)
            if _ipv4_ok(ip):
                tag = ipv4_class(ip)
                add(_Hit(IOCType.IPV4.value, ip, match.start(), match.end(), (tag,) if tag else ()))

    if IOCType.CIDR.value in enabled:
        for match in IPV4_CIDR_RE.finditer(text):
            cidr = match.group(0)
            address, _slash, _prefix = cidr.partition("/")
            if _ipv4_ok(address):
                tag = ipv4_class(address)
                add(
                    _Hit(
                        IOCType.CIDR.value, cidr, match.start(), match.end(), (tag,) if tag else ()
                    )
                )
        for match in IPV6_CIDR_RE.finditer(text):
            add(_Hit(IOCType.CIDR.value, match.group(0).lower(), match.start(), match.end()))

    if IOCType.IPV6.value in enabled:
        for match in IPV6_RE.finditer(text):
            token = match.group(0)
            if (
                token.count(":") >= 2
                and re.search(r"[a-fA-F0-9]", token)
                and IPV6_TIME_RE.fullmatch(token) is None
            ):
                lowered = token.lower()
                tags: tuple[str, ...] = ()
                try:
                    tags = ipv6_tags(ipaddress.IPv6Address(lowered))
                except ValueError:
                    tags = ()
                add(_Hit(IOCType.IPV6.value, lowered, match.start(), match.end(), tags))

    want_email = IOCType.EMAIL.value in enabled
    if want_email or want_domain:
        for match in EMAIL_RE.finditer(text):
            address = match.group(0)
            local, _at, domain = address.partition("@")
            folded_domain = fold_domain(domain)
            if want_email:
                add(
                    _Hit(
                        IOCType.EMAIL.value,
                        f"{local.lower()}@{folded_domain}",
                        match.start(),
                        match.end(),
                    )
                )
            if want_domain:
                domain_at = address.rfind(domain)
                add(
                    _Hit(
                        IOCType.DOMAIN.value,
                        folded_domain,
                        match.start() + domain_at,
                        match.start() + domain_at + len(domain),
                    )
                )

    if want_domain:
        for match in DOMAIN_RE.finditer(text):
            domain = match.group(0).lower()
            tld = domain.rsplit(".", 1)[-1]
            if tld in FILE_EXT:
                continue
            add(_Hit(IOCType.DOMAIN.value, fold_domain(domain), match.start(), match.end()))

    if IOCType.CVE.value in enabled:
        for match in CVE_RE.finditer(text):
            add(_Hit(IOCType.CVE.value, match.group(0).upper(), match.start(), match.end()))
    if IOCType.ATTACK.value in enabled:
        for match in ATTACK_RE.finditer(text):
            add(_Hit(IOCType.ATTACK.value, match.group(0), match.start(), match.end()))
    if IOCType.REGISTRY.value in enabled:
        for match in REGISTRY_RE.finditer(text):
            add(_Hit(IOCType.REGISTRY.value, match.group(0), match.start(), match.end()))
    if IOCType.WALLET.value in enabled:
        for match in WALLET_RE.finditer(text):
            add(_Hit(IOCType.WALLET.value, match.group(0), match.start(), match.end()))
    if IOCType.MAC.value in enabled:
        for match in MAC_RE.finditer(text):
            add(_Hit(IOCType.MAC.value, match.group(0), match.start(), match.end()))
    if IOCType.ASN.value in enabled:
        for match in ASN_RE.finditer(text):
            add(_Hit(IOCType.ASN.value, match.group(0), match.start(), match.end()))
    if IOCType.JA3S.value in enabled:
        for match in JA3S_RE.finditer(text):
            add(_Hit(IOCType.JA3S.value, match.group(1).lower(), match.start(1), match.end(1)))
    if IOCType.JA3.value in enabled:
        for match in JA3_RE.finditer(text):
            add(_Hit(IOCType.JA3.value, match.group(1).lower(), match.start(1), match.end(1)))
    if IOCType.JARM.value in enabled:
        for match in JARM_RE.finditer(text):
            add(_Hit(IOCType.JARM.value, match.group(1).lower(), match.start(1), match.end(1)))
    if IOCType.MUTEX.value in enabled:
        for match in MUTEX_RE.finditer(text):
            add(_Hit(IOCType.MUTEX.value, match.group(0), match.start(), match.end()))
    if IOCType.PATH.value in enabled:
        for pattern in (WINDOWS_PATH_RE, UNC_PATH_RE, UNIX_PATH_RE):
            for match in pattern.finditer(text):
                add(_Hit(IOCType.PATH.value, match.group(0), match.start(), match.end()))
    if IOCType.USER_AGENT.value in enabled:
        for match in USER_AGENT_RE.finditer(text):
            agent = match.group(1).strip()
            if "/" not in agent:
                continue
            add(_Hit(IOCType.USER_AGENT.value, agent, match.start(1), match.start(1) + len(agent)))

    for spec, pattern in custom:
        if spec.type_name not in enabled:
            continue
        for match in pattern.finditer(text):
            token = match.group(1) if match.lastindex else match.group(0)
            if token is None:
                continue
            if spec.folds == "lower":
                token = token.lower()
            elif spec.folds == "upper":
                token = token.upper()
            start = match.start(1) if match.lastindex else match.start()
            end = match.end(1) if match.lastindex else match.end()
            add(_Hit(spec.type_name, token, start, end))
    if limited:
        logger.warning("event=match_limit limit=%s", limit)
    return hits, limited


def _ipv4_ok(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        number = int(part)
        if number > 255 or str(number) != part:
            return False
    return True


def _url_host(url: str) -> str | None:
    from urllib.parse import urlparse

    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def _fingerprint(kind: str, correlation_key: str) -> str:
    digest = hashlib.sha256(f"{kind}\n{correlation_key}".encode())
    return digest.hexdigest()


def _commit_hits(
    hits: Sequence[_Hit],
    spans: Sequence[tuple[int, int]],
    safe: int,
    last: bool,
) -> tuple[list[_Hit], int]:
    """Choose a cut that does not slice an open match.

    Matches that end at or before the cut are committed. A match that would
    cross the cut pulls the cut back to the match start so the next window
    still contains it.
    """

    located: list[tuple[_Hit, int, int]] = []
    for hit in hits:
        if not spans or hit.start >= len(spans) or hit.end <= hit.start:
            continue
        origin_start, origin_end = _span_of(spans, hit.start, hit.end)
        origin_start = max(0, origin_start)
        origin_end = max(origin_start, origin_end)
        located.append((hit, origin_start, origin_end))
    cut = safe
    if not last:
        for _hit, origin_start, origin_end in located:
            if origin_start < cut < origin_end:
                cut = origin_start
    kept = [hit for hit, _origin_start, origin_end in located if origin_end <= cut]
    return kept, cut


def _span_of(spans: Sequence[tuple[int, int]], start: int, end: int) -> tuple[int, int]:
    if not spans:
        return (0, 0)
    left = min(max(start, 0), len(spans) - 1)
    right = min(max(end - 1, left), len(spans) - 1)
    return spans[left][0], spans[right][1]


def _page_at(offset: int, pages: Sequence[PageSpan]) -> int | None:
    for page, start, end in pages:
        if start <= offset < end:
            return page
    return None


def _glob_any(indicator: Indicator, patterns: Sequence[str]) -> bool:
    from fnmatch import fnmatch

    haystacks = (
        indicator.value.casefold(),
        indicator.normalized.casefold(),
        indicator.raw.casefold(),
    )
    for pattern in patterns:
        folded = pattern.casefold()
        for haystack in haystacks:
            if fnmatch(haystack, folded):
                return True
    return False


def _sort_indicators(indicators: Sequence[Indicator]) -> tuple[Indicator, ...]:
    rank = {name: index for index, name in enumerate(OUTPUT_ORDER)}
    next_rank = len(rank)
    dynamic: dict[str, int] = {}
    scored: list[tuple[int, int, Indicator]] = []
    for index, indicator in enumerate(indicators):
        if indicator.type in rank:
            type_rank = rank[indicator.type]
        else:
            type_rank = dynamic.get(indicator.type, -1)
            if type_rank < 0:
                type_rank = next_rank
                dynamic[indicator.type] = type_rank
                next_rank += 1
        scored.append((type_rank, index, indicator))
    scored.sort(key=lambda item: (item[0], item[1]))
    return tuple(item[2] for item in scored)


def _pack(
    indicators: Sequence[Indicator],
    *,
    input_characters: int,
    truncated: bool,
    match_limit_hit: bool,
    sources: tuple[str, ...],
) -> Extraction:
    counts: dict[str, int] = {}
    sightings = 0
    for indicator in indicators:
        counts[indicator.type] = counts.get(indicator.type, 0) + 1
        sightings += indicator.occurrences
    stats = ExtractionStats(
        counts=counts,
        total=len(indicators),
        sightings=sightings,
        input_characters=input_characters,
        truncated=truncated,
        match_limit_hit=match_limit_hit,
        sources=sources,
    )
    return Extraction(indicators=tuple(indicators), stats=stats)


def _empty_extraction() -> Extraction:
    return _pack((), input_characters=0, truncated=False, match_limit_hit=False, sources=())


def _iter_file(path: Path, chunk_size: int) -> Iterator[str]:
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            yield chunk
