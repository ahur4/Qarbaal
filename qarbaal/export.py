"""Exporters. STIX, MISP, and OpenIOC are built with the standard library.

YARA and Sigma are not generated. A file hash is not a YARA rule on its own,
and a Sigma rule needs a log source and field selection that an indicator list
does not carry. Suricata and Snort rules are emitted only for IPs, CIDR
ranges, domains, and URLs.
"""

from __future__ import annotations

import json
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from xml.dom import minidom

from qarbaal.refang import defang
from qarbaal.types import OUTPUT_ORDER, Extraction, Indicator, IOCType
from qarbaal.version import TOOL_NAME

_NETWORK_RULES = {
    IOCType.IPV4.value,
    IOCType.IPV6.value,
    IOCType.CIDR.value,
    IOCType.DOMAIN.value,
    IOCType.URL.value,
}
_STIX_PATTERN = {
    IOCType.IPV4.value: "[ipv4-addr:value = '{value}']",
    IOCType.IPV6.value: "[ipv6-addr:value = '{value}']",
    IOCType.DOMAIN.value: "[domain-name:value = '{value}']",
    IOCType.URL.value: "[url:value = '{value}']",
    IOCType.MD5.value: "[file:hashes.MD5 = '{value}']",
    IOCType.SHA1.value: "[file:hashes.'SHA-1' = '{value}']",
    IOCType.SHA256.value: "[file:hashes.'SHA-256' = '{value}']",
    IOCType.SHA512.value: "[file:hashes.'SHA-512' = '{value}']",
    IOCType.EMAIL.value: "[email-addr:value = '{value}']",
    IOCType.REGISTRY.value: "[windows-registry-key:key = '{value}']",
    IOCType.MAC.value: "[mac-addr:value = '{value}']",
    IOCType.MUTEX.value: "[mutex:name = '{value}']",
}
_MISP = {
    IOCType.IPV4.value: ("Network activity", "ip-dst", True),
    IOCType.IPV6.value: ("Network activity", "ip-dst", True),
    IOCType.CIDR.value: ("Network activity", "ip-dst", True),
    IOCType.DOMAIN.value: ("Network activity", "domain", True),
    IOCType.URL.value: ("Network activity", "url", True),
    IOCType.MD5.value: ("Payload delivery", "md5", True),
    IOCType.SHA1.value: ("Payload delivery", "sha1", True),
    IOCType.SHA256.value: ("Payload delivery", "sha256", True),
    IOCType.SHA512.value: ("Payload delivery", "sha512", True),
    IOCType.EMAIL.value: ("Payload delivery", "email-src", True),
    IOCType.CVE.value: ("External analysis", "vulnerability", False),
    IOCType.REGISTRY.value: ("Persistence mechanism", "regkey", True),
    IOCType.WALLET.value: ("Financial fraud", "btc", True),
    IOCType.MAC.value: ("Network activity", "mac-address", False),
    IOCType.ASN.value: ("Network activity", "AS", False),
    IOCType.JA3.value: ("Network activity", "ja3-fingerprint-md5", True),
    IOCType.JA3S.value: ("Network activity", "ja3s-fingerprint-md5", True),
    IOCType.JARM.value: ("Network activity", "jarm-fingerprint", True),
    IOCType.MUTEX.value: ("Artifacts dropped", "mutex", True),
    IOCType.PATH.value: ("Payload installation", "filename", True),
    IOCType.USER_AGENT.value: ("Network activity", "user-agent", False),
    IOCType.ATTACK.value: ("Attribution", "text", False),
}
_OPENIOC_CONTEXT = {
    IOCType.IPV4.value: ("Network", "ipv4"),
    IOCType.IPV6.value: ("Network", "ipv6"),
    IOCType.CIDR.value: ("Network", "cidr"),
    IOCType.DOMAIN.value: ("Network", "domain"),
    IOCType.URL.value: ("Network", "url"),
    IOCType.EMAIL.value: ("Email", "email"),
    IOCType.MD5.value: ("File", "md5"),
    IOCType.SHA1.value: ("File", "sha1"),
    IOCType.SHA256.value: ("File", "sha256"),
    IOCType.SHA512.value: ("File", "sha512"),
    IOCType.REGISTRY.value: ("Registry", "key"),
    IOCType.CVE.value: ("Vulnerability", "cve"),
    IOCType.MAC.value: ("Network", "mac"),
    IOCType.ASN.value: ("Network", "asn"),
    IOCType.MUTEX.value: ("Process", "mutex"),
    IOCType.PATH.value: ("File", "path"),
    IOCType.USER_AGENT.value: ("Network", "user-agent"),
    IOCType.JA3.value: ("Network", "ja3"),
    IOCType.JA3S.value: ("Network", "ja3s"),
    IOCType.JARM.value: ("Network", "jarm"),
    IOCType.WALLET.value: ("Other", "wallet"),
    IOCType.ATTACK.value: ("Other", "attack"),
}
IdFactory = Callable[[str], str]


def to_csv(
    result: Extraction,
    *,
    hide_private: bool = False,
    detailed: bool = False,
) -> str:
    """Render indicators as CSV.

    The compact form is ``type,value,tags`` with a UTF-8 BOM, CRLF line breaks,
    and every field quoted. Tags are joined with ``|``. There is no trailing
    line break after the last row.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP, IPv6, and CIDR rows.
        detailed: Add normalized value, fingerprint, provenance, and confidence.

    Returns:
        CSV text, including the leading BOM.
    """

    rows: list[list[object]] = [list(_csv_header(detailed))]
    for indicator in _visible(result, hide_private):
        rows.append(_csv_row(indicator, detailed))
    return "\ufeff" + "\r\n".join(",".join(_quote(cell) for cell in row) for row in rows)


def to_json(
    result: Extraction,
    *,
    hide_private: bool = False,
    detailed: bool = False,
    generated: datetime | None = None,
) -> str:
    """Render indicators as JSON.

    The compact document is ``{"tool", "generated", "iocs"}`` where ``iocs``
    maps a type key to a list of sieve values. Types with no values are omitted.
    ``detailed=True`` writes one object per indicator, including provenance.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP, IPv6, and CIDR values.
        detailed: Write the full indicator records.
        generated: Timestamp used for ``generated``. Defaults to the current time.

    Returns:
        JSON text indented by two spaces, without a trailing newline.
    """

    stamp = isoformat_z(generated)
    visible = _visible(result, hide_private)
    if detailed:
        payload: dict[str, object] = {
            "tool": TOOL_NAME,
            "generated": stamp,
            "truncated": result.stats.truncated,
            "stats": {
                "total": len(visible),
                "sightings": sum(item.occurrences for item in visible),
                "counts": _counts(visible),
            },
            "indicators": [indicator_to_dict(item) for item in visible],
        }
    else:
        grouped: dict[str, list[str]] = {}
        for indicator in visible:
            grouped.setdefault(indicator.type, []).append(indicator.value)
        payload = {"tool": TOOL_NAME, "generated": stamp, "iocs": grouped}
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_jsonl(
    result: Extraction,
    *,
    hide_private: bool = False,
) -> str:
    """Render one JSON object per indicator, followed by a newline.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP, IPv6, and CIDR rows.

    Returns:
        JSONL text. An empty extraction returns an empty string.
    """

    lines = [
        json.dumps(indicator_to_dict(indicator), ensure_ascii=False)
        for indicator in _visible(result, hide_private)
    ]
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def to_defanged_list(result: Extraction, *, hide_private: bool = False) -> str:
    """Render one defanged indicator per line, in export order.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP, IPv6, and CIDR rows.

    Returns:
        Plain text. Lines are separated by ``\\n`` with no trailing newline.
    """

    lines = [
        defang(indicator.value, indicator.type) for indicator in _visible(result, hide_private)
    ]
    return "\n".join(lines)


def to_stix(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    id_factory: IdFactory | None = None,
) -> str:
    """Render a STIX 2.1 bundle.

    IPs, domains, URLs, hashes, email addresses, registry keys, MAC addresses,
    and mutexes become ``indicator`` objects. CVE identifiers become
    ``vulnerability`` objects. ASN values become indicators with an
    ``autonomous-system:number`` pattern. Types without a single clear STIX
    pattern (CIDR, JA3, JA3S, JARM, file paths, user agents, wallets, ATT&CK
    technique IDs) are left out of the bundle.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP and IPv6 objects.
        generated: Timestamp applied to every object.
        id_factory: Callable that receives ``bundle``, ``indicator``, or
            ``vulnerability`` and returns the full STIX id.

    Returns:
        JSON text for the bundle.
    """

    stamp = isoformat_z(generated)
    mint = id_factory or _default_id
    objects: list[dict[str, object]] = []
    for indicator in _visible(result, hide_private):
        built = _stix_object(indicator, stamp, mint)
        if built is not None:
            objects.append(built)
    payload = {"type": "bundle", "id": mint("bundle"), "objects": objects}
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_misp(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
) -> str:
    """Render a MISP event containing one attribute per indicator.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP, IPv6, and CIDR attributes.
        generated: Event date. Defaults to the current UTC day.

    Returns:
        MISP event JSON.
    """

    moment = generated or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    attributes: list[dict[str, object]] = []
    for indicator in _visible(result, hide_private):
        category, misp_type, to_ids = _MISP.get(
            indicator.type,
            ("External analysis", "text", False),
        )
        attributes.append(
            {
                "type": misp_type,
                "category": category,
                "value": indicator.value,
                "to_ids": to_ids,
                "comment": indicator.type,
            }
        )
    payload = {
        "Event": {
            "info": f"{TOOL_NAME} indicators",
            "date": moment.astimezone(timezone.utc).date().isoformat(),
            "Attribute": attributes,
        }
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_openioc(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    id_factory: IdFactory | None = None,
) -> str:
    """Render an OpenIOC 1.1 document.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP, IPv6, and CIDR items.
        generated: ``last-modified`` and ``authored_date`` timestamp.
        id_factory: Callable used for the document id and each indicator item.

    Returns:
        XML text with an XML declaration.
    """

    stamp = isoformat_z(generated)
    mint = id_factory or _default_id
    root = ET.Element(
        "ioc",
        {
            "xmlns": "http://schemas.mandiant.com/2010/ioc",
            "id": mint("ioc"),
            "last-modified": stamp,
        },
    )
    ET.SubElement(root, "short_description").text = f"{TOOL_NAME} indicators"
    ET.SubElement(root, "description").text = "Indicators exported by qarbaal."
    ET.SubElement(root, "authored_by").text = TOOL_NAME
    ET.SubElement(root, "authored_date").text = stamp
    definition = ET.SubElement(root, "definition")
    group = ET.SubElement(definition, "Indicator", {"operator": "OR", "id": mint("indicator")})
    for indicator in _visible(result, hide_private):
        document, search = _OPENIOC_CONTEXT.get(indicator.type, ("Other", indicator.type))
        item = ET.SubElement(
            group,
            "IndicatorItem",
            {"id": mint("item"), "condition": "is"},
        )
        ET.SubElement(item, "Context", {"document": document, "search": search, "type": "mir"})
        content = ET.SubElement(item, "Content", {"type": "string"})
        content.text = indicator.value
    rough = ET.tostring(root, encoding="utf-8")
    parsed = minidom.parseString(rough)
    return parsed.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8").strip()


def to_suricata(
    result: Extraction, *, hide_private: bool = False, sid_start: int = 1_000_001
) -> str:
    """Render Suricata rules for IPs, CIDR ranges, domains, and URLs.

    Other types are omitted. A value containing a quote, semicolon, or backslash
    is omitted rather than escaped into a broken rule.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged addresses.
        sid_start: First SID. Each rule increments it by one.

    Returns:
        Rule text ending in a newline, or a comment when nothing applies.
    """

    return _rules(result, hide_private=hide_private, sid_start=sid_start, kind="suricata")


def to_snort(result: Extraction, *, hide_private: bool = False, sid_start: int = 1_000_001) -> str:
    """Render Snort rules for IPs, CIDR ranges, domains, and URLs.

    Domain rules match the name in DNS traffic (UDP port 53). Suricata rules
    use ``dns.query`` instead. The same character limits as :func:`to_suricata`
    apply.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged addresses.
        sid_start: First SID.

    Returns:
        Rule text ending in a newline, or a comment when nothing applies.
    """

    return _rules(result, hide_private=hide_private, sid_start=sid_start, kind="snort")


def indicator_to_dict(indicator: Indicator) -> dict[str, object]:
    """Return a JSON-ready mapping for one indicator.

    Args:
        indicator: Indicator to describe.

    Returns:
        A dictionary of plain JSON types.
    """

    return {
        "type": indicator.type,
        "value": indicator.value,
        "normalized": indicator.normalized,
        "raw": indicator.raw,
        "tags": list(indicator.tags),
        "fingerprint": indicator.fingerprint,
        "valid": indicator.valid,
        "confidence": indicator.confidence,
        "validation_notes": list(indicator.validation_notes),
        "occurrences": indicator.occurrences,
        "sources": list(indicator.sources),
        "sightings": [
            {
                "source": sighting.source,
                "line": sighting.line,
                "offset": sighting.offset,
                "end_offset": sighting.end_offset,
                "page": sighting.page,
            }
            for sighting in indicator.sightings
        ],
        "enrichment": indicator.enrichment.as_dict(),
        "pivots": [{"name": name, "url": url} for name, url in indicator.pivots],
    }


def isoformat_z(moment: datetime | None = None) -> str:
    """Format a timestamp as ``YYYY-MM-DDTHH:MM:SS.sssZ``.

    Args:
        moment: Aware or naive datetime. Naive values are treated as UTC.
            Defaults to the current time.

    Returns:
        A UTC timestamp with millisecond precision and a ``Z`` suffix.
    """

    current = moment or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    return current.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _visible(result: Extraction, hide_private: bool) -> tuple[Indicator, ...]:
    if not hide_private:
        return result.indicators
    hidden = {IOCType.IPV4.value, IOCType.IPV6.value, IOCType.CIDR.value}
    return tuple(
        indicator
        for indicator in result.indicators
        if not (indicator.type in hidden and indicator.tags)
    )


def _csv_header(detailed: bool) -> list[str]:
    if not detailed:
        return ["type", "value", "tags"]
    return [
        "type",
        "value",
        "normalized",
        "tags",
        "fingerprint",
        "source",
        "line",
        "offset",
        "page",
        "occurrences",
        "confidence",
        "valid",
    ]


def _csv_row(indicator: Indicator, detailed: bool) -> list[object]:
    tags = "|".join(indicator.tags)
    if not detailed:
        return [indicator.type, indicator.value, tags]
    valid = "" if indicator.valid is None else str(indicator.valid).lower()
    return [
        indicator.type,
        indicator.value,
        indicator.normalized,
        tags,
        indicator.fingerprint,
        indicator.source,
        "" if indicator.line is None else indicator.line,
        "" if indicator.offset is None else indicator.offset,
        "" if indicator.page is None else indicator.page,
        indicator.occurrences,
        f"{indicator.confidence:.2f}",
        valid,
    ]


def _quote(cell: object) -> str:
    text = "" if cell is None else str(cell)
    return '"' + text.replace('"', '""') + '"'


def _counts(indicators: Sequence[Indicator]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in OUTPUT_ORDER:
        found = sum(1 for indicator in indicators if indicator.type == name)
        if found:
            counts[name] = found
    for indicator in indicators:
        if indicator.type not in counts:
            counts[indicator.type] = sum(1 for item in indicators if item.type == indicator.type)
    return counts


def _stix_object(
    indicator: Indicator,
    stamp: str,
    mint: IdFactory,
) -> dict[str, object] | None:
    labels = [f"{TOOL_NAME}-extracted", *indicator.tags]
    if indicator.type == IOCType.CVE.value:
        return {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": mint("vulnerability"),
            "created": stamp,
            "modified": stamp,
            "name": indicator.value,
            "external_references": [{"source_name": "cve", "external_id": indicator.value}],
        }
    if indicator.type == IOCType.ASN.value and indicator.normalized[2:].isdigit():
        pattern = f"[autonomous-system:number = {int(indicator.normalized[2:])}]"
    elif indicator.type in _STIX_PATTERN:
        pattern = _STIX_PATTERN[indicator.type].format(
            value=_stix_escape(indicator.type, _stix_value(indicator))
        )
    else:
        return None
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": mint("indicator"),
        "created": stamp,
        "modified": stamp,
        "name": f"{TOOL_NAME} {indicator.type}: {indicator.value}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": stamp,
        "labels": labels,
    }


def _stix_value(indicator: Indicator) -> str:
    if indicator.type == IOCType.MAC.value:
        return indicator.normalized
    return indicator.value


def _stix_escape(kind: str, value: str) -> str:
    if kind in {IOCType.REGISTRY.value, IOCType.MUTEX.value}:
        return value.replace("\\", "\\\\").replace("'", "\\'")
    if kind == IOCType.URL.value:
        return value.replace("'", "\\'")
    return value


def _rules(result: Extraction, *, hide_private: bool, sid_start: int, kind: str) -> str:
    rules: list[str] = []
    sid = sid_start
    for indicator in _visible(result, hide_private):
        if indicator.type not in _NETWORK_RULES or not _rule_safe(indicator.normalized):
            continue
        rule = _one_rule(indicator, sid, kind)
        if rule is None:
            continue
        rules.append(rule)
        sid += 1
    if not rules:
        return f"# {TOOL_NAME}: no network indicators to emit\n"
    return "\n".join(rules) + "\n"


def _rule_safe(value: str) -> bool:
    return bool(value) and not any(char in value for char in '"\\;\r\n')


def _one_rule(indicator: Indicator, sid: int, kind: str) -> str | None:
    message = f"{TOOL_NAME} {indicator.type} {indicator.normalized}"
    if indicator.type in {IOCType.IPV4.value, IOCType.IPV6.value, IOCType.CIDR.value}:
        return (
            f"alert ip any any -> {indicator.normalized} any "
            f'(msg:"{message}"; classtype:trojan-activity; sid:{sid}; rev:1;)'
        )
    if indicator.type == IOCType.DOMAIN.value:
        if kind == "suricata":
            return (
                f'alert dns any any -> any any (msg:"{message}"; dns.query; '
                f'content:"{indicator.normalized}"; nocase; classtype:trojan-activity; '
                f"sid:{sid}; rev:1;)"
            )
        return (
            f'alert udp any any -> any 53 (msg:"{message}"; content:"{indicator.normalized}"; '
            f"nocase; sid:{sid}; rev:1;)"
        )
    if indicator.type == IOCType.URL.value:
        from urllib.parse import urlsplit

        parts = urlsplit(indicator.normalized)
        host = parts.hostname or ""
        path = parts.path or "/"
        if not _rule_safe(host) or not _rule_safe(path):
            return None
        if kind == "suricata":
            return (
                f'alert http any any -> any any (msg:"{message}"; http.host; content:"{host}"; '
                f'http.uri; content:"{path}"; classtype:trojan-activity; sid:{sid}; rev:1;)'
            )
        return (
            f'alert tcp any any -> any any (msg:"{message}"; content:"{host}"; content:"{path}"; '
            f"sid:{sid}; rev:1;)"
        )
    return None


def _default_id(kind: str) -> str:
    return f"{kind}--{uuid.uuid4()}"
