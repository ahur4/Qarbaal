"""Exporters. STIX, MISP, and OpenIOC are built with the standard library.

Pass ``path`` and ``filename`` to write the same text to a file. The call then
returns an ``ExportFile``. Omit both and the function returns the text.

YARA and Sigma are not generated. A file hash is not a YARA rule on its own,
and a Sigma rule needs a log source and field selection that an indicator list
does not carry. Suricata and Snort rules are emitted only for IPs, CIDR
ranges, domains, and URLs.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import overload
from xml.dom import minidom

from pydantic import BaseModel, ConfigDict

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

_DEFAULT_FILENAMES: dict[str, str] = {
    "csv": f"{TOOL_NAME}.csv",
    "json": f"{TOOL_NAME}.json",
    "jsonl": f"{TOOL_NAME}.jsonl",
    "defanged": f"{TOOL_NAME}.defanged.txt",
    "stix": f"{TOOL_NAME}.stix.json",
    "misp": f"{TOOL_NAME}.misp.json",
    "openioc": f"{TOOL_NAME}.openioc.xml",
    "suricata": f"{TOOL_NAME}.suricata.rules",
    "snort": f"{TOOL_NAME}.snort.rules",
}


class ExportFile(BaseModel):
    """A file written by an export function.

    An exporter returns this model when ``path`` or ``filename`` is set. With
    neither argument it returns the serialized text instead.

    Attributes:
        path: Absolute path of the written file.
        filename: File name, without a directory.
        size: File size in bytes.
        format: Export format, such as ``csv``, ``json``, or ``stix``.
        count: Indicators represented in the file. Suricata and Snort count
            emitted rules. A STIX bundle counts the objects in the bundle.
        sha256: SHA-256 hex digest of the file bytes.
    """

    model_config = ConfigDict(frozen=True)

    path: str
    filename: str
    size: int
    format: str
    count: int
    sha256: str


def _finish(
    content: str,
    *,
    format_name: str,
    count: int,
    path: str | os.PathLike[str] | None,
    filename: str | None,
) -> str | ExportFile:
    if path is None and filename is None:
        return content
    directory = Path.cwd() if path is None else Path(path).expanduser()
    name = _plain_filename(filename) if filename is not None else _DEFAULT_FILENAMES[format_name]
    directory.mkdir(parents=True, exist_ok=True)
    destination = (directory / name).resolve()
    payload = content.encode("utf-8")
    destination.write_bytes(payload)
    return ExportFile(
        path=str(destination),
        filename=name,
        size=destination.stat().st_size,
        format=format_name,
        count=count,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _plain_filename(filename: str) -> str:
    if (
        not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or "\x00" in filename
        or filename != filename.strip()
    ):
        raise ValueError("filename must be a file name, without a directory")
    return filename


@overload
def to_csv(
    result: Extraction,
    *,
    hide_private: bool = False,
    detailed: bool = False,
    path: None = None,
    filename: None = None,
) -> str: ...


@overload
def to_csv(
    result: Extraction,
    *,
    hide_private: bool = False,
    detailed: bool = False,
    path: str | os.PathLike[str],
    filename: str | None = None,
) -> ExportFile: ...


@overload
def to_csv(
    result: Extraction,
    *,
    hide_private: bool = False,
    detailed: bool = False,
    path: str | os.PathLike[str] | None = None,
    filename: str,
) -> ExportFile: ...


@overload
def to_csv(
    result: Extraction,
    *,
    hide_private: bool = False,
    detailed: bool = False,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile: ...


def to_csv(
    result: Extraction,
    *,
    hide_private: bool = False,
    detailed: bool = False,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile:
    """Render indicators as CSV.

    The compact form is ``type,value,tags`` with a UTF-8 BOM, CRLF line breaks,
    and every field quoted. Tags are joined with ``|``. There is no trailing
    line break after the last row.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP, IPv6, and CIDR rows.
        detailed: Add normalized value, fingerprint, provenance, and confidence.
        path: Directory for the file. Created when missing. The current working
            directory is used when only ``filename`` is set.
        filename: File name to write. The default is ``qarbaal.csv``. A name
            that contains a directory is rejected.

    Returns:
        CSV text, or an ``ExportFile`` when a file is written.
    """

    rows: list[list[object]] = [list(_csv_header(detailed))]
    for indicator in _visible(result, hide_private):
        rows.append(_csv_row(indicator, detailed))
    content = "\ufeff" + "\r\n".join(",".join(_quote(cell) for cell in row) for row in rows)
    return _finish(content, format_name="csv", count=len(rows) - 1, path=path, filename=filename)


@overload
def to_json(
    result: Extraction,
    *,
    hide_private: bool = False,
    detailed: bool = False,
    generated: datetime | None = None,
    path: None = None,
    filename: None = None,
) -> str: ...


@overload
def to_json(
    result: Extraction,
    *,
    hide_private: bool = False,
    detailed: bool = False,
    generated: datetime | None = None,
    path: str | os.PathLike[str],
    filename: str | None = None,
) -> ExportFile: ...


@overload
def to_json(
    result: Extraction,
    *,
    hide_private: bool = False,
    detailed: bool = False,
    generated: datetime | None = None,
    path: str | os.PathLike[str] | None = None,
    filename: str,
) -> ExportFile: ...


@overload
def to_json(
    result: Extraction,
    *,
    hide_private: bool = False,
    detailed: bool = False,
    generated: datetime | None = None,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile: ...


def to_json(
    result: Extraction,
    *,
    hide_private: bool = False,
    detailed: bool = False,
    generated: datetime | None = None,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile:
    """Render indicators as JSON.

    The compact document is ``{"tool", "generated", "iocs"}`` where ``iocs``
    maps a type key to a list of sieve values. Types with no values are omitted.
    ``detailed=True`` writes one object per indicator, including provenance.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP, IPv6, and CIDR values.
        detailed: Write the full indicator records.
        generated: Timestamp used for ``generated``. Defaults to the current time.
        path: Directory for the file. Created when missing. The current working
            directory is used when only ``filename`` is set.
        filename: File name to write. The default is ``qarbaal.json``. A name
            that contains a directory is rejected.

    Returns:
        JSON text, or an ``ExportFile`` when a file is written.
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
            grouped.setdefault(indicator.type.value, []).append(indicator.value)
        payload = {"tool": TOOL_NAME, "generated": stamp, "iocs": grouped}
    content = json.dumps(payload, indent=2, ensure_ascii=False)
    return _finish(content, format_name="json", count=len(visible), path=path, filename=filename)


@overload
def to_jsonl(
    result: Extraction,
    *,
    hide_private: bool = False,
    path: None = None,
    filename: None = None,
) -> str: ...


@overload
def to_jsonl(
    result: Extraction,
    *,
    hide_private: bool = False,
    path: str | os.PathLike[str],
    filename: str | None = None,
) -> ExportFile: ...


@overload
def to_jsonl(
    result: Extraction,
    *,
    hide_private: bool = False,
    path: str | os.PathLike[str] | None = None,
    filename: str,
) -> ExportFile: ...


@overload
def to_jsonl(
    result: Extraction,
    *,
    hide_private: bool = False,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile: ...


def to_jsonl(
    result: Extraction,
    *,
    hide_private: bool = False,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile:
    """Render one JSON object per indicator, followed by a newline.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP, IPv6, and CIDR rows.
        path: Directory for the file. Created when missing. The current working
            directory is used when only ``filename`` is set.
        filename: File name to write. The default is ``qarbaal.jsonl``. A name
            that contains a directory is rejected.

    Returns:
        JSONL text, or an ``ExportFile`` when a file is written.
    """

    visible = _visible(result, hide_private)
    lines = [json.dumps(indicator_to_dict(indicator), ensure_ascii=False) for indicator in visible]
    content = "" if not lines else "\n".join(lines) + "\n"
    return _finish(content, format_name="jsonl", count=len(visible), path=path, filename=filename)


@overload
def to_defanged_list(
    result: Extraction,
    *,
    hide_private: bool = False,
    path: None = None,
    filename: None = None,
) -> str: ...


@overload
def to_defanged_list(
    result: Extraction,
    *,
    hide_private: bool = False,
    path: str | os.PathLike[str],
    filename: str | None = None,
) -> ExportFile: ...


@overload
def to_defanged_list(
    result: Extraction,
    *,
    hide_private: bool = False,
    path: str | os.PathLike[str] | None = None,
    filename: str,
) -> ExportFile: ...


@overload
def to_defanged_list(
    result: Extraction,
    *,
    hide_private: bool = False,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile: ...


def to_defanged_list(
    result: Extraction,
    *,
    hide_private: bool = False,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile:
    """Render one defanged indicator per line, in export order.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP, IPv6, and CIDR rows.
        path: Directory for the file. Created when missing. The current working
            directory is used when only ``filename`` is set.
        filename: File name to write. The default is ``qarbaal.defanged.txt``.
            A name that contains a directory is rejected.

    Returns:
        Plain text, or an ``ExportFile`` when a file is written.
    """

    visible = _visible(result, hide_private)
    lines = [defang(indicator.value, indicator.type) for indicator in visible]
    return _finish(
        "\n".join(lines),
        format_name="defanged",
        count=len(visible),
        path=path,
        filename=filename,
    )


@overload
def to_stix(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    id_factory: IdFactory | None = None,
    path: None = None,
    filename: None = None,
) -> str: ...


@overload
def to_stix(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    id_factory: IdFactory | None = None,
    path: str | os.PathLike[str],
    filename: str | None = None,
) -> ExportFile: ...


@overload
def to_stix(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    id_factory: IdFactory | None = None,
    path: str | os.PathLike[str] | None = None,
    filename: str,
) -> ExportFile: ...


@overload
def to_stix(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    id_factory: IdFactory | None = None,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile: ...


def to_stix(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    id_factory: IdFactory | None = None,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile:
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
        path: Directory for the file. Created when missing. The current working
            directory is used when only ``filename`` is set.
        filename: File name to write. The default is ``qarbaal.stix.json``.
            A name that contains a directory is rejected.

    Returns:
        Bundle JSON, or an ``ExportFile`` when a file is written.
    """

    stamp = isoformat_z(generated)
    mint = id_factory or _default_id
    objects: list[dict[str, object]] = []
    for indicator in _visible(result, hide_private):
        built = _stix_object(indicator, stamp, mint)
        if built is not None:
            objects.append(built)
    payload = {"type": "bundle", "id": mint("bundle"), "objects": objects}
    content = json.dumps(payload, indent=2, ensure_ascii=False)
    return _finish(content, format_name="stix", count=len(objects), path=path, filename=filename)


@overload
def to_misp(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    path: None = None,
    filename: None = None,
) -> str: ...


@overload
def to_misp(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    path: str | os.PathLike[str],
    filename: str | None = None,
) -> ExportFile: ...


@overload
def to_misp(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    path: str | os.PathLike[str] | None = None,
    filename: str,
) -> ExportFile: ...


@overload
def to_misp(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile: ...


def to_misp(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile:
    """Render a MISP event containing one attribute per indicator.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP, IPv6, and CIDR attributes.
        generated: Event date. Defaults to the current UTC day.
        path: Directory for the file. Created when missing. The current working
            directory is used when only ``filename`` is set.
        filename: File name to write. The default is ``qarbaal.misp.json``.
            A name that contains a directory is rejected.

    Returns:
        MISP JSON, or an ``ExportFile`` when a file is written.
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
                "comment": indicator.type.value,
            }
        )
    payload = {
        "Event": {
            "info": f"{TOOL_NAME} indicators",
            "date": moment.astimezone(timezone.utc).date().isoformat(),
            "Attribute": attributes,
        }
    }
    content = json.dumps(payload, indent=2, ensure_ascii=False)
    return _finish(
        content,
        format_name="misp",
        count=len(attributes),
        path=path,
        filename=filename,
    )


@overload
def to_openioc(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    id_factory: IdFactory | None = None,
    path: None = None,
    filename: None = None,
) -> str: ...


@overload
def to_openioc(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    id_factory: IdFactory | None = None,
    path: str | os.PathLike[str],
    filename: str | None = None,
) -> ExportFile: ...


@overload
def to_openioc(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    id_factory: IdFactory | None = None,
    path: str | os.PathLike[str] | None = None,
    filename: str,
) -> ExportFile: ...


@overload
def to_openioc(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    id_factory: IdFactory | None = None,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile: ...


def to_openioc(
    result: Extraction,
    *,
    hide_private: bool = False,
    generated: datetime | None = None,
    id_factory: IdFactory | None = None,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile:
    """Render an OpenIOC 1.1 document.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged IP, IPv6, and CIDR items.
        generated: ``last-modified`` and ``authored_date`` timestamp.
        id_factory: Callable used for the document id and each indicator item.
        path: Directory for the file. Created when missing. The current working
            directory is used when only ``filename`` is set.
        filename: File name to write. The default is ``qarbaal.openioc.xml``.
            A name that contains a directory is rejected.

    Returns:
        OpenIOC XML, or an ``ExportFile`` when a file is written.
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
    visible = _visible(result, hide_private)
    for indicator in visible:
        document, search = _OPENIOC_CONTEXT.get(indicator.type, ("Other", indicator.type.value))
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
    rendered = parsed.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8").strip()
    return _finish(
        rendered,
        format_name="openioc",
        count=len(visible),
        path=path,
        filename=filename,
    )


@overload
def to_suricata(
    result: Extraction,
    *,
    hide_private: bool = False,
    sid_start: int = 1_000_001,
    path: None = None,
    filename: None = None,
) -> str: ...


@overload
def to_suricata(
    result: Extraction,
    *,
    hide_private: bool = False,
    sid_start: int = 1_000_001,
    path: str | os.PathLike[str],
    filename: str | None = None,
) -> ExportFile: ...


@overload
def to_suricata(
    result: Extraction,
    *,
    hide_private: bool = False,
    sid_start: int = 1_000_001,
    path: str | os.PathLike[str] | None = None,
    filename: str,
) -> ExportFile: ...


@overload
def to_suricata(
    result: Extraction,
    *,
    hide_private: bool = False,
    sid_start: int = 1_000_001,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile: ...


def to_suricata(
    result: Extraction,
    *,
    hide_private: bool = False,
    sid_start: int = 1_000_001,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile:
    """Render Suricata rules for IPs, CIDR ranges, domains, and URLs.

    Other types are omitted. A value containing a quote, semicolon, or backslash
    is omitted rather than escaped into a broken rule.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged addresses.
        sid_start: First SID. Each rule increments it by one.
        path: Directory for the file. Created when missing. The current working
            directory is used when only ``filename`` is set.
        filename: File name to write. The default is ``qarbaal.suricata.rules``.
            A name that contains a directory is rejected.

    Returns:
        Rule text, or an ``ExportFile`` when a file is written.
    """

    content, count = _rules(result, hide_private=hide_private, sid_start=sid_start, kind="suricata")
    return _finish(content, format_name="suricata", count=count, path=path, filename=filename)


@overload
def to_snort(
    result: Extraction,
    *,
    hide_private: bool = False,
    sid_start: int = 1_000_001,
    path: None = None,
    filename: None = None,
) -> str: ...


@overload
def to_snort(
    result: Extraction,
    *,
    hide_private: bool = False,
    sid_start: int = 1_000_001,
    path: str | os.PathLike[str],
    filename: str | None = None,
) -> ExportFile: ...


@overload
def to_snort(
    result: Extraction,
    *,
    hide_private: bool = False,
    sid_start: int = 1_000_001,
    path: str | os.PathLike[str] | None = None,
    filename: str,
) -> ExportFile: ...


@overload
def to_snort(
    result: Extraction,
    *,
    hide_private: bool = False,
    sid_start: int = 1_000_001,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile: ...


def to_snort(
    result: Extraction,
    *,
    hide_private: bool = False,
    sid_start: int = 1_000_001,
    path: str | os.PathLike[str] | None = None,
    filename: str | None = None,
) -> str | ExportFile:
    """Render Snort rules for IPs, CIDR ranges, domains, and URLs.

    Domain rules match the name in DNS traffic (UDP port 53). Suricata rules
    use ``dns.query`` instead. The same character limits as :func:`to_suricata`
    apply.

    Args:
        result: Extraction to render.
        hide_private: Drop tagged addresses.
        sid_start: First SID.
        path: Directory for the file. Created when missing. The current working
            directory is used when only ``filename`` is set.
        filename: File name to write. The default is ``qarbaal.snort.rules``.
            A name that contains a directory is rejected.

    Returns:
        Rule text, or an ``ExportFile`` when a file is written.
    """

    content, count = _rules(result, hide_private=hide_private, sid_start=sid_start, kind="snort")
    return _finish(content, format_name="snort", count=count, path=path, filename=filename)


def indicator_to_dict(indicator: Indicator) -> dict[str, object]:
    """Return a JSON-ready mapping for one indicator.

    Args:
        indicator: Indicator to describe.

    Returns:
        A dictionary of plain JSON types.
    """

    return {
        "type": indicator.type.value,
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
        return [indicator.type.value, indicator.value, tags]
    valid = "" if indicator.valid is None else str(indicator.valid).lower()
    return [
        indicator.type.value,
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
        if indicator.type.value not in counts:
            counts[indicator.type.value] = sum(
                1 for item in indicators if item.type == indicator.type
            )
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
        "name": f"{TOOL_NAME} {indicator.type.value}: {indicator.value}",
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


def _rules(result: Extraction, *, hide_private: bool, sid_start: int, kind: str) -> tuple[str, int]:
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
        return f"# {TOOL_NAME}: no network indicators to emit\n", 0
    return "\n".join(rules) + "\n", len(rules)


def _rule_safe(value: str) -> bool:
    return bool(value) and not any(char in value for char in '"\\;\r\n')


def _one_rule(indicator: Indicator, sid: int, kind: str) -> str | None:
    message = f"{TOOL_NAME} {indicator.type.value} {indicator.normalized}"
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
