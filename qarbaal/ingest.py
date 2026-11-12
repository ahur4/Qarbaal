"""Read files into text the sieve can scan.

Plain text, JSON, CSV, XML, EML, and MBOX use the standard library. HTML, PDF,
DOCX, YAML, and PCAP are optional extras. A missing extra raises
:class:`~qarbaal.exceptions.OptionalDependencyError` with the install command.
The core package does not import those libraries.
"""

from __future__ import annotations

import contextlib
import csv
import email
import email.policy
import importlib
import io
import json
import logging
import mailbox
import re
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from qarbaal.exceptions import OptionalDependencyError, ParseError, UnsupportedFormatError

logger = logging.getLogger("qarbaal.ingest")

PageSpan = tuple[int, int, int]
_TAG = re.compile(r"<[^>]+>")
_PRINTABLE = re.compile(r"[\x20-\x7e]{8,}")

_PLAIN = {".txt", ".log", ".md", ".text"}
_STDLIB = {
    ".json": "json",
    ".csv": "csv",
    ".xml": "xml",
    ".eml": "eml",
    ".mbox": "mbox",
}
_OPTIONAL = {
    ".html": ("html", "beautifulsoup4", "bs4"),
    ".htm": ("html", "beautifulsoup4", "bs4"),
    ".pdf": ("pdf", "pymupdf", "fitz"),
    ".docx": ("docx", "python-docx", "docx"),
    ".yaml": ("yaml", "pyyaml", "yaml"),
    ".yml": ("yaml", "pyyaml", "yaml"),
    ".pcap": ("pcap", "scapy", "scapy.all"),
    ".pcapng": ("pcap", "scapy", "scapy.all"),
}
_BY_NAME = {
    "text": "text",
    "json": "json",
    "csv": "csv",
    "xml": "xml",
    "eml": "eml",
    "mbox": "mbox",
    "html": "html",
    "pdf": "pdf",
    "docx": "docx",
    "yaml": "yaml",
    "pcap": "pcap",
}


@dataclass(frozen=True, slots=True)
class LoadedDocument:
    """Text produced from a file, plus page spans when the format has them.

    Attributes:
        source: Path that was read.
        text: Text the sieve should scan. For email this is the decoded body,
            not the raw bytes. For JSON, CSV, XML, and YAML it is the file text,
            so line numbers match the file.
        format: Parser name, such as ``json`` or ``pdf``.
        pages: ``(page, start, end)`` spans into ``text``. Empty when the format
            has no pages.
        truncated: Whether the reader stopped at ``max_chars``.
    """

    source: str
    text: str
    format: str
    pages: tuple[PageSpan, ...] = ()
    truncated: bool = False


def supported_formats() -> tuple[str, ...]:
    """Return the suffixes :func:`load_document` accepts, in a stable order."""

    names = set(_PLAIN)
    names.update(_STDLIB)
    names.update(_OPTIONAL)
    return tuple(sorted(names))


def load_document(
    path: str | Path,
    *,
    parser: str | None = None,
    max_chars: int = 2_000_000,
    pcap_max_packets: int = 20_000,
) -> LoadedDocument:
    """Load a file into text.

    Args:
        path: File to read.
        parser: Parser name (``json``, ``eml``, ``pdf``, ...) instead of the suffix.
        max_chars: Maximum characters returned. Longer input is truncated.
        pcap_max_packets: Packet cap for the PCAP parser.

    Returns:
        A :class:`LoadedDocument`.

    Raises:
        UnsupportedFormatError: The suffix is not supported.
        OptionalDependencyError: The format needs an extra that is not installed.
        ParseError: The file is not valid for the selected parser.
    """

    file_path = Path(path)
    kind = _select(file_path, parser)
    if kind == "text":
        text, truncated = _read_capped(file_path, max_chars)
        return LoadedDocument(str(file_path), text, "text", truncated=truncated)
    if kind == "json":
        text, truncated = _read_capped(file_path, max_chars)
        _parse_json(text)
        return LoadedDocument(str(file_path), text, "json", truncated=truncated)
    if kind == "csv":
        text, truncated = _read_capped(file_path, max_chars)
        _parse_csv(text)
        return LoadedDocument(str(file_path), text, "csv", truncated=truncated)
    if kind == "xml":
        text, truncated = _read_capped(file_path, max_chars)
        _parse_xml(text)
        return LoadedDocument(str(file_path), text, "xml", truncated=truncated)
    if kind == "yaml":
        text, truncated = _read_capped(file_path, max_chars)
        _parse_yaml(text)
        return LoadedDocument(str(file_path), text, "yaml", truncated=truncated)
    if kind == "eml":
        data, truncated = _read_bytes_capped(file_path, max_chars)
        text = _eml_text(data)
        text, truncated = _cap_text(text, max_chars, truncated)
        return LoadedDocument(str(file_path), text, "eml", truncated=truncated)
    if kind == "mbox":
        text = _mbox_text(file_path)
        text, truncated = _cap_text(text, max_chars, False)
        return LoadedDocument(str(file_path), text, "mbox", truncated=truncated)
    if kind == "html":
        data, truncated = _read_bytes_capped(file_path, max_chars)
        text = _html_text(data)
        text, truncated = _cap_text(text, max_chars, truncated)
        return LoadedDocument(str(file_path), text, "html", truncated=truncated)
    if kind == "pdf":
        text, pages, truncated = _pdf_text(file_path, max_chars)
        return LoadedDocument(str(file_path), text, "pdf", pages=pages, truncated=truncated)
    if kind == "docx":
        text = _docx_text(file_path)
        text, truncated = _cap_text(text, max_chars, False)
        return LoadedDocument(str(file_path), text, "docx", truncated=truncated)
    if kind == "pcap":
        text = _pcap_text(file_path, pcap_max_packets)
        text, truncated = _cap_text(text, max_chars, False)
        return LoadedDocument(str(file_path), text, "pcap", truncated=truncated)
    raise UnsupportedFormatError(f"unsupported format: {kind}")


def _select(path: Path, parser: str | None) -> str:
    if parser:
        key = parser.strip().lower()
        if key not in _BY_NAME:
            raise UnsupportedFormatError(
                f"unknown parser {parser!r}; choose from {', '.join(sorted(_BY_NAME))}"
            )
        return _BY_NAME[key]
    suffix = path.suffix.lower()
    if suffix in _PLAIN or suffix == "":
        return "text"
    if suffix in _STDLIB:
        return _STDLIB[suffix]
    if suffix in _OPTIONAL:
        return _OPTIONAL[suffix][0]
    supported = ", ".join(supported_formats())
    raise UnsupportedFormatError(
        f"unsupported file type {suffix or '(none)'}; supported: {supported}"
    )


def _read_capped(path: Path, max_chars: int) -> tuple[str, bool]:
    data, truncated = _read_bytes_capped(path, max_chars)
    text = data.decode("utf-8-sig", errors="replace")
    return _cap_text(text, max_chars, truncated)


def _read_bytes_capped(path: Path, max_chars: int) -> tuple[bytes, bool]:
    limit = max_chars * 4
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > limit:
            return handle.read(limit), True
        return handle.read(), False


def _cap_text(text: str, max_chars: int, already: bool) -> tuple[str, bool]:
    if len(text) > max_chars:
        logger.warning("event=input_truncated limit=%s original=%s", max_chars, len(text))
        return text[:max_chars], True
    return text, already


def _parse_json(text: str) -> None:
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc}") from exc


def _parse_csv(text: str) -> None:
    try:
        list(csv.reader(io.StringIO(text)))
    except csv.Error as exc:
        raise ParseError(f"invalid CSV: {exc}") from exc


def _parse_xml(text: str) -> None:
    try:
        ET.fromstring(text)
    except ET.ParseError as exc:
        raise ParseError(f"invalid XML: {exc}") from exc


def _parse_yaml(text: str) -> None:
    module = _require("yaml", extra="yaml", package="pyyaml")
    loader = getattr(module, "safe_load")
    try:
        loader(text)
    except Exception as exc:
        raise ParseError(f"invalid YAML: {exc}") from exc


def _eml_text(data: bytes) -> str:
    try:
        message = email.message_from_bytes(data, policy=email.policy.default)
    except Exception as exc:
        raise ParseError(f"invalid email: {exc}") from exc
    return _render_message(message)


def _render_message(message: email.message.Message) -> str:
    lines: list[str] = []
    for header in ("from", "to", "cc", "reply-to", "return-path", "subject"):
        value = message.get(header)
        if value:
            lines.append(f"{header}: {value}")
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            content_type = part.get_content_type()
            if content_type not in {"text/plain", "text/html"}:
                continue
            payload = _part_text(part)
            if content_type == "text/html":
                payload = _strip_html(payload)
            if payload:
                lines.append(payload)
    else:
        payload = _part_text(message)
        if message.get_content_type() == "text/html":
            payload = _strip_html(payload)
        if payload:
            lines.append(payload)
    return "\n".join(lines)


def _part_text(part: email.message.Message) -> str:
    getter: Callable[[], object] | None = getattr(part, "get_content", None)
    if callable(getter):
        try:
            content = getter()
        except Exception as exc:
            raise ParseError(f"could not decode an email part: {exc}") from exc
        if isinstance(content, str):
            return content
        if isinstance(content, bytes):
            return content.decode("utf-8", errors="replace")
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    if isinstance(payload, str):
        return payload
    return ""


def _mbox_text(path: Path) -> str:
    try:
        box = mailbox.mbox(path)
    except Exception as exc:
        raise ParseError(f"invalid mbox: {exc}") from exc
    parts: list[str] = []
    try:
        for index, message in enumerate(box, start=1):
            raw = message.as_bytes()
            parsed = email.message_from_bytes(raw, policy=email.policy.default)
            parts.append(f"Message-Index: {index}\n{_render_message(parsed)}")
    finally:
        box.close()
    return "\n".join(parts)


def _html_text(data: bytes) -> str:
    module = _require("bs4", extra="html", package="beautifulsoup4")
    parser = getattr(module, "BeautifulSoup")
    soup = parser(data, "html.parser")
    text = soup.get_text("\n")
    if not isinstance(text, str):
        raise ParseError("HTML parser did not return text")
    return text


def _pdf_text(path: Path, max_chars: int) -> tuple[str, tuple[PageSpan, ...], bool]:
    module = _require("fitz", extra="pdf", package="pymupdf")
    opener = getattr(module, "open")
    document = opener(path)
    chunks: list[str] = []
    pages: list[PageSpan] = []
    cursor = 0
    truncated = False
    try:
        for index, page in enumerate(document, start=1):
            extracted = page.get_text("text")
            if not isinstance(extracted, str):
                extracted = str(extracted)
            if chunks:
                chunks.append("\n")
                cursor += 1
            start = cursor
            chunks.append(extracted)
            cursor += len(extracted)
            pages.append((index, start, cursor))
            if cursor >= max_chars:
                truncated = True
                break
    finally:
        closer = getattr(document, "close", None)
        if callable(closer):
            closer()
    text = "".join(chunks)
    if len(text) > max_chars:
        text = text[:max_chars]
        trimmed: list[PageSpan] = []
        for page, start, end in pages:
            if start >= max_chars:
                break
            trimmed.append((page, start, min(end, max_chars)))
        return text, tuple(trimmed), True
    return text, tuple(pages), truncated


def _docx_text(path: Path) -> str:
    module = _require("docx", extra="docx", package="python-docx")
    factory = getattr(module, "Document")
    document = factory(str(path))
    parts: list[str] = []
    for paragraph in document.paragraphs:
        if paragraph.text:
            parts.append(str(paragraph.text))
    for table in document.tables:
        for row in table.rows:
            cells = [str(cell.text).strip() for cell in row.cells if str(cell.text).strip()]
            if cells:
                parts.append("\t".join(cells))
    return "\n".join(parts)


def _pcap_text(path: Path, max_packets: int) -> str:
    module = _require("scapy.all", extra="pcap", package="scapy")
    reader_cls = getattr(module, "PcapReader")
    dns_cls = getattr(module, "DNS", None)
    lines: list[str] = []
    reader = reader_cls(str(path))
    try:
        for index, packet in enumerate(reader, start=1):
            if index > max_packets:
                logger.warning("event=pcap_packet_cap limit=%s", max_packets)
                break
            if dns_cls is not None:
                try:
                    has_layer = getattr(packet, "haslayer", None)
                    if callable(has_layer) and has_layer(dns_cls):
                        layer = packet.getlayer(dns_cls)
                        record = getattr(layer, "qd", None)
                        # Recent Scapy versions expose qd as a list of questions.
                        if record is not None and not isinstance(record, (bytes, str)):
                            with contextlib.suppress(TypeError, IndexError, KeyError):
                                record = record[0]
                        qname = getattr(record, "qname", None) if record is not None else None
                        if isinstance(qname, bytes):
                            lines.append(qname.decode("utf-8", "replace").rstrip("."))
                        elif isinstance(qname, str):
                            lines.append(qname.rstrip("."))
                except Exception:
                    logger.debug("event=pcap_dns_skipped")
            try:
                raw = bytes(packet)
            except Exception:
                continue
            decoded = raw.decode("latin-1", "replace")
            lines.extend(match.group(0) for match in _PRINTABLE.finditer(decoded))
    finally:
        closer = getattr(reader, "close", None)
        if callable(closer):
            closer()
    return "\n".join(lines)


def _strip_html(text: str) -> str:
    return _TAG.sub(" ", text)


def _require(module_name: str, *, extra: str, package: str) -> object:
    try:
        return importlib.import_module(module_name)
    except ImportError as exc:
        raise OptionalDependencyError(
            f"{package} is required for this format. "
            f"Install it with: pip install 'qarbaal[{extra}]'"
        ) from exc
