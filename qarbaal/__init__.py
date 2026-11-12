"""Extract, normalize, and export indicators of compromise.

``qarbaal`` reads text and common file formats locally. It does not call a
network service. Pivot URLs are built for the analyst to open.
"""

from __future__ import annotations

from qarbaal.exceptions import (
    InputTooLargeError,
    OptionalDependencyError,
    ParseError,
    QarbaalError,
    UnsupportedFormatError,
)
from qarbaal.export import (
    to_csv,
    to_defanged_list,
    to_json,
    to_jsonl,
    to_misp,
    to_openioc,
    to_snort,
    to_stix,
    to_suricata,
)
from qarbaal.extract import IOCExtractor, extract, merge
from qarbaal.ingest import LoadedDocument, load_document
from qarbaal.normalize import normalize_value
from qarbaal.patterns import PatternSpec
from qarbaal.refang import defang, refang
from qarbaal.sample import SAMPLE
from qarbaal.types import (
    Enrichment,
    Extraction,
    ExtractionStats,
    Indicator,
    IOCType,
    Sighting,
)
from qarbaal.validate import ipv4_class
from qarbaal.version import __version__

__all__ = [
    "SAMPLE",
    "Enrichment",
    "Extraction",
    "ExtractionStats",
    "IOCExtractor",
    "IOCType",
    "Indicator",
    "InputTooLargeError",
    "LoadedDocument",
    "OptionalDependencyError",
    "ParseError",
    "PatternSpec",
    "QarbaalError",
    "Sighting",
    "UnsupportedFormatError",
    "__version__",
    "defang",
    "extract",
    "ipv4_class",
    "load_document",
    "merge",
    "normalize_value",
    "refang",
    "to_csv",
    "to_defanged_list",
    "to_json",
    "to_jsonl",
    "to_misp",
    "to_openioc",
    "to_snort",
    "to_stix",
    "to_suricata",
]
