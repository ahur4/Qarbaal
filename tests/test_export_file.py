from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import pytest

from qarbaal import ExportFile, extract, to_csv, to_defanged_list, to_json, to_jsonl, to_stix
from qarbaal.export import to_misp, to_openioc, to_snort, to_suricata

TEXT = "8.8.8.8 evil.example"
STAMP = datetime(2020, 1, 2, 3, 4, 5, 6000, tzinfo=timezone.utc)


def _mint(kind: str) -> str:
    return f"{kind}--{uuid.UUID(int=1)}"


def test_each_format_writes_default_name(tmp_path: Path) -> None:
    result = extract(TEXT)
    memory = {
        "csv": to_csv(result),
        "json": to_json(result, generated=STAMP),
        "jsonl": to_jsonl(result),
        "defanged": to_defanged_list(result),
        "stix": to_stix(result, generated=STAMP, id_factory=_mint),
        "misp": to_misp(result, generated=STAMP),
        "openioc": to_openioc(result, generated=STAMP, id_factory=_mint),
        "suricata": to_suricata(result),
        "snort": to_snort(result),
    }
    writers: dict[str, Callable[[], ExportFile]] = {
        "csv": lambda: to_csv(result, path=tmp_path),
        "json": lambda: to_json(result, path=tmp_path, generated=STAMP),
        "jsonl": lambda: to_jsonl(result, path=tmp_path),
        "defanged": lambda: to_defanged_list(result, path=tmp_path),
        "stix": lambda: to_stix(result, path=tmp_path, generated=STAMP, id_factory=_mint),
        "misp": lambda: to_misp(result, path=tmp_path, generated=STAMP),
        "openioc": lambda: to_openioc(result, path=tmp_path, generated=STAMP, id_factory=_mint),
        "suricata": lambda: to_suricata(result, path=tmp_path),
        "snort": lambda: to_snort(result, path=tmp_path),
    }
    names = {
        "csv": "qarbaal.csv",
        "json": "qarbaal.json",
        "jsonl": "qarbaal.jsonl",
        "defanged": "qarbaal.defanged.txt",
        "stix": "qarbaal.stix.json",
        "misp": "qarbaal.misp.json",
        "openioc": "qarbaal.openioc.xml",
        "suricata": "qarbaal.suricata.rules",
        "snort": "qarbaal.snort.rules",
    }
    for format_name, write in writers.items():
        info = write()
        destination = tmp_path / names[format_name]
        payload = destination.read_bytes()
        assert isinstance(info, ExportFile)
        assert info.format == format_name
        assert info.filename == names[format_name]
        assert info.path == str(destination.resolve())
        assert Path(info.path).is_absolute()
        assert info.size == len(payload) == destination.stat().st_size
        assert info.sha256 == hashlib.sha256(payload).hexdigest()
        assert payload.decode("utf-8") == memory[format_name]
        assert info.count == 2
        dumped = info.model_dump()
        assert set(dumped) == {"path", "filename", "size", "format", "count", "sha256"}


def test_custom_filename_creates_directory(tmp_path: Path) -> None:
    result = extract(TEXT)
    nested = tmp_path / "reports" / "day"
    info = to_json(result, path=nested, filename="indicators.json", generated=STAMP)
    destination = nested / "indicators.json"
    assert nested.is_dir()
    assert info.filename == "indicators.json"
    assert info.path == str(destination.resolve())
    assert destination.read_text(encoding="utf-8") == to_json(result, generated=STAMP)
    assert info.size == destination.stat().st_size
    assert info.count == 2


def test_filename_alone_uses_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = extract(TEXT)
    info = to_csv(result, filename="named.csv")
    destination = tmp_path / "named.csv"
    assert info.path == str(destination.resolve())
    assert info.filename == "named.csv"
    assert destination.read_bytes().decode("utf-8") == to_csv(result)
    assert info.size == destination.stat().st_size


def test_omitting_destination_returns_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = extract(TEXT)
    payload = to_json(result)
    assert isinstance(payload, str)
    assert payload.startswith("{")
    assert list(tmp_path.iterdir()) == []


def test_rule_file_counts_emitted_rules(tmp_path: Path) -> None:
    empty = to_suricata(extract("CVE-2024-21412 just words"), path=tmp_path)
    assert empty.count == 0
    assert empty.format == "suricata"
    text = (tmp_path / "qarbaal.suricata.rules").read_text(encoding="utf-8")
    assert text.startswith("# qarbaal:")
    assert empty.size == len(text.encode("utf-8"))

    rules = to_snort(extract(TEXT), path=tmp_path, filename="local.rules")
    body = (tmp_path / "local.rules").read_text(encoding="utf-8")
    assert rules.count == 2
    assert body.count("sid:") == 2
    assert rules.sha256 == hashlib.sha256(body.encode("utf-8")).hexdigest()


def test_stix_count_is_bundle_objects(tmp_path: Path) -> None:
    result = extract("CVE-2024-21412 bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
    info = to_stix(result, path=tmp_path, filename="bundle.stix.json")
    assert info.count == 1
    assert info.filename == "bundle.stix.json"


def test_filename_must_not_be_a_path(tmp_path: Path) -> None:
    result = extract(TEXT)
    for name in ("nested/nope.csv", r"nested\nope.csv", "", ".", "..", " padded.csv"):
        with pytest.raises(ValueError):
            to_csv(result, path=tmp_path, filename=name)
    assert list(tmp_path.iterdir()) == []
