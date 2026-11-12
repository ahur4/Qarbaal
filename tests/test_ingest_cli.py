from __future__ import annotations

import json
from email.message import EmailMessage

import pytest

from qarbaal.cli import main
from qarbaal.exceptions import OptionalDependencyError, ParseError, UnsupportedFormatError
from qarbaal.extract import IOCExtractor
from qarbaal.ingest import load_document


def test_stdlib_formats(tmp_path) -> None:
    json_path = tmp_path / "note.json"
    json_path.write_text(json.dumps({"host": "evil.example", "ip": "8.8.8.8"}), encoding="utf-8")
    csv_path = tmp_path / "rows.csv"
    csv_path.write_text("kind,value\nip,1.1.1.1\n", encoding="utf-8")
    xml_path = tmp_path / "note.xml"
    xml_path.write_text("<root><ioc>cdn.example</ioc></root>", encoding="utf-8")
    text_path = tmp_path / "notes.txt"
    text_path.write_text("see 9.9.9.9\n", encoding="utf-8")
    extractor = IOCExtractor()
    assert "evil.example" in extractor.extract_path(json_path).values("domain")
    assert "8.8.8.8" in extractor.extract_path(json_path).values("ip")
    assert "1.1.1.1" in extractor.extract_path(csv_path).values("ip")
    assert "cdn.example" in extractor.extract_path(xml_path).values("domain")
    streamed = extractor.extract_path(text_path)
    indicator = streamed.get("ip")[0]
    assert indicator.value == "9.9.9.9"
    assert indicator.line == 1
    assert indicator.offset == text_path.read_text(encoding="utf-8").index("9.9.9.9")


def test_eml_and_mbox(tmp_path) -> None:
    message = EmailMessage()
    message["From"] = "analyst@corp.example"
    message["Subject"] = "invoice"
    message.set_content("beacon 203.0.113.5\n")
    eml = tmp_path / "mail.eml"
    eml.write_bytes(message.as_bytes())
    found = IOCExtractor().extract_path(eml)
    assert "analyst@corp.example" in found.values("email")
    assert "203.0.113.5" in found.values("ip")

    mbox = tmp_path / "mail.mbox"
    mbox.write_text(
        "From user@localhost Mon Nov 10 00:00:00 2026\n"
        "From: other@corp.example\n"
        "Subject: hi\n"
        "\n"
        "host 198.51.100.7\n",
        encoding="utf-8",
    )
    mailbox_result = IOCExtractor().extract_path(mbox)
    assert "198.51.100.7" in mailbox_result.values("ip")
    assert "other@corp.example" in mailbox_result.values("email")


def test_bad_json_and_unknown_suffix(tmp_path) -> None:
    broken = tmp_path / "bad.json"
    broken.write_text("{", encoding="utf-8")
    with pytest.raises(ParseError):
        load_document(broken)
    unknown = tmp_path / "notes.bin"
    unknown.write_text("8.8.8.8", encoding="utf-8")
    with pytest.raises(UnsupportedFormatError):
        load_document(unknown)


def test_optional_parser_error_without_the_extra(tmp_path, monkeypatch) -> None:
    page = tmp_path / "page.html"
    page.write_text("<p>8.8.8.8</p>", encoding="utf-8")

    def missing(name: str) -> object:
        raise ImportError(name)

    monkeypatch.setattr("qarbaal.ingest.importlib.import_module", missing)
    with pytest.raises(OptionalDependencyError) as caught:
        load_document(page)
    assert "qarbaal[html]" in str(caught.value)


def test_html_pdf_docx_yaml_when_installed(tmp_path) -> None:
    yaml = pytest.importorskip("yaml")
    del yaml
    yaml_path = tmp_path / "ind.yaml"
    yaml_path.write_text("host: yaml.example\n", encoding="utf-8")
    assert "yaml.example" in IOCExtractor().extract_path(yaml_path).values("domain")

    bs4 = pytest.importorskip("bs4")
    del bs4
    html = tmp_path / "page.html"
    html.write_text("<html><body>contact admin@corp.example</body></html>", encoding="utf-8")
    assert "admin@corp.example" in IOCExtractor().extract_path(html).values("email")

    docx = pytest.importorskip("docx")
    document = docx.Document()
    document.add_paragraph("server 203.0.113.9")
    docx_path = tmp_path / "note.docx"
    document.save(docx_path)
    assert "203.0.113.9" in IOCExtractor().extract_path(docx_path).values("ip")


def test_pdf_when_installed(tmp_path) -> None:
    fitz = pytest.importorskip("fitz")
    pdf = fitz.open()
    page = pdf.new_page()
    page.insert_text((72, 72), "indicator 198.51.100.20")
    pdf_path = tmp_path / "note.pdf"
    pdf.save(pdf_path)
    pdf.close()
    found = IOCExtractor().extract_path(pdf_path)
    assert "198.51.100.20" in found.values("ip")
    assert found.get("ip")[0].page == 1


def test_cli_file_and_stdin(tmp_path, capsys, monkeypatch) -> None:
    path = tmp_path / "in.txt"
    path.write_text("8.8.8.8\n", encoding="utf-8")
    assert main([str(path), "-f", "json", "--compact"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["iocs"]["ip"] == ["8.8.8.8"]
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("1.2.3.4\n"))
    assert main(["-f", "list"]) == 0
    assert capsys.readouterr().out.strip() == "1[.]2[.]3[.]4"
    assert main([str(tmp_path / "missing.txt")]) == 2
    assert "qarbaal:" in capsys.readouterr().err


def test_cli_hides_private_and_defangs(tmp_path, capsys) -> None:
    path = tmp_path / "in.txt"
    path.write_text("10.0.0.1 8.8.8.8\n", encoding="utf-8")
    assert main([str(path), "--hide-private", "--defang"]) == 0
    output = capsys.readouterr().out
    assert "8[.]8[.]8[.]8" in output
    assert "10[.]0[.]0[.]1" not in output


def test_limits_and_stats() -> None:
    from qarbaal.exceptions import InputTooLargeError

    short = IOCExtractor(max_input_chars=7).extract("1.2.3.4 extra")
    assert short.truncated is True
    assert short.values("ip") == ("1.2.3.4",)
    with pytest.raises(InputTooLargeError):
        IOCExtractor(max_input_chars=4, strict_limits=True).extract("8.8.8.8")
    capped = IOCExtractor(max_matches_per_type=1).extract("8.8.8.8 1.1.1.1")
    assert capped.values("ip") == ("8.8.8.8",)
    assert capped.stats.match_limit_hit is True
    assert capped.stats.counts["ip"] == 1


def test_pydantic_adapter_when_installed() -> None:
    pytest.importorskip("pydantic")
    from qarbaal.adapters import to_pydantic

    model = to_pydantic(IOCExtractor().extract("8.8.8.8").get("ip")[0])
    assert model.value == "8.8.8.8"
    assert model.type == "ip"
    assert model.fingerprint
