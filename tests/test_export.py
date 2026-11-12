from __future__ import annotations

import json
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from qarbaal import SAMPLE, extract, to_csv, to_defanged_list, to_json, to_jsonl, to_stix
from qarbaal.export import to_misp, to_openioc, to_snort, to_suricata

STAMP = datetime(2020, 1, 2, 3, 4, 5, 6000, tzinfo=timezone.utc)


def test_csv_is_quoted_bom_crlf() -> None:
    result = extract("8.8.8.8 10.0.0.1 evil.example")
    payload = to_csv(result)
    assert payload.startswith("\ufeff")
    assert "\r\n" in payload
    assert not payload.endswith("\r\n")
    rows = payload.removeprefix("\ufeff").split("\r\n")
    assert rows[0] == '"type","value","tags"'
    assert '"ip","8.8.8.8",""' in rows
    assert '"ip","10.0.0.1","private"' in rows
    hidden = to_csv(result, hide_private=True)
    assert "10.0.0.1" not in hidden
    detailed = to_csv(result, detailed=True)
    assert '"normalized"' in detailed.split("\r\n", 1)[0]
    assert '"fingerprint"' in detailed


def test_compact_and_detailed_json() -> None:
    result = extract(SAMPLE)
    payload = to_json(result, generated=STAMP)
    document = json.loads(payload)
    assert list(document) == ["tool", "generated", "iocs"]
    assert document["tool"] == "qarbaal"
    assert document["generated"] == "2020-01-02T03:04:05.006Z"
    assert document["iocs"]["ip"][0] == "185.220.101.42"
    assert document["iocs"]["cve"] == ["CVE-2024-21412", "CVE-2023-23397"]
    assert "path" not in document["iocs"]
    assert not payload.endswith("\n")
    detailed = json.loads(to_json(result, detailed=True, generated=STAMP))
    assert detailed["indicators"][0]["fingerprint"]
    assert "sightings" in detailed["indicators"][0]


def test_jsonl_and_defanged_list() -> None:
    result = extract("8.8.8.8 admin@corp.example https://evil.example/a")
    lines = [json.loads(line) for line in to_jsonl(result).splitlines()]
    assert [item["type"] for item in lines] == ["ip", "domain", "domain", "url", "email"]
    assert lines[0]["type"] == "ip"
    listed = to_defanged_list(result)
    assert listed.split("\n")[0] == "8[.]8[.]8[.]8"
    assert "admin[at]corp[.]example" in listed
    assert "hxxps://evil[.]example/a" in listed
    assert not listed.endswith("\n")


def test_stix_bundle_shape() -> None:
    result = extract(
        "8.8.8.8 10.0.0.1 evil.example https://evil.example/a "
        "d41d8cd98f00b204e9800998ecf8427e admin@corp.example "
        "CVE-2021-44228 "
        + "ab" * 32
        + " "
        + r"HKLM\Software\Foo AS13335 00:11:22:33:44:55 "
        + "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq T1105"
    )
    counter = {"n": 0}

    def mint(kind: str) -> str:
        counter["n"] += 1
        return f"{kind}--{uuid.UUID(int=counter['n'])}"

    bundle = json.loads(to_stix(result, generated=STAMP, id_factory=mint))
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    kinds = [item["type"] for item in bundle["objects"]]
    assert "vulnerability" in kinds
    assert "indicator" in kinds
    names = [item.get("name", "") for item in bundle["objects"]]
    assert not any(str(name).startswith("qarbaal wallet") for name in names)
    assert not any(str(name).startswith("qarbaal attack") for name in names)
    cve = next(item for item in bundle["objects"] if item["type"] == "vulnerability")
    assert cve["external_references"][0]["external_id"] == "CVE-2021-44228"
    assert cve["spec_version"] == "2.1"
    private = next(item for item in bundle["objects"] if item.get("name", "").endswith("10.0.0.1"))
    assert private["labels"] == ["qarbaal-extracted", "private"]
    assert private["pattern"] == "[ipv4-addr:value = '10.0.0.1']"
    registry = next(item for item in bundle["objects"] if "registry" in item.get("name", ""))
    assert r"HKLM\\Software\\Foo" in registry["pattern"]
    asn = next(item for item in bundle["objects"] if "asn" in item.get("name", ""))
    assert asn["pattern"] == "[autonomous-system:number = 13335]"
    for item in bundle["objects"]:
        if item["type"] == "indicator":
            uuid.UUID(item["id"].removeprefix("indicator--"))


def test_misp_openioc_and_rules() -> None:
    result = extract("8.8.8.8 evil.example d41d8cd98f00b204e9800998ecf8427e CVE-2024-21412")
    event = json.loads(to_misp(result, generated=STAMP))
    attributes = event["Event"]["Attribute"]
    ip = next(item for item in attributes if item["value"] == "8.8.8.8")
    assert ip["type"] == "ip-dst" and ip["to_ids"] is True
    cve = next(item for item in attributes if item["value"] == "CVE-2024-21412")
    assert cve["type"] == "vulnerability" and cve["to_ids"] is False
    root = ET.fromstring(to_openioc(result, generated=STAMP))
    assert root.tag.endswith("ioc")
    contents = [node.text for node in root.iter() if node.tag.endswith("Content")]
    assert "8.8.8.8" in contents
    suricata = to_suricata(result)
    snort = to_snort(result)
    assert "alert ip any any -> 8.8.8.8 any" in suricata
    assert "dns.query" in suricata
    assert "d41d8cd98f00b204e9800998ecf8427e" not in suricata
    assert "CVE-2024-21412" not in suricata
    assert "alert udp any any -> any 53" in snort
    assert "d41d8cd98f00b204e9800998ecf8427e" not in snort
    assert to_suricata(extract("just words")).startswith("# qarbaal:")
