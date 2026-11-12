# qarbaal

Extract, normalize, validate, and export indicators of compromise from text and files.

[![Python 3.10–3.13](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776AB)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/github/license/ahur4/Qarbaal)](https://github.com/ahur4/Qarbaal/blob/main/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/ahur4/Qarbaal/ci.yml?branch=main&label=CI)](https://github.com/ahur4/Qarbaal/actions/workflows/ci.yml)
[![Documentation](https://img.shields.io/badge/docs-mkdocs-0A7AAA)](https://ahur4.github.io/Qarbaal/)

**Documentation:** <https://ahur4.github.io/Qarbaal/>

`qarbaal` reads reports, logs, and message files on your machine and returns classified indicators. It refangs defanged text, records where each value came from, and writes CSV, JSON, STIX 2.1, MISP, OpenIOC, and network rules. The base install uses only the Python standard library. It does not call an enrichment API.

## Installation

Python 3.10 or newer.

```console
pip install qarbaal
```

That install has no runtime dependencies. Optional readers are separate extras:

```console
pip install "qarbaal[html]"    # HTML
pip install "qarbaal[pdf]"     # PDF
pip install "qarbaal[docx]"    # Word
pip install "qarbaal[yaml]"    # YAML
pip install "qarbaal[pcap]"    # packet captures
pip install "qarbaal[pydantic]"
pip install "qarbaal[all]"
```

## Quickstart

```python
from qarbaal import IOCExtractor, extract

report = """
From: support[at]corp-it-desk[.]com
Lure: hxxps://login[.]corp-it-desk[.]com/session
Beacon: 185.220.101.42
MD5: d41d8cd98f00b204e9800998ecf8427e
"""

result = extract(report)
for indicator in result:
    print(indicator.type, indicator.value, indicator.tags, indicator.line)

extractor = IOCExtractor(
    extract_types=["ipv4", "domain", "url", "hash", "email"],
    normalize=True,
    validate=True,
    deduplicate=True,
)
same = extractor.extract(report, source="ticket-14")
```

`extract()` uses the default type set. File paths, mutex names, and User-Agent strings stay out of that set until you ask for them with `extract_types` or `"all"`.

A synthetic incident is included:

```python
from qarbaal import SAMPLE, extract

print(extract(SAMPLE).stats.counts)
```

## What you get back

Each indicator keeps three strings:

| Field | Meaning |
| --- | --- |
| `value` | First-seen sieve form. Hashes are lower case, CVE IDs are upper case. |
| `raw` | Exact slice of the source, which may still be defanged. |
| `normalized` | Canonical form used for the fingerprint. |

It also carries noise tags, a validation result, a confidence heuristic, local enrichment, pivot links, and one sighting per occurrence (source, line, offset, and page when the file has pages).

## Command line

```console
qarbaal report.txt
qarbaal mail.eml notes.json -f stix -o bundle.json
qarbaal --hide-private --defang -f table alerts.log
qarbaal --types all -f suricata capture.txt
```

With no file, `qarbaal` reads stdin. Formats: `table`, `csv`, `json`, `jsonl`, `stix`, `list`, `misp`, `openioc`, `suricata`, `snort`.

## Further reading

- [Installation](https://ahur4.github.io/Qarbaal/installation/)
- [Indicator types](https://ahur4.github.io/Qarbaal/indicator-types/)
- [Defanging](https://ahur4.github.io/Qarbaal/defanging/)
- [Normalization](https://ahur4.github.io/Qarbaal/normalization/)
- [Exports](https://ahur4.github.io/Qarbaal/exports/)
- [Command line](https://ahur4.github.io/Qarbaal/cli/)
- [API reference](https://ahur4.github.io/Qarbaal/reference/)
- [Changelog](https://ahur4.github.io/Qarbaal/changelog/)
