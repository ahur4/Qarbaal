# qarbaal

Extract, normalize, validate, and export indicators of compromise from text and files.

`qarbaal` is a local sieve. You give it a report, a log, an email, or a JSON export. It refangs defanged indicators, classifies them, and writes the formats analysts hand to other tools. Nothing is sent to an enrichment service. Pivot links are URLs you can open yourself.

Use it when a ticket, a hunt note, or a mailbox needs a first pass: pull the indicators out, drop the private addresses you do not want, and export the rest.

## Install

Python 3.10 or newer.

```console
pip install qarbaal
```

The base install depends on pydantic. HTML, PDF, Word, YAML, and packet-capture readers are optional extras. See [Installation](installation.md).

## A first call

```python
from qarbaal import IOCType, extract

result = extract("Beacon 185.220[.]101.42 and hxxps://evil[.]example/a")
for indicator in result:
    print(indicator.type, indicator.value, indicator.line)
```

`result` is a pydantic `Extraction`. Iterate it, or call `result.values(IOCType.IPV4)` and `result.get(IOCType.DOMAIN)`.

The configurable processor is `IOCExtractor`. It selects types, turns normalization and validation on or off, and can merge several named sources.

```python
from qarbaal import IOCExtractor, IOCType

text = "Beacon 8.8.8.8 and https://evil.example/a"
extractor = IOCExtractor(
    extract_types=[
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.EMAIL,
        IOCType.CVE,
    ],
    normalize=True,
    validate=True,
    deduplicate=True,
)
result = extractor.extract(text, source="incident-42")
```

## Where to go next

- [Installation](installation.md) lists the extras.
- [Quickstart](quickstart.md) walks through a report, a file, and an export.
- [Using qarbaal in Python](python.md) is the library API: indicators, configuration, enrichment, correlation, streaming, custom patterns, files, and exports.
- [Indicator types](indicator-types.md) is the catalog, including which types are opt-in.
- [Defanging](defanging.md) covers the refang rules.
- [Normalization](normalization.md) explains original versus canonical values and fingerprints.
- [Validation](validation.md) is the structural checks and the confidence heuristic.
- [Enrichment](enrichment.md) is the local context attached to each indicator.
- [Provenance and correlation](provenance.md) covers line, offset, page, and shared indicators.
- [File formats](formats.md) lists the readers.
- [Exports](exports.md) covers CSV, JSON, STIX, MISP, OpenIOC, and rules.
- [Streaming](streaming.md) is for large text files.
- [API reference](reference/index.md) is generated from the docstrings.
- [Changelog](changelog.md) records releases.

`qarbaal.__version__` matches `[project].version` in `pyproject.toml`.
