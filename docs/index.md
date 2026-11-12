# qarbaal

Extract, normalize, validate, and export indicators of compromise from text and files.

`qarbaal` is a local sieve. You give it a report, a log, an email, or a JSON export. It refangs defanged indicators, classifies them, and writes the formats analysts hand to other tools. Nothing is sent to an enrichment service. Pivot links are URLs you can open yourself.

Use it when a ticket, a hunt note, or a mailbox needs a first pass: pull the indicators out, drop the private addresses you do not want, and export the rest.

## Install

Python 3.10 or newer.

```console
pip install qarbaal
```

The base install has no runtime dependencies. HTML, PDF, Word, YAML, and packet-capture readers are optional extras. See [Installation](installation.md).

## A first call

```python
from qarbaal import extract

result = extract("Beacon 185.220[.]101.42 and hxxps://evil[.]example/a")
for indicator in result:
    print(indicator.type, indicator.value, indicator.line)
```

`result` is an `Extraction`. Iterate it, or call `result.values("ip")` and `result.get("domain")`.

The configurable processor is `IOCExtractor`. It selects types, turns normalization and validation on or off, and can merge several named sources.

```python
from qarbaal import IOCExtractor

extractor = IOCExtractor(
    extract_types=["ipv4", "ipv6", "domain", "url", "hash", "email", "cve"],
    normalize=True,
    validate=True,
    deduplicate=True,
)
result = extractor.extract(text, source="incident-42")
```

## Where to go next

- [Installation](installation.md) lists the extras.
- [Quickstart](quickstart.md) walks through a report, a file, and an export.
- [Indicator types](indicator-types.md) is the catalog, including which types are opt-in.
- [Defanging](defanging.md) covers the refang rules.
- [Normalization](normalization.md) explains original versus canonical values and fingerprints.
- [Validation](validation.md) is the structural checks and the confidence heuristic.
- [Enrichment](enrichment.md) is the local context attached to each indicator.
- [Provenance and correlation](provenance.md) covers line, offset, page, and shared indicators.
- [File formats](formats.md) lists the readers.
- [Exports](exports.md) covers CSV, JSON, STIX, MISP, OpenIOC, and rules.
- [Streaming](streaming.md) is for large text files.
- [Command line](cli.md) is the `qarbaal` command.
- [API reference](reference/index.md) is generated from the docstrings.
- [Changelog](changelog.md) records releases.

`qarbaal.__version__` matches `[project].version` in `pyproject.toml`.
