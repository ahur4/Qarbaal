# Using qarbaal in Python

These calls use the public API. Pass `IOCType` members such as `IOCType.IPV4` and `IOCType.URL`. `extract` returns a pydantic `Extraction`, and each indicator is a pydantic model. Nothing in this page contacts a network service.

## Quick extraction

`extract` uses the default type set. Paths, mutex names, and User-Agent strings stay out until you ask for them.

```python
from qarbaal import IOCType, extract

text = "Beacon 185.220.101.42 and hxxps://login[.]evil[.]example/a"
result = extract(text)

for indicator in result.indicators:
    print(indicator.type, indicator.value)
    print(indicator.raw, indicator.normalized)
    print(indicator.confidence, indicator.fingerprint)
    print(indicator.sources, indicator.occurrences, indicator.valid)
    print(indicator.validation_notes)
    for sighting in indicator.sightings:
        print(
            sighting.source,
            sighting.line,
            sighting.offset,
            sighting.end_offset,
            sighting.page,
        )
    print(indicator.enrichment)

ips = result.get(IOCType.IPV4)
print(result.values(IOCType.IPV4))
print(
    result.stats.counts,
    result.stats.total,
    result.stats.sightings,
    result.stats.input_characters,
)
```

`result` is an `Extraction`. `result.indicators` is the deduplicated tuple in export order. Iterating `result` walks that same tuple.

`result.get(IOCType.IPV4)` returns the indicators of one type. `result.values(IOCType.IPV4)` returns their sieve strings. `indicator.type` is an `IOCType` member. `result.stats` is an `ExtractionStats`: `counts` (unique indicators per type), `total`, `sightings`, and `input_characters`, plus `truncated`, `match_limit_hit`, and `sources`. Call `model_dump()` when you want a dictionary.

Each `Indicator` keeps `type`, `value` (first-seen sieve form), `raw` (the original slice, which may still be defanged), and `normalized`. `fingerprint` is the SHA-256 hex digest of the type and the normalized value. `sources` is the distinct source labels. `occurrences` is the number of sightings. Each `Sighting` has `source`, `line`, `offset`, `end_offset`, and `page` (`None` when the file has no pages). `valid` is `True`, `False`, or `None` when validation was skipped. `validation_notes` lists reason codes.

## Configured extractor

```python
from qarbaal import IOCExtractor

text = "Beacon 185.220.101.42 and https://login.evil.example/a and 10.1.1.1"
extractor = IOCExtractor(
    normalize=True,
    validate=True,
    deduplicate=True,
    hide_private=True,
    drop_invalid=False,
    allow=["185.220.*", "*.example"],
    deny=["10.*"],
)
result = extractor.extract(text, source="ticket-14")
```

`normalize` keeps a canonical value and applies NFKC before the scan. `validate` records structural checks and the confidence heuristic. `deduplicate` merges indicators that share a fingerprint. `hide_private` drops tagged IPv4, IPv6, and CIDR indicators. `drop_invalid` drops indicators whose `valid` is `False`.

`allow` and `deny` are globs, compared case-insensitively to `value`, `normalized`, and `raw`. When `allow` is set, a value must match one pattern. A `deny` match always drops the indicator. `source` is the label stored on every sighting.

## Enrichment

Enrichment is computed locally. `as_dict()` omits empty fields.

```python
from qarbaal import IOCType, extract

ip = extract("8.8.8.8").get(IOCType.IPV4)[0]
print(ip.enrichment.as_dict())

url = extract("https://login.evil.example/a").get(IOCType.URL)[0]
print(url.enrichment.as_dict())

domain = extract("login.evil.example").get(IOCType.DOMAIN)[0]
print(domain.enrichment.as_dict())
```

An IP dictionary includes `ip_version`, `is_private`, `is_global`, `is_multicast`, `is_reserved`, `is_loopback`, `is_link_local`, and `is_cgnat`. A domain dictionary includes `tld`, `registered_domain`, and `subdomain`. A URL dictionary adds `scheme`, `port`, `path`, and `host`. The registered-domain split is a best-effort heuristic, not a Public Suffix List.

## Cross-source correlation

`extract_many` accepts a mapping or a sequence of `(name, text)` pairs. Indicators seen in two or more sources are `shared()`. `occurrences` counts every sighting.

```python
from qarbaal import IOCExtractor, merge

extractor = IOCExtractor()
correlated = extractor.extract_many(
    {
        "feedA": "C2 185.220.101.42",
        "feedB": "also 185.220.101.42 and 1.2.3.4",
    }
)
for indicator in correlated.shared():
    print(indicator.value, indicator.occurrences, indicator.sources)

res1 = extractor.extract("C2 185.220.101.42", source="feedA")
res2 = extractor.extract("also 185.220.101.42 and 1.2.3.4", source="feedB")
merged = merge([res1, res2])
```

`merge` combines `Extraction` objects that were produced separately. The first sieve value wins. Use `extract_many` when you still have the text.

## Streaming large inputs

`extract_iter` reads an iterable of strings and keeps only an overlap window between chunks, so a large file does not have to sit in memory as one string. Offsets and line numbers are counted from the start of the stream.

```python
from qarbaal import IOCExtractor


def chunks():
    yield "first 185.220.101.42\n"
    yield "second 1.1.1.1\n"


extractor = IOCExtractor()
streamed = extractor.extract_iter(chunks(), source="huge.log")
```

Plain-text `extract_path` uses this path. Keep `chunk_overlap` at least as long as the longest token you care about. The default is 8192.

## Custom indicator types

`PatternSpec` adds a pattern for an existing `IOCType`. Group 1 is the value when the expression has a group. Otherwise the whole match is the value. `folds` is `lower`, `upper`, or `preserve`. The type's own checks still apply. A mutex pattern is included below because mutexes are opt-in, and this pattern enables that type.

A validator receives the indicator and returns `False` to mark it invalid. Validation must be on, which is the default. The note is `rejected-by:` plus the function name. `drop_invalid=True` then leaves that indicator out of the result.

```python
from qarbaal import IOCExtractor, IOCType, PatternSpec


def public_only(indicator):
    return not indicator.tags


extractor = IOCExtractor(
    custom_patterns=[
        PatternSpec(type=IOCType.MUTEX, regex=r"mutex\{([^}]+)\}"),
    ],
    validators=[public_only],
)
result = extractor.extract("saw mutex{WinDefend} and 10.0.0.1")
print(result.values(IOCType.MUTEX))
```

## Files

`load_document` turns a file into text and, for PDF, page spans. `extract_path` loads and extracts in one call. The source label is the path.

```python
from qarbaal import IOCExtractor, load_document

document = load_document("notes.json")
result = IOCExtractor().extract(
    document.text,
    source=document.source,
    pages=document.pages,
)

same = IOCExtractor().extract_path("notes.txt")
```

Text, JSON, CSV, XML, EML, and MBOX need no extra. HTML, PDF, DOCX, YAML, and PCAP need the matching extra. A missing extra raises `OptionalDependencyError` with the install command.

## Exports

Each exporter takes an `Extraction` and returns text. Live values are kept, except `to_defanged_list`, which rewrites them for a report.

```python
from qarbaal import (
    extract,
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

result = extract("8.8.8.8 https://evil.example/a")
print(to_defanged_list(result))
print(to_stix(result))
```

`to_csv`, `to_json`, `to_jsonl`, `to_misp`, `to_openioc`, `to_suricata`, and `to_snort` take the same extraction. Suricata and Snort rules are emitted only for addresses, CIDR ranges, domains, and URLs.

## Pydantic

`Extraction`, `Indicator`, `Sighting`, `Enrichment`, and `ExtractionStats` are pydantic models. `indicator.type` is an `IOCType` member. `model_dump()` and `model_dump(mode="json")` serialize them. `model_dump(mode="json")` writes the type as its short key, such as `"ip"`.
