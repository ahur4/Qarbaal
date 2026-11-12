# Quickstart

## Extract a report

Defanged text is understood. Dots written as `[.]`, `(dot)`, or ` dot ` become dots before the scan. `hxxps` becomes `https`.

```python
from qarbaal import IOCType, extract

report = """
From: "IT Helpdesk" <support[at]corp-it-desk[.]com>
Lure URL: hxxps://login[.]corp-it-desk[.]com/session/verify?id=88231
Beacon: 185.220.101.42:443
Internal: 10.14.2.77
MD5: d41d8cd98f00b204e9800998ecf8427e
Unpatched: CVE-2024-21412 and T1566.001
"""

result = extract(report)
print(result.values(IOCType.URL))
print(result.values(IOCType.IPV4))
print(result.get(IOCType.IPV4)[1].tags)  # ('private',)
```

`SAMPLE` is a longer synthetic incident in the same style.

```python
from qarbaal import SAMPLE, extract

result = extract(SAMPLE)
print(result.stats.counts)
```

## Choose types

The default set is the high-precision types. Paths, mutexes, and User-Agent strings are opt-in because they are noisy in ordinary prose.

```python
from qarbaal import IOCExtractor, IOCType

extractor = IOCExtractor(
    extract_types=[
        IOCType.IPV4,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.EMAIL,
        IOCType.CVE,
    ],
    hide_private=True,
    drop_invalid=True,
)
clean = extractor.extract(report, source="ticket-14")
```

`extract_types` takes `IOCType` members. `"hash"` selects MD5, SHA-1, SHA-256, and SHA-512. `"all"` selects every type, including the opt-in ones.

## Read a file and export

```python
from qarbaal import IOCExtractor
from qarbaal.export import to_json, to_stix

extractor = IOCExtractor()
result = extractor.extract_path("alert.eml")
to_json(result, detailed=True, path="out", filename="iocs.json")
written = to_stix(result, path="out", filename="bundle.stix.json")
print(written.path, written.size)
```

Several named sources become one correlated result. `extract_many` accepts a mapping or `(name, text)` pairs. Indicators that appear in more than one source are `result.shared()`. The same calls, including streaming, custom patterns, and exports, are in [Using qarbaal in Python](python.md).

```python
merged = extractor.extract_many(
    [
        ("monday", open("monday.txt", encoding="utf-8").read()),
        ("tuesday", open("tuesday.txt", encoding="utf-8").read()),
    ]
)
for indicator in merged.shared():
    print(indicator.value, indicator.sources, indicator.occurrences)
```

## Hide tagged addresses

IPv4 tags follow a fixed classifier: `private`, `loopback`, `link-local`, `cgnat`, `multicast`, and `reserved`. `hide_private=True` drops every tagged IPv4, IPv6, and CIDR indicator, not only RFC 1918.
