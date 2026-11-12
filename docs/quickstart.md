# Quickstart

## Extract a report

Defanged text is understood. Dots written as `[.]`, `(dot)`, or ` dot ` become dots before the scan. `hxxps` becomes `https`.

```python
from qarbaal import extract

report = """
From: "IT Helpdesk" <support[at]corp-it-desk[.]com>
Lure URL: hxxps://login[.]corp-it-desk[.]com/session/verify?id=88231
Beacon: 185.220.101.42:443
Internal: 10.14.2.77
MD5: d41d8cd98f00b204e9800998ecf8427e
Unpatched: CVE-2024-21412 and T1566.001
"""

result = extract(report)
print(result.values("url"))
print(result.values("ip"))
print(result.get("ip")[1].tags)  # ('private',)
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
from qarbaal import IOCExtractor

extractor = IOCExtractor(
    extract_types=["ipv4", "domain", "url", "hash", "email", "cve"],
    hide_private=True,
    drop_invalid=True,
)
clean = extractor.extract(report, source="ticket-14")
```

`hash` means MD5, SHA-1, SHA-256, and SHA-512. `all` adds the opt-in types.

## Read a file and export

```python
from qarbaal import IOCExtractor
from qarbaal.export import to_json, to_stix

extractor = IOCExtractor()
result = extractor.extract_path("alert.eml")
open("iocs.json", "w", encoding="utf-8").write(to_json(result, detailed=True))
open("bundle.json", "w", encoding="utf-8").write(to_stix(result))
```

Several files become one correlated result. Indicators that appear in more than one file are `result.shared()`.

```python
merged = extractor.extract_many(
    [("monday", open("monday.txt", encoding="utf-8").read()),
     ("tuesday", open("tuesday.txt", encoding="utf-8").read())]
)
for indicator in merged.shared():
    print(indicator.value, indicator.sources, indicator.occurrences)
```

## Hide tagged addresses

IPv4 tags follow a fixed classifier: `private`, `loopback`, `link-local`, `cgnat`, `multicast`, and `reserved`. `hide_private=True` drops every tagged IPv4, IPv6, and CIDR indicator, not only RFC 1918.
