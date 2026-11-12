# Provenance and correlation

Every indicator records where it was found. The fields on the indicator itself describe the first sighting. Later copies live in `indicator.sightings`.

| Field | Meaning |
| --- | --- |
| `source` | The label you passed, or the file name. |
| `line` | 1-based line of the original text. |
| `offset` | 0-based character index of `raw` in the original text. |
| `end_offset` | Index just past `raw`. |
| `page` | 1-based page for PDF. `None` for other formats. |
| `occurrences` | How many sightings survived deduplication. |
| `sources` | Distinct source labels, first-seen order. |

```python
from qarbaal import extract

text = "line one\n91.92.240[.]119\n"
indicator = extract(text, source="note.txt").get("ip")[0]
indicator.line        # 2
indicator.offset      # index of '91.92.240[.]119'
indicator.raw         # '91.92.240[.]119'
indicator.source      # 'note.txt'
```

Offsets refer to the text you passed in, before refang and before NFKC. A domain copied out of a URL is attributed to the host inside the URL, not to the whole URL. If the same host is written again later and the slices differ, both sightings are kept and `occurrences` is 2. If two passes land on the exact same slice, they count once.

## Several sources

`extract_many` labels each input and merges by fingerprint.

```python
from qarbaal import IOCExtractor

extractor = IOCExtractor()
result = extractor.extract_many(
    [
        ("report-a", "C2 185.220.101.42"),
        ("report-b", "also 185.220.101.42"),
    ]
)
shared = result.shared()
shared[0].sources       # ('report-a', 'report-b')
shared[0].occurrences   # 2
```

`shared()` returns indicators whose sightings come from at least two different source labels. Repeating an indicator inside one file raises `occurrences` and does not mark it shared.

`merge()` combines two `Extraction` objects the same way. The first sieve value wins. Input character counts are added. Truncation flags are combined with or.

## Statistics

`result.stats` reports:

- `counts` — unique indicators per type, in display order
- `total` — unique indicators
- `sightings` — all occurrences
- `input_characters` — characters examined, after any truncation
- `truncated` — an input hit `max_input_chars`
- `match_limit_hit` — a type hit `max_matches_per_type`
- `sources` — labels seen
