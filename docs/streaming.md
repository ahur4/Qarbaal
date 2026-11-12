# Streaming

`extract_iter` scans text in windows so a large file does not have to become one string of matches. `extract_path` uses it for `.txt`, `.log`, `.md`, `.text`, and files with no suffix. Other formats are parsed first, then extracted.

```python
from qarbaal import IOCExtractor

extractor = IOCExtractor()
with open("huge.log", encoding="utf-8") as handle:
    result = extractor.extract_iter(handle, source="huge.log")
```

The reader yields strings. They are concatenated until `chunk_size` (default 1,048,576 characters) and then scanned with `chunk_overlap` (default 8,192) characters kept for the next window. A match that crosses the cut is held back and finished in the next window, so line numbers and offsets stay aligned with the original stream.

The overlap should be at least as long as the longest token you care about. The default token cap used by the sieve is 4,096 characters. A shorter overlap logs a warning on `qarbaal.extract`. A single token longer than the overlap can be split and missed.

`max_matches_per_type` (default 20,000) caps how many raw matches of one type are kept. `stats.match_limit_hit` is then true. `max_input_chars` still applies to the stream.

Batch extraction of already-loaded strings is `extract_many`. It does not stream, and it does correlate.
