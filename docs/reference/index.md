# API reference

These pages are generated from the package docstrings.

| Module | Role |
| --- | --- |
| [Extractor](extractor.md) | `IOCExtractor`, `extract`, `merge` |
| [Types](types.md) | `Indicator`, `Extraction`, `IOCType` |
| [Refang](refang.md) | `refang`, `defang` |
| [Normalization](normalize.md) | `normalize_value` |
| [Validation](validate.md) | address classes and confidence |
| [Enrichment](enrich.md) | local enrichment fields |
| [Exports](export.md) | CSV, JSON, STIX, MISP, OpenIOC, rules |
| [Ingest](ingest.md) | file readers |
| [Exceptions](exceptions.md) | error types |

The public names are also exported from `qarbaal`:

```python
from qarbaal import IOCExtractor, IOCType, extract
```
