# File formats

`IOCExtractor.extract_path(path)` picks a reader from the suffix. `load_document(path)` returns the text plus page spans, without extracting.

Text, JSON, CSV, XML, EML, and MBOX use the standard library. The other readers are extras. If the extra is not installed, the call raises `OptionalDependencyError` and names the extra to install.

| Suffix | Reader | Extra |
| --- | --- | --- |
| `.txt`, `.log`, `.md`, `.text`, or none | The file as text. Large files are streamed. | none |
| `.json` | Parsed to confirm it is JSON, then sieved as the raw file so line numbers match the file. | none |
| `.csv` | Parsed to confirm it is CSV, then sieved as the raw file. | none |
| `.xml` | Parsed with `xml.etree`, then sieved as the raw file. | none |
| `.yaml`, `.yml` | Parsed with PyYAML, then sieved as the raw file. | `yaml` |
| `.eml` | Selected headers and the text and HTML bodies. | none |
| `.mbox` | The same, for every message. | none |
| `.html`, `.htm` | Visible text via Beautiful Soup. Script and style tags are dropped. | `html` |
| `.pdf` | Text per page. Each indicator's `page` is set. | `pdf` |
| `.docx` | Paragraphs and table cells. | `docx` |
| `.pcap`, `.pcapng` | DNS query names and printable strings from packet payloads. | `pcap` |

JSON, CSV, XML, and YAML are not walked as trees for extraction. Parsing them first rejects a file that is not well formed, and sieving the original text keeps `line` and `offset` aligned with what you open in an editor.

EML and MBOX decode `From`, `To`, `Cc`, `Reply-To`, `Return-Path`, and `Subject`, then `text/plain` parts and a lightly tag-stripped `text/html` part. HTML email does not require the `html` extra.

PCAP extraction is a string pass over payloads, capped at 20,000 packets. It is not a protocol decode. DNS names and URLs that appear as text are the indicators you should expect.

## Limits

`max_input_chars` defaults to 2,000,000. A larger file is truncated and `stats.truncated` is set. `strict_limits=True` raises `InputTooLargeError` instead of truncating.

```python
from qarbaal import IOCExtractor

IOCExtractor(max_input_chars=100_000, strict_limits=True).extract(huge)
```

Unknown suffixes raise `UnsupportedFormatError`.
