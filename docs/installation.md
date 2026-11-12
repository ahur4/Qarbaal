# Installation

Python 3.10 or newer. The base package has no runtime dependencies.

```console
pip install qarbaal
```

## Optional extras

Text, JSON, CSV, XML, EML, and MBOX need no extra. Install a reader only for the formats you use. A missing extra raises `OptionalDependencyError` with the install command. It does not affect text extraction.

One extra, several at once, or all of them:

```console
pip install "qarbaal[html]"
pip install "qarbaal[html,pdf,docx]"
pip install "qarbaal[all]"
```

| Input | Extra | Package |
| --- | --- | --- |
| Text, JSON, CSV, XML, EML, MBOX | none | standard library |
| HTML (`.html`, `.htm`) | `html` | beautifulsoup4 |
| PDF (`.pdf`, including page numbers) | `pdf` | pymupdf |
| DOCX (`.docx`) | `docx` | python-docx |
| YAML (`.yaml`, `.yml`) | `yaml` | pyyaml |
| PCAP (`.pcap`, `.pcapng`) | `pcap` | scapy |

`docs` installs MkDocs Material and mkdocstrings. `dev` installs pytest, mypy, and ruff.

### Pydantic models

```console
pip install "qarbaal[pydantic]"
```

`qarbaal.adapters.to_pydantic(indicator)` and `extraction_to_pydantic(result)` return a pydantic `BaseModel` named `QarbaalIndicator`. Use it when an app or API already validates and serializes with pydantic. Core results stay plain dataclasses, so the base install keeps zero runtime dependencies. Calling either function without pydantic raises `OptionalDependencyError` with the install hint.

```python
from qarbaal.adapters import extraction_to_pydantic, to_pydantic
```

## From a checkout

```console
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy --strict qarbaal
pytest
```

To preview this site:

```console
pip install -e ".[docs]"
mkdocs serve
```

The published site is <https://ahur4.github.io/Qarbaal/>.
