# Installation

Python 3.10 or newer. The base package has no runtime dependencies.

```console
pip install qarbaal
```

## Optional extras

Install an extra only for the formats you read. A missing extra raises `OptionalDependencyError` with the install command. It does not affect text extraction.

| Extra | Packages | Use |
| --- | --- | --- |
| `html` | beautifulsoup4 | `.html`, `.htm` |
| `pdf` | pymupdf | `.pdf`, including page numbers |
| `docx` | python-docx | `.docx` |
| `yaml` | pyyaml | `.yaml`, `.yml` |
| `pcap` | scapy | `.pcap`, `.pcapng` |
| `pydantic` | pydantic | dataclass results as pydantic models |
| `all` | all of the above | every optional reader |
| `docs` | MkDocs Material, mkdocstrings | this site |
| `dev` | pytest, mypy, ruff | tests and type checks |

```console
pip install "qarbaal[pdf,html]"
pip install "qarbaal[all]"
```

Pydantic is not required. Core results are dataclasses. When the extra is installed:

```python
from qarbaal.adapters import to_pydantic
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
