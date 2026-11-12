# Defanging

Reports often replace dots and schemes so a reader does not open a live indicator. `qarbaal` rewrites those forms before it extracts, and it can defang values again when you publish a list.

## Refang

`refang()` applies these substitutions, in order:

- `hxxps` to `https`, then `hxxp` to `http`, then `fxp` to `ftp`
- `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, `{dot}`, and ` dot ` (whitespace on both sides) to `.`
- `[at]`, `(at)`, `[@]`, and `(@)` to `@`
- `[://]` to `://`, and `[:]` to `:`

`hxxps` and the bracket forms are case-insensitive. `[://]` and `[:]` are not.

```python
from qarbaal import refang

refang("hxxps://evil[.]example[.]com admin[at]corp[.]com")
# 'https://evil.example.com admin@corp.com'
```

Extra substitutions run first. They are case-sensitive unless you put `(?i)` in the expression.

```python
from qarbaal import IOCExtractor

extractor = IOCExtractor(defang_patterns=[(r"\[dotdot\]", ".")])
extractor.extract("evil[dotdot]com")
```

Extraction always refangs. Turning `normalize=False` skips Unicode NFKC and the later canonical forms. It does not skip refanging.

## Defang

`defang(value, type)` replaces every dot with `[.]`. For a URL it also rewrites a leading `http` to `hxxp` and a leading `ftp` to `fxp`, so `https` becomes `hxxps`. For an email address it rewrites the first `@` as `[at]`.

```python
from qarbaal import defang

defang("https://evil.example/a.b", "url")
# 'hxxps://evil[.]example/a[.]b'
```

The defanged list export uses this helper. CSV, JSON, STIX, MISP, OpenIOC, and the rule exporters keep live values so the output can be matched and pivoted. The command-line `--defang` flag affects the table. The `list` format is always defanged.

## Original text is kept

Refanging changes the length of the text. The indicator's `raw` field is the slice of the original source, and `offset` points at that slice. `value` is the refanged sieve form.

```python
from qarbaal import extract

indicator = extract("91.92.240[.]119").get("ip")[0]
indicator.raw    # '91.92.240[.]119'
indicator.value  # '91.92.240.119'
```
