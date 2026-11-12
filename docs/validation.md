# Validation

Validation is structural. It uses `ipaddress`, the shape of the value, and the bundled TLD list. It does not score likelihood with a model, and it does not look the indicator up on the internet.

With `validate=True` (the default), `indicator.valid` is `True` or `False` and `validation_notes` lists reason codes. With `validate=False`, `valid` is `None`. `drop_invalid=True` removes indicators whose `valid` is `False`.

## Checks

| Type | Invalid when |
| --- | --- |
| IPv4, IPv6 | `ipaddress` cannot parse the normalized text. IPv4 tokens with a bad octet never enter the result. |
| CIDR | `ipaddress.ip_network` rejects the text. |
| Domain | A label is empty, too long, or illegally hyphenated, or the TLD is not recognized. |
| Email | The local part is empty or longer than 64 characters, or the domain fails the domain checks. |
| URL | The scheme is not http, https, or ftp, or the host is not an IP and not a valid domain. |
| Hashes, JA3, JA3S, JARM | The hex length does not match the type. |
| CVE | The year is outside 1999-2099. |
| ASN | The number is missing or above 4294967295. |
| MAC | The normalized form is not six colon-separated octets. |
| User-Agent | The value has no `/`. The extractor already requires one. |

Recognized TLDs are the IANA root-zone list shipped in the package, plus the special-use names `example`, `invalid`, `localhost`, `test`, `local`, `onion`, and `internal`. `.onion` is included because it shows up in reports and is not a delegated root-zone label. `refund.department` fails with `tld-not-recognized`.

IPv4 noise tags are separate from validity. `10.1.1.1` is valid and tagged `private`. `8.8.8.8` is valid and untagged. CGNAT (`100.64.0.0/10`) is tagged `cgnat` even though `ipaddress` does not mark it private.

## Confidence

`confidence` is a heuristic in the range 0.01 to 0.99. It is not a probability.

- Invalid: 0.25
- Validation skipped: 0.55
- Valid: 0.80
- Tagged IPv4, IPv6, or CIDR: subtract 0.15
- Valid untagged IPv4 or IPv6: add 0.10
- Valid hash, JA3, JA3S, or JARM: add 0.10

A public IPv4 address scores 0.90. A private IPv4 address scores 0.65. A valid domain scores 0.80. An unrecognized TLD scores 0.25.

## Your own checks

A validator receives the indicator and returns `False` to reject it. The note is `rejected-by:` plus the function name.

```python
from qarbaal import IOCExtractor

def allow_only_public(indicator):
    return not indicator.tags

IOCExtractor(validators=[allow_only_public], drop_invalid=True)
```

## Allow and deny

`allow` and `deny` are glob patterns, compared case-insensitively to `value`, `normalized`, and `raw`. When `allow` is set, a value must match one pattern. A `deny` match always drops the indicator.

```python
IOCExtractor(allow=["8.8.8.8"], deny=["*.example"])
```
