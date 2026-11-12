# Normalization

Every indicator stores the sieve value and a normalized value. Normalization does not delete the original.

| Field | Contents |
| --- | --- |
| `raw` | Exact source slice for the first sighting. Defang marks stay in place. |
| `value` | First-seen sieve form after refang. Case follows the type: hashes and domains lower, CVE IDs upper, URLs keep the case they had. |
| `normalized` | Canonical form. This is the correlation key when normalization is on. |

`normalize=False` still refangs. In that mode `normalized` equals `value`, and the fingerprint uses the case-folded sieve value so `Evil.COM` and `evil.com` still meet.

## Steps

When normalization is on, the input is rewritten with Unicode NFKC before the sieve, one character at a time, so offsets still land on the original text. Full-width dots and digits become ASCII and can then match. The value itself is then:

1. NFKC-normalized, stripped, and refanged.
2. Rewritten for its type.

| Type | Canonical form |
| --- | --- |
| IPv4 | `ipaddress` text, no leading zeros. |
| IPv6 | Compressed lower-case text. Unparseable tokens stay lower-case and fail validation. |
| CIDR | Network address plus prefix. Host bits are cleared. |
| Domain | Lower case, trailing dot removed, IDNA / punycode. |
| Email | Lower-case local part, domain as above. |
| URL | Lower-case scheme and host, IDNA host, default ports removed (`:443` on https, `:80` on http, `:21` on ftp). Path, query, and fragment keep their case and order. |
| Hashes, JA3, JA3S, JARM | Lower-case hex with whitespace removed. |
| CVE, ATT&CK, ASN | Upper case. ASN numeric text has no leading zeros. |
| MAC | Lower-case, colon-separated. |
| Registry | Backslashes normalized, case-folded, so `HKLM` and `hklm` share a fingerprint. `value` keeps the first spelling. |
| Wallet | `bc1` addresses lower-cased. Legacy base58 keeps its case. |
| User-Agent | Ends stripped, internal whitespace collapsed to one space. |
| Path, mutex | Trimmed. |

```python
from qarbaal import extract, normalize_value

normalize_value("url", "HTTPS://Evil.Example:443/A")
# 'https://evil.example/A'

indicator = extract("2001:0db8:0000:0000:0000:0000:0000:0001").get("ip6")[0]
indicator.value        # the expanded form, lower case
indicator.normalized   # '2001:db8::1'
```

## Fingerprint

The fingerprint is the SHA-256 hex digest of `type + newline + correlation key`.

- Normalization on: the key is `normalized`.
- Normalization off: the key is `value.casefold()`.

The same type and the same key always produce the same fingerprint. Deduplication and cross-report correlation use that digest. Two URLs that differ only by host case or a default port collapse to one indicator. Two URLs that differ by path case stay distinct, because the path is left as written.

`occurrences` counts sightings after that merge, including repeats inside one file.
