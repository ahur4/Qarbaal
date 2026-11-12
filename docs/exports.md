# Exports

Exports live in `qarbaal.export`. The command line selects the same formats with `-f`.

Machine-readable formats keep live indicator values. The defanged list is the exception, and the table honors `--defang`.

## CSV

`to_csv` writes a UTF-8 BOM, CRLF line endings, and quotes every field. There is no trailing CRLF. The compact columns are `type`, `value`, `tags`. The detailed form adds `normalized`, `fingerprint`, `source`, `line`, `offset`, `page`, `occurrences`, `confidence`, and `valid`.

## JSON

Compact JSON is one object:

```json
{"tool": "qarbaal", "generated": "2026-11-11T00:00:00.000Z", "iocs": {"ip": ["8.8.8.8"]}}
```

Empty types are omitted. There is no trailing newline. `generated` is UTC with millisecond precision and a `Z` suffix.

Detailed JSON is the same envelope with `truncated`, `stats`, and an `indicators` array. Each object carries provenance, validation, enrichment, and sightings. JSONL is one indicator object per line, with a trailing newline when the list is not empty.

## Defanged list

`to_defanged_list` is one defanged value per line, joined with `\n`, with no trailing newline. Types follow the display order.

## STIX 2.1

`to_stix` builds a bundle with `uuid` and `json`. It does not import the `stix2` package.

| Indicator | STIX object |
| --- | --- |
| IPv4, IPv6, domain, URL, hashes, email, registry, MAC, mutex, ASN | `indicator` with a STIX pattern |
| CVE | `vulnerability` SDO |

CIDR, JA3, JA3S, JARM, paths, User-Agent strings, wallets, and ATT&CK IDs are omitted. A CIDR is not an `ipv4-addr`, and the omitted types have no pattern that a STIX consumer can use without inventing a vocabulary. Registry and mutex values escape backslashes. URL patterns escape quotes. The indicator label is `qarbaal-extracted`.

## MISP

`to_misp` writes a MISP event as JSON. Addresses and CIDR ranges are `ip-dst` (direction is not inferred). The other mappings are `domain`, `url`, `md5`, `sha1`, `sha256`, `sha512`, `email-src`, `vulnerability`, `regkey`, `btc`, `mac-address`, `AS`, `ja3-fingerprint-md5`, `ja3s-fingerprint-md5`, `jarm-fingerprint`, `mutex`, `filename` for paths, `user-agent`, and `text` for ATT&CK IDs. `to_ids` is false for CVE, MAC, ASN, User-Agent, and ATT&CK attributes.

## OpenIOC

`to_openioc` writes an OpenIOC 1.1 document with `xml.etree` and a pretty-printed body. Each value is an `IndicatorItem` under an `OR` group. The `Context` document and search names follow the type (`Network` / `ipv4`, `File` / `md5`, and so on).

## Suricata and Snort

Rules are emitted only for IPv4, IPv6, CIDR, domains, and URLs.

- An address or CIDR becomes an IP rule.
- A domain becomes a Suricata `dns.query` content rule and a Snort UDP/53 content rule.
- A URL becomes a Suricata `http.host` plus `http.uri` rule, and a Snort rule with both contents.

Values that contain a quote, a backslash, a semicolon, or a newline are skipped so the rule stays valid. If nothing qualifies, the output is the comment `# qarbaal: no network indicators to emit`.

Hashes, emails, CVEs, and the other types do not become Suricata or Snort rules. A lone hash is not a network signature.

## YARA and Sigma

YARA and Sigma generation are out of scope. A hash set is not a useful YARA rule: YARA has no standard condition that matches a file hash, and inventing a string rule from a digest would not detect the file. Sigma needs a log source and a field mapping that this library does not have. Write those rules in a tool that knows the log source.

## Pydantic

Core objects stay dataclasses. With `pip install "qarbaal[pydantic]"`:

```python
from qarbaal.adapters import extraction_to_pydantic, to_pydantic

models = extraction_to_pydantic(result)
```

Without the extra, the adapter raises `OptionalDependencyError`.
