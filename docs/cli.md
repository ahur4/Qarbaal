# Command line

```console
qarbaal [options] [file ...]
```

With no files, the command reads stdin. Several files are correlated into one result. The source label is the path, or `<stdin>` for standard input.

| Option | Meaning |
| --- | --- |
| `-f`, `--format` | `table` (default), `csv`, `json`, `jsonl`, `stix`, `list`, `misp`, `openioc`, `suricata`, `snort` |
| `-o`, `--output` | Write here instead of stdout |
| `--types` | Comma-separated type keys, `hash`, or `all`. Default is the standard set. |
| `--parser` | Force a reader instead of using the file suffix. |
| `--defang` | Defang values in the table. `list` is always defanged. |
| `--hide-private` | Drop tagged IPv4, IPv6, and CIDR indicators. |
| `--drop-invalid` | Drop indicators that failed structural validation. |
| `--no-normalize` | Skip NFKC and canonical forms. Refanging still runs. |
| `--no-validate` | Skip structural validation. |
| `--no-dedup` | Keep every match as its own indicator. |
| `--allow` | Glob of values to keep. Repeat the flag to add a pattern. |
| `--deny` | Glob of values to drop. Repeat the flag to add a pattern. |
| `--compact` | Compact JSON object. This is the default for CSV. |
| `--detailed` | Detailed CSV or JSON. This is the default for JSON and JSONL. |
| `--max-chars` | Input character limit. Default 2000000. |
| `--strict-limits` | Raise an error instead of truncating a large input. |
| `--verbose` | Debug logging. |
| `--version` | Print the version and exit. |

`--compact` and `--detailed` together are an error. JSON defaults to the detailed document so provenance is visible. Pass `--compact` for the `{tool, generated, iocs}` object.

Exit status is 0 on success and 2 when the input cannot be read, the format is unknown, or a limit is exceeded in strict mode.

```console
qarbaal hunt.md -f json --compact
qarbaal mail.eml -f stix -o bundle.json
qarbaal --types ip,domain,url --hide-private alerts.log
qarbaal --types all -f suricata capture.txt
```
