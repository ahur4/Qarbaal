# Indicator types

The default extractor enables every type in the table below except the three marked opt-in. Select types with `IOCType` members, for example `IOCType.IPV4` and `IOCType.DOMAIN`. `extract_types=["all"]` or `tuple(IOCType)` enables every type, including the opt-in ones. The short keys in the table are the `IOCType` values written into JSON exports.

Hashes are scanned longest first. A SHA-256 digest is not also reported as MD5 or SHA-1. Matches are deduplicated within a type. The first spelling is kept on `value`.

## Default types

| Key | What it matches | False-positive notes |
| --- | --- | --- |
| `ip` | Dotted IPv4. Each octet is 0-255 with no leading zero. | `1.2.3.4.5` still yields `1.2.3.4`. Tagged addresses are kept unless you hide them. |
| `ip6` | A bounded IPv6 token: two to seven hex groups, then a group or a colon. | A compressed address can stop at `::` when more groups follow it. `2a06:98c1:3121::7d3a` is captured as `2a06:98c1:3121::`. Clock times such as `12:34:56` are rejected. A colon MAC of exactly six two-hex groups (`00:1A:2B:3C:4D:5E`) is not an IPv6 address. |
| `domain` | Host names. Also taken from URL hosts and the domain part of email addresses. | A trailing label that is a file extension (`exe`, `hta`, `pdf`, ...) is ignored on the standalone pass. Domains copied out of an email address are not filtered that way, so `a@b.exe` still contributes `b.exe`. Labels are checked against the bundled TLD list when validation is on. |
| `url` | `http`, `https`, and `ftp` URLs. Trailing `.,;:!?` and `)` are stripped. | Brackets are not part of the token, so `http://[2001:db8::1]/` is not a URL. The IPv6 address can still be found on its own. |
| `md5` | 32 hex characters, not touching other hex. | Any 32-hex token is an MD5, including a JA3 that was also labeled. |
| `sha1` | 40 hex characters. | Same boundary rule. |
| `sha256` | 64 hex characters. | Same boundary rule. |
| `sha512` | 128 hex characters. | Same boundary rule. |
| `email` | `local@host` with a letter TLD of 2-24 characters. | The host is also stored as a domain. |
| `cve` | `CVE-YYYY-NNNN` with 4 to 7 digits. Stored in upper case. | Years outside 1999-2099 fail validation. |
| `attack` | `T1xxx` and `T1xxx.xxx`. | `T1566.01` still yields `T1566`, because the shorter form is a complete match. Lower case `t1105` is ignored. There is no ATT&CK catalog check. |
| `registry` | A hive (`HKLM`, `HKCU`, `HKEY_LOCAL_MACHINE`, and the other standard hives) and the rest of the key. | The match stops at whitespace or `" ' < > \| * ?`. |
| `wallet` | Bitcoin legacy (`1` or `3`, base58 length) and bech32 `bc1` text. | There is no checksum test. Short or mixed-case `bc1` strings are ignored. |
| `cidr` | IPv4 `address/prefix` and a bounded IPv6 prefix. | The address inside an IPv4 range is also reported as `ip` when it is a valid address. Host bits are kept on `value` and cleared on `normalized` (`192.168.1.5/24` becomes `192.168.1.0/24`). |
| `mac` | Six octets, colon-separated or hyphen-separated, one style only. | A seventh octet prevents a match. Cisco dotted form is not extracted. |
| `asn` | Upper-case `AS` plus a number without a leading zero. | `as13335` is ignored on purpose. Values above 4294967295 fail validation. |
| `ja3` | A `JA3:` or `JA3=` label and 32 hex characters. | Unlabeled 32-hex strings stay MD5 only. The hash is still an MD5 as well. |
| `ja3s` | A `JA3S:` or `JA3S=` label and 32 hex characters. | Independent of JA3. `JA3S` is not read as JA3. |
| `jarm` | A `JARM:` or `JARM=` label and 62 hex characters. | Bare 62-hex strings are not extracted. They collide with arbitrary hex. |

## Opt-in types

These stay disabled until `extract_types` includes them or you pass `all`.

| Key | Pattern | Why it is opt-in |
| --- | --- | --- |
| `path` | Windows path with a drive and at least one directory (`C:\Windows\System32\cmd.exe`), a UNC path with server, share, and file, or a Unix path with at least two directories (`/usr/local/bin/nc`). | `C:\notes.txt` and `/tmp/x` are ignored. URL paths that sit against a hostname are ignored. Prose still contains real paths you may not want in every export. |
| `mutex` | `Global\Name` or `Local\Name`, four or more characters after the slash. | Short names and ordinary backslash text would dominate a default scan. |
| `user_agent` | The value of a `User-Agent:` header. The value must contain `/`. | Free text mentions of browsers are not indicators. |

## Custom patterns

```python
from qarbaal import IOCExtractor, PatternSpec

spec = PatternSpec("case", r"\bCASE-\d{4}\b", flags=0, folds="upper")
result = IOCExtractor(custom_patterns=[spec]).extract("CASE-1042")
```

`folds` is `lower`, `upper`, or `preserve`. Group 1 is the value when the expression has a group. Otherwise the whole match is the value. Custom patterns are your responsibility. A pattern that can match the empty string, or that backtracks badly, is not sandboxed beyond the input size limit.

## Pivot links

Each built-in type that has a stable public search page exposes `indicator.pivots`, a tuple of `(name, url)`. The library does not fetch them. Email addresses and registry keys have no pivot. IPv4 links to VirusTotal, AbuseIPDB, and Shodan. Domains link to VirusTotal, urlscan, and WHOIS. URLs link to VirusTotal and urlscan. Hashes link to VirusTotal and MalwareBazaar. CVEs link to NVD and MITRE. ATT&CK IDs link to the technique page, with the first dot replaced by a slash. Wallets link to Blockchain.com. AS numbers link to Hurricane Electric. CIDR ranges and JARM fingerprints link to a Shodan search. JA3 and JA3S link to a VirusTotal search.
