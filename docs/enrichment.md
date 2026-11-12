# Enrichment

Enrichment is computed locally from the indicator. `qarbaal` does not query VirusTotal, passive DNS, or any other service. `indicator.pivots` are links only.

`indicator.enrichment` is an `Enrichment` object. `as_dict()` drops empty fields. The detailed JSON export includes that dictionary.

## IP addresses

For an address that `ipaddress` can parse:

- `ip_version`
- `is_private`, `is_global`, `is_multicast`, `is_reserved`, `is_loopback`, `is_link_local`

These flags are the `ipaddress` values, unchanged. They are not the same as the sieve tags. In particular, `100.64.1.1` has tag `cgnat` and `is_cgnat=True`, while `is_private` stays `False`. Multicast addresses can report `is_global=True` in current Python. Read `tags` when you want the sieve's noise class, and the enrichment flags when you want `ipaddress`.

CIDR enrichment adds `cidr_prefix` and `cidr_network`.

## Domains

`tld`, `registered_domain`, and `subdomain` come from a small heuristic, not the Public Suffix List.

- The TLD is the last label.
- For a short built-in list of multi-label suffixes (`co.uk`, `com.au`, `co.jp`, and similar), the TLD is those two labels and the registered domain adds one label in front.
- Everything in front of the registered domain is the subdomain.

`login.corp-it-desk.com` splits into TLD `com`, registered domain `corp-it-desk.com`, subdomain `login`. `a.b.co.uk` splits into `co.uk`, `b.co.uk`, and `a`.

This is wrong for public suffixes that are not in that short list. `foo.blogspot.com` is reported as a subdomain of `blogspot.com`. There is no network fetch and no Public Suffix List dependency. If you need registry boundaries, apply a PSL in your own code.

Email addresses use the same split on the host. URLs use it on the hostname unless the host is an IP literal.

## URLs

- `scheme`, `host`, `port` (the effective port, including 443, 80, and 21 when the URL omitted it)
- `path`
- `query_parameters`, a sequence of `(name, values)`
- `host_is_ip`
- `file_extension` from the last path segment, when it looks like an extension

## Other types

- Hashes, JA3, JA3S, and JARM set `hash_algorithm` from the type, then from the digest length (`32` MD5, `40` SHA-1, `64` SHA-256, `128` SHA-512).
- AS numbers set `asn_number`.
- MAC addresses set `mac_multicast` and `mac_locally_administered` from the first octet.
- Bitcoin addresses set `wallet_format` to `bech32` or `legacy`.
- Registry keys set `registry_hive` to the expanded hive name.
- File paths set `file_extension` when the last segment has one.
