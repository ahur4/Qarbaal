# Changelog

## 0.1.0

First public release of qarbaal, a local toolkit for extracting and classifying
indicators of compromise.

- Extracts IPv4, IPv6, domains, URLs, MD5, SHA-1, SHA-256, SHA-512, email
  addresses, CVE identifiers, MITRE ATT&CK technique IDs, Windows registry
  keys, and Bitcoin addresses. Defanged text is refanged before the scan.
- Adds CIDR ranges, MAC addresses, AS numbers, and labeled JA3, JA3S, and JARM
  fingerprints. File paths, mutex names, and User-Agent strings are available
  when you opt in.
- Keeps the original value and a normalized value, with a stable fingerprint
  for deduplication. Records the source, line, character offset, and PDF page
  for every sighting.
- Validates addresses, domains, URLs, emails, hashes, CIDR ranges, CVEs, and
  AS numbers with the standard library and a bundled IANA TLD list. Scores
  each indicator with a documented heuristic.
- Reads text, JSON, CSV, XML, EML, and MBOX with no extra dependencies.
  HTML, PDF, DOCX, YAML, and PCAP readers are optional installs.
- Exports CSV, JSON, JSONL, a defanged list, STIX 2.1, MISP, OpenIOC, and
  Suricata and Snort rules for network indicators.
- Provides a `qarbaal` command and a configurable `IOCExtractor`.
