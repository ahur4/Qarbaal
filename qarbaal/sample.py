"""Synthetic incident used by the documentation and the tests.

The text is a fabricated triage note. It is safe to paste into a report.
"""

SAMPLE = r"""===== INCIDENT IR-2026-0142 — TRIAGE NOTES (synthetic sample) =====
Analyst: SOC-T2 | Severity: High | Source: EDR + mail gateway + proxy

[Phishing wave]
From: "IT Helpdesk" <support[at]corp-it-desk[.]com>
Reply-To: refund.department@billing-secure-portal.net
Lure URL: hxxps://login[.]corp-it-desk[.]com/session/verify?id=88231
Redirect chain -> hxxp://cdn-static-delivery[.]net/o/payload.hta

[Payload / EDR]
Dropper:  invoice_march.hta
MD5:      d41d8cd98f00b204e9800998ecf8427e
SHA1:     3395856ce81f2b7382dee72602f798b642f14140
SHA256:   275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
Persistence: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdaterSvc
Technique map: T1566.001 (spearphish attachment), T1547.001 (registry run key), T1105 (ingress tool transfer)

[C2 / network]
Beacon:   185.220.101.42:443 (JA3 matched)
Fallback: 91.92.240[.]119 and 2a06:98c1:3121::7d3a
Internal pivot attempts from 10.14.2.77 and 192.168.50.9 (contained)
DNS:      exfil-sync.datavault-storage.com | telemetry.win-metrics[.]org

[Vulnerability angle]
Initial access host unpatched for CVE-2024-21412 and CVE-2023-23397.

[Ransom note artifacts]
Contact:  recovery-desk@onionmail.org
BTC:      1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
bech32:   bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
===== END ====="""
