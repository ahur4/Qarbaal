from __future__ import annotations

import hashlib

from qarbaal import extract, normalize_value
from qarbaal.extract import IOCExtractor


def test_normalize_domain_url_and_ipv6() -> None:
    assert normalize_value("domain", "Bücher.Example.") == "xn--bcher-kva.example"
    assert normalize_value("url", "HTTPS://Evil.Example:443/A") == "https://evil.example/A"
    expanded = "2001:0db8:0000:0000:0000:0000:0000:0001"
    assert normalize_value("ip6", expanded) == "2001:db8::1"
    result = extract(expanded)
    assert result.values("ip6") == (expanded.lower(),)
    assert result.get("ip6")[0].normalized == "2001:db8::1"
    assert result.get("ip6")[0].value != result.get("ip6")[0].normalized


def test_nfkc_fullwidth_dot_is_extracted_by_default() -> None:
    text = "evil" + "\uff0e" + "example" + "\uff0e" + "com"
    result = extract(text)
    assert result.values("domain") == ("evil.example.com",)
    plain = IOCExtractor(normalize=False).extract(text)
    assert plain.get("domain") == ()


def test_url_canonicalization_dedups() -> None:
    text = "https://Evil.Example:443/A https://evil.example/A"
    merged = extract(text)
    assert len(merged.get("url")) == 1
    assert merged.get("url")[0].occurrences == 2
    assert merged.get("url")[0].normalized == "https://evil.example/A"
    separate = IOCExtractor(normalize=False).extract(text)
    assert len(separate.get("url")) == 2


def test_fingerprint_is_deterministic() -> None:
    first = extract("8.8.8.8").get("ip")[0]
    second = extract("8.8.8.8").get("ip")[0]
    assert first.fingerprint == second.fingerprint
    expected = hashlib.sha256(b"ip\n8.8.8.8").hexdigest()
    assert first.fingerprint == expected


def test_whitespace_and_mac_normalization() -> None:
    assert normalize_value("md5", "AA BB") == "aabb"
    assert normalize_value("user_agent", "Mozilla/5.0   (test)") == "Mozilla/5.0 (test)"
    assert normalize_value("asn", "AS00015169") == "AS15169"
