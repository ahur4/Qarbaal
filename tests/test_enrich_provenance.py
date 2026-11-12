from __future__ import annotations

from qarbaal import SAMPLE, extract
from qarbaal.extract import IOCExtractor
from qarbaal.types import IOCType


def test_provenance_points_at_the_source_slice() -> None:
    result = extract(SAMPLE)
    private = next(item for item in result.get(IOCType.IPV4) if item.value == "10.14.2.77")
    assert private.offset == SAMPLE.index("10.14.2.77")
    assert private.line == SAMPLE.count("\n", 0, private.offset) + 1
    assert SAMPLE[private.offset : private.end_offset] == "10.14.2.77"
    defanged = next(item for item in result.get(IOCType.IPV4) if item.value == "91.92.240.119")
    assert defanged.raw == "91.92.240[.]119"
    assert defanged.offset == SAMPLE.index("91.92.240[.]119")
    host = next(
        item for item in result.get(IOCType.DOMAIN) if item.value == "login.corp-it-desk.com"
    )
    assert host.raw == "login[.]corp-it-desk[.]com"
    email = next(item for item in result.get(IOCType.EMAIL) if item.value.startswith("support@"))
    assert "support" in email.raw and "[at]" in email.raw


def test_page_spans() -> None:
    text = "8.8.8.8\n1.1.1.1"
    result = IOCExtractor().extract(text, pages=((1, 0, 8), (2, 8, len(text))))
    pages = {item.value: item.page for item in result.get(IOCType.IPV4)}
    assert pages == {"8.8.8.8": 1, "1.1.1.1": 2}


def test_enrichment_fields() -> None:
    ip = extract("8.8.8.8").get(IOCType.IPV4)[0]
    assert ip.enrichment.ip_version == 4
    assert ip.enrichment.is_global is True
    assert ip.enrichment.is_private is False
    cgnat = extract("100.64.1.1").get(IOCType.IPV4)[0]
    assert cgnat.tags == ("cgnat",)
    assert cgnat.enrichment.is_cgnat is True
    assert cgnat.enrichment.is_private is False
    domain = extract("login.corp-it-desk.com").get(IOCType.DOMAIN)[0]
    assert domain.enrichment.tld == "com"
    assert domain.enrichment.registered_domain == "corp-it-desk.com"
    assert domain.enrichment.subdomain == "login"
    url = extract("https://evil.example/a/payload.hta?id=1&id=2").get(IOCType.URL)[0]
    assert url.enrichment.scheme == "https"
    assert url.enrichment.port == 443
    assert url.enrichment.path == "/a/payload.hta"
    assert url.enrichment.file_extension == "hta"
    assert url.enrichment.host_is_ip is False
    assert dict(url.enrichment.query_parameters)["id"] == ("1", "2")
    literal = extract("http://8.8.8.8/a").get(IOCType.URL)[0]
    assert literal.enrichment.host_is_ip is True
    wallet = extract("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").get(IOCType.WALLET)[0]
    assert wallet.enrichment.wallet_format == "bech32"


def test_correlation_across_sources() -> None:
    result = IOCExtractor().extract_many(
        [("alpha", "seen 1.2.3.4 and evil.example"), ("beta", "also 1.2.3.4")]
    )
    shared = result.shared()
    assert [item.value for item in shared] == ["1.2.3.4"]
    assert shared[0].occurrences == 2
    assert shared[0].sources == ("alpha", "beta")
    assert result.get(IOCType.DOMAIN)[0].sources == ("alpha",)
    assert result.stats.sources == ("alpha", "beta")


def test_streaming_preserves_offsets() -> None:
    text = SAMPLE
    chunks = [text[index : index + 40] for index in range(0, len(text), 40)]
    streamed = IOCExtractor(chunk_overlap=300).extract_iter(chunks, source="notes")
    whole = extract(text)
    assert streamed.values(IOCType.IPV4) == whole.values(IOCType.IPV4)
    assert streamed.values(IOCType.SHA256) == whole.values(IOCType.SHA256)
    assert streamed.values(IOCType.URL) == whole.values(IOCType.URL)
    left = next(item for item in streamed.get(IOCType.IPV4) if item.value == "10.14.2.77")
    right = next(item for item in whole.get(IOCType.IPV4) if item.value == "10.14.2.77")
    assert (left.offset, left.line, left.raw) == (right.offset, right.line, right.raw)


def test_long_url_survives_small_chunks() -> None:
    url = "https://evil.example/" + ("a" * 250)
    chunks = [url[index : index + 50] for index in range(0, len(url), 50)]
    found = IOCExtractor(chunk_overlap=400).extract_iter(chunks)
    assert found.values(IOCType.URL) == (url,)
