from __future__ import annotations

from qarbaal import SAMPLE, extract
from qarbaal.extract import IOCExtractor
from qarbaal.tlds import iana_tlds, split_domain, tld_recognized


def test_validation_flags_and_confidence() -> None:
    public = extract("8.8.8.8").get("ip")[0]
    private = extract("10.1.1.1").get("ip")[0]
    domain = extract("corp.example").get("domain")[0]
    bogus = extract("refund.department").get("domain")[0]
    digest = extract("d41d8cd98f00b204e9800998ecf8427e").get("md5")[0]
    assert public.valid is True and public.confidence == 0.9
    assert private.valid is True and private.confidence == 0.65 and private.tags == ("private",)
    assert domain.valid is True and domain.confidence == 0.8
    assert bogus.valid is False
    assert "tld-not-recognized" in bogus.validation_notes
    assert bogus.confidence == 0.25
    assert digest.confidence == 0.9
    assert digest.enrichment.hash_algorithm == "MD5"


def test_drop_invalid_removes_unknown_tlds() -> None:
    result = IOCExtractor(drop_invalid=True).extract(SAMPLE)
    assert "refund.department" not in result.values("domain")
    assert "corp-it-desk.com" in result.values("domain")
    loose = extract("ab:cd:ef")
    assert loose.get("ip6")[0].valid is False
    assert IOCExtractor(drop_invalid=True).extract("ab:cd:ef").get("ip6") == ()


def test_email_url_cve_and_asn_validation() -> None:
    email = extract("a@b.exe").get("email")[0]
    assert email.valid is False
    url = extract("https://evil.example/a").get("url")[0]
    assert url.valid is True
    partial = extract("https://not a url").get("url")[0]
    assert partial.value == "https://not"
    assert partial.valid is False
    old = extract("CVE-1800-1234").get("cve")[0]
    assert old.validation_notes == ("bad-cve-year",)
    assert extract("CVE-2024-21412").get("cve")[0].valid is True


def test_tld_list_and_registered_domain_heuristic() -> None:
    assert "com" in iana_tlds()
    assert tld_recognized("onion")
    assert tld_recognized("example")
    assert not tld_recognized("department")
    assert split_domain("login.corp-it-desk.com") == ("com", "corp-it-desk.com", "login")
    assert split_domain("a.b.co.uk") == ("co.uk", "b.co.uk", "a")


def test_custom_validator_marks_invalid() -> None:
    def reject_public(indicator: object) -> bool:
        from qarbaal import Indicator

        assert isinstance(indicator, Indicator)
        return indicator.value != "8.8.8.8"

    result = IOCExtractor(validators=[reject_public]).extract("8.8.8.8 1.1.1.1")
    flagged = result.get("ip")[0]
    assert flagged.value == "8.8.8.8"
    assert flagged.valid is False
    assert any(note.startswith("rejected-by:") for note in flagged.validation_notes)


def test_allow_and_deny() -> None:
    kept = IOCExtractor(allow=["8.8.8.8"]).extract("8.8.8.8 1.1.1.1")
    assert kept.values("ip") == ("8.8.8.8",)
    denied = IOCExtractor(deny=["10.*"]).extract("10.1.2.3 8.8.8.8")
    assert denied.values("ip") == ("8.8.8.8",)
