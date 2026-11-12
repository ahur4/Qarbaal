"""IANA root-zone TLDs, plus a short special-use set."""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files

from qarbaal.exceptions import QarbaalError

# RFC 6761 / RFC 7686 names that are not delegated in the root zone but are
# real indicator suffixes. ``onion`` in particular shows up in defanged reports.
SPECIAL_USE_TLDS: frozenset[str] = frozenset(
    {"example", "invalid", "localhost", "test", "local", "onion", "internal"}
)

# Common multi-label suffixes. This is a heuristic, not the Public Suffix List.
# ``foo.blogspot.com`` is treated as a subdomain of ``blogspot.com``.
MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "ltd.uk",
        "plc.uk",
        "net.uk",
        "sch.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "asn.au",
        "id.au",
        "co.jp",
        "or.jp",
        "ne.jp",
        "ac.jp",
        "go.jp",
        "co.kr",
        "or.kr",
        "ne.kr",
        "go.kr",
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "com.mx",
        "com.tr",
        "com.sg",
        "com.hk",
        "com.tw",
        "com.ar",
        "com.co",
        "co.za",
        "co.nz",
        "co.in",
        "net.in",
        "org.in",
        "com.ua",
        "co.il",
        "org.il",
        "ac.il",
        "gov.il",
        "com.pl",
        "co.id",
        "co.th",
    }
)


@lru_cache(maxsize=1)
def iana_tlds() -> frozenset[str]:
    """Return the bundled root-zone TLD list, lower case, without comments.

    The file is the IANA ``tlds-alpha-by-domain`` list shipped with the package.
    Special-use names live in :data:`SPECIAL_USE_TLDS` and are not mixed in here.
    """

    resource = files("qarbaal").joinpath("data/tlds.txt")
    try:
        text = resource.read_text(encoding="utf-8")
    except OSError as exc:
        raise QarbaalError("the bundled IANA TLD list is missing") from exc
    found: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        found.add(stripped.lower())
    if not found:
        raise QarbaalError("the bundled IANA TLD list is empty")
    return frozenset(found)


def tld_recognized(tld: str) -> bool:
    """Return whether ``tld`` is in the root zone or the special-use set."""

    label = tld.strip().lower().rstrip(".")
    if not label:
        return False
    return label in iana_tlds() or label in SPECIAL_USE_TLDS


def split_domain(domain: str) -> tuple[str | None, str | None, str | None]:
    """Split a domain into ``(tld, registered_domain, subdomain)``.

    The TLD is the last label, or the last two labels when they are in
    :data:`MULTI_LABEL_SUFFIXES` (``co.uk`` and similar). The registered domain
    is the suffix plus one label. Everything in front of that is the subdomain.

    This is intentionally not a Public Suffix List. Private suffixes such as
    ``blogspot.com`` are not treated as registry boundaries.

    Args:
        domain: A host name without a scheme. A trailing dot is ignored.

    Returns:
        ``(tld, registered_domain, subdomain)``. ``subdomain`` is ``None`` when
        the name has no labels in front of the registered domain.
    """

    labels = [label for label in domain.strip().lower().rstrip(".").split(".") if label]
    if not labels:
        return None, None, None
    if len(labels) == 1:
        return labels[0], labels[0], None
    suffix = ".".join(labels[-2:])
    if suffix in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        registered = ".".join(labels[-3:])
        subdomain = ".".join(labels[:-3]) or None
        return suffix, registered, subdomain
    registered = ".".join(labels[-2:])
    subdomain = ".".join(labels[:-2]) or None
    return labels[-1], registered, subdomain
