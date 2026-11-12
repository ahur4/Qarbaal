"""Sieve regular expressions and the file-extension exclusion set.

The twelve original patterns follow the reference sieve, including order.
Hashes are matched longest first so a longer digest is not also reported as a
shorter one. Extra types use their own patterns and do not change those matches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from qarbaal.types import IOCType

_ASCII = re.ASCII

FILE_EXT: frozenset[str] = frozenset(
    (
        "exe dll bat cmd ps1 vbs js jse wsf hta scr txt log md doc docx xls xlsx "
        "ppt pptx pdf rtf zip rar 7z tar gz bz2 jpg jpeg png gif bmp svg ico webp "
        "mp3 mp4 avi mov dat bin tmp sys ini cfg conf yml yaml json xml html htm css "
        "php asp aspx jsp py sh rb pl class jar war apk ipa db sqlite sql bak lnk "
        "iso img dmg msi cab reg pcap pcapng evtx dmp"
    ).split()
)

SHA512_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{128}(?![a-fA-F0-9])", _ASCII)
SHA256_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])", _ASCII)
SHA1_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])", _ASCII)
MD5_RE = re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])", _ASCII)

URL_RE = re.compile(
    r"""\b(?:https?|ftp)://[^\s"'<>()\[\]{}]+""",
    _ASCII | re.IGNORECASE,
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _ASCII)
IPV4_CIDR_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}/(?:[0-9]|[12]\d|3[0-2])\b",
    _ASCII,
)
# Same bounded IPv6 token as the reference sieve. A compressed address can end
# at ``::`` when more groups follow it. Validation then parses that token.
IPV6_RE = re.compile(
    r"\b(?:[a-fA-F0-9]{1,4}:){2,7}(?::|[a-fA-F0-9]{1,4})\b",
    _ASCII,
)
IPV6_TIME_RE = re.compile(r"(?:\d{1,2}:){2,}\d{1,2}", _ASCII)
IPV6_CIDR_RE = re.compile(
    r"(?i)\b(?:[a-f0-9]{1,4}:){2,7}(?::|[a-f0-9]{1,4})/(?:12[0-8]|1[01]\d|\d{1,2})\b",
    _ASCII,
)
EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}\b",
    _ASCII,
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b",
    _ASCII,
)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", _ASCII | re.IGNORECASE)
ATTACK_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b", _ASCII)
REGISTRY_RE = re.compile(
    r"""\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"'<>|*?]+""",
    _ASCII | re.IGNORECASE,
)
WALLET_RE = re.compile(
    r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
    _ASCII,
)
MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:-])(?:"
    r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
    r"|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}"
    r")(?![0-9A-Fa-f:-])",
    _ASCII,
)
ASN_RE = re.compile(r"\bAS[1-9]\d{0,9}\b", _ASCII)
JA3S_RE = re.compile(r"\bJA3S\s*[:=]\s*([a-fA-F0-9]{32})\b", _ASCII | re.IGNORECASE)
JA3_RE = re.compile(r"\bJA3\s*[:=]\s*([a-fA-F0-9]{32})\b", _ASCII | re.IGNORECASE)
JARM_RE = re.compile(r"\bJARM\s*[:=]\s*([a-fA-F0-9]{62})\b", _ASCII | re.IGNORECASE)
MUTEX_RE = re.compile(
    r"\b(?:Global|Local)\\[A-Za-z0-9_.:-]{4,120}\b",
    _ASCII | re.IGNORECASE,
)
WINDOWS_PATH_RE = re.compile(
    r"""(?i)\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)+[^\\/:*?"<>|\r\n]+""",
    _ASCII,
)
UNC_PATH_RE = re.compile(
    r"""\\\\[^\\/:*?"<>|\r\n]+\\[^\\/:*?"<>|\r\n]+\\[^\\/:*?"<>|\r\n]+""",
    _ASCII,
)
UNIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9._-]{1,64}/){2,}[A-Za-z0-9._-]{1,128}",
    _ASCII,
)
USER_AGENT_RE = re.compile(
    r"\bUser-Agent\s*:\s*([^\r\n]{6,400})",
    _ASCII | re.IGNORECASE,
)
IPV4_HOST_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
TRAILING_URL_PUNCT_RE = re.compile(r"[.,;:!?)]+$")

MAX_TOKEN_LENGTH = 4096


@dataclass(frozen=True, slots=True)
class PatternSpec:
    """A caller-supplied indicator pattern for an existing :class:`~qarbaal.types.IOCType`.

    Attributes:
        type: Indicator type stored on matches.
        regex: Regular expression. Group 1 is the value when present; otherwise the whole match.
        flags: Extra :mod:`re` flags. ``re.ASCII`` is not added for you.
        folds: ``lower``, ``upper``, or ``preserve``.
    """

    type: IOCType
    regex: str
    flags: int = 0
    folds: str = "preserve"

    def compile(self) -> re.Pattern[str]:
        """Compile the pattern, or raise ``ValueError`` when it is invalid."""

        if self.folds not in {"lower", "upper", "preserve"}:
            raise ValueError("folds must be 'lower', 'upper', or 'preserve'")
        try:
            return re.compile(self.regex, self.flags)
        except re.error as exc:
            raise ValueError(f"invalid custom pattern {self.type.value!r}: {exc}") from exc
