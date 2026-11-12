"""Refang defanged text and defang values for safe reports."""

from __future__ import annotations

import re
from collections.abc import Sequence

from qarbaal.types import IOCType

# Applied in this order. ``hxxps`` is rewritten before ``hxxp``.
_REFANG_STEPS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"fxp", re.IGNORECASE), "ftp"),
    (re.compile(r"\[(?:\.|dot)\]", re.IGNORECASE), "."),
    (re.compile(r"\((?:\.|dot)\)", re.IGNORECASE), "."),
    (re.compile(r"\{(?:\.|dot)\}", re.IGNORECASE), "."),
    (re.compile(r"\s+dot\s+", re.IGNORECASE), "."),
    (re.compile(r"\[(?:@|at)\]", re.IGNORECASE), "@"),
    (re.compile(r"\((?:@|at)\)", re.IGNORECASE), "@"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
)

Span = tuple[int, int]


def refang(text: str, extra: Sequence[tuple[str, str]] | None = None) -> str:
    """Rewrite defanged text into plain text.

    Replacements, in order:

    - ``hxxps`` to ``https``, ``hxxp`` to ``http``, ``fxp`` to ``ftp``
    - ``[.]``, ``(.)``, ``{.}``, ``[dot]``, ``(dot)``, ``{dot}``, and `` dot `` to ``.``
    - ``[at]``, ``(at)``, ``[@]``, and ``(@)`` to ``@``
    - ``[://]`` to ``://`` and ``[:]`` to ``:``

    ``extra`` is a list of ``(regex, replacement)`` pairs applied before the
    built-in rules. Patterns are case-sensitive unless the regex says otherwise.

    Args:
        text: Arbitrary input. It is not required to contain indicators.
        extra: Optional substitutions applied first.

    Returns:
        The refanged string.
    """

    refanged, _spans = refang_tracked(text, extra)
    return refanged


def refang_tracked(
    text: str,
    extra: Sequence[tuple[str, str]] | None = None,
) -> tuple[str, list[Span]]:
    """Refang ``text`` and map each output character back to the original.

    Each span is ``(start, end)`` in the original string. A replacement that
    shrinks the text, such as ``[.]`` to ``.``, maps the new character onto the
    whole original slice.

    Args:
        text: Original input.
        extra: Optional substitutions applied first.

    Returns:
        The refanged text and one span per output character.
    """

    spans: list[Span] = [(index, index + 1) for index in range(len(text))]
    current = text
    steps: list[tuple[re.Pattern[str], str]] = []
    for expression, replacement in extra or ():
        steps.append((re.compile(expression), replacement))
    steps.extend(_REFANG_STEPS)
    for compiled, replacement in steps:
        current, spans = _substitute(compiled, replacement, current, spans)
    return current, spans


def defang(value: str, kind: IOCType | str | None = None) -> str:
    """Defang one indicator for a report.

    Dots become ``[.]``. URLs also rewrite a leading ``http`` to ``hxxp`` and a
    leading ``ftp`` to ``fxp`` (so ``https`` becomes ``hxxps``). Email addresses
    rewrite the first ``@`` as ``[at]``.

    Args:
        value: Indicator value, already refanged.
        kind: Type key. Only ``url`` and ``email`` change more than the dots.

    Returns:
        The defanged value.
    """

    key = ""
    if isinstance(kind, IOCType):
        key = kind.value
    elif kind:
        key = kind.strip().lower()
    text = value.replace(".", "[.]")
    if key == IOCType.URL.value:
        text = re.sub(r"^http", "hxxp", text, count=1, flags=re.IGNORECASE)
        text = re.sub(r"^ftp", "fxp", text, count=1, flags=re.IGNORECASE)
    elif key == IOCType.EMAIL.value:
        text = text.replace("@", "[at]", 1)
    return text


def _substitute(
    pattern: re.Pattern[str],
    replacement: str,
    text: str,
    spans: list[Span],
) -> tuple[str, list[Span]]:
    pieces: list[str] = []
    mapped: list[Span] = []
    cursor = 0
    for match in pattern.finditer(text):
        pieces.append(text[cursor : match.start()])
        mapped.extend(spans[cursor : match.start()])
        if match.start() < match.end():
            cover = (spans[match.start()][0], spans[match.end() - 1][1])
        else:
            cover = spans[match.start()] if match.start() < len(spans) else (0, 0)
        pieces.append(replacement)
        mapped.extend([cover] * len(replacement))
        cursor = match.end()
    pieces.append(text[cursor:])
    mapped.extend(spans[cursor:])
    return "".join(pieces), mapped
