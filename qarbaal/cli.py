"""The ``qarbaal`` command."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from qarbaal.exceptions import QarbaalError
from qarbaal.export import (
    to_csv,
    to_defanged_list,
    to_json,
    to_jsonl,
    to_misp,
    to_openioc,
    to_snort,
    to_stix,
    to_suricata,
)
from qarbaal.extract import IOCExtractor, merge
from qarbaal.refang import defang
from qarbaal.types import Extraction
from qarbaal.version import __version__

_FORMATS = (
    "table",
    "csv",
    "json",
    "jsonl",
    "stix",
    "list",
    "misp",
    "openioc",
    "suricata",
    "snort",
)


def main(argv: list[str] | None = None) -> int:
    """Run the command line interface.

    Args:
        argv: Arguments, excluding the program name. Defaults to ``sys.argv[1:]``.

    Returns:
        ``0`` on success and ``2`` when a file or argument is rejected.
    """

    parser = _parser()
    args = parser.parse_args(argv)
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")
    if args.compact and args.detailed:
        parser.error("--compact and --detailed cannot be combined")
    try:
        types = _split_types(args.types)
        extractor = IOCExtractor(
            extract_types=types,
            normalize=not args.no_normalize,
            validate=not args.no_validate,
            deduplicate=not args.no_dedup,
            hide_private=args.hide_private,
            drop_invalid=args.drop_invalid,
            max_input_chars=args.max_chars,
            strict_limits=args.strict_limits,
            allow=tuple(args.allow or ()),
            deny=tuple(args.deny or ()),
        )
        result = _read(extractor, args.paths, args.parser)
        text = _render(
            result,
            fmt=args.format,
            defang_output=args.defang,
            detailed=_detailed(args.format, args.detailed, args.compact),
        )
    except (QarbaalError, OSError, ValueError) as exc:
        print(f"qarbaal: {exc}", file=sys.stderr)
        return 2
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
        if text and not text.endswith("\n"):
            sys.stdout.write("\n")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qarbaal",
        description="Extract and classify indicators of compromise from text and files.",
    )
    parser.add_argument("paths", nargs="*", help="Files to read. Omit to read stdin.")
    parser.add_argument(
        "-f",
        "--format",
        choices=_FORMATS,
        default="table",
        help="Output format. Default: table.",
    )
    parser.add_argument("--defang", action="store_true", help="Defang values in table output.")
    parser.add_argument(
        "--hide-private",
        action="store_true",
        help="Hide private, loopback, link-local, CGNAT, multicast, and reserved addresses.",
    )
    parser.add_argument(
        "--types",
        help=(
            "Comma-separated types to extract. "
            "Use 'all' to include paths, user agents, and mutexes."
        ),
    )
    parser.add_argument(
        "--parser", help="Force an input parser instead of detecting it from the suffix."
    )
    parser.add_argument(
        "--drop-invalid", action="store_true", help="Drop indicators that fail validation."
    )
    parser.add_argument(
        "--no-normalize", action="store_true", help="Skip NFKC and canonical forms."
    )
    parser.add_argument("--no-validate", action="store_true", help="Skip structural validation.")
    parser.add_argument(
        "--no-dedup", action="store_true", help="Keep every match as its own indicator."
    )
    parser.add_argument(
        "--detailed", action="store_true", help="Write detailed CSV or JSON records."
    )
    parser.add_argument(
        "--compact", action="store_true", help="Write the compact JSON sieve document."
    )
    parser.add_argument(
        "--allow", action="append", default=[], help="Glob of values to keep. Repeatable."
    )
    parser.add_argument(
        "--deny", action="append", default=[], help="Glob of values to drop. Repeatable."
    )
    parser.add_argument(
        "--max-chars", type=int, default=2_000_000, help="Maximum characters read from one source."
    )
    parser.add_argument(
        "--strict-limits", action="store_true", help="Fail instead of truncating long input."
    )
    parser.add_argument("-o", "--output", help="Write the result to this file.")
    parser.add_argument("--verbose", action="store_true", help="Log at debug level.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _split_types(value: str | None) -> list[str] | None:
    if value is None:
        return None
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if not parts:
        raise ValueError("--types did not contain a type name")
    return parts


def _read(extractor: IOCExtractor, paths: list[str], parser: str | None) -> Extraction:
    if not paths:
        text = sys.stdin.read(extractor.max_input_chars + 1)
        truncated = False
        if len(text) > extractor.max_input_chars:
            if extractor.strict_limits:
                from qarbaal.exceptions import InputTooLargeError

                raise InputTooLargeError(len(text), extractor.max_input_chars)
            text = text[: extractor.max_input_chars]
            truncated = True
        return extractor.extract(text, source="<stdin>", truncated=truncated)
    parts = [extractor.extract_path(path, parser=parser) for path in paths]
    if len(parts) == 1:
        return parts[0]
    return merge(parts)


def _detailed(fmt: str, detailed: bool, compact: bool) -> bool:
    if fmt == "json":
        return not compact
    if fmt == "csv":
        return detailed
    return detailed


def _render(result: Extraction, *, fmt: str, defang_output: bool, detailed: bool) -> str:
    if fmt == "table":
        return format_table(result, defang_output=defang_output)
    if fmt == "csv":
        return to_csv(result, detailed=detailed)
    if fmt == "json":
        return to_json(result, detailed=detailed)
    if fmt == "jsonl":
        return to_jsonl(result)
    if fmt == "stix":
        return to_stix(result)
    if fmt == "list":
        return to_defanged_list(result)
    if fmt == "misp":
        return to_misp(result)
    if fmt == "openioc":
        return to_openioc(result)
    if fmt == "suricata":
        return to_suricata(result)
    if fmt == "snort":
        return to_snort(result)
    raise ValueError(f"unknown format: {fmt}")


def format_table(result: Extraction, *, defang_output: bool = False) -> str:
    """Render a plain-text table.

    Args:
        result: Extraction to render.
        defang_output: Defang the value column.

    Returns:
        A table, or a short message when there are no indicators.
    """

    if not result.indicators:
        return "No indicators found."
    header = ("type", "value", "tags", "conf", "source", "line", "n")
    rows = [header]
    for indicator in result.indicators:
        shown = defang(indicator.value, indicator.type) if defang_output else indicator.value
        shown = shown.replace("\n", " ")
        rows.append(
            (
                indicator.type,
                shown,
                ",".join(indicator.tags),
                f"{indicator.confidence:.2f}",
                indicator.source,
                "" if indicator.line is None else str(indicator.line),
                str(indicator.occurrences),
            )
        )
    widths = [max(len(row[index]) for row in rows) for index in range(len(header))]
    # The value column is the only one that should stay readable when long.
    widths[1] = min(widths[1], 80)
    lines = []
    for row_index, row in enumerate(rows):
        cells = []
        for index, cell in enumerate(row):
            if index == 1 and len(cell) > widths[1]:
                cell = cell[: widths[1] - 1] + "…"
            cells.append(cell.ljust(widths[index]))
        lines.append("  ".join(cells).rstrip())
        if row_index == 0:
            lines.append("  ".join("-" * width for width in widths))
    return "\n".join(lines)
