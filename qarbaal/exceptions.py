"""Errors raised by qarbaal."""

from __future__ import annotations


class QarbaalError(Exception):
    """Base class for qarbaal errors."""


class InputTooLargeError(QarbaalError):
    """Input exceeded the configured character limit in strict mode.

    Attributes:
        size: Length of the input that was rejected.
        limit: Configured maximum, in characters.
    """

    def __init__(self, size: int, limit: int) -> None:
        super().__init__(f"input length {size} exceeds limit {limit}")
        self.size = size
        self.limit = limit


class UnsupportedFormatError(QarbaalError):
    """The file suffix is not a supported input format."""


class OptionalDependencyError(QarbaalError):
    """An optional parser or adapter is not installed."""


class ParseError(QarbaalError):
    """A file could not be parsed as the selected format."""
