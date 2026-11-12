"""Optional pydantic models.

The core result types are dataclasses. This module builds a pydantic model only
when pydantic is installed (``pip install 'qarbaal[pydantic]'``).
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from functools import lru_cache
from typing import Protocol, cast

from qarbaal.exceptions import OptionalDependencyError
from qarbaal.export import indicator_to_dict
from qarbaal.types import Extraction, Indicator


class IndicatorRecord(Protocol):
    """Structural type of the optional pydantic indicator model."""

    type: str
    value: str
    normalized: str
    raw: str
    fingerprint: str
    confidence: float
    occurrences: int
    valid: bool | None


def to_pydantic(indicator: Indicator) -> IndicatorRecord:
    """Convert one indicator to a pydantic model.

    Args:
        indicator: Indicator to convert.

    Returns:
        A pydantic ``BaseModel`` instance with the indicator fields.

    Raises:
        OptionalDependencyError: pydantic is not installed.
    """

    validate = _validator()
    return cast(IndicatorRecord, validate(indicator_to_dict(indicator)))


def extraction_to_pydantic(result: Extraction) -> list[IndicatorRecord]:
    """Convert every indicator in an extraction.

    Args:
        result: Extraction to convert.

    Returns:
        One pydantic model per indicator.

    Raises:
        OptionalDependencyError: pydantic is not installed.
    """

    return [to_pydantic(indicator) for indicator in result]


@lru_cache(maxsize=1)
def _validator() -> Callable[[object], object]:
    try:
        module = importlib.import_module("pydantic")
    except ImportError as exc:
        raise OptionalDependencyError(
            "pydantic is required for this adapter. "
            "Install it with: pip install 'qarbaal[pydantic]'"
        ) from exc
    factory = getattr(module, "create_model", None)
    if not callable(factory):
        raise OptionalDependencyError("pydantic.create_model is unavailable")
    create = cast(Callable[..., type[object]], factory)
    model = create(
        "QarbaalIndicator",
        type=(str, ...),
        value=(str, ...),
        normalized=(str, ...),
        raw=(str, ...),
        tags=(list[str], ...),
        fingerprint=(str, ...),
        valid=(bool | None, ...),
        confidence=(float, ...),
        validation_notes=(list[str], ...),
        occurrences=(int, ...),
        sources=(list[str], ...),
        sightings=(list[dict[str, object]], ...),
        enrichment=(dict[str, object], ...),
        pivots=(list[dict[str, str]], ...),
    )
    validate = getattr(model, "model_validate", None)
    if not callable(validate):
        raise OptionalDependencyError("pydantic model has no model_validate")
    return cast(Callable[[object], object], validate)
