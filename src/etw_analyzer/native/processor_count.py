"""Canonical logical-processor count selection."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if parsed > 0 else None


def select_processor_count(
    authoritative_counts: Iterable[Any] = (),
    fallback_counts: Iterable[Any] = (),
    observed_cpu_ids: Iterable[Any] = (),
) -> int | None:
    """Choose an LP count without inventing 0/1 processor systems.

    Positive EventTrace/TRACE_LOGFILE_HEADER values are authoritative. The
    maximum observed CPU ID plus one is only a fallback lower bound when no
    valid header count exists.
    """

    authoritative = [
        count
        for value in authoritative_counts
        if (count := _positive_int(value)) is not None
    ]
    if authoritative:
        return max(authoritative)

    fallback = [
        count
        for value in fallback_counts
        if (count := _positive_int(value)) is not None
    ]
    observed = []
    for value in observed_cpu_ids:
        try:
            cpu_id = int(value)
        except (TypeError, ValueError, OverflowError):
            continue
        if cpu_id >= 0:
            observed.append(cpu_id)
    if observed:
        fallback.append(max(observed) + 1)
    return max(fallback) if fallback else None
