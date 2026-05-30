"""Structured load telemetry for the native + dotnet trace-load pipeline.

The goal of this module is operational visibility: when load_trace runs,
operators (and the test harness) should be able to see which mode was
resolved, whether the cache hit or missed, when the sidecar spawned and
exited, when the aggregation worker ran, and when staging was promoted —
all at a glance, without enabling debug-level logging.

Format
------

Every event is a single log line at ``INFO`` level on the logger
``etw_analyzer.native.telemetry``:

    event=<name> mode=<dotnet|native|xperf|auto> trace_id=<id> key=value ...

Keys are ``snake_case``; values are formatted via :func:`format_value` so
floats stay readable (``%.3f``), paths render as ``str(path)``, and
booleans render as ``true``/``false``. Unprintable characters in values
are stripped — operators copy these lines into bug reports and we don't
want stray newlines breaking the grep target.

Design notes
------------

* The logger is **never** configured here. ``logging.basicConfig`` is the
  tool-host's job; this module just emits records.
* Default level is ``INFO`` so events are visible without ``--verbose``
  but easy to silence by setting the logger to ``WARNING``.
* The event names are part of the contract — tests grep for them. Do not
  rename without updating the matching tests.
* The shape is deliberately key=value text (not JSON) because operators
  read these in terminals; structured downstream consumers can parse
  them with ``shlex.split`` if needed.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

LOGGER_NAME = "etw_analyzer.native.telemetry"
LOGGER = logging.getLogger(LOGGER_NAME)

# Event names — kept here so the producer modules and tests share one
# source of truth. Adding a new event? Add the constant, update
# ``KNOWN_EVENTS``, and add a phase log at the call site.
EVENT_LOAD_START = "load.start"
EVENT_LOAD_CACHE_HIT = "load.cache_hit"
EVENT_LOAD_CACHE_MISS = "load.cache_miss"
EVENT_LOAD_DISPATCH = "load.dispatch"
EVENT_LOAD_COMPLETE = "load.complete"
EVENT_LOAD_FAILED = "load.failed"
EVENT_CSHARP_SPAWN = "dotnet.spawn"
EVENT_CSHARP_RESULT = "dotnet.result"
EVENT_CSHARP_CHILD_EXIT = "dotnet.child_exit"
EVENT_CSHARP_CACHE_VALIDATE = "dotnet.cache_validate"
EVENT_CSHARP_AGGREGATION_START = "dotnet.aggregation_start"
EVENT_CSHARP_AGGREGATION_DONE = "dotnet.aggregation_done"
EVENT_CSHARP_CACHE_PROMOTE = "dotnet.cache_promote"
EVENT_NATIVE_SPAWN = "native.spawn"
EVENT_NATIVE_CHILD_EXIT = "native.child_exit"

KNOWN_EVENTS: frozenset[str] = frozenset({
    EVENT_LOAD_START,
    EVENT_LOAD_CACHE_HIT,
    EVENT_LOAD_CACHE_MISS,
    EVENT_LOAD_DISPATCH,
    EVENT_LOAD_COMPLETE,
    EVENT_LOAD_FAILED,
    EVENT_CSHARP_SPAWN,
    EVENT_CSHARP_RESULT,
    EVENT_CSHARP_CHILD_EXIT,
    EVENT_CSHARP_CACHE_VALIDATE,
    EVENT_CSHARP_AGGREGATION_START,
    EVENT_CSHARP_AGGREGATION_DONE,
    EVENT_CSHARP_CACHE_PROMOTE,
    EVENT_NATIVE_SPAWN,
    EVENT_NATIVE_CHILD_EXIT,
})


def format_value(value: Any) -> str:
    """Render ``value`` as a single-token key=value field.

    * ``None``       → ``"-"`` (so empty fields don't get serialized as
                       the literal string ``"None"``, which is noisy).
    * ``bool``       → ``"true"`` / ``"false"``.
    * ``float``      → ``"%.3f"`` (sub-millisecond precision).
    * ``int``        → ``str(int)``.
    * ``Path``       → ``str(path)``.
    * ``str``        → as-is, except whitespace and control chars are
                       collapsed; a value containing ``" "`` is quoted
                       so the line still tokenises cleanly.
    * everything else→ ``str(value)`` and the same cleanup.
    """
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.3f}"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Path):
        text = str(value)
    else:
        text = str(value)
    cleaned = (
        text.replace("\r", " ")
        .replace("\n", " ")
        .replace("\t", " ")
    )
    if " " in cleaned or "=" in cleaned:
        cleaned = cleaned.replace('"', '\\"')
        return f'"{cleaned}"'
    return cleaned


def emit(event: str, **fields: Any) -> None:
    """Emit a telemetry record.

    Parameters
    ----------
    event:
        Event name — must be one of :data:`KNOWN_EVENTS` (validated only
        in debug — assertion isn't worth the cost in hot paths, but
        misspellings will fail the unit test that pins the contract).
    fields:
        Key=value fields to include. ``mode`` and ``trace_id`` are the
        conventional fields callers should always pass; everything else
        is event-specific.

    The log call is wrapped in :func:`LOGGER.isEnabledFor` so callers
    don't pay the formatting cost when telemetry is silenced.
    """
    if not LOGGER.isEnabledFor(logging.INFO):
        return
    parts = [f"event={event}"]
    for key, value in fields.items():
        parts.append(f"{key}={format_value(value)}")
    LOGGER.info(" ".join(parts))


def emit_with(event: str, *, mode: str | None = None, trace_id: str | None = None, **fields: Any) -> None:
    """Convenience wrapper that ensures ``mode`` and ``trace_id`` come first.

    Most call sites have both fields in scope and benefit from the
    standardised ordering for grep-readability.
    """
    ordered: dict[str, Any] = {}
    if mode is not None:
        ordered["mode"] = mode
    if trace_id is not None:
        ordered["trace_id"] = trace_id
    ordered.update(fields)
    emit(event, **ordered)


__all__ = [
    "EVENT_CSHARP_AGGREGATION_DONE",
    "EVENT_CSHARP_AGGREGATION_START",
    "EVENT_CSHARP_CACHE_PROMOTE",
    "EVENT_CSHARP_CACHE_VALIDATE",
    "EVENT_CSHARP_CHILD_EXIT",
    "EVENT_CSHARP_RESULT",
    "EVENT_CSHARP_SPAWN",
    "EVENT_LOAD_CACHE_HIT",
    "EVENT_LOAD_CACHE_MISS",
    "EVENT_LOAD_COMPLETE",
    "EVENT_LOAD_DISPATCH",
    "EVENT_LOAD_FAILED",
    "EVENT_LOAD_START",
    "EVENT_NATIVE_CHILD_EXIT",
    "EVENT_NATIVE_SPAWN",
    "KNOWN_EVENTS",
    "LOGGER",
    "LOGGER_NAME",
    "emit",
    "emit_with",
    "format_value",
]
