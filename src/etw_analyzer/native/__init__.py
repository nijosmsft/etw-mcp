"""Native ETW consumer (Phase N1).

This package replaces the ``xperf -a dumper`` subprocess pipeline with a
direct ETW consumer built on ``OpenTraceW`` / ``ProcessTrace``.

In Phase N1 only the consumer plumbing, ctypes bindings, and a minimal
``SampledProfile`` decoder are wired up. Manifest-provider decoding via
TDH lands in Phase N2 alongside the kernel MOF table.

Public API
----------
* :class:`EtwConsumer` — open + run + close a single trace.
* :func:`extract_events` — drop-in equivalent of
  ``parse_dumper_events``; returns the same ``{class_name: DataFrame}``
  shape so the trace-management code does not need to special-case mode.
* :func:`is_available` — cheap availability check used by
  ``mode="auto"`` resolution in ``load_trace``.
* :exc:`NativeConsumerError` — raised when the underlying ETW APIs fail.

Importing this package on a non-Windows host does *not* immediately fail
— the DLL loads are deferred to the moment something is actually used.
``is_available`` returns ``False`` in that case.
"""

from __future__ import annotations

from .consumer import (
    ConsumerStats,
    EtwConsumer,
    NativeConsumerError,
    is_available,
)
from .extract import (
    CANONICAL_EVENT_CLASSES,
    ExtractStats,
    count_events_by_provider,
    extract_events,
)


__all__ = [
    "EtwConsumer",
    "ConsumerStats",
    "NativeConsumerError",
    "is_available",
    "extract_events",
    "count_events_by_provider",
    "CANONICAL_EVENT_CLASSES",
    "ExtractStats",
]
