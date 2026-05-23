"""Phase N4 aggregators — pandas-based replacements for ``xperf -a`` actions.

The Phase N1-N3 native consumer extracts *event-level* DataFrames
(SampledProfile, CSwitch, DPC, ISR, ImageLoad, Process, DiskIo, ...). The
analysis tools downstream of ``load_trace`` were built against the xperf
output: pre-aggregated DataFrames keyed by ``trace.raw_csv["cpu_sampling"]``
/ ``["cpu_timeline"]`` / ``["dpc_isr"]`` / etc.

This package closes the gap. Each module exposes a single
``aggregate_<name>(trace)`` function that takes a :class:`TraceData` with
the Phase N2 event DataFrames already populated and returns the
xperf-equivalent aggregate DataFrame (or ``None`` when the source data
isn't available).

The aggregators are intentionally small and free of I/O — they consume
in-memory DataFrames, never the .etl. ``tools.trace_mgmt`` is the only
caller and it wires the results back into ``trace.raw_csv``.
"""

from __future__ import annotations

from .profile_detail import aggregate_cpu_sampling
from .profile_util import aggregate_cpu_timeline
from .dpcisr import aggregate_dpc_isr, build_dpc_isr_raw_text
from .stack_butterfly import aggregate_stack_butterfly
from .sysconfig import build_sysconfig_text
from .process_info import build_process_info_text
from .diskio import build_diskio_text
from .tracestats import build_tracestats_text


__all__ = [
    "aggregate_cpu_sampling",
    "aggregate_cpu_timeline",
    "aggregate_dpc_isr",
    "build_dpc_isr_raw_text",
    "aggregate_stack_butterfly",
    "build_sysconfig_text",
    "build_process_info_text",
    "build_diskio_text",
    "build_tracestats_text",
]
