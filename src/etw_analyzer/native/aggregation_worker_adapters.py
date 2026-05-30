"""Csharp-sidecar → native-aggregator schema adapters.

The C# sidecar (``wpr-mcp-extract.exe``) writes per-event-class parquets
whose column names follow the layer-2 schema in
``csharp/docs/event-class-mapping.md`` — notably ``TimeStampQpc`` (raw
QPC ticks) instead of the legacy ``TimeStamp`` column the in-tree
native aggregators were written against.

Rather than modify every aggregator to be schema-aware, this module
provides thin in-place adapters that normalize sidecar DataFrames to
what ``etw_analyzer.native.aggregators.*`` expects. The adapters are
called from :mod:`etw_analyzer.native.aggregation_worker` immediately
after the sidecar parquets are loaded and before the aggregators run.

Per the Phase A plan
(``manager-log/csharp-parity-exploration.md`` §5):

* **DO NOT** modify the native aggregator functions themselves — they
  continue to run unmodified under ``mode="native"``.
* **DO** keep the adapters small and reversible; a future cache
  rehydrate must not see double-renamed columns.
* **DO** also synthesize the ancillary metadata the aggregators read
  off ``TraceData`` (duration, cpu_count, perf_freq) — the sidecar
  carries the QPC timestamps but the per-event-class parquets do not
  carry the header. We derive what we can from the QPC range and the
  v3 manifest.

This module has no I/O — it operates on already-loaded DataFrames and
the parsed :class:`native_cache.CacheManifest`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import pandas as pd

from etw_analyzer.native import cache as native_cache
from etw_analyzer.trace_state import TraceData


# Sidecar parquets emit ``TimeStampQpc`` (per ``schemas.EVENT_SCHEMAS``);
# the native worker emits ``TimeStamp`` (per the mof handlers). The native
# aggregators (profile_util.aggregate_cpu_timeline,
# stack_butterfly.aggregate_stack_butterfly, etc.) read ``TimeStamp``.
# When both names are present (e.g. a cross-mode reload) we prefer the
# existing ``TimeStamp`` and leave the QPC column alone.
_TIMESTAMP_SOURCE = "TimeStampQpc"
_TIMESTAMP_TARGET = "TimeStamp"


@dataclass
class CsharpMetadata:
    """Header-equivalent metadata derived from the sidecar manifest."""

    cpu_count: int | None = None
    duration_seconds: float | None = None
    timestamp_frequency: float | None = None


def normalize_csharp_dataframe(df: pd.DataFrame | None) -> pd.DataFrame | None:
    """Rename ``TimeStampQpc`` → ``TimeStamp`` if needed, in place.

    Returns the same DataFrame for chaining. ``None`` propagates.
    No-op when ``TimeStamp`` already exists (cross-mode reload) or
    ``TimeStampQpc`` is absent (already adapted / non-sidecar source).
    """
    if df is None or df.empty:
        return df
    if _TIMESTAMP_TARGET in df.columns:
        return df
    if _TIMESTAMP_SOURCE not in df.columns:
        return df
    df.rename(columns={_TIMESTAMP_SOURCE: _TIMESTAMP_TARGET}, inplace=True)
    return df


def normalize_csharp_trace(trace: TraceData) -> None:
    """Apply the column rename to every sidecar-loaded DataFrame on ``trace``.

    Mutates ``trace.dumper_df`` / ``trace.cswitch_events_df`` /
    ``trace.raw_csv`` in place. Safe to call multiple times.
    """
    normalize_csharp_dataframe(trace.dumper_df)
    normalize_csharp_dataframe(trace.cswitch_events_df)
    for key, df in list(trace.raw_csv.items()):
        if isinstance(df, pd.DataFrame):
            normalize_csharp_dataframe(df)


def derive_metadata_from_sidecar(
    trace: TraceData,
    sidecar_manifest: native_cache.CacheManifest,
) -> CsharpMetadata:
    """Derive header-equivalent metadata from sidecar parquets + manifest.

    The sidecar doesn't yet emit ``EventTrace/Header`` so the trace's
    ``duration_seconds`` / ``cpu_count`` / ``timestamp_frequency``
    cannot be filled from the header rundown. Best-effort derivation:

    * **cpu_count** — ``max(CPU) + 1`` across SampledProfile + CSwitch
      (the two streams the sidecar emits today that carry per-event CPU).
    * **duration_seconds** — ``(QPC_max - QPC_min) / perf_freq`` if a
      ``perf_freq`` can be inferred. With no header rundown we default
      ``perf_freq`` to 10 MHz (the same default
      ``profile_util._timeline_metadata`` uses when nothing else is
      known). Caller can override later if the sidecar starts emitting
      EventTrace/Header.
    * **timestamp_frequency** — 10 MHz default; the QPC frequency is a
      hardware-defined constant that's also missing from sidecar output
      today.

    The defaults match what ``profile_util.aggregate_cpu_timeline``
    falls back to internally, so even when the metadata can't be
    derived the aggregator still produces a usable timeline.
    """

    cpu_count = _max_cpu_plus_one(trace)
    qpc_min, qpc_max = _qpc_range(trace)

    # 10 MHz is the canonical default — it's the resolution of the
    # Windows performance counter on most platforms and matches what
    # the existing ``_timeline_metadata`` fallback uses when both
    # ``trace.timestamp_frequency`` and ``trace_metadata.PerfFreq``
    # are absent (see profile_util.py:140-141).
    timestamp_frequency = 10_000_000.0

    duration_seconds: float | None = None
    if qpc_min is not None and qpc_max is not None and qpc_max > qpc_min:
        duration_seconds = (qpc_max - qpc_min) / timestamp_frequency

    return CsharpMetadata(
        cpu_count=cpu_count,
        duration_seconds=duration_seconds,
        timestamp_frequency=timestamp_frequency,
    )


def apply_metadata_to_trace(
    trace: TraceData, metadata: CsharpMetadata
) -> None:
    """Populate the metadata fields the aggregators read off ``TraceData``.

    Only fills fields that are currently unset — never overwrites a
    value that came from a real header or a previous reload.
    """
    if trace.cpu_count is None and metadata.cpu_count:
        trace.cpu_count = metadata.cpu_count
    if trace.duration_seconds is None and metadata.duration_seconds:
        trace.duration_seconds = metadata.duration_seconds
    if (
        trace.timestamp_frequency is None
        and metadata.timestamp_frequency
    ):
        trace.timestamp_frequency = metadata.timestamp_frequency


def build_trace_metadata_dataframe(
    metadata: CsharpMetadata,
    sidecar_manifest: native_cache.CacheManifest,
) -> pd.DataFrame:
    """Build a one-row ``trace_metadata`` DataFrame matching native schema.

    Columns mirror ``_native_metadata_rows`` in
    ``tools/trace_mgmt.py``: ``NumberOfProcessors``, ``StartTime``,
    ``EndTime``, ``DurationSeconds``, ``PerfFreq``, ``TimerResolution``,
    ``CpuSpeedInMHz``, ``EventsLost``, ``BuffersLost``,
    ``BuffersWritten``, ``PointerSize``. Anything the sidecar doesn't
    expose is emitted as 0 / None so downstream consumers (e.g.
    ``tracestats._metadata_lines``, ``profile_util._timeline_metadata``)
    can still distinguish "known zero" from "missing".
    """
    return pd.DataFrame([
        {
            "NumberOfProcessors": int(metadata.cpu_count or 0),
            "StartTime": 0,
            "EndTime": 0,
            "DurationSeconds": (
                float(metadata.duration_seconds)
                if metadata.duration_seconds
                else None
            ),
            "PerfFreq": int(metadata.timestamp_frequency or 0),
            "TimerResolution": 0,
            "CpuSpeedInMHz": 0,
            "EventsLost": 0,
            "BuffersLost": 0,
            "BuffersWritten": 0,
            "PointerSize": 8,
        }
    ])


def populate_event_counts_from_manifest(
    trace: TraceData, sidecar_manifest: native_cache.CacheManifest
) -> None:
    """Seed ``trace.event_counts`` from manifest ``row_count`` per dataset.

    ``build_tracestats_text`` (aggregators/tracestats.py) falls back to
    ``trace.event_counts`` when no ``ExtractStats`` is present, which is
    always the case under ``mode="csharp"``. Populating counts here
    means the existing aggregator emits a meaningful provider-counts
    block without modification.
    """
    for dataset in sidecar_manifest.datasets:
        if dataset.row_count is None:
            continue
        # Only seed if not already populated by a real DataFrame load.
        # ``_populate_metadata`` later does ``event_counts[name] = len(df)``
        # for everything in ``raw_csv``; we don't want to overwrite that
        # with the manifest value for keys already present (the
        # in-memory row count is the source of truth there).
        if dataset.name not in trace.event_counts:
            trace.event_counts[dataset.name] = int(dataset.row_count)


# ---- internal helpers --------------------------------------------------


def _max_cpu_plus_one(trace: TraceData) -> int | None:
    candidates: list[int] = []
    for df in _candidate_dataframes(trace):
        if df is None or df.empty or "CPU" not in df.columns:
            continue
        try:
            value = pd.to_numeric(df["CPU"], errors="coerce").dropna()
        except Exception:
            continue
        if value.empty:
            continue
        try:
            candidates.append(int(value.max()))
        except (ValueError, TypeError):
            continue
    if not candidates:
        return None
    return max(candidates) + 1


def _qpc_range(trace: TraceData) -> tuple[int | None, int | None]:
    mins: list[int] = []
    maxes: list[int] = []
    for df in _candidate_dataframes(trace):
        if df is None or df.empty:
            continue
        column = None
        if _TIMESTAMP_SOURCE in df.columns:
            column = _TIMESTAMP_SOURCE
        elif _TIMESTAMP_TARGET in df.columns:
            column = _TIMESTAMP_TARGET
        if column is None:
            continue
        try:
            values = pd.to_numeric(df[column], errors="coerce").dropna()
        except Exception:
            continue
        if values.empty:
            continue
        try:
            mins.append(int(values.min()))
            maxes.append(int(values.max()))
        except (ValueError, TypeError):
            continue
    if not mins or not maxes:
        return (None, None)
    return (min(mins), max(maxes))


def _candidate_dataframes(trace: TraceData) -> Iterable[pd.DataFrame | None]:
    yield trace.dumper_df
    yield trace.cswitch_events_df
    # Also look at all the per-class network DataFrames the sidecar
    # might have populated.
    for key, df in trace.raw_csv.items():
        if key.startswith("_"):
            continue
        if isinstance(df, pd.DataFrame):
            yield df


__all__ = [
    "CsharpMetadata",
    "normalize_csharp_dataframe",
    "normalize_csharp_trace",
    "derive_metadata_from_sidecar",
    "apply_metadata_to_trace",
    "build_trace_metadata_dataframe",
    "populate_event_counts_from_manifest",
    # Phase B per-opcode adapters.
    "adapt_csharp_dpc_dataframe",
    "PHASE_B_DPC_STEMS",
    "adapt_csharp_process_dataframe",
    "PHASE_B_PROCESS_STEMS",
]


# ----- Phase B: per-opcode kernel-meta adapters --------------------------
#
# The sidecar (Phase B build, 39.9 MB) writes per-opcode parquets for
# kernel-meta event classes. Column names follow the layer-2 schema
# documented in csharp/docs/event-class-mapping.md, which intentionally
# differs from the native MOF-handler shape the in-tree aggregators were
# written against. These adapters do the column-rename / column-synthesis
# work so the same aggregator code can consume both producers.
#
# Track P1 chose:
#   * sidecar process/thread rows use PID / ParentPID / TID,
#     not ProcessId / ParentId / ThreadId;
#   * sidecar DPC/ISR rows carry ElapsedMicros (the already-computed
#     duration in microseconds), not a separate InitialTime column;
#   * sidecar process rows do NOT carry SessionId at all
#     (a documented Phase B limitation; the native worker derives
#     SessionId from a separate manifest event we have no plans to add).
#
# We DO NOT modify the aggregators themselves — these adapters keep the
# Phase A "thin in-place rename" contract intact.


# Phase B per-opcode stems that feed the DPC/ISR aggregator. Track P2
# concatenates these into raw_csv[<canonical event class>] before the
# aggregator runs, so the existing _gather_dpc_events fallback path
# (which iterates _DPC_CLASSES) finds rows.
PHASE_B_DPC_STEMS: dict[str, str] = {
    "perfinfo_dpc":          "PerfInfo/DPC",
    "perfinfo_threaded_dpc": "PerfInfo/ThreadedDPC",
    "perfinfo_timer_dpc":    "PerfInfo/TimerDPC",
    "perfinfo_isr":          "PerfInfo/ISR",
}


def adapt_csharp_dpc_dataframe(
    df: pd.DataFrame | None,
    *,
    perf_freq_hz: float = 10_000_000.0,
) -> pd.DataFrame | None:
    """Adapt a Phase B perfinfo_* parquet to the dpc_isr aggregator schema.

    Phase B columns: ``EventSequence, TimeStampQpc, CPU, Routine,
    ElapsedMicros``.

    The native aggregator (``aggregators/dpcisr.py``) requires
    ``{"TimeStamp", "CPU", "Routine", "InitialTime"}`` and computes the
    per-event duration as ``(TimeStamp - InitialTime) * 1e6 / perf_freq``.
    To re-use that code path unchanged, we synthesise ``InitialTime`` as
    ``TimeStamp - ElapsedMicros * perf_freq / 1e6`` — i.e. we project the
    already-computed duration back onto the QPC timeline. The aggregator
    then recomputes the same number and gets ElapsedMicros back. This
    keeps the duration math in one place (the aggregator) and avoids a
    parallel division-by-QPC code path in the adapter.

    Returns the same DataFrame (mutated) for chaining. ``None`` and empty
    DataFrames pass through unchanged.
    """

    if df is None or df.empty:
        return df
    if "TimeStamp" not in df.columns and "TimeStampQpc" in df.columns:
        df = df.rename(columns={"TimeStampQpc": "TimeStamp"})
    # ElapsedMicros → InitialTime synth. If ElapsedMicros is absent the
    # sidecar didn't emit it (older builds), and InitialTime is left
    # missing — the aggregator silently drops rows that don't satisfy
    # the column-set check.
    if (
        "InitialTime" not in df.columns
        and "ElapsedMicros" in df.columns
        and "TimeStamp" in df.columns
    ):
        ticks_per_us = max(1.0, float(perf_freq_hz) / 1_000_000.0)
        elapsed_ticks = pd.to_numeric(df["ElapsedMicros"], errors="coerce") * ticks_per_us
        df["InitialTime"] = (
            pd.to_numeric(df["TimeStamp"], errors="coerce") - elapsed_ticks
        )
    return df


# Phase B per-opcode stems that feed the process_info aggregator.
PHASE_B_PROCESS_STEMS: dict[str, str] = {
    "process_start":    "Process/Start",
    "process_end":      "Process/End",
    "process_dcstart":  "Process/DCStart",
    "process_dcend":    "Process/DCEnd",
    "process_defunct":  "Process/Defunct",
}


def adapt_csharp_process_dataframe(df: pd.DataFrame | None) -> pd.DataFrame | None:
    """Adapt a Phase B process_* parquet to the process_info schema.

    Phase B columns: ``EventSequence, TimeStampQpc, CPU, PID, ParentPID,
    ImageFileName, CommandLine``.

    The native ``process_info`` aggregator reads ``ProcessId``,
    ``ParentId``, ``SessionId``, ``ImageFileName``, ``CommandLine``,
    ``TimeStamp``. Map PID -> ProcessId, ParentPID -> ParentId, and
    synthesise SessionId=0 (the sidecar does not decode session IDs —
    documented in csharp/docs/event-class-mapping.md). TimeStampQpc ->
    TimeStamp is the same rename ``normalize_csharp_dataframe`` does.

    Returns the same DataFrame (mutated) for chaining; ``None`` /
    empty inputs are returned unchanged.
    """

    if df is None or df.empty:
        return df
    rename_map: dict[str, str] = {}
    if "TimeStampQpc" in df.columns and "TimeStamp" not in df.columns:
        rename_map["TimeStampQpc"] = "TimeStamp"
    if "PID" in df.columns and "ProcessId" not in df.columns:
        rename_map["PID"] = "ProcessId"
    if "ParentPID" in df.columns and "ParentId" not in df.columns:
        rename_map["ParentPID"] = "ParentId"
    if rename_map:
        df = df.rename(columns=rename_map)
    if "SessionId" not in df.columns:
        df["SessionId"] = 0
    return df
