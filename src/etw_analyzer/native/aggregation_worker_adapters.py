"""Dotnet-sidecar → native-aggregator schema adapters.

The .NET sidecar (``etw-extract.exe``) writes per-event-class parquets
whose column names follow the layer-2 schema in
``dotnet/docs/event-class-mapping.md`` — notably ``TimeStampQpc`` (raw
QPC ticks) instead of the legacy ``TimeStamp`` column the in-tree
native aggregators were written against.

Rather than modify every aggregator to be schema-aware, this module
provides thin in-place adapters that normalize sidecar DataFrames to
what ``etw_analyzer.native.aggregators.*`` expects. The adapters are
called from :mod:`etw_analyzer.native.aggregation_worker` immediately
after the sidecar parquets are loaded and before the aggregators run.

Per the Phase A plan
(``manager-log/dotnet-parity-exploration.md`` §5):

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
class DotnetMetadata:
    """Header-equivalent metadata derived from the sidecar manifest."""

    cpu_count: int | None = None
    duration_seconds: float | None = None
    timestamp_frequency: float | None = None


def normalize_dotnet_dataframe(df: pd.DataFrame | None) -> pd.DataFrame | None:
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


def normalize_dotnet_trace(trace: TraceData) -> None:
    """Apply the column rename to every sidecar-loaded DataFrame on ``trace``.

    Mutates ``trace.dumper_df`` / ``trace.cswitch_events_df`` /
    ``trace.raw_csv`` in place. Safe to call multiple times.
    """
    normalize_dotnet_dataframe(trace.dumper_df)
    normalize_dotnet_dataframe(trace.cswitch_events_df)
    for key, df in list(trace.raw_csv.items()):
        if isinstance(df, pd.DataFrame):
            normalize_dotnet_dataframe(df)


def derive_metadata_from_sidecar(
    trace: TraceData,
    sidecar_manifest: native_cache.CacheManifest,
) -> DotnetMetadata:
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

    return DotnetMetadata(
        cpu_count=cpu_count,
        duration_seconds=duration_seconds,
        timestamp_frequency=timestamp_frequency,
    )


def apply_metadata_to_trace(
    trace: TraceData, metadata: DotnetMetadata
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
    metadata: DotnetMetadata,
    sidecar_manifest: native_cache.CacheManifest,
    *,
    eventtrace_header_df: pd.DataFrame | None = None,
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

    Phase B: when ``eventtrace_header_df`` is provided (single-row
    parquet from the sidecar) the StartTime / EndTime / TimerResolution
    / CpuSpeedInMHz / EventsLost / BuffersWritten / PointerSize columns
    are filled from the authoritative kernel header instead of being
    emitted as zero.
    """
    extra = _extract_eventtrace_header_extras(eventtrace_header_df)
    return pd.DataFrame([
        {
            "NumberOfProcessors": int(metadata.cpu_count or 0),
            "StartTime": int(extra.get("StartTime", 0)),
            "EndTime": int(extra.get("EndTime", 0)),
            "DurationSeconds": (
                float(metadata.duration_seconds)
                if metadata.duration_seconds
                else None
            ),
            "PerfFreq": int(metadata.timestamp_frequency or 0),
            "TimerResolution": int(extra.get("TimerResolution", 0)),
            "CpuSpeedInMHz": int(extra.get("CpuSpeedInMHz", 0)),
            "EventsLost": int(extra.get("EventsLost", 0)),
            "BuffersLost": 0,
            "BuffersWritten": int(extra.get("BuffersWritten", 0)),
            "PointerSize": int(extra.get("PointerSize", 8)),
        }
    ])


def _extract_eventtrace_header_extras(
    df: pd.DataFrame | None,
) -> dict[str, int]:
    """Pull non-metadata fields from the eventtrace_header parquet.

    Returns 0/8 defaults when ``df`` is None / empty / missing columns
    so the caller can splat the dict into the trace_metadata row.
    """
    if df is None or df.empty:
        return {}
    row = df.iloc[0]
    out: dict[str, int] = {}
    for src, dst in (
        ("StartTime100Ns", "StartTime"),
        ("EndTime100Ns", "EndTime"),
        ("TimerResolution", "TimerResolution"),
        ("CpuSpeedMHz", "CpuSpeedInMHz"),
        ("EventsLost", "EventsLost"),
        ("BuffersWritten", "BuffersWritten"),
        ("PointerSize", "PointerSize"),
    ):
        if src in df.columns:
            try:
                out[dst] = int(row[src] or 0)
            except (TypeError, ValueError):
                out[dst] = 0
    return out


def populate_event_counts_from_manifest(
    trace: TraceData, sidecar_manifest: native_cache.CacheManifest
) -> None:
    """Seed ``trace.event_counts`` from manifest ``row_count`` per dataset.

    ``build_tracestats_text`` (aggregators/tracestats.py) falls back to
    ``trace.event_counts`` when no ``ExtractStats`` is present, which is
    always the case under ``mode="dotnet"``. Populating counts here
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
    "DotnetMetadata",
    "normalize_dotnet_dataframe",
    "normalize_dotnet_trace",
    "derive_metadata_from_sidecar",
    "apply_metadata_to_trace",
    "build_trace_metadata_dataframe",
    "populate_event_counts_from_manifest",
    # Phase B per-opcode adapters.
    "adapt_dotnet_dpc_dataframe",
    "PHASE_B_DPC_STEMS",
    "adapt_dotnet_process_dataframe",
    "PHASE_B_PROCESS_STEMS",
    "adapt_dotnet_thread_dataframe",
    "PHASE_B_THREAD_STEMS",
    "adapt_dotnet_sampled_profile_dataframe",
    "adapt_dotnet_diskio_dataframe",
    "PHASE_B_DISKIO_STEMS",
    "adapt_dotnet_image_dataframe",
    "PHASE_B_IMAGE_STEMS",
    "build_symbolizer_from_dotnet_images",
    "eventtrace_header_to_metadata",
]


# ----- Phase B: per-opcode kernel-meta adapters --------------------------
#
# The sidecar (Phase B build, 39.9 MB) writes per-opcode parquets for
# kernel-meta event classes. Column names follow the layer-2 schema
# documented in dotnet/docs/event-class-mapping.md, which intentionally
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


def adapt_dotnet_dpc_dataframe(
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


def adapt_dotnet_process_dataframe(df: pd.DataFrame | None) -> pd.DataFrame | None:
    """Adapt a Phase B process_* parquet to the process_info schema.

    Phase B columns: ``EventSequence, TimeStampQpc, CPU, PID, ParentPID,
    ImageFileName, CommandLine``.

    The native ``process_info`` aggregator reads ``ProcessId``,
    ``ParentId``, ``SessionId``, ``ImageFileName``, ``CommandLine``,
    ``TimeStamp``. Map PID -> ProcessId, ParentPID -> ParentId, and
    synthesise SessionId=0 (the sidecar does not decode session IDs —
    documented in dotnet/docs/event-class-mapping.md). TimeStampQpc ->
    TimeStamp is the same rename ``normalize_dotnet_dataframe`` does.

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


# Phase B per-opcode stems that feed the SampledProfile-aware
# enrichment used by cpu_sampling / stacks. The sidecar emits
# ``thread_{start,end,dcstart,dcend}`` with ``PID``/``TID`` (matching
# the Phase B process schema), but
# ``profile_detail._build_tid_to_pid_map_from_raw_csv`` and the cswitch
# enrichment helpers expect ``ProcessId``/``ThreadId`` (matching the
# native MOF handler shape). Without this adapter the TID→PID map comes
# out empty and every SampledProfile row collapses into
# ``Process Name='unknown', PID=0`` — see
# ``manager-log/sampledprofile-attribution-finding.md``.
PHASE_B_THREAD_STEMS: dict[str, str] = {
    "thread_start":   "Thread/Start",
    "thread_end":     "Thread/End",
    "thread_dcstart": "Thread/DCStart",
    "thread_dcend":   "Thread/DCEnd",
}


def adapt_dotnet_thread_dataframe(df: pd.DataFrame | None) -> pd.DataFrame | None:
    """Adapt a Phase B thread_* parquet to the TID→PID-map schema.

    Phase B columns: ``EventSequence, TimeStampQpc, CPU, PID, TID,
    ImageFileName?, ...``. The aggregator helpers that consume
    Thread/Start / Thread/DCStart rows
    (``profile_detail._build_tid_to_pid_map_from_raw_csv``,
    cswitch readythread joins) require ``ProcessId`` and ``ThreadId``.

    Returns the same DataFrame (mutated) for chaining; ``None`` /
    empty inputs are returned unchanged. Idempotent when applied to an
    already-native-shape DataFrame.
    """

    if df is None or df.empty:
        return df
    rename_map: dict[str, str] = {}
    if "TimeStampQpc" in df.columns and "TimeStamp" not in df.columns:
        rename_map["TimeStampQpc"] = "TimeStamp"
    if "PID" in df.columns and "ProcessId" not in df.columns:
        rename_map["PID"] = "ProcessId"
    if "TID" in df.columns and "ThreadId" not in df.columns:
        rename_map["TID"] = "ThreadId"
    if rename_map:
        df = df.rename(columns=rename_map)
    return df


def adapt_dotnet_sampled_profile_dataframe(
    df: pd.DataFrame | None,
) -> pd.DataFrame | None:
    """Adapt a Phase B sampled_profile parquet to the cpu_sampling schema.

    Phase B columns: ``EventSequence, TimeStampQpc, CPU, ProcessId,
    ThreadId, PayloadThreadId, InstructionPointer, Weight, ProfileWeight,
    Stack``.

    The native cpu_sampling / stacks aggregators read ``PID`` (not
    ``ProcessId``) — the in-tree MOF handlers emit ``PID`` on
    SampledProfile rows even though they emit ``ProcessId`` on Process
    rows. The sidecar is consistently camelCase (``ProcessId``), so we
    rename to bridge to the aggregator's expectation. Without this
    rename, the process-name lookup in
    ``profile_detail.enrich_sampled_profile_attribution`` (gated on
    ``if "PID" in df.columns``) silently falls through and every row
    collapses into ``Process Name='unknown'``. See
    ``manager-log/sampledprofile-attribution-finding.md`` for the full
    chain of failure.

    ``ThreadId`` and ``PayloadThreadId`` are intentionally left alone:
    the aggregator reads ``PayloadThreadId`` directly, and the native
    MOF shape carries both columns under the same names.

    Returns the same DataFrame (mutated) for chaining; ``None`` /
    empty inputs are returned unchanged. Idempotent when applied to an
    already-native-shape DataFrame (already-PID DataFrames pass
    through).
    """

    if df is None or df.empty:
        return df
    rename_map: dict[str, str] = {}
    if "TimeStampQpc" in df.columns and "TimeStamp" not in df.columns:
        rename_map["TimeStampQpc"] = "TimeStamp"
    if "ProcessId" in df.columns and "PID" not in df.columns:
        rename_map["ProcessId"] = "PID"
    if rename_map:
        df = df.rename(columns=rename_map)
    return df


# Phase B per-opcode stems that feed the diskio aggregator.
PHASE_B_DISKIO_STEMS: dict[str, str] = {
    "diskio_read":         "DiskIo/Read",
    "diskio_write":        "DiskIo/Write",
    "diskio_flushbuffers": "DiskIo/FlushBuffers",
}


def adapt_dotnet_diskio_dataframe(df: pd.DataFrame | None) -> pd.DataFrame | None:
    """Adapt a Phase B diskio_* parquet to the diskio aggregator schema.

    Phase B columns vary by opcode but generally include ``DiskNumber``
    and ``TransferSize`` already in the schema the in-tree aggregator
    expects. Only the ``TimeStampQpc -> TimeStamp`` rename is needed
    today; documented as its own adapter so the field stems still match
    the other adapters' surface, and so future schema drift has a
    single place to land.

    Important: the test fixture used by the Phase B smoke run has
    **zero disk events**, so the corresponding parquets are absent
    rather than empty (per the sidecar's gating policy). Callers must
    treat absence as a no-op, not an error.
    """

    if df is None or df.empty:
        return df
    if "TimeStampQpc" in df.columns and "TimeStamp" not in df.columns:
        df = df.rename(columns={"TimeStampQpc": "TimeStamp"})
    return df


# Phase B per-opcode stems that feed the symbolizer.
PHASE_B_IMAGE_STEMS: dict[str, str] = {
    "image_load":    "Image/Load",
    "image_dcstart": "Image/DCStart",
}


def adapt_dotnet_image_dataframe(df: pd.DataFrame | None) -> pd.DataFrame | None:
    """Adapt a Phase B image_* parquet to the symbolizer-input schema.

    Phase B columns: ``EventSequence, TimeStampQpc, CPU, PID, ImageBase,
    ImageSize, TimeDateStamp, FileName``.

    The native symbolizer (``_build_symbolizer_from_images``) reads
    ``ImageBase``, ``ImageSize``, and ``FileName`` straight from each
    row — all three Phase B names already match. Only the TimeStampQpc
    rename is done so the row also satisfies the canonical
    ``TimeStamp`` contract used elsewhere in the trace.
    """

    if df is None or df.empty:
        return df
    if "TimeStampQpc" in df.columns and "TimeStamp" not in df.columns:
        df = df.rename(columns={"TimeStampQpc": "TimeStamp"})
    return df


def build_symbolizer_from_dotnet_images(trace) -> bool:
    """Build a dbghelp-backed Symbolizer from Phase B image parquets.

    Reads ``trace.raw_csv['Image/Load']`` and ``trace.raw_csv['Image/DCStart']``
    (whichever are present), deduplicates by ImageBase, and registers
    every module with the symbolizer so subsequent
    ``aggregate_stack_butterfly`` calls can resolve addresses.

    On a dotnet cache hit, the sidecar's combined image parquet is keyed
    by stem (``raw_csv["image"]``) rather than by canonical class name.
    If neither canonical key has any rows, this function falls back to
    ``raw_csv["image"]`` automatically. That combined form contains both
    Load and DCStart rows; either is sufficient because only
    (ImageBase, ImageSize, FileName) are needed for module registration.

    Returns True when a symbolizer was installed (already-present
    counts as success), False when:
      * the native Symbolizer module isn't importable (no Windows
        dbghelp, or a unit-test environment), OR
      * none of Image/Load, Image/DCStart, or image has any rows.

    This is the dotnet equivalent of trace_mgmt._build_symbolizer_from_images
    (which the native path calls during the in-process consumer's
    Image/Load fan-out). Kept here rather than reusing the trace_mgmt
    helper directly because the dotnet path doesn't go through
    _start_background_dumper and we want a clear chain of dotnet-
    specific helpers in this module.
    """

    if getattr(trace, "symbolizer", None) is not None:
        return True

    try:
        from etw_analyzer.native import Symbolizer
    except (ImportError, OSError):
        return False

    rows: list[dict] = []
    for canonical in ("Image/Load", "Image/DCStart"):
        df = trace.raw_csv.get(canonical)
        if df is None or df.empty:
            continue
        for row in df.to_dict(orient="records"):
            rows.append(row)
    if not rows:
        # Cache-hit path: the sidecar's combined "image" parquet is keyed
        # by stem rather than canonical class. It contains both Load and
        # DCStart rows distinguished by the "Kind" column; either is fine
        # for the symbolizer because we only need (ImageBase, ImageSize,
        # FileName) and dedup by base.
        combined = trace.raw_csv.get("image")
        if combined is not None and not combined.empty:
            for row in combined.to_dict(orient="records"):
                rows.append(row)

    if not rows:
        return False

    try:
        symbolizer = Symbolizer(symbol_path=getattr(trace, "symbol_path", None))
    except Exception:
        return False

    seen_bases: set[int] = set()
    for row in rows:
        try:
            base = int(row.get("ImageBase", 0) or 0)
        except (TypeError, ValueError):
            continue
        if not base or base in seen_bases:
            continue
        seen_bases.add(base)
        try:
            size = int(row.get("ImageSize", 0) or 0)
        except (TypeError, ValueError):
            size = 0
        file_name = str(row.get("FileName", "") or "")
        try:
            symbolizer.add_module(base, size, file_name)
        except Exception:
            continue

    trace.symbolizer = symbolizer
    return True


def eventtrace_header_to_metadata(
    df: pd.DataFrame | None,
) -> DotnetMetadata | None:
    """Build a DotnetMetadata from a Phase B eventtrace_header parquet.

    The sidecar's eventtrace_header parquet is a single-row table with
    the authoritative ETL kernel-header fields:

      ``PerfFreq, NumberOfProcessors, TimerResolution, StartTime100Ns,
       EndTime100Ns, BootTime100Ns, CpuSpeedMHz, PointerSize,
       LogFileMode, BuffersWritten, EventsLost, SessionName,
       LogFileName``

    When present, these REPLACE the heuristic derivation
    (max(CPU)+1 + QPC-range / 10 MHz) that ``derive_metadata_from_sidecar``
    fell back to in Phase A. Per P1's handoff the
    StartTime100Ns / EndTime100Ns are FILETIME 100ns units since
    1601 UTC; duration is ``(End - Start) / 1e7`` seconds.

    Returns ``None`` when the parquet is None / empty / missing required
    columns, so callers can fall through to the heuristic path.
    """

    if df is None or df.empty:
        return None
    row = df.iloc[0]
    try:
        perf_freq = float(row.get("PerfFreq", 0) or 0)
    except (TypeError, ValueError):
        perf_freq = 0.0
    try:
        cpu_count = int(row.get("NumberOfProcessors", 0) or 0)
    except (TypeError, ValueError):
        cpu_count = 0
    try:
        start_100ns = int(row.get("StartTime100Ns", 0) or 0)
    except (TypeError, ValueError):
        start_100ns = 0
    try:
        end_100ns = int(row.get("EndTime100Ns", 0) or 0)
    except (TypeError, ValueError):
        end_100ns = 0

    duration: float | None = None
    if end_100ns > start_100ns > 0:
        # FILETIME 100ns ticks since 1601 UTC; (delta) / 10^7 == seconds.
        duration = (end_100ns - start_100ns) / 10_000_000.0

    if not (perf_freq or cpu_count or duration):
        # Nothing usable — let the heuristic path try.
        return None

    return DotnetMetadata(
        cpu_count=cpu_count or None,
        duration_seconds=duration,
        timestamp_frequency=perf_freq or None,
    )
