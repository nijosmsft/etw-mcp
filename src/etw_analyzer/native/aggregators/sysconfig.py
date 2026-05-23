"""Aggregator: ``sysconfig`` raw-text — replacement for ``xperf -a sysconfig``.

xperf's sysconfig output is a free-form text dump of system metadata
(CPU, NICs, disks, services, ...). The Phase N2 SystemConfig MOF
handler emits one row per SystemConfig opcode with a human-readable
name (CPU/NIC/PhyDisk/Power/…) and the opcode's payload byte length.

For Phase N4 we wrap those rows, plus any native ``trace_metadata``
header fields, into the single-row ``raw_text`` DataFrame shape the
existing trace loader uses for raw text outputs.

If the trace was collected without rundown events and no ETL header
metadata is available, this returns ``None``.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Optional

import pandas as pd

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


def _positive_int(value) -> int | None:
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _positive_float(value) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _first_numeric(df: pd.DataFrame | None, column: str, *, integer: bool = True):
    if df is None or df.empty or column not in df.columns:
        return None
    values = pd.to_numeric(df[column], errors="coerce").dropna()
    values = values[values > 0]
    if values.empty:
        return None
    value = values.iloc[0]
    return int(value) if integer else float(value)


def _metadata_values(trace: "TraceData") -> dict[str, int | float]:
    """Collect header metadata exposed by native trace loading."""
    raw_csv = getattr(trace, "raw_csv", {}) or {}
    values: dict[str, int | float] = {}

    cpu_count = getattr(trace, "cpu_count", None)
    if (cpu := _positive_int(cpu_count)) is not None:
        values["ProcessorNum"] = cpu
    duration = getattr(trace, "duration_seconds", None)
    if (dur := _positive_float(duration)) is not None:
        values["DurationSeconds"] = dur

    trace_metadata = raw_csv.get("trace_metadata")
    if "ProcessorNum" not in values:
        cpu = _first_numeric(trace_metadata, "NumberOfProcessors")
        if cpu is not None:
            values["ProcessorNum"] = cpu
    if "DurationSeconds" not in values:
        duration = _first_numeric(trace_metadata, "DurationSeconds", integer=False)
        if duration is not None:
            values["DurationSeconds"] = duration

    for source in (trace_metadata, raw_csv.get("EventTrace/Header")):
        for out_key, column in (
            ("ProcessorSpeed", "CpuSpeedInMHz"),
            ("TimerResolution", "TimerResolution"),
            ("PointerSize", "PointerSize"),
            ("EventsLost", "EventsLost"),
            ("BuffersLost", "BuffersLost"),
            ("BuffersWritten", "BuffersWritten"),
        ):
            if out_key in values:
                continue
            value = _first_numeric(source, column)
            if value is not None:
                values[out_key] = value

    stats = getattr(trace, "_native_extract_stats", None)
    for item in getattr(stats, "logfile_metadata", None) or []:
        if "ProcessorNum" not in values:
            cpu = _positive_int(getattr(item, "number_of_processors", None))
            if cpu is not None:
                values["ProcessorNum"] = cpu
        if "DurationSeconds" not in values:
            duration = _positive_float(getattr(item, "duration_seconds", None))
            if duration is not None:
                values["DurationSeconds"] = duration
        for out_key, attr in (
            ("ProcessorSpeed", "cpu_speed_mhz"),
            ("TimerResolution", "timer_resolution_100ns"),
            ("PointerSize", "pointer_size"),
            ("EventsLost", "events_lost"),
            ("BuffersLost", "buffers_lost"),
            ("BuffersWritten", "buffers_written"),
        ):
            if out_key in values:
                continue
            value = _positive_int(getattr(item, attr, None))
            if value is not None:
                values[out_key] = value
    return values


def build_sysconfig_text(trace: "TraceData") -> Optional[str]:
    """Generate a sysconfig-equivalent text block.

    Returns ``None`` when no SystemConfig events or trace metadata have
    been decoded.
    """
    raw_csv = getattr(trace, "raw_csv", {}) or {}
    df = raw_csv.get("SystemConfig")
    metadata = _metadata_values(trace)
    has_sysconfig = df is not None and not df.empty and "OpcodeName" in df.columns
    if not metadata and not has_sysconfig:
        return None

    counts: Counter[str] = Counter()
    bytes_per: Counter[str] = Counter()
    if has_sysconfig:
        for _, row in df.iterrows():
            name = str(row["OpcodeName"])
            counts[name] += 1
            bytes_per[name] += int(row.get("PayloadBytes", 0) or 0)

    lines: list[str] = ["System Configuration Summary", "="]
    if metadata:
        lines.append("Trace Metadata:")
        for key in (
            "ProcessorNum",
            "ProcessorSpeed",
            "DurationSeconds",
            "TimerResolution",
            "PointerSize",
            "EventsLost",
            "BuffersLost",
            "BuffersWritten",
        ):
            if key not in metadata:
                continue
            value = metadata[key]
            if key == "DurationSeconds":
                lines.append(f"  {key}: {float(value):.7f}")
            else:
                lines.append(f"  {key}: {int(value)}")
    if counts:
        if metadata:
            lines.append("")
        lines.append("SystemConfig Records:")
        for name in sorted(counts):
            lines.append(
                f"  {name}: {counts[name]} record(s), {bytes_per[name]} byte(s) of payload"
            )
    lines.append("")
    return "\n".join(lines) + "\n"


__all__ = ["build_sysconfig_text"]
