"""Aggregator: ``cpu_timeline`` — replacement for ``xperf -a profile`` (no -detail).

Output DataFrame schema mirrors :func:`parsing.wpa_exporter._parse_profile_utilization`::

    StartTime, EndTime, Cpu 0, Cpu 1, ..., Cpu N

Times are in microseconds — same units xperf emits. The ``Cpu <n>``
columns hold per-CPU utilization as a percent of wall time in that
bucket.

Algorithm
---------
1. Convert SampledProfile timestamps to seconds from trace start.
2. Bucket by wall-clock time and count samples per (bucket, CPU).
3. Divide by ``sample_rate_hz * bucket_width`` so sparse CPUs are
   normalized by elapsed wall time, not by only the interval in which
   they emitted samples.
4. Pivot wide and include every logical processor known from the ETL
   header so inactive CPUs show up as zero-utilization columns.

The default sample rate is 1 kHz per CPU. Current native extraction
normalizes event timestamps to xperf-relative microseconds before the
aggregator runs. The legacy raw-QPC path is still tolerated via ETL header
metadata for old in-memory test fixtures or stale caches.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import TYPE_CHECKING, Optional

import pandas as pd

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


# Default Windows kernel sampler runs at 1 kHz per CPU when the
# SampledProfile flag is enabled without an override. The actual rate
# can be tuned via ``xperf -SetProfInt`` but 1000 is the canonical default.
_DEFAULT_SAMPLE_RATE_HZ = 1000


def _extract_raw_csv_value(
    trace: "TraceData",
    dataset: str,
    column: str,
) -> float | None:
    raw_csv = getattr(trace, "raw_csv", {}) or {}
    df = raw_csv.get(dataset)
    if df is None or df.empty or column not in df.columns:
        return None
    values = pd.to_numeric(df[column], errors="coerce").dropna()
    if values.empty:
        return None
    value = float(values.iloc[0])
    return value if value > 0 else None


@dataclass(frozen=True)
class _TimelineMetadata:
    duration_s: float
    timestamp_frequency: float
    timestamp_origin: float
    cpu_count: int


def _native_logfile_metadata(trace: "TraceData") -> list:
    stats = getattr(trace, "_native_extract_stats", None)
    return list(getattr(stats, "logfile_metadata", None) or [])


def _looks_like_relative_microseconds(
    trace: "TraceData",
    timestamps: pd.Series,
    duration_s: float | None,
) -> bool:
    if getattr(trace, "mode", None) != "native":
        return False
    if duration_s is None or duration_s <= 0:
        return False
    values = pd.to_numeric(timestamps, errors="coerce").dropna()
    if values.empty:
        return False
    duration_us = duration_s * 1_000_000.0
    tolerance_us = max(1_000_000.0, duration_us * 0.05)
    return float(values.min()) >= -tolerance_us and float(values.max()) <= duration_us + tolerance_us


def _timeline_metadata(
    trace: "TraceData",
    timestamps: pd.Series,
    cpus: pd.Series,
) -> _TimelineMetadata | None:
    t_min = float(timestamps.min())
    t_max = float(timestamps.max())
    span = t_max - t_min

    duration_s = getattr(trace, "duration_seconds", None)
    if not duration_s or duration_s <= 0:
        duration_s = None

    logfile_metadata = _native_logfile_metadata(trace)
    if duration_s is None:
        duration_s = _extract_raw_csv_value(trace, "trace_metadata", "DurationSeconds")
    if duration_s is None and logfile_metadata:
        durations = [
            float(getattr(item, "duration_seconds", 0) or 0)
            for item in logfile_metadata
            if float(getattr(item, "duration_seconds", 0) or 0) > 0
        ]
        if durations:
            duration_s = max(durations)
        else:
            starts = [
                int(getattr(item, "start_time_utc_100ns", 0) or 0)
                for item in logfile_metadata
                if int(getattr(item, "start_time_utc_100ns", 0) or 0) > 0
            ]
            ends = [
                int(getattr(item, "end_time_utc_100ns", 0) or 0)
                for item in logfile_metadata
                if int(getattr(item, "end_time_utc_100ns", 0) or 0) > 0
            ]
            if starts and ends and max(ends) > min(starts):
                duration_s = (max(ends) - min(starts)) / 10_000_000.0

    timestamp_frequency = getattr(trace, "timestamp_frequency", None)
    if not timestamp_frequency or timestamp_frequency <= 0:
        timestamp_frequency = _extract_raw_csv_value(trace, "trace_metadata", "PerfFreq")
    if (not timestamp_frequency or timestamp_frequency <= 0) and logfile_metadata:
        frequencies = [
            int(getattr(item, "perf_freq", 0) or 0)
            for item in logfile_metadata
            if int(getattr(item, "perf_freq", 0) or 0) > 0
        ]
        if frequencies:
            timestamp_frequency = float(frequencies[0])
    if not timestamp_frequency or timestamp_frequency <= 0:
        timestamp_frequency = 1_000_000.0

    if duration_s is None:
        if span <= 0:
            return None
        duration_s = span / float(timestamp_frequency)

    if duration_s <= 0:
        return None

    if _looks_like_relative_microseconds(trace, timestamps, duration_s):
        timestamp_frequency = 1_000_000.0
        timestamp_origin = 0.0
    else:
        timestamp_frequency = None

        timestamp_frequency = getattr(trace, "timestamp_frequency", None)
        if not timestamp_frequency or timestamp_frequency <= 0:
            timestamp_frequency = _extract_raw_csv_value(trace, "trace_metadata", "PerfFreq")
        if (not timestamp_frequency or timestamp_frequency <= 0) and logfile_metadata:
            frequencies = [
                int(getattr(item, "perf_freq", 0) or 0)
                for item in logfile_metadata
                if int(getattr(item, "perf_freq", 0) or 0) > 0
            ]
            if frequencies:
                timestamp_frequency = float(frequencies[0])
        if not timestamp_frequency or timestamp_frequency <= 0:
            timestamp_frequency = 1_000_000.0

        timestamp_origin = _extract_raw_csv_value(trace, "EventTrace/Header", "TimeStamp")
        if timestamp_origin is None:
            timestamp_origin = t_min

    cpu_count = getattr(trace, "cpu_count", None)
    if not cpu_count or cpu_count <= 0:
        metadata_cpu_count = _extract_raw_csv_value(
            trace,
            "trace_metadata",
            "NumberOfProcessors",
        )
        if metadata_cpu_count is not None:
            cpu_count = int(metadata_cpu_count)
    if (not cpu_count or cpu_count <= 0) and logfile_metadata:
        cpu_counts = [
            int(getattr(item, "number_of_processors", 0) or 0)
            for item in logfile_metadata
            if int(getattr(item, "number_of_processors", 0) or 0) > 0
        ]
        if cpu_counts:
            cpu_count = max(cpu_counts)
    if not cpu_count or cpu_count <= 0:
        header_cpu_count = _extract_raw_csv_value(
            trace,
            "EventTrace/Header",
            "NumberOfProcessors",
        )
        if header_cpu_count is not None:
            cpu_count = int(header_cpu_count)
    if not cpu_count or cpu_count <= 0:
        cpu_vals = pd.to_numeric(cpus, errors="coerce").dropna()
        if cpu_vals.empty:
            return None
        cpu_count = int(cpu_vals.max()) + 1

    return _TimelineMetadata(
        duration_s=float(duration_s),
        timestamp_frequency=float(timestamp_frequency),
        timestamp_origin=float(timestamp_origin),
        cpu_count=int(cpu_count),
    )


def aggregate_cpu_timeline(
    trace: "TraceData",
    *,
    bucket_seconds: float = 1.0,
    sample_rate_hz: int = _DEFAULT_SAMPLE_RATE_HZ,
) -> Optional[pd.DataFrame]:
    """Build the ``cpu_timeline`` DataFrame from native SampledProfile rows.

    Returns ``None`` when no SampledProfile data is available.
    """
    dumper = trace.dumper_df
    if dumper is None or dumper.empty:
        return None

    df = dumper
    needed = {"TimeStamp", "CPU"}
    if not needed.issubset(df.columns):
        return None

    timestamps = pd.to_numeric(df["TimeStamp"], errors="coerce")
    cpus = pd.to_numeric(df["CPU"], errors="coerce")
    valid = timestamps.notna() & cpus.notna()
    if not valid.any():
        return None

    sub = df.loc[valid].copy()
    sub["TimeStamp"] = timestamps.loc[valid].astype("float64")
    sub["CPU"] = cpus.loc[valid].astype("int64")

    metadata = _timeline_metadata(trace, sub["TimeStamp"], sub["CPU"])
    if metadata is None:
        return None

    if bucket_seconds <= 0:
        bucket_seconds = 1.0

    sub["__sec"] = (
        (sub["TimeStamp"] - metadata.timestamp_origin) / metadata.timestamp_frequency
    ).clip(lower=0.0)
    sub = sub[sub["__sec"] <= metadata.duration_s]
    if sub.empty:
        bucket_count = max(1, int(math.ceil(metadata.duration_s / bucket_seconds)))
        buckets = pd.DataFrame({"Bucket": range(bucket_count)})
    else:
        sub["__bucket"] = (sub["__sec"] // bucket_seconds).astype("int64")
        bucket_count = max(
            int(math.ceil(metadata.duration_s / bucket_seconds)),
            int(sub["__bucket"].max()) + 1,
            1,
        )
        sub = sub[sub["__bucket"] < bucket_count]
        buckets = pd.DataFrame({"Bucket": range(bucket_count)})

    sub["__sample_count"] = 1

    if sub.empty:
        pivot = buckets
    else:
        grouped = (
            sub.groupby(["__bucket", "CPU"], dropna=False)["__sample_count"]
            .sum()
            .reset_index()
        )
        pivot = grouped.pivot(index="__bucket", columns="CPU", values="__sample_count")
        pivot = pivot.reindex(range(bucket_count), fill_value=0).fillna(0)
        pivot.columns = [f"Cpu {int(c)}" for c in pivot.columns]
        pivot = pivot.sort_index().reset_index().rename(columns={"__bucket": "Bucket"})

    for cpu in range(metadata.cpu_count):
        col = f"Cpu {cpu}"
        if col not in pivot.columns:
            pivot[col] = 0.0

    pivot["StartTime"] = (pivot["Bucket"] * bucket_seconds * 1_000_000).astype("int64")
    end_us = ((pivot["Bucket"] + 1) * bucket_seconds * 1_000_000).clip(
        upper=metadata.duration_s * 1_000_000
    )
    pivot["EndTime"] = end_us.round().astype("int64")

    bucket_width_s = (pivot["EndTime"] - pivot["StartTime"]) / 1_000_000.0
    bucket_width_s = bucket_width_s.where(bucket_width_s > 0, bucket_seconds)
    cpu_cols = sorted(
        [c for c in pivot.columns if c.startswith("Cpu ")],
        key=lambda c: int(c.split()[1]),
    )
    for col in cpu_cols:
        max_samples = float(sample_rate_hz) * bucket_width_s
        max_samples = max_samples.where(max_samples > 0, 1.0)
        pivot[col] = (pivot[col] / max_samples * 100.0).clip(upper=100.0).round(2)

    final_cols = ["StartTime", "EndTime"] + cpu_cols
    return pivot[final_cols].reset_index(drop=True)


__all__ = ["aggregate_cpu_timeline"]
