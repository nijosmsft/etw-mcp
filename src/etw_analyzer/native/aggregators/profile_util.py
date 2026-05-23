"""Aggregator: ``cpu_timeline`` — replacement for ``xperf -a profile`` (no -detail).

Output DataFrame schema mirrors :func:`parsing.wpa_exporter._parse_profile_utilization`::

    StartTime, EndTime, Cpu 0, Cpu 1, ..., Cpu N

Times are in microseconds — same units xperf emits. The ``Cpu <n>``
columns hold per-CPU utilization as a percent of wall time in that
bucket.

Algorithm
---------
1. Bucket SampledProfile events by ``TimeStamp`` and ``CPU``.
2. Count samples per (bucket, CPU) — sampling rate is fixed (default
   1ms = 1000 samples/second/CPU), so ``samples / (rate * bucket_s)``
   gives utilization.
3. Pivot wide so each CPU is a column.

The default xperf bucket is the trace duration / 1000 (typically a
few hundred ms), and ``samples_per_second_per_cpu`` defaults to 1000.
Both can be overridden if a test pins them; in production the values
are picked off ``trace.duration_seconds`` and a 1ms-tick assumption.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

import pandas as pd

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


# Default Windows kernel sampler runs at 1 kHz per CPU when the
# SampledProfile flag is enabled without an override. The actual rate
# can be tuned via ``xperf -SetProfInt`` but 1000 is the canonical default.
_DEFAULT_SAMPLE_RATE_HZ = 1000


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

    # TimeStamp on the native path is QPC ticks (matches xperf). xperf
    # converts to microseconds via the trace's QPC frequency at export
    # time; we don't have that here. Fall back to scaling against the
    # known trace duration if the timestamps look like raw QPC.
    timestamps = pd.to_numeric(df["TimeStamp"], errors="coerce").dropna()
    if timestamps.empty:
        return None

    t_min = float(timestamps.min())
    t_max = float(timestamps.max())
    span = t_max - t_min

    # Trace duration in seconds. Prefer the trace metadata if available;
    # otherwise infer it (less accurate but workable).
    duration_s = trace.duration_seconds if trace.duration_seconds and trace.duration_seconds > 0 else None
    if duration_s is None:
        # If timestamps look like microseconds (xperf-like), span is duration_us.
        # If they look like QPC ticks (huge numbers), divide by a typical 10MHz QPC freq.
        if span <= 0:
            return None
        if span > 1e12:
            duration_s = span / 10_000_000.0
        else:
            duration_s = span / 1_000_000.0

    if duration_s <= 0:
        return None

    # Map every timestamp to a fractional second within the trace, then
    # bucket. Working in seconds keeps the arithmetic simple. When span
    # is zero (all samples at the same QPC, e.g. a synthetic test) we
    # place every sample in bucket 0.
    if span <= 0:
        secs = pd.Series([0.0] * len(timestamps), index=timestamps.index)
    else:
        secs = (timestamps - t_min) * (duration_s / span)

    # Re-attach to the rest of the columns
    sub = df.loc[timestamps.index].copy()
    sub["__sec"] = secs.values
    sub["__bucket"] = (sub["__sec"] // bucket_seconds).astype("int64")

    # Count samples per (bucket, CPU). Weight is almost always 1 for
    # SampledProfile; sum it so xperf-style "weighted" tools still work.
    weight_col = "Weight" if "Weight" in sub.columns else None
    if weight_col is None:
        sub["__weight"] = 1
        weight_col = "__weight"

    grouped = (
        sub.groupby(["__bucket", "CPU"], dropna=False)[weight_col]
        .sum()
        .reset_index()
    )

    # Pivot wide.
    pivot = grouped.pivot(index="__bucket", columns="CPU", values=weight_col).fillna(0)
    pivot.columns = [f"Cpu {int(c)}" for c in pivot.columns]
    pivot = pivot.sort_index().reset_index().rename(columns={"__bucket": "Bucket"})

    # StartTime / EndTime in microseconds (xperf convention).
    pivot["StartTime"] = (pivot["Bucket"] * bucket_seconds * 1_000_000).astype("int64")
    pivot["EndTime"] = (
        ((pivot["Bucket"] + 1) * bucket_seconds * 1_000_000)
        .astype("int64")
        .clip(upper=int(duration_s * 1_000_000))
    )

    # Convert sample-count → percent. Per bucket per CPU, the upper bound
    # of samples is ``sample_rate_hz * bucket_seconds``. Anything beyond
    # that means the kernel sampler caught up — clip to 100%.
    max_samples_per_bucket = float(sample_rate_hz) * float(bucket_seconds)
    if max_samples_per_bucket <= 0:
        max_samples_per_bucket = 1.0

    cpu_cols = [c for c in pivot.columns if c.startswith("Cpu ")]
    for col in cpu_cols:
        pivot[col] = (pivot[col] / max_samples_per_bucket * 100.0).clip(upper=100.0).round(2)

    final_cols = ["StartTime", "EndTime"] + sorted(
        cpu_cols, key=lambda c: int(c.split()[1])
    )
    return pivot[final_cols].reset_index(drop=True)


__all__ = ["aggregate_cpu_timeline"]
