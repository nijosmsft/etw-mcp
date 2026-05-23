"""Aggregator: ``dpc_isr`` + ``dpc_isr_raw`` — replacement for ``xperf -a dpcisr``.

Two outputs:

* ``dpc_isr`` — per-module duration histogram DataFrame matching the
  schema produced by :func:`parsing.wpa_exporter._parse_dpcisr`::

      Module, Bucket_Low_us, Bucket_High_us, Count, Pct

* ``dpc_isr_raw`` — raw text mimicking the format
  :func:`tools.network_dispatch._per_cpu_dpc_rows` expects: one line
  per module with comma-separated ``usec  pct`` pairs (one pair per
  CPU), trailing module-name token. The Phase 4 networking tools read
  this for per-CPU NIC-DPC affinity stats.

Algorithm
---------
Native consumer emits two kinds of events for each DPC:

* opcode 66 (``PerfInfo/ThreadedDPC``) — DPC *start* marker; carries
  the routine address.
* opcode 68 (``PerfInfo/DPC``) — DPC *end* marker; carries the same
  routine and an ``InitialTime`` (QPC of the start).

Per design §7.2 we pair start + end events by ``(CPU, Routine)`` to
get the duration, then bucket per module. The module name comes from
the symbolizer (the DPC routine address → ``module!func``).

The bucket boundaries match xperf's defaults — log-spaced from 0us up
to >32ms — so downstream tools that expect the xperf shape can be
left untouched.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import TYPE_CHECKING, Optional

import pandas as pd

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


# xperf's dpcisr bucket boundaries (microseconds). Each entry is
# (low, high); a duration of "low <= d < high" falls into that bucket.
# The last bucket is "everything above" — represented as (high, inf-ish).
_BUCKETS: list[tuple[int, int]] = [
    (0, 1),
    (1, 2),
    (2, 4),
    (4, 8),
    (8, 16),
    (16, 32),
    (32, 64),
    (64, 128),
    (128, 256),
    (256, 512),
    (512, 1024),
    (1024, 2048),
    (2048, 4096),
    (4096, 8192),
    (8192, 16384),
    (16384, 32768),
    (32768, 99_999_999),  # tail
]


_DPC_CLASSES = ("PerfInfo/DPC", "PerfInfo/ThreadedDPC", "PerfInfo/TimerDPC", "PerfInfo/ISR")


# Matches ``module!function+0x…`` shape from Symbolizer.resolve. Module
# only — we don't need the function for the per-module histogram.
_MODULE_RE = re.compile(r"^([^!]+)!")
_MODULE_FALLBACK_RE = re.compile(r"^([^+]+)\+0x")


def _module_from_label(label: str) -> str:
    if not label:
        return "unknown"
    m = _MODULE_RE.match(label)
    if m:
        return m.group(1).strip()
    m = _MODULE_FALLBACK_RE.match(label)
    if m:
        return m.group(1).strip()
    return label


def _bucket_for(duration_us: int) -> tuple[int, int]:
    """Return the (low, high) bucket bounds that contain ``duration_us``."""
    for low, high in _BUCKETS:
        if low <= duration_us < high:
            return low, high
    return _BUCKETS[-1]


def _to_uint64_series(col: pd.Series) -> pd.Series:
    """Coerce a column of kernel addresses to ``uint64`` without overflow.

    Kernel-mode pointers live in the upper half of the 64-bit space
    (``0xFFFF8000_00000000``+ on x64). ``pd.to_numeric(..., downcast=…)``
    and the previous ``astype("int64")`` path silently overflowed those
    to negative values, which then failed every symbolizer lookup —
    leaving the per-CPU DPC text empty and breaking
    ``get_per_nic_queue_arrivals`` / ``get_rss_dispatch_quality``.

    This helper takes whatever the upstream extractor produced (numpy
    ``uint64``, Python ``int``, ``object``) and returns a ``uint64``
    Series with NaN-safe handling. Values that genuinely don't fit in
    a uint64 fall through as ``pd.NA``.
    """
    import numpy as _np
    if pd.api.types.is_integer_dtype(col) and col.dtype.kind == "u":
        return col
    out = []
    for v in col.tolist():
        if v is None or (isinstance(v, float) and _np.isnan(v)):
            out.append(None)
            continue
        try:
            iv = int(v)
        except (TypeError, ValueError):
            out.append(None)
            continue
        if iv < 0:
            # Already-overflowed int64 — recover the unsigned form.
            iv = iv & 0xFFFFFFFFFFFFFFFF
        if 0 <= iv < (1 << 64):
            out.append(_np.uint64(iv))
        else:
            out.append(None)
    return pd.Series(out, index=col.index, dtype="object")


def _gather_dpc_events(trace: "TraceData") -> pd.DataFrame:
    """Concatenate every DPC/ISR class DataFrame into one frame.

    Reads from ``trace.raw_csv['_native_dpc_events']`` when populated
    (Phase N4 wires this), otherwise from the per-class slots the Phase
    N2 extractor may have stashed on ``trace``.
    """
    rows: list[pd.DataFrame] = []
    raw_csv = getattr(trace, "raw_csv", {}) or {}

    # Phase N4 wiring drops a combined frame in ``_native_dpc_events``
    # to avoid re-concatenating on every aggregate call.
    combined = raw_csv.get("_native_dpc_events")
    if combined is not None and not combined.empty:
        return combined

    for cls in _DPC_CLASSES:
        df = raw_csv.get(cls)
        if df is not None and not df.empty:
            rows.append(df)

    if not rows:
        return pd.DataFrame()

    return pd.concat(rows, ignore_index=True, sort=False)


def aggregate_dpc_isr(trace: "TraceData") -> Optional[pd.DataFrame]:
    """Build the per-module DPC/ISR duration histogram DataFrame.

    Returns ``None`` when no DPC/ISR events have been decoded.
    """
    dpc_df = _gather_dpc_events(trace)
    if dpc_df.empty:
        return None
    required = {"TimeStamp", "CPU", "Routine", "InitialTime"}
    if not required.issubset(dpc_df.columns):
        return None

    # Compute duration per event. PerfInfo emits InitialTime = QPC at
    # routine start, TimeStamp = QPC at end. xperf reports duration in
    # microseconds; convert via the QPC frequency if known, otherwise
    # use a 10 MHz fallback (Windows default on most systems).
    qpc_hz = getattr(trace, "qpc_frequency_hz", None) or 10_000_000
    durations_qpc = (
        pd.to_numeric(dpc_df["TimeStamp"], errors="coerce")
        - pd.to_numeric(dpc_df["InitialTime"], errors="coerce")
    )
    durations_us = (durations_qpc * 1_000_000 / qpc_hz).fillna(0).clip(lower=0).astype("int64")

    # Symbolize the Routine to a module label. Kernel addresses live in
    # the upper half of the 64-bit space (``0xFFFF...``), so we must keep
    # the column as uint64 — ``astype("int64")`` overflows to negative
    # and the resulting addresses don't match any registered module,
    # which is why the verification report saw "(unknown)" for every DPC.
    symbolizer = getattr(trace, "symbolizer", None)
    routine_col = _to_uint64_series(dpc_df["Routine"])
    unique_routines = routine_col.dropna().unique().tolist()
    label_map: dict[int, str] = {}
    if symbolizer is not None and unique_routines:
        try:
            label_map = symbolizer.bulk_resolve([int(r) for r in unique_routines])
        except Exception:
            label_map = {}
    modules = (
        routine_col
        .map(label_map)
        .fillna("")
        .map(_module_from_label)
        .fillna("unknown")
    )

    work = pd.DataFrame({
        "Module": modules.values,
        "DurUs": durations_us.values,
    })

    # Bucket and count.
    bucket_rows: dict[tuple[str, int, int], int] = defaultdict(int)
    for module, dur in zip(work["Module"], work["DurUs"]):
        low, high = _bucket_for(int(dur))
        bucket_rows[(module, low, high)] += 1

    # Compute module totals first so the per-bucket Pct matches xperf
    # (percentage is per-module, not global).
    module_totals: dict[str, int] = defaultdict(int)
    for (module, _low, _high), count in bucket_rows.items():
        module_totals[module] += count

    out_rows: list[dict] = []
    for (module, low, high), count in bucket_rows.items():
        total = module_totals.get(module, 0)
        pct = (count / total * 100.0) if total else 0.0
        out_rows.append({
            "Module": module,
            "Bucket_Low_us": low,
            "Bucket_High_us": high,
            "Count": count,
            "Pct": round(pct, 2),
        })

    # Also emit the synthetic "(all)" rows so the global health checks
    # in :func:`tools.dpc_isr._global_health` work unchanged.
    all_buckets: dict[tuple[int, int], int] = defaultdict(int)
    for (_module, low, high), count in bucket_rows.items():
        all_buckets[(low, high)] += count
    all_total = sum(all_buckets.values())
    for (low, high), count in all_buckets.items():
        pct = (count / all_total * 100.0) if all_total else 0.0
        out_rows.append({
            "Module": "(all)",
            "Bucket_Low_us": low,
            "Bucket_High_us": high,
            "Count": count,
            "Pct": round(pct, 2),
        })

    if not out_rows:
        return None

    df = pd.DataFrame(out_rows)
    df = df.sort_values(["Module", "Bucket_Low_us"]).reset_index(drop=True)
    return df


def build_dpc_isr_raw_text(trace: "TraceData") -> Optional[str]:
    """Synthesise the ``dpcisr.txt`` text that xperf would write.

    Format the Phase 4 networking tools rely on (see
    :func:`tools.network_dispatch._per_cpu_dpc_rows`)::

        Total = <count> for module <NAME>.SYS
        Elapsed Time, > 0 usecs AND <= 1 usecs, <count>, or <pct>%
        ...
        Elapsed Time, > N usecs AND <= 2N usecs, <count>, or <pct>%
        <usec> <pct>, <usec> <pct>, ..., <module>.sys

    The trailing per-CPU pair line is what
    ``_per_cpu_dpc_rows`` parses for per-CPU NIC-DPC affinity. We
    generate one line per module covering every CPU 0..max(CPU).
    """
    dpc_df = _gather_dpc_events(trace)
    if dpc_df.empty:
        return None
    required = {"TimeStamp", "CPU", "Routine", "InitialTime"}
    if not required.issubset(dpc_df.columns):
        return None

    qpc_hz = getattr(trace, "qpc_frequency_hz", None) or 10_000_000

    timestamps = pd.to_numeric(dpc_df["TimeStamp"], errors="coerce")
    initials = pd.to_numeric(dpc_df["InitialTime"], errors="coerce")
    durations_us = ((timestamps - initials) * 1_000_000 / qpc_hz).fillna(0).clip(lower=0).astype("int64")

    cpus = pd.to_numeric(dpc_df["CPU"], errors="coerce").fillna(-1).astype("int64")

    symbolizer = getattr(trace, "symbolizer", None)
    routine_col = _to_uint64_series(dpc_df["Routine"])
    unique_routines = routine_col.dropna().unique().tolist()
    label_map: dict[int, str] = {}
    if symbolizer is not None and unique_routines:
        try:
            label_map = symbolizer.bulk_resolve([int(r) for r in unique_routines])
        except Exception:
            label_map = {}
    modules = (
        routine_col
        .map(label_map)
        .fillna("")
        .map(_module_from_label)
        .fillna("unknown")
    )

    work = pd.DataFrame({
        "Module": modules.values,
        "CPU": cpus.values,
        "DurUs": durations_us.values,
    })
    work = work[work["CPU"] >= 0]
    if work.empty:
        return None

    # Skip the "(unknown)" pseudo-module so the parser regex (which
    # demands a trailing ``.sys``/``.exe``/``.dll``) doesn't pick it up.
    work = work[
        work["Module"]
        .astype(str)
        .str.lower()
        .str.endswith((".sys", ".exe", ".dll"))
    ]
    if work.empty:
        return None

    max_cpu = int(work["CPU"].max())

    # Per-module per-CPU usec sum.
    grouped = (
        work.groupby(["Module", "CPU"], dropna=False)["DurUs"]
        .sum()
        .reset_index()
    )

    # Each CPU's % of its own walltime — we use trace duration as the
    # walltime baseline. Approximate but matches xperf's calculation
    # within rounding.
    duration_us = int((trace.duration_seconds or 1.0) * 1_000_000) or 1

    lines: list[str] = []

    # Module-by-module: histogram block first, then per-CPU pair line.
    for module, mod_group in grouped.groupby("Module"):
        mod_rows = work[work["Module"] == module]
        total = len(mod_rows)
        if total == 0:
            continue

        lines.append(f"Total = {total} for module {module.upper()}")

        bucket_counts: dict[tuple[int, int], int] = defaultdict(int)
        for dur in mod_rows["DurUs"]:
            low, high = _bucket_for(int(dur))
            bucket_counts[(low, high)] += 1
        for (low, high) in _BUCKETS:
            count = bucket_counts.get((low, high), 0)
            pct = (count / total * 100.0) if total else 0.0
            lines.append(
                f"Elapsed Time, >  {low} usecs AND <=  {high} usecs, {count}, or {pct:.2f}%"
            )
        lines.append("Total,,")

        # Per-CPU usec/pct pair line.
        cpu_usecs = dict(zip(mod_group["CPU"], mod_group["DurUs"]))
        pairs: list[str] = []
        for cpu in range(max_cpu + 1):
            usec = int(cpu_usecs.get(cpu, 0))
            pct = (usec / duration_us * 100.0) if duration_us else 0.0
            pairs.append(f"  {usec}  {pct:.2f}")
        # network_dispatch._per_cpu_dpc_rows expects the trailing module
        # name (lower-cased basename), preceded by the comma-separated
        # pair list.
        lines.append(", ".join(pairs) + f" {module}")
        lines.append("")

    return "\n".join(lines) + "\n"


__all__ = ["aggregate_dpc_isr", "build_dpc_isr_raw_text"]
