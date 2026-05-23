"""Aggregator: ``diskio`` raw-text — replacement for ``xperf -a diskio``.

xperf prints per-IO records and a summary; we ship the summary only,
keyed by disk number with totals for reads/writes/flushes. The Phase
N2 ``DiskIo`` MOF handler emits one row per IO; we aggregate.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

import pandas as pd

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


_DISKIO_CLASSES = ("DiskIo/Read", "DiskIo/Write", "DiskIo/FlushBuffers")


def _gather_diskio(trace: "TraceData") -> pd.DataFrame:
    raw_csv = getattr(trace, "raw_csv", {}) or {}
    rows: list[pd.DataFrame] = []
    for cls in _DISKIO_CLASSES:
        df = raw_csv.get(cls)
        if df is not None and not df.empty:
            tagged = df.copy()
            tagged["__op"] = cls.split("/", 1)[1]
            rows.append(tagged)
    if not rows:
        return pd.DataFrame()
    return pd.concat(rows, ignore_index=True, sort=False)


def build_diskio_text(trace: "TraceData") -> Optional[str]:
    """Build a per-disk DiskIo summary text block."""
    df = _gather_diskio(trace)
    if df.empty:
        return None
    if "DiskNumber" not in df.columns:
        return None

    lines: list[str] = ["DiskIo Summary", "==="]
    for disk_num, group in df.groupby("DiskNumber", dropna=False):
        reads = group[group["__op"] == "Read"]
        writes = group[group["__op"] == "Write"]
        flushes = group[group["__op"] == "FlushBuffers"]
        rbytes = int(reads["TransferSize"].sum()) if "TransferSize" in reads.columns else 0
        wbytes = int(writes["TransferSize"].sum()) if "TransferSize" in writes.columns else 0
        lines.append(
            f"Disk {int(disk_num)}: "
            f"reads={len(reads)} ({rbytes:,}B), "
            f"writes={len(writes)} ({wbytes:,}B), "
            f"flushes={len(flushes)}"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


__all__ = ["build_diskio_text"]
