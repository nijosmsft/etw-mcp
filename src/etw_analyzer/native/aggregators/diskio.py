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

# Native/dotnet manifest keys (underscore form). These mirror
# ``aggregation_worker_adapters.PHASE_B_DISKIO_STEMS`` and carry the same
# per-IO schema as the xperf slash keys.
_DISKIO_UNDERSCORE = {
    "diskio_read": "Read",
    "diskio_write": "Write",
    "diskio_flushbuffers": "FlushBuffers",
}


def _normalize_op(value: object) -> str:
    """Normalise an operation token to the canonical ``Read``/``Write``/
    ``FlushBuffers`` form used by :func:`build_diskio_text`.

    Accepts xperf slash form (``DiskIo/Read``), underscore form
    (``diskio_read``), or the bare ``Type`` value (``Read``) emitted on the
    combined ``diskio`` parquet.
    """
    text = str(value).strip()
    if "/" in text:
        text = text.split("/", 1)[1]
    if text.lower().startswith("diskio_"):
        text = text.split("_", 1)[1]
    if not text:
        return text
    return text[:1].upper() + text[1:]


def _gather_diskio(trace: "TraceData") -> pd.DataFrame:
    raw_csv = getattr(trace, "raw_csv", {}) or {}
    rows: list[pd.DataFrame] = []

    # 1. xperf slash-format per-op keys (DiskIo/Read, ...).
    for cls in _DISKIO_CLASSES:
        df = raw_csv.get(cls)
        if df is not None and not df.empty:
            tagged = df.copy()
            tagged["__op"] = cls.split("/", 1)[1]
            rows.append(tagged)

    # 2. native/dotnet underscore-format per-op keys (diskio_read, ...).
    for key, op in _DISKIO_UNDERSCORE.items():
        df = raw_csv.get(key)
        if df is not None and not df.empty:
            tagged = df.copy()
            tagged["__op"] = op
            rows.append(tagged)

    # 3. Combined parquet (raw_csv["diskio"]) — one row per IO carrying a
    #    per-row ``Type`` column. Only consulted when no per-op slot was
    #    populated, so we never double-count the same events (issue #14).
    if not rows:
        combined = raw_csv.get("diskio")
        if (
            combined is not None
            and not combined.empty
            and "raw_text" not in combined.columns
        ):
            tagged = combined.copy()
            if "__op" not in tagged.columns:
                for op_col in ("Kind", "Type", "Operation"):
                    if op_col in tagged.columns:
                        tagged["__op"] = tagged[op_col].map(_normalize_op)
                        break
            if "__op" in tagged.columns:
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
