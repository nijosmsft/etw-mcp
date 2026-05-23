"""Aggregator: ``process_info`` raw-text — replacement for ``xperf -a process``.

xperf's process action prints one block per process (Start/End/DCStart/
DCEnd) with PID, parent, session, command line, etc. The Phase N2
``Process`` MOF handler decodes the same fields into structured rows.

This module formats those rows into a single text block matching the
shape downstream code expects in ``trace.raw_csv['process_info']``
(stored as a single-row DataFrame with a ``raw_text`` column).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterable, Optional

import pandas as pd

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


_PROCESS_CLASSES = (
    "Process/Start",
    "Process/End",
    "Process/DCStart",
    "Process/DCEnd",
    "Process/Defunct",
)


def _gather_process_events(trace: "TraceData") -> pd.DataFrame:
    raw_csv = getattr(trace, "raw_csv", {}) or {}
    combined = raw_csv.get("_native_process_events")
    if combined is not None and not combined.empty:
        return combined
    process_table = raw_csv.get("process")
    if process_table is not None and not process_table.empty:
        return process_table

    rows: list[pd.DataFrame] = []
    for cls in _PROCESS_CLASSES:
        df = raw_csv.get(cls)
        if df is not None and not df.empty:
            tagged = df.copy()
            tagged["__cls"] = cls
            rows.append(tagged)
    if not rows:
        return pd.DataFrame()
    return pd.concat(rows, ignore_index=True, sort=False)


def build_process_info_text(trace: "TraceData") -> Optional[str]:
    """Return a text dump matching xperf's ``-a process`` output shape.

    ``None`` when no Process events have been decoded.
    """
    df = _gather_process_events(trace)
    if df.empty:
        return None

    lines: list[str] = ["Process records", "==="]
    cls_col = "__cls" if "__cls" in df.columns else None
    for _, row in df.iterrows():
        cls = row[cls_col] if cls_col else "Process"
        pid = int(row.get("ProcessId", 0) or 0)
        parent = int(row.get("ParentId", 0) or 0)
        sess = int(row.get("SessionId", 0) or 0)
        image = str(row.get("ImageFileName", "") or "").strip("\x00").strip()
        cmd = str(row.get("CommandLine", "") or "").strip("\x00").strip()
        ts = int(row.get("TimeStamp", 0) or 0)
        lines.append(
            f"{cls} TimeStamp={ts} PID={pid} Parent={parent} Session={sess} "
            f"Image={image!r} CmdLine={cmd!r}"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def build_process_table(trace: "TraceData") -> Optional[pd.DataFrame]:
    """Return a structured ProcessId-keyed DataFrame.

    Useful for the ``cpu_sampling`` aggregator's PID-to-name lookup.
    Columns: ``ProcessId``, ``ParentId``, ``SessionId``, ``ImageFileName``,
    ``CommandLine``, ``TimeStamp``.
    """
    df = _gather_process_events(trace)
    if df.empty:
        return None
    keep = ["ProcessId", "ParentId", "SessionId", "ImageFileName", "CommandLine", "TimeStamp"]
    cols = [c for c in keep if c in df.columns]
    return df[cols].drop_duplicates(subset=["ProcessId"], keep="last").reset_index(drop=True)


__all__ = ["build_process_info_text", "build_process_table"]
