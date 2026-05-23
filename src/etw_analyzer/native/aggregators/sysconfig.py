"""Aggregator: ``sysconfig`` raw-text — replacement for ``xperf -a sysconfig``.

xperf's sysconfig output is a free-form text dump of system metadata
(CPU, NICs, disks, services, ...). The Phase N2 SystemConfig MOF
handler emits one row per SystemConfig opcode with a human-readable
name (CPU/NIC/PhyDisk/Power/…) and the opcode's payload byte length.

For Phase N4 we wrap those rows into the single-row ``raw_text``
DataFrame shape the existing trace loader uses for raw text outputs.
The text is a compact summary — "N <Name> records, total <bytes>
bytes of payload" — which is enough for tools that grep over
``sysconfig`` (none in the current codebase rely on exact field
content; the SystemConfig data is mostly informational).

If the trace was collected without rundown events (e.g. an event-only
ETW session that omitted SystemConfig), this returns ``None``.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Optional

import pandas as pd

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


def build_sysconfig_text(trace: "TraceData") -> Optional[str]:
    """Generate a sysconfig-equivalent text block.

    Returns ``None`` when no SystemConfig events have been decoded.
    """
    raw_csv = getattr(trace, "raw_csv", {}) or {}
    df = raw_csv.get("SystemConfig")
    if df is None or df.empty:
        return None
    if "OpcodeName" not in df.columns:
        return None

    counts: Counter[str] = Counter()
    bytes_per: Counter[str] = Counter()
    for _, row in df.iterrows():
        name = str(row["OpcodeName"])
        counts[name] += 1
        bytes_per[name] += int(row.get("PayloadBytes", 0) or 0)

    lines: list[str] = ["System Configuration Summary", "="]
    for name in sorted(counts):
        lines.append(
            f"  {name}: {counts[name]} record(s), {bytes_per[name]} byte(s) of payload"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


__all__ = ["build_sysconfig_text"]
