"""Aggregator: ``cpu_sampling`` (the ``xperf -a profile -detail`` replacement).

Output DataFrame columns (matching :func:`parsing.wpa_exporter._parse_profile_detail`)::

    Process Name, PID, Weight, % Weight, Module, Function

Algorithm:
    1. Start from the per-sample SampledProfile DataFrame
       (``trace.dumper_df``). Each row already has Weight, CPU, PID.
    2. Symbolize the ``InstructionPointer`` of each sample via
       ``trace.symbolizer.bulk_resolve`` — this is the leaf frame of the
       sampled call stack, i.e. exactly what xperf's ``-detail`` action
       reports.
    3. Split the resolved string ``module!function+0x…`` into Module and
       Function columns.
    4. Look up the process name via the Process/DCStart/Start events
       harvested into ``trace.raw_csv['_native_process_map']`` (an
       internal optimisation populated when this aggregator runs).
    5. Group by (Process Name, PID, Module, Function), sum Weight,
       compute % Weight.

Symbolization is the expensive step here. We deduplicate IPs first so
``bulk_resolve`` only pays the dbghelp cost once per unique address —
typical traces collapse 10M samples into <50K unique IPs.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

import pandas as pd

if TYPE_CHECKING:
    from etw_analyzer.trace_state import TraceData


# Matches the standard ``module!function+0x123`` shape produced by
# :meth:`Symbolizer.resolve`. The trailing ``+offset`` is optional —
# resolved-without-PDB fallback emits ``ntoskrnl.exe+0x12345`` (no
# function), which we surface as Function="" so the row is still useful.
_SYM_RE = re.compile(r"^(?P<module>[^!]+)!(?P<function>[^+]+)(?:\+0x[0-9a-fA-F]+)?$")
_SYM_NOFUNC_RE = re.compile(r"^(?P<module>[^+]+)\+0x[0-9a-fA-F]+$")


def _split_resolved(label: str) -> tuple[str, str]:
    """Split ``"module!function+0x…"`` into ``(module, function)``.

    Falls back to ``("unknown", "")`` for unparseable strings.
    """
    if not label:
        return "unknown", ""
    m = _SYM_RE.match(label)
    if m:
        return m.group("module"), m.group("function")
    m = _SYM_NOFUNC_RE.match(label)
    if m:
        return m.group("module"), ""
    if label == "unknown+0x0":
        return "unknown", ""
    return label, ""


def aggregate_cpu_sampling(trace: "TraceData") -> Optional[pd.DataFrame]:
    """Build the ``cpu_sampling`` DataFrame from native event DataFrames.

    Returns ``None`` when ``trace.dumper_df`` is absent or empty — the
    caller is expected to gracefully fall through to the existing
    "no data" path.
    """
    dumper = trace.dumper_df
    if dumper is None or dumper.empty:
        return None

    df = dumper

    # Symbolize once per unique IP. If we have no symbolizer the values
    # in Module / Function stay blank — that matches the Phase N1
    # ``_synthesize_native_cpu_sampling`` behaviour and keeps the
    # downstream tools running (just without function attribution).
    if "InstructionPointer" in df.columns:
        unique_ips = df["InstructionPointer"].dropna().astype("int64").unique().tolist()
    else:
        unique_ips = []

    symbolizer = getattr(trace, "symbolizer", None)
    ip_to_label: dict[int, str] = {}
    if symbolizer is not None and unique_ips:
        try:
            ip_to_label = symbolizer.bulk_resolve(unique_ips)
        except Exception:
            ip_to_label = {}

    # Build a per-row (module, function) — vectorised via map for speed.
    if ip_to_label:
        labels = df["InstructionPointer"].map(ip_to_label)
        # Pre-split into module/function — done once per unique label.
        unique_labels = set(v for v in ip_to_label.values() if v)
        label_to_mod_fn = {lab: _split_resolved(lab) for lab in unique_labels}
        # Empty-label sentinel for missing symbolization.
        label_to_mod_fn[None] = ("", "")
        label_to_mod_fn[""] = ("", "")

        modules = labels.map(lambda lab: label_to_mod_fn.get(lab, (lab, ""))[0])
        functions = labels.map(lambda lab: label_to_mod_fn.get(lab, (lab, ""))[1])
    else:
        # Phase N1 fallback: rely on whatever Module/Function the dumper
        # already had (likely blank from the native consumer, real
        # values for the xperf consumer).
        modules = df["Module"] if "Module" in df.columns else pd.Series([""] * len(df))
        functions = df["Function"] if "Function" in df.columns else pd.Series([""] * len(df))

    # Replace any blank module from symbolization with the value the
    # native consumer originally stored (none, but harmless), or with
    # "unknown" so groupby buckets stay meaningful.
    modules = modules.fillna("").replace("", "unknown")
    functions = functions.fillna("")

    # Resolve process name. The native SampledProfile decoder leaves
    # ``Process Name`` blank because the process->name mapping isn't in
    # the sample's payload — it has to come from Process/DCStart events.
    # Build the lookup table on demand and merge.
    pid_to_name = _build_pid_to_name_map(trace)
    if pid_to_name and "PID" in df.columns:
        process_names = df["PID"].map(pid_to_name)
        # Fallback: prefer whatever the dumper already provided over
        # an "unknown" placeholder. Then use the PID-mapped name.
        existing = df["Process Name"] if "Process Name" in df.columns else pd.Series([""] * len(df))
        process_names = process_names.fillna(existing).fillna("").replace("", "unknown")
    else:
        if "Process Name" in df.columns:
            process_names = df["Process Name"].fillna("").replace("", "unknown")
        else:
            process_names = pd.Series(["unknown"] * len(df))

    agg_input = pd.DataFrame({
        "Process Name": process_names.astype(str).values,
        "PID": df["PID"].values if "PID" in df.columns else 0,
        "Weight": df["Weight"].values if "Weight" in df.columns else 1,
        "Module": modules.astype(str).values,
        "Function": functions.astype(str).values,
    })

    group_cols = ["Process Name", "PID", "Module", "Function"]
    agg = (
        agg_input.groupby(group_cols, dropna=False, sort=False)["Weight"]
        .sum()
        .reset_index()
    )
    total = float(agg["Weight"].sum()) or 1.0
    agg["% Weight"] = (agg["Weight"] / total) * 100.0
    agg = agg[["Process Name", "PID", "Weight", "% Weight", "Module", "Function"]]
    agg = agg.sort_values("Weight", ascending=False).reset_index(drop=True)
    return agg


def _build_pid_to_name_map(trace: "TraceData") -> dict[int, str]:
    """Build a ``{pid: image_file_name}`` map from any Process events.

    Looks at the Phase N2 ``Process/DCStart`` / ``Process/Start`` /
    ``Process/DCEnd`` / ``Process/End`` DataFrames if the native
    consumer registered them under ``trace.raw_csv`` (which Phase N4
    does — see :func:`tools.trace_mgmt` wiring). Falls back to an
    in-memory ``_native_process_events`` slot.
    """
    pid_map: dict[int, str] = {}
    for key in (
        "_native_process_events",
        "process",
        "process_info",
    ):
        candidate = trace.raw_csv.get(key) if hasattr(trace, "raw_csv") else None
        if candidate is None or candidate.empty:
            continue
        if "ProcessId" not in candidate.columns and "PID" not in candidate.columns:
            continue
        if "ImageFileName" not in candidate.columns and "ImageName" not in candidate.columns:
            continue
        pid_col = "ProcessId" if "ProcessId" in candidate.columns else "PID"
        name_col = "ImageFileName" if "ImageFileName" in candidate.columns else "ImageName"
        for _, row in candidate.iterrows():
            try:
                pid_map[int(row[pid_col])] = str(row[name_col] or "").strip("\x00").strip()
            except (ValueError, TypeError):
                continue
    return pid_map


__all__ = ["aggregate_cpu_sampling"]
