"""Aggregator: ``cpu_sampling`` (the ``xperf -a profile -detail`` replacement).

Output DataFrame columns (matching :func:`parsing.wpa_exporter._parse_profile_detail`)::

    Process Name, PID, Weight, % Weight, Module, Function

Algorithm:
    1. Start from the per-sample SampledProfile DataFrame
       (``trace.dumper_df``). ``Weight`` matches xperf dumper Count;
       native rows also carry ``ProfileWeight`` for xperf profile-detail
       parity.
    2. Symbolize the ``InstructionPointer`` of each sample via
       ``trace.symbolizer.bulk_resolve`` — this is the leaf frame of the
       sampled call stack, i.e. exactly what xperf's ``-detail`` action
       reports.
    3. Split the resolved string ``module!function+0x…`` into Module and
       Function columns.
    4. Resolve SampledProfile ``PayloadThreadId`` through native Thread
       rundown/start rows when the event-header PID is the kernel sentinel,
       then look up the process name from Process/DCStart/Start rows.
    5. Group by (Process Name, PID, Module, Function), sum
       ``ProfileWeight`` when present (else ``Weight``), compute % Weight.

Symbolization is the expensive step here. We deduplicate IPs first so
``bulk_resolve`` only pays the dbghelp cost once per unique address —
typical traces collapse 10M samples into <50K unique IPs.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
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

    df = enrich_sampled_profile_attribution(dumper, getattr(trace, "raw_csv", {}) or {})
    if df is not dumper:
        try:
            trace.dumper_df = df
        except Exception:
            pass

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

    # Resolve process name. Native SampledProfile carries the sampled
    # thread ID, not a trustworthy event-header PID; the enrichment above
    # maps PayloadThreadId -> ProcessId and then PID -> process name from
    # Thread/DCStart + Process/DCStart/Start rows. The lookup below also
    # covers xperf-like DataFrames that already have real PIDs but blank
    # names.
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

    weight_col = "ProfileWeight" if "ProfileWeight" in df.columns else "Weight"
    agg_input = pd.DataFrame({
        "Process Name": process_names.astype(str).values,
        "PID": df["PID"].values if "PID" in df.columns else 0,
        "Weight": df[weight_col].values if weight_col in df.columns else 1,
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
    raw_csv = getattr(trace, "raw_csv", {}) or {}
    return _build_pid_to_name_map_from_raw_csv(raw_csv)


def _build_pid_to_name_map_from_raw_csv(
    raw_csv: Mapping[str, pd.DataFrame],
) -> dict[int, str]:
    pid_map: dict[int, str] = {}
    for key in (
        "_native_process_events",
        "Process/DCStart",
        "Process/Start",
        "Process/DCEnd",
        "Process/End",
        "Process/Defunct",
        "process",
        "process_info",
    ):
        candidate = raw_csv.get(key)
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


def _build_tid_to_pid_map_from_raw_csv(
    raw_csv: Mapping[str, pd.DataFrame],
) -> dict[int, int]:
    tid_map: dict[int, int] = {}
    for key in (
        "Thread/DCStart",
        "Thread/Start",
        "Thread/DCEnd",
        "Thread/End",
    ):
        candidate = raw_csv.get(key)
        if candidate is None or candidate.empty:
            continue
        if "ThreadId" not in candidate.columns or "ProcessId" not in candidate.columns:
            continue
        sort_cols = ["TimeStamp"] if "TimeStamp" in candidate.columns else None
        rows = candidate.sort_values(sort_cols) if sort_cols else candidate
        for _, row in rows.iterrows():
            try:
                tid = int(row["ThreadId"])
                pid = int(row["ProcessId"])
            except (ValueError, TypeError):
                continue
            if tid <= 0 or pid < 0:
                continue
            # Prefer DCStart/Start records over teardown events and keep
            # the earliest row per class for stable attribution when TIDs
            # are reused inside very short traces.
            tid_map.setdefault(tid, pid)
    return tid_map


def _blank_process_name_mask(series: pd.Series) -> pd.Series:
    values = series.fillna("").astype(str).str.strip()
    return values.isin(("", "unknown", "<unknown>"))


def enrich_sampled_profile_attribution(
    samples: pd.DataFrame,
    raw_csv: Mapping[str, pd.DataFrame],
) -> pd.DataFrame:
    """Return SampledProfile rows with xperf-equivalent PID/process fields.

    Native PerfInfo/SampledProfile events commonly use the kernel
    ``0xFFFFFFFF`` ProcessId sentinel in the event header. The payload's
    thread id is the reliable attribution key, so we resolve
    ``PayloadThreadId`` through Thread/DCStart/Start rows and then resolve
    the resulting PID through Process/DCStart/Start rows.
    """

    if samples is None or samples.empty:
        return samples

    tid_to_pid = _build_tid_to_pid_map_from_raw_csv(raw_csv)
    pid_to_name = _build_pid_to_name_map_from_raw_csv(raw_csv)

    df = samples.copy()
    changed = False

    if "PayloadThreadId" in df.columns and tid_to_pid:
        resolved_pid = pd.to_numeric(df["PayloadThreadId"], errors="coerce").map(tid_to_pid)
        if "PID" in df.columns:
            current_pid = pd.to_numeric(df["PID"], errors="coerce")
            needs_pid = (
                current_pid.isna()
                | (current_pid <= 0)
                | (current_pid == 0xFFFFFFFF)
            )
            fillable = needs_pid & resolved_pid.notna()
            if fillable.any():
                df.loc[fillable, "PID"] = resolved_pid[fillable].astype("int64")
                changed = True
        else:
            df["PID"] = resolved_pid.fillna(0).astype("int64")
            changed = True

    if pid_to_name and "PID" in df.columns:
        resolved_name = pd.to_numeric(df["PID"], errors="coerce").map(pid_to_name)
        if "Process Name" in df.columns:
            blank = _blank_process_name_mask(df["Process Name"])
            fillable = blank & resolved_name.notna()
            if fillable.any():
                df.loc[fillable, "Process Name"] = resolved_name[fillable].astype(str)
                changed = True
        else:
            df["Process Name"] = resolved_name.fillna("unknown").astype(str)
            changed = True

    if "Weight" in df.columns:
        weights = pd.to_numeric(df["Weight"], errors="coerce").fillna(1)
        weights = weights.where(weights > 0, 1).astype("int64")
        if not weights.equals(df["Weight"]):
            df["Weight"] = weights
            changed = True
    if "ProfileWeight" in df.columns:
        weights = pd.to_numeric(df["ProfileWeight"], errors="coerce").fillna(1)
        weights = weights.where(weights > 0, 1).astype("int64")
        if not weights.equals(df["ProfileWeight"]):
            df["ProfileWeight"] = weights
            changed = True

    if "PID" in df.columns:
        current_pid = pd.to_numeric(df["PID"], errors="coerce")
        sentinel = current_pid == 0xFFFFFFFF
        if sentinel.any():
            df.loc[sentinel, "PID"] = -1
            changed = True

    if "Process Name" in df.columns:
        blank = _blank_process_name_mask(df["Process Name"])
        if blank.any():
            df.loc[blank, "Process Name"] = "Unknown"
            changed = True

    return df if changed else samples


__all__ = [
    "aggregate_cpu_sampling",
    "enrich_sampled_profile_attribution",
]
