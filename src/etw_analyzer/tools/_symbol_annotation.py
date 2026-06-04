"""Shared helpers for annotating tool output with symbol-resolution
confidence indicators.

When the symbolizer falls back to PE export-table nearest-neighbour
resolution, the function names it returns are GUESSES — the address
that was sampled could be ANY internal (non-exported) function near
the matched export. Surfacing these as plain function names in
``get_hot_functions`` / ``get_hot_stacks`` is dishonest: callers will
draw conclusions from names that may be wrong by hundreds of bytes.

This module derives the set of "export-only" modules from the
SymbolSource breakdown in the cpu_sampling DataFrame and annotates
rows from those modules with a leading ``*`` plus a footnote pointing
at ``check_symbols`` / ``diagnose_symbol_load`` for follow-up.

The export-only module set is cached on the TraceData object via
``setattr`` so repeated tool calls on the same trace don't re-scan
the cpu_sampling frame.
"""

from __future__ import annotations

from typing import Iterable

import pandas as pd

from etw_analyzer.trace_state import TraceData

# Threshold mirrors check_symbols EXPORT_ONLY:
# pct_export >= 90 AND pct_pdb < 10. A module that crosses both bars
# has names that are almost entirely PE export-table guesses.
_EXPORT_THRESHOLD_PCT = 90.0
_PDB_THRESHOLD_PCT = 10.0

# Attribute name we hang the cached set off the TraceData object.
_CACHE_ATTR = "_export_only_modules"


def _compute_export_only_modules(cpu_df: pd.DataFrame) -> frozenset[str]:
    """Walk the cpu_sampling DataFrame and return the lowercased names
    of modules whose function names came (almost) entirely from the
    PE export table fallback.
    """
    if cpu_df is None or cpu_df.empty:
        return frozenset()
    if "SymbolSource" not in cpu_df.columns or "Module" not in cpu_df.columns:
        return frozenset()

    weight_col = "Weight" if "Weight" in cpu_df.columns else None
    export_only: set[str] = set()

    for module, group in cpu_df.groupby("Module", dropna=False):
        mod_str = str(module).strip()
        if not mod_str:
            continue

        source_col = group["SymbolSource"].astype(str)
        if weight_col:
            w = group[weight_col].astype(float)
            pdb_weight = float(w[source_col == "pdb"].sum())
            export_weight = float(w[source_col == "export"].sum())
            unknown_weight = float(w[source_col.isin(["unknown", ""])].sum())
            denom = pdb_weight + export_weight + unknown_weight
        else:
            pdb_weight = float((source_col == "pdb").sum())
            export_weight = float((source_col == "export").sum())
            unknown_weight = float(source_col.isin(["unknown", ""]).sum())
            denom = float(len(group))

        if denom <= 0:
            continue

        pct_pdb = pdb_weight / denom * 100.0
        pct_export = export_weight / denom * 100.0

        if pct_export >= _EXPORT_THRESHOLD_PCT and pct_pdb < _PDB_THRESHOLD_PCT:
            export_only.add(mod_str.lower())

    return frozenset(export_only)


def get_export_only_modules(trace: TraceData) -> frozenset[str]:
    """Return the cached set of export-only module names for ``trace``.

    Lowercased for case-insensitive matching. Empty when the trace
    cache predates v0.6 (no SymbolSource column) or when no module
    crosses the EXPORT_ONLY threshold.
    """
    cached = getattr(trace, _CACHE_ATTR, None)
    if cached is not None:
        return cached

    cpu_df = None
    for key in ("cpu_sampling", "CpuSampling", "CPU Usage (Sampled)"):
        if key in trace.raw_csv:
            cpu_df = trace.raw_csv[key]
            break

    result = _compute_export_only_modules(cpu_df) if cpu_df is not None else frozenset()
    setattr(trace, _CACHE_ATTR, result)
    return result


def annotate_export_fallback(
    df: pd.DataFrame,
    trace: TraceData,
    *,
    module_col: str = "Module",
    function_col: str = "Function",
) -> tuple[pd.DataFrame, bool]:
    """Prepend ``*`` to function names in rows from export-only modules.

    Returns ``(annotated_df, any_annotated)``. The caller is responsible
    for appending the footnote when ``any_annotated`` is True.

    The input frame is copied — the caller's frame is left untouched.
    """
    if df is None or df.empty:
        return df, False
    if module_col not in df.columns or function_col not in df.columns:
        return df, False

    export_only = get_export_only_modules(trace)
    if not export_only:
        return df, False

    annotated = df.copy()
    module_lc = annotated[module_col].astype(str).str.lower()
    mask = module_lc.isin(export_only)

    if not mask.any():
        return annotated, False

    annotated.loc[mask, function_col] = "*" + annotated.loc[mask, function_col].astype(str)
    return annotated, True


def export_fallback_footnote() -> str:
    """Standard footnote text appended below tables with ``*`` rows."""
    return (
        "\\* = function name came from PE export table fallback "
        "(PDB missing or stale). Names are nearest-neighbour guesses "
        "and may be wrong by hundreds of bytes. Run `check_symbols` "
        "to see which modules are EXPORT_ONLY and "
        "`diagnose_symbol_load(trace_id, '<module>')` to investigate."
    )


def export_fallback_modules_for_summary(
    trace: TraceData,
    matched_modules: Iterable[str],
) -> list[str]:
    """Return the subset of ``matched_modules`` that are EXPORT_ONLY,
    for callers that want to surface a list rather than annotate rows.
    """
    export_only = get_export_only_modules(trace)
    if not export_only:
        return []
    return [m for m in matched_modules if str(m).lower() in export_only]
