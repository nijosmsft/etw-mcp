"""Trace comparison tools — diff two traces to find regressions."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import TraceData, make_trace_id
from etw_analyzer.tools.trace_mgmt import (
    _load_file,
    _load_from_cache,
    _write_cache_manifest,
)
from etw_analyzer.parsing.wpa_exporter import export_all_profiles, find_xperf, _run_xperf
from etw_analyzer.parsing.csv_loader import load_csv
from etw_analyzer.formatting.markdown import format_table, format_pct

import os


def _load_trace_data(etl_path: str) -> TraceData:
    """Load a trace into a TraceData object without setting it as current."""
    path = Path(etl_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {etl_path}")

    sym_path = os.environ.get("_NT_SYMBOL_PATH")
    export_dir = path.parent / f".etw-export-{path.stem}"

    # Try cache first
    cached = _load_from_cache(export_dir, path, mode="xperf")
    if cached is not None:
        return TraceData(
            trace_id=make_trace_id(path),
            etl_path=path,
            export_dir=export_dir,
            symbol_path=sym_path,
            raw_csv=cached,
        )

    # Export
    try:
        _run_xperf(path, "symcache", ["-build"], symbol_path=sym_path, symbols=True, timeout_seconds=300)
    except Exception:
        pass

    file_paths = export_all_profiles(path, export_dir, symbol_path=sym_path, timeout_seconds=300)
    results: dict[str, pd.DataFrame] = {}
    for name, fp in file_paths.items():
        try:
            results[name] = _load_file(fp)
        except Exception:
            pass

    _write_cache_manifest(export_dir, path, "xperf", results, dumper_stems=frozenset())

    return TraceData(
        trace_id=make_trace_id(path),
        etl_path=path,
        export_dir=export_dir,
        symbol_path=sym_path,
        raw_csv=results,
    )


@mcp.tool()
def compare_traces(
    baseline_etl: str,
    test_etl: str,
    mode: str = "hot_functions",
    modules: str | None = None,
    max_rows: int = 30,
) -> str:
    """Compare two traces to find performance differences.

    Loads both traces (using cache if available), computes per-module or
    per-function CPU weight, and shows the delta between them. Positive
    delta means the test trace uses MORE CPU than baseline.

    The loaded trace registry is NOT affected — comparison uses separate
    TraceData objects.

    Args:
        baseline_etl: Path to baseline .etl file.
        test_etl: Path to test .etl file.
        mode: Comparison mode — 'hot_functions' (module+function), 'modules' (module only),
              or 'per_cpu' (per-CPU utilization). Default: 'hot_functions'.
        modules: Comma-separated module filter for hot_functions/modules mode.
                 Use 'all' for no filtering. Default: networking stack.
        max_rows: Maximum rows to show. Default: 30.
    """
    # Load both traces
    try:
        baseline = _load_trace_data(baseline_etl)
    except Exception as e:
        return f"*Failed to load baseline trace: {e}*"

    try:
        test = _load_trace_data(test_etl)
    except Exception as e:
        return f"*Failed to load test trace: {e}*"

    if mode == "per_cpu":
        return _compare_per_cpu(baseline, test, max_rows)
    else:
        return _compare_sampling(baseline, test, mode, modules, max_rows)


def _compare_sampling(
    baseline: TraceData,
    test: TraceData,
    mode: str,
    modules: str | None,
    max_rows: int,
) -> str:
    """Compare CPU sampling data between two traces."""
    b_df = baseline.raw_csv.get("cpu_sampling")
    t_df = test.raw_csv.get("cpu_sampling")

    if b_df is None or t_df is None:
        return "*Both traces must have CPU sampling data for comparison.*"

    # Determine grouping
    if mode == "modules":
        group_cols = ["Module"]
    else:
        group_cols = ["Module", "Function"]

    # Module filter
    from etw_analyzer.tools.cpu_sampling import _DEFAULT_HOT_MODULES
    if modules and modules.strip().lower() != "all":
        target = [m.strip().lower() for m in modules.split(",")]
    elif modules and modules.strip().lower() == "all":
        target = None
    else:
        target = [m.lower() for m in _DEFAULT_HOT_MODULES]

    def _aggregate(df: pd.DataFrame) -> pd.DataFrame:
        if "Weight" not in df.columns:
            return pd.DataFrame()
        if target and "Module" in df.columns:
            df = df[df["Module"].str.lower().apply(lambda m: any(t in m for t in target))]
        existing = [c for c in group_cols if c in df.columns]
        if not existing:
            return pd.DataFrame()
        result = df.groupby(existing, dropna=False)["Weight"].sum().reset_index()
        total = result["Weight"].sum()
        result["% Weight"] = (result["Weight"] / total * 100) if total > 0 else 0
        return result

    b_agg = _aggregate(b_df)
    t_agg = _aggregate(t_df)

    if b_agg.empty or t_agg.empty:
        return "*Could not aggregate sampling data from both traces.*"

    # Merge on group columns
    existing = [c for c in group_cols if c in b_agg.columns and c in t_agg.columns]
    merged = pd.merge(
        b_agg, t_agg,
        on=existing, how="outer",
        suffixes=("_baseline", "_test"),
    ).fillna(0)

    merged["Delta Weight"] = merged["Weight_test"] - merged["Weight_baseline"]
    merged["Delta %"] = merged["% Weight_test"] - merged["% Weight_baseline"]

    # Sort by absolute delta descending
    merged["_abs_delta"] = merged["Delta %"].abs()
    merged = merged.sort_values("_abs_delta", ascending=False).head(max_rows)

    # Format output
    rows = []
    for _, row in merged.iterrows():
        out = {}
        for c in existing:
            out[c] = row[c]
        out["Baseline %"] = f"{row['% Weight_baseline']:.2f}%"
        out["Test %"] = f"{row['% Weight_test']:.2f}%"
        delta = row["Delta %"]
        sign = "+" if delta > 0 else ""
        out["Delta"] = f"{sign}{delta:.2f}%"
        rows.append(out)

    result_df = pd.DataFrame(rows)

    b_name = Path(baseline.etl_path).stem
    t_name = Path(test.etl_path).stem

    header = (
        f"**Trace Comparison** ({mode})\n"
        f"- Baseline: `{b_name}`\n"
        f"- Test: `{t_name}`\n"
        f"- Positive delta = test uses MORE CPU"
    )

    return f"{header}\n\n{format_table(result_df, max_rows=max_rows)}"


def _compare_per_cpu(
    baseline: TraceData,
    test: TraceData,
    max_rows: int,
) -> str:
    """Compare per-CPU utilization between two traces."""
    import re

    b_tl = baseline.raw_csv.get("cpu_timeline")
    t_tl = test.raw_csv.get("cpu_timeline")

    if b_tl is None or t_tl is None:
        return "*Both traces must have cpu_timeline data for per-CPU comparison.*"

    def _avg_per_cpu(df: pd.DataFrame) -> dict[int, float]:
        avgs = {}
        for col in df.columns:
            m = re.match(r"Cpu\s+(\d+)", col, re.IGNORECASE)
            if m:
                cpu_id = int(m.group(1))
                vals = pd.to_numeric(df[col], errors="coerce").dropna()
                avgs[cpu_id] = float(vals.mean()) if not vals.empty else 0.0
        return avgs

    b_avgs = _avg_per_cpu(b_tl)
    t_avgs = _avg_per_cpu(t_tl)

    all_cpus = sorted(set(b_avgs.keys()) | set(t_avgs.keys()))

    rows = []
    for cpu in all_cpus:
        b_val = b_avgs.get(cpu, 0)
        t_val = t_avgs.get(cpu, 0)
        delta = t_val - b_val
        if abs(delta) < 0.5 and b_val < 1 and t_val < 1:
            continue  # Skip idle CPUs with no change
        sign = "+" if delta > 0 else ""
        rows.append({
            "CPU": cpu,
            "Baseline %": f"{b_val:.1f}%",
            "Test %": f"{t_val:.1f}%",
            "Delta": f"{sign}{delta:.1f}%",
            "_abs": abs(delta),
        })

    result_df = pd.DataFrame(rows)
    result_df = result_df.sort_values("_abs", ascending=False).drop(columns=["_abs"]).head(max_rows)

    b_name = Path(baseline.etl_path).stem
    t_name = Path(test.etl_path).stem
    b_active = sum(1 for v in b_avgs.values() if v >= 2)
    t_active = sum(1 for v in t_avgs.values() if v >= 2)

    header = (
        f"**Per-CPU Comparison**\n"
        f"- Baseline: `{b_name}` ({b_active} active CPUs)\n"
        f"- Test: `{t_name}` ({t_active} active CPUs)\n"
        f"- Positive delta = test uses MORE CPU on that core"
    )

    return f"{header}\n\n{format_table(result_df, max_rows=max_rows)}"
