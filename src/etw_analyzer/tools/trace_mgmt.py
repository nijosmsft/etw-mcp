"""Trace management tools: list_traces, load_trace, trace_info, loaded trace registry."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from etw_analyzer.app import mcp
from etw_analyzer.trace_state import (
    TraceData,
    list_loaded_traces as get_loaded_traces,
    make_trace_id,
    register_trace,
    require_trace,
    unregister_trace,
)
from etw_analyzer.parsing.wpa_exporter import (
    _parse_stack_butterfly_html,
    export_all_profiles,
    find_xperf,
    parse_stack_butterfly_callers,
)
from etw_analyzer.parsing.csv_loader import load_csv
from etw_analyzer.formatting.markdown import format_table

import pandas as pd


@mcp.tool()
def list_traces(directory: str = r"C:\traces", pattern: str = "*.etl") -> str:
    """List ETL trace files in a directory.

    Args:
        directory: Directory to search for trace files. Default: C:\\traces
        pattern: Glob pattern for trace files. Default: *.etl
    """
    trace_dir = Path(directory)
    if not trace_dir.exists():
        return f"Directory not found: {directory}"

    files = sorted(trace_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return f"No {pattern} files found in {directory}"

    rows = []
    for f in files:
        stat = f.stat()
        size_mb = stat.st_size / (1024 * 1024)
        mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        rows.append({
            "Name": f.name,
            "Size": f"{size_mb:.1f} MB",
            "Modified": mtime.strftime("%Y-%m-%d %H:%M"),
            "Path": str(f),
        })

    df = pd.DataFrame(rows)
    return f"**ETL Traces in {directory}** ({len(files)} files)\n\n{format_table(df)}"


@mcp.tool()
def load_trace(
    etl_path: str,
    symbol_path: str | None = None,
    timeout_seconds: int = 300,
    force: bool = False,
) -> str:
    """Load an ETL trace file for analysis.

    Runs xperf to extract CPU sampling, DPC/ISR, and context switch data,
    then caches the results in memory. Takes 30-180 seconds depending on
    trace size and symbol resolution.

    If the trace was previously loaded, uses cached data for instant reload.
    Set force=True to delete the cache and re-export from scratch.

    Args:
        etl_path: Full path to the .etl file.
        symbol_path: NT symbol path (e.g. 'srv*C:\\symbols*https://msdl.microsoft.com/download/symbols').
                     If not set, uses _NT_SYMBOL_PATH env var.
        timeout_seconds: Max seconds per xperf invocation. Default: 300.
        force: Delete cached exports and re-run xperf. Default: False.
    """
    path = Path(etl_path)
    if not path.exists():
        return f"File not found: {etl_path}"
    if not path.suffix.lower() == ".etl":
        return f"Expected .etl file, got: {path.suffix}"

    # Resolve symbol path
    sym_path = symbol_path or os.environ.get("_NT_SYMBOL_PATH")

    # Export directory next to the ETL file
    export_dir = path.parent / f".etw-export-{path.stem}"

    # Force re-export: delete cache directory
    if force and export_dir.exists():
        import shutil
        shutil.rmtree(export_dir)

    xperf = find_xperf()
    if xperf is None:
        return (
            "xperf.exe not found. Install Windows Performance Toolkit "
            "(part of Windows SDK/ADK) or add it to PATH.\n\n"
            "Expected at: C:\\Program Files (x86)\\Windows Kits\\10\\Windows Performance Toolkit\\xperf.exe"
        )

    # Check if we can skip re-export (cached parquet/csv files exist and are newer than ETL)
    cached = _load_from_cache(export_dir, path)
    if cached is not None:
        errors: list[str] = []
        _refresh_stack_cache_from_html(export_dir, cached, errors)
        trace = TraceData(
            trace_id=make_trace_id(path),
            etl_path=path,
            export_dir=export_dir,
            symbol_path=sym_path,
            raw_csv=cached,
            export_errors=errors,
        )
        _populate_metadata(trace)
        register_trace(trace)
        _start_background_dumper(trace)
        summary = _format_load_summary(trace)
        return summary.replace("**Trace loaded:**", "**Trace loaded (from cache):**")

    # Build symcache — idempotent, fast when symbols already cached
    from etw_analyzer.parsing.wpa_exporter import _run_xperf
    try:
        _run_xperf(
            path, "symcache", ["-build"],
            symbol_path=sym_path,
            symbols=True,
            timeout_seconds=timeout_seconds,
        )
    except Exception:
        pass  # Non-fatal — continue with whatever symbols are available

    # Run exports (parallel xperf actions, saves parquet + raw text)
    results: dict[str, pd.DataFrame] = {}
    errors: list[str] = []

    try:
        file_paths = export_all_profiles(
            path, export_dir,
            symbol_path=sym_path,
            timeout_seconds=timeout_seconds,
        )
    except Exception as e:
        return f"Export failed: {e}"

    for profile_name, file_path in file_paths.items():
        try:
            results[profile_name] = _load_file(file_path)
        except Exception as e:
            errors.append(f"{profile_name}: {e}")

    _refresh_stack_cache_from_html(export_dir, results, errors)

    trace = TraceData(
        trace_id=make_trace_id(path),
        etl_path=path,
        export_dir=export_dir,
        symbol_path=sym_path,
        raw_csv=results,
        export_errors=errors,
    )

    _populate_metadata(trace)
    register_trace(trace)
    _start_background_dumper(trace)

    return _format_load_summary(trace)


def _refresh_stack_cache_from_html(
    export_dir: Path,
    results: dict[str, pd.DataFrame],
    errors: list[str],
) -> None:
    """Refresh stack parquet data from the richer xperf butterfly HTML."""
    butterfly_html = export_dir / "stack-butterfly.html"
    if not butterfly_html.exists():
        return

    try:
        html_text = butterfly_html.read_text(encoding="utf-8")
    except Exception as e:
        errors.append(f"stack-butterfly.html: {e}")
        return

    try:
        stacks_df = _parse_stack_butterfly_html(html_text)
        if not stacks_df.empty:
            stacks_df.to_parquet(export_dir / "stacks.parquet", index=False)
            results["stacks"] = stacks_df
    except Exception as e:
        errors.append(f"stacks: {e}")

    try:
        callers_df = parse_stack_butterfly_callers(html_text)
        if not callers_df.empty:
            callers_df.to_parquet(export_dir / "stacks_callers.parquet", index=False)
            results["stacks_callers"] = callers_df
    except Exception as e:
        errors.append(f"stacks_callers: {e}")


# Background-extracted dumper event classes. Each entry maps the canonical
# event-class name (the key in :data:`parsing.wpa_exporter.EVENT_HANDLERS`)
# to the (a) trace attribute that holds the DataFrame and (b) the parquet
# filename stem used for cache rehydration. Adding a new event class is
# done here, not in extraction code.
#
# Every parquet stem listed here MUST also appear in ``_PARQUET_EXCLUDED``
# below so the glob-based ``_load_from_cache`` does not load it into
# ``raw_csv`` (these DataFrames live on dedicated trace attributes).
_DUMPER_EVENT_CLASSES: dict[str, tuple[str, str]] = {
    "SampledProfile":   ("dumper_df",            "sampled_profile"),
    "CSwitch":          ("cswitch_events_df",    "cswitch_events"),
    "TcpIp/Recv":       ("tcpip_recv_df",        "tcpip_recv"),
    "TcpIp/Send":       ("tcpip_send_df",        "tcpip_send"),
    "TcpIp/Retransmit": ("tcpip_retransmit_df",  "tcpip_retransmit"),
    "TcpIp/Connect":    ("tcpip_connect_df",     "tcpip_connect"),
    "TcpIp/Accept":     ("tcpip_accept_df",      "tcpip_accept"),
    "UdpIp/Recv":       ("udp_recv_df",          "udp_recv"),
    "UdpIp/Send":       ("udp_send_df",          "udp_send"),
}


def _start_background_dumper(trace: TraceData) -> None:
    """Start background extraction of dumper events (single xperf pass).

    Runs ``xperf -a dumper`` once and dispatches each line to the appropriate
    handler in :data:`parsing.wpa_exporter.EVENT_HANDLERS`. One DataFrame per
    canonical event class listed in :data:`_DUMPER_EVENT_CLASSES` is populated
    and cached to parquet.

    Cache policy: if every parquet already exists, the trace is fully
    rehydrated synchronously (fast path). Otherwise a background thread is
    launched that extracts *only the missing classes* — already-cached
    classes are not re-extracted.

    Trace attributes touched (currently):
      - ``dumper_df`` ← SampledProfile
      - ``cswitch_events_df`` ← CSwitch
      - ``tcpip_recv_df`` / ``tcpip_send_df`` / ``tcpip_retransmit_df``
      - ``tcpip_connect_df`` / ``tcpip_accept_df``
      - ``udp_recv_df`` / ``udp_send_df``

    The mapping is data-driven via :data:`_DUMPER_EVENT_CLASSES`; this
    function stays generic.
    """
    import threading

    def _parquet_for(stem: str) -> Path:
        return trace.export_dir / f"{stem}.parquet"

    with trace.lock:
        # Already fully populated, or a background thread is already running.
        all_loaded = all(
            getattr(trace, attr) is not None
            for attr, _ in _DUMPER_EVENT_CLASSES.values()
        )
        if all_loaded or trace._dumper_future is not None:
            return

        # Fast path: rehydrate any class whose parquet is already on disk.
        # Glob-based ``_load_from_cache`` excludes these stems so they don't
        # leak into ``raw_csv``.
        for canonical, (attr, stem) in _DUMPER_EVENT_CLASSES.items():
            parquet = _parquet_for(stem)
            if getattr(trace, attr) is None and parquet.exists():
                try:
                    setattr(trace, attr, pd.read_parquet(parquet))
                except Exception:
                    pass

        # If everything is cached now, signal ready and return.
        if all(
            getattr(trace, attr) is not None
            for attr, _ in _DUMPER_EVENT_CLASSES.values()
        ):
            trace._dumper_ready.set()
            return

    def _extract():
        try:
            from etw_analyzer.parsing.wpa_exporter import parse_dumper_events

            # Only re-extract classes that weren't cached. A single xperf
            # pass services all of them.
            wanted: set[str] = {
                canonical
                for canonical, (attr, _) in _DUMPER_EVENT_CLASSES.items()
                if getattr(trace, attr) is None
            }

            if not wanted:
                return

            results = parse_dumper_events(
                etl_path=trace.etl_path,
                symbol_path=trace.symbol_path,
                cpu_filter=None,
                start_time=None,
                end_time=None,
                timeout_seconds=300,
                event_classes=wanted,
            )
            with trace.lock:
                for canonical, (attr, stem) in _DUMPER_EVENT_CLASSES.items():
                    if canonical not in results:
                        continue
                    df = results[canonical]
                    setattr(trace, attr, df)
                    if not df.empty:
                        trace.export_dir.mkdir(parents=True, exist_ok=True)
                        try:
                            df.to_parquet(_parquet_for(stem), index=False)
                        except Exception:
                            # Non-fatal: keep the in-memory DataFrame even if
                            # we can't persist (e.g. disk full, readonly).
                            pass
        except Exception as e:
            with trace.lock:
                trace._dumper_error = str(e)
        finally:
            trace._dumper_ready.set()

    thread = threading.Thread(target=_extract, daemon=True, name="dumper-extract")
    with trace.lock:
        # Re-check after thread construction — another caller may have
        # raced us in.
        if all(
            getattr(trace, attr) is not None
            for attr, _ in _DUMPER_EVENT_CLASSES.values()
        ) or trace._dumper_future is not None:
            return
        trace._dumper_future = thread
        thread.start()


def _load_file(file_path: Path) -> pd.DataFrame:
    """Load a single exported file (parquet, csv, or raw text)."""
    if file_path.suffix == ".parquet":
        return pd.read_parquet(file_path)
    elif file_path.suffix == ".csv":
        return load_csv(file_path)
    elif file_path.suffix in (".txt", ".html"):
        return pd.DataFrame({"raw_text": [file_path.read_text(encoding="utf-8")]})
    else:
        raise ValueError(f"Unknown file type: {file_path.suffix}")


# Parquet datasets are discovered dynamically via glob on the export directory
# (see _load_from_cache). This means new parquets written by future event-class
# exporters (e.g. tcpip_recv.parquet, udp_events.parquet, afd_events.parquet)
# are picked up automatically without changes here.
#
# Approach chosen: glob-based discovery (option A).
# Reasoning: parquet filename == dataset name is already the convention enforced
# by wpa_exporter._save_df (writes "{name}.parquet"). A registry would require
# every new producer module to be imported before _load_from_cache runs, which
# is fragile given lazy-import patterns in this codebase. Glob discovery is
# self-maintaining: drop a file in the dir, it loads.
#
# Stray-file mitigation: _PARQUET_EXCLUDED lists parquets that live in the
# same export dir but are NOT part of raw_csv (loaded into other slots like
# trace.dumper_df). Any other unexpected .parquet files will be loaded under
# their filename stem — this is intentional so new exporters "just work".
_PARQUET_EXCLUDED = frozenset({
    "sampled_profile",   # Loaded into trace.dumper_df by _start_background_dumper
    "cswitch_events",    # Loaded into trace.cswitch_events_df by _start_background_dumper
    # Phase 3a networking event-class parquets. Loaded into dedicated
    # trace attributes (tcpip_recv_df, ...) by _start_background_dumper.
    "tcpip_recv",
    "tcpip_send",
    "tcpip_retransmit",
    "tcpip_connect",
    "tcpip_accept",
    "udp_recv",
    "udp_send",
})

# Datasets that MUST be present (and load successfully) for the cache to be
# considered usable. Without cpu_sampling, most analysis tools have nothing
# to chew on, so we treat it as the floor. Other datasets are best-effort.
_PARQUET_REQUIRED = frozenset({"cpu_sampling"})

# Legacy exports may have written .csv instead of .parquet for the original
# five datasets. Only fall back to CSV for these names, since we have no
# equivalent allowlist signal for new event classes.
_LEGACY_CSV_DATASETS = frozenset({
    "cpu_sampling", "cpu_timeline", "dpc_isr", "stacks", "stacks_callers",
})

# Datasets that are raw text files
_TEXT_DATASETS = {
    "dpc_isr_raw": "dpcisr.txt",
    "cswitch_raw": "cswitch.txt",
    "tracestats": "tracestats.txt",
    "sysconfig": "sysconfig.txt",
    "process_info": "process_info.txt",
    "diskio": "diskio.txt",
}


def _load_from_cache(export_dir: Path, etl_path: Path) -> dict[str, pd.DataFrame] | None:
    """Try to load previously exported data from the cache directory.

    Returns None if the cache is missing or stale (ETL is newer than cache).

    Parquet files are discovered by globbing the export directory rather than
    iterating a hardcoded allowlist. Each "{name}.parquet" becomes a dataset
    keyed by its filename stem, except names listed in _PARQUET_EXCLUDED which
    are owned by other code paths.

    Freshness policy: the cache is considered fresh if all names in
    _PARQUET_REQUIRED loaded successfully (currently just cpu_sampling). This
    matches the previous behaviour where "no useful data" returned None, but
    is now keyed on a documented required set rather than an implicit
    "at least one" check.
    """
    if not export_dir.exists():
        return None

    # Staleness check: if ETL is newer than export dir, re-export
    try:
        etl_mtime = etl_path.stat().st_mtime
        export_mtime = export_dir.stat().st_mtime
        if etl_mtime > export_mtime:
            return None
    except OSError:
        return None

    results: dict[str, pd.DataFrame] = {}

    # Discover parquet datasets via glob — any *.parquet not in the exclusion
    # set is loaded as a dataset keyed by its filename stem.
    for parquet_path in sorted(export_dir.glob("*.parquet")):
        name = parquet_path.stem
        if name in _PARQUET_EXCLUDED:
            continue
        try:
            results[name] = pd.read_parquet(parquet_path)
        except Exception:
            pass

    # Backward-compat: see _LEGACY_CSV_DATASETS at module scope.
    for name in _LEGACY_CSV_DATASETS:
        if name in results:
            continue
        csv_path = export_dir / f"{name}.csv"
        if csv_path.exists():
            try:
                results[name] = load_csv(csv_path)
            except Exception:
                pass

    # Freshness gate: every required dataset must have loaded.
    if not _PARQUET_REQUIRED.issubset(results.keys()):
        return None

    for key, filename in _TEXT_DATASETS.items():
        txt_path = export_dir / filename
        if txt_path.exists():
            try:
                results[key] = pd.DataFrame({"raw_text": [txt_path.read_text(encoding="utf-8")]})
            except Exception:
                pass

    return results


def _populate_metadata(trace: TraceData) -> None:
    """Extract metadata from loaded DataFrames."""
    for name, df in trace.raw_csv.items():
        trace.event_counts[name] = len(df)

        # Try to find CPU count from CPU column
        if trace.cpu_count is None and "CPU" in df.columns:
            try:
                trace.cpu_count = int(df["CPU"].max()) + 1
            except (ValueError, TypeError):
                pass

        # Try to find trace duration from timestamp column
        if trace.duration_seconds is None:
            for col in ["TimeStamp", "Time", "Timestamp (s)"]:
                if col in df.columns:
                    try:
                        vals = pd.to_numeric(df[col], errors="coerce").dropna()
                        if not vals.empty:
                            trace.duration_seconds = float(vals.max() - vals.min())
                            break
                    except Exception:
                        pass


def _format_load_summary(trace: TraceData) -> str:
    """Format a summary of the loaded trace."""
    lines = [
        f"**Trace loaded:** `{trace.etl_path.name}`",
        f"**Trace ID:** `{trace.trace_id}`",
        "",
    ]

    if trace.duration_seconds:
        lines.append(f"- **Duration:** {trace.duration_seconds:.1f}s")
    if trace.cpu_count:
        lines.append(f"- **CPUs:** {trace.cpu_count}")
    if trace.symbol_path:
        lines.append(f"- **Symbols:** `{trace.symbol_path[:80]}...`" if len(trace.symbol_path or "") > 80 else f"- **Symbols:** `{trace.symbol_path}`")

    lines.append("")
    lines.append("**Exported datasets:**")
    for name, df in trace.raw_csv.items():
        cols_preview = ", ".join(df.columns[:6])
        if len(df.columns) > 6:
            cols_preview += f", ... (+{len(df.columns) - 6} more)"
        lines.append(f"- `{name}`: {len(df):,} rows — columns: {cols_preview}")

    if trace.export_errors:
        lines.append("")
        lines.append("**Export warnings:**")
        for err in trace.export_errors:
            lines.append(f"- {err}")

    lines.append("")
    lines.append(
        f"Ready for analysis. Pass `trace_id=\"{trace.trace_id}\"` to analysis tools "
        "such as `get_cpu_samples`, `get_hot_functions`, and `get_dpc_summary`."
    )

    return "\n".join(lines)


@mcp.tool()
def trace_info(trace_id: str) -> str:
    """Show metadata about a loaded trace.

    Returns duration, CPU count, event counts, symbol status, and available datasets.

    Args:
        trace_id: ID returned by load_trace.
    """
    trace = require_trace(trace_id)
    return _format_load_summary(trace)


@mcp.tool()
def list_loaded_traces() -> str:
    """Show traces currently loaded in this MCP server process."""
    traces = get_loaded_traces()
    if not traces:
        return "*No traces loaded. Call `load_trace` first.*"

    rows = []
    for trace in traces:
        rows.append({
            "Trace ID": trace.trace_id,
            "Name": trace.etl_path.name,
            "Path": str(trace.etl_path),
            "Datasets": len(trace.raw_csv),
            "CPUs": trace.cpu_count if trace.cpu_count is not None else "",
            "Duration (s)": f"{trace.duration_seconds:.1f}" if trace.duration_seconds is not None else "",
        })

    return f"**Loaded Traces** ({len(rows)})\n\n{format_table(pd.DataFrame(rows))}"


@mcp.tool()
def unload_trace(trace_id: str) -> str:
    """Remove a loaded trace from memory.

    Args:
        trace_id: ID returned by load_trace.
    """
    trace = require_trace(trace_id)
    if unregister_trace(trace_id):
        return f"Unloaded trace `{trace.trace_id}` (`{trace.etl_path.name}`)"
    return f"Trace `{trace_id}` was not loaded."


@mcp.tool()
def check_symbols(trace_id: str) -> str:
    """Check symbol resolution status for a trace.

    Reports:
    - Each path in _NT_SYMBOL_PATH: exists/accessible, contains PDBs
    - Per-module symbol resolution: resolved vs Unknown functions
    - Top unresolved modules (likely missing PDBs)
    - Recommendations for fixing symbol issues

    Args:
        trace_id: ID returned by load_trace.
    """
    trace = require_trace(trace_id)
    lines: list[str] = ["**Symbol Resolution Check**", ""]

    # 1. Symbol path analysis
    sym_path = trace.symbol_path or os.environ.get("_NT_SYMBOL_PATH", "")
    lines.append("**Symbol Path (`_NT_SYMBOL_PATH`):**")
    if not sym_path:
        lines.append("- **NOT SET** — xperf cannot resolve function names without symbols")
        lines.append("- Set via: `_NT_SYMBOL_PATH=srv*C:\\symbols*https://msdl.microsoft.com/download/symbols`")
        lines.append("")
    else:
        # Parse the semicolon-separated path entries
        entries = [e.strip() for e in sym_path.split(";") if e.strip()]
        for entry in entries:
            status = _check_symbol_entry(entry)
            lines.append(f"- `{entry}`")
            lines.append(f"  {status}")
        lines.append("")

    # 2. Per-module resolution stats from CPU sampling data
    cpu_df = None
    for key in ["cpu_sampling", "CpuSampling", "CPU Usage (Sampled)"]:
        if key in trace.raw_csv:
            cpu_df = trace.raw_csv[key]
            break

    if cpu_df is not None and "Module" in cpu_df.columns and "Function" in cpu_df.columns:
        lines.append("**Per-Module Symbol Resolution:**")
        lines.append("")

        weight_col = "Weight" if "Weight" in cpu_df.columns else None

        # Group by module, check resolved vs unknown
        rows = []
        for module, group in cpu_df.groupby("Module", dropna=False):
            mod_str = str(module)
            total_funcs = len(group)
            unknown = group["Function"].astype(str).str.contains(
                r"^Unknown$|^\*\*\*unknown\*\*\*$|^$", case=False, na=True
            ).sum()
            resolved = total_funcs - unknown
            pct_resolved = (resolved / total_funcs * 100) if total_funcs > 0 else 0

            mod_weight = int(group[weight_col].sum()) if weight_col else total_funcs

            if pct_resolved >= 90:
                status_icon = "OK"
            elif pct_resolved > 0:
                status_icon = "PARTIAL"
            else:
                status_icon = "MISSING"

            rows.append({
                "Module": mod_str,
                "Functions": total_funcs,
                "Resolved": resolved,
                "Unknown": unknown,
                "% Resolved": f"{pct_resolved:.0f}%",
                "Weight": mod_weight,
                "Status": status_icon,
            })

        result_df = pd.DataFrame(rows)
        result_df = result_df.sort_values("Weight", ascending=False).reset_index(drop=True)
        lines.append(format_table(result_df, max_rows=25))
        lines.append("")

        # 3. Summary and recommendations
        total_weight = result_df["Weight"].sum()
        missing_df = result_df[result_df["Status"] == "MISSING"]
        missing_weight = missing_df["Weight"].sum()
        missing_pct = (missing_weight / total_weight * 100) if total_weight > 0 else 0

        lines.append("**Summary:**")
        lines.append(f"- Total modules: {len(result_df)}")
        lines.append(f"- Fully resolved: {len(result_df[result_df['Status'] == 'OK'])}")
        lines.append(f"- Partially resolved: {len(result_df[result_df['Status'] == 'PARTIAL'])}")
        lines.append(f"- No symbols: {len(missing_df)}")
        lines.append(f"- Unresolved weight: {missing_pct:.1f}% of total CPU samples")
        lines.append("")

        if not missing_df.empty:
            lines.append("**Top Unresolved Modules (need PDBs):**")
            top_missing = missing_df.head(10)
            for _, row in top_missing.iterrows():
                lines.append(f"- `{row['Module']}` — {row['Weight']:,} weight ({row['Weight']/total_weight*100:.1f}%)")
            lines.append("")

            lines.append("**Recommendations:**")
            # Check for common modules
            missing_names = set(missing_df["Module"].str.lower())
            if any(m in missing_names for m in ["ntoskrnl.exe", "ntkrnlmp.exe"]):
                lines.append("- **ntoskrnl.exe**: Download from symbol server — "
                           "`symchk /s srv*C:\\symbols*https://msdl.microsoft.com/download/symbols "
                           "C:\\Windows\\System32\\ntoskrnl.exe`")
            if "afd.sys" in missing_names:
                lines.append("- **afd.sys**: `symchk /s srv*C:\\symbols*https://msdl.microsoft.com/download/symbols "
                           "C:\\Windows\\System32\\drivers\\afd.sys`")
            if "ndis.sys" in missing_names:
                lines.append("- **ndis.sys**: `symchk /s srv*C:\\symbols*https://msdl.microsoft.com/download/symbols "
                           "C:\\Windows\\System32\\drivers\\ndis.sys`")
            if any("xdp" in m for m in missing_names):
                lines.append("- **xdp.sys**: Add XDP build artifacts directory to `_NT_SYMBOL_PATH`")
            lines.append("- For Microsoft internal builds: add `https://symweb.azurefd.net` to symbol path")
            lines.append("- After downloading PDBs, re-run `load_trace` to re-analyze with symbols")

    else:
        lines.append("*No CPU sampling data loaded — load a trace first with `load_trace`.*")

    return "\n".join(lines)


@mcp.tool()
def resolve_symbols(trace_id: str, modules: str | None = None) -> str:
    """Build symbol cache for a trace using xperf.

    Runs xperf -a symcache -build which uses dbghelp.dll to download PDBs
    from the symbol servers configured in _NT_SYMBOL_PATH. Also shows debug
    IDs for any modules that fail to resolve.

    Args:
        trace_id: ID returned by load_trace.
        modules: Comma-separated module names to focus on (e.g. 'ntoskrnl.exe,ndis.sys').
                 Default: all modules in the trace.
    """
    try:
        return _resolve_symbols_impl(trace_id, modules)
    except Exception as e:
        return f"Symbol resolution failed: {e}"


def _resolve_symbols_impl(trace_id: str, modules: str | None) -> str:
    import re
    from etw_analyzer.parsing.wpa_exporter import find_xperf, _run_xperf

    trace = require_trace(trace_id)
    path = trace.etl_path

    if not path.exists():
        return f"File not found: {path}"

    sym_path = trace.symbol_path or os.environ.get("_NT_SYMBOL_PATH", "")
    lines = ["**Symbol Resolver**", ""]
    lines.append(f"Trace: `{path.name}`")
    lines.append(f"Trace ID: `{trace.trace_id}`")
    lines.append(f"Symbol path: `{sym_path[:120]}{'...' if len(sym_path) > 120 else ''}`")
    lines.append("")

    xperf = find_xperf()
    if xperf is None:
        return "xperf.exe not found."

    if not sym_path:
        lines.append("**WARNING:** `_NT_SYMBOL_PATH` is not set. Configure it in `.mcp.json` env.")
        lines.append("")

    # Parse module filter
    image_args: list[str] = []
    if modules:
        mod_list = [m.strip() for m in modules.split(",") if m.strip()]
        image_args = ["-image"] + mod_list
        lines.append(f"Modules: {', '.join(mod_list)}")
    else:
        lines.append("Modules: all")
    lines.append("")

    # Step 1: Build symcache (downloads PDBs via dbghelp.dll)
    lines.append("**Building symcache (downloading PDBs)...**")
    try:
        text = _run_xperf(
            path, "symcache", ["-build"] + image_args,
            symbol_path=sym_path or None,
            symbols=True,
            timeout_seconds=300,
        )
        warnings = [l.strip() for l in text.splitlines()
                    if "warning" in l.lower() or "not found" in l.lower()]
        progress = [l.strip() for l in text.splitlines()
                    if "%" in l or l.strip().startswith("[")]

        if progress:
            for p in progress[:5]:
                lines.append(f"  {p}")

        if warnings:
            lines.append("")
            lines.append(f"**Failed to resolve ({len(warnings)} modules):**")
            for w in warnings[:20]:
                lines.append(f"- {w}")
        elif not text.strip():
            lines.append("Completed (symbols may already be cached)")
        else:
            lines.append("All symbols resolved successfully")
    except Exception as e:
        lines.append(f"symcache build error: {e}")

    lines.append("")

    # Step 2: Show debug IDs for unresolved modules
    lines.append("**Debug IDs (PDB GUID/Age from trace):**")
    try:
        text = _run_xperf(
            path, "symcache", ["-dbgid"] + image_args,
            symbol_path=sym_path or None,
            symbols=False,
            timeout_seconds=60,
        )
        dbg_lines = [l.strip().strip('"') for l in text.splitlines() if "[RSDS]" in l]
        if dbg_lines:
            for dl in dbg_lines[:30]:
                lines.append(f"- `{dl}`")
        else:
            lines.append("No RSDS debug records found")
    except Exception as e:
        lines.append(f"dbgid query error: {e}")

    # Step 3: Re-export trace with newly resolved symbols
    lines.append("")
    lines.append("**Re-loading trace with resolved symbols...**")
    try:
        import shutil
        export_dir = path.parent / f".etw-export-{path.stem}"
        if export_dir.exists():
            shutil.rmtree(export_dir)
        reload_result = load_trace(str(path), symbol_path=trace.symbol_path)
        lines.append(reload_result)
    except Exception as e:
        lines.append(f"Re-load failed: {e}")
        lines.append("Run `load_trace` manually to re-analyze.")

    return "\n".join(lines)


def _check_symbol_entry(entry: str) -> str:
    """Check a single _NT_SYMBOL_PATH entry and return status string."""
    # srv*cache*server format
    if entry.lower().startswith("srv*"):
        parts = entry.split("*")
        statuses = []

        # Check cache directory
        if len(parts) >= 2 and parts[1]:
            cache_path = Path(parts[1])
            if cache_path.exists():
                # Count PDB files
                pdbs = list(cache_path.glob("**/*.pdb"))
                statuses.append(f"Cache `{parts[1]}`: {len(pdbs)} PDBs cached")
            else:
                statuses.append(f"Cache `{parts[1]}`: directory does not exist (will be created on first use)")

        # Check server URL
        if len(parts) >= 3 and parts[2]:
            server = parts[2]
            if "msdl.microsoft.com" in server:
                statuses.append(f"Server: Microsoft public symbol server")
            elif "symweb" in server:
                statuses.append(f"Server: Microsoft internal symbol server (requires corpnet)")
            else:
                statuses.append(f"Server: `{server}`")

        return " | ".join(statuses) if statuses else "Symbol server entry"

    # Plain directory path
    path = Path(entry)
    if path.exists():
        if path.is_dir():
            pdbs = list(path.glob("*.pdb"))
            sys_pdbs = list(path.glob("**/*.pdb"))
            if sys_pdbs:
                return f"OK — directory exists, {len(sys_pdbs)} PDB files found"
            else:
                return f"WARNING — directory exists but no .pdb files found"
        elif path.is_file():
            return f"OK — file exists ({path.stat().st_size / 1024:.0f} KB)"
        else:
            return f"EXISTS — unknown type"
    else:
        return f"NOT FOUND — `{entry}` does not exist"
