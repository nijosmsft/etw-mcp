"""Trace management tools: list_traces, load_trace, trace_info, loaded trace registry."""

from __future__ import annotations

import os
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from etw_analyzer.app import mcp
from etw_analyzer.native import telemetry as _telemetry
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
    mode: str = "auto",
) -> str:
    """Load an ETL trace file for analysis.

    Extracts CPU sampling, DPC/ISR, context switch, networking, HTTP, and
    QUIC events from the trace and caches the results in memory. Takes
    30-180 seconds depending on trace size and symbol resolution.

    If the trace was previously loaded, uses cached data for instant reload.
    Set force=True to delete the cache and re-export from scratch.

    Args:
        etl_path: Full path to the .etl file.
        symbol_path: NT symbol path (e.g. 'srv*C:\\symbols*https://msdl.microsoft.com/download/symbols').
                     If not set, uses _NT_SYMBOL_PATH env var.
        timeout_seconds: Max seconds per xperf invocation. Default: 300.
                         Native ETW extraction currently runs to completion;
                         non-default timeout values require mode="xperf".
        force: Delete cached exports and re-run xperf. Default: False.
        mode: Pipeline used to load the trace.
              ``"auto"`` (default — Phase N5) walks the documented
              fallback chain ``csharp → native → xperf``: the C# sidecar
              when the ``WPR_MCP_CSHARP_SIDECAR`` env var is set (or
              ``wpr-mcp-extract.exe`` is on PATH), then the in-process
              ``OpenTraceW`` consumer when its bindings load, then the
              legacy text-based ``xperf -a dumper`` as the universal
              opt-out. ``"csharp"`` forces the C# sidecar and raises if
              the binary is unfindable (naming the env var override).
              ``"native"`` forces the in-process consumer and raises if
              it's unavailable. ``"xperf"`` forces the legacy pipeline.
              The ``WPR_MCP_MODE`` environment variable overrides this
              arg when the arg is left at its default. The native and
              csharp pipelines are fast paths for a curated event /
              aggregation subset; use ``mode="xperf"`` for broadest
              coverage.
    """
    path = Path(etl_path)
    if not path.exists():
        return (
            f"File not found: {etl_path}\n\n"
            "Use list_traces(directory=...) to enumerate .etl files in a "
            "directory, or check the path for typos / drive-letter case. "
            "load_trace needs an absolute path to an existing .etl file."
        )
    if not path.suffix.lower() == ".etl":
        return (
            f"Expected .etl file, got: {path.suffix or '(no suffix)'}\n\n"
            f"Path: {etl_path}\n\n"
            "load_trace only accepts ETW trace files with a .etl extension. "
            "Use list_traces(directory=...) to find .etl files in a "
            "directory, or rename the file if you know it is a valid ETW "
            "trace under a different extension."
        )

    _load_start_monotonic = time.monotonic()
    try:
        etl_size_mb = path.stat().st_size / (1024 * 1024)
    except OSError:
        etl_size_mb = None
    _telemetry.emit_with(
        _telemetry.EVENT_LOAD_START,
        mode=mode,
        trace_id=make_trace_id(path),
        etl_path=path,
        etl_size_mb=etl_size_mb,
        force=force,
    )

    # Resolve the load pipeline. Environment variable overrides the arg
    # when the arg is left at its default. An explicit ``mode="native"``
    # request can raise ``RuntimeError`` when the consumer isn't
    # available on this host — surface that to the caller rather than
    # silently falling back to xperf, so they know to flip to
    # ``mode="xperf"`` or ``mode="auto"``.
    from etw_analyzer.native.config import (
        _csharp_was_forced,
        _native_was_forced,
        apply_native_size_guardrail,
        resolve_mode,
    )
    try:
        csharp_was_forced = _csharp_was_forced(mode)
        native_was_forced = _native_was_forced(mode)
        resolved_mode = resolve_mode(mode, etl_path=path)
        resolved_mode, guardrail_notice = apply_native_size_guardrail(
            mode,
            resolved_mode,
            path,
        )
    except ValueError as e:
        return str(e)
    except RuntimeError as e:
        return str(e)

    if resolved_mode == "native" and timeout_seconds != 300:
        return (
            "timeout_seconds is only supported for mode='xperf'. The native "
            "ETW pipeline currently runs to completion because safe "
            "cancellation is not implemented. Use mode='xperf' for timeout "
            "enforcement, or leave timeout_seconds at its default for native."
        )

    # Resolve symbol path
    sym_path = symbol_path or os.environ.get("_NT_SYMBOL_PATH")
    load_notices: list[str] = [guardrail_notice] if guardrail_notice else []

    # Export directory next to the ETL file
    export_dir = path.parent / f".etw-export-{path.stem}"

    # Force re-export: delete cache directory
    if force and export_dir.exists():
        import shutil
        shutil.rmtree(export_dir)

    # Native mode skips xperf entirely. csharp mode also skips xperf — the
    # sidecar does the decode. Without xperf installed we still try the cache
    # and the alternative pipelines; if neither works we fall through to the
    # "xperf.exe not found" error at the bottom of this block.
    xperf = find_xperf()
    if xperf is None and resolved_mode not in ("native", "csharp"):
        prefix = f"{guardrail_notice}\n\n" if guardrail_notice else ""
        return prefix + (
            "xperf.exe not found. Install Windows Performance Toolkit "
            "(part of Windows SDK/ADK) or add it to PATH.\n\n"
            "Expected at: C:\\Program Files (x86)\\Windows Kits\\10\\Windows Performance Toolkit\\xperf.exe\n\n"
            "Alternatives that do not need xperf:\n"
            "  - Pass mode='native' (or set WPR_MCP_MODE=native) to use the "
            "in-process ETW consumer when its bindings load on this host.\n"
            "  - Build the C# sidecar (cd csharp && dotnet publish -c Release "
            "-r win-x64 --self-contained), set WPR_MCP_CSHARP_SIDECAR to the "
            "published wpr-mcp-extract.exe path, and pass mode='csharp' (or "
            "set WPR_MCP_MODE=csharp)."
        )

    # Check if we can skip re-export (cached parquet/csv files exist and are newer than ETL)
    cached = _load_from_cache(export_dir, path, mode=resolved_mode)
    if cached is not None:
        trace_id = make_trace_id(path)
        _telemetry.emit_with(
            _telemetry.EVENT_LOAD_CACHE_HIT,
            mode=resolved_mode,
            trace_id=trace_id,
            export_dir=export_dir,
            datasets=len(cached),
        )
        result = _register_cached_trace(
            path,
            export_dir,
            sym_path,
            resolved_mode,
            cached,
            load_notices,
            from_cache=True,
        )
        _telemetry.emit_with(
            _telemetry.EVENT_LOAD_COMPLETE,
            mode=resolved_mode,
            trace_id=trace_id,
            wall_seconds=time.monotonic() - _load_start_monotonic,
            from_cache=True,
        )
        return result

    _telemetry.emit_with(
        _telemetry.EVENT_LOAD_CACHE_MISS,
        mode=resolved_mode,
        trace_id=make_trace_id(path),
        export_dir=export_dir,
    )

    if resolved_mode == "csharp":
        _telemetry.emit_with(
            _telemetry.EVENT_LOAD_DISPATCH,
            mode=resolved_mode,
            trace_id=make_trace_id(path),
            dispatch="csharp_worker",
        )
        worker_result = _load_csharp_with_worker(
            path,
            export_dir,
            sym_path,
        )
        if worker_result.ok:
            cached = _load_from_cache(export_dir, path, mode="csharp")
            if cached is not None:
                if worker_result.aggregation_warnings:
                    load_notices.extend(worker_result.aggregation_warnings)
                result = _register_cached_trace(
                    path,
                    export_dir,
                    sym_path,
                    "csharp",
                    cached,
                    load_notices,
                    from_cache=False,
                )
                _telemetry.emit_with(
                    _telemetry.EVENT_LOAD_COMPLETE,
                    mode="csharp",
                    trace_id=make_trace_id(path),
                    wall_seconds=time.monotonic() - _load_start_monotonic,
                    from_cache=False,
                )
                return result
            worker_result.message = (
                "csharp sidecar completed but the promoted cache could not be loaded"
            )
            try:
                import shutil
                shutil.rmtree(export_dir)
            except Exception:
                pass

        if csharp_was_forced:
            return _native_worker_load_failed(worker_result, producer="csharp")

        # Auto-resolved csharp failed; fall back along the documented
        # chain csharp → native → xperf. Drop to native first when its
        # worker is enabled, otherwise straight to xperf.
        if _native_worker_enabled():
            load_notices.append(
                "C# sidecar failed; falling back to mode='native': "
                f"{worker_result.message}"
            )
            resolved_mode = "native"
            cached = _load_from_cache(export_dir, path, mode="native")
            if cached is not None:
                return _register_cached_trace(
                    path,
                    export_dir,
                    sym_path,
                    "native",
                    cached,
                    load_notices,
                    from_cache=True,
                )
        elif xperf is not None:
            load_notices.append(
                "C# sidecar failed; falling back to mode='xperf': "
                f"{worker_result.message}"
            )
            resolved_mode = "xperf"
            cached = _load_from_cache(export_dir, path, mode="xperf")
            if cached is not None:
                return _register_cached_trace(
                    path,
                    export_dir,
                    sym_path,
                    "xperf",
                    cached,
                    load_notices,
                    from_cache=True,
                )
        else:
            return _native_worker_load_failed(worker_result, producer="csharp")

    if resolved_mode == "native" and _native_worker_enabled():
        _telemetry.emit_with(
            _telemetry.EVENT_LOAD_DISPATCH,
            mode=resolved_mode,
            trace_id=make_trace_id(path),
            dispatch="native_worker",
        )
        worker_result = _load_native_with_worker(
            path,
            export_dir,
            sym_path,
        )
        if worker_result.ok:
            cached = _load_from_cache(export_dir, path, mode="native")
            if cached is not None:
                result = _register_cached_trace(
                    path,
                    export_dir,
                    sym_path,
                    "native",
                    cached,
                    load_notices,
                    from_cache=False,
                )
                _telemetry.emit_with(
                    _telemetry.EVENT_LOAD_COMPLETE,
                    mode="native",
                    trace_id=make_trace_id(path),
                    wall_seconds=time.monotonic() - _load_start_monotonic,
                    from_cache=False,
                )
                return result
            worker_result.message = (
                "native worker completed but the promoted cache could not be loaded"
            )
            try:
                import shutil
                shutil.rmtree(export_dir)
            except Exception:
                pass

        if native_was_forced:
            return _native_worker_load_failed(worker_result)
        if xperf is not None:
            load_notices.append(
                "Native worker failed; falling back to mode='xperf': "
                f"{worker_result.message}"
            )
            resolved_mode = "xperf"
            cached = _load_from_cache(export_dir, path, mode="xperf")
            if cached is not None:
                return _register_cached_trace(
                    path,
                    export_dir,
                    sym_path,
                    "xperf",
                    cached,
                    load_notices,
                    from_cache=True,
                )
        else:
            return _native_worker_load_failed(worker_result)

    # Native fast path: skip the xperf export pipeline entirely. The
    # background dumper extraction (kicked off below) reads the trace via
    # the native consumer; we only need to synthesize the minimal
    # ``raw_csv`` slots that existing analysis tools look for. Phase N4
    # will replace these synthesized stubs with proper native
    # aggregators; today, ``cpu_sampling`` is the only one tools depend
    # on for the no-cpu-filter path, and we materialise it on first use
    # via ``_synthesize_native_cpu_sampling`` rather than running xperf.
    if resolved_mode == "native":
        export_dir.mkdir(parents=True, exist_ok=True)
        results: dict[str, pd.DataFrame] = {}
        errors: list[str] = list(load_notices)

        trace = TraceData(
            trace_id=make_trace_id(path),
            etl_path=path,
            export_dir=export_dir,
            symbol_path=sym_path,
            mode=resolved_mode,
            raw_csv=results,
            export_errors=errors,
        )

        _populate_metadata(trace)
        register_trace(trace)
        _start_background_dumper(trace)
        # Phase N4: block until the background extraction (and its
        # in-thread aggregators) finishes so the loaded-summary
        # reflects every dataset. The Phase N4 aggregators populate
        # ``cpu_sampling`` / ``cpu_timeline`` / ``dpc_isr`` /
        # ``stacks`` etc. inside the background thread. If they
        # somehow didn't, fall back to the Phase N1 stub for
        # ``cpu_sampling`` so ``get_cpu_samples`` still has a row set.
        trace.wait_for_dumper()
        if trace._dumper_error:
            return _native_load_failed(trace, trace._dumper_error)
        if "cpu_sampling" not in trace.raw_csv:
            _synthesize_native_cpu_sampling(trace)
        _populate_metadata(trace)
        _write_cache_manifest(trace.export_dir, trace.etl_path, trace.mode, trace.raw_csv)

        _telemetry.emit_with(
            _telemetry.EVENT_LOAD_COMPLETE,
            mode="native",
            trace_id=trace.trace_id,
            wall_seconds=time.monotonic() - _load_start_monotonic,
            from_cache=False,
        )
        return _format_load_summary(trace)

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
    errors: list[str] = list(load_notices)

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
        mode=resolved_mode,
        raw_csv=results,
        export_errors=errors,
    )

    _populate_metadata(trace)
    register_trace(trace)
    _write_cache_manifest(
        trace.export_dir,
        trace.etl_path,
        trace.mode,
        trace.raw_csv,
        dumper_stems=frozenset(),
    )
    _start_background_dumper(trace)

    _telemetry.emit_with(
        _telemetry.EVENT_LOAD_COMPLETE,
        mode=resolved_mode,
        trace_id=trace.trace_id,
        wall_seconds=time.monotonic() - _load_start_monotonic,
        from_cache=False,
    )
    return _format_load_summary(trace)


def _register_cached_trace(
    path: Path,
    export_dir: Path,
    sym_path: str | None,
    resolved_mode: str,
    cached: dict[str, pd.DataFrame],
    notices: list[str],
    *,
    from_cache: bool,
) -> str:
    """Register a trace from a validated on-disk cache."""

    errors: list[str] = list(notices)
    _refresh_stack_cache_from_html(export_dir, cached, errors)
    trace = TraceData(
        trace_id=make_trace_id(path),
        etl_path=path,
        export_dir=export_dir,
        symbol_path=sym_path,
        mode=resolved_mode,
        raw_csv=cached,
        export_errors=errors,
        event_store=_open_native_event_store_from_cache(
            export_dir,
            path,
            resolved_mode,
        ),
    )
    _populate_metadata(trace)
    register_trace(trace)
    if resolved_mode == "xperf":
        _write_cache_manifest(
            trace.export_dir,
            trace.etl_path,
            trace.mode,
            trace.raw_csv,
            dumper_stems=frozenset(),
        )
    streaming_store = (
        resolved_mode in ("native", "csharp")
        and trace.event_store is not None
        and _is_streaming_event_store_cache(export_dir)
    )
    if streaming_store:
        missing = _streaming_missing_aggregates(trace.raw_csv)
        if missing:
            trace.export_errors.append(
                "Native streaming event-store cache loaded; some low-risk "
                "aggregate datasets are not present: " + ", ".join(missing)
            )
    elif resolved_mode != "csharp":
        # csharp caches were already populated by the sidecar +
        # aggregation_worker; no background xperf dumper pass is needed.
        _start_background_dumper(trace)
    if resolved_mode == "native" and not streaming_store:
        trace.wait_for_dumper()
        if trace._dumper_error:
            return _native_load_failed(trace, trace._dumper_error)
        if "cpu_sampling" not in trace.raw_csv:
            _synthesize_native_cpu_sampling(trace)
        _populate_metadata(trace)
    summary = _format_load_summary(trace)
    if from_cache:
        return summary.replace("**Trace loaded:**", "**Trace loaded (from cache):**")
    return summary


def _open_native_event_store_from_cache(
    export_dir: Path,
    etl_path: Path,
    mode: str,
):
    """Open the optional chunked event store referenced by a native v2 cache."""

    if mode not in ("native", "csharp"):
        return None
    manifest_data = _read_cache_manifest(export_dir)
    if manifest_data is None or not _is_native_v2_manifest(manifest_data):
        return None
    try:
        from etw_analyzer.native import cache as native_cache
        from etw_analyzer.native.event_store import NativeEventStore

        manifest = native_cache.CacheManifest.from_dict(manifest_data)
        native_cache.validate_manifest(
            manifest,
            export_dir,
            etl_path,
            mode="native",
        )
        return NativeEventStore.open_from_cache_manifest(export_dir, manifest)
    except Exception:
        return None


def _is_streaming_event_store_cache(export_dir: Path) -> bool:
    manifest_data = _read_cache_manifest(export_dir)
    if manifest_data is None or not _is_native_v2_manifest(manifest_data):
        return False
    try:
        from etw_analyzer.native import cache as native_cache

        manifest = native_cache.CacheManifest.from_dict(manifest_data)
        return manifest.strategy == native_cache.STREAMING_EVENT_STORE_STRATEGY
    except Exception:
        return False


_STREAMING_LOW_RISK_AGGREGATES = frozenset({
    "trace_metadata",
    "cpu_sampling",
    "cpu_timeline",
    "dpc_isr",
    "dpc_isr_per_cpu",
    "process_info",
    "sysconfig",
    "tracestats",
})


def _streaming_missing_aggregates(raw_csv: dict[str, pd.DataFrame]) -> list[str]:
    return sorted(name for name in _STREAMING_LOW_RISK_AGGREGATES if name not in raw_csv)


def _native_worker_enabled() -> bool:
    try:
        from etw_analyzer.native.worker_supervisor import native_worker_enabled

        return native_worker_enabled()
    except Exception:
        return False


def _load_native_with_worker(
    path: Path,
    export_dir: Path,
    sym_path: str | None,
):
    from etw_analyzer.native.worker_supervisor import run_native_worker_extraction

    return run_native_worker_extraction(
        etl_path=path,
        export_dir=export_dir,
        trace_id=make_trace_id(path),
        symbol_path=sym_path,
        requested_event_classes=_DUMPER_EVENT_CLASSES.keys(),
    )


def _load_csharp_with_worker(
    path: Path,
    export_dir: Path,
    sym_path: str | None,
):
    """Dispatch to the C# sidecar via worker_supervisor.run_csharp_worker_extraction.

    Returns a ``NativeWorkerResult`` whose ``ok`` field signals success.
    The supervisor handles staging, validation, aggregation, and atomic
    promotion. On failure the staging directory is preserved for debugging
    per the spike contract.
    """
    from etw_analyzer.native.worker_supervisor import run_csharp_worker_extraction

    return run_csharp_worker_extraction(
        etl_path=path,
        export_dir=export_dir,
        trace_id=make_trace_id(path),
        symbol_path=sym_path,
        requested_event_classes=_DUMPER_EVENT_CLASSES.keys(),
    )


def _native_worker_load_failed(worker_result, *, producer: str = "native") -> str:
    """Return an actionable message for a failed worker load.

    ``producer`` names which extraction backend produced ``worker_result``
    so the suggested next steps point at the right alternative(s).
    """

    detail = worker_result.message
    failure_kind = getattr(worker_result, "failure_kind", None)
    if failure_kind:
        detail = f"{failure_kind}: {detail}"
    stderr_tail = getattr(worker_result, "stderr_tail", "")
    if stderr_tail:
        detail = f"{detail}\n\nWorker stderr tail:\n{stderr_tail[-2000:]}"
    invalid_tail = getattr(worker_result, "invalid_stdout_tail", "")
    if invalid_tail:
        detail = f"{detail}\n\nInvalid worker stdout tail:\n{invalid_tail[-2000:]}"

    if producer == "csharp":
        # The csharp sidecar can fail for build-incompatibility reasons that
        # mode='native' / mode='xperf' will not hit. Surface the rebuild hint
        # alongside the standard fallback suggestion so callers do not stay
        # stuck on a stale binary.
        rebuild_hint = ""
        if failure_kind in {"invalid-stdout", "invalid-jsonl", "exit-code"}:
            rebuild_hint = (
                "\n\nThe sidecar binary may be a stale build. Rebuild with "
                "`cd csharp && dotnet publish -c Release -r win-x64 "
                "--self-contained` and retry. If WPR_MCP_CSHARP_SIDECAR "
                "points at an old install, update it to the newly-published "
                "wpr-mcp-extract.exe."
            )
        return (
            "C# sidecar ETW worker extraction failed: "
            f"{detail}{rebuild_hint}\n\n"
            "No trace was loaded. Use mode='native' or mode='xperf' to "
            "bypass the sidecar (the cache is shared, so a successful run "
            "under either mode satisfies subsequent loads)."
        )

    return (
        "Native ETW worker extraction failed: "
        f"{detail}\n\n"
        "No trace was loaded. Use mode='xperf' to fall back to the legacy "
        "xperf pipeline, or unset WPR_MCP_NATIVE_WORKER to retry the "
        "in-process native pipeline."
    )


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


def _native_load_failed(trace: TraceData, error: str) -> str:
    """Unregister a failed native load and return an actionable message."""
    unregister_trace(trace.trace_id)
    _remove_cache_manifest(trace.export_dir)
    sym = getattr(trace, "symbolizer", None)
    if sym is not None:
        try:
            sym.close()
        except Exception:
            pass
    return (
        "Native ETW extraction failed: "
        f"{error}\n\n"
        "No trace was loaded. Use mode='xperf' to fall back to the legacy "
        "xperf pipeline, or retry with force=True after fixing the native "
        "extraction error."
    )


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
    # Phase 3b: AFD socket-level events + NDIS drops.
    "AFD/Recv":         ("afd_recv_df",          "afd_recv"),
    "AFD/Send":         ("afd_send_df",          "afd_send"),
    "AFD/Connect":      ("afd_connect_df",       "afd_connect"),
    "AFD/Accept":       ("afd_accept_df",        "afd_accept"),
    "AFD/Close":        ("afd_close_df",         "afd_close"),
    "NdisDrop":         ("ndis_drops_df",        "ndis_drops"),
    # Phase 4: NDIS PacketCapture (decoded packet bytes).
    "NdisPacketCapture": ("packet_capture_df",   "packet_capture"),
    # Phase 5: HTTP.sys request lifecycle.
    "HttpService/Recv":    ("http_recv_df",       "http_recv"),
    "HttpService/Deliver": ("http_deliver_df",    "http_deliver"),
    "HttpService/Send":    ("http_send_df",       "http_send"),
    "HttpService/Close":   ("http_close_df",      "http_close"),
    # Phase 5: MsQuic connection state.
    "Quic/ConnectionCreated": ("quic_conn_created_df", "quic_conn_created"),
    "Quic/ConnectionClosed":  ("quic_conn_closed_df",  "quic_conn_closed"),
    "Quic/PacketRecv":        ("quic_packet_recv_df",  "quic_packet_recv"),
    "Quic/PacketSend":        ("quic_packet_send_df",  "quic_packet_send"),
    "Quic/AckReceived":       ("quic_ack_recv_df",     "quic_ack_recv"),
    # Phase B (csharp sidecar): per-opcode kernel-meta event classes.
    # Names and stem mappings come verbatim from Track P1's handoff in
    # ``manager-log/phase-b-sidecar-status.md`` ("Stem-name additions to
    # _DUMPER_EVENT_CLASSES"). The sidecar consumes this dict via
    # ``requested_event_classes`` to know which event classes to emit
    # per-opcode parquets for. The native worker has no handlers for
    # these so the attr fields stay None under mode="native" (the
    # in-process consumer continues to use the combined parquets from
    # _SIDECAR_AUX_STEMS instead).
    "PerfInfo/DPC":          ("perfinfo_dpc_df",          "perfinfo_dpc"),
    "PerfInfo/ThreadedDPC":  ("perfinfo_threaded_dpc_df", "perfinfo_threaded_dpc"),
    "PerfInfo/TimerDPC":     ("perfinfo_timer_dpc_df",    "perfinfo_timer_dpc"),
    "PerfInfo/ISR":          ("perfinfo_isr_df",          "perfinfo_isr"),
    "Process/Start":         ("process_start_df",         "process_start"),
    "Process/End":           ("process_end_df",           "process_end"),
    "Process/DCStart":       ("process_dcstart_df",       "process_dcstart"),
    "Process/DCEnd":         ("process_dcend_df",         "process_dcend"),
    "Process/Defunct":       ("process_defunct_df",       "process_defunct"),
    "Thread/Start":          ("thread_start_df",          "thread_start"),
    "Thread/End":            ("thread_end_df",            "thread_end"),
    "Thread/DCStart":        ("thread_dcstart_df",        "thread_dcstart"),
    "Thread/DCEnd":          ("thread_dcend_df",          "thread_dcend"),
    "DiskIo/Read":           ("diskio_read_df",           "diskio_read"),
    "DiskIo/Write":          ("diskio_write_df",          "diskio_write"),
    "DiskIo/FlushBuffers":   ("diskio_flushbuffers_df",   "diskio_flushbuffers"),
    "Image/Load":            ("image_load_df",            "image_load"),
    "Image/DCStart":         ("image_dcstart_df",         "image_dcstart"),
    "EventTrace/Header":     ("eventtrace_header_df",     "eventtrace_header"),
}


def _persist_dumper_parquet(df: pd.DataFrame, path: Path) -> None:
    """Write a dumper DataFrame to parquet, sanitizing kernel-address columns.

    The native-mode ``Stack`` column is a tuple of kernel pointers — values
    routinely exceed signed ``int64`` (e.g. ``0xFFFFF80...`` runs > 2**63).
    pyarrow's default conversion picks ``int64`` and raises
    ``OverflowError: int too big to convert``, which used to be silently
    swallowed in ``_extract`` — leaving the in-memory DataFrame intact for
    the current session but stranding it from the on-disk cache. The next
    reload then started from scratch with no ``Stack`` column, which broke
    every downstream tool that depended on it (most visibly
    ``get_network_wait_chain`` reporting "No CSwitch events available"
    after a cache rehydrate).

    The fix is to coerce the ``Stack`` column to a ``numpy uint64`` array
    column before handing off to ``to_parquet``. pyarrow round-trips that
    as ``list<uint64>`` and the read path materialises it back as a
    Python list — close enough to the original tuple shape that the
    butterfly/wait-chain aggregators don't care.
    """
    if "Stack" in df.columns:
        import numpy as _np
        def _to_uint64_list(v):
            if v is None:
                return None
            if isinstance(v, (tuple, list)):
                try:
                    return _np.asarray(v, dtype=_np.uint64)
                except (OverflowError, ValueError):
                    # Last-ditch: drop the addresses we can't fit.
                    return _np.asarray(
                        [x for x in v if 0 <= int(x) < (1 << 64)],
                        dtype=_np.uint64,
                    )
            return None
        df = df.copy()
        df["Stack"] = df["Stack"].map(_to_uint64_list)
    df.to_parquet(path, index=False)


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

    cached_dumper_paths = _cached_dumper_paths_for_trace(trace)

    def _parquet_for(stem: str) -> Path:
        if cached_dumper_paths is not None and stem in cached_dumper_paths:
            return cached_dumper_paths[stem]
        return trace.export_dir / f"{stem}.parquet"

    with trace.lock:
        # Already fully populated, or a background thread is already running.
        all_loaded = all(
            getattr(trace, attr, None) is not None
            for attr, _ in _DUMPER_EVENT_CLASSES.values()
        )
        if all_loaded or trace._dumper_future is not None:
            return

        # Fast path: rehydrate any class whose parquet is already on disk.
        # Glob-based ``_load_from_cache`` excludes these stems so they don't
        # leak into ``raw_csv``.
        for canonical, (attr, stem) in _DUMPER_EVENT_CLASSES.items():
            if cached_dumper_paths is not None and stem not in cached_dumper_paths:
                continue
            parquet = _parquet_for(stem)
            if getattr(trace, attr, None) is None and parquet.exists():
                try:
                    setattr(trace, attr, pd.read_parquet(parquet))
                except Exception:
                    pass

        # If everything is cached now, signal ready and return.
        if all(
            getattr(trace, attr, None) is not None
            for attr, _ in _DUMPER_EVENT_CLASSES.values()
        ):
            trace._dumper_ready.set()
            return

    def _extract():
        success = False
        try:
            # Only re-extract classes that weren't cached. A single
            # extraction pass services all of them — both pipelines
            # accept the same ``event_classes`` set.
            wanted: set[str] = {
                canonical
                for canonical, (attr, _) in _DUMPER_EVENT_CLASSES.items()
                if getattr(trace, attr, None) is None
            }

            if not wanted:
                return

            if trace.mode == "native":
                from etw_analyzer.native import extract_events, ExtractStats

                # Phase N3: include Image/Load + Image/DCStart so the
                # Symbolizer can register every module the trace touched.
                # Phase N4: also pull DPC/ISR/Process/DiskIo/SystemConfig
                # so the post-extraction aggregators can build the
                # xperf-equivalent ``cpu_sampling`` / ``dpc_isr`` /
                # ``process_info`` / ``diskio`` / ``sysconfig`` /
                # ``tracestats`` outputs. These auxiliaries don't get
                # persisted to parquet directly — they live in
                # ``trace.raw_csv`` under their canonical class names
                # until the aggregators digest them.
                wanted_with_aux = set(wanted)
                wanted_with_aux.update({
                    "Image/Load", "Image/DCStart",
                    "PerfInfo/DPC", "PerfInfo/ThreadedDPC",
                    "PerfInfo/TimerDPC", "PerfInfo/ISR",
                    "Process/Start", "Process/End",
                    "Process/DCStart", "Process/DCEnd",
                    "Process/Defunct",
                    # Thread events feed the TID-to-PID map that
                    # ``_run_native_aggregators`` uses to backfill
                    # NewProcessName / OldProcessName on the CSwitch
                    # DataFrame — the cswitch payload itself carries
                    # only TIDs.
                    "Thread/Start", "Thread/End",
                    "Thread/DCStart", "Thread/DCEnd",
                    "DiskIo/Read", "DiskIo/Write", "DiskIo/FlushBuffers",
                    "EventTrace/Header", "SystemConfig",
                })

                stats_sink: list[ExtractStats] = []
                results = extract_events(
                    trace.etl_path,
                    event_classes=wanted_with_aux,
                    stats_sink=stats_sink,
                )
                if stats_sink:
                    with trace.lock:
                        trace._native_extract_stats = stats_sink[-1]
                    _apply_native_metadata(trace)

                # Build the per-trace Symbolizer and feed every
                # ImageLoad row into it. Phase N3 only wires the
                # plumbing — no symbol resolution happens during load,
                # so failures here shouldn't block. Phase N4
                # aggregators (butterfly, hot_functions) will call into
                # ``trace.symbolizer.bulk_resolve`` lazily.
                _build_symbolizer_from_images(trace, results)

                # Stash auxiliary class DataFrames on raw_csv under
                # their canonical names so the aggregators can find
                # them. Aggregators themselves run *after* the with
                # lock block below.
                _native_aux = {
                    name: results.get(name)
                    for name in (
                        "PerfInfo/DPC", "PerfInfo/ThreadedDPC",
                        "PerfInfo/TimerDPC", "PerfInfo/ISR",
                        "Process/Start", "Process/End",
                        "Process/DCStart", "Process/DCEnd",
                        "Process/Defunct",
                        "Thread/Start", "Thread/End",
                        "Thread/DCStart", "Thread/DCEnd",
                        "DiskIo/Read", "DiskIo/Write", "DiskIo/FlushBuffers",
                        "EventTrace/Header", "SystemConfig",
                    )
                }
                for name, df in _native_aux.items():
                    if df is not None and not df.empty:
                        trace.raw_csv[name] = df
            else:
                from etw_analyzer.parsing.wpa_exporter import parse_dumper_events

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
                    if df is None:
                        continue
                    setattr(trace, attr, df)
                    trace.export_dir.mkdir(parents=True, exist_ok=True)
                    try:
                        _persist_dumper_parquet(df, _parquet_for(stem))
                    except Exception:
                        # Non-fatal: keep the in-memory DataFrame even if
                        # we can't persist (e.g. disk full, readonly).
                        # Empty DataFrames are intentionally persisted so a
                        # trace with no events for a class does not re-run the
                        # native/xperf dumper on every cache reload.
                        pass

            # Phase N4: with the event-level DataFrames in place, run the
            # native-mode aggregators to populate ``trace.raw_csv`` with
            # the xperf-equivalent aggregates that the existing analysis
            # tools consume. Best-effort — a failing aggregator should
            # not block the trace from loading.
            if trace.mode == "native":
                _run_native_aggregators(trace)
            success = True
        except Exception as e:
            with trace.lock:
                trace._dumper_error = str(e)
        finally:
            if success:
                _write_cache_manifest(trace.export_dir, trace.etl_path, trace.mode, trace.raw_csv)
            trace._dumper_ready.set()

    thread = threading.Thread(target=_extract, daemon=True, name="dumper-extract")
    with trace.lock:
        # Re-check after thread construction — another caller may have
        # raced us in.
        if all(
            getattr(trace, attr, None) is not None
            for attr, _ in _DUMPER_EVENT_CLASSES.values()
        ) or trace._dumper_future is not None:
            return
        trace._dumper_future = thread
        thread.start()


def _build_symbolizer_from_images(
    trace: TraceData,
    results: dict[str, pd.DataFrame],
) -> None:
    """Instantiate the per-trace Symbolizer and register every loaded module.

    Phase N3 plumbing — Phase N4 will read ``trace.symbolizer`` from the
    aggregators (butterfly / hot_functions). Today the symbolizer just
    needs to know the modules so the lazy ``resolve()`` calls later have
    enough metadata to ask dbghelp.

    Failures here are non-fatal: the trace still loads, just without
    symbolized stacks. The xperf-mode path is unaffected.
    """

    try:
        from etw_analyzer.native import Symbolizer
    except (ImportError, OSError):
        return

    try:
        symbolizer = Symbolizer(symbol_path=trace.symbol_path)
    except Exception:
        return

    # Combine Image/Load and Image/DCStart rows. DCStart events are
    # emitted at trace start for already-loaded modules; Load events
    # fire as new modules come online during capture. Together they
    # cover every module a SampledProfile stack could reference.
    rows: list[dict] = []
    for class_name in ("Image/Load", "Image/DCStart"):
        df = results.get(class_name)
        if df is None or df.empty:
            continue
        for row in df.to_dict(orient="records"):
            rows.append(row)

    # Deduplicate by ImageBase. ETW frequently repeats the same module
    # across DCStart + a follow-up Load with the same base; one
    # registration is enough.
    seen_bases: set[int] = set()
    for row in rows:
        base = int(row.get("ImageBase", 0) or 0)
        if not base or base in seen_bases:
            continue
        seen_bases.add(base)
        size = int(row.get("ImageSize", 0) or 0)
        file_name = str(row.get("FileName", "") or "")
        try:
            symbolizer.add_module(base, size, file_name)
        except Exception:
            # Per-module failure is non-fatal; the address will still
            # resolve to ``unknown+0x…`` if dbghelp can't find a PDB.
            continue

    with trace.lock:
        trace.symbolizer = symbolizer


def _run_native_aggregators(trace: TraceData) -> None:
    """Drive every Phase N4 aggregator and stash results in ``raw_csv``.

    Each aggregator is best-effort: an individual failure logs and is
    swallowed so the trace can still load. The aggregators read from
    ``trace.dumper_df`` / ``trace.raw_csv`` (auxiliary classes stashed
    by the native-mode extractor) and write back to ``trace.raw_csv``
    under the xperf-equivalent dataset names.
    """

    try:
        from etw_analyzer.native.aggregators import (
            aggregate_cpu_sampling,
            aggregate_cpu_timeline,
            aggregate_dpc_isr,
            build_dpc_isr_raw_text,
            aggregate_stack_butterfly,
            build_sysconfig_text,
            build_process_info_text,
            build_diskio_text,
            build_tracestats_text,
            enrich_network_events,
        )
        from etw_analyzer.native.aggregators.process_info import build_process_table
        from etw_analyzer.native.aggregators.stack_butterfly import aggregate_stack_callers
    except Exception:
        return

    # Build the PID-to-name lookup first so ``cpu_sampling`` can populate
    # Process Name from Process/DCStart rows.
    try:
        ptable = build_process_table(trace)
        if ptable is not None and not ptable.empty:
            trace.raw_csv["_native_process_events"] = ptable
    except Exception:
        pass

    # Enrich native manifest networking rows before tools/cache consumers
    # read them: TCP send/recv usually carries only ConnId/TCB, while
    # connect/rundown carries the 5-tuple.
    try:
        mutated_network = enrich_network_events(trace)
        for canonical in mutated_network:
            attr, stem = _DUMPER_EVENT_CLASSES.get(canonical, (None, None))
            if not attr or not stem:
                continue
            df = getattr(trace, attr, None)
            if df is None:
                continue
            try:
                _persist_dumper_parquet(
                    df,
                    trace.export_dir / f"{stem}.parquet",
                )
            except Exception:
                pass
    except Exception:
        pass

    # Populate NewProcessName / OldProcessName / NewPID / OldPID on the
    # native CSwitch DataFrame. The native CSwitch decoder gets only the
    # NewTID/OldTID from the binary payload and the EventHeader PID is
    # 0xFFFFFFFF for kernel scheduling events, so without this enrichment
    # ``get_network_wait_chain`` can't match its process-substring
    # argument against any row even though 393K CSwitch events were
    # successfully decoded.
    #
    # We build a TID→PID map from Thread/DCStart/Start events, then chain
    # PID → name through the Process-event table. Both maps are built once
    # and applied vectorized.
    try:
        cswitch_df = trace.cswitch_events_df
        if cswitch_df is not None and not cswitch_df.empty:
            from etw_analyzer.native.aggregators.profile_detail import (
                _build_pid_to_name_map,
            )
            pid_map = _build_pid_to_name_map(trace)
            tid_to_pid: dict[int, int] = {}
            for cls in ("Thread/DCStart", "Thread/Start",
                        "Thread/DCEnd", "Thread/End"):
                tdf = trace.raw_csv.get(cls)
                if tdf is None or tdf.empty:
                    continue
                if "ThreadId" not in tdf.columns or "ProcessId" not in tdf.columns:
                    continue
                for tid, pid in zip(tdf["ThreadId"].tolist(),
                                    tdf["ProcessId"].tolist()):
                    try:
                        tid_i = int(tid)
                        pid_i = int(pid)
                    except (TypeError, ValueError):
                        continue
                    # Prefer earlier (DCStart) over later (End) entries
                    # for stable mapping when TIDs are reused.
                    tid_to_pid.setdefault(tid_i, pid_i)

            mutated = False
            if tid_to_pid and "NewTID" in cswitch_df.columns:
                # Backfill NewPID from the TID map. The native CSwitch
                # decoder leaves NewPID==0 whenever the EventHeader
                # ProcessId is the kernel "no process context" sentinel
                # (which is virtually always), so we treat 0 / negative /
                # 0xFFFFFFFF as "needs resolution".
                resolved_new_pid = cswitch_df["NewTID"].map(tid_to_pid)
                current_new = cswitch_df["NewPID"] if "NewPID" in cswitch_df.columns else None
                if current_new is not None:
                    sentinel = (current_new == 0xFFFFFFFF) | (current_new <= 0)
                    cswitch_df.loc[sentinel, "NewPID"] = (
                        resolved_new_pid[sentinel].fillna(0).astype("int64")
                    )
                else:
                    cswitch_df["NewPID"] = resolved_new_pid.fillna(0).astype("int64")
                mutated = True

            if tid_to_pid and "OldTID" in cswitch_df.columns:
                resolved_old_pid = cswitch_df["OldTID"].map(tid_to_pid)
                current_old = cswitch_df["OldPID"] if "OldPID" in cswitch_df.columns else None
                if current_old is not None:
                    sentinel = (current_old == 0xFFFFFFFF) | (current_old <= 0)
                    cswitch_df.loc[sentinel, "OldPID"] = (
                        resolved_old_pid[sentinel].fillna(0).astype("int64")
                    )
                else:
                    cswitch_df["OldPID"] = resolved_old_pid.fillna(0).astype("int64")
                mutated = True

            if pid_map:
                if "NewProcessName" in cswitch_df.columns and "NewPID" in cswitch_df.columns:
                    blank = cswitch_df["NewProcessName"].astype(str).str.len() == 0
                    if blank.any():
                        cswitch_df.loc[blank, "NewProcessName"] = (
                            cswitch_df.loc[blank, "NewPID"]
                            .map(pid_map)
                            .fillna("")
                            .astype(str)
                        )
                        mutated = True
                if "OldProcessName" in cswitch_df.columns and "OldPID" in cswitch_df.columns:
                    blank = cswitch_df["OldProcessName"].astype(str).str.len() == 0
                    if blank.any():
                        cswitch_df.loc[blank, "OldProcessName"] = (
                            cswitch_df.loc[blank, "OldPID"]
                            .map(pid_map)
                            .fillna("")
                            .astype(str)
                        )
                        mutated = True

            if mutated:
                # Persist the enriched DataFrame so cache rehydration
                # picks up the names too.
                try:
                    _persist_dumper_parquet(
                        cswitch_df,
                        trace.export_dir / "cswitch_events.parquet",
                    )
                except Exception:
                    pass
    except Exception:
        pass

    def _persist_df(name: str, stem: str, df) -> None:
        if df is None or getattr(df, "empty", True):
            return
        with trace.lock:
            trace.raw_csv[name] = df
        try:
            trace.export_dir.mkdir(parents=True, exist_ok=True)
            df.to_parquet(trace.export_dir / f"{stem}.parquet", index=False)
        except Exception:
            pass

    def _persist_text(name: str, filename: str, text) -> None:
        if not text:
            return
        with trace.lock:
            import pandas as _pd
            trace.raw_csv[name] = _pd.DataFrame({"raw_text": [text]})
        try:
            trace.export_dir.mkdir(parents=True, exist_ok=True)
            (trace.export_dir / filename).write_text(text, encoding="utf-8")
        except Exception:
            pass

    # trace_metadata — authoritative header-derived duration / CPU count.
    try:
        _persist_df("trace_metadata", "trace_metadata", _native_metadata_dataframe(trace))
    except Exception:
        pass

    # cpu_sampling — the floor everything else needs.
    try:
        _persist_df("cpu_sampling", "cpu_sampling", aggregate_cpu_sampling(trace))
    except Exception:
        pass

    # cpu_timeline — per-CPU utilization buckets.
    try:
        _persist_df("cpu_timeline", "cpu_timeline", aggregate_cpu_timeline(trace))
    except Exception:
        pass

    # dpc_isr — per-module duration histogram.
    try:
        _persist_df("dpc_isr", "dpc_isr", aggregate_dpc_isr(trace))
    except Exception:
        pass

    # dpc_isr_raw — xperf-format text with per-CPU pair lines.
    try:
        _persist_text("dpc_isr_raw", "dpcisr.txt", build_dpc_isr_raw_text(trace))
    except Exception:
        pass

    # stacks — butterfly inclusive/exclusive table. Symbolization-heavy,
    # so this can take a while on big traces. Skipped silently if no
    # symbolizer is available.
    try:
        _persist_df("stacks", "stacks", aggregate_stack_butterfly(trace))
    except Exception:
        pass

    # stacks_callers — caller edges (v1 — see module docstring).
    try:
        _persist_df("stacks_callers", "stacks_callers", aggregate_stack_callers(trace))
    except Exception:
        pass

    # Raw-text aggregates.
    try:
        _persist_text("sysconfig", "sysconfig.txt", build_sysconfig_text(trace))
    except Exception:
        pass

    try:
        _persist_text("process_info", "process_info.txt", build_process_info_text(trace))
    except Exception:
        pass

    try:
        _persist_text("diskio", "diskio.txt", build_diskio_text(trace))
    except Exception:
        pass

    try:
        _persist_text("tracestats", "tracestats.txt", build_tracestats_text(trace))
    except Exception:
        pass


def _synthesize_native_cpu_sampling(trace: TraceData) -> None:
    """Build a ``cpu_sampling`` DataFrame from the native SampledProfile dump.

    The xperf-driven path produces a ``cpu_sampling.parquet`` aggregated by
    ``Process Name`` / ``PID`` / ``Module`` / ``Function`` with ``Weight``
    summed across CPUs and threads. In Phase N1 native mode we don't run
    xperf, so we synthesize the same DataFrame from ``trace.dumper_df``
    (the per-sample stream the native consumer collects). Module and
    Function are blank until Phase N3 wires in dbghelp symbolization; the
    aggregation by ``PID`` is enough for ``get_cpu_samples`` to produce
    meaningful output.

    Blocks on the background dumper extraction. If it produced no
    SampledProfile rows (small/odd trace), ``cpu_sampling`` stays absent
    rather than empty so downstream tools fall through to their existing
    "no data" branch.
    """

    dumper_df = trace.wait_for_dumper()
    if dumper_df is None or dumper_df.empty:
        return

    # Match the xperf schema. Process Name, PID are already there;
    # Module / Function are empty strings on the native path; Weight
    # comes from the per-sample Count.
    group_cols = ["Process Name", "PID", "Module", "Function"]
    agg = (
        dumper_df.groupby(group_cols, dropna=False)["Weight"]
        .sum()
        .reset_index()
    )
    total = agg["Weight"].sum() or 1
    agg["% Weight"] = (agg["Weight"] / total) * 100.0

    # Reorder columns to match xperf for downstream tools that index by
    # name/position.
    agg = agg[["Process Name", "PID", "Weight", "% Weight", "Module", "Function"]]

    with trace.lock:
        trace.raw_csv["cpu_sampling"] = agg
        trace.event_counts["cpu_sampling"] = len(agg)

    # Persist alongside the native parquets so a follow-up
    # ``_load_from_cache`` call can rehydrate without re-running the
    # consumer. Best-effort: a write failure isn't fatal.
    try:
        trace.export_dir.mkdir(parents=True, exist_ok=True)
        agg.to_parquet(trace.export_dir / "cpu_sampling.parquet", index=False)
    except Exception:
        pass


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
    # Phase 3b networking event-class parquets — same plumbing as above.
    "afd_recv",
    "afd_send",
    "afd_connect",
    "afd_accept",
    "afd_close",
    "ndis_drops",
    # Phase 4 packet-capture parquet — loaded into trace.packet_capture_df.
    "packet_capture",
    # Phase 5 HTTP.sys parquets — loaded into trace.http_*_df.
    "http_recv",
    "http_deliver",
    "http_send",
    "http_close",
    # Phase 5 MsQuic parquets — loaded into trace.quic_*_df.
    "quic_conn_created",
    "quic_conn_closed",
    "quic_packet_recv",
    "quic_packet_send",
    "quic_ack_recv",
    # Phase B csharp-sidecar per-opcode kernel-meta parquets. Loaded into
    # dedicated trace.<class>_df attributes via _DUMPER_EVENT_CLASSES, then
    # adapted into raw_csv under canonical event-class names by the csharp
    # aggregation worker. The glob skip avoids a duplicate stem entry in
    # raw_csv that would shadow the adapter-normalized canonical keys.
    "perfinfo_dpc",
    "perfinfo_threaded_dpc",
    "perfinfo_timer_dpc",
    "perfinfo_isr",
    "process_start",
    "process_end",
    "process_dcstart",
    "process_dcend",
    "process_defunct",
    "thread_start",
    "thread_end",
    "thread_dcstart",
    "thread_dcend",
    "diskio_read",
    "diskio_write",
    "diskio_flushbuffers",
    "image_load",
    "image_dcstart",
    "eventtrace_header",
})

# Cache manifest written after successful exports. Xperf continues to use the
# v1 flat manifest. Native writes a v2 manifest via etw_analyzer.native.cache,
# but v1 native manifests remain readable for compatibility.
_CACHE_MANIFEST_FILENAME = "wpr-mcp-cache-manifest.json"
_CACHE_SCHEMA_VERSION = 1

# Datasets that MUST be present (and load successfully) for a cache to be
# considered usable. Xperf needs cpu_sampling as the historical floor. Native
# and csharp can have traces with no sampled-profile rows, so completeness is
# tracked by the per-event parquet set in the manifest instead. csharp shares
# the native cache shape (the producer field on the v3 manifest carries the
# distinction).
_CACHE_REQUIRED_DATASETS_BY_MODE = {
    "xperf": frozenset({"cpu_sampling"}),
    "native": frozenset(),
    "csharp": frozenset(),
}

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


def _cache_manifest_path(export_dir: Path) -> Path:
    return export_dir / _CACHE_MANIFEST_FILENAME


def _etl_cache_identity(etl_path: Path) -> dict[str, int]:
    stat = etl_path.stat()
    return {
        "etl_size": int(stat.st_size),
        "etl_mtime_ns": int(stat.st_mtime_ns),
    }


def _read_cache_manifest(export_dir: Path) -> dict | None:
    manifest_path = _cache_manifest_path(export_dir)
    if not manifest_path.exists():
        return None
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _remove_cache_manifest(export_dir: Path) -> None:
    try:
        _cache_manifest_path(export_dir).unlink(missing_ok=True)
    except Exception:
        pass


def _is_native_v2_manifest(manifest: dict) -> bool:
    """Return True for native cache manifests we know how to read.

    The name predates schema v3 — it now matches any schema version listed
    in :data:`etw_analyzer.native.cache.SUPPORTED_SCHEMA_VERSIONS`. Both
    v2 (legacy) and v3 (csharp/native producer split) caches qualify; the
    cache loader does the producer-specific translation downstream.
    """

    if manifest.get("mode") != "native":
        return False
    try:
        from etw_analyzer.native.cache import SUPPORTED_SCHEMA_VERSIONS
    except Exception:
        return False
    return manifest.get("schema_version") in SUPPORTED_SCHEMA_VERSIONS


def _required_dumper_stems_for_mode(mode: str) -> frozenset[str]:
    if mode in ("native", "csharp"):
        return frozenset(stem for _, stem in _DUMPER_EVENT_CLASSES.values())
    return frozenset()


def _looks_like_legacy_xperf_cache(export_dir: Path) -> bool:
    """Return True for pre-manifest xperf caches we can safely reload."""
    return (
        (export_dir / "profile-detail.txt").exists()
        or (export_dir / "stack-butterfly.html").exists()
    )


def _manifest_matches_etl(manifest: dict, etl_path: Path) -> bool:
    try:
        identity = _etl_cache_identity(etl_path)
    except OSError:
        return False
    try:
        return (
            int(manifest.get("etl_size", -1)) == identity["etl_size"]
            and int(manifest.get("etl_mtime_ns", -1)) == identity["etl_mtime_ns"]
        )
    except (TypeError, ValueError):
        return False


def _cached_dumper_paths_for_trace(trace: TraceData) -> dict[str, Path] | None:
    """Return dumper parquet paths valid for this trace mode.

    ``None`` means pre-manifest xperf compatibility: allow any existing flat
    dumper parquet. A concrete mapping means only those stems may be rehydrated.
    """
    manifest = _read_cache_manifest(trace.export_dir)
    if manifest is None:
        if trace.mode == "xperf" and _looks_like_legacy_xperf_cache(trace.export_dir):
            return None
        return {}

    if _is_native_v2_manifest(manifest):
        try:
            from etw_analyzer.native import cache as native_cache

            parsed = native_cache.CacheManifest.from_dict(manifest)
            native_cache.validate_manifest(
                parsed,
                trace.export_dir,
                trace.etl_path,
                mode=trace.mode,
            )
            paths = {
                dataset.name: native_cache.resolve_dataset_path(
                    trace.export_dir,
                    parsed,
                    dataset,
                )
                for dataset in parsed.datasets
                if dataset.kind == "dumper-parquet"
                and dataset.materialize_on_load is False
            }
        except Exception:
            return {}

        required_stems = _required_dumper_stems_for_mode(trace.mode)
        if required_stems and not required_stems.issubset(paths.keys()):
            return {}
        return {
            stem: path
            for stem, path in paths.items()
            if path.exists()
        }

    if manifest.get("schema_version") != _CACHE_SCHEMA_VERSION:
        return {}
    if manifest.get("mode") != trace.mode:
        return {}
    if manifest.get("complete") is not True:
        return {}
    if not _manifest_matches_etl(manifest, trace.etl_path):
        return {}
    return {
        str(name): trace.export_dir / f"{name}.parquet"
        for name in manifest.get("dumper_datasets", [])
        if isinstance(name, str)
    }


def _cached_dumper_stems_for_trace(trace: TraceData) -> frozenset[str] | None:
    paths = _cached_dumper_paths_for_trace(trace)
    if paths is None:
        return None
    return frozenset(paths)


def _write_cache_manifest(
    export_dir: Path,
    etl_path: Path,
    mode: str,
    raw_csv: dict[str, pd.DataFrame],
    dumper_stems: frozenset[str] | set[str] | None = None,
) -> None:
    """Write a mode-aware cache manifest when the cache is complete."""
    if mode == "native":
        _write_native_v2_cache_manifest(
            export_dir,
            etl_path,
            raw_csv,
            dumper_stems=dumper_stems,
        )
        return

    if mode not in _CACHE_REQUIRED_DATASETS_BY_MODE:
        return

    try:
        identity = _etl_cache_identity(etl_path)
    except OSError:
        return

    persisted_datasets: list[str] = []
    for name in raw_csv:
        if name in _TEXT_DATASETS:
            if (export_dir / _TEXT_DATASETS[name]).exists():
                persisted_datasets.append(name)
            continue
        if name in _PARQUET_EXCLUDED:
            continue
        if (export_dir / f"{name}.parquet").exists():
            persisted_datasets.append(name)

    if dumper_stems is None:
        persisted_dumper_stems = sorted(
            stem
            for _, stem in _DUMPER_EVENT_CLASSES.values()
            if (export_dir / f"{stem}.parquet").exists()
        )
    else:
        persisted_dumper_stems = sorted(
            stem
            for stem in dumper_stems
            if (export_dir / f"{stem}.parquet").exists()
        )

    required_datasets = _CACHE_REQUIRED_DATASETS_BY_MODE[mode]
    required_dumper_stems = _required_dumper_stems_for_mode(mode)
    if not required_datasets.issubset(persisted_datasets):
        return
    if not required_dumper_stems.issubset(persisted_dumper_stems):
        return

    manifest = {
        "schema_version": _CACHE_SCHEMA_VERSION,
        "mode": mode,
        "complete": True,
        **identity,
        "datasets": sorted(set(persisted_datasets)),
        "dumper_datasets": persisted_dumper_stems,
        "required_datasets": sorted(required_datasets),
        "required_dumper_datasets": sorted(required_dumper_stems),
    }

    try:
        export_dir.mkdir(parents=True, exist_ok=True)
        _cache_manifest_path(export_dir).write_text(
            json.dumps(manifest, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    except Exception:
        pass


def _write_native_v2_cache_manifest(
    export_dir: Path,
    etl_path: Path,
    raw_csv: dict[str, pd.DataFrame],
    dumper_stems: frozenset[str] | set[str] | None = None,
) -> None:
    """Write the native cache v2 manifest for the current flat cache layout."""
    try:
        from etw_analyzer.native import cache as native_cache
    except Exception:
        return

    datasets: list[native_cache.CacheDataset] = []
    materialized_names: list[str] = []

    for name, df in raw_csv.items():
        if name in _TEXT_DATASETS:
            filename = _TEXT_DATASETS[name]
            if (export_dir / filename).exists():
                datasets.append(native_cache.CacheDataset(
                    name=name,
                    kind="text",
                    path=filename,
                    row_count=len(df),
                    materialize_on_load=True,
                ))
                materialized_names.append(name)
            continue
        if name in _PARQUET_EXCLUDED:
            continue
        parquet = export_dir / f"{name}.parquet"
        if parquet.exists():
            datasets.append(native_cache.CacheDataset(
                name=name,
                kind="parquet",
                path=f"{name}.parquet",
                row_count=len(df),
                materialize_on_load=True,
            ))
            materialized_names.append(name)

    if dumper_stems is None:
        persisted_dumper_stems = sorted(
            stem
            for _, stem in _DUMPER_EVENT_CLASSES.values()
            if (export_dir / f"{stem}.parquet").exists()
        )
    else:
        persisted_dumper_stems = sorted(
            stem
            for stem in dumper_stems
            if (export_dir / f"{stem}.parquet").exists()
        )

    required_datasets = _CACHE_REQUIRED_DATASETS_BY_MODE["native"]
    required_dumper_stems = _required_dumper_stems_for_mode("native")
    if not required_datasets.issubset(materialized_names):
        return
    if not required_dumper_stems.issubset(persisted_dumper_stems):
        return

    for stem in persisted_dumper_stems:
        parquet = export_dir / f"{stem}.parquet"
        datasets.append(native_cache.CacheDataset(
            name=stem,
            kind="dumper-parquet",
            path=f"{stem}.parquet",
            row_count=_parquet_row_count(parquet),
            materialize_on_load=False,
        ))

    try:
        manifest = native_cache.CacheManifest.materialized_small(
            etl_path,
            datasets,
            native_store=native_cache.NativeStoreGeneration.flat(),
        )
        native_cache.write_manifest(export_dir, manifest)
    except Exception:
        pass


def _parquet_row_count(path: Path) -> int | None:
    try:
        import pyarrow.parquet as pq

        return int(pq.ParquetFile(path).metadata.num_rows)
    except Exception:
        return None


def _load_native_v2_from_cache(
    export_dir: Path,
    etl_path: Path,
    mode: str,
    manifest_data: dict,
) -> dict[str, pd.DataFrame] | None:
    try:
        from etw_analyzer.native import cache as native_cache
        from etw_analyzer.native.event_store import (
            NATIVE_EVENT_STORE_DATASET_KIND,
            NativeEventStore,
        )

        manifest = native_cache.CacheManifest.from_dict(manifest_data)
        native_cache.validate_manifest(
            manifest,
            export_dir,
            etl_path,
            mode=mode,
        )

        event_store = None
        for dataset in manifest.datasets:
            if dataset.kind == NATIVE_EVENT_STORE_DATASET_KIND:
                event_store = NativeEventStore.open_from_cache_manifest(
                    export_dir,
                    manifest,
                )
                break
        streaming_store = (
            manifest.strategy == native_cache.STREAMING_EVENT_STORE_STRATEGY
        )
        if streaming_store and event_store is None:
            return None

        dumper_paths = {
            dataset.name: native_cache.resolve_dataset_path(
                export_dir,
                manifest,
                dataset,
            )
            for dataset in manifest.datasets
            if dataset.kind == "dumper-parquet"
            and dataset.materialize_on_load is False
        }
        required_stems = (
            frozenset()
            if streaming_store
            else _required_dumper_stems_for_mode(mode)
        )
        if required_stems and not required_stems.issubset(dumper_paths.keys()):
            return None
        for stem in required_stems:
            if not dumper_paths[stem].exists():
                return None

        results: dict[str, pd.DataFrame] = {}
        for dataset in manifest.datasets:
            if dataset.materialize_on_load is not True:
                continue
            path = native_cache.resolve_dataset_path(export_dir, manifest, dataset)
            if not path.exists():
                return None
            if dataset.kind == "parquet":
                results[dataset.name] = pd.read_parquet(path)
            elif dataset.kind == "text":
                results[dataset.name] = pd.DataFrame({
                    "raw_text": [path.read_text(encoding="utf-8")]
                })
            else:
                return None

        required_datasets = _CACHE_REQUIRED_DATASETS_BY_MODE[mode]
        if not required_datasets.issubset(results.keys()):
            return None
        return results
    except Exception:
        return None


def _load_from_cache(
    export_dir: Path,
    etl_path: Path,
    mode: str = "xperf",
) -> dict[str, pd.DataFrame] | None:
    """Try to load previously exported data from the cache directory.

    Returns None if the cache is missing or stale (ETL is newer than cache).

    Parquet files are discovered by globbing the export directory rather than
    iterating a hardcoded allowlist. Each "{name}.parquet" becomes a dataset
    keyed by its filename stem, except names listed in _PARQUET_EXCLUDED which
    are owned by other code paths.

    Freshness policy: manifest-backed caches must match the requested mode,
    schema version, ETL size, and ETL mtime. Legacy xperf caches without a
    manifest are still accepted when xperf-only marker files are present.
    """
    if mode not in _CACHE_REQUIRED_DATASETS_BY_MODE:
        return None
    if not export_dir.exists():
        return None

    manifest = _read_cache_manifest(export_dir)
    if manifest is not None and _is_native_v2_manifest(manifest):
        # csharp and native share the on-disk cache shape (csharp writes
        # mode="native" into the manifest). When the caller asks for
        # mode="csharp", validate against the manifest's intrinsic mode
        # but keep the requested mode visible to the rest of the loader.
        manifest_mode = "native" if mode == "csharp" else mode
        return _load_native_v2_from_cache(
            export_dir, etl_path, manifest_mode, manifest
        )

    legacy_xperf = manifest is None
    if manifest is None:
        if mode != "xperf" or not _looks_like_legacy_xperf_cache(export_dir):
            return None
        # Staleness check for pre-manifest xperf caches.
        try:
            etl_mtime = etl_path.stat().st_mtime
            export_mtime = export_dir.stat().st_mtime
            if etl_mtime > export_mtime:
                return None
        except OSError:
            return None
        manifest_datasets: set[str] | None = None
    else:
        if manifest.get("schema_version") != _CACHE_SCHEMA_VERSION:
            return None
        if manifest.get("mode") != mode:
            return None
        if manifest.get("complete") is not True:
            return None
        if not _manifest_matches_etl(manifest, etl_path):
            return None
        manifest_datasets = {
            str(name)
            for name in manifest.get("datasets", [])
            if isinstance(name, str)
        }

        required_stems = _required_dumper_stems_for_mode(mode)
        if required_stems:
            manifest_stems = {
                str(name)
                for name in manifest.get("dumper_datasets", [])
                if isinstance(name, str)
            }
            if not required_stems.issubset(manifest_stems):
                return None
            for stem in required_stems:
                if not (export_dir / f"{stem}.parquet").exists():
                    return None

    results: dict[str, pd.DataFrame] = {}

    # Discover parquet datasets via glob — any *.parquet not in the exclusion
    # set is loaded as a dataset keyed by its filename stem.
    if manifest_datasets is None:
        parquet_names = {
            parquet_path.stem
            for parquet_path in export_dir.glob("*.parquet")
            if parquet_path.stem not in _PARQUET_EXCLUDED
        }
    else:
        parquet_names = {
            name
            for name in manifest_datasets
            if name not in _TEXT_DATASETS and name not in _PARQUET_EXCLUDED
        }

    for name in sorted(parquet_names):
        parquet_path = export_dir / f"{name}.parquet"
        if name in _PARQUET_EXCLUDED:
            continue
        if not parquet_path.exists():
            continue
        try:
            results[name] = pd.read_parquet(parquet_path)
        except Exception:
            pass

    # Backward-compat: see _LEGACY_CSV_DATASETS at module scope.
    if legacy_xperf:
        for name in _LEGACY_CSV_DATASETS:
            if name in results:
                continue
            csv_path = export_dir / f"{name}.csv"
            if csv_path.exists():
                try:
                    results[name] = load_csv(csv_path)
                except Exception:
                    pass

    text_datasets = _TEXT_DATASETS
    if manifest_datasets is not None:
        text_datasets = {
            key: filename
            for key, filename in _TEXT_DATASETS.items()
            if key in manifest_datasets
        }
    for key, filename in text_datasets.items():
        txt_path = export_dir / filename
        if txt_path.exists():
            try:
                results[key] = pd.DataFrame({"raw_text": [txt_path.read_text(encoding="utf-8")]})
            except Exception:
                pass

    required_datasets = _CACHE_REQUIRED_DATASETS_BY_MODE[mode]
    if not required_datasets.issubset(results.keys()):
        return None

    return results


def _native_metadata_rows(trace: TraceData) -> list[dict]:
    """Return native ETL header metadata rows from the latest extraction."""
    stats = getattr(trace, "_native_extract_stats", None)
    metadata = getattr(stats, "logfile_metadata", None) or []
    rows: list[dict] = []
    for item in metadata:
        start = int(getattr(item, "start_time_utc_100ns", 0) or 0)
        end = int(getattr(item, "end_time_utc_100ns", 0) or 0)
        duration = getattr(item, "duration_seconds", None)
        if duration is None and start > 0 and end > start:
            duration = (end - start) / 10_000_000.0
        rows.append({
            "NumberOfProcessors": int(getattr(item, "number_of_processors", 0) or 0),
            "StartTime": start,
            "EndTime": end,
            "DurationSeconds": float(duration) if duration is not None else None,
            "PerfFreq": int(getattr(item, "perf_freq", 0) or 0),
            "TimerResolution": int(getattr(item, "timer_resolution_100ns", 0) or 0),
            "CpuSpeedInMHz": int(getattr(item, "cpu_speed_mhz", 0) or 0),
            "EventsLost": int(getattr(item, "events_lost", 0) or 0),
            "BuffersLost": int(getattr(item, "buffers_lost", 0) or 0),
            "BuffersWritten": int(getattr(item, "buffers_written", 0) or 0),
            "PointerSize": int(getattr(item, "pointer_size", 0) or 0),
        })
    return rows


def _native_metadata_dataframe(trace: TraceData) -> pd.DataFrame | None:
    rows = _native_metadata_rows(trace)
    if rows:
        return pd.DataFrame(rows)
    df = trace.raw_csv.get("trace_metadata")
    if df is not None and not df.empty:
        return df
    return None


def _numeric_metadata_column(df: pd.DataFrame, column: str) -> pd.Series:
    if column not in df.columns:
        return pd.Series(dtype="float64")
    return pd.to_numeric(df[column], errors="coerce").dropna()


def _apply_native_metadata(trace: TraceData) -> None:
    """Populate native-mode metadata from ETL logfile headers."""
    if trace.mode != "native":
        return

    df = trace.raw_csv.get("trace_metadata")
    if df is None or df.empty:
        df = _native_metadata_dataframe(trace)
        if df is not None and not df.empty:
            with trace.lock:
                trace.raw_csv["trace_metadata"] = df
    if df is None or df.empty:
        return

    cpu_values = _numeric_metadata_column(df, "NumberOfProcessors")
    cpu_values = cpu_values[cpu_values > 0]
    if not cpu_values.empty:
        trace.cpu_count = int(cpu_values.max())

    duration_values = _numeric_metadata_column(df, "DurationSeconds")
    duration_values = duration_values[duration_values > 0]
    if not duration_values.empty:
        trace.duration_seconds = float(duration_values.max())
    else:
        starts = _numeric_metadata_column(df, "StartTime")
        ends = _numeric_metadata_column(df, "EndTime")
        starts = starts[starts > 0]
        ends = ends[ends > 0]
        if not starts.empty and not ends.empty and float(ends.max()) > float(starts.min()):
            trace.duration_seconds = (float(ends.max()) - float(starts.min())) / 10_000_000.0

    freq_values = _numeric_metadata_column(df, "PerfFreq")
    freq_values = freq_values[freq_values > 0]
    if not freq_values.empty:
        trace.timestamp_frequency = float(freq_values.iloc[0])


def _populate_metadata(trace: TraceData) -> None:
    """Extract metadata from loaded DataFrames."""
    _apply_native_metadata(trace)
    allow_inferred_metadata = trace.mode != "native"

    for name, df in trace.raw_csv.items():
        trace.event_counts[name] = len(df)

        # xperf data lacks a dedicated metadata row, so keep the historical
        # best-effort inference there. Native traces use TRACE_LOGFILE_HEADER.
        if allow_inferred_metadata and trace.cpu_count is None and "CPU" in df.columns:
            try:
                trace.cpu_count = int(df["CPU"].max()) + 1
            except (ValueError, TypeError):
                pass

        if allow_inferred_metadata and trace.duration_seconds is None:
            for col in ["TimeStamp", "Time", "Timestamp (s)"]:
                if col in df.columns:
                    try:
                        vals = pd.to_numeric(df[col], errors="coerce").dropna()
                        if not vals.empty:
                            trace.duration_seconds = float(vals.max() - vals.min())
                            break
                    except Exception:
                        pass

    if trace.event_store is not None:
        for name, dataset in trace.event_store.manifest.datasets.items():
            trace.event_counts[f"event_store:{name}"] = dataset.row_count


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

    if trace.event_store is not None:
        lines.append("")
        lines.append("**Native event store:**")
        lines.append(
            "Native mode is a fast-path coverage subset, not full `xperf` "
            "parity; reload with `mode=\"xperf\"` if an analysis needs "
            "broader WPA/xperf-derived data."
        )
        for name, dataset in sorted(trace.event_store.manifest.datasets.items()):
            lines.append(
                f"- `{name}`: {dataset.row_count:,} rows across "
                f"{len(dataset.parts)} chunk(s)"
            )
        if _is_streaming_event_store_cache(trace.export_dir):
            lines.append(
                "Streaming event chunks are loaded without materializing raw "
                "events. Low-risk aggregate datasets are loaded when present; "
                "stack aggregates are built lazily when SampledProfile stack "
                "lists were captured."
            )

    if trace.export_errors:
        lines.append("")
        lines.append(f"## Export errors ({len(trace.export_errors)})")
        for err in trace.export_errors:
            lines.append(f"- {err}")

    lines.append("")
    if trace.event_store is not None and _is_streaming_event_store_cache(trace.export_dir):
        missing = _streaming_missing_aggregates(trace.raw_csv)
        if missing:
            lines.append(
                f"Ready for event-store-aware analysis. Pass `trace_id=\"{trace.trace_id}\"`; "
                "aggregate tools may report limited data for missing datasets: "
                + ", ".join(missing)
            )
        else:
            lines.append(
                f"Ready for analysis. Pass `trace_id=\"{trace.trace_id}\"` to analysis tools "
                "such as `get_cpu_samples`, `get_per_cpu_summary`, `get_dpc_summary`, "
                "and `get_hot_stacks`."
            )
    else:
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
        # Release dbghelp state if we had a symbolizer attached
        # (native-mode traces only). Errors here are silent — the
        # registry removal already succeeded.
        sym = getattr(trace, "symbolizer", None)
        if sym is not None:
            try:
                sym.close()
            except Exception:
                pass
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
        return (
            "xperf.exe not found.\n\n"
            "resolve_symbols uses xperf to build the symcache and download "
            "PDBs. Install Windows Performance Toolkit (part of Windows "
            "SDK/ADK) or add it to PATH.\n\n"
            "Expected at: C:\\Program Files (x86)\\Windows Kits\\10\\Windows Performance Toolkit\\xperf.exe\n\n"
            "Note: load_trace itself can run under mode='native' or "
            "mode='csharp' without xperf, but symbol resolution still "
            "requires xperf today."
        )

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
