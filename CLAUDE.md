# CLAUDE.md

Guidance for Claude Code (and other AI assistants) when working on the **wpr-mcp-server** source. For end-user docs (install, MCP config, tool list), see `README.md`.

## What this repo is

An MCP server that wraps `xperf.exe` so AI assistants can analyze Windows WPR/ETW traces (`.etl`). Python 3.11+, packaged with `uv`, served over stdio via FastMCP. Windows-only — every analysis tool ultimately runs `xperf` as a subprocess.

## Layout

```
src/etw_analyzer/
  server.py              ← entry point: imports each tools.* module to register @mcp.tool()s, then mcp.run("stdio")
  app.py                 ← single FastMCP instance ("etw-trace-analyzer") + server instructions
  trace_state.py         ← TraceData dataclass + registry (make_trace_id, register/get/require_trace, list_loaded_trace_ids)
  tools/                 ← one module per tool group; each calls @mcp.tool() at import time
    trace_mgmt.py        ← list_traces, load_trace, list_loaded_traces, unload_trace, trace_info, check_symbols, resolve_symbols
    cpu_sampling.py      ← get_cpu_samples, get_hot_functions
    per_cpu.py           ← get_per_cpu_summary, get_cpu_timeline
    stack_analysis.py    ← get_hot_stacks, get_function_callers, walk_stack, count_stacks, butterfly_chain
    dpc_isr.py           ← get_dpc_summary, get_dpc_per_cpu
    context_switch.py    ← get_lock_contention
    memory.py            ← get_memory_pools
    system_info.py       ← get_sysconfig, get_process_info, get_diskio_summary, get_trace_stats
    compare.py           ← compare_traces
    summary.py           ← analyze, export_analysis
  parsing/
    wpa_exporter.py      ← xperf subprocess wrapper, all output parsers, export_all_profiles (parallel)
    csv_loader.py        ← BOM/comma-aware CSV → DataFrame normalization
    aggregator.py        ← parse_cpu_filter, apply_filters, group/sum, percentiles, time_bucket
  formatting/
    markdown.py          ← format_table, format_pct — every tool returns a markdown string
tests/                   ← pytest, synthetic data only — no xperf or .etl required
pyproject.toml           ← hatchling build, deps: mcp, pandas, pyarrow; dev: pytest
```

## How tools get registered

Tools are not enumerated by FastMCP automatically — `server.py` imports every `tools.*` submodule, and each submodule attaches functions to the shared `mcp` instance via `@mcp.tool()`. **If you add a new tool module, you must add an `import` line to `server.py` or the tool will not be visible.**

Every analysis tool's signature starts with `trace_id: str` and calls `require_trace(trace_id)` immediately. There is no "current trace" state — IDs are explicit so multiple traces can be analyzed concurrently in one process.

## Trace lifecycle

```
load_trace(etl_path)
  → find_xperf() locates xperf.exe under "Windows Kits\10\Windows Performance Toolkit"
  → export_dir = etl_path.parent / ".etw-export-<stem>"
  → _load_from_cache() — if parquet files newer than ETL, skip xperf entirely
  → otherwise run _run_xperf(..., "symcache", ["-build"]) then export_all_profiles():
       ThreadPoolExecutor runs 9 xperf actions in parallel:
         profile -detail, profile -util, dpcisr, stack -butterfly, cswitch,
         tracestats, sysconfig, process, diskio
       outputs land in export_dir as .parquet (structured) or .txt (raw)
  → _refresh_stack_cache_from_html() re-parses the richer butterfly HTML into stacks.parquet
  → TraceData built with raw_csv = {profile_name: DataFrame}, registered in _traces dict
  → _start_background_dumper() kicks off xperf -a dumper in a thread to populate
    SampledProfile events for per-CPU queries (TraceData._dumper_future / _dumper_ready)
  → returns markdown summary including the trace_id

trace_id format: "trace_<sha256[:12]>" of (lowercase path | size | mtime_ns) — stable per ETL version.

require_trace(trace_id) raises ValueError listing loaded IDs when the ID is unknown — propagate that message, don't swallow it.
```

## Conventions

- **Tool docstrings are user-visible.** FastMCP exposes them as the tool description in the MCP protocol. Keep them concrete; describe arg semantics (units, format like `"18-39"` for CPU ranges, `"trace" | "active_cpus" | "active_busy" | "custom"` for denominators).
- **Every tool returns a markdown string.** Use `format_table(df)` / `format_pct(value)`. Don't return DataFrames or raw dicts.
- **DataFrames live in `TraceData.raw_csv` keyed by short name** (`"cpu_sampling"`, `"dpc_isr"`, `"cswitch"`, `"stacks"`, `"stacks_callers"`, `"cpu_timeline"`, `"sysconfig"`, `"process"`, `"diskio"`, `"tracestats"`). Helpers like `_get_sampling_df()` and `_get_stacks_df()` already exist — reuse them rather than indexing `raw_csv` directly.
- **Common filter args** flow through `parsing.aggregator.apply_filters` (cpu_filter, start/end_time, module/process/function_filter). Don't re-roll filter logic.
- **CPU filters** use `parse_cpu_filter("0-7,16,18-20")` → list/set of ints. Keep that format consistent across new tools.
- **Per-CPU drill-downs** that go beyond xperf's aggregate output need the dumper DataFrame — call `trace.wait_for_dumper()` (blocks on the background thread) before filtering.
- **No emojis, no decorative output.** Markdown tables and plain headers only.

## xperf integration notes

- `_run_xperf()` always passes `-symbols` unless `symbols=False`; injects `_NT_SYMBOL_PATH` via env; uses `CREATE_NO_WINDOW` on win32 so progress bars don't escape capture; non-zero exit is tolerated if stdout has content (xperf is noisy).
- New "action" support: add an `_export_<name>` function in `wpa_exporter.py`, append it to the `export_fns` list inside `export_all_profiles`, and either `_save_df` parquet output or write raw `.txt`. Then expose the parsed DataFrame via `trace.raw_csv["<name>"]`.
- The parquet cache is the source of truth on reload — bumping a parser is not enough; users must `force=True` or delete `.etw-export-<stem>/`. Mention this in any commit that changes parser output schema.

## Running and testing

```powershell
# Run the server (stdio — exits on EOF, Ctrl+C to stop interactively)
uv run python -m etw_analyzer.server

# Tests — synthetic data, no xperf needed, fast
uv run --group dev pytest tests/ -v

# Single test file
uv run --group dev pytest tests/test_parsers.py -v
```

`uv` handles the venv and Python install — don't `pip install` directly. Dependencies are pinned in `uv.lock`.

## Commits

- **All commits must be signed off** (`git commit -s` or include `Signed-off-by: <name> <email>` manually). The whole history follows this.
- Subject line is a single short imperative sentence ("Background dumper extraction after load_trace", "Add xperf.exe check to install prompt"). Body explains *why*, often as bullet points.
- Small, single-concern commits — see `git log` for the cadence.
- **Don't commit unless the user asks.** Same rule as the parent `C:\git\CLAUDE.md`.

## Things to know before changing behavior

- **`load_trace` re-export is expensive** (30–180s). Anything that invalidates the cache silently is a footgun — prefer explicit `force=True` or a parquet-version bump.
- **The dumper thread runs unbounded.** `_start_background_dumper` swallows errors into `TraceData._dumper_error`; check that field rather than assuming success after `wait_for_dumper()`.
- **Tests don't cover the xperf path.** They parse fixture strings via `_parse_*` helpers. End-to-end with a real ETL is manual.
- **Tool count is part of the contract.** Renaming or removing an `@mcp.tool()` is a breaking change for any agent already configured against this server — bump `version` in `pyproject.toml` and note it.
- **FastMCP's `instructions` string** (in `app.py`) is what clients see as server-level guidance. Keep it in sync with the actual tool set when adding or removing tools.
