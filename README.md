# WPR Trace Analyzer MCP Server

An [MCP](https://modelcontextprotocol.io/) server that lets AI coding assistants analyze Windows WPR/ETW traces (`.etl` files). Load a trace, then ask questions in natural language — the server decodes the ETL in-process via `OpenTraceW` (with a legacy `xperf.exe` fallback) and returns structured results.

Works with any Windows performance trace: networking (tcpip.sys, NDIS, NIC drivers, HTTP.sys), kernel (DPCs, ISRs, context switches), and application workloads.

### Quick Install

Copy-paste this into Claude Code, Copilot, or any AI assistant to install automatically:

```
Install the WPR trace analyzer MCP server on this Windows machine:
1. Run: winget install astral-sh.uv (skip if uv is already installed)
2. Check if xperf.exe exists at "C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe". If not, run: winget install Microsoft.WindowsSDK
3. Run: git clone https://github.com/nijosmsft/wpr-mcp-server.git C:\tools\wpr-mcp-server
4. Add this MCP server config to .mcp.json:
   {"mcpServers":{"wpr-trace-analyzer":{"type":"stdio","command":"uv","args":["run","--directory","C:\\tools\\wpr-mcp-server","python","-m","etw_analyzer.server"],"env":{"_NT_SYMBOL_PATH":"srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"}}}}
5. Verify: run "uv run --directory C:\tools\wpr-mcp-server python -m etw_analyzer.server" and confirm it starts
```

## Features

- **Auto-summary** — one-call comprehensive analysis: system config, per-CPU utilization, hot functions, symbol status, DPC health
- **CPU sampling** — hot functions by module, process, or call stack
- **Per-CPU breakdown** — utilization per logical processor, identify hot/idle/saturated CPUs
- **Per-CPU filtering** — drill into what's running on a specific CPU (e.g. "what's saturating CPU 0?")
- **Trace comparison** — diff two traces to find regressions (hot functions, modules, or per-CPU utilization)
- **DPC/ISR analysis** — duration histograms, per-CPU distribution, watchdog risk detection
- **Lock contention** — spinlock contention from ReadyThread/context switch stacks
- **Symbol resolution** — automatic PDB download from symbol servers
- **Call stacks** — butterfly stacks with caller/callee relationships, recursive stack walks, and WPA-style chain exports
- **System info** — CPU model, NIC details, memory, disk config from trace metadata
- **Process info** — running processes, command lines, loaded driver versions
- **Disk I/O** — per-file I/O summary to rule out storage bottlenecks
- **Export** — save analysis to markdown for sharing via email
- **Caching** — parquet-based disk cache for instant reload, parallel xperf extraction

## Installation

**Windows only** — this server uses Windows ETW APIs (`advapi32`, `tdh`, `dbghelp`).

```powershell
# 1. Install prerequisites — skip any you already have
winget install astral-sh.uv              # Python package manager
winget install Microsoft.WindowsSDK      # Optional — only needed for the xperf fallback

# 2. Clone and verify
git clone https://github.com/nijosmsft/wpr-mcp-server.git
cd wpr-mcp-server
uv run python -m etw_analyzer.server     # verify it starts (Ctrl+C to stop)
```

- **uv** automatically downloads Python, creates a virtual environment, and installs all dependencies on first run. No separate Python install needed.
- **Native ETW consumer (default)** — the server decodes ETL files in-process via `OpenTraceW`/`tdh.dll`. No external tools needed on a recent Windows build.
- **xperf.exe (fallback)** — installed as part of the Windows Performance Toolkit (included in the Windows SDK). Only required if you opt out of the native pipeline with `mode="xperf"` or `WPR_MCP_MODE=xperf`, or when running on an older Windows build where the native bindings can't load. Expected location: `C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe`

## Setup

Configure your AI assistant to use the server:

### Claude Code

Add to your `.mcp.json` (project root or `~/.claude/.mcp.json`):

```json
{
  "mcpServers": {
    "wpr-trace-analyzer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--directory", "C:\\path\\to\\wpr-mcp-server", "python", "-m", "etw_analyzer.server"],
      "env": {
        "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
      }
    }
  }
}
```

### VS Code (GitHub Copilot)

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "wpr-trace-analyzer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--directory", "C:\\path\\to\\wpr-mcp-server", "python", "-m", "etw_analyzer.server"],
      "env": {
        "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
      }
    }
  }
}
```

Replace `C:\\path\\to\\wpr-mcp-server` with the actual path to this repo.

## Usage

### Just Ask

You don't need to know tool names. Just describe what you want:

```
"Load the trace at C:\traces\mytrace.etl"
"Use the returned trace_id for the next questions"
"Give me a summary of this trace"
"Where is CPU time being spent?"
"What's running on CPU 0?"
"Which CPUs have echo_server active?"
"Show me the hottest functions in tcpip.sys"
"Walk the caller chain for KeAcquireInStackQueuedSpinLock"
"Count stacks containing KxWaitForSpinLockAndAcquire and IppResolveNeighbor"
"What are the DPC durations for the NIC driver?"
"Which CPUs are active and which are idle?"
"Is there lock contention in the networking stack?"
"Compare this trace with the baseline"
"Export the analysis to a markdown file"
"What hardware is this trace from?"
"Which processes were running during the trace?"
```

### Workflow

```
load_trace(path)          → Parse ETL via xperf, cache as parquet, return trace_id
analyze(trace_id)         → One-call comprehensive report
detailed tools(trace_id)  → Drill into specific areas
export_analysis(trace_id) → Save to .md for sharing
```

Every analysis tool requires the `trace_id` returned by `load_trace`. This allows multiple traces to be analyzed concurrently in the same MCP server process without cross-trace contamination.

### Available Tools

#### Trace Management

| Tool | Purpose |
|------|---------|
| `list_traces` | Find `.etl` files in a directory |
| `load_trace` | Load an ETL file. Decodes events via the native consumer by default (set `mode="xperf"` to use the legacy pipeline), caches as parquet. Set `force=True` to re-export. |
| `list_loaded_traces` | Show trace IDs currently loaded in memory |
| `unload_trace` | Remove a loaded trace from memory |
| `trace_info` | Show loaded trace metadata by `trace_id` |
| `check_symbols` | Check symbol resolution status by `trace_id`, identify missing PDBs |
| `resolve_symbols` | Download PDBs from symbol servers and reload trace by `trace_id` |

#### Analysis

| Tool | Purpose |
|------|---------|
| `analyze` | One-call comprehensive report: sysconfig, per-CPU, hot functions, symbols, DPC health |
| `get_cpu_samples` | CPU sampling grouped by process, module, function, or CPU. Per-CPU filtering supported. |
| `get_hot_functions` | Hot functions filtered to networking modules (customizable). Per-CPU filtering and denominator modes supported. |
| `get_per_cpu_summary` | Per-CPU utilization with role classification (saturated/active/idle) |
| `get_cpu_timeline` | Per-CPU utilization over time with hot CPU identification |
| `get_hot_stacks` | Hot stack functions with true inclusive/exclusive weights and selectable denominator |
| `get_function_callers` | Who calls a function and what it calls, with parent and denominator percentages |
| `walk_stack` | Recursively walk caller/callee butterfly edges with dominant/all/threshold branch policy |
| `count_stacks` | Estimate aggregate butterfly sample counts for stack predicates |
| `butterfly_chain` | One-shot WPA-style chain export around a target function (`table`, `csv`, or `wpa_csv`) |
| `get_dpc_summary` | DPC/ISR duration histogram per module with watchdog risk assessment |
| `get_dpc_per_cpu` | Per-CPU DPC breakdown |
| `get_lock_contention` | Spinlock contention from ReadyThread stacks |
| `get_memory_pools` | Kernel pool allocations by module and tag |

#### System & Process Info

| Tool | Purpose |
|------|---------|
| `get_sysconfig` | CPU model, core count, memory, NIC details, disk config from trace |
| `get_process_info` | Running processes, command lines, loaded images. Filterable by process name. |
| `get_diskio_summary` | Per-file disk I/O counts, bytes, and latency |
| `get_trace_stats` | Which ETW providers/events are in the trace. Diagnose missing data. |

#### Comparison & Export

| Tool | Purpose |
|------|---------|
| `compare_traces` | Diff two traces: hot functions, modules, or per-CPU utilization. Shows delta. |
| `export_analysis` | Save the auto-summary analysis to a .md file for sharing |

### Common Parameters

Most analysis tools accept:

- `trace_id` — required ID returned by `load_trace`
- `cpu_filter` — CPU range, e.g. `"0"` or `"18-39"`. Enables per-CPU extraction from raw events.
- `start_time` / `end_time` — seconds from trace start
- `module_filter` — substring match, e.g. `"tcpip.sys"`
- `process_filter` — substring match, e.g. `"echo_server"`
- `max_rows` — limit output rows
- `denominator` — percentage basis for hot stack/function tools: `"trace"`, `"active_cpus"`, `"active_busy"`, or `"custom"`

### Stack Analysis Notes

`get_hot_stacks` uses xperf's butterfly `Functions by UniInclusive Hits` table, so inclusive and exclusive hit counts are kept separate. `walk_stack` and `butterfly_chain` use the butterfly caller/callee table and require the `trace_id` returned by `load_trace`. `count_stacks` currently works from aggregate butterfly edges, so it estimates matching sample counts rather than counting distinct raw stack instances.

### Trace Loading Modes

`load_trace` accepts a `mode` argument that selects the extraction pipeline:

| Mode | Behavior |
|------|----------|
| `"auto"` (default) | Probes the in-process native consumer. Uses it when available; silently falls back to xperf when the bindings can't load (e.g. older Windows builds). |
| `"native"` | Forces the in-process `OpenTraceW`/`tdh.dll` consumer. Decodes manifest providers (TCPIP, AFD, MsQuic, HTTP.sys) that xperf cannot enumerate. Raises an error if the native bindings aren't available — does not fall back. |
| `"xperf"` | Forces the legacy `xperf.exe -a dumper` text-based extraction. Requires the Windows Performance Toolkit on PATH. Use this if you hit a native-mode bug or are running on a build the native consumer doesn't support. |

The `WPR_MCP_MODE` environment variable overrides the default when `mode=` is left unspecified. Set `WPR_MCP_MODE=xperf` in your MCP config to opt every load_trace call back to the legacy pipeline:

```json
{
  "mcpServers": {
    "wpr-trace-analyzer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--directory", "C:\\path\\to\\wpr-mcp-server", "python", "-m", "etw_analyzer.server"],
      "env": {
        "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
        "WPR_MCP_MODE": "xperf"
      }
    }
  }
}
```

The explicit `mode=` arg always wins over the env var. Both pipelines write the same parquet cache layout, so traces loaded in one mode can be rehydrated from cache in the other without re-extracting.

### Parallel Analysis

The server supports multiple loaded traces in one MCP server process when callers pass `trace_id` explicitly. Each analysis tool resolves data from the requested trace ID instead of using shared "current trace" state, so parallel agents can safely analyze different ETLs at the same time.

## Architecture

```
AI Assistant ←stdio→ wpr-mcp-server (Python)
                         │
                         ├── Native consumer (default, mode="auto" or "native")
                         │   ├── OpenTraceW / ProcessTrace via advapi32
                         │   ├── TdhGetEventInformation via tdh.dll
                         │   ├── dbghelp.dll for symbolization
                         │   └── In-process event dispatch → aggregators
                         │       → CPU sampling, DPC/ISR, CSwitch, TCPIP, UDP,
                         │         AFD, NDIS PacketCapture, HTTP.sys, MsQuic, ...
                         │
                         ├── xperf.exe (fallback, mode="xperf")
                         │   ├── profile -detail   → CPU sampling (module!function)
                         │   ├── profile -util     → Per-CPU utilization timeline
                         │   ├── dpcisr            → DPC/ISR histograms
                         │   ├── stack -butterfly   → Call stacks with callers/callees
                         │   ├── cswitch           → Context switch data
                         │   ├── sysconfig         → Hardware configuration
                         │   ├── process           → Process/thread/image info
                         │   ├── diskio            → Disk I/O summary
                         │   ├── tracestats        → Trace metadata
                         │   └── dumper            → Raw events (on-demand, cached)
                         │
                         ├── parquet cache (.etw-export-<name>/)
                         │   Structured data saved as .parquet for instant reload.
                         │   Raw text saved as .txt. Cache invalidated when ETL is newer.
                         │   Shared between native and xperf modes.
                         │
                         ├── pandas (aggregation + filtering)
                         └── FastMCP (stdio transport)
```

### Performance

- **First load (native, default):** 5-30s for typical traces. Single in-process pass — no subprocess overhead.
- **First load (xperf fallback):** 30-180s (9 xperf actions run in parallel with 4 workers)
- **Subsequent loads:** Instant (reads from parquet cache, regardless of mode)
- **Per-CPU queries:** First query parses all SampledProfile events, subsequent queries filter in-memory (<1s)
- **Trace comparison:** Uses cache from both traces — instant if both were previously loaded

## Project Structure

```
wpr-mcp-server/
├── pyproject.toml
├── README.md
├── LICENSE
├── tests/                           ← synthetic data, no xperf needed
└── src/etw_analyzer/
    ├── server.py                    ← MCP server entry point
    ├── app.py                       ← FastMCP instance
    ├── trace_state.py               ← Loaded trace registry + dumper cache
    ├── tools/
    │   ├── trace_mgmt.py            ← load_trace, list_traces, list_loaded_traces, check/resolve_symbols
    │   ├── cpu_sampling.py          ← get_cpu_samples, get_hot_functions
    │   ├── per_cpu.py               ← get_per_cpu_summary, get_cpu_timeline
    │   ├── stack_analysis.py        ← get_hot_stacks, get_function_callers
    │   ├── dpc_isr.py               ← get_dpc_summary, get_dpc_per_cpu
    │   ├── context_switch.py        ← get_lock_contention
    │   ├── memory.py                ← get_memory_pools
    │   ├── system_info.py           ← get_sysconfig, get_process_info, get_diskio_summary, get_trace_stats
    │   ├── compare.py               ← compare_traces
    │   └── summary.py               ← analyze, export_analysis
    ├── parsing/
    │   ├── wpa_exporter.py          ← xperf subprocess wrapper + output parsers
    │   ├── csv_loader.py            ← CSV parsing + normalization
    │   └── aggregator.py            ← Filters, group-by, percentiles
    └── formatting/
        └── markdown.py              ← Table formatting for MCP responses
```

## Symbol Configuration

For Microsoft system binaries, use the public symbol server:

```
_NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols
```

For internal Microsoft builds, use the internal server:

```
_NT_SYMBOL_PATH=srv*C:\symbols*https://symweb.azurefd.net
```

Multiple paths can be combined with semicolons. Add local PDB directories for your own binaries:

```
_NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols;C:\myproject\build\bin
```

## Development

### Running Tests

```powershell
uv run --group dev pytest tests/ -v
```

Tests use synthetic data and don't require `xperf.exe` or ETL trace files.

## Contributing

Contributions welcome. Please open an issue first to discuss what you'd like to change.

## License

[MIT](LICENSE)
