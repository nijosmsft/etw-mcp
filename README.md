# etw-mcp

An [MCP](https://modelcontextprotocol.io/) server that lets AI coding assistants analyze Windows WPR/ETW traces (`.etl` files). Load a trace, then ask questions in natural language — the server uses a self-contained .NET sidecar by default (auto-downloaded on first use), with a fast in-process ETW path and `xperf.exe` as fallbacks.

> [!IMPORTANT]
> **Personal hobby project — not endorsed by Microsoft.**
>
> This repository is a personal side project. It is not an official
> Microsoft product, is not affiliated with or endorsed by Microsoft,
> and carries no warranty or support guarantee. Use at your own risk.

> New here? Start with [GETTING-STARTED.md](GETTING-STARTED.md) for a 30-minute clone-to-first-query walkthrough, then [ARCHITECTURE.md](ARCHITECTURE.md) for the cross-repo dataflow.

Works with any Windows performance trace: networking (tcpip.sys, NDIS, NIC drivers, HTTP.sys), kernel (DPCs, ISRs, context switches), and application workloads.

### Quick Install

The snippet below pins v0.6.0 — grab the latest wheel URL from <https://github.com/nijosmsft/etw-mcp/releases/latest> if you need a newer build. Install [uv](https://docs.astral.sh/uv/) (`winget install astral-sh.uv`) and the Windows Performance Toolkit (`winget install --id Microsoft.WindowsADK --override "/features OptionId.WindowsPerformanceToolkit /quiet"`), then drop the config below into your MCP client. The top-level key is `mcpServers` for Claude / Copilot CLI / Claude Desktop / Cursor and `servers` for VS Code — per-client config paths are spelled out in [Setup](#setup) below. The first `load_trace` call auto-downloads the matching .NET sidecar (~40 MB) into `%LOCALAPPDATA%\etw-mcp\sidecar\v0.6.0\` and pulls 200-500 MB of PDBs to `C:\symbols`; set `ETW_MCP_NO_AUTO_DOWNLOAD=1` to skip the sidecar fetch.

```json
{
  "mcpServers": {
    "etw-trace-analyzer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--no-project", "--with",
               "https://github.com/nijosmsft/etw-mcp/releases/download/v0.6.2/etw_mcp-0.6.2-py3-none-any.whl",
               "python", "-m", "etw_analyzer.server"],
      "env": {
        "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
      }
    }
  }
}
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
- **Network flows and sockets** — TCP/UDP throughput, per-flow summaries, retransmits, socket lifecycle, and AFD batching
- **Packet capture analysis** — decode NDIS PacketCapture frame bytes from WPR/pktmon-style ETLs, including 5-tuples, timelines, and Send→Recv latency estimates
- **Export** — save analysis to markdown for sharing via email
- **Caching** — parquet-based disk cache for instant reload, parallel xperf extraction

## Installation

**Windows only** — this server uses Windows ETW APIs (`advapi32`, `tdh`, `dbghelp`).

```powershell
# 1. Install prerequisites — skip any you already have
winget install astral-sh.uv              # Python package manager
winget install --id Microsoft.WindowsADK --override "/features OptionId.WindowsPerformanceToolkit /quiet"
                                         # Recommended — provides xperf for fallback and full analysis coverage.
                                         # NOTE: do NOT use Microsoft.WindowsSDK — it is not a valid winget package ID.
                                         # The --override flag installs just the ~150 MB WPT feature instead of the full ~5 GB ADK.

# 2. Verify the latest release wheel starts (Ctrl+C to stop)
uv run --no-project --with https://github.com/nijosmsft/etw-mcp/releases/download/v0.6.2/etw_mcp-0.6.2-py3-none-any.whl python -m etw_analyzer.server
```

- **uv** automatically downloads Python, creates a virtual environment, and installs all dependencies on first run. No separate Python install needed.
- **Release wheel** — use the `.whl` asset URL from the latest [GitHub release](https://github.com/nijosmsft/etw-mcp/releases). The examples use `<release-tag>` and `<wheel-file>` placeholders because the URL is only valid after a release is published. Maintainers can publish that asset with the manual **Manual release** GitHub Actions workflow.
- **.NET sidecar (default; auto-bootstrapped)** — `etw-extract.exe` is a self-contained .NET binary (~40 MB, no .NET install required) that decodes ETL files faster than the in-process path and frees the Python process from holding the full event buffer. The wheel **auto-fetches the matching version** from the GitHub release on first use and caches it at `%LOCALAPPDATA%\etw-mcp\sidecar\v<wheel-version>\`. Set `ETW_MCP_NO_AUTO_DOWNLOAD=1` to disable the fetch (the server then falls back to the native consumer) or set `ETW_MCP_DOTNET_SIDECAR` to pin a manually-built binary. See [`dotnet/README.md`](dotnet/README.md) for build instructions and [`src/etw_analyzer/native/SIDECAR.md`](src/etw_analyzer/native/SIDECAR.md) for the supervisor plumbing.
- **Native ETW consumer (fallback when sidecar is unavailable)** — the server decodes ETL files in-process via `OpenTraceW`/`tdh.dll`. This path is enough to start the MCP server and run the core native analysis tools on recent Windows builds and is the automatic fallback when auto-bootstrap is blocked.
- **xperf.exe / Windows Performance Toolkit** — installed as part of the Windows SDK. Recommended for complete results because it enables fallback extraction, richer WPA-derived stack views, xperf-only tools such as pool analysis, and older Windows builds where the native bindings can't load. Expected location: `C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe`

## Setup

Configure your AI assistant to use the server:

### Claude Code

Add to your `.mcp.json` (project root or `~/.claude/.mcp.json`):

```json
{
  "mcpServers": {
    "etw-trace-analyzer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--no-project", "--with", "https://github.com/nijosmsft/etw-mcp/releases/download/v0.6.2/etw_mcp-0.6.2-py3-none-any.whl", "python", "-m", "etw_analyzer.server"],
      "env": {
        "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
      }
    }
  }
}
```

### VS Code (GitHub Copilot)

Add to `.vscode/mcp.json` (workspace) or `%APPDATA%\Code\User\mcp.json` (user-scoped):

> **Note: VS Code uses `servers` as the top-level key, NOT `mcpServers`.** Pasting an `mcpServers` block into a VS Code config silently does nothing — the server will not appear in Copilot. Every other MCP client documented here uses `mcpServers`.

```json
{
  "servers": {
    "etw-trace-analyzer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--no-project", "--with", "https://github.com/nijosmsft/etw-mcp/releases/download/v0.6.2/etw_mcp-0.6.2-py3-none-any.whl", "python", "-m", "etw_analyzer.server"],
      "env": {
        "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
      }
    }
  }
}
```

### Claude Desktop

Add to `%APPDATA%\Claude\claude_desktop_config.json` (top-level key: `mcpServers`):

```json
{
  "mcpServers": {
    "etw-trace-analyzer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--no-project", "--with", "https://github.com/nijosmsft/etw-mcp/releases/download/v0.6.2/etw_mcp-0.6.2-py3-none-any.whl", "python", "-m", "etw_analyzer.server"],
      "env": {
        "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
      }
    }
  }
}
```

### GitHub Copilot CLI

Add to `%USERPROFILE%\.copilot\mcp-config.json` (top-level key: `mcpServers`):

```json
{
  "mcpServers": {
    "etw-trace-analyzer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--no-project", "--with", "https://github.com/nijosmsft/etw-mcp/releases/download/v0.6.2/etw_mcp-0.6.2-py3-none-any.whl", "python", "-m", "etw_analyzer.server"],
      "env": {
        "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` (project root) or `%USERPROFILE%\.cursor\mcp.json` (user-scoped). Top-level key: `mcpServers`. The JSON body is identical to the Claude Code example above.

Replace the release URL in every example with the wheel asset from the release you want to run.

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
"Show TCP and UDP throughput by process"
"Summarize UDP flows in this trace"
"Show packet drops by miniport and reason"
"Summarize packet-capture 5-tuples from this pktmon trace"
"Show the packet timeline for 10.0.0.1:5000 -> 10.0.0.2:6000/udp"
"Decode the packet closest to timestamp 123456789"
"Estimate Send -> Recv latency from packet capture data"
"Compare this trace with the baseline"
"Export the analysis to a markdown file"
"What hardware is this trace from?"
"Which processes were running during the trace?"
```

### Workflow

```
load_trace(path)          → Parse ETL via dotnet sidecar, native ETW, or xperf;
                            cache as parquet; return trace_id
analyze(trace_id)         → One-call comprehensive report
detailed tools(trace_id)  → Drill into specific areas
export_analysis(trace_id) → Save to .md for sharing
```

Every analysis tool requires the `trace_id` returned by `load_trace`. This allows multiple traces to be analyzed concurrently in the same MCP server process without cross-trace contamination.

### Packet Capture and pktmon Examples

Packet-level drill-down tools need an ETL that includes NDIS PacketCapture frame bytes or pktmon packet bytes. For pktmon, collect with `--pkt-size 0`; the analyzer can convert the ETL with `pktmon etl2txt`/`pktmon etl2pcap`, summarize top flows, show timelines, decode packets, estimate Send -> Recv latency, and report pktmon component/edge layer latency. Latency estimates are heuristic and are most reliable on loopback or hosts with synchronized clocks:

```powershell
pktmon filter remove
pktmon filter add UdpEcho -t UDP -p 4444
pktmon start --capture --pkt-size 0 --file-name C:\traces\pktmon-udp.etl
# Run the workload you want to inspect.
pktmon stop
```

WPR profiles work too as long as they enable the `Microsoft-Windows-NDIS-PacketCapture` provider.

Pktmon ETLs expose numeric component/edge IDs in packet events. For friendly component names, the analyzer uses `pktmon comp list --all` on the analysis host or a sidecar file named `<trace>.components.txt` / `pktmon.components.txt` captured from the target machine.

Then ask questions like:

```
"Load C:\traces\pktmon-udp.etl and show the packet capture summary"
"Which 5-tuples account for the most bytes?"
"Show packet timeline for 10.0.0.1:4444 -> 10.0.0.2:4444/udp"
"Decode the packet closest to timestamp 123456789"
"Estimate one-way Send -> Recv latency for captured packets and explain any clock-sync caveats"
"Show pktmon layer latency for the top TCP and UDP flows"
"Show NDIS packet drops by miniport and reason"
"Check whether UDP recv processing is staying on the same CPUs as NIC DPCs"
```

### Remote Collection with LabLink MCP

[LabLink](https://github.com/nijosmsft/LabLink) — lightweight Go MCP for remote command execution on Windows lab machines. When the AI client has both MCP servers configured, LabLink can collect traces from remote Windows machines; etw-mcp analyzes the ETL after LabLink pulls it to the operator machine.

Common combined prompts:

```
"On vm-server, collect a 60 second networking trace and tell me which network functions are hottest."
"Capture UDP port 4444 packets on vm-server for 30 seconds and show the top flows."
"Get a 30 second performance log from the server role and summarize CPU, DPCs, and TCP/UDP throughput."
"Trace traffic between 10.0.0.1 and 10.0.0.2 on vm-server, then decode the largest flow and estimate Send -> Recv latency with clock-sync caveats."
```

For WPR captures, ask for the outcome instead of naming tools:

```
"Collect a 60 second networking trace from vm-server and tell me which modules and functions used the most CPU."
"Capture a performance trace from the server role, then summarize CPU usage, DPC time, TCP/UDP throughput, and any packet drops."
"Get a WPR trace from vm-server while I reproduce the issue, then analyze network hot functions and lock contention."
```

For pktmon captures, describe the traffic pattern and the analysis you want:

```
"Collect packet monitor traffic on vm-server for UDP port 4444 for 30 seconds, then show the top flows."
"Trace packets between 10.0.0.1 and 10.0.0.2 on vm-server, then decode the busiest flow and estimate layer latency with confidence levels."
"Capture pktmon data for TCP 443 on vm-server, pull it back, and tell me which component/edge hop adds the most latency."
"Collect a packet trace for this pattern and analyze it end to end: top flows, timeline, packet decode, and pktmon layer latency."
```

Run the LabLink agent elevated, or under an account with permission to start ETW sessions and write the chosen remote ETL path. The analyzer runs locally after the `.etl` is pulled back, so it only needs read access to the local trace file.

### Available Tools

#### Trace Management

| Tool | Purpose |
|------|---------|
| `list_traces` | Find `.etl` files in a directory |
| `load_trace` | Load an ETL file. Decodes events via the .NET sidecar (when configured), the in-process native consumer, or xperf — see [Trace Loading Modes](#trace-loading-modes). Caches as parquet. Set `force=True` to re-export. |
| `list_loaded_traces` | Show trace IDs currently loaded in memory |
| `unload_trace` | Remove a loaded trace from memory |
| `trace_info` | Show loaded trace metadata by `trace_id` |
| `check_symbols` | Check symbol resolution by `trace_id` with honest 3-category classification (OK / EXPORT_ONLY / MISSING). Accepts `extra_symbol_paths` to append local PDB dirs. |
| `resolve_symbols` | Download PDBs from symbol servers and reload trace by `trace_id`. Accepts `extra_symbol_paths`. |
| `diagnose_symbol_load` | Explain why a module is EXPORT_ONLY / MISSING by reconciling the EXE's RSDS record, all candidate PDBs on disk, and what dbghelp actually loaded. |
| `clean_stale_symbol_files` | Remove stale `C:\SymCache\<pdb>\<GUID+Age>\` subfolders that don't match the current EXE's RSDS record (dry_run by default). |

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

#### Networking & Packet Capture

| Tool | Purpose |
|------|---------|
| `get_connection_summary` | Per-TCP-connection bytes, packets, retransmits, and duration |
| `get_udp_flow_summary` | Per-UDP-flow packet counts, bytes, duration, and packet rate |
| `get_per_process_socket_throughput` | Per-process TCP/UDP PPS and MB/s, split by send and receive |
| `get_tcp_retransmits` | Per-connection TCP retransmit counts and rates |
| `get_connect_latency` | Per-process TCP connect cadence/latency percentiles |
| `get_accept_latency` | Per-process TCP accept cadence/latency percentiles |
| `get_packet_drops` | NDIS dropped-packet counts by miniport and reason |
| `get_afd_batching` | Approximate packets per AFD/IOCP receive completion |
| `get_socket_lifecycle` | Socket create/close timing, duration, recv/send counts, and bytes |
| `get_socket_affinity_check` | Whether AFD recv completions cluster on one CPU per socket |
| `get_packet_capture_summary` | Decode packet-capture frame bytes and group traffic by 5-tuple |
| `get_packet_timeline` | Show chronological packets for a selected 5-tuple |
| `decode_packet` | Decode the Ethernet, IP, and L4 headers for the packet nearest a timestamp |
| `get_send_recv_latency` | Heuristic Send→Recv latency from matched packet-capture events |
| `get_pktmon_layer_latency` | Estimate pktmon component/edge traversal latency for TCP, UDP, and IP packets |
| `get_rss_dispatch_quality` | Compare NIC DPC CPUs with process CPU samples to spot cross-CPU dispatch |
| `get_udp_dispatch_quality` | UDP receive-path CPU distribution and overlap with networking DPC CPUs |
| `get_per_nic_queue_arrivals` | Per-CPU distribution of NIC-driver DPCs for RSS queue spread |
| `get_network_wait_chain` | Wait-reason and ReadyThread detail for network-active threads |
| `get_network_hot_functions` | Convenience view for hot functions in networking modules |
| `get_network_hot_stacks` | Convenience view for hot stack frames in networking modules |
| `get_network_dpcs` | Convenience view for DPC/ISR activity in networking modules |
| `get_network_lock_contention` | Convenience view for lock contention in networking modules |
| `get_http_requests` | HTTP.sys request lifecycle, URL, status, and latency |
| `get_http_queue_depth` | HTTP.sys URL-group queue depth and completion latency |
| `get_quic_connections` | MsQuic connection lifetime, packets, bytes, and loss estimate |
| `get_quic_cid_distribution` | MsQuic CID hash bucket and CPU distribution |
| `get_quic_ack_delays` | MsQuic AckDelay percentiles by connection |

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

For full WPA/butterfly stack parity, load with `mode="xperf"` (or set `ETW_MCP_MODE=xperf`); native mode covers core stack analysis but may not expose every xperf-derived view.

### Capturing traces

Most workflows start by analyzing an existing `.etl`. When you need to author one — locally or on a lab machine — use the four `capture_profiles` tools:

| Tool | Purpose |
| --- | --- |
| `list_capture_profiles` | Markdown table of the 9 bundled WPR scenarios (`cpu`, `cpu_dpc_isr`, `network`, `network_minimal`, `network_packets`, `xdp_cpumap`, `quic`, `ebpf`, `general`) plus the `pktmon` pseudo-scenario. Start here. |
| `get_capture_profile(scenario)` | Metadata table + the bundled `.wprp` XML in a fenced ```xml``` block, ready to save to a file on the target. |
| `get_capture_commands(scenario, output_path, duration_s=10)` | Paste-ready 3-step PowerShell (start / sleep / stop) plus a verification step. Branches automatically for the `pktmon` scenario (uses `pktmon start --capture --pkt-size 0 -f <path>` instead of `wpr -start`). |
| `get_capture_instructions(scenario, target="local" \| "remote", output_path)` | Long-form runbook covering prerequisites, profile save, start/verify, transfer-back examples (PowerShell remoting / LabLink MCP / scp) when `target="remote"`, and a `load_trace` pointer. |

The tools are transport-agnostic — they emit strings, never invoke `wpr.exe` or `pktmon.exe` themselves. Run the commands on local PowerShell, a [LabLink](https://github.com/nijosmsft/LabLink) MCP node, an SSH host, or hand them to a human. Then call `load_trace(etl_path=...)` on the resulting file to analyze it.

```powershell
# Typical local capture: 10s CPU profile, then analyze
wpr -start .\cpu.wprp -filemode
Start-Sleep -Seconds 10
wpr -stop 'C:\traces\cpu.etl'
# → call load_trace(etl_path='C:\traces\cpu.etl')
```

All WPR profiles require administrator elevation. WPR uses the NT Kernel Logger and so cannot run inside a Windows container.

### Trace Loading Modes

`load_trace` accepts a `mode` argument that selects the extraction pipeline. Three pipelines coexist, each with the same trace_id and parquet cache layout so a trace extracted in one mode can be reloaded in another. The default `mode="auto"` walks the fallback chain **`.NET sidecar → native → xperf`** and picks the first one available.

The `ETW_MCP_MODE` environment variable overrides the default when `mode=` is left unspecified. The explicit `mode=` arg always wins over the env var. See [CHANGELOG.md](CHANGELOG.md) for the `csharp` → `dotnet` rename history.

| Mode | What it is | When `auto` picks it | Force with | Notes |
| --- | --- | --- | --- | --- |
| `dotnet` | Self-contained .NET 8 binary (`etw-extract.exe`, ~40 MB) that decodes ETW Layer-1 events into per-class parquets. The Python server runs Layer-3 aggregators over the result. ~9× faster end-to-end than native on a 1 GB ETL. | Sidecar resolvable (auto-bootstrapped on first use). | `mode="dotnet"` or `ETW_MCP_MODE=dotnet` (raises if the binary cannot be resolved). | Pin a specific binary with `ETW_MCP_DOTNET_SIDECAR=<path>`; disable the GitHub fetch with `ETW_MCP_NO_AUTO_DOWNLOAD=1`. Manifests record `producer="dotnet"`. |
| `native` | In-process `OpenTraceW` + `tdh.dll` consumer in Python via `advapi32`. Decodes manifest providers (TCPIP, AFD, MsQuic, HTTP.sys) that xperf can't enumerate. | `.NET sidecar` unavailable, native bindings load. | `mode="native"` or `ETW_MCP_MODE=native` (raises if bindings can't load). | For ETLs >1 GB also set `ETW_MCP_NATIVE_ALLOW_LARGE=1` (the pipeline buffers events in pandas DataFrames in-process). Probe availability with `uv run python -c "from etw_analyzer.native.consumer import is_available; print(is_available())"`. Manifests record `producer="native"`. |
| `xperf` | Subprocess pipeline that shells out to `xperf.exe` from the Windows Performance Toolkit (`profile`, `dpcisr`, `stack -butterfly`, `cswitch`, `sysconfig`, `process`, `diskio`, `tracestats`) plus `xperf -a dumper` for raw events. Slowest path, broadest WPA tool coverage. | Neither sidecar nor native consumer is available. | `mode="xperf"` or `ETW_MCP_MODE=xperf`. | Requires WPT installed (default path `C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe`, or on `PATH`). Legacy pre-v3 manifests with no producer field are read as `producer="xperf"`. |

#### Pre-populating or building the .NET sidecar

The wheel auto-bootstraps the matching binary on first use, so most users don't need to do anything. For locked-down environments (no GitHub access) you can pre-populate the per-version cache or build from source.

```powershell
# Option A — download the prebuilt asset
New-Item -ItemType Directory -Force -Path "$env:LOCALAPPDATA\etw-mcp\sidecar\v0.6.0" | Out-Null
Invoke-WebRequest `
  -Uri "https://github.com/nijosmsft/etw-mcp/releases/download/v0.6.2/etw-extract.exe" `
  -OutFile "$env:LOCALAPPDATA\etw-mcp\sidecar\v0.6.0\etw-extract.exe"

# Option B — build from source (no .NET runtime required for the resulting binary; only for the build)
cd <repo>\dotnet
dotnet publish -c Release -r win-x64 --self-contained -o publish\win-x64
# Then either set ETW_MCP_DOTNET_SIDECAR to the published path or copy
# it into %LOCALAPPDATA%\etw-mcp\sidecar\v<wheel-version>\
```

Two .NET-sidecar strategies are available: `materialized-small` (default, fastest) and `event-store-streaming` (bounded RSS for very large traces). Full build + run docs live in [`dotnet/README.md`](dotnet/README.md); supervisor / debugging notes in [`src/etw_analyzer/native/SIDECAR.md`](src/etw_analyzer/native/SIDECAR.md).

#### Forcing re-extraction across modes

All three pipelines write the same cache layout, so reloads can short-circuit even if you switch modes. Use `force=True` on `load_trace` when you need to re-extract with the selected mode (e.g. after rebuilding the .NET sidecar with a new event class).

### Parallel Analysis

The server supports multiple loaded traces in one MCP server process when callers pass `trace_id` explicitly. Each analysis tool resolves data from the requested trace ID instead of using shared "current trace" state, so parallel agents can safely analyze different ETLs at the same time.

## Architecture

```
AI Assistant ←stdio→ etw-mcp (Python)
                         │
                         ├── .NET sidecar (preferred when configured, mode="dotnet" or auto)
                         │   ├── etw-extract.exe — self-contained .NET binary (~38 MB)
                         │   ├── Decodes Layer-1 events to per-class parquets
                         │   ├── JSONL heartbeat/progress over stdout
                         │   └── Python supervisor runs Layer-3 aggregators
                         │
                         ├── Native consumer (default when no sidecar configured, mode="auto" or "native")
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
                         │   Schema v3 manifest records producer ∈ {dotnet, native, xperf}.
                         │   Shared across all three modes — load once, reuse anywhere.
                         │
                         ├── pandas (aggregation + filtering)
                         └── FastMCP (stdio transport)
```

For end-to-end dataflow across the MCP ecosystem (analyzer + sidecar), see [ARCHITECTURE.md](ARCHITECTURE.md).

### Performance

- **First load (dotnet sidecar):** ~13s on a 1.1 GB ETL (256 K events/sec). Subprocess overhead is paid once, Python stays free of the event buffer.
- **First load (native, default when no sidecar):** 5-30s for typical traces. Single in-process pass — no subprocess overhead.
- **First load (xperf fallback):** 30-180s (9 xperf actions run in parallel with 4 workers)
- **Subsequent loads:** Instant (reads from parquet cache, regardless of mode)
- **Per-CPU queries:** First query parses all SampledProfile events, subsequent queries filter in-memory (<1s)
- **Trace comparison:** Uses cache from both traces — instant if both were previously loaded

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

### Kernel symbol resolution

Starting in v0.7.0, etw-mcp resolves kernel-mode symbols (ntoskrnl.exe, tcpip.sys, afd.sys,
driver stack frames, etc.) correctly from cross-machine traces. Previously, the symbolizer
read the local analyst box's kernel image to derive the PDB GUID, which produced wrong
symbols on any machine that didn't match the trace host (bogus ntoskrnl entries such as
`MmCopyMemory`, `strncpy`, and `FsRtlAreNamesEqual`). Now the sidecar and native consumer
capture the exact PDB identity (GUID, age, name) from each image's `DbgID_RSDS` rundown
record embedded in the ETL, and the symbolizer loads PDBs by that exact identity via
`SymFindFileInPathW`. The result is correct PDB-resolved function names for all kernel
modules regardless of the analyst machine's installed OS version.

**MSFZ PDB format requirement.** Internal and lab symbol servers (including Microsoft's
internal `symweb`) distribute kernel/driver PDBs in MSFZ (compressed) format. The system
`dbghelp.dll` (v10.0.26100, shipped with Windows) cannot load MSFZ PDBs and silently falls
back to PE export-table symbols. etw-mcp automatically prefers the WinDbg "Debugging Tools
for Windows" `dbghelp.dll` at `C:\Debuggers\dbghelp.dll` (v10.0.29507 or later) over the
system one when it is present. Install WinDbg Preview from the Microsoft Store, or the
standalone Debugging Tools for Windows from the Windows ADK, to enable MSFZ support.

Public Microsoft symbol server (`msdl.microsoft.com`) PDBs use standard MSF7 format and
work correctly with the system `dbghelp.dll`. Only internal/lab PDB stores require the
upgraded dbghelp.

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the project structure, how to run tests, and how maintainers publish releases. Please [open an issue](https://github.com/nijosmsft/etw-mcp/issues) first to discuss what you'd like to change.

## License

[MIT](LICENSE)
