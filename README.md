# WPR Trace Analyzer MCP Server

An [MCP](https://modelcontextprotocol.io/) server that lets AI coding assistants analyze Windows WPR/ETW traces (`.etl` files). Load a trace, then ask questions in natural language — the server uses a fast in-process ETW path by default, can offload extraction to a self-contained .NET sidecar when one is configured, and falls back to `xperf.exe` for full WPA-style coverage.

> New here? Start with [GETTING-STARTED.md](GETTING-STARTED.md) for a 30-minute clone-to-first-query walkthrough, then [ARCHITECTURE.md](ARCHITECTURE.md) for the cross-repo dataflow.

Works with any Windows performance trace: networking (tcpip.sys, NDIS, NIC drivers, HTTP.sys), kernel (DPCs, ISRs, context switches), and application workloads.

### Quick Install

> **The snippet below is hard-coded to v0.2.0.** For the latest version, grab the URLs from <https://github.com/nijosmsft/wpr-mcp-server/releases/latest> and substitute them in.

Copy-paste this into Claude Code, Copilot, or any AI assistant to install automatically.

```
Install the WPR trace analyzer MCP server on this Windows machine:

1. Install uv (skip if `uv --version` already works):
     winget install astral-sh.uv
   Note: uv will download a private CPython interpreter on the first `uv run` — benign but expected.

2. Install xperf (skip if "C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe" exists):
     winget install --id Microsoft.WindowsADK --override "/features OptionId.WindowsPerformanceToolkit /quiet"
   The Windows Performance Toolkit is a ~150 MB feature of the Windows ADK; do NOT use `Microsoft.WindowsSDK` — it is not a valid winget ID.

3. Download the .NET sidecar (38 MB; gives a ~9x faster load_trace than the in-process fallback; no .NET runtime install needed — the binary is self-contained):
     New-Item -ItemType Directory -Force -Path C:\install | Out-Null
     Invoke-WebRequest `
       -Uri https://github.com/nijosmsft/wpr-mcp-server/releases/download/v0.2.0/wpr-mcp-extract.exe `
       -OutFile C:\install\wpr-mcp-extract.exe

4. Add this MCP server config to the file for your client:
     - Claude Code (project):     <repo>\.mcp.json                              top-level key: "mcpServers"
     - Claude Code (user):        %USERPROFILE%\.claude.json                    top-level key: "mcpServers"
     - Claude Desktop:            %APPDATA%\Claude\claude_desktop_config.json   top-level key: "mcpServers"
     - GitHub Copilot CLI:        %USERPROFILE%\.copilot\mcp-config.json        top-level key: "mcpServers"
     - VS Code GitHub Copilot:    <repo>\.vscode\mcp.json  OR  %APPDATA%\Code\User\mcp.json
                                                                                  top-level key: "servers"   <- not "mcpServers"
     - Cursor:                    <repo>\.cursor\mcp.json  OR  %USERPROFILE%\.cursor\mcp.json
                                                                                  top-level key: "mcpServers"

     {
       "<top-level-key>": {
         "wpr-trace-analyzer": {
           "type": "stdio",
           "command": "uv",
           "args": ["run", "--no-project", "--with",
                    "https://github.com/nijosmsft/wpr-mcp-server/releases/download/v0.2.0/wpr_mcp_server-0.2.0-py3-none-any.whl",
                    "python", "-m", "etw_analyzer.server"],
           "env": {
             "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
             "WPR_MCP_DOTNET_SIDECAR": "C:\\install\\wpr-mcp-extract.exe"
           }
         }
       }
     }

5. Verify the wheel imports cleanly (does NOT hang; exits with "OK"):
     uv run --no-project `
       --with https://github.com/nijosmsft/wpr-mcp-server/releases/download/v0.2.0/wpr_mcp_server-0.2.0-py3-none-any.whl `
       python -c "import etw_analyzer.server; print('OK - wpr-mcp-server v0.2.0 importable')"

Expect the first `load_trace` call to download 200-500 MB of PDBs to C:\symbols (one-time; subsequent loads use the cache).
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
winget install Microsoft.WindowsSDK      # Recommended — provides xperf for fallback and full analysis coverage

# 2. Verify the latest release wheel starts (Ctrl+C to stop)
uv run --no-project --with https://github.com/nijosmsft/wpr-mcp-server/releases/download/<release-tag>/<wheel-file>.whl python -m etw_analyzer.server
```

- **uv** automatically downloads Python, creates a virtual environment, and installs all dependencies on first run. No separate Python install needed.
- **Release wheel** — use the `.whl` asset URL from the latest [GitHub release](https://github.com/nijosmsft/wpr-mcp-server/releases). The examples use `<release-tag>` and `<wheel-file>` placeholders because the URL is only valid after a release is published. Maintainers can publish that asset with the manual **Manual release** GitHub Actions workflow.
- **Native ETW consumer (default when no sidecar is configured)** — the server decodes ETL files in-process via `OpenTraceW`/`tdh.dll`. This path is enough to start the MCP server and run the core native analysis tools on recent Windows builds.
- **.NET sidecar (preferred when configured)** — `wpr-mcp-extract.exe` is a self-contained .NET binary (~38 MB, no .NET install required) that decodes ETL files faster than the in-process path and frees the Python process from holding the full event buffer. The server auto-detects it when `WPR_MCP_DOTNET_SIDECAR` is set or `wpr-mcp-extract.exe` is on PATH. See [`dotnet/README.md`](dotnet/README.md) for build instructions and [`src/etw_analyzer/native/SIDECAR.md`](src/etw_analyzer/native/SIDECAR.md) for the supervisor plumbing.
- **xperf.exe / Windows Performance Toolkit** — installed as part of the Windows SDK. Recommended for complete results because it enables fallback extraction, richer WPA-derived stack views, xperf-only tools such as pool analysis, and older Windows builds where the native bindings can't load. Expected location: `C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe`
- **Evidence federation (optional)** — `uv sync --extra evidence` pulls in the [`wpr-mcp-evidence-store`](../wpr-mcp-evidence-store) library and, when `WPR_MCP_EVIDENCE_PATH` is set, the server writes per-host entity rows (modules, processes, CPU sample summaries) to a shared DuckDB so the [`wpr-mcp-evidence-query`](../wpr-mcp-evidence-query) MCP can correlate ETW evidence with crash dumps from the same host. The feature is silently inert when the extra isn't installed or the env var isn't set.

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
      "args": ["run", "--no-project", "--with", "https://github.com/nijosmsft/wpr-mcp-server/releases/download/<release-tag>/<wheel-file>.whl", "python", "-m", "etw_analyzer.server"],
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
      "args": ["run", "--no-project", "--with", "https://github.com/nijosmsft/wpr-mcp-server/releases/download/<release-tag>/<wheel-file>.whl", "python", "-m", "etw_analyzer.server"],
      "env": {
        "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
      }
    }
  }
}
```

Replace the release URL with the wheel asset from the release you want to run.

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

This server pairs well with [LabLink MCP](https://github.com/nijosmsft/LabLink) when the AI client has both MCP servers configured. LabLink can collect traces from remote Windows machines; wpr-mcp-server analyzes the ETL after LabLink pulls it to the operator machine.

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

For full WPA/butterfly stack parity, load with `mode="xperf"` or set `WPR_MCP_MODE=xperf`. In xperf mode, `get_hot_stacks` uses xperf's butterfly `Functions by UniInclusive Hits` table, so inclusive and exclusive hit counts are kept separate. `walk_stack` and `butterfly_chain` use the butterfly caller/callee table and require the `trace_id` returned by `load_trace`. Native mode covers core stack analysis but may not expose every xperf-derived stack view. `count_stacks` currently works from aggregate butterfly edges, so it estimates matching sample counts rather than counting distinct raw stack instances.

### Trace Loading Modes

`load_trace` accepts a `mode` argument that selects the extraction pipeline. Three modern pipelines coexist, each with the same trace_id and parquet cache layout so a trace extracted in one mode can be reloaded in another. The default `mode="auto"` walks the fallback chain **`.NET sidecar → native → xperf`** and picks the first one available.

The `WPR_MCP_MODE` environment variable overrides the default when `mode=` is left unspecified. The explicit `mode=` arg always wins over the env var.

> **Naming note.** Earlier versions of this server called the sidecar mode `"csharp"` (matching the language of the binary). It was renamed to `"dotnet"` across the API (env vars, `mode=` args, manifest `producer` field, telemetry events, Python symbols) to align with the user-facing `.NET sidecar` label, which more accurately describes the bundled runtime. Stale on-disk caches with `producer="csharp"` no longer validate; pass `force=True` (or delete the `.etw-export-*` directory) once to re-extract under the new producer name. The old `WPR_MCP_CSHARP_SIDECAR` env var is no longer recognized — set `WPR_MCP_DOTNET_SIDECAR` instead.

---

#### .NET sidecar mode — recommended (fast, default-preferred in `auto`)

**What it is.** A self-contained .NET 8 binary (`wpr-mcp-extract.exe`, ~40 MB single-file deploy) that decodes ETW Layer-1 events from an ETL into per-class parquet files. The Python server invokes it as a subprocess, streams its JSONL progress, then runs the same Layer-3 aggregators it would for native mode.

**When to use it.** The default choice for everything. ~9× faster end-to-end than native on a 1 GB ETL (45s vs 429s on the lab fixture), correct TraceLogging decode out of the box, and the cache layout is identical to native mode so you don't lock yourself in.

**How to enable it.**

1. Get the binary. **Either** download the prebuilt asset from the latest [GitHub release](https://github.com/nijosmsft/wpr-mcp-server/releases):

   ```powershell
   Invoke-WebRequest `
     -Uri "https://github.com/nijosmsft/wpr-mcp-server/releases/download/<release-tag>/wpr-mcp-extract.exe" `
     -OutFile "C:\install\wpr-mcp-extract.exe"
   ```

   **Or** build it from source (no .NET runtime required for the resulting binary; only for the build):

   ```powershell
   cd <repo>\dotnet
   dotnet publish -c Release -r win-x64 --self-contained -o publish\win-x64
   ```

2. Point the server at it. Either set `WPR_MCP_DOTNET_SIDECAR` to the absolute path, or drop `wpr-mcp-extract.exe` on `PATH`. Once `WPR_MCP_DOTNET_SIDECAR` is set, `mode="auto"` picks it automatically:

   ```json
   {
     "mcpServers": {
       "wpr-trace-analyzer": {
         "type": "stdio",
         "command": "uv",
         "args": ["run", "--no-project", "--with", "https://github.com/nijosmsft/wpr-mcp-server/releases/download/<release-tag>/<wheel-file>.whl", "python", "-m", "etw_analyzer.server"],
         "env": {
           "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
           "WPR_MCP_DOTNET_SIDECAR": "C:\\install\\wpr-mcp-extract.exe"
         }
       }
     }
   }
   ```

3. Force this mode unconditionally with `WPR_MCP_MODE=dotnet`, or pass `mode="dotnet"` to `load_trace`. With the explicit form, the server raises a `ValueError` (naming the env var) if the binary can't be found instead of silently falling back.

Cache manifests record `producer="dotnet"`. Two strategies are available: `materialized-small` (default, fastest) and `event-store-streaming` (bounded RSS for very large traces). Full build + run docs live in [`dotnet/README.md`](dotnet/README.md); supervisor / debugging notes in [`src/etw_analyzer/native/SIDECAR.md`](src/etw_analyzer/native/SIDECAR.md).

---

#### Native mode — in-process Python consumer

**What it is.** An in-process `OpenTraceW` + `tdh.dll` consumer that decodes ETW events directly in Python via `advapi32`. Decodes manifest providers (TCPIP, AFD, MsQuic, HTTP.sys) that xperf can't enumerate. No subprocess, no separate binary.

**When to use it.** When the .NET sidecar isn't available (no `dotnet publish` access, restricted machine, etc.) but the native consumer bindings load. Best fallback in the `auto` chain.

**How to enable it.**

1. Nothing to install — it's bundled with the Python server. Verify the consumer is available on your host:

   ```powershell
   uv run python -c "from etw_analyzer.native.consumer import is_available; print(is_available())"
   ```

2. Force it with `WPR_MCP_MODE=native` or `mode="native"`. With the explicit form, the server raises if the bindings can't load instead of falling back:

   ```json
   "env": {
     "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
     "WPR_MCP_MODE": "native"
   }
   ```

3. For ETLs larger than the safety guardrail (default 1 GB), also set `WPR_MCP_NATIVE_ALLOW_LARGE=1`. The native pipeline buffers events in pandas DataFrames in-process, so memory grows with trace size.

Cache manifests record `producer="native"`. Same parquet schema as .NET mode, so caches are interchangeable.

---

#### xperf mode — legacy WPA-based extraction

**What it is.** A subprocess pipeline that shells out to `xperf.exe` from the Windows Performance Toolkit, running WPA-style actions (`profile`, `dpcisr`, `stack -butterfly`, `cswitch`, `sysconfig`, `process`, `diskio`, `tracestats`) plus `xperf -a dumper` for raw events.

**When to use it.** When you hit a native-mode bug, need full WPA-style stack coverage, or you're on a machine where WPT is installed but you can't or don't want to run the .NET sidecar.

**How to enable it.**

1. Install the Windows Performance Toolkit (part of the Windows SDK or ADK). The server auto-detects `xperf.exe` at the standard install path:

   ```
   C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe
   ```

   Or put it on `PATH`.

2. Force it with `WPR_MCP_MODE=xperf` or `mode="xperf"`. xperf is also the final fallback in the `auto` chain when neither the .NET sidecar nor the native consumer are available:

   ```json
   "env": {
     "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
     "WPR_MCP_MODE": "xperf"
   }
   ```

xperf mode is the slowest path but the broadest in tool coverage. Cache manifests for legacy xperf runs (pre-v3) may carry no producer field; the loader treats them as `producer="xperf"` on read.

---

#### Forcing re-extraction across modes

All three pipelines write the same cache layout, so reloads can short-circuit even if you switch modes. Use `force=True` on `load_trace` when you need to re-extract with the selected mode (e.g. after rebuilding the .NET sidecar with a new event class).


### Evidence federation (optional)

The server can record per-host entities (modules, processes, CPU sample summaries) into a shared DuckDB so the [`wpr-mcp-evidence-query`](../wpr-mcp-evidence-query) MCP can correlate ETW evidence with crash-dump findings from the same machine. Enable with:

```powershell
uv sync --extra evidence                           # install evidence-store as optional dep
$env:WPR_MCP_EVIDENCE_PATH = "C:\evidence"        # one DuckDB per machine under this root
```

Without the extra installed, or without `WPR_MCP_EVIDENCE_PATH` set, the integration short-circuits — `load_trace` behaves identically to a vanilla install. The library shape and identity contract live in [`wpr-mcp-evidence-store`](../wpr-mcp-evidence-store) (`docs/IDENTITY-SPEC.md`, `docs/PRODUCER-CONTRACT.md`). The read side runs as a separate MCP server, [`wpr-mcp-evidence-query`](../wpr-mcp-evidence-query).

### Parallel Analysis

The server supports multiple loaded traces in one MCP server process when callers pass `trace_id` explicitly. Each analysis tool resolves data from the requested trace ID instead of using shared "current trace" state, so parallel agents can safely analyze different ETLs at the same time.

## Architecture

```
AI Assistant ←stdio→ wpr-mcp-server (Python)
                         │
                         ├── .NET sidecar (preferred when configured, mode="dotnet" or auto)
                         │   ├── wpr-mcp-extract.exe — self-contained .NET binary (~38 MB)
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
                         ├── (optional) evidence-store → DuckDB per machine
                         └── FastMCP (stdio transport)
```

For end-to-end dataflow across the 5-repo MCP ecosystem (analyzer + sidecar + evidence-store + evidence-query + crash-dump-mcp-server), see [ARCHITECTURE.md](ARCHITECTURE.md).

### Performance

- **First load (dotnet sidecar):** ~13s on a 1.1 GB ETL (256 K events/sec). Subprocess overhead is paid once, Python stays free of the event buffer.
- **First load (native, default when no sidecar):** 5-30s for typical traces. Single in-process pass — no subprocess overhead.
- **First load (xperf fallback):** 30-180s (9 xperf actions run in parallel with 4 workers)
- **Subsequent loads:** Instant (reads from parquet cache, regardless of mode)
- **Per-CPU queries:** First query parses all SampledProfile events, subsequent queries filter in-memory (<1s)
- **Trace comparison:** Uses cache from both traces — instant if both were previously loaded

## Project Structure

```
wpr-mcp-server-dotnet-sidecar/
├── pyproject.toml
├── README.md                        ← this file
├── ARCHITECTURE.md                  ← cross-repo dataflow + failure modes
├── GETTING-STARTED.md               ← 30-minute onboarding
├── CLAUDE.md                        ← AI-assistant operating notes
├── LICENSE
├── dotnet/                          ← .NET sidecar (wpr-mcp-extract.exe)
│   ├── README.md                    ← build + run docs for the sidecar
│   ├── src/                         ← .NET 8 source
│   ├── scripts/smoke-test.ps1
│   └── publish/win-x64/             ← dotnet publish output (not checked in)
├── docs/decisions/                  ← promoted decision/review docs
├── tests/                           ← synthetic tests by default; gated fixture tests are opt-in
└── src/etw_analyzer/
    ├── server.py                    ← MCP server entry point
    ├── app.py                       ← FastMCP instance + server instructions
    ├── trace_state.py               ← Loaded trace registry + dumper cache
    ├── native/                      ← in-process consumer + dotnet sidecar plumbing
    │   ├── SIDECAR.md               ← supervisor / debugging notes for the .NET sidecar
    │   ├── worker_supervisor.py     ← spawns the sidecar / native worker
    │   ├── aggregation_worker.py    ← Layer-3 aggregators over staging parquets
    │   └── config.py                ← resolve_mode, find_dotnet_sidecar
    ├── tools/
    │   ├── trace_mgmt.py            ← load_trace, list_traces, list_loaded_traces, check/resolve_symbols
    │   ├── cpu_sampling.py          ← get_cpu_samples, get_hot_functions
    │   ├── per_cpu.py               ← get_per_cpu_summary, get_cpu_timeline
    │   ├── stack_analysis.py        ← get_hot_stacks, get_function_callers
    │   ├── dpc_isr.py               ← get_dpc_summary, get_dpc_per_cpu
    │   ├── context_switch.py        ← get_lock_contention
    │   ├── memory.py                ← get_memory_pools
    │   ├── network_events*.py       ← TCP/UDP/socket/throughput tools
    │   ├── network_lenses.py        ← networking-focused hot functions/stacks/DPCs
    │   ├── network_wait_chain.py    ← network wait-chain analysis
    │   ├── packet_capture.py        ← NDIS PacketCapture and pktmon packet tools
    │   ├── app_layer.py             ← HTTP.sys and MsQuic tools
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

Default tests use synthetic data and don't require `xperf.exe` or ETL trace files. Gated fixture tests can generate ETLs and independent expected data when explicitly enabled; fixture generation requires Windows Performance Toolkit (`xperf.exe`/`wpr.exe`) and `pktmon.exe`, and may require elevation depending on local policy:

```powershell
uv run --group dev pytest tests\test_fixture_golden.py --run-fixture --run-golden --generate-fixture-etls -q
```

### Publishing a Release

Maintainers can publish release wheels from GitHub Actions:

1. Open **Actions** → **Manual release**.
2. Run the workflow with a tag matching `pyproject.toml`, for example `v0.1.0`.
3. The workflow validates the version, runs tests, builds wheel/sdist artifacts, and uploads them to the GitHub Release.

## Contributing

Contributions welcome. Please open an issue first to discuss what you'd like to change.

## License

[MIT](LICENSE)
