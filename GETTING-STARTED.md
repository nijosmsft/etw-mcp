# Getting Started

Clone-to-first-query walkthrough for `wpr-mcp-server-dotnet-sidecar`. Budget
~30 minutes the first time. By the end you will have an MCP server running,
an `.etl` loaded, and answers to the four questions every triage starts with:
*Where did the CPU go? Which DPCs were slow? Which connections were busy? Why
did this function run?*

For the wider picture (sibling repos, evidence federation), read
[`ARCHITECTURE.md`](ARCHITECTURE.md) after the first successful query. For the
full tool catalog, [`README.md`](README.md) is the canonical reference.

---

## 1. Prerequisites

| Tool | Why | How |
|---|---|---|
| Windows 10/11 or Windows Server 2022+ | ETW + dbghelp are Windows-only. WSL does **not** work. | — |
| Python 3.12+ | Runtime for the MCP server. `uv` will fetch this for you on first run. | `winget install astral-sh.uv` (or use existing Python) |
| `uv` | Project + environment manager. The repo is a `pyproject.toml` workspace. | `winget install astral-sh.uv` |
| Windows Performance Toolkit (`xperf.exe`, `wpr.exe`) | Captures ETL files and serves as the fallback extraction backend. Strongly recommended. | `winget install Microsoft.WindowsSDK` — selects the Windows Performance Toolkit feature |
| Symbol cache writable directory | `dbghelp.dll` writes downloaded PDBs here. Pick anywhere with ~5 GB free. | `mkdir C:\symbols` |
| .NET 8 SDK | *Only* needed if you build the .NET sidecar yourself. The native + xperf paths work without it. | `winget install Microsoft.DotNet.SDK.8` |

Verify the toolchain:

```powershell
uv --version                                       # uv 0.x.x
python --version                                   # 3.12.x or newer
where.exe xperf.exe                                # ...\Windows Performance Toolkit\xperf.exe
where.exe wpr.exe                                  # ...\Windows Performance Toolkit\wpr.exe
```

If `where.exe xperf.exe` finds nothing, you can still continue — `mode="native"`
will run on recent Windows builds — but the fallback path and several
xperf-only tools (`get_memory_pools` and the full butterfly stack views) will
fail with actionable errors.

---

## 2. Clone and install

```powershell
git clone https://github.com/nijosmsft/wpr-mcp-server-dotnet-sidecar.git
cd wpr-mcp-server-dotnet-sidecar

# Base install — everything needed to run the MCP server.
uv sync --group dev

# Optional: pull in the evidence-store library so the per-machine DuckDB
# write hook is available. See ARCHITECTURE.md §7.
uv sync --extra evidence
```

`uv sync` creates `.venv/` and pins every dependency from `uv.lock`. The
`--group dev` group adds `pytest` + `pytest-xdist` so you can run the test
suite. The optional `evidence` extra is silently inert until you set
`WPR_MCP_EVIDENCE_PATH`.

Smoke-test the install:

```powershell
uv run --group dev pytest tests/ -q -k "test_smoke or test_app_instructions" -x
```

A passing run takes <10 seconds. If imports fail, re-run
`uv sync --group dev --reinstall`.

### Optional: build the .NET sidecar

The sidecar is the preferred extraction backend when available (see
[`ARCHITECTURE.md`](ARCHITECTURE.md) §3 and §5). Build once:

```powershell
cd dotnet
dotnet publish -c Release -r win-x64 --self-contained -o publish\win-x64
cd ..

# Point the server at the binary you just built. Persist this in your shell
# profile or your MCP client config; the example uses the current session.
$env:WPR_MCP_DOTNET_SIDECAR = "$PWD\dotnet\publish\win-x64\wpr-mcp-extract.exe"
```

The server will now use `dotnet → native → xperf` as its extraction fallback
chain. Leaving `WPR_MCP_DOTNET_SIDECAR` unset is fine — the chain collapses to
`native → xperf`.

---

## 3. Get an ETL

The repo ships a fixture-collection script that captures three small ETLs
straight from `xperf`/`wpr`/`pktmon`. They are designed for the test suite
but work beautifully as first-load demos:

```powershell
# Captures three ~10-50 MB ETLs into tests\fixtures\<name>\<name>.etl
.\scripts\collect_fixture_etl.ps1 -DurationSeconds 5

# Outputs:
#   tests\fixtures\empty-trace\empty-trace.etl              (PROC+LOADER only)
#   tests\fixtures\cpu-only-trace\cpu-only-trace.etl        (CPU sampling, CPU.light profile)
#   tests\fixtures\pktmon-capture-trace\pktmon-capture-trace.etl (packet capture)
```

If you already have a real WPR profile (e.g. one of the `udp-perf` repo's
`.wprp` files), capture with `wpr -start <profile>.wprp -filemode` and
`wpr -stop my-trace.etl` instead. Any standards-compliant ETL works — the
server has no fixture-specific code paths.

There is **no built-in sample ETL** in the repo. Anything bigger than the
fixtures lives in `udp-perf`-style traces or your own captures; we deliberately
do not commit large binaries.

---

## 4. Configure your MCP client

The server is a stdio MCP. Two common clients:

### Claude Desktop / Code

Edit `claude_desktop_config.json` (Windows path:
`%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "etw-trace-analyzer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--project", "C:\\git\\wpr-mcp-server-dotnet-sidecar", "python", "-m", "etw_analyzer.server"],
      "env": {
        "_NT_SYMBOL_PATH": "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols",
        "WPR_MCP_DOTNET_SIDECAR": "C:\\git\\wpr-mcp-server-dotnet-sidecar\\dotnet\\publish\\win-x64\\wpr-mcp-extract.exe"
      }
    }
  }
}
```

`WPR_MCP_DOTNET_SIDECAR` is optional. Omit it and the server falls back to
the native consumer (then xperf).

### VS Code GitHub Copilot

Add to your MCP config (typically `.vscode/mcp.json` or user settings):

```json
{
  "servers": {
    "etw-trace-analyzer": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--project", "C:\\git\\wpr-mcp-server-dotnet-sidecar", "python", "-m", "etw_analyzer.server"]
    }
  }
}
```

Restart the client. You should see the `etw-trace-analyzer` server connect
and ~50 tools become available.

### Sanity check from the terminal

You can also speak MCP by hand to confirm the server starts:

```powershell
uv run python -m etw_analyzer.server   # blocks reading from stdin
# Ctrl+C to exit
```

A clean start prints nothing on stdout — the protocol is on stdin/stdout, and
diagnostic output goes to stderr.

---

## 5. First-load orientation

These five tool calls answer the four headline triage questions on any ETL.
Substitute your own path for the fixture.

```
list_traces directory="C:\\git\\wpr-mcp-server-dotnet-sidecar\\tests\\fixtures\\cpu-only-trace"
load_trace etl_path="C:\\git\\wpr-mcp-server-dotnet-sidecar\\tests\\fixtures\\cpu-only-trace\\cpu-only-trace.etl"
trace_info trace_id="trace_<...>"
get_sysconfig trace_id="trace_<...>"
analyze trace_id="trace_<...>"
```

Expected timing on a 50 MB fixture:

* `load_trace`: 10-30 s first time (decode + parquet write), <1 s on subsequent
  calls (cache hit). The summary it returns names the producer that won
  (`dotnet`, `native`, or `xperf`) and the size of every parquet dataset.
* `trace_info`: instant. Reports duration, CPU count, event counts per dataset.
* `get_sysconfig`: instant. CPU model, NIC, memory, OS build — context for
  every subsequent reading.
* `analyze`: 1-2 s. Hot modules, per-CPU summary, DPC summary, symbol health,
  all in one report.

If a tool returns `Trace <id> not found. Call load_trace first.`, use
`list_loaded_traces` to confirm what is currently loaded. The server has no
"current trace" — every analysis call takes `trace_id` explicitly.

---

## 6. Drill into hot stacks

Once `analyze` points at a hot module:

```
get_hot_functions trace_id="..." modules="ntoskrnl.exe,xdp.sys,tcpip.sys"
get_hot_stacks trace_id="..." module_filter="xdp.sys" min_weight_pct=2.0
butterfly_chain trace_id="..." target_function="XdpCpuMapDrainDpc" direction="callers" max_depth=8
```

`get_hot_functions` is a flat top-N. `get_hot_stacks` adds caller/callee
context. `butterfly_chain` is a WPA-style walk — it tells you not just *what
ran* but *why*. Default modes give percentage estimates against the trace
denominator; pass `denominator="active_cpus"` if you want CPU-relative numbers.

---

## 7. Drill into network behaviour

The network helpers are convenience wrappers around the generic tools, scoped
to the curated networking module set (`tcpip.sys`, `ndis.sys`, `xdp.sys`,
`afd.sys`, NIC drivers, `ws2_32.dll`, `msquic.dll`...). They keep you from
having to remember every kernel binary name:

```
get_per_process_socket_throughput trace_id="..."
get_network_hot_functions trace_id="..."
get_network_dpcs trace_id="..."
get_udp_flow_summary trace_id="..."
get_packet_capture_summary trace_id="..."          # only useful with pktmon ETLs
get_packet_timeline trace_id="..." five_tuple="10.0.0.1:5000 -> 10.0.0.2:6000/udp"
```

For TCP, swap in `get_connection_summary` and `get_tcp_retransmits`. For QUIC,
`get_quic_connections` and `get_quic_cid_distribution` (the CID-hash bucket
view is the headline tool for validating XDP CPUMAP cpuredirect).

---

## 8. Symbols

`get_sysconfig`, `get_hot_functions`, and `get_hot_stacks` are dramatically
more useful with symbols. If function names show up as
`ntoskrnl.exe+0x1234`, `dbghelp` could not find a matching PDB.

```powershell
# Set once for the MCP client process. Persist in your shell profile or MCP env.
$env:_NT_SYMBOL_PATH = "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"

# Then from the MCP client:
#   check_symbols trace_id="..."          ← reports missing PDBs by module
#   resolve_symbols trace_id="..."        ← forces dbghelp re-download
```

Symbolization is Python-side (`etw_analyzer.native.symbolizer`) regardless of
which extraction producer ran. Both the dotnet sidecar and the native consumer
hand event records to the same symbolizer — there is no per-producer symbol
configuration.

---

## 9. Cache and re-loads

The first `load_trace` decodes the ETL into
`<etl-parent>\.etw-export-<etl-stem>\` (parquet datasets + a JSON manifest at
schema v3). Every subsequent `load_trace` against the same ETL rehydrates
from the cache in <1 second. The cache is shared across the three extraction
backends — a trace decoded with the .NET sidecar can be reloaded under `mode="xperf"`
without re-decoding, because the on-disk shape is identical (see
[`ARCHITECTURE.md`](ARCHITECTURE.md) §5).

If `load_trace` returns a cache-schema error, pass `force=True` to rebuild:

```
load_trace etl_path="...\\my.etl" force=True
```

To invalidate manually, delete `<etl-parent>\.etw-export-<etl-stem>\`.

---

## 10. Where to go next

* **Tool catalog and full mode-table** — [`README.md`](README.md).
* **How the pieces fit (sidecar, evidence federation, sibling MCPs)** —
  [`ARCHITECTURE.md`](ARCHITECTURE.md).
* **AI-assistant operating notes (canonical trace lifecycle narrative)** —
  [`CLAUDE.md`](CLAUDE.md).
* **.NET sidecar build/run/troubleshoot** — [`dotnet/README.md`](dotnet/README.md)
  and [`src/etw_analyzer/native/SIDECAR.md`](src/etw_analyzer/native/SIDECAR.md).
* **Evidence federation** — install with `uv sync --extra evidence`, set
  `WPR_MCP_EVIDENCE_PATH=C:\evidence`, then load any trace; rows appear at
  `C:\evidence\<machine_id>\evidence.duckdb`. The reader MCP is
  [`wpr-mcp-evidence-query`](../wpr-mcp-evidence-query).
* **Trouble?** [`ARCHITECTURE.md`](ARCHITECTURE.md) §8 lists the six common
  failure modes with exact error text and the fix for each. The error messages
  the tools themselves return are written in the same "what next" style, so
  the response usually tells you the next command to run.

---

## Troubleshooting quick reference

| Symptom | Likely fix |
|---|---|
| `xperf.exe not found` | Install Windows Performance Toolkit (Windows SDK), or set `mode="native"` if your build supports the in-process consumer, or build the sidecar and set `WPR_MCP_DOTNET_SIDECAR`. |
| `mode='dotnet' requested but wpr-mcp-extract.exe was not found` | Build the sidecar (`cd dotnet; dotnet publish -c Release -r win-x64 --self-contained`) and set `WPR_MCP_DOTNET_SIDECAR` to the published exe path. |
| Functions show up as `module+0x...` | `_NT_SYMBOL_PATH` is unset or the symbol cache is unwritable. Set the env var, call `resolve_symbols`. |
| `Trace ... not found. Call load_trace first.` | The trace was unloaded or the client lost state. Call `list_loaded_traces`, then `load_trace` again. The cache should make this fast. |
| `another process is writing to .etw-export-...` | A prior load was killed. Delete the `.etw-export-<stem>\` directory next to the ETL and retry. |
| `invalid-cache: cache manifest schema_version=2` | Re-run with `force=True` to rebuild from the ETL. |

If something else breaks, capture the exact error text — the server's error
messages name the next command to run. If that doesn't get you unstuck,
[`ARCHITECTURE.md`](ARCHITECTURE.md) §8 has worked examples for every common
failure mode.
