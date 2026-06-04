# Contributing

Contributions welcome. Please [open an issue](https://github.com/nijosmsft/etw-mcp/issues) first to discuss what you'd like to change. Pull requests should be focused on a single concern and pass `uv run --group dev pytest tests/ -v` locally before review.

All commits must include a `Signed-off-by:` trailer (use `git commit -s` or add the trailer manually).

## Project Structure

```
etw-mcp/
├── pyproject.toml
├── README.md                        ← end-user docs (install, config, tool list)
├── CHANGELOG.md                     ← release notes + naming history
├── CONTRIBUTING.md                  ← this file
├── ARCHITECTURE.md                  ← cross-repo dataflow + failure modes
├── GETTING-STARTED.md               ← 30-minute onboarding
├── CLAUDE.md                        ← AI-assistant operating notes
├── LICENSE
├── dotnet/                          ← .NET sidecar (etw-extract.exe)
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
    │   ├── context_switch.py       ← get_lock_contention
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

## Running Tests

```powershell
uv run --group dev pytest tests/ -v
```

Default tests use synthetic data and don't require `xperf.exe` or ETL trace files. Gated fixture tests can generate ETLs and independent expected data when explicitly enabled; fixture generation requires Windows Performance Toolkit (`xperf.exe` / `wpr.exe`) and `pktmon.exe`, and may require elevation depending on local policy:

```powershell
uv run --group dev pytest tests\test_fixture_golden.py --run-fixture --run-golden --generate-fixture-etls -q
```

## Publishing a Release

Maintainers can publish release wheels from GitHub Actions:

1. Open **Actions** → **Manual release**.
2. Run the workflow with a tag matching `pyproject.toml`, for example `v0.6.0`.
3. The workflow validates the version, runs tests, builds wheel/sdist artifacts, and uploads them to the GitHub Release.
