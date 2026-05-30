# Manual smoke test — C# sidecar end-to-end against real fixture

This is the human-operator playbook for verifying that `mode="dotnet"`
extracts a real ETL through the C# sidecar, runs the Python aggregators,
promotes the cache, and reloads it on a second invocation. The
automated coverage of the same path lives in
`tests/native/test_cross_producer_cache.py::test_dotnet_e2e_against_real_fixture_rehydrates_from_cache`;
this doc captures the wall-clock numbers and CLI-level invocations a
reviewer can re-execute to validate a release candidate.

## Pre-requisites

1. **Sidecar binary published.** From the repo root:

   ```powershell
   cd dotnet
   dotnet publish -c Release -r win-x64 --self-contained
   Test-Path .\publish\win-x64\wpr-mcp-extract.exe   # → True
   ```

2. **Real fixture present** at the canonical staging-poc location:

   ```powershell
   Test-Path C:\git\wpr-mcp-poc-staging\real-fixture\spike-fixture.etl   # → True
   ```

   Fixture: **1068 MB** (≈ 1.05 GiB) of mixed kernel + user-mode traffic.

3. **Python env synced**:

   ```powershell
   cd C:\git\wpr-mcp-server-dotnet-sidecar
   uv sync --group dev   # builds the venv if it isn't already
   ```

## Run the smoke

```powershell
cd C:\git\wpr-mcp-server-dotnet-sidecar

$env:WPR_MCP_DOTNET_SIDECAR = `
    "C:\git\wpr-mcp-server-dotnet-sidecar\dotnet\publish\win-x64\wpr-mcp-extract.exe"
$env:WPR_MCP_MODE             = "dotnet"
$env:WPR_MCP_NATIVE_ALLOW_LARGE = "1"   # required because fixture > 512 MB native limit

# Clean any stale output so timings are meaningful.
Remove-Item -Recurse -Force C:\Temp\etw-export-dotnet-smoke -ErrorAction SilentlyContinue

uv run python tests\manual\_smoke_dotnet.py
```

## Expected output (validated 2026-05-29, branch `feature/dotnet-sidecar`)

```
SIDECAR_PATH=C:\git\wpr-mcp-server-dotnet-sidecar\dotnet\publish\win-x64\wpr-mcp-extract.exe
ETL_SIZE_MB=1068.0
OK=True
MSG=dotnet sidecar completed: aggregation completed: 1 aggregator parquets written, 31 datasets in manifest
WALL_E2E_S=25.3
SIDECAR_WALL_S=19.648
SIDECAR_EPS=163720
SIDECAR_PEAK_RSS_MB=2287.4
EVENT_SAMPLED=55652
EVENT_CSWITCH=2100633
MANIFEST_PRODUCER=dotnet
MANIFEST_SCHEMA=3
MANIFEST_DATASETS=31
MANIFEST_DATASET_NAMES=afd_accept,afd_bind,afd_close,afd_connect,afd_recv,afd_send,cpu_sampling,cswitch_events,http_close,http_deliver,http_recv,http_send,ndis_drops,packet_capture,quic_ack_recv,quic_conn_closed,quic_conn_created,quic_packet_recv,quic_packet_send,readythread,sampled_profile,sysconfig,tcpip_accept,tcpip_connect,tcpip_disconnect,tcpip_recv,tcpip_retransmit,tcpip_send,tracelogging_events,udp_recv,udp_send
```

Pass criteria:

* `OK=True`
* `MANIFEST_PRODUCER=dotnet` and `MANIFEST_SCHEMA=3`
* `cpu_sampling` appears in the manifest dataset list (proves the Python
  aggregator ran post-sidecar)
* `WALL_E2E_S < 60` (sidecar + aggregation; sub-25s on the lab box)
* `EVENT_SAMPLED` and `EVENT_CSWITCH` are non-zero

## Cross-mode trace_id stability check

The `trace_id` for a given ETL is a SHA-256 of `(lowercase path | size |
mtime_ns)`. **All three modes must produce the same id** so a cache
written by one is rehydratable by another.

```powershell
uv run python -c "from etw_analyzer.trace_state import make_trace_id; from pathlib import Path; print(make_trace_id(Path(r'C:\git\wpr-mcp-poc-staging\real-fixture\spike-fixture.etl')))"
```

Expected: `trace_0dd889e969b0` (lab box; the value depends on the
fixture's mtime — what matters is that the same id is reported across
modes, not the specific hex).

## Cross-mode parity (optional — slow)

To verify dotnet and native produce the same `cpu_sampling` row count:

```powershell
# dotnet mode (already ran above) — record the row count
uv run python -c "import pandas as pd; print('dotnet_rows=', len(pd.read_parquet(r'C:\Temp\etw-export-dotnet-smoke\cpu_sampling.parquet')))"

# native mode — clean re-extract via the legacy in-process path
Remove-Item Env:WPR_MCP_DOTNET_SIDECAR -ErrorAction SilentlyContinue
$env:WPR_MCP_MODE = "native"
Remove-Item -Recurse -Force C:\Temp\etw-export-native-smoke -ErrorAction SilentlyContinue
# (no automated harness for this yet — invoke load_trace via the MCP server
# or write a one-off harness like _smoke_dotnet.py)
```

The dotnet + native cpu_sampling row counts should match within the
aggregator's tolerance (sometimes ±1 row due to symbolicate-on-missing-PID
behaviour).

## Wall-clock budget reference

| Phase                       | Lab time | Notes                                                                                  |
| --------------------------- | -------- | -------------------------------------------------------------------------------------- |
| Python startup + import     | ~2 s     | Dominated by FastMCP + pandas import (avoidable with persistent server)                |
| Sidecar (`SIDECAR_WALL_S`)  | ~20 s    | 164 K eps × 8 event classes on the 1 GB fixture                                        |
| Aggregation worker          | ~3 s     | cpu_sampling synthesis + manifest rewrite. Most aggregators no-op with this event set. |
| Atomic promotion (rename)   | < 1 s    |                                                                                        |
| **Total (`WALL_E2E_S`)**    | ~25 s    |                                                                                        |

The post-P1b streaming sidecar typically reports `SIDECAR_PEAK_RSS_MB`
in the 2 000–2 400 MB range on this fixture. The number is recorded
for trend tracking; the parity test
(`tests/native/test_dotnet_native_parity.py --run-parity`) is what
enforces the 2 500 MB ceiling. See `SIDECAR.md` "RSS profile" for
strategy comparison and the residual-headroom breakdown.

## Known issues / caveats

1. **Symbol resolution is Python-side.** The sidecar emits `Image/Load`
   + `Image/DCStart` rows but does not symbolicate. After cache promote,
   `etw_analyzer.native.symbolizer` runs in-process. If symbols are slow
   or missing, that's a Python-path issue, not a sidecar issue.
