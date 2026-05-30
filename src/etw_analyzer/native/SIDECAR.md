# C# sidecar — developer notes

The `wpr-mcp-extract.exe` sidecar is Track B of the hybrid migration plan
(see `rust-hybrid-migration-plan.md` §4 and `spike-contract.md`). It is a
self-contained Windows .NET binary that decodes ETW Layer-1 events from an
`.etl` and writes per-class parquets + a v3 cache manifest into a staging
directory. The Python supervisor (`worker_supervisor.py`) spawns it, the
aggregation worker (`aggregation_worker.py`) runs Layer-3 aggregators
against the staging outputs, and the result is atomically promoted into
the final cache directory.

## When each mode wins

| Mode      | Wins when…                                                                  |
| --------- | --------------------------------------------------------------------------- |
| `csharp`  | `WPR_MCP_CSHARP_SIDECAR` env var is set OR `wpr-mcp-extract.exe` is on PATH |
| `native`  | The in-process `OpenTraceW` consumer loads (Windows Server / recent client) |
| `xperf`   | Anywhere else, or as the explicit `mode="xperf"` opt-out                    |

The `auto` chain is `csharp → native → xperf`. The in-tree publish path
(`csharp/publish/win-x64/wpr-mcp-extract.exe`) is **intentionally skipped**
by the auto detector so a dev workstation with a published build doesn't
silently switch its default pipeline. Explicit `mode="csharp"` *does*
include the in-tree path — that's the convenience hook for development.

## Installing / locating the binary

1. **Build it once** (from the repo root, in a shell that has the .NET SDK
   on PATH):

   ```powershell
   cd csharp
   dotnet publish -c Release -r win-x64 --self-contained
   # → csharp/publish/win-x64/wpr-mcp-extract.exe  (~38 MB)
   ```

2. **Pin the path** for production use:

   ```powershell
   $env:WPR_MCP_CSHARP_SIDECAR = "C:\install\wpr-mcp-extract.exe"
   $env:WPR_MCP_MODE = "csharp"        # force, or leave at auto
   ```

3. **Verify** with the `find_csharp_sidecar` helper:

   ```python
   from etw_analyzer.native.config import find_csharp_sidecar
   print(find_csharp_sidecar())   # → Path | None
   ```

## How the load path runs

```
load_trace(etl_path)              # default mode="auto"
  ↓ config.resolve_mode → "csharp" when WPR_MCP_CSHARP_SIDECAR set
  ↓ trace_mgmt invokes worker_supervisor.run_csharp_worker_extraction
  ↓
  ├─ build request.json (spike-contract §3 schema)
  ├─ spawn wpr-mcp-extract.exe --request <path>
  ├─ stream stdout JSONL (heartbeat / progress / result)
  ├─ validate sidecar manifest (mode='native', producer='csharp')
  ├─ run aggregation_worker.run_aggregation_worker(staging_dir, …)
  │    ↓ hydrate TraceData from sidecar parquets
  │    ↓ trace_mgmt._run_native_aggregators(trace)  ← Layer-3 outputs
  │    ↓ rewrite manifest in place with aggregator parquets added
  └─ atomic promote staging_dir → export_dir
```

The supervisor never blocks on the aggregator — they run sequentially in
the parent process, AFTER the sidecar exits.

## Debugging a stuck supervisor

If `load_trace` hangs or returns a `failure_kind` you don't understand,
walk the PID tree + JSONL trail + staging contents:

### 1. Find the sidecar PID

```powershell
Get-CimInstance Win32_Process -Filter "Name='wpr-mcp-extract.exe'" |
    Select-Object ProcessId, ParentProcessId, CommandLine
```

The `CommandLine` will name the request file (`--request <path>`); its
directory is the staging dir.

### 2. Inspect the request

```powershell
Get-Content "C:\…\.etw-export-X.csharp-trace_Y-Z\request.json"
```

Verify `etl_path` resolves, `staging_dir` is writable, `strategy` matches
expectations, and `requested_event_classes` is non-empty.

### 3. Tail the JSONL stdout

The supervisor captures the last 16 KiB of stdout in
`NativeWorkerResult.stdout_tail`. If you're debugging interactively,
re-run the sidecar by hand to see live output:

```powershell
& "C:\install\wpr-mcp-extract.exe" --request "<path-to-request.json>"
```

Every stdout line is `{"type": "heartbeat"|"progress"|"result", "time": …}`.
Stderr carries plain log lines. The `result` record is the source of
truth — exit code is a fallback signal per spike-contract §2.3.

### 4. Inspect the staging dir

On failure the staging dir is preserved (per spike-contract §11 phase 0).
Expect:

```
.etw-export-X.csharp-trace_Y-Z/
├─ request.json                      ← what the supervisor wrote
├─ wpr-mcp-cache-manifest.json       ← v3 manifest; producer="csharp"
├─ sampled_profile.parquet
├─ cswitch_events.parquet
├─ … one parquet per requested event class …
├─ sysconfig.txt
└─ (after aggregation_worker ran) cpu_sampling.parquet, dpc_isr.parquet, etc.
```

If the manifest is missing the sidecar crashed mid-write. If aggregator
parquets are missing the post-processing failed; check the supervisor
result's `failure_kind` (`"aggregation"` vs `"invalid-cache"` vs
`"promotion"`) to localize.

### 5. Force-recover

To re-run from scratch:

```powershell
Remove-Item -Recurse -Force "C:\…\.etw-export-X*"
```

then re-invoke `load_trace(…, force=True)`.

## RSS profile

Streaming refactor (P1b) bounds per-class row buffers via
`System.Threading.Channels<T>` with backpressure, then rotates Parquet
chunks at fixed intervals. Measured peak RSS on the 1 GB real fixture
(3.2 M events, dual Xeon Silver 4316):

| Strategy                  | Peak RSS | Notes                                                         |
| ------------------------- | -------- | ------------------------------------------------------------- |
| `event-store-materialized`| ~5 GB    | Pre-streaming behaviour. Whole-trace per-class buffer.        |
| `event-store-streaming`   | ~2.3 GB  | Post-P1b. Bounded channels + chunk rotation.                  |
| Theoretical floor         | ~1 GB    | One in-flight chunk per class × ~30 classes × ~30 MB buffers. |

The ~1.3 GB residual above the theoretical floor is dominated by
Parquet column-buffer headroom during chunk rotation — each class
holds *two* buffers briefly (the rotating-out chunk being flushed +
the new chunk accepting rows) and Parquet's column writers don't free
their compression scratch until the row group is committed. This is
acceptable headroom; chasing it lower would require a custom
column-buffer pool in the sidecar and is not on the P2 plan.

Enforcement:

* `tests/native/test_csharp_native_parity.py` (`pytest --run-parity`)
  asserts the **Python process** stays below 2 500 MB peak RSS during
  the csharp load. That's a proxy for the sidecar's own working set
  staying bounded, since a runaway sidecar would force Python to pull
  oversized parquet chunks into memory at aggregation time.
* `tests/manual/test_csharp_e2e_smoke.md` records
  `SIDECAR_PEAK_RSS_MB` from the sidecar's terminal `result` JSONL
  line (its own self-report). The runbook shows the expected value
  band but does not gate on it — the parity test is the gate.

## Known limitations

* **Symbol resolution stays Python-side** — the sidecar emits `Image/Load`
  + `Image/DCStart` events but does not symbolicate. The symbolizer lives
  in `etw_analyzer.native.symbolizer` and runs after the cache promotes.

## Source layout

| File                                                       | Purpose                                              |
| ---------------------------------------------------------- | ---------------------------------------------------- |
| `src/etw_analyzer/native/config.py`                        | `find_csharp_sidecar`, `resolve_mode` (csharp peer)  |
| `src/etw_analyzer/native/worker_supervisor.py`             | `run_csharp_worker_extraction`, `run_csharp_process` |
| `src/etw_analyzer/native/aggregation_worker.py`            | Layer-3 aggregator runner against sidecar staging    |
| `src/etw_analyzer/native/cache.py`                         | Manifest v3 reader/writer + `producer` field         |
| `csharp/src/Program.cs`                                    | Sidecar entry — CLI parsing + dispatch               |
| `csharp/src/Request.cs`                                    | Request DTO + validation                             |
| `csharp/src/JsonlEmitter.cs`                               | Thread-safe stdout JSONL writer                      |
| `csharp/src/ManifestEmitter.cs`                            | v3 manifest writer (sidecar side)                    |
