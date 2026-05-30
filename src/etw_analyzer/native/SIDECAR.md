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

## Known limitations

* **`mtime_ns` encoding** — the C# emitter writes
  `LastWriteTimeUtc.Ticks * 100` (.NET ns since year 0001) while Python's
  `st_mtime_ns` is ns since the Unix epoch. The two will never match.
  Until the sidecar is fixed, `EtlIdentity.matches_loose()` is used for
  `producer='csharp'` manifests — identity check is `name + size`, not
  `name + size + mtime_ns`. Same-size in-place ETL edits will not
  invalidate the cache. Accepted POC trade-off; tracked for v0.2.0 of
  the sidecar.

* **Streaming RSS not yet budget-compliant** — the sidecar buffers per-class
  rows in memory before chunked-writing. Real-fixture run: 4 GB RSS for
  `event-store-streaming`. The 1 GB target needs source-side bounded
  channels in the sidecar (see `csharp/README.md`).

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
