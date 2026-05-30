# C# Parity Phase A — Smoke Test Runbook

Manual end-to-end validation that `mode="csharp"` produces ≥ 9 `raw_csv`
keys after the Phase A adapter + aggregator hooks land.

## Prerequisites

* The C# sidecar binary is built and lives at
  `C:\git\wpr-mcp-server-csharp-sidecar\csharp\publish\win-x64\wpr-mcp-extract.exe`.
* The test fixture ETL at
  `C:\git\wpr-mcp-poc-staging\cross-mode-smoke\csharp-mode\spike-fixture.etl`
  still exists (it is the same fixture used by the cross-mode smoke).
* `uv` and the project dependencies are installed.

## Procedure

```powershell
cd C:\git\wpr-mcp-server-csharp-sidecar

# Point the auto-detect at the sidecar binary and force csharp mode.
$env:WPR_MCP_CSHARP_SIDECAR = "C:\git\wpr-mcp-server-csharp-sidecar\csharp\publish\win-x64\wpr-mcp-extract.exe"
$env:WPR_MCP_MODE = "csharp"
$env:WPR_MCP_NATIVE_ALLOW_LARGE = "1"

# Force re-extract so the new Phase A aggregators actually run.
Remove-Item -Recurse -Force C:\git\wpr-mcp-poc-staging\cross-mode-smoke\csharp-mode\.etw-export-spike-fixture\

# Drive load_trace via a small snippet and dump the resulting raw_csv keys.
uv run python -c @"
import time
from etw_analyzer.tools import trace_mgmt
from etw_analyzer.trace_state import _traces
etl = r'C:\git\wpr-mcp-poc-staging\cross-mode-smoke\csharp-mode\spike-fixture.etl'
t0 = time.monotonic()
md = trace_mgmt.load_trace(etl)
elapsed = time.monotonic() - t0
print(f'wall time: {elapsed:.1f}s')
trace = next(iter(_traces.values()))
keys = sorted(trace.raw_csv.keys())
print(f'raw_csv keys ({len(keys)}):')
for k in keys:
    print(f'  {k}')
"@
```

## Expected output

`raw_csv` should contain **≥ 9 keys** including:

- `cpu_sampling`  (Phase pre-A — synthesised from sampled_profile)
- `cpu_timeline`  (Phase A — `aggregate_cpu_timeline` against sidecar dumper_df)
- `stacks`        (Phase A — when a symbolizer is available; absent otherwise — see Phase B note below)
- `stacks_callers`(Phase A — same caveat as `stacks`)
- `sysconfig`     (Phase A — passthrough or native-synthesized)
- `trace_metadata`(Phase A — synthesised from sidecar QPC range + manifest)
- `tracestats`    (Phase A — synthesised from manifest dataset row_counts)
- `ReadyThread`   (Phase A passthrough — empty on this fixture)
- One or more sidecar passthroughs (`CSwitch`, `SampledProfile`, …)

If `stacks` / `stacks_callers` are missing, the sidecar did not provide
Image/Load events (a known Phase B follow-up); the run is still
considered successful when the remaining Phase A keys are present.

## What's NOT covered by Phase A

Per `manager-log/csharp-parity-exploration.md` §4, Phase A intentionally
defers any aggregator that needs new sidecar event classes:

- `dpc_isr` / `dpc_isr_raw` — needs `PerfInfo/{DPC,ThreadedDPC,TimerDPC,ISR}`
- `process_info`            — needs `Process/{Start,End,DCStart,DCEnd,Defunct}`
- `diskio`                  — needs `DiskIo/{Read,Write,FlushBuffers}`
- Real `stacks` / `stacks_callers` — needs `Image/Load` + `Image/DCStart`
- `EventTrace/Header` raw   — needs sidecar header rundown

These unlock incrementally as the sidecar gains event-class support.
