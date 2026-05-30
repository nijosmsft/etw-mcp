# C# spike — `wpr-mcp-extract.exe`

Sidecar binary that decodes Windows ETL traces into Layer-1 parquets per
[spike-contract.md](../docs/spike-contract.md). Half of the Rust vs C#
language decision spike.

## Build

```powershell
cd csharp-spike
dotnet publish -c Release -r win-x64 -o publish\win-x64
# → publish\win-x64\wpr-mcp-extract.exe  (self-contained single-file, ~38 MB)
```

`net8.0` LTS. Self-contained single-file deploy (not NativeAOT — the
TraceEvent library's trim-compat is unverified for AOT). No runtime
install required on the target machine.

## Run

```powershell
wpr-mcp-extract.exe --request <path-to-request.json>
```

Stdout is reserved for the JSONL protocol (heartbeat / progress / result).
Stderr carries human-readable logs. See contract §4-§5.

## Scope (phase 0)

Decodes 8 event classes:

| Class | Source |
|---|---|
| SampledProfile | kernel MOF (PerfInfo opcode 46) |
| StackWalk | kernel MOF — paired into Stack columns, not its own output |
| CSwitch | kernel MOF (Thread opcode 36) |
| ReadyThread | kernel MOF (Thread opcode 50) |
| TcpIp/Recv | kernel MOF (TcpIp) + Microsoft-Windows-TCPIP manifest |
| AFD/Recv | Microsoft-Windows-Winsock-AFD manifest (via RegisteredTraceEventParser) |
| NdisDrop | Microsoft-Windows-NDIS / NDIS-PacketCapture |
| SystemConfig | kernel MOF — written as `sysconfig.txt` |

Stack pairing uses a 1024-entry FIFO buffer keyed by
`(TimeStampQpc, ThreadID)` per contract §10.

## Architecture

```
Program.cs            ── --request parse, top-level try/catch → result JSONL
  ↓
Request.cs            ── deserialize + validate
  ↓
ExtractRunner.cs      ── ETWTraceEventSource.Process()
  │                     • kernel handlers (typed) → row buffers
  │                     • tcpipManifest/ndisCapture/registered/dynamic .All
  │                       (manifest providers — RegisteredTraceEventParser
  │                       covers AFD via system TDH manifest)
  │                     • StackWalk handler → pair into pending buffer
  │                     • every callback body in Wrap(try/catch) — panic_probe
  │                       exception escapes to abort cleanly
  ↓
EventCollector.cs     ── row buffers + PendingStackBuffer (1024 capacity)
  ↓
ParquetEmitter.cs     ── lower-level Parquet.Net writer
                         (controls list-inner field name = "item" to match
                          pyarrow's canonical type repr)
ManifestEmitter.cs    ── wpr-mcp-cache-manifest.json (producer="csharp")
SysconfigCollector.cs ── sysconfig.txt (CPU / NIC / Disk / OS lines)
```

## Validation

Smoke-tested against `real-fixture/spike-fixture.etl` (1.1 GB, 6.5 s,
Server 2025, 80 CPUs). Results from the harness in `../spike-results/`:

| Metric | Value |
|---|---|
| Wall time | 12.7 s |
| Events/sec | 252,532 |
| Peak RSS | 5,012 MB |
| SampledProfile rows | 55,652 (matches oracle exactly) |
| CSwitch rows | 2,100,633 |
| ReadyThread rows | 1,049,308 |
| TcpIp/Recv / AFD/Recv / NdisDrop rows | 0 (fixture has no manifest events — verified via xperf dumper) |
| Panic test | exit=1, failure_kind=`csharp_exception`, no manifest left behind |
| Deploy | self-contained single-file, no runtime install |

## Known issues / assumptions

1. **Stack pairing rate metric**. The harness's parity check counts a row
   as "paired" if its `Stack` column has any non-null list entry. The C#
   sidecar's representation of "no stack" as a single-null-entry list
   (Parquet.Net 5.0.2's DataColumn API for nullable lists) shows up as
   `[None]` (length 1, paired) rather than `null` (skipped). The internal
   `stacks_paired / stack_eligible_events` metric in the result payload
   reports the true ratio (~35 % on the real fixture).
2. **Manifest provider decode** requires the local TDH manifests to match
   the ones used at capture time. On a Win11 host decoding a Server 2025
   trace, some manifest events may not decode — but the test fixture
   contains no such events anyway.
3. **Peak RSS 5 GB** is high. Buffers hold every row in memory; an
   `event-store-streaming` strategy with per-class rolling parquet parts
   would cap RSS at chunk size × class-count.
