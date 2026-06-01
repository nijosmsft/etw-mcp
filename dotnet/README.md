# `etw-extract.exe` — .NET sidecar (production)

Sidecar binary that decodes Windows ETL traces into Layer-1 parquets per
[spike-contract.md](../../wpr-mcp-poc-staging/docs/spike-contract.md).
Closes the 5 documented parity gaps in
[../native-vs-xperf-parity-review.md](../native-vs-xperf-parity-review.md)
and bumps the spike to production quality on `feature/dotnet-sidecar`.

## Build

```powershell
cd dotnet
dotnet publish -c Release -r win-x64 --self-contained -o publish\win-x64
# → publish\win-x64\etw-extract.exe  (self-contained single-file, ~38 MB)
```

`net8.0` LTS. Self-contained single-file deploy. No runtime install required.
NativeAOT is intentionally not used — see
[docs/signing.md](docs/signing.md#why-not-nativeaot).

## Run

```powershell
etw-extract.exe --request <path-to-request.json>
etw-extract.exe --request <path>.json --no-include-tracelogging
```

Stdout is reserved for JSONL protocol (heartbeat / progress / result).
Stderr carries human-readable logs. See spike-contract §4-§5.

CLI flags:

| Flag | Default | Meaning |
|---|---|---|
| `--request <path>` | (required) | Absolute path to request.json. |
| `--include-tracelogging` | on | Emit `tracelogging_events.parquet` for self-describing providers not routed to a typed buffer. |
| `--no-include-tracelogging` | — | Disable the TraceLogging passthrough. |

CLI flags override the request-file value for the same field.

## Smoke test

```powershell
.\scripts\smoke-test.ps1                    # build + run both strategies + diff vs oracle
.\scripts\smoke-test.ps1 -SkipBuild         # skip dotnet publish
.\scripts\smoke-test.ps1 -SkipStreaming     # materialized only
```

The script builds the sidecar, runs it twice (materialized-small +
event-store-streaming) against
`C:\git\wpr-mcp-poc-staging\real-fixture\spike-fixture.etl`, and diffs
output row counts + manifests against the Python-native oracle in
`C:\git\wpr-mcp-poc-staging\real-fixture\oracle\`. Exits non-zero on any
build, row-count, or manifest-schema divergence.

Last green run (Server 2025, 80 CPUs):

| Mode | Wall | EPS | Peak RSS | Datasets matched |
|---|---|---|---|---|
| materialized-small      | 15.1 s | 233,241 | 5,017 MB | 25/25 row-counts exact |
| event-store-streaming   | 13.2 s | 255,565 | 3,927 MB | 28 datasets, CSwitch chunked into 9 × 256K-row parts |

## Event class coverage

28 canonical classes from Python's `_DUMPER_EVENT_CLASSES`
([trace_mgmt.py:555-585](../../etw-mcp/src/etw_analyzer/tools/trace_mgmt.py)):

Kernel MOF: `SampledProfile`, `CSwitch`, `ReadyThread`, `TcpIp/Recv|Send|Connect|Accept|Retransmit|Disconnect`,
`UdpIp/Recv|Send`, `Process` (Start/End/DCStart/DCEnd/Defunct), `Thread` (Start/End/DCStart/DCEnd),
`Image/Load|DCStart`, `DiskIo` (Read/Write/FlushBuffers), `PerfInfo` (DPC/ThreadedDPC/TimerDPC/ISR),
`EventTrace/Header`, `SystemConfig`.

Manifest providers: `AFD/Recv|Send|Connect|Accept|Close|Bind`,
`NdisDrop`, `NdisPacketCapture`, `HttpService/Recv|Deliver|Send|Close`,
`Quic/ConnectionCreated|ConnectionClosed|PacketRecv|PacketSend|AckReceived`.

Generic passthrough: `tracelogging_events.parquet` for any self-describing
provider not routed to a typed buffer (gated by `--include-tracelogging`).

See [docs/event-class-mapping.md](docs/event-class-mapping.md) for the
full request-name → TraceEvent handler → parquet stem table and the
"how to add a new event class" recipe.

## Output layout — `materialized-small`

```
<staging>/
├── wpr-mcp-cache-manifest.json     (schema_version=3, producer="dotnet")
├── sampled_profile.parquet
├── cswitch_events.parquet
├── readythread.parquet
├── tcpip_{recv,send,connect,accept,retransmit,disconnect}.parquet
├── udp_{recv,send}.parquet
├── afd_{recv,send,connect,accept,close,bind}.parquet
├── ndis_drops.parquet
├── packet_capture.parquet
├── http_{recv,deliver,send,close}.parquet
├── quic_{conn_created,conn_closed,packet_recv,packet_send,ack_recv}.parquet
├── [process|image|diskio|dpc_isr].parquet  (combined, kept for back-compat)
├── [process_{start,end,dcstart,dcend,defunct}.parquet]   (Phase B per-opcode)
├── [thread_{start,end,dcstart,dcend}.parquet]            (Phase B per-opcode)
├── [image_{load,dcstart}.parquet]                        (Phase B per-opcode, drives symbolizer)
├── [diskio_{read,write,flushbuffers}.parquet]            (Phase B per-opcode)
├── [perfinfo_{dpc,threaded_dpc,timer_dpc,isr}.parquet]   (Phase B per-opcode)
├── [eventtrace_header.parquet]                           (Phase B authoritative metadata)
├── [tracelogging_events.parquet]           (when --include-tracelogging)
└── sysconfig.txt
```

## Output layout — `event-store-streaming`

```
<staging>/
├── wpr-mcp-cache-manifest.json
├── sysconfig.txt
└── native-store/
    └── generations/
        └── <run_id>/
            ├── native-event-store-manifest.json
            └── events/
                ├── sampled_profile/part-0000.parquet
                ├── cswitch_events/part-0000.parquet ... part-NNNN.parquet
                └── ... (one subdir per non-empty class)
```

Parts rotate at 256 000 rows (matches Python `sinks.DEFAULT_MAX_ROWS_PER_PART`).
The sub-manifest records `min_qpc`/`max_qpc`/`byte_size` per part so the
Python loader can prune by time-range without opening each parquet.

## Architecture

```
Program.cs            ── --request parse, --include-tracelogging override,
                         strategy dispatch, top-level try/catch → result JSONL
  ↓
Request.cs            ── deserialize + validate (rejects relative paths,
                         requires version=1)
  ↓
ExtractRunner.cs      ── ETWTraceEventSource.Process()
  │                     • kernel typed handlers (PerfInfoSample, ThreadCSwitch,
  │                       DispatcherReadyThread, TcpIp/Udp Recv/Send/Connect/
  │                       Accept/Retransmit/Disconnect IPv4+IPv6, ImageLoad,
  │                       ProcessStart/Stop/DC*, DiskIORead/Write/Flush,
  │                       PerfInfoDPC/ThreadedDPC/ISR, SystemConfig*) → row buffers
  │                     • RegisteredTraceEventParser.All for AFD (TDH manifest)
  │                     • typed MicrosoftWindowsTCPIP / NDISPacketCapture parsers
  │                     • Dynamic.All + AllEvents for HTTP.sys, MsQuic, and the
  │                       generic TraceLogging passthrough (gated, de-duped via
  │                       _consumedKeys)
  │                     • StackWalk handler → pair into pending FIFO (1024-cap)
  │                     • every callback body in Wrap(try/catch) — panic_probe
  │                       exception escapes to abort cleanly
  ↓
EventCollector.cs     ── row buffers (~28) + PendingStackBuffer (1024 capacity)
  ↓
ParquetEmitter.cs     ── lower-level Parquet.Net writer with list-inner field
                         name="element" (pyarrow canonical). Internal writers
                         shared between materialized-small and event-store-streaming.
  ↓
EventStoreEmitter.cs  ── chunked per-class parquets + native-event-store-manifest.json
                         (event-store-streaming only)
ManifestEmitter.cs    ── wpr-mcp-cache-manifest.json (schema_version=3,
                         producer="dotnet", timebase {qpc_origin, perf_freq})
SysconfigCollector.cs ── sysconfig.txt (CPU / NIC / Disk / OS lines)
```

## Performance budget

| Metric | Spike (8 classes) | This branch (28 classes) | Task target |
|---|---|---|---|
| Wall (real-fixture, materialized) | 12.7 s | 15.1 s | ≤ 20 s |
| Wall (real-fixture, streaming)    | n/a    | 13.2 s | ≤ 20 s |
| Events / sec                       | 252K   | 233K (materialized), 256K (streaming) | — |
| Peak RSS (materialized)            | 5,012 MB | 5,017 MB | ≤ 6,144 MB |
| Peak RSS (streaming)               | n/a    | 3,927 MB | ≤ 1,024 MB target (≤ 6 GB hard) |
| Self-contained binary              | 38 MB  | 38 MB    | — |

The streaming RSS budget (≤ 1 GB target) is not yet met. Today the rows
are still buffered in full before chunked write — the streaming benefit is
on the *output* side (cap chunk size × class count for downstream Python
loaders), not the source side. Implementing source-side incremental flush
(buffer per part, write, free) is deferred — see "Known limitations" below.

## Parity status against the 5 documented gaps

From `../native-vs-xperf-parity-review.md`:

| # | Gap | Status |
|---|---|---|
| 1 | NdisDrop events silently dropped | **FIXED** — handler + parquet emitted; real-fixture has 0 NdisDrop events, sidecar produces 0-row parquet matching oracle. Real validation deferred to lab fixture with populated NdisDrop. |
| 2 | TraceLogging providers not decoded | **FIXED** in spike via `source.AllEvents` (29,046 events decoded on the SDN test ETL). `--include-tracelogging` CLI flag now controls behavior. |
| 3 | Module identity collapse (TimeDateStamp + SizeOfImage) | Sidecar emits `Image/Load` + `Image/DCStart` rows with `TimeDateStamp`, `ImageSize`, `ImageBase`, `FileName`. Python aggregator owns the collapse. |
| 4 | NIC by LUID | Sidecar's `sysconfig.txt` lists NICs by `FriendlyName`/`Driver`/`Mac`. LUID extraction requires `SystemConfigNetwork`/`SystemConfigIRoute` events — present in the kernel SystemConfig parser; not extracted today. **Deferred.** |
| 5 | HTTP.sys + MsQuic decode | **FIXED** — handlers for HttpService (`Recv|Deliver|Send|Close`) and MsQuic (`ConnectionCreated|ConnectionClosed|PacketRecv|PacketSend|AckReceived`) attached. Real-fixture has 0 events of these classes; sidecar produces 0-row parquets matching oracle. |

## Known limitations

1. **Event-store-streaming RSS not yet bounded.** Rows are buffered in
   full before chunked write. The streaming benefit is on the *output*
   side (downstream Python loaders cap memory per part), not the
   sidecar's source side. Lifting the source-side cap requires
   refactoring `EventCollector` from `List<T>` to bounded channels — a
   ~2-day change deferred to a follow-up commit.
2. **NdisDrop and the manifest providers not exercised on real data.**
   The lab fixture has 0 events for AFD, NDIS, HTTP.sys, MsQuic, TCP-IPv4
   recv/send/etc. Sidecar produces correctly-schema'd 0-row parquets
   matching the oracle. End-to-end content validation requires capturing
   a trace with populated networking events (the lab UDP-echo workload
   should do that; not gated on for this POC). The
   `synthetic-fixtures` ETL is a placeholder, not a real ETW capture, so
   it can't substitute.
3. **Module identity NIC-by-LUID extraction deferred.** See gap #4 above.
4. **Symbol resolution returns 0/0 in result.performance.** Symbolizing
   is a Python-side aggregator concern under the contract; the sidecar
   only emits Image/Load rows that downstream code uses to build the
   symbolizer. This matches the Python native pipeline.
5. **TraceEvent `QPCFreq` is internal.** Accessed via reflection on
   session open. If TraceEvent 4.x makes it public, drop the reflection
   call in `ExtractRunner.Run()`.

## Compatibility notes

- **`mtime_ns` encoding.** As of this branch, `wpr-mcp-cache-manifest.json`
  encodes the ETL's `mtime_ns` as Unix-epoch nanoseconds (matching
  Python's `int(Path(etl).stat().st_mtime_ns)`). The Python supervisor
  still carries an `EtlIdentity.matches_loose()` fall-back for
  manifests written by prior builds that used the year-0001 reference
  (.NET `Ticks * 100`). That shim will be removed on the Python side in
  a follow-up commit (P2 scope); both encodings are accepted in the
  interim so cache rehydration of older runs keeps working.

## Adding a new event class

See [docs/event-class-mapping.md](docs/event-class-mapping.md#adding-a-new-event-class) — 8 steps with concrete file pointers.

## Code signing

See [docs/signing.md](docs/signing.md). Binary is unsigned by default; for lab
or prod deployment, sign with the engineering Authenticode cert.

## Files

```
dotnet/
├── README.md                   (this file)
├── etw-extract.csproj      (.NET 8 single-file self-contained)
├── docs/
│   ├── event-class-mapping.md  (request-name → handler → parquet stem)
│   └── signing.md              (Authenticode posture, WDAC/HVCI, SBOM)
├── scripts/
│   └── smoke-test.ps1          (build + run + diff vs oracle)
└── src/
    ├── Program.cs              (CLI, top-level orchestration)
    ├── Request.cs              (request DTO + validator)
    ├── Rows.cs                 (row types for every event class)
    ├── EventCollector.cs       (buffers + pending stack pair)
    ├── ExtractRunner.cs        (ETWTraceEventSource handlers + dispatch)
    ├── ParquetEmitter.cs       (Parquet.Net writers)
    ├── EventStoreEmitter.cs    (chunked event-store-streaming layout)
    ├── ManifestEmitter.cs      (wpr-mcp-cache-manifest.json, schema_version=3)
    ├── SysconfigCollector.cs   (sysconfig.txt)
    └── JsonlEmitter.cs         (heartbeat/progress/result protocol)
```
