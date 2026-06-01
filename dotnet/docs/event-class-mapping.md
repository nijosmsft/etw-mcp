# Event-class name mapping

Authoritative source for the canonical event-class strings the .NET sidecar
recognizes in `request.requested_event_classes`, the TraceEvent typed-handler
they bind to, the destination row buffer, the parquet filename, and how the
mapping correlates with Python's
`src/etw_analyzer/tools/trace_mgmt._DUMPER_EVENT_CLASSES`.

Names are case-insensitive. Both the Python `TaskName/Opcode` form
("`TcpIp/Recv`") and the parquet stem ("`tcpip_recv`") are accepted —
whichever the caller finds easiest. The sidecar `Want()` helper in
`ExtractRunner.cs` enumerates all aliases per class.

## Kernel MOF (typed TraceEvent classes)

| Request name (aliases)                  | TraceEvent handler                     | Buffer                       | Parquet                       | Python class           |
| --------------------------------------- | -------------------------------------- | ---------------------------- | ----------------------------- | ---------------------- |
| `SampledProfile`, `sampled_profile`     | `kernel.PerfInfoSample`                | `SampledProfile`             | `sampled_profile.parquet`     | `SampledProfile`       |
| `CSwitch`, `cswitch`, `cswitch_events`  | `kernel.ThreadCSwitch`                 | `CSwitch`                    | `cswitch_events.parquet`      | `CSwitch`              |
| `ReadyThread`, `readythread`            | `kernel.DispatcherReadyThread`         | `ReadyThread`                | `readythread.parquet`         | *(not in Python list)* |
| `TcpIp/Recv`, `tcpip_recv`              | `kernel.TcpIpRecv` + `TcpIpRecvIPV6`   | `TcpipRecv`                  | `tcpip_recv.parquet`          | `TcpIp/Recv`           |
| `TcpIp/Send`, `tcpip_send`              | `kernel.TcpIpSend` + `TcpIpSendIPV6`   | `TcpipSend`                  | `tcpip_send.parquet`          | `TcpIp/Send`           |
| `TcpIp/Connect`, `tcpip_connect`        | `kernel.TcpIpConnect` (+ IPV6)         | `TcpipConnect`               | `tcpip_connect.parquet`       | `TcpIp/Connect`        |
| `TcpIp/Accept`, `tcpip_accept`          | `kernel.TcpIpAccept` (+ IPV6)          | `TcpipAccept`                | `tcpip_accept.parquet`        | `TcpIp/Accept`         |
| `TcpIp/Retransmit`, `tcpip_retransmit`  | `kernel.TcpIpRetransmit` (+ IPV6)      | `TcpipRetransmit`            | `tcpip_retransmit.parquet`    | `TcpIp/Retransmit`     |
| `TcpIp/Disconnect`, `tcpip_disconnect`  | `kernel.TcpIpDisconnect` (+ IPV6)      | `TcpipDisconnect`            | `tcpip_disconnect.parquet`    | *(not in Python list)* |
| `UdpIp/Recv`, `udp_recv`                | `kernel.UdpIpRecv` + `UdpIpRecvIPV6`   | `UdpRecv`                    | `udp_recv.parquet`            | `UdpIp/Recv`           |
| `UdpIp/Send`, `udp_send`                | `kernel.UdpIpSend` + `UdpIpSendIPV6`   | `UdpSend`                    | `udp_send.parquet`            | `UdpIp/Send`           |
| `Process`, `process`                    | `kernel.ProcessStart/Stop/DCStart/Stop/Defunct`| `Process`                | `process.parquet` + per-opcode `process_{start,end,dcstart,dcend,defunct}.parquet` | *(aggregate in Py)*    |
| `Image/Load`, `Image/DCStart`, `image`  | `kernel.ImageLoad`, `kernel.ImageDCStart` | `Image`                   | `image.parquet` + per-opcode `image_{load,dcstart}.parquet` | *(aggregate in Py)*    |
| `DiskIo`, `diskio`                      | `kernel.DiskIORead/Write/FlushBuffers` | `DiskIo`                     | `diskio.parquet` + per-opcode `diskio_{read,write,flushbuffers}.parquet` | *(aggregate in Py)*    |
| `PerfInfo`, `dpcisr`, `dpc_isr`         | `kernel.PerfInfoDPC/ThreadedDPC/TimerDPC/ISR` | `DpcIsr`               | `dpc_isr.parquet` + per-opcode `perfinfo_{dpc,threaded_dpc,timer_dpc,isr}.parquet` | *(aggregate in Py)*    |
| `Thread`, `thread`                      | `kernel.ThreadStart/Stop/DCStart/Stop`  | `Thread`                     | per-opcode `thread_{start,end,dcstart,dcend}.parquet` | *(Track P2 wiring)* |
| `EventTrace/Header`, `eventtrace_header`| `kernel.EventTraceHeader`               | `EventTraceHeader`           | `eventtrace_header.parquet` | *(Track P2 wiring)* |
| `SystemConfig`, `sysconfig`             | `kernel.SystemConfig*` family          | `Sysconfig`                  | `sysconfig.txt`               | *(aggregate in Py)*    |

The four `Process`/`Image`/`DiskIo`/`PerfInfo` classes have no canonical
parquet stem in Python's `_DUMPER_EVENT_CLASSES` — Python derives equivalent
data inside `_run_native_aggregators` rather than persisting a per-event
parquet. The sidecar persists them when the caller asks for them, because
the Rust/C# split-out keeps the aggregator-on-load architecture purely
Python-side.

### Phase B per-opcode parquets

Each combined kernel-meta buffer (`Process`, `Image`, `DiskIo`, `DpcIsr`) is
also emitted as a set of per-opcode parquets — same row schema as the combined
file but with the `Kind` column dropped (each file is a single opcode). Stem
names match the convention `<class>_<opcode>` in lowercase snake-case, e.g.
`perfinfo_dpc.parquet`, `process_dcstart.parquet`. These stems align with the
naming pattern Track P2 will use when it extends Python's
`_DUMPER_EVENT_CLASSES` to surface these opcodes individually.

`Thread/*` and `EventTrace/Header` are new in Phase B and have no combined
parquet — only the per-opcode `thread_{start,end,dcstart,dcend}.parquet`
and the single-row `eventtrace_header.parquet`. The latter contains the
authoritative `PerfFreq`, `NumberOfProcessors`, `TimerResolution`,
`StartTime100Ns`, `EndTime100Ns`, `BootTime100Ns`, `CpuSpeedMHz`, and
`PointerSize` for `derive_metadata_from_sidecar` to consume instead of
guessing 10 MHz.

## Manifest providers (decoded via parser `.All` or `RegisteredTraceEventParser`)

The TaskName/Opcode/EventName triple of each decoded event is substring-matched
against the words below to choose the destination buffer.

| Provider                                | GUID                                      | Buffer dispatch                                                                                                   |
| --------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Microsoft-Windows-Winsock-AFD           | `e53c6823-7bb8-44bb-90dc-3f86090d48a6`    | `Receive`/`Recv` → `AfdRecv`; `Send` → `AfdSend`; `Connect` → `AfdConnect`; `Accept` → `AfdAccept`; `Close` → `AfdClose`; `Bind` → `AfdBind` |
| Microsoft-Windows-NDIS                  | `cdeb2c52-5d52-4d97-9fd0-7a13a3a4cdfa`    | `Drop`/`Discard` → `NdisDrops`                                                                                    |
| Microsoft-Windows-NDIS-PacketCapture    | `2ed6006e-4f4a-4a6d-b5c3-83e3bc8cc3a4`    | `Drop`/`Discard` → `NdisDrops`; `Packet`/`Capture`/`Fragment` → `NdisPacketCapture`                               |
| Microsoft-Windows-TCPIP (manifest)      | `2f07e2ee-15db-40f1-90ef-9d7ba282188a`    | `Receive`/`Recv`/`DataTransferReceive` → `TcpipRecv`                                                              |
| Microsoft-Windows-HttpService           | `dd5ef90a-6398-47a4-ad34-4dcecdef795f`    | `Recv` → `HttpRecv`; `Deliver` → `HttpDeliver`; `Send` → `HttpSend`; `Close` → `HttpClose`                       |
| MsQuic                                  | `ff15e657-4f26-570e-88ab-0796b258d11c`    | `ConnectionCreated` → `QuicConnCreated`; `ConnectionClosed` → `QuicConnClosed`; `PacketRecv` → `QuicPacketRecv`; `PacketSend` → `QuicPacketSend`; `Ack*` → `QuicAckReceived` |

## Pairing semantics

`StackWalk/Stack` events are paired by `(TimeStampQPC, ThreadID)` to the
most recent stack-eligible event added to the
1024-entry FIFO `PendingStackBuffer`. Stack-eligible classes today:
`SampledProfile`, `CSwitch`, `ReadyThread`. See `EventCollector.cs` and
`ExtractRunner.cs::Run()` for the exact ordering rule.

## Adding a new event class

1. Add a `Row` type to `Rows.cs` (or reuse `NetworkFlowRow`/`AfdEventRow`
   if the columns match an existing shape).
2. Add a `List<TRow>` buffer to `EventCollector.cs`.
3. Add a `_wantXxx` flag and a `Want(...)` line to the `ExtractRunner`
   constructor, listing every alias the caller might use.
4. Hook the TraceEvent handler in `ExtractRunner.Run()` (kernel) or add a
   branch to `DispatchManifest` (manifest provider).
5. Add a `WriteXxxAsync(rows, path)` method in `ParquetEmitter.cs` with the
   `internal static` visibility that matches the existing per-class writers,
   and call it from `WriteAllAsync` for `materialized-small`.
6. Add a `ChunkXxxAsync` line in `EventStoreEmitter.WriteAllAsync` so the
   class participates in `event-store-streaming` too.
7. Register the dataset entry in `Program.cs` so both the cache manifest
   and the JSONL `result.event_counts` advertise it.
8. Update this doc.
