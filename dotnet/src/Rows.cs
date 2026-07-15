namespace EtwExtract.Rows;

// Mutable row types — the stack pairing pass writes the Stack field
// after the row has been appended.

internal sealed class SampledProfileRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public long? ProcessId;
    public long? ThreadId;
    public long? PayloadThreadId;
    public ulong InstructionPointer;
    public long Weight = 1;
    public long ProfileWeight = 1;
    public List<ulong>? Stack;
}

internal sealed class CSwitchRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public long? NewTid;
    public long? OldTid;
    public long? NewPid;
    public long? OldPid;
    public string? WaitReason;
    // Previous scheduling state of the switched-out thread ("Waiting",
    // "Standby", "Running", "Ready", ...). Required so downstream tooling can
    // distinguish a genuine Wait->Running park from a preemption. See #36.
    public string? OldThreadState;
    public List<ulong>? Stack;
}

internal sealed class ReadyThreadRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    // ThreadId / ProcessId identify the READIED (awakened) thread, matching the
    // native mof decoder contract (payload TThreadId). ReadyingThreadId /
    // ReadyingProcessId identify the thread that performed the ready (event
    // header). Unified schema for native + sidecar — see #36 / #28.
    public long? ProcessId;
    public long? ThreadId;
    public long? ReadiedThreadId;
    public long? ReadyingThreadId;
    public long? ReadyingProcessId;
    public int? AdjustReason;
    public int? AdjustIncrement;
    public int? Flag;
    public List<ulong>? Stack;
}

/// <summary>
/// Shared row shape for all TCP/UDP flow events (Recv/Send/Connect/Accept/
/// Retransmit/UdpRecv/UdpSend). Python's <c>_DUMPER_EVENT_CLASSES</c> emits
/// one parquet per (proto, opcode) but they share columns, so we share the
/// row class and only differentiate by the destination buffer.
/// Historical alias: also exposed via <see cref="TcpipRecvRow"/>.
/// </summary>
internal sealed class NetworkFlowRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string? ProcessName;
    public long? Pid;
    public long? ThreadId;
    public string? LocalAddr;
    public long? LocalPort;
    public string? RemoteAddr;
    public long? RemotePort;
    public long? Size;
    public ulong? SeqNo;
    public ulong? ConnId;
}

// Alias used by the original spike handlers.
internal sealed class TcpipRecvRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string? ProcessName;
    public long? Pid;
    public long? ThreadId;
    public string? LocalAddr;
    public long? LocalPort;
    public string? RemoteAddr;
    public long? RemotePort;
    public long? Size;
    public ulong? SeqNo;
    public ulong? ConnId;
}

/// <summary>
/// Shared row shape for AFD socket lifecycle events
/// (Recv/Send/Connect/Accept/Close/Bind).
/// </summary>
internal sealed class AfdEventRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string? ProcessName;
    public long? Pid;
    public long? ThreadId;
    public ulong? SocketHandle;
    public long? Size;
    public long? CompletionStatus;
}

// Alias used by the original spike handlers.
internal sealed class AfdRecvRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string? ProcessName;
    public long? Pid;
    public long? ThreadId;
    public ulong? SocketHandle;
    public long? Size;
    public long? CompletionStatus;
}

internal sealed class NdisDropRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string? ProcessName;
    public long? Pid;
    public long? ThreadId;
    public string? MiniportName;
    public string? Reason;
    public long? Size;
}

/// <summary>NDIS PacketCapture decoded frame row.</summary>
internal sealed class NdisPacketCaptureRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string? MiniportName;
    public string? Direction;
    public long? FragmentSize;
    public byte[]? Fragment;
}

/// <summary>HTTP.sys request lifecycle row (Recv/Deliver/Send/Close share schema).</summary>
internal sealed class HttpRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string? ProcessName;
    public long? Pid;
    public long? ThreadId;
    public ulong? RequestId;
    public ulong? ConnectionId;
    public ulong? UrlGroupId;
    public string? Url;
    public string? Verb;
    public long? Status;
    public long? BytesSent;
    public long? BytesReceived;
}

/// <summary>MsQuic connection / packet row.</summary>
internal sealed class QuicRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string? ProcessName;
    public long? Pid;
    public long? ThreadId;
    public ulong? ConnectionId;
    public string? Cid;
    public ulong? PacketNumber;
    public long? PacketSize;
    public long? AckDelayUs;
}

/// <summary>Process create/exit row.</summary>
internal sealed class ProcessRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string Kind = ""; // "Start" | "End" | "DCStart" | "DCEnd"
    public long Pid;
    public long ParentPid;
    public string? ImageFileName;
    public string? CommandLine;
}

/// <summary>Image load / dcstart / dcend row (for symbol resolution downstream).</summary>
internal sealed class ImageRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string Kind = ""; // "Load" | "DCStart" | "DCEnd"
    public long Pid;
    public ulong ImageBase;
    public long ImageSize;
    public long TimeDateStamp;
    public string? FileName;
    // PDB identity from DbgID/RSDS rundown (null when no RSDS record matched).
    public string? PdbGuid;  // canonical uppercase hyphenated, e.g. AFB1E3B1-3754-8BA7-3B92-C060D6D5605F
    public int? PdbAge;
    public string? PdbName;  // basename only, e.g. ntkrnlmp.pdb
}

/// <summary>DiskIo row (read/write).</summary>
internal sealed class DiskIoRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string Kind = ""; // "Read" | "Write" | "FlushBuffers"
    public long? DiskNumber;
    public ulong? ByteOffset;
    public long? TransferSize;
    public long? Pid;
    public string? FileName;
    public long? ElapsedMicros;
}

/// <summary>PerfInfo DPC/ISR event row.</summary>
internal sealed class DpcIsrRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string Kind = ""; // "DPC" | "ISR" | "ThreadedDPC"
    public ulong Routine;
    public long ElapsedMicros;
}

/// <summary>Thread create/exit row (Start/End/DCStart/DCEnd).</summary>
internal sealed class ThreadRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public string Kind = ""; // "Start" | "End" | "DCStart" | "DCEnd"
    public long Pid;
    public long Tid;
    public long? ParentPid;
    public long? ParentTid;
    public ulong StartAddr;
    public ulong Win32StartAddr;
    public ulong StackBase;
    public ulong StackLimit;
    public ulong UserStackBase;
    public ulong UserStackLimit;
    public int? BasePriority;
    public string? ThreadName;
}

/// <summary>
/// EventTrace/Header row — single-row table per ETL with authoritative trace
/// metadata. Source: <c>kernel.EventTraceHeader</c>.
/// </summary>
internal sealed class EventTraceHeaderRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public long PerfFreq;
    public int NumberOfProcessors;
    public int TimerResolution;
    public long StartTime100Ns;        // FILETIME-style 100ns since 1601
    public long EndTime100Ns;
    public long BootTime100Ns;
    public int CpuSpeedMHz;
    public int PointerSize;            // 4 or 8
    public int LogFileMode;
    public int BuffersWritten;
    public int EventsLost;
    public string? SessionName;
    public string? LogFileName;
}

internal sealed class TraceloggingRow
{
    public long TimeStampQpc;
    public string ProviderGuid = "";
    public string ProviderName = "";
    public string EventName = "";
    public long ProcessId;
    public long ThreadId;
    public int Cpu;
    public int Level;
    public ulong Keywords;
    public string FieldsJson = "{}";
}
