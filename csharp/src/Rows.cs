namespace WprMcpExtract.Rows;

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
    public List<ulong>? Stack;
}

internal sealed class ReadyThreadRow
{
    public ulong EventSequence;
    public long TimeStampQpc;
    public int Cpu;
    public long? ProcessId;
    public long? ThreadId;
    public int? AdjustReason;
    public int? AdjustIncrement;
    public int? Flag;
    public List<ulong>? Stack;
}

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
