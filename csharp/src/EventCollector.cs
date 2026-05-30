using WprMcpExtract.Rows;

namespace WprMcpExtract;

/// <summary>
/// Pending-row buffer for stack pairing. Per spike contract §10, capacity
/// is exactly 1024. On overflow we evict the oldest entry (FIFO).
/// </summary>
internal sealed class PendingStackBuffer
{
    private const int Capacity = 1024;

    private readonly record struct Key(long Qpc, long Tid);

    private sealed class Entry
    {
        public Key Key;
        public Action<List<ulong>> Setter = _ => { };
    }

    private readonly LinkedList<Entry> _order = new();
    private readonly Dictionary<Key, LinkedListNode<Entry>> _index = new(Capacity);

    public int Evictions { get; private set; }
    public int Pending => _index.Count;

    public void Add(long qpc, long tid, Action<List<ulong>> setter)
    {
        var key = new Key(qpc, tid);
        if (_index.TryGetValue(key, out var existing))
        {
            // Same key already pending — replace (newer event wins).
            _order.Remove(existing);
            _index.Remove(key);
        }
        if (_index.Count >= Capacity)
        {
            var oldest = _order.First;
            if (oldest != null)
            {
                _order.RemoveFirst();
                _index.Remove(oldest.Value.Key);
                Evictions++;
            }
        }
        var node = _order.AddLast(new Entry { Key = key, Setter = setter });
        _index[key] = node;
    }

    public bool TryPair(long qpc, long tid, List<ulong> addresses)
    {
        var key = new Key(qpc, tid);
        if (!_index.TryGetValue(key, out var node))
            return false;
        _index.Remove(key);
        _order.Remove(node);
        try { node.Value.Setter(addresses); } catch { /* swallow */ }
        return true;
    }
}

/// <summary>
/// Holds row buffers for every event class and the pending stack pairing
/// state. Counters mutate from the single TraceEvent callback thread, so
/// no locking is required.
/// </summary>
internal sealed class EventCollector
{
    // Kernel + paired classes
    public readonly List<SampledProfileRow> SampledProfile = new(capacity: 1 << 16);
    public readonly List<CSwitchRow> CSwitch = new(capacity: 1 << 17);
    public readonly List<ReadyThreadRow> ReadyThread = new(capacity: 1 << 16);

    // TCP/UDP flow buffers — share the NetworkFlowRow shape per Python's
    // _DUMPER_EVENT_CLASSES contract.
    public readonly List<TcpipRecvRow> TcpipRecv = new();
    public readonly List<NetworkFlowRow> TcpipSend = new();
    public readonly List<NetworkFlowRow> TcpipConnect = new();
    public readonly List<NetworkFlowRow> TcpipAccept = new();
    public readonly List<NetworkFlowRow> TcpipRetransmit = new();
    public readonly List<NetworkFlowRow> TcpipDisconnect = new();
    public readonly List<NetworkFlowRow> UdpRecv = new();
    public readonly List<NetworkFlowRow> UdpSend = new();

    // AFD (Winsock) — share the AfdEventRow shape.
    public readonly List<AfdRecvRow> AfdRecv = new();
    public readonly List<AfdEventRow> AfdSend = new();
    public readonly List<AfdEventRow> AfdConnect = new();
    public readonly List<AfdEventRow> AfdAccept = new();
    public readonly List<AfdEventRow> AfdClose = new();
    public readonly List<AfdEventRow> AfdBind = new();

    // NDIS
    public readonly List<NdisDropRow> NdisDrops = new();
    public readonly List<NdisPacketCaptureRow> NdisPacketCapture = new();

    // HTTP.sys lifecycle
    public readonly List<HttpRow> HttpRecv = new();
    public readonly List<HttpRow> HttpDeliver = new();
    public readonly List<HttpRow> HttpSend = new();
    public readonly List<HttpRow> HttpClose = new();

    // MsQuic
    public readonly List<QuicRow> QuicConnCreated = new();
    public readonly List<QuicRow> QuicConnClosed = new();
    public readonly List<QuicRow> QuicPacketRecv = new();
    public readonly List<QuicRow> QuicPacketSend = new();
    public readonly List<QuicRow> QuicAckReceived = new();

    // Kernel meta classes
    public readonly List<ProcessRow> Process = new();
    public readonly List<ImageRow> Image = new();
    public readonly List<DiskIoRow> DiskIo = new();
    public readonly List<DpcIsrRow> DpcIsr = new();
    public readonly List<ThreadRow> Thread = new();
    public readonly List<EventTraceHeaderRow> EventTraceHeader = new();

    // Generic self-describing TraceLogging passthrough.
    public readonly List<TraceloggingRow> Tracelogging = new();

    public readonly PendingStackBuffer Pending = new();

    public ulong EventSequence;
    public long EventsDecoded;
    public long StacksPaired;
    public long StackEligibleEvents;  // rows in stackable classes (regardless of pairing)
    public long StackWalksSeen;
    public long CallbackExceptions;

    public ulong NextSeq() => EventSequence++;
}
