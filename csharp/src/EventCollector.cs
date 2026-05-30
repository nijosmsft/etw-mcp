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
    public readonly List<SampledProfileRow> SampledProfile = new(capacity: 1 << 16);
    public readonly List<CSwitchRow> CSwitch = new(capacity: 1 << 17);
    public readonly List<ReadyThreadRow> ReadyThread = new(capacity: 1 << 16);
    public readonly List<TcpipRecvRow> TcpipRecv = new();
    public readonly List<AfdRecvRow> AfdRecv = new();
    public readonly List<NdisDropRow> NdisDrops = new();
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
