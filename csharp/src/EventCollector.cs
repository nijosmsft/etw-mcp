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
///
/// The per-class buffers are <see cref="RowBuffer{T}"/> wrappers so the
/// ETW callbacks have a uniform <c>.Add(row)</c> surface regardless of
/// strategy. In <c>materialized-small</c> mode each buffer is backed by a
/// <see cref="List{T}"/> and the post-Process parquet emitter writes the
/// full list at the end (unchanged behaviour). In <c>event-store-streaming</c>
/// mode the buffer is backed by a <see cref="StreamingChunkSink{T}"/> that
/// rotates batches into a bounded queue consumed by a background writer,
/// bounding live memory regardless of trace size.
///
/// Call <see cref="ConfigureStreaming"/> before <see cref="ExtractRunner.Run"/>
/// to switch into streaming mode; otherwise materialized mode is implicit.
/// </summary>
internal sealed class EventCollector
{
    // Kernel + paired classes
    public RowBuffer<SampledProfileRow> SampledProfile { get; private set; } = new(capacity: 1 << 16);
    public RowBuffer<CSwitchRow> CSwitch { get; private set; } = new(capacity: 1 << 17);
    public RowBuffer<ReadyThreadRow> ReadyThread { get; private set; } = new(capacity: 1 << 16);

    // TCP/UDP flow buffers — share the NetworkFlowRow shape per Python's
    // _DUMPER_EVENT_CLASSES contract.
    public RowBuffer<TcpipRecvRow> TcpipRecv { get; private set; } = new();
    public RowBuffer<NetworkFlowRow> TcpipSend { get; private set; } = new();
    public RowBuffer<NetworkFlowRow> TcpipConnect { get; private set; } = new();
    public RowBuffer<NetworkFlowRow> TcpipAccept { get; private set; } = new();
    public RowBuffer<NetworkFlowRow> TcpipRetransmit { get; private set; } = new();
    public RowBuffer<NetworkFlowRow> TcpipDisconnect { get; private set; } = new();
    public RowBuffer<NetworkFlowRow> UdpRecv { get; private set; } = new();
    public RowBuffer<NetworkFlowRow> UdpSend { get; private set; } = new();

    // AFD (Winsock) — share the AfdEventRow shape.
    public RowBuffer<AfdRecvRow> AfdRecv { get; private set; } = new();
    public RowBuffer<AfdEventRow> AfdSend { get; private set; } = new();
    public RowBuffer<AfdEventRow> AfdConnect { get; private set; } = new();
    public RowBuffer<AfdEventRow> AfdAccept { get; private set; } = new();
    public RowBuffer<AfdEventRow> AfdClose { get; private set; } = new();
    public RowBuffer<AfdEventRow> AfdBind { get; private set; } = new();

    // NDIS
    public RowBuffer<NdisDropRow> NdisDrops { get; private set; } = new();
    public RowBuffer<NdisPacketCaptureRow> NdisPacketCapture { get; private set; } = new();

    // HTTP.sys lifecycle
    public RowBuffer<HttpRow> HttpRecv { get; private set; } = new();
    public RowBuffer<HttpRow> HttpDeliver { get; private set; } = new();
    public RowBuffer<HttpRow> HttpSend { get; private set; } = new();
    public RowBuffer<HttpRow> HttpClose { get; private set; } = new();

    // MsQuic
    public RowBuffer<QuicRow> QuicConnCreated { get; private set; } = new();
    public RowBuffer<QuicRow> QuicConnClosed { get; private set; } = new();
    public RowBuffer<QuicRow> QuicPacketRecv { get; private set; } = new();
    public RowBuffer<QuicRow> QuicPacketSend { get; private set; } = new();
    public RowBuffer<QuicRow> QuicAckReceived { get; private set; } = new();

    // Kernel meta classes
    public RowBuffer<ProcessRow> Process { get; private set; } = new();
    public RowBuffer<ImageRow> Image { get; private set; } = new();
    public RowBuffer<DiskIoRow> DiskIo { get; private set; } = new();
    public RowBuffer<DpcIsrRow> DpcIsr { get; private set; } = new();
    public RowBuffer<ThreadRow> Thread { get; private set; } = new();
    public RowBuffer<EventTraceHeaderRow> EventTraceHeader { get; private set; } = new();

    // Generic self-describing TraceLogging passthrough.
    public RowBuffer<TraceloggingRow> Tracelogging { get; private set; } = new();

    public readonly PendingStackBuffer Pending = new();

    public ulong EventSequence;
    public long EventsDecoded;
    public long StacksPaired;
    public long StackEligibleEvents;  // rows in stackable classes (regardless of pairing)
    public long StackWalksSeen;
    public long CallbackExceptions;

    public ulong NextSeq() => EventSequence++;

    /// <summary>True iff <see cref="ConfigureStreaming"/> has been called.</summary>
    public bool IsStreaming { get; private set; }

    /// <summary>
    /// Streaming-mode sinks. Empty list in materialized mode. Populated by
    /// <see cref="ConfigureStreaming"/> in order matching the per-class
    /// dataset enumeration; <see cref="CompleteAllStreamingAsync"/> awaits
    /// them and returns the summaries.
    /// </summary>
    private readonly List<Func<Task<EventStoreEmitter.DatasetSummary>>> _streamingCompleters = new();

    /// <summary>
    /// Switch every per-class buffer into streaming mode. Must be called
    /// BEFORE ETW callbacks start firing (i.e. before
    /// <see cref="ExtractRunner.Run"/>). The chunk size and queue capacity
    /// mirror <see cref="EventStoreEmitter.DefaultMaxRowsPerPart"/> and
    /// match Python's <c>sinks.DEFAULT_MAX_ROWS_PER_PART</c>.
    /// </summary>
    public void ConfigureStreaming(string eventsDir, int chunkSize, int queueCapacity)
    {
        if (IsStreaming) throw new InvalidOperationException("already configured");
        IsStreaming = true;
        Directory.CreateDirectory(eventsDir);

        // ---- helpers ----
        RowBuffer<TR> Wire<TR>(
            string name,
            Func<TR, long> qpc,
            Func<List<TR>, string, Task<long>> writer)
        {
            var sink = new StreamingChunkSink<TR>(name, eventsDir, chunkSize, queueCapacity, writer, qpc);
            _streamingCompleters.Add(sink.CompleteAsync);
            return new RowBuffer<TR>(sink);
        }

        // ---- paired (stackable) classes ----
        SampledProfile = Wire<SampledProfileRow>("sampled_profile", r => r.TimeStampQpc, ParquetEmitter.WriteSampledProfileAsync);
        CSwitch        = Wire<CSwitchRow>      ("cswitch_events",  r => r.TimeStampQpc, ParquetEmitter.WriteCSwitchAsync);
        ReadyThread    = Wire<ReadyThreadRow>  ("readythread",     r => r.TimeStampQpc, ParquetEmitter.WriteReadyThreadAsync);

        // ---- TCP/UDP flow ----
        TcpipRecv       = Wire<TcpipRecvRow>   ("tcpip_recv",       r => r.TimeStampQpc, ParquetEmitter.WriteTcpipRecvAsync);
        TcpipSend       = Wire<NetworkFlowRow> ("tcpip_send",       r => r.TimeStampQpc, ParquetEmitter.WriteFlowAsync);
        TcpipConnect    = Wire<NetworkFlowRow> ("tcpip_connect",    r => r.TimeStampQpc, ParquetEmitter.WriteFlowAsync);
        TcpipAccept     = Wire<NetworkFlowRow> ("tcpip_accept",     r => r.TimeStampQpc, ParquetEmitter.WriteFlowAsync);
        TcpipRetransmit = Wire<NetworkFlowRow> ("tcpip_retransmit", r => r.TimeStampQpc, ParquetEmitter.WriteFlowAsync);
        TcpipDisconnect = Wire<NetworkFlowRow> ("tcpip_disconnect", r => r.TimeStampQpc, ParquetEmitter.WriteFlowAsync);
        UdpRecv         = Wire<NetworkFlowRow> ("udp_recv",         r => r.TimeStampQpc, ParquetEmitter.WriteFlowAsync);
        UdpSend         = Wire<NetworkFlowRow> ("udp_send",         r => r.TimeStampQpc, ParquetEmitter.WriteFlowAsync);

        // ---- AFD ----
        AfdRecv    = Wire<AfdRecvRow>  ("afd_recv",    r => r.TimeStampQpc, ParquetEmitter.WriteAfdRecvAsync);
        AfdSend    = Wire<AfdEventRow> ("afd_send",    r => r.TimeStampQpc, ParquetEmitter.WriteAfdEventAsync);
        AfdConnect = Wire<AfdEventRow> ("afd_connect", r => r.TimeStampQpc, ParquetEmitter.WriteAfdEventAsync);
        AfdAccept  = Wire<AfdEventRow> ("afd_accept",  r => r.TimeStampQpc, ParquetEmitter.WriteAfdEventAsync);
        AfdClose   = Wire<AfdEventRow> ("afd_close",   r => r.TimeStampQpc, ParquetEmitter.WriteAfdEventAsync);
        AfdBind    = Wire<AfdEventRow> ("afd_bind",    r => r.TimeStampQpc, ParquetEmitter.WriteAfdEventAsync);

        // ---- NDIS ----
        NdisDrops         = Wire<NdisDropRow>          ("ndis_drops",     r => r.TimeStampQpc, ParquetEmitter.WriteNdisDropsAsync);
        NdisPacketCapture = Wire<NdisPacketCaptureRow> ("packet_capture", r => r.TimeStampQpc, ParquetEmitter.WriteNdisPacketCaptureAsync);

        // ---- HTTP.sys ----
        HttpRecv    = Wire<HttpRow>("http_recv",    r => r.TimeStampQpc, ParquetEmitter.WriteHttpAsync);
        HttpDeliver = Wire<HttpRow>("http_deliver", r => r.TimeStampQpc, ParquetEmitter.WriteHttpAsync);
        HttpSend    = Wire<HttpRow>("http_send",    r => r.TimeStampQpc, ParquetEmitter.WriteHttpAsync);
        HttpClose   = Wire<HttpRow>("http_close",   r => r.TimeStampQpc, ParquetEmitter.WriteHttpAsync);

        // ---- MsQuic ----
        QuicConnCreated = Wire<QuicRow>("quic_conn_created", r => r.TimeStampQpc, ParquetEmitter.WriteQuicAsync);
        QuicConnClosed  = Wire<QuicRow>("quic_conn_closed",  r => r.TimeStampQpc, ParquetEmitter.WriteQuicAsync);
        QuicPacketRecv  = Wire<QuicRow>("quic_packet_recv",  r => r.TimeStampQpc, ParquetEmitter.WriteQuicAsync);
        QuicPacketSend  = Wire<QuicRow>("quic_packet_send",  r => r.TimeStampQpc, ParquetEmitter.WriteQuicAsync);
        QuicAckReceived = Wire<QuicRow>("quic_ack_recv",     r => r.TimeStampQpc, ParquetEmitter.WriteQuicAsync);

        // ---- kernel meta ----
        // Match the original EventStoreEmitter.WriteAllAsync set: Process,
        // Image, DiskIo, DpcIsr are streamed; Thread/EventTraceHeader/
        // Tracelogging stay in-memory (Python doesn't ingest them from the
        // event-store path today, and they're never large anyway).
        Process = Wire<ProcessRow>("process", r => r.TimeStampQpc, ParquetEmitter.WriteProcessAsync);
        Image   = Wire<ImageRow>  ("image",   r => r.TimeStampQpc, ParquetEmitter.WriteImageAsync);
        DiskIo  = Wire<DiskIoRow> ("diskio",  r => r.TimeStampQpc, ParquetEmitter.WriteDiskIoAsync);
        DpcIsr  = Wire<DpcIsrRow> ("dpc_isr", r => r.TimeStampQpc, ParquetEmitter.WriteDpcIsrAsync);
        // Thread / EventTraceHeader / Tracelogging keep their default
        // in-memory backends so this method is the SOLE switch.
    }

    /// <summary>
    /// In streaming mode, drain every chunk sink and return the per-class
    /// dataset summaries. In materialized mode returns an empty list.
    /// Safe to call exactly once after <see cref="ExtractRunner.Run"/>.
    /// </summary>
    public async Task<List<EventStoreEmitter.DatasetSummary>> CompleteAllStreamingAsync()
    {
        var summaries = new List<EventStoreEmitter.DatasetSummary>(_streamingCompleters.Count);
        foreach (var completer in _streamingCompleters)
            summaries.Add(await completer().ConfigureAwait(false));
        return summaries;
    }
}
