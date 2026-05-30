using System.Collections;

namespace WprMcpExtract;

/// <summary>
/// Strategy-aware wrapper around a per-class row store. Exposes a uniform
/// <see cref="Add"/> surface to the ETW callbacks so they don't have to
/// know whether the trace is being materialized into a flat parquet
/// (<c>materialized-small</c> strategy) or chunk-streamed into
/// <c>events/&lt;class&gt;/part-NNNN.parquet</c> files
/// (<c>event-store-streaming</c> strategy).
///
/// In materialized mode the backend is a plain <see cref="List{T}"/> that
/// the parquet emitter writes wholesale at the end. In streaming mode the
/// backend is a <see cref="StreamingChunkSink{T}"/> that rotates batches
/// into a bounded queue consumed by a background writer task — so live
/// memory is bounded to a handful of chunks regardless of the trace size.
///
/// The materialized path is the default and is functionally unchanged
/// from the pre-refactor List&lt;T&gt; world (List&lt;T&gt; is the
/// backend; <see cref="AsList"/> exposes it for direct write).
///
/// <see cref="IEnumerable{T}"/> is implemented for materialized-only
/// iteration (e.g. Program.cs counts Process/Image/DiskIo/DpcIsr/Thread
/// opcodes for the dataset manifest). In streaming mode the enumerator
/// throws because the rows have already been flushed to disk.
/// </summary>
internal sealed class RowBuffer<T> : IEnumerable<T>
{
    private readonly List<T>? _list;
    private readonly StreamingChunkSink<T>? _sink;

    /// <summary>Materialized-mode buffer.</summary>
    public RowBuffer(int capacity = 16)
    {
        _list = new List<T>(capacity);
    }

    /// <summary>Streaming-mode buffer wrapping a chunk sink.</summary>
    public RowBuffer(StreamingChunkSink<T> sink)
    {
        _sink = sink;
    }

    public bool IsStreaming => _sink != null;

    /// <summary>
    /// Append a row. In streaming mode this may block briefly to apply
    /// backpressure when the disk writer is behind — that is by design.
    /// </summary>
    public void Add(T row)
    {
        if (_list != null) _list.Add(row);
        else _sink!.Add(row);
    }

    /// <summary>Logical row count (across all flushed + in-flight batches).</summary>
    public long LongCount => _list?.Count ?? _sink!.TotalCount;

    /// <summary>
    /// Convenience int count for materialized mode. In streaming mode
    /// returns the truncated value — callers that need the full count
    /// should use <see cref="LongCount"/>.
    /// </summary>
    public int Count => _list?.Count ?? checked((int)Math.Min(int.MaxValue, _sink!.TotalCount));

    /// <summary>
    /// Returns the underlying <see cref="List{T}"/> in materialized mode.
    /// In streaming mode this throws — the rows have already been flushed
    /// to per-part parquets and the streaming sink is the source of truth.
    /// </summary>
    public List<T> AsList()
    {
        if (_list == null)
            throw new InvalidOperationException(
                "RowBuffer is in streaming mode — rows are not retained in memory; " +
                "call CompleteAsync() to drain and obtain the dataset summary.");
        return _list;
    }

    /// <summary>
    /// Drain the streaming sink and return the finalized dataset summary
    /// (counts, parts, min/max QPC). In materialized mode this throws —
    /// materialized writes happen via <see cref="ParquetEmitter"/>.
    /// </summary>
    public Task<EventStoreEmitter.DatasetSummary> CompleteAsync()
    {
        if (_sink == null)
            throw new InvalidOperationException(
                "RowBuffer is in materialized mode — call AsList() and hand to ParquetEmitter.");
        return _sink.CompleteAsync();
    }

    /// <summary>
    /// Materialized-mode enumeration. Streaming mode throws because the
    /// rows have already been handed off to the chunk writer and are no
    /// longer addressable in memory.
    /// </summary>
    public IEnumerator<T> GetEnumerator()
    {
        if (_list == null)
            throw new InvalidOperationException(
                "RowBuffer is in streaming mode and does not retain rows for enumeration.");
        return _list.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

/// <summary>
/// Internal marker used by <see cref="StreamingChunkSink{T}"/> so we can
/// keep the public <see cref="RowBuffer{T}"/> surface narrow. Not used
/// elsewhere today; reserved for future polymorphic sinks (e.g. an
/// in-memory + tee-to-disk hybrid for debugging).
/// </summary>
internal interface IRowBufferBackend<T>
{
    void Add(T row);
    long TotalCount { get; }
}
