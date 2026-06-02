using System.Collections.Concurrent;

namespace EtwExtract;

/// <summary>
/// Producer/consumer sink for the <c>event-store-streaming</c> strategy.
///
/// The ETW callback thread calls <see cref="Add"/> to append rows. When the
/// in-flight batch reaches <see cref="_chunkSize"/> rows it is handed off to
/// a bounded <see cref="BlockingCollection{T}"/> and a fresh batch starts.
/// A single background consumer task per sink drains the queue and writes
/// each batch to <c>events/&lt;name&gt;/part-NNNN.parquet</c> via the
/// caller-supplied <paramref name="writer"/>.
///
/// Memory budget per class: <c>chunkSize × (queueCapacity + 2)</c> rows
/// (one being filled, one being written, queueCapacity sitting waiting).
/// With the defaults this caps live rows per class at ~1M (256K × 4) vs
/// the previous "buffer everything, write at end" pattern which held the
/// entire trace's row set live.
///
/// Stack-pairing safety: <see cref="PendingStackBuffer"/> is capped at 1024
/// entries. Any setter for a row older than 1024 newer stack-eligible
/// events has either fired or been evicted, so the row's Stack field is
/// final and the row is safe to ship. With <see cref="_chunkSize"/> set to
/// 256K (250× the pending capacity), the FIRST batch hand-off for any
/// stackable class is already past the safety window, and every subsequent
/// hand-off trivially is. Non-stackable classes have no safety constraint.
///
/// Backpressure: <c>BlockingCollection.Add</c> blocks the producer when the
/// queue is full, throttling ProcessTrace to disk speed instead of letting
/// the producer outrun the writer.
/// </summary>
internal sealed class StreamingChunkSink<T> : IRowBufferBackend<T>
{
    private readonly BlockingCollection<List<T>> _queue;
    private readonly Task _consumerTask;
    private readonly int _chunkSize;
    private readonly string _name;
    private readonly string _eventsDir;
    private readonly Func<List<T>, string, Task<long>> _writer;
    private readonly Func<T, long> _qpcSelector;
    private readonly EventStoreEmitter.DatasetSummary _summary;

    private List<T> _current;
    private long _totalCount;
    private bool _completed;

    public StreamingChunkSink(
        string name,
        string eventsDir,
        int chunkSize,
        int queueCapacity,
        Func<List<T>, string, Task<long>> writer,
        Func<T, long> qpcSelector)
    {
        _name = name;
        _eventsDir = eventsDir;
        _chunkSize = chunkSize;
        _writer = writer;
        _qpcSelector = qpcSelector;
        _current = new List<T>(_chunkSize);
        _queue = new BlockingCollection<List<T>>(boundedCapacity: queueCapacity);
        _summary = new EventStoreEmitter.DatasetSummary { Name = name };
        _consumerTask = Task.Run(ConsumeAsync);
    }

    public long TotalCount => _totalCount;

    /// <summary>
    /// Called on the ETW callback thread. Appends to the in-flight batch and
    /// rotates (with potential backpressure) when full.
    /// </summary>
    public void Add(T row)
    {
        _current.Add(row);
        _totalCount++;
        if (_current.Count >= _chunkSize)
            ShipCurrent();
    }

    private void ShipCurrent()
    {
        if (_current.Count == 0) return;
        var batch = _current;
        _current = new List<T>(_chunkSize);
        // BlockingCollection.Add() blocks if bounded capacity is hit. That
        // applies backpressure to the producer (ETW thread) when the disk
        // writer can't keep up — preferred over unbounded memory growth.
        _queue.Add(batch);
    }

    /// <summary>
    /// Drain the remaining in-flight batch (if any), close the queue, and
    /// wait for the consumer to finish writing all parts. Returns the
    /// finalized dataset summary.
    /// </summary>
    public async Task<EventStoreEmitter.DatasetSummary> CompleteAsync()
    {
        if (_completed) return _summary;
        _completed = true;
        ShipCurrent();
        _queue.CompleteAdding();
        await _consumerTask.ConfigureAwait(false);
        return _summary;
    }

    private async Task ConsumeAsync()
    {
        Directory.CreateDirectory(Path.Combine(_eventsDir, _name));
        int partIndex = 0;
        foreach (var batch in _queue.GetConsumingEnumerable())
        {
            if (batch.Count == 0) continue;
            long minQ = _qpcSelector(batch[0]);
            long maxQ = minQ;
            for (int i = 1; i < batch.Count; i++)
            {
                long v = _qpcSelector(batch[i]);
                if (v < minQ) minQ = v;
                if (v > maxQ) maxQ = v;
            }
            string partRel = $"events/{_name}/part-{partIndex:D4}.parquet";
            string partPath = Path.GetFullPath(Path.Combine(_eventsDir, "..", partRel));
            long bytes = await _writer(batch, partPath).ConfigureAwait(false);
            _summary.Parts.Add(new EventStoreEmitter.PartInfo(partRel, batch.Count, minQ, maxQ, bytes));
            _summary.RowCount += batch.Count;
            _summary.MinQpc = _summary.MinQpc.HasValue ? Math.Min(_summary.MinQpc.Value, minQ) : minQ;
            _summary.MaxQpc = _summary.MaxQpc.HasValue ? Math.Max(_summary.MaxQpc.Value, maxQ) : maxQ;
            partIndex++;
            // Release the batch reference so the rows can be GC'd while we
            // wait for the next batch.
            batch.Clear();
        }
    }
}
