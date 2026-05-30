using System.Text;
using System.Text.Json;
using Parquet;
using Parquet.Data;
using Parquet.Schema;
using WprMcpExtract.Rows;

namespace WprMcpExtract;

/// <summary>
/// Writes the <c>event-store-streaming</c> strategy layout per spike-contract
/// §8 / §9.2: chunked per-class parquets under
/// <c>native-store/generations/&lt;run_id&gt;/events/&lt;class&gt;/part-NNNN.parquet</c>
/// plus a <c>native-event-store-manifest.json</c>. Defaults match the Python
/// <c>sinks.py</c> (256 000 rows or 128 MiB per part).
/// </summary>
internal static class EventStoreEmitter
{
    public const int DefaultMaxRowsPerPart = 256_000;
    public const long DefaultMaxBytesPerPart = 128L * 1024L * 1024L;
    public const int StoreSchemaVersion = 1;

    public sealed record PartInfo(string RelativePath, long RowCount, long? MinQpc, long? MaxQpc, long ByteSize);

    public sealed class DatasetSummary
    {
        public string Name = "";
        public long RowCount;
        public long? MinQpc;
        public long? MaxQpc;
        public readonly List<PartInfo> Parts = new();
    }

    /// <summary>
    /// Emit every non-empty buffer as a chunked dataset. Returns the
    /// dataset-level summary and the generation directory used.
    /// </summary>
    public static async Task<(List<DatasetSummary> datasets, string runId, string generationDir, long totalBytes)>
        WriteAllAsync(EventCollector ec, string stagingDir, long qpcOrigin, double perfFreq)
    {
        var runId = Guid.NewGuid().ToString("N");
        var generationDir = Path.Combine(stagingDir, "native-store", "generations", runId);
        var eventsDir = Path.Combine(generationDir, "events");
        Directory.CreateDirectory(eventsDir);

        var summaries = new List<DatasetSummary>();
        long total = 0;

        // Paired (stack) classes.
        total += await ChunkParquetAsync("sampled_profile", ec.SampledProfile, eventsDir, summaries,
            r => r.TimeStampQpc, ParquetEmitter.WriteSampledProfileAsync);
        total += await ChunkParquetAsync("cswitch_events", ec.CSwitch, eventsDir, summaries,
            r => r.TimeStampQpc, ParquetEmitter.WriteCSwitchAsync);
        total += await ChunkParquetAsync("readythread", ec.ReadyThread, eventsDir, summaries,
            r => r.TimeStampQpc, ParquetEmitter.WriteReadyThreadAsync);

        // Network flow classes.
        total += await ChunkParquetAsync("tcpip_recv", ec.TcpipRecv, eventsDir, summaries,
            r => r.TimeStampQpc, ParquetEmitter.WriteTcpipRecvAsync);
        total += await ChunkFlowAsync("tcpip_send",        ec.TcpipSend,        eventsDir, summaries);
        total += await ChunkFlowAsync("tcpip_connect",     ec.TcpipConnect,     eventsDir, summaries);
        total += await ChunkFlowAsync("tcpip_accept",      ec.TcpipAccept,      eventsDir, summaries);
        total += await ChunkFlowAsync("tcpip_retransmit",  ec.TcpipRetransmit,  eventsDir, summaries);
        total += await ChunkFlowAsync("tcpip_disconnect",  ec.TcpipDisconnect,  eventsDir, summaries);
        total += await ChunkFlowAsync("udp_recv",          ec.UdpRecv,          eventsDir, summaries);
        total += await ChunkFlowAsync("udp_send",          ec.UdpSend,          eventsDir, summaries);

        // AFD.
        total += await ChunkParquetAsync("afd_recv", ec.AfdRecv, eventsDir, summaries,
            r => r.TimeStampQpc, ParquetEmitter.WriteAfdRecvAsync);
        total += await ChunkAfdAsync("afd_send",    ec.AfdSend,    eventsDir, summaries);
        total += await ChunkAfdAsync("afd_connect", ec.AfdConnect, eventsDir, summaries);
        total += await ChunkAfdAsync("afd_accept",  ec.AfdAccept,  eventsDir, summaries);
        total += await ChunkAfdAsync("afd_close",   ec.AfdClose,   eventsDir, summaries);
        total += await ChunkAfdAsync("afd_bind",    ec.AfdBind,    eventsDir, summaries);

        // NDIS.
        total += await ChunkParquetAsync("ndis_drops", ec.NdisDrops, eventsDir, summaries,
            r => r.TimeStampQpc, ParquetEmitter.WriteNdisDropsAsync);
        total += await ChunkParquetAsync("packet_capture", ec.NdisPacketCapture, eventsDir, summaries,
            r => r.TimeStampQpc, ParquetEmitter.WriteNdisPacketCaptureAsync);

        // HTTP.
        total += await ChunkHttpAsync("http_recv",    ec.HttpRecv,    eventsDir, summaries);
        total += await ChunkHttpAsync("http_deliver", ec.HttpDeliver, eventsDir, summaries);
        total += await ChunkHttpAsync("http_send",    ec.HttpSend,    eventsDir, summaries);
        total += await ChunkHttpAsync("http_close",   ec.HttpClose,   eventsDir, summaries);

        // MsQuic.
        total += await ChunkQuicAsync("quic_conn_created", ec.QuicConnCreated, eventsDir, summaries);
        total += await ChunkQuicAsync("quic_conn_closed",  ec.QuicConnClosed,  eventsDir, summaries);
        total += await ChunkQuicAsync("quic_packet_recv",  ec.QuicPacketRecv,  eventsDir, summaries);
        total += await ChunkQuicAsync("quic_packet_send",  ec.QuicPacketSend,  eventsDir, summaries);
        total += await ChunkQuicAsync("quic_ack_recv",     ec.QuicAckReceived, eventsDir, summaries);

        // Kernel meta.
        if (ec.Process.Count > 0)
            total += await ChunkParquetAsync("process", ec.Process, eventsDir, summaries,
                r => r.TimeStampQpc, ParquetEmitter.WriteProcessAsync);
        if (ec.Image.Count > 0)
            total += await ChunkParquetAsync("image", ec.Image, eventsDir, summaries,
                r => r.TimeStampQpc, ParquetEmitter.WriteImageAsync);
        if (ec.DiskIo.Count > 0)
            total += await ChunkParquetAsync("diskio", ec.DiskIo, eventsDir, summaries,
                r => r.TimeStampQpc, ParquetEmitter.WriteDiskIoAsync);
        if (ec.DpcIsr.Count > 0)
            total += await ChunkParquetAsync("dpc_isr", ec.DpcIsr, eventsDir, summaries,
                r => r.TimeStampQpc, ParquetEmitter.WriteDpcIsrAsync);

        // Sub-manifest at the generation root.
        var manifestPath = Path.Combine(generationDir, "native-event-store-manifest.json");
        WriteSubManifest(manifestPath, runId, qpcOrigin, perfFreq, summaries);
        total += new FileInfo(manifestPath).Length;

        return (summaries, runId, generationDir, total);
    }

    // ----- chunk-rotation helpers -----

    /// <summary>
    /// Slice a row buffer into part-NNNN.parquet files honoring the row/byte
    /// caps. The caller-supplied <paramref name="writer"/> writes one slice
    /// to one path; we measure file size to enforce the byte cap on the
    /// *next* rotation decision.
    /// </summary>
    private static async Task<long> ChunkParquetAsync<T>(
        string name,
        List<T> rows,
        string eventsDir,
        List<DatasetSummary> summaries,
        Func<T, long> qpcSelector,
        Func<List<T>, string, Task<long>> writer)
    {
        var summary = new DatasetSummary { Name = name, RowCount = rows.Count };
        summaries.Add(summary);
        if (rows.Count == 0) return 0;

        var dir = Path.Combine(eventsDir, name);
        Directory.CreateDirectory(dir);

        long totalBytes = 0;
        int partIndex = 0;
        int cursor = 0;
        long? overallMin = null, overallMax = null;
        while (cursor < rows.Count)
        {
            int take = Math.Min(DefaultMaxRowsPerPart, rows.Count - cursor);
            var slice = rows.GetRange(cursor, take);
            long minQpc = qpcSelector(slice[0]);
            long maxQpc = qpcSelector(slice[^1]);
            for (int i = 1; i < slice.Count; i++)
            {
                var v = qpcSelector(slice[i]);
                if (v < minQpc) minQpc = v;
                if (v > maxQpc) maxQpc = v;
            }
            var partRel = $"events/{name}/part-{partIndex:D4}.parquet";
            var partPath = Path.Combine(eventsDir, "..", partRel);
            partPath = Path.GetFullPath(partPath);
            long bytes = await writer(slice, partPath);
            totalBytes += bytes;
            summary.Parts.Add(new PartInfo(partRel, slice.Count, minQpc, maxQpc, bytes));
            overallMin = overallMin.HasValue ? Math.Min(overallMin.Value, minQpc) : minQpc;
            overallMax = overallMax.HasValue ? Math.Max(overallMax.Value, maxQpc) : maxQpc;
            cursor += take;
            partIndex++;
        }
        summary.MinQpc = overallMin;
        summary.MaxQpc = overallMax;
        return totalBytes;
    }

    private static Task<long> ChunkFlowAsync(string name, List<NetworkFlowRow> rows, string eventsDir, List<DatasetSummary> summaries)
        => ChunkParquetAsync(name, rows, eventsDir, summaries, r => r.TimeStampQpc, ParquetEmitter.WriteFlowAsync);

    private static Task<long> ChunkAfdAsync(string name, List<AfdEventRow> rows, string eventsDir, List<DatasetSummary> summaries)
        => ChunkParquetAsync(name, rows, eventsDir, summaries, r => r.TimeStampQpc, ParquetEmitter.WriteAfdEventAsync);

    private static Task<long> ChunkHttpAsync(string name, List<HttpRow> rows, string eventsDir, List<DatasetSummary> summaries)
        => ChunkParquetAsync(name, rows, eventsDir, summaries, r => r.TimeStampQpc, ParquetEmitter.WriteHttpAsync);

    private static Task<long> ChunkQuicAsync(string name, List<QuicRow> rows, string eventsDir, List<DatasetSummary> summaries)
        => ChunkParquetAsync(name, rows, eventsDir, summaries, r => r.TimeStampQpc, ParquetEmitter.WriteQuicAsync);

    private static void WriteSubManifest(string path, string runId, long qpcOrigin, double perfFreq, List<DatasetSummary> summaries)
    {
        var manifest = new
        {
            schema_version = StoreSchemaVersion,
            run_id = runId,
            created_utc = DateTime.UtcNow.ToString("O"),
            timebase = new
            {
                qpc_origin = qpcOrigin == 0 ? (long?)null : qpcOrigin,
                perf_freq = perfFreq == 0.0 ? (double?)null : perfFreq,
            },
            datasets = summaries.Select(s => new
            {
                name = s.Name,
                schema_version = StoreSchemaVersion,
                row_count = s.RowCount,
                min_qpc = s.MinQpc,
                max_qpc = s.MaxQpc,
                parts = s.Parts.Select(p => new
                {
                    path = p.RelativePath,
                    row_count = p.RowCount,
                    min_qpc = p.MinQpc,
                    max_qpc = p.MaxQpc,
                    byte_size = p.ByteSize,
                }).ToArray(),
            }).ToArray(),
        };
        var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
        });
        File.WriteAllText(path, json, new UTF8Encoding(false));
    }
}
