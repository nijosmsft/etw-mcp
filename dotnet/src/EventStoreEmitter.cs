using System.Text;
using System.Text.Json;
using Parquet;
using Parquet.Data;
using Parquet.Schema;
using EtwExtract.Rows;

namespace EtwExtract;

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
    /// Awaits every streaming sink configured on <paramref name="ec"/>,
    /// then writes the sub-manifest at the generation root. In the new
    /// streaming-channels model the actual chunked parquet parts are
    /// written CONCURRENTLY with ProcessTrace by the per-class
    /// <see cref="StreamingChunkSink{T}"/> background tasks, so this
    /// method is purely a drain + manifest step.
    ///
    /// <paramref name="ec"/> must have been switched into streaming mode
    /// via <see cref="EventCollector.ConfigureStreaming"/> with the same
    /// generation directory that <paramref name="generationDir"/> points
    /// to here (i.e. the caller must allocate the run id up-front, pass
    /// it to <c>ConfigureStreaming</c> via <c>events/</c> subpath, and
    /// pass it back in here).
    /// </summary>
    public static async Task<(List<DatasetSummary> datasets, string runId, string generationDir, long totalBytes)>
        WriteAllAsync(EventCollector ec, string stagingDir, long qpcOrigin, double perfFreq, string runId, string generationDir)
    {
        var summaries = await ec.CompleteAllStreamingAsync().ConfigureAwait(false);

        // Match the pre-D2 behaviour: kernel-meta datasets (process / image
        // / diskio / dpc_isr) only appear in the sub-manifest when they
        // have rows. The AFD / TCP / UDP / QUIC / HTTP / NDIS / paired
        // datasets are always included (possibly empty) — also matching
        // the old EventStoreEmitter.ChunkParquetAsync contract.
        var kernelMeta = new HashSet<string>(StringComparer.Ordinal)
            { "process", "image", "diskio", "dpc_isr" };
        summaries = summaries.Where(s => !(kernelMeta.Contains(s.Name) && s.RowCount == 0)).ToList();

        long total = summaries.Sum(s => s.Parts.Sum(p => p.ByteSize));

        var manifestPath = Path.Combine(generationDir, "native-event-store-manifest.json");
        WriteSubManifest(manifestPath, runId, qpcOrigin, perfFreq, summaries);
        total += new FileInfo(manifestPath).Length;
        return (summaries, runId, generationDir, total);
    }

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
