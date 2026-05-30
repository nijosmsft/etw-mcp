using System.Text;
using System.Text.Json;

namespace WprMcpExtract;

internal static class ManifestEmitter
{
    /// <summary>
    /// Write the top-level cache manifest at <paramref name="stagingDir"/>/wpr-mcp-cache-manifest.json.
    /// Schema version 3 — adds the <c>producer</c> field per spike-contract §7.
    /// </summary>
    /// <param name="stagingDir">Absolute staging directory.</param>
    /// <param name="etlPath">Absolute path to the source ETL.</param>
    /// <param name="strategy">"materialized-small" or "event-store-streaming".</param>
    /// <param name="datasets">Datasets to advertise.</param>
    /// <param name="complete">Whether the extraction succeeded.</param>
    /// <param name="runId">Generation ID for event-store-streaming (null = flat).</param>
    /// <param name="qpcOrigin">QPC tick of first event (0 = unknown).</param>
    /// <param name="perfFreq">QueryPerformanceFrequency (0 = unknown).</param>
    public static long WriteCacheManifest(
        string stagingDir,
        string etlPath,
        string strategy,
        IReadOnlyList<DatasetEntry> datasets,
        bool complete,
        string? runId = null,
        long qpcOrigin = 0,
        double perfFreq = 0.0)
    {
        var etlInfo = new FileInfo(etlPath);
        object? nativeStore = runId == null
            ? new { generation_id = "flat", path = "." }
            : new { generation_id = runId, path = "." };

        var manifest = new
        {
            schema_version = 3,
            mode = "native",
            producer = "csharp",
            strategy,
            complete,
            etl = new
            {
                path = Path.GetFullPath(etlPath),
                name = etlInfo.Name,
                size = etlInfo.Length,
                mtime_ns = etlInfo.LastWriteTimeUtc.Ticks * 100,  // ticks → ns (100ns/tick)
            },
            datasets = datasets.Select(d => new
            {
                name = d.Name,
                kind = d.Kind,
                path = d.Path,
                schema_version = d.SchemaVersion,
                row_count = d.RowCount,
                materialize_on_load = d.MaterializeOnLoad,
            }).ToArray(),
            timebase = new
            {
                qpc_origin = qpcOrigin == 0 ? (long?)null : qpcOrigin,
                perf_freq = perfFreq == 0.0 ? (double?)null : perfFreq,
            },
            native_store = nativeStore,
        };
        var path = Path.Combine(stagingDir, "wpr-mcp-cache-manifest.json");
        var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
        });
        File.WriteAllText(path, json, new UTF8Encoding(false));
        return new FileInfo(path).Length;
    }
}

internal sealed record DatasetEntry(string Name, string Kind, string Path, int SchemaVersion, long? RowCount, bool MaterializeOnLoad);
