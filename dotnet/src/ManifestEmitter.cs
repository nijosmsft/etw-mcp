using System.Text;
using System.Text.Json;

namespace WprMcpExtract;

internal static class ManifestEmitter
{
    /// <summary>
    /// Reference instant for the manifest's <c>mtime_ns</c> field. Kept here
    /// (rather than via <c>DateTime.UnixEpoch</c>) so the intent is obvious
    /// at the call site and so the arithmetic stays in <c>DateTimeKind.Utc</c>.
    /// </summary>
    private static readonly DateTime UnixEpochUtc = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

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
                // Must match Python's `int(Path(etl).stat().st_mtime_ns)` exactly
                // (nanoseconds since the Unix epoch, 1970-01-01T00:00:00Z).
                //
                // .NET DateTime.Ticks counts 100-ns intervals from 0001-01-01.
                // Subtracting the Unix-epoch reference gives ticks since 1970,
                // and multiplying by 100 converts to nanoseconds. The arithmetic
                // is integer-exact (no rounding) for any datetime FileInfo can
                // produce, and matches Python's BCL stat() output bit-for-bit.
                //
                // The Python side currently carries an `EtlIdentity.matches_loose()`
                // workaround for the prior (year-0001) encoding; that shim will be
                // removed in a follow-up Python-side change (P2 scope).
                mtime_ns = (etlInfo.LastWriteTimeUtc - UnixEpochUtc).Ticks * 100,
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
