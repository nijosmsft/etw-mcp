using System.Text;
using System.Text.Json;

namespace EtwExtract;

internal static class ManifestEmitter
{
    /// <summary>
    /// Reference instant for the manifest's <c>mtime_ns</c> field. Kept here
    /// (rather than via <c>DateTime.UnixEpoch</c>) so the intent is obvious
    /// at the call site and so the arithmetic stays in <c>DateTimeKind.Utc</c>.
    /// </summary>
    private static readonly DateTime UnixEpochUtc = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>
    /// Write the sidecar's non-final manifest at <paramref name="stagingDir"/>/wpr-mcp-cache-manifest.json.
    /// Python aggregation owns the final complete manifest and writes it last.
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
            schema_version = 4,
            mode = "native",
            producer = "dotnet",
            strategy,
            complete,
            finalized = complete,
            // event_schema_version MUST track schemas.py::EVENT_SCHEMA_VERSION.
            // Bumped 3 -> 4 when Image/DCEnd (kernel stop-rundown) was added to
            // the image set so kernel sample addresses resolve to real modules.
            event_schema_version = 4,
            finalizer = complete ? "dotnet-sidecar" : (string?)null,
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
        // NOTE: The manifest filename intentionally retains the "wpr-mcp-"
        // prefix even after the v0.4 etw-mcp rename. The Python loader keys
        // user cache discovery off this exact filename
        // (see src/etw_analyzer/native/cache.py:MANIFEST_FILENAME); renaming
        // it would invalidate every user's on-disk extracted-parquet cache.
        var path = Path.Combine(stagingDir, "wpr-mcp-cache-manifest.json");
        var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
        });
        var tmpPath = Path.Combine(
            stagingDir,
            $"wpr-mcp-cache-manifest.json.tmp.{Environment.ProcessId}.{Guid.NewGuid():N}");
        try
        {
            using (var stream = new FileStream(
                tmpPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
            {
                writer.Write(json);
                writer.WriteLine();
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }
            File.Move(tmpPath, path, overwrite: true);
        }
        finally
        {
            try
            {
                if (File.Exists(tmpPath))
                    File.Delete(tmpPath);
            }
            catch { /* best effort cleanup */ }
        }
        return new FileInfo(path).Length;
    }
}

internal sealed record DatasetEntry(string Name, string Kind, string Path, int SchemaVersion, long? RowCount, bool MaterializeOnLoad);
