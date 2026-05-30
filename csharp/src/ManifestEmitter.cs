using System.Text;
using System.Text.Json;

namespace WprMcpExtract;

internal static class ManifestEmitter
{
    public static long WriteCacheManifest(string stagingDir, string etlPath, string strategy, IReadOnlyList<DatasetEntry> datasets, bool complete)
    {
        var etlInfo = new FileInfo(etlPath);
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
                mtime_ns = etlInfo.LastWriteTimeUtc.Ticks * 100,  // ticks→ns (100ns/tick)
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
            native_store = (object?)null,
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
