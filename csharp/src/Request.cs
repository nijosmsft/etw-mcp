using System.Text.Json;
using System.Text.Json.Serialization;

namespace WprMcpExtract;

internal sealed class Request
{
    [JsonPropertyName("version")] public int Version { get; init; }
    [JsonPropertyName("trace_id")] public string TraceId { get; init; } = "";
    [JsonPropertyName("etl_path")] public string EtlPath { get; init; } = "";
    [JsonPropertyName("staging_dir")] public string StagingDir { get; init; } = "";
    [JsonPropertyName("strategy")] public string Strategy { get; init; } = "";
    [JsonPropertyName("requested_event_classes")] public List<string> RequestedEventClasses { get; init; } = new();
    [JsonPropertyName("symbol_path")] public string? SymbolPath { get; init; }
    [JsonPropertyName("max_etl_mb")] public int MaxEtlMb { get; init; } = 2048;
    [JsonPropertyName("heartbeat_interval_ms")] public int HeartbeatIntervalMs { get; init; } = 1000;
    [JsonPropertyName("log_level")] public string LogLevel { get; init; } = "info";
    [JsonPropertyName("panic_probe")] public string? PanicProbe { get; init; }
    [JsonPropertyName("include_tracelogging")] public bool IncludeTracelogging { get; init; }
}

internal sealed record RequestValidation(bool Ok, string? FailureKind = null, string? Error = null)
{
    public static RequestValidation Success() => new(true);
    public static RequestValidation Fail(string kind, string err) => new(false, kind, err);
}

internal static class RequestLoader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        AllowTrailingCommas = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        PropertyNameCaseInsensitive = true,
    };

    public static (Request? req, RequestValidation v) Load(string path)
    {
        try
        {
            var raw = File.ReadAllText(path);
            var req = JsonSerializer.Deserialize<Request>(raw, Options);
            if (req == null)
                return (null, RequestValidation.Fail("bad-request", "request JSON deserialized to null"));
            var v = Validate(req);
            return v.Ok ? (req, v) : (null, v);
        }
        catch (FileNotFoundException ex)
        {
            return (null, RequestValidation.Fail("bad-request", $"request file not found: {ex.Message}"));
        }
        catch (JsonException ex)
        {
            return (null, RequestValidation.Fail("bad-request", $"invalid request JSON: {ex.Message}"));
        }
        catch (Exception ex)
        {
            return (null, RequestValidation.Fail("bad-request", $"failed to read request: {ex.Message}"));
        }
    }

    private static RequestValidation Validate(Request r)
    {
        if (r.Version != 1)
            return RequestValidation.Fail("bad-request", $"version must be 1, got {r.Version}");
        if (string.IsNullOrWhiteSpace(r.TraceId))
            return RequestValidation.Fail("bad-request", "trace_id is required");
        if (string.IsNullOrWhiteSpace(r.EtlPath))
            return RequestValidation.Fail("bad-request", "etl_path is required");
        if (!Path.IsPathRooted(r.EtlPath))
            return RequestValidation.Fail("bad-request", "etl_path must be absolute");
        if (string.IsNullOrWhiteSpace(r.StagingDir))
            return RequestValidation.Fail("bad-request", "staging_dir is required");
        if (!Path.IsPathRooted(r.StagingDir))
            return RequestValidation.Fail("bad-request", "staging_dir must be absolute");
        if (r.Strategy != "materialized-small" && r.Strategy != "event-store-streaming")
            return RequestValidation.Fail("bad-request", $"unsupported strategy: {r.Strategy}");
        if (r.HeartbeatIntervalMs is < 250 or > 30000)
            return RequestValidation.Fail("bad-request", $"heartbeat_interval_ms out of range: {r.HeartbeatIntervalMs}");
        if (r.RequestedEventClasses == null || r.RequestedEventClasses.Count == 0)
            return RequestValidation.Fail("bad-request", "requested_event_classes must be non-empty");
        return RequestValidation.Success();
    }
}
