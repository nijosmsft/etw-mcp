using System.Text.Json;

namespace WprMcpExtract;

/// <summary>
/// Thread-safe JSONL writer to stdout. The spike contract reserves stdout
/// exclusively for line-delimited JSON; diagnostic logging goes to stderr.
/// </summary>
internal sealed class JsonlEmitter
{
    private readonly object _lock = new();
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public void Emit(object payload)
    {
        var json = JsonSerializer.Serialize(payload, Options);
        lock (_lock)
        {
            Console.Out.Write(json);
            Console.Out.Write('\n');
            Console.Out.Flush();
        }
    }

    public void Heartbeat(string phase)
        => Emit(new { type = "heartbeat", time = UnixTime.Now, phase });

    public void Progress(string phase, long eventsDecoded, long stacksPaired, long bytesProcessed, long? eventsLost = null)
        => Emit(new
        {
            type = "progress",
            time = UnixTime.Now,
            phase,
            events_decoded = eventsDecoded,
            stacks_paired = stacksPaired,
            bytes_processed = bytesProcessed,
            events_lost = eventsLost,
        });

    public void Log(string level, string module, string message)
    {
        var line = $"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss.fffZ} {level,-5} {module}: {message}";
        try { Console.Error.WriteLine(line); } catch { /* swallow */ }
    }
}

internal static class UnixTime
{
    private static readonly DateTime Epoch = new(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    public static double Now => (DateTime.UtcNow - Epoch).TotalSeconds;
}
