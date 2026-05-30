using System.Diagnostics;
using WprMcpExtract;

var emit = new JsonlEmitter();
var startTime = Stopwatch.StartNew();
string phase = "reading-request";
long eventsAtFailure = 0;
const string ProducerVersion = "0.1.0-spike";
const string Producer = "csharp";

void EmitFailure(string failureKind, string error, string? tracebackTail = null)
{
    emit.Emit(new
    {
        type = "result",
        time = UnixTime.Now,
        ok = false,
        producer = Producer,
        producer_version = ProducerVersion,
        failure_kind = failureKind,
        error,
        traceback_tail = tracebackTail,
        phase_at_failure = phase,
        events_decoded_at_failure = eventsAtFailure,
    });
}

// ---- Parse CLI args ------------------------------------------------------
string? requestPath = null;
try
{
    for (int i = 0; i < args.Length; i++)
    {
        if (args[i] == "--request" && i + 1 < args.Length)
        {
            requestPath = args[++i];
        }
        else
        {
            EmitFailure("bad-args", $"unrecognized argument: {args[i]}");
            return 1;
        }
    }
    if (requestPath == null)
    {
        EmitFailure("bad-args", "missing --request <path>");
        return 1;
    }
}
catch (Exception ex)
{
    EmitFailure("csharp_exception", ex.Message, ex.StackTrace);
    return 1;
}

// ---- Load + validate request --------------------------------------------
Request? req;
try
{
    var (loaded, v) = RequestLoader.Load(requestPath);
    if (!v.Ok)
    {
        EmitFailure(v.FailureKind ?? "bad-request", v.Error ?? "bad request");
        return 1;
    }
    req = loaded!;
}
catch (Exception ex)
{
    EmitFailure("csharp_exception", ex.Message, ex.StackTrace);
    return 1;
}

// ---- Pre-flight checks ---------------------------------------------------
try
{
    phase = "reading-request";
    if (!File.Exists(req.EtlPath))
    {
        EmitFailure("etl-missing", $"etl_path does not exist: {req.EtlPath}");
        return 1;
    }
    var size = new FileInfo(req.EtlPath).Length;
    var sizeMb = size / (1024.0 * 1024.0);
    if (sizeMb > req.MaxEtlMb)
    {
        EmitFailure("etl-too-large", $"etl is {sizeMb:F1} MB > max {req.MaxEtlMb} MB");
        return 1;
    }
    try
    {
        Directory.CreateDirectory(req.StagingDir);
    }
    catch (Exception ex)
    {
        EmitFailure("staging-error", $"cannot create staging_dir: {ex.Message}");
        return 1;
    }
    // Probe write permission.
    var probe = Path.Combine(req.StagingDir, ".write-probe");
    try { File.WriteAllText(probe, ""); File.Delete(probe); }
    catch (Exception ex)
    {
        EmitFailure("staging-error", $"staging_dir not writable: {ex.Message}");
        return 1;
    }

    // open_trace_panic probe — fires before OpenTraceW.
    if (req.PanicProbe == "open_trace_panic")
        throw new InvalidOperationException("panic_probe=open_trace_panic triggered");
}
catch (InvalidOperationException ex) when (req.PanicProbe == "open_trace_panic")
{
    EmitFailure("csharp_exception", ex.Message, ex.StackTrace);
    return 1;
}
catch (Exception ex)
{
    EmitFailure("csharp_exception", ex.Message, ex.StackTrace);
    return 1;
}

// ---- Run the extractor --------------------------------------------------
var runner = new ExtractRunner(req, emit);
try
{
    phase = "opening-trace";
    emit.Heartbeat(phase);
    phase = "decoding";
    runner.Run();
}
catch (Exception ex)
{
    eventsAtFailure = runner.Collector.EventsDecoded;
    EmitFailure("csharp_exception", $"{ex.GetType().Name}: {ex.Message}", ex.StackTrace);
    // Defense in depth: don't leave .tmp files behind.
    try
    {
        foreach (var f in Directory.EnumerateFiles(req.StagingDir, "*.tmp"))
            try { File.Delete(f); } catch { /* swallow */ }
    }
    catch { /* swallow */ }
    return 1;
}

// ---- Write outputs ------------------------------------------------------
long parquetBytes = 0;
long sysconfigBytes = 0;
long manifestBytes = 0;
try
{
    phase = "writing-parquet";
    emit.Heartbeat(phase);
    parquetBytes = await ParquetEmitter.WriteAllAsync(runner.Collector, req.StagingDir);

    phase = "writing-parquet";
    sysconfigBytes = runner.Sysconfig.WriteFile(req.StagingDir);

    phase = "writing-manifest";
    emit.Heartbeat(phase);

    // manifest_write_panic probe fires here.
    if (req.PanicProbe == "manifest_write_panic")
        throw new InvalidOperationException("panic_probe=manifest_write_panic triggered");

    var datasets = new List<DatasetEntry>
    {
        new("sampled_profile", "parquet", "sampled_profile.parquet", 1, runner.Collector.SampledProfile.Count, true),
        new("cswitch",         "parquet", "cswitch.parquet",         1, runner.Collector.CSwitch.Count,         true),
        new("readythread",     "parquet", "readythread.parquet",     1, runner.Collector.ReadyThread.Count,     true),
        new("tcpip_recv",      "parquet", "tcpip_recv.parquet",      1, runner.Collector.TcpipRecv.Count,       true),
        new("afd_recv",        "parquet", "afd_recv.parquet",        1, runner.Collector.AfdRecv.Count,         true),
        new("ndis_drops",      "parquet", "ndis_drops.parquet",      1, runner.Collector.NdisDrops.Count,       true),
        new("sysconfig",       "text",    "sysconfig.txt",           1, 1,                                       true),
    };
    if (req.IncludeTracelogging && runner.Collector.Tracelogging.Count > 0)
        datasets.Add(new("tracelogging_events", "parquet", "tracelogging_events.parquet", 1, runner.Collector.Tracelogging.Count, true));
    manifestBytes = ManifestEmitter.WriteCacheManifest(req.StagingDir, req.EtlPath, req.Strategy, datasets, complete: true);
}
catch (Exception ex)
{
    eventsAtFailure = runner.Collector.EventsDecoded;
    var kind = phase switch
    {
        "writing-parquet" => "parquet-error",
        "writing-manifest" => req.PanicProbe == "manifest_write_panic" ? "csharp_exception" : "manifest-error",
        _ => "csharp_exception",
    };
    EmitFailure(kind, $"{ex.GetType().Name}: {ex.Message}", ex.StackTrace);
    return 1;
}

// ---- Emit success result ------------------------------------------------
startTime.Stop();
var wall = startTime.Elapsed.TotalSeconds;
double eps = wall > 0 ? runner.Collector.EventsDecoded / wall : 0.0;
double stackRate = runner.Collector.StackEligibleEvents > 0
    ? (double)runner.Collector.StacksPaired / runner.Collector.StackEligibleEvents
    : 0.0;
double peakRssMb;
try
{
    using var proc = Process.GetCurrentProcess();
    proc.Refresh();
    peakRssMb = proc.PeakWorkingSet64 / (1024.0 * 1024.0);
}
catch { peakRssMb = 0.0; }

emit.Emit(new
{
    type = "result",
    time = UnixTime.Now,
    ok = true,
    producer = Producer,
    producer_version = ProducerVersion,
    trace_id = req.TraceId,
    staging_dir = req.StagingDir,
    strategy = req.Strategy,
    manifest = "wpr-mcp-cache-manifest.json",
    datasets = req.IncludeTracelogging && runner.Collector.Tracelogging.Count > 0
        ? new[] { "sampled_profile", "cswitch", "readythread", "tcpip_recv", "afd_recv", "ndis_drops", "sysconfig", "tracelogging_events" }
        : new[] { "sampled_profile", "cswitch", "readythread", "tcpip_recv", "afd_recv", "ndis_drops", "sysconfig" },
    event_counts = new Dictionary<string, long>
    {
        ["SampledProfile"] = runner.Collector.SampledProfile.Count,
        ["CSwitch"] = runner.Collector.CSwitch.Count,
        ["ReadyThread"] = runner.Collector.ReadyThread.Count,
        ["TcpIp/Recv"] = runner.Collector.TcpipRecv.Count,
        ["AFD/Recv"] = runner.Collector.AfdRecv.Count,
        ["NdisDrop"] = runner.Collector.NdisDrops.Count,
        ["SystemConfig"] = runner.Sysconfig.Nics.Count + runner.Sysconfig.Disks.Count + 1,
        ["TraceLogging"] = runner.Collector.Tracelogging.Count,
    },
    performance = new
    {
        wall_seconds = Math.Round(wall, 3),
        events_per_second = Math.Round(eps, 1),
        peak_rss_mb = Math.Round(peakRssMb, 1),
        stack_pairing_rate = Math.Round(stackRate, 6),
        symbols_resolved = 0,
        symbols_unresolved = 0,
        parquet_bytes_written = parquetBytes + sysconfigBytes,
        events_lost = runner.EventsLost,
        manifest_bytes = manifestBytes,
        stack_eligible_events = runner.Collector.StackEligibleEvents,
        stacks_paired = runner.Collector.StacksPaired,
        pending_evictions = runner.Collector.Pending.Evictions,
        callback_exceptions = runner.Collector.CallbackExceptions,
    },
});
return 0;
