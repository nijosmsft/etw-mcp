using System.Diagnostics;
using EtwExtract;

var emit = new JsonlEmitter();
var startTime = Stopwatch.StartNew();
string phase = "reading-request";
long eventsAtFailure = 0;
const string ProducerVersion = "0.1.0-spike";
const string Producer = "dotnet";

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
bool? cliIncludeTracelogging = null;  // null = unset, takes default from request.json
try
{
    for (int i = 0; i < args.Length; i++)
    {
        if (args[i] == "--request" && i + 1 < args.Length)
        {
            requestPath = args[++i];
        }
        else if (args[i] == "--include-tracelogging")
        {
            cliIncludeTracelogging = true;
        }
        else if (args[i] == "--no-include-tracelogging")
        {
            cliIncludeTracelogging = false;
        }
        else if (args[i] == "--help" || args[i] == "-h")
        {
            Console.Error.WriteLine("etw-extract --request <path> [--include-tracelogging|--no-include-tracelogging]");
            Console.Error.WriteLine("  Per spike-contract §2.2 the only required flag is --request.");
            Console.Error.WriteLine("  --include-tracelogging (default: true) writes a generic TraceLogging");
            Console.Error.WriteLine("  passthrough parquet for self-describing providers not routed to a");
            Console.Error.WriteLine("  typed buffer; --no-include-tracelogging disables it.");
            return 0;
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
    EmitFailure("dotnet_exception", ex.Message, ex.StackTrace);
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
    if (cliIncludeTracelogging.HasValue)
        req.IncludeTracelogging = cliIncludeTracelogging.Value;
}
catch (Exception ex)
{
    EmitFailure("dotnet_exception", ex.Message, ex.StackTrace);
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
    EmitFailure("dotnet_exception", ex.Message, ex.StackTrace);
    return 1;
}
catch (Exception ex)
{
    EmitFailure("dotnet_exception", ex.Message, ex.StackTrace);
    return 1;
}

// ---- Run the extractor --------------------------------------------------
var runner = new ExtractRunner(req, emit);

// For event-store-streaming we must allocate the run id and wire the
// per-class chunk sinks BEFORE ProcessTrace fires any callbacks, so that
// each Add() goes straight into the bounded-queue rotator instead of
// accumulating in a flat List<T>. Materialized strategies leave the
// collector in its default in-memory mode (no behavior change).
string? streamingRunIdAllocated = null;
string? streamingGenDir = null;
if (req.Strategy == "event-store-streaming")
{
    streamingRunIdAllocated = Guid.NewGuid().ToString("N");
    streamingGenDir = Path.Combine(req.StagingDir, "native-store", "generations", streamingRunIdAllocated);
    var eventsDir = Path.Combine(streamingGenDir, "events");
    runner.Collector.ConfigureStreaming(
        eventsDir,
        chunkSize: EventStoreEmitter.DefaultMaxRowsPerPart,
        queueCapacity: 2);
}

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
    EmitFailure("dotnet_exception", $"{ex.GetType().Name}: {ex.Message}", ex.StackTrace);
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
var datasets = new List<DatasetEntry>();
string? streamingRunId = null;
try
{
    phase = "writing-parquet";
    emit.Heartbeat(phase);

    if (req.Strategy == "event-store-streaming")
    {
        // Chunked per-class parquets under
        // <staging>/native-store/generations/<run_id>/events/<class>/part-NNNN.parquet
        // plus native-event-store-manifest.json at the generation root.
        // The chunk writes happened CONCURRENTLY with ProcessTrace via the
        // streaming sinks; this call just drains them and writes the manifest.
        var (storeDatasets, runId, genDir, storeBytes) =
            await EventStoreEmitter.WriteAllAsync(
                runner.Collector, req.StagingDir, runner.QpcOrigin, runner.PerfFreq,
                streamingRunIdAllocated!, streamingGenDir!);
        streamingRunId = runId;
        parquetBytes = storeBytes;
        long totalRows = storeDatasets.Sum(d => d.RowCount);
        var relManifest = Path.Combine("native-store", "generations", runId, "native-event-store-manifest.json")
            .Replace('\\', '/');
        datasets.Add(new("native_event_store", "native-event-store", relManifest, 1, totalRows, false));
    }
    else
    {
        parquetBytes = await ParquetEmitter.WriteAllAsync(runner.Collector, req.StagingDir);
        datasets.AddRange(new[]
        {
            new DatasetEntry("sampled_profile",  "parquet", "sampled_profile.parquet",  1, runner.Collector.SampledProfile.Count, true),
            new DatasetEntry("cswitch_events",   "parquet", "cswitch_events.parquet",   1, runner.Collector.CSwitch.Count,        true),
            new DatasetEntry("readythread",      "parquet", "readythread.parquet",      1, runner.Collector.ReadyThread.Count,    true),
            new DatasetEntry("tcpip_recv",       "parquet", "tcpip_recv.parquet",       1, runner.Collector.TcpipRecv.Count,      true),
            new DatasetEntry("tcpip_send",       "parquet", "tcpip_send.parquet",       1, runner.Collector.TcpipSend.Count,      false),
            new DatasetEntry("tcpip_connect",    "parquet", "tcpip_connect.parquet",    1, runner.Collector.TcpipConnect.Count,   false),
            new DatasetEntry("tcpip_accept",     "parquet", "tcpip_accept.parquet",     1, runner.Collector.TcpipAccept.Count,    false),
            new DatasetEntry("tcpip_retransmit", "parquet", "tcpip_retransmit.parquet", 1, runner.Collector.TcpipRetransmit.Count, false),
            new DatasetEntry("tcpip_disconnect", "parquet", "tcpip_disconnect.parquet", 1, runner.Collector.TcpipDisconnect.Count, false),
            new DatasetEntry("udp_recv",         "parquet", "udp_recv.parquet",         1, runner.Collector.UdpRecv.Count,         false),
            new DatasetEntry("udp_send",         "parquet", "udp_send.parquet",         1, runner.Collector.UdpSend.Count,         false),
            new DatasetEntry("afd_recv",         "parquet", "afd_recv.parquet",         1, runner.Collector.AfdRecv.Count,         true),
            new DatasetEntry("afd_send",         "parquet", "afd_send.parquet",         1, runner.Collector.AfdSend.Count,         false),
            new DatasetEntry("afd_connect",      "parquet", "afd_connect.parquet",      1, runner.Collector.AfdConnect.Count,      false),
            new DatasetEntry("afd_accept",       "parquet", "afd_accept.parquet",       1, runner.Collector.AfdAccept.Count,       false),
            new DatasetEntry("afd_close",        "parquet", "afd_close.parquet",        1, runner.Collector.AfdClose.Count,        false),
            new DatasetEntry("afd_bind",         "parquet", "afd_bind.parquet",         1, runner.Collector.AfdBind.Count,         false),
            new DatasetEntry("ndis_drops",       "parquet", "ndis_drops.parquet",       1, runner.Collector.NdisDrops.Count,       true),
            new DatasetEntry("packet_capture",   "parquet", "packet_capture.parquet",   1, runner.Collector.NdisPacketCapture.Count, false),
            new DatasetEntry("http_recv",        "parquet", "http_recv.parquet",        1, runner.Collector.HttpRecv.Count,        false),
            new DatasetEntry("http_deliver",     "parquet", "http_deliver.parquet",     1, runner.Collector.HttpDeliver.Count,     false),
            new DatasetEntry("http_send",        "parquet", "http_send.parquet",        1, runner.Collector.HttpSend.Count,        false),
            new DatasetEntry("http_close",       "parquet", "http_close.parquet",       1, runner.Collector.HttpClose.Count,       false),
            new DatasetEntry("quic_conn_created","parquet", "quic_conn_created.parquet",1, runner.Collector.QuicConnCreated.Count, false),
            new DatasetEntry("quic_conn_closed", "parquet", "quic_conn_closed.parquet", 1, runner.Collector.QuicConnClosed.Count,  false),
            new DatasetEntry("quic_packet_recv", "parquet", "quic_packet_recv.parquet", 1, runner.Collector.QuicPacketRecv.Count,  false),
            new DatasetEntry("quic_packet_send", "parquet", "quic_packet_send.parquet", 1, runner.Collector.QuicPacketSend.Count,  false),
            new DatasetEntry("quic_ack_recv",    "parquet", "quic_ack_recv.parquet",    1, runner.Collector.QuicAckReceived.Count, false),
        });
        if (runner.Collector.Process.Count > 0)
        {
            datasets.Add(new("process", "parquet", "process.parquet", 1, runner.Collector.Process.Count, true));
            // Phase B per-opcode Process parquets.
            int nStart = 0, nEnd = 0, nDcStart = 0, nDcEnd = 0, nDefunct = 0;
            foreach (var r in runner.Collector.Process)
            {
                switch (r.Kind)
                {
                    case "Start":   nStart++;   break;
                    case "End":     nEnd++;     break;
                    case "DCStart": nDcStart++; break;
                    case "DCEnd":   nDcEnd++;   break;
                    case "Defunct": nDefunct++; break;
                }
            }
            datasets.Add(new("process_start",   "parquet", "process_start.parquet",   1, nStart,   false));
            datasets.Add(new("process_end",     "parquet", "process_end.parquet",     1, nEnd,     false));
            datasets.Add(new("process_dcstart", "parquet", "process_dcstart.parquet", 1, nDcStart, false));
            datasets.Add(new("process_dcend",   "parquet", "process_dcend.parquet",   1, nDcEnd,   false));
            datasets.Add(new("process_defunct", "parquet", "process_defunct.parquet", 1, nDefunct, false));
        }
        if (runner.Collector.Image.Count > 0)
        {
            datasets.Add(new("image", "parquet", "image.parquet", 1, runner.Collector.Image.Count, true));
            // Phase B per-opcode Image parquets.
            int iLoad = 0, iDcStart = 0, iDcEnd = 0;
            foreach (var r in runner.Collector.Image)
            {
                switch (r.Kind)
                {
                    case "Load":    iLoad++;    break;
                    case "DCStart": iDcStart++; break;
                    case "DCEnd":   iDcEnd++;   break;
                }
            }
            datasets.Add(new("image_load",    "parquet", "image_load.parquet",    1, iLoad,    false));
            datasets.Add(new("image_dcstart", "parquet", "image_dcstart.parquet", 1, iDcStart, false));
            datasets.Add(new("image_dcend",   "parquet", "image_dcend.parquet",   1, iDcEnd,   false));
        }
        if (runner.Collector.DiskIo.Count > 0)
        {
            datasets.Add(new("diskio", "parquet", "diskio.parquet", 1, runner.Collector.DiskIo.Count, true));
            // Phase B per-opcode DiskIo parquets.
            int dRead = 0, dWrite = 0, dFlush = 0;
            foreach (var r in runner.Collector.DiskIo)
            {
                switch (r.Kind)
                {
                    case "Read":         dRead++;  break;
                    case "Write":        dWrite++; break;
                    case "FlushBuffers": dFlush++; break;
                }
            }
            datasets.Add(new("diskio_read",         "parquet", "diskio_read.parquet",         1, dRead,  false));
            datasets.Add(new("diskio_write",        "parquet", "diskio_write.parquet",        1, dWrite, false));
            datasets.Add(new("diskio_flushbuffers", "parquet", "diskio_flushbuffers.parquet", 1, dFlush, false));
        }
        if (runner.Collector.DpcIsr.Count > 0)
        {
            datasets.Add(new("dpc_isr", "parquet", "dpc_isr.parquet", 1, runner.Collector.DpcIsr.Count, true));
            // Phase B per-opcode PerfInfo parquets.
            int nDpc = 0, nTdpc = 0, nTimDpc = 0, nIsr = 0;
            foreach (var r in runner.Collector.DpcIsr)
            {
                switch (r.Kind)
                {
                    case "DPC": nDpc++; break;
                    case "ThreadedDPC": nTdpc++; break;
                    case "TimerDPC": nTimDpc++; break;
                    case "ISR": nIsr++; break;
                }
            }
            datasets.Add(new("perfinfo_dpc",          "parquet", "perfinfo_dpc.parquet",          1, nDpc,    false));
            datasets.Add(new("perfinfo_threaded_dpc", "parquet", "perfinfo_threaded_dpc.parquet", 1, nTdpc,   false));
            datasets.Add(new("perfinfo_timer_dpc",    "parquet", "perfinfo_timer_dpc.parquet",    1, nTimDpc, false));
            datasets.Add(new("perfinfo_isr",          "parquet", "perfinfo_isr.parquet",          1, nIsr,    false));
        }
        // Phase B: Thread/* per-opcode parquets.
        if (runner.Collector.Thread.Count > 0)
        {
            int tStart = 0, tEnd = 0, tDcStart = 0, tDcEnd = 0;
            foreach (var r in runner.Collector.Thread)
            {
                switch (r.Kind)
                {
                    case "Start":   tStart++;   break;
                    case "End":     tEnd++;     break;
                    case "DCStart": tDcStart++; break;
                    case "DCEnd":   tDcEnd++;   break;
                }
            }
            datasets.Add(new("thread_start",   "parquet", "thread_start.parquet",   1, tStart,   false));
            datasets.Add(new("thread_end",     "parquet", "thread_end.parquet",     1, tEnd,     false));
            datasets.Add(new("thread_dcstart", "parquet", "thread_dcstart.parquet", 1, tDcStart, false));
            datasets.Add(new("thread_dcend",   "parquet", "thread_dcend.parquet",   1, tDcEnd,   false));
        }
        // Phase B: EventTrace/Header.
        if (runner.Collector.EventTraceHeader.Count > 0)
            datasets.Add(new("eventtrace_header", "parquet", "eventtrace_header.parquet", 1,
                runner.Collector.EventTraceHeader.Count, true));
        if (req.IncludeTracelogging && runner.Collector.Tracelogging.Count > 0)
            datasets.Add(new("tracelogging_events", "parquet", "tracelogging_events.parquet", 1, runner.Collector.Tracelogging.Count, true));
    }

    phase = "writing-parquet";
    sysconfigBytes = runner.Sysconfig.WriteFile(req.StagingDir);
    // sysconfig.txt lives at the staging-dir root in both strategies (contract §9.2).
    datasets.Add(new("sysconfig", "text", "sysconfig.txt", 1, 1, true));

    phase = "writing-manifest";
    emit.Heartbeat(phase);

    // manifest_write_panic probe fires here.
    if (req.PanicProbe == "manifest_write_panic")
        throw new InvalidOperationException("panic_probe=manifest_write_panic triggered");

    // This is intentionally non-final. Python aggregation adds derived
    // datasets and writes the sole complete=true manifest last.
    manifestBytes = ManifestEmitter.WriteCacheManifest(req.StagingDir, req.EtlPath, req.Strategy, datasets,
        complete: false, runId: streamingRunId, qpcOrigin: runner.QpcOrigin, perfFreq: runner.PerfFreq);
}
catch (Exception ex)
{
    eventsAtFailure = runner.Collector.EventsDecoded;
    var kind = phase switch
    {
        "writing-parquet" => "parquet-error",
        "writing-manifest" => req.PanicProbe == "manifest_write_panic" ? "dotnet_exception" : "manifest-error",
        _ => "dotnet_exception",
    };
    EmitFailure(kind, $"{ex.GetType().Name}: {ex.Message}", ex.StackTrace);
    return 1;
}

// ---- Emit success result ------------------------------------------------
startTime.Stop();
var wall = startTime.Elapsed.TotalSeconds;
// EventsDecoded only tracks manifest-routed events (kernel typed handlers
// don't go through OnEvent). Compute the true total from the per-class
// row counts so the eps metric is meaningful for kernel-heavy traces.
long totalEvents = runner.Collector.EventsDecoded
    + runner.Collector.SampledProfile.Count
    + runner.Collector.CSwitch.Count
    + runner.Collector.ReadyThread.Count
    + runner.Collector.Process.Count
    + runner.Collector.Image.Count
    + runner.Collector.DiskIo.Count
    + runner.Collector.DpcIsr.Count
    + runner.Collector.Thread.Count
    + runner.Collector.EventTraceHeader.Count;
double eps = wall > 0 ? totalEvents / wall : 0.0;
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
    datasets = datasets.Select(d => d.Name).ToArray(),
    event_counts = new Dictionary<string, long>
    {
        ["SampledProfile"]    = runner.Collector.SampledProfile.Count,
        ["CSwitch"]           = runner.Collector.CSwitch.Count,
        ["ReadyThread"]       = runner.Collector.ReadyThread.Count,
        ["TcpIp/Recv"]        = runner.Collector.TcpipRecv.Count,
        ["TcpIp/Send"]        = runner.Collector.TcpipSend.Count,
        ["TcpIp/Connect"]     = runner.Collector.TcpipConnect.Count,
        ["TcpIp/Accept"]      = runner.Collector.TcpipAccept.Count,
        ["TcpIp/Retransmit"]  = runner.Collector.TcpipRetransmit.Count,
        ["TcpIp/Disconnect"]  = runner.Collector.TcpipDisconnect.Count,
        ["UdpIp/Recv"]        = runner.Collector.UdpRecv.Count,
        ["UdpIp/Send"]        = runner.Collector.UdpSend.Count,
        ["AFD/Recv"]          = runner.Collector.AfdRecv.Count,
        ["AFD/Send"]          = runner.Collector.AfdSend.Count,
        ["AFD/Connect"]       = runner.Collector.AfdConnect.Count,
        ["AFD/Accept"]        = runner.Collector.AfdAccept.Count,
        ["AFD/Close"]         = runner.Collector.AfdClose.Count,
        ["AFD/Bind"]          = runner.Collector.AfdBind.Count,
        ["NdisDrop"]          = runner.Collector.NdisDrops.Count,
        ["NdisPacketCapture"] = runner.Collector.NdisPacketCapture.Count,
        ["HttpService/Recv"]    = runner.Collector.HttpRecv.Count,
        ["HttpService/Deliver"] = runner.Collector.HttpDeliver.Count,
        ["HttpService/Send"]    = runner.Collector.HttpSend.Count,
        ["HttpService/Close"]   = runner.Collector.HttpClose.Count,
        ["Quic/ConnectionCreated"] = runner.Collector.QuicConnCreated.Count,
        ["Quic/ConnectionClosed"]  = runner.Collector.QuicConnClosed.Count,
        ["Quic/PacketRecv"]        = runner.Collector.QuicPacketRecv.Count,
        ["Quic/PacketSend"]        = runner.Collector.QuicPacketSend.Count,
        ["Quic/AckReceived"]       = runner.Collector.QuicAckReceived.Count,
        ["Process"]      = runner.Collector.Process.Count,
        ["Image"]        = runner.Collector.Image.Count,
        ["DiskIo"]       = runner.Collector.DiskIo.Count,
        ["PerfInfo"]     = runner.Collector.DpcIsr.Count,
        ["Thread"]       = runner.Collector.Thread.Count,
        ["EventTrace/Header"] = runner.Collector.EventTraceHeader.Count,
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
