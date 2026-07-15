using Parquet;
using Parquet.Data;
using Parquet.Schema;
using EtwExtract.Rows;

namespace EtwExtract;

/// <summary>
/// Writes Layer 1 flat-per-class parquets using the lower-level Parquet.Net
/// API so we can control list-inner-field naming ("element") to match
/// pyarrow's canonical representation. The Python loader cares about column
/// names but tolerates extra columns via <c>_FIELD_ALIASES</c>, so the
/// sidecar's <c>EventSequence</c>/<c>TimeStampQpc</c>/<c>CPU</c> additions
/// are safe.
/// </summary>
internal static class ParquetEmitter
{
    public const string ListItemName = "element";  // matches pyarrow default

    public static async Task<long> WriteAllAsync(EventCollector ec, string stagingDir)
    {
        // Materialized path — buffers are List<T>-backed, .AsList() returns
        // the underlying List without copying. Streaming-mode collectors
        // would throw here; callers must dispatch on EventCollector.IsStreaming.
        long total = 0;
        // Paired (stack) classes.
        total += await WriteSampledProfileAsync(ec.SampledProfile.AsList(), Path.Combine(stagingDir, "sampled_profile.parquet"));
        total += await WriteCSwitchAsync(ec.CSwitch.AsList(), Path.Combine(stagingDir, "cswitch_events.parquet"));
        total += await WriteReadyThreadAsync(ec.ReadyThread.AsList(), Path.Combine(stagingDir, "readythread.parquet"));
        // TCP/IP and UDP/IP flow classes — Python expects one parquet per (proto, opcode).
        total += await WriteTcpipRecvAsync(ec.TcpipRecv.AsList(), Path.Combine(stagingDir, "tcpip_recv.parquet"));
        total += await WriteFlowAsync(ec.TcpipSend.AsList(),        Path.Combine(stagingDir, "tcpip_send.parquet"));
        total += await WriteFlowAsync(ec.TcpipConnect.AsList(),     Path.Combine(stagingDir, "tcpip_connect.parquet"));
        total += await WriteFlowAsync(ec.TcpipAccept.AsList(),      Path.Combine(stagingDir, "tcpip_accept.parquet"));
        total += await WriteFlowAsync(ec.TcpipRetransmit.AsList(),  Path.Combine(stagingDir, "tcpip_retransmit.parquet"));
        total += await WriteFlowAsync(ec.TcpipDisconnect.AsList(),  Path.Combine(stagingDir, "tcpip_disconnect.parquet"));
        total += await WriteFlowAsync(ec.UdpRecv.AsList(),          Path.Combine(stagingDir, "udp_recv.parquet"));
        total += await WriteFlowAsync(ec.UdpSend.AsList(),          Path.Combine(stagingDir, "udp_send.parquet"));
        // AFD socket-level events.
        total += await WriteAfdRecvAsync(ec.AfdRecv.AsList(),       Path.Combine(stagingDir, "afd_recv.parquet"));
        total += await WriteAfdEventAsync(ec.AfdSend.AsList(),      Path.Combine(stagingDir, "afd_send.parquet"));
        total += await WriteAfdEventAsync(ec.AfdConnect.AsList(),   Path.Combine(stagingDir, "afd_connect.parquet"));
        total += await WriteAfdEventAsync(ec.AfdAccept.AsList(),    Path.Combine(stagingDir, "afd_accept.parquet"));
        total += await WriteAfdEventAsync(ec.AfdClose.AsList(),     Path.Combine(stagingDir, "afd_close.parquet"));
        total += await WriteAfdEventAsync(ec.AfdBind.AsList(),      Path.Combine(stagingDir, "afd_bind.parquet"));
        // NDIS.
        total += await WriteNdisDropsAsync(ec.NdisDrops.AsList(),   Path.Combine(stagingDir, "ndis_drops.parquet"));
        total += await WriteNdisPacketCaptureAsync(ec.NdisPacketCapture.AsList(), Path.Combine(stagingDir, "packet_capture.parquet"));
        // HTTP.sys.
        total += await WriteHttpAsync(ec.HttpRecv.AsList(),         Path.Combine(stagingDir, "http_recv.parquet"));
        total += await WriteHttpAsync(ec.HttpDeliver.AsList(),      Path.Combine(stagingDir, "http_deliver.parquet"));
        total += await WriteHttpAsync(ec.HttpSend.AsList(),         Path.Combine(stagingDir, "http_send.parquet"));
        total += await WriteHttpAsync(ec.HttpClose.AsList(),        Path.Combine(stagingDir, "http_close.parquet"));
        // MsQuic.
        total += await WriteQuicAsync(ec.QuicConnCreated.AsList(),  Path.Combine(stagingDir, "quic_conn_created.parquet"));
        total += await WriteQuicAsync(ec.QuicConnClosed.AsList(),   Path.Combine(stagingDir, "quic_conn_closed.parquet"));
        total += await WriteQuicAsync(ec.QuicPacketRecv.AsList(),   Path.Combine(stagingDir, "quic_packet_recv.parquet"));
        total += await WriteQuicAsync(ec.QuicPacketSend.AsList(),   Path.Combine(stagingDir, "quic_packet_send.parquet"));
        total += await WriteQuicAsync(ec.QuicAckReceived.AsList(),  Path.Combine(stagingDir, "quic_ack_recv.parquet"));
        // Kernel meta — only emit if collected (request opt-in).
        if (ec.Process.Count > 0)
        {
            var processList = ec.Process.AsList();
            total += await WriteProcessAsync(processList, Path.Combine(stagingDir, "process.parquet"));
            // Phase B per-opcode Process parquets.
            total += await WriteProcessByKindAsync(processList, "Start",   Path.Combine(stagingDir, "process_start.parquet"));
            total += await WriteProcessByKindAsync(processList, "End",     Path.Combine(stagingDir, "process_end.parquet"));
            total += await WriteProcessByKindAsync(processList, "DCStart", Path.Combine(stagingDir, "process_dcstart.parquet"));
            total += await WriteProcessByKindAsync(processList, "DCEnd",   Path.Combine(stagingDir, "process_dcend.parquet"));
            total += await WriteProcessByKindAsync(processList, "Defunct", Path.Combine(stagingDir, "process_defunct.parquet"));
        }
        if (ec.Image.Count > 0)
        {
            var imageList = ec.Image.AsList();
            total += await WriteImageAsync(imageList,     Path.Combine(stagingDir, "image.parquet"));
            // Phase B per-opcode Image parquets — power the Python symbolizer build.
            total += await WriteImageByKindAsync(imageList, "Load",    Path.Combine(stagingDir, "image_load.parquet"));
            total += await WriteImageByKindAsync(imageList, "DCStart", Path.Combine(stagingDir, "image_dcstart.parquet"));
            total += await WriteImageByKindAsync(imageList, "DCEnd",   Path.Combine(stagingDir, "image_dcend.parquet"));
        }
        if (ec.DiskIo.Count > 0)
        {
            var diskList = ec.DiskIo.AsList();
            total += await WriteDiskIoAsync(diskList,   Path.Combine(stagingDir, "diskio.parquet"));
            // Phase B per-opcode DiskIo parquets.
            total += await WriteDiskIoByKindAsync(diskList, "Read",         Path.Combine(stagingDir, "diskio_read.parquet"));
            total += await WriteDiskIoByKindAsync(diskList, "Write",        Path.Combine(stagingDir, "diskio_write.parquet"));
            total += await WriteDiskIoByKindAsync(diskList, "FlushBuffers", Path.Combine(stagingDir, "diskio_flushbuffers.parquet"));
        }
        if (ec.DpcIsr.Count > 0)
        {
            var dpcList = ec.DpcIsr.AsList();
            total += await WriteDpcIsrAsync(dpcList,   Path.Combine(stagingDir, "dpc_isr.parquet"));
            // Per-opcode PerfInfo parquets (Phase B). Always emit so Python aggregators
            // can rely on stable filenames; the writer produces an empty parquet when
            // the per-Kind filter is empty.
            total += await WriteDpcIsrByKindAsync(dpcList, "DPC",         Path.Combine(stagingDir, "perfinfo_dpc.parquet"));
            total += await WriteDpcIsrByKindAsync(dpcList, "ThreadedDPC", Path.Combine(stagingDir, "perfinfo_threaded_dpc.parquet"));
            total += await WriteDpcIsrByKindAsync(dpcList, "TimerDPC",    Path.Combine(stagingDir, "perfinfo_timer_dpc.parquet"));
            total += await WriteDpcIsrByKindAsync(dpcList, "ISR",         Path.Combine(stagingDir, "perfinfo_isr.parquet"));
        }
        // Phase B: Thread/* per-opcode parquets.
        if (ec.Thread.Count > 0)
        {
            var threadList = ec.Thread.AsList();
            total += await WriteThreadByKindAsync(threadList, "Start",   Path.Combine(stagingDir, "thread_start.parquet"));
            total += await WriteThreadByKindAsync(threadList, "End",     Path.Combine(stagingDir, "thread_end.parquet"));
            total += await WriteThreadByKindAsync(threadList, "DCStart", Path.Combine(stagingDir, "thread_dcstart.parquet"));
            total += await WriteThreadByKindAsync(threadList, "DCEnd",   Path.Combine(stagingDir, "thread_dcend.parquet"));
        }
        // Phase B: EventTrace/Header (one row per ETL).
        if (ec.EventTraceHeader.Count > 0)
            total += await WriteEventTraceHeaderAsync(ec.EventTraceHeader.AsList(), Path.Combine(stagingDir, "eventtrace_header.parquet"));
        if (ec.Tracelogging.Count > 0)
            total += await WriteTraceloggingAsync(ec.Tracelogging.AsList(), Path.Combine(stagingDir, "tracelogging_events.parquet"));
        return total;
    }

    internal static async Task<long> WriteTraceloggingAsync(List<TraceloggingRow> rows, string path)
    {
        var fQpc = Df<long>("TimeStampQpc", false);
        var fGuid = DfStr("ProviderGuid");
        var fProv = DfStr("ProviderName");
        var fName = DfStr("EventName");
        var fPid = Df<long>("ProcessId", false);
        var fTid = Df<long>("ThreadId", false);
        var fCpu = Df<int>("CPU", false);
        var fLevel = Df<int>("Level", false);
        var fKeywords = Df<ulong>("Keywords", false);
        var fFields = DfStr("FieldsJson");
        var schema = new ParquetSchema(fQpc, fGuid, fProv, fName, fPid, fTid, fCpu, fLevel, fKeywords, fFields);

        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var qpc = new long[n]; var guid = new string?[n]; var prov = new string?[n]; var name = new string?[n];
            var pid = new long[n]; var tid = new long[n]; var cpu = new int[n]; var lvl = new int[n];
            var kw = new ulong[n]; var fields = new string?[n];
            for (int i = 0; i < n; i++)
            {
                var r = rows[i];
                qpc[i] = r.TimeStampQpc; guid[i] = r.ProviderGuid; prov[i] = r.ProviderName; name[i] = r.EventName;
                pid[i] = r.ProcessId; tid[i] = r.ThreadId; cpu[i] = r.Cpu; lvl[i] = r.Level;
                kw[i] = r.Keywords; fields[i] = r.FieldsJson;
            }
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fGuid, guid));
            await rg.WriteColumnAsync(new DataColumn(fProv, prov));
            await rg.WriteColumnAsync(new DataColumn(fName, name));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fTid, tid));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fLevel, lvl));
            await rg.WriteColumnAsync(new DataColumn(fKeywords, kw));
            await rg.WriteColumnAsync(new DataColumn(fFields, fields));
        });
    }

    // ----- helpers -------------------------------------------------------

    private static DataField<T> Df<T>(string name, bool isNullable) where T : struct
        => new(name, (bool?)isNullable);

    private static DataField<string> DfStr(string name) => new(name, (bool?)true);

    private static ListField StackField() =>
        new("Stack", new DataField<ulong>(ListItemName, (bool?)true));

    internal static async Task<long> WriteRowGroupAsync(string path, ParquetSchema schema, Func<ParquetRowGroupWriter, Task> body)
    {
        // Atomic write via .tmp suffix to satisfy contract §9 (no .tmp at exit).
        var tmp = path + ".tmp";
        if (File.Exists(tmp)) File.Delete(tmp);
        long size;
        await using (var fs = File.Create(tmp))
        {
            await using (var writer = await ParquetWriter.CreateAsync(schema, fs))
            {
                writer.CompressionMethod = CompressionMethod.Snappy;
                using (var rg = writer.CreateRowGroup())
                {
                    await body(rg);
                }
            }
            size = fs.Length;
        }
        if (File.Exists(path)) File.Delete(path);
        File.Move(tmp, path);
        return size;
    }

    private static (ulong?[] data, int[] reps) FlattenStacks(IEnumerable<List<ulong>?> stacks)
    {
        var data = new List<ulong?>();
        var reps = new List<int>();
        foreach (var s in stacks)
        {
            if (s is null || s.Count == 0)
            {
                // Null list → single null entry, rep=0.
                data.Add(null);
                reps.Add(0);
            }
            else
            {
                for (int i = 0; i < s.Count; i++)
                {
                    data.Add(s[i]);
                    reps.Add(i == 0 ? 0 : 1);
                }
            }
        }
        return (data.ToArray(), reps.ToArray());
    }

    // ----- per-class writers --------------------------------------------

    internal static async Task<long> WriteSampledProfileAsync(List<SampledProfileRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fPid = Df<long>("ProcessId", true);
        var fTid = Df<long>("ThreadId", true);
        var fPayloadTid = Df<long>("PayloadThreadId", true);
        var fIp = Df<ulong>("InstructionPointer", false);
        var fWeight = Df<long>("Weight", false);
        var fProfileWeight = Df<long>("ProfileWeight", false);
        var fStack = StackField();
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fPid, fTid, fPayloadTid, fIp, fWeight, fProfileWeight, fStack);

        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pid = new long?[n]; var tid = new long?[n]; var ptid = new long?[n];
            var ip = new ulong[n]; var w = new long[n]; var pw = new long[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; pid[i] = r.ProcessId; tid[i] = r.ThreadId; ptid[i] = r.PayloadThreadId; ip[i] = r.InstructionPointer; w[i] = r.Weight; pw[i] = r.ProfileWeight; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fTid, tid));
            await rg.WriteColumnAsync(new DataColumn(fPayloadTid, ptid));
            await rg.WriteColumnAsync(new DataColumn(fIp, ip));
            await rg.WriteColumnAsync(new DataColumn(fWeight, w));
            await rg.WriteColumnAsync(new DataColumn(fProfileWeight, pw));
            var (sd, sr) = FlattenStacks(rows.Select(r => r.Stack));
            await rg.WriteColumnAsync(new DataColumn((DataField)fStack.Item, sd, sr));
        });
    }

    internal static async Task<long> WriteCSwitchAsync(List<CSwitchRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fNewTid = Df<long>("NewTID", true);
        var fOldTid = Df<long>("OldTID", true);
        var fNewPid = Df<long>("NewPID", true);
        var fOldPid = Df<long>("OldPID", true);
        var fWait = DfStr("WaitReason");
        var fOldState = DfStr("OldThreadState");
        var fStack = StackField();
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fNewTid, fOldTid, fNewPid, fOldPid, fWait, fOldState, fStack);

        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var ntid = new long?[n]; var otid = new long?[n]; var npid = new long?[n]; var opid = new long?[n];
            var wait = new string?[n]; var oldState = new string?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; ntid[i] = r.NewTid; otid[i] = r.OldTid; npid[i] = r.NewPid; opid[i] = r.OldPid; wait[i] = r.WaitReason; oldState[i] = r.OldThreadState; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fNewTid, ntid));
            await rg.WriteColumnAsync(new DataColumn(fOldTid, otid));
            await rg.WriteColumnAsync(new DataColumn(fNewPid, npid));
            await rg.WriteColumnAsync(new DataColumn(fOldPid, opid));
            await rg.WriteColumnAsync(new DataColumn(fWait, wait));
            await rg.WriteColumnAsync(new DataColumn(fOldState, oldState));
            var (sd, sr) = FlattenStacks(rows.Select(r => r.Stack));
            await rg.WriteColumnAsync(new DataColumn((DataField)fStack.Item, sd, sr));
        });
    }

    internal static async Task<long> WriteReadyThreadAsync(List<ReadyThreadRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fPid = Df<long>("ProcessId", true);
        var fTid = Df<long>("ThreadId", true);
        var fReadied = Df<long>("ReadiedThreadId", true);
        var fReadyingTid = Df<long>("ReadyingThreadId", true);
        var fReadyingPid = Df<long>("ReadyingProcessId", true);
        var fReason = Df<int>("AdjustReason", true);
        var fInc = Df<int>("AdjustIncrement", true);
        var fFlag = Df<int>("Flag", true);
        var fStack = StackField();
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fPid, fTid, fReadied, fReadyingTid, fReadyingPid, fReason, fInc, fFlag, fStack);

        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pid = new long?[n]; var tid = new long?[n];
            var readied = new long?[n]; var ryTid = new long?[n]; var ryPid = new long?[n];
            var reason = new int?[n]; var inc = new int?[n]; var flag = new int?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; pid[i] = r.ProcessId; tid[i] = r.ThreadId; readied[i] = r.ReadiedThreadId; ryTid[i] = r.ReadyingThreadId; ryPid[i] = r.ReadyingProcessId; reason[i] = r.AdjustReason; inc[i] = r.AdjustIncrement; flag[i] = r.Flag; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fTid, tid));
            await rg.WriteColumnAsync(new DataColumn(fReadied, readied));
            await rg.WriteColumnAsync(new DataColumn(fReadyingTid, ryTid));
            await rg.WriteColumnAsync(new DataColumn(fReadyingPid, ryPid));
            await rg.WriteColumnAsync(new DataColumn(fReason, reason));
            await rg.WriteColumnAsync(new DataColumn(fInc, inc));
            await rg.WriteColumnAsync(new DataColumn(fFlag, flag));
            var (sd, sr) = FlattenStacks(rows.Select(r => r.Stack));
            await rg.WriteColumnAsync(new DataColumn((DataField)fStack.Item, sd, sr));
        });
    }

    internal static async Task<long> WriteTcpipRecvAsync(List<TcpipRecvRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fProcName = DfStr("Process Name");
        var fPid = Df<long>("PID", true);
        var fTid = Df<long>("ThreadID", true);
        var fLocalAddr = DfStr("LocalAddr");
        var fLocalPort = Df<long>("LocalPort", true);
        var fRemoteAddr = DfStr("RemoteAddr");
        var fRemotePort = Df<long>("RemotePort", true);
        var fSize = Df<long>("Size", true);
        var fSeq = Df<ulong>("SeqNo", true);
        var fConn = Df<ulong>("ConnId", true);
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fProcName, fPid, fTid, fLocalAddr, fLocalPort, fRemoteAddr, fRemotePort, fSize, fSeq, fConn);

        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pn = new string?[n]; var pid = new long?[n]; var tid = new long?[n];
            var la = new string?[n]; var lp = new long?[n]; var ra = new string?[n]; var rp = new long?[n];
            var sz = new long?[n]; var seq = new ulong?[n]; var conn = new ulong?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; pn[i] = r.ProcessName; pid[i] = r.Pid; tid[i] = r.ThreadId; la[i] = r.LocalAddr; lp[i] = r.LocalPort; ra[i] = r.RemoteAddr; rp[i] = r.RemotePort; sz[i] = r.Size; seq[i] = r.SeqNo; conn[i] = r.ConnId; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fProcName, pn));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fTid, tid));
            await rg.WriteColumnAsync(new DataColumn(fLocalAddr, la));
            await rg.WriteColumnAsync(new DataColumn(fLocalPort, lp));
            await rg.WriteColumnAsync(new DataColumn(fRemoteAddr, ra));
            await rg.WriteColumnAsync(new DataColumn(fRemotePort, rp));
            await rg.WriteColumnAsync(new DataColumn(fSize, sz));
            await rg.WriteColumnAsync(new DataColumn(fSeq, seq));
            await rg.WriteColumnAsync(new DataColumn(fConn, conn));
        });
    }

    internal static async Task<long> WriteAfdRecvAsync(List<AfdRecvRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fProcName = DfStr("Process Name");
        var fPid = Df<long>("PID", true);
        var fTid = Df<long>("ThreadID", true);
        var fSock = Df<ulong>("SocketHandle", true);
        var fSize = Df<long>("Size", true);
        var fStatus = Df<long>("CompletionStatus", true);
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fProcName, fPid, fTid, fSock, fSize, fStatus);

        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pn = new string?[n]; var pid = new long?[n]; var tid = new long?[n];
            var sock = new ulong?[n]; var sz = new long?[n]; var st = new long?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; pn[i] = r.ProcessName; pid[i] = r.Pid; tid[i] = r.ThreadId; sock[i] = r.SocketHandle; sz[i] = r.Size; st[i] = r.CompletionStatus; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fProcName, pn));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fTid, tid));
            await rg.WriteColumnAsync(new DataColumn(fSock, sock));
            await rg.WriteColumnAsync(new DataColumn(fSize, sz));
            await rg.WriteColumnAsync(new DataColumn(fStatus, st));
        });
    }

    internal static async Task<long> WriteNdisDropsAsync(List<NdisDropRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fProcName = DfStr("Process Name");
        var fPid = Df<long>("PID", true);
        var fTid = Df<long>("ThreadID", true);
        var fMini = DfStr("MiniportName");
        var fReason = DfStr("Reason");
        var fSize = Df<long>("Size", true);
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fProcName, fPid, fTid, fMini, fReason, fSize);

        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pn = new string?[n]; var pid = new long?[n]; var tid = new long?[n];
            var mini = new string?[n]; var reason = new string?[n]; var sz = new long?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; pn[i] = r.ProcessName; pid[i] = r.Pid; tid[i] = r.ThreadId; mini[i] = r.MiniportName; reason[i] = r.Reason; sz[i] = r.Size; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fProcName, pn));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fTid, tid));
            await rg.WriteColumnAsync(new DataColumn(fMini, mini));
            await rg.WriteColumnAsync(new DataColumn(fReason, reason));
            await rg.WriteColumnAsync(new DataColumn(fSize, sz));
        });
    }

    // ----- generic flow writer (reused for tcpip_send/connect/accept/retransmit/disconnect, udp_recv/send) -----

    internal static async Task<long> WriteFlowAsync(List<NetworkFlowRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fProcName = DfStr("Process Name");
        var fPid = Df<long>("PID", true);
        var fTid = Df<long>("ThreadID", true);
        var fLocalAddr = DfStr("LocalAddr");
        var fLocalPort = Df<long>("LocalPort", true);
        var fRemoteAddr = DfStr("RemoteAddr");
        var fRemotePort = Df<long>("RemotePort", true);
        var fSize = Df<long>("Size", true);
        var fSeq = Df<ulong>("SeqNo", true);
        var fConn = Df<ulong>("ConnId", true);
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fProcName, fPid, fTid, fLocalAddr, fLocalPort, fRemoteAddr, fRemotePort, fSize, fSeq, fConn);

        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pn = new string?[n]; var pid = new long?[n]; var tid = new long?[n];
            var la = new string?[n]; var lp = new long?[n]; var ra = new string?[n]; var rp = new long?[n];
            var sz = new long?[n]; var seq = new ulong?[n]; var conn = new ulong?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; pn[i] = r.ProcessName; pid[i] = r.Pid; tid[i] = r.ThreadId; la[i] = r.LocalAddr; lp[i] = r.LocalPort; ra[i] = r.RemoteAddr; rp[i] = r.RemotePort; sz[i] = r.Size; seq[i] = r.SeqNo; conn[i] = r.ConnId; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fProcName, pn));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fTid, tid));
            await rg.WriteColumnAsync(new DataColumn(fLocalAddr, la));
            await rg.WriteColumnAsync(new DataColumn(fLocalPort, lp));
            await rg.WriteColumnAsync(new DataColumn(fRemoteAddr, ra));
            await rg.WriteColumnAsync(new DataColumn(fRemotePort, rp));
            await rg.WriteColumnAsync(new DataColumn(fSize, sz));
            await rg.WriteColumnAsync(new DataColumn(fSeq, seq));
            await rg.WriteColumnAsync(new DataColumn(fConn, conn));
        });
    }

    // ----- generic AFD writer (reused for send/connect/accept/close/bind) -----

    internal static async Task<long> WriteAfdEventAsync(List<AfdEventRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fProcName = DfStr("Process Name");
        var fPid = Df<long>("PID", true);
        var fTid = Df<long>("ThreadID", true);
        var fSock = Df<ulong>("SocketHandle", true);
        var fSize = Df<long>("Size", true);
        var fStatus = Df<long>("CompletionStatus", true);
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fProcName, fPid, fTid, fSock, fSize, fStatus);

        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pn = new string?[n]; var pid = new long?[n]; var tid = new long?[n];
            var sock = new ulong?[n]; var sz = new long?[n]; var st = new long?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; pn[i] = r.ProcessName; pid[i] = r.Pid; tid[i] = r.ThreadId; sock[i] = r.SocketHandle; sz[i] = r.Size; st[i] = r.CompletionStatus; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fProcName, pn));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fTid, tid));
            await rg.WriteColumnAsync(new DataColumn(fSock, sock));
            await rg.WriteColumnAsync(new DataColumn(fSize, sz));
            await rg.WriteColumnAsync(new DataColumn(fStatus, st));
        });
    }

    // ----- NDIS PacketCapture -----

    internal static async Task<long> WriteNdisPacketCaptureAsync(List<NdisPacketCaptureRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fMini = DfStr("MiniportName");
        var fDir = DfStr("Direction");
        var fSize = Df<long>("FragmentSize", true);
        // Fragment bytes intentionally omitted from parquet (Python loader doesn't
        // need raw bytes today and they bloat the file by orders of magnitude).
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fMini, fDir, fSize);

        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var mini = new string?[n]; var dir = new string?[n]; var sz = new long?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; mini[i] = r.MiniportName; dir[i] = r.Direction; sz[i] = r.FragmentSize; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fMini, mini));
            await rg.WriteColumnAsync(new DataColumn(fDir, dir));
            await rg.WriteColumnAsync(new DataColumn(fSize, sz));
        });
    }

    // ----- HTTP.sys -----

    internal static async Task<long> WriteHttpAsync(List<HttpRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fProcName = DfStr("Process Name");
        var fPid = Df<long>("PID", true);
        var fTid = Df<long>("ThreadID", true);
        var fReq = Df<ulong>("RequestId", true);
        var fConn = Df<ulong>("ConnectionId", true);
        var fUrlGrp = Df<ulong>("UrlGroupId", true);
        var fUrl = DfStr("Url");
        var fVerb = DfStr("Verb");
        var fStatus = Df<long>("Status", true);
        var fSent = Df<long>("BytesSent", true);
        var fRecv = Df<long>("BytesReceived", true);
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fProcName, fPid, fTid, fReq, fConn, fUrlGrp, fUrl, fVerb, fStatus, fSent, fRecv);

        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pn = new string?[n]; var pid = new long?[n]; var tid = new long?[n];
            var req = new ulong?[n]; var conn = new ulong?[n]; var ug = new ulong?[n];
            var url = new string?[n]; var verb = new string?[n];
            var status = new long?[n]; var sent = new long?[n]; var recv = new long?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; pn[i] = r.ProcessName; pid[i] = r.Pid; tid[i] = r.ThreadId; req[i] = r.RequestId; conn[i] = r.ConnectionId; ug[i] = r.UrlGroupId; url[i] = r.Url; verb[i] = r.Verb; status[i] = r.Status; sent[i] = r.BytesSent; recv[i] = r.BytesReceived; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fProcName, pn));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fTid, tid));
            await rg.WriteColumnAsync(new DataColumn(fReq, req));
            await rg.WriteColumnAsync(new DataColumn(fConn, conn));
            await rg.WriteColumnAsync(new DataColumn(fUrlGrp, ug));
            await rg.WriteColumnAsync(new DataColumn(fUrl, url));
            await rg.WriteColumnAsync(new DataColumn(fVerb, verb));
            await rg.WriteColumnAsync(new DataColumn(fStatus, status));
            await rg.WriteColumnAsync(new DataColumn(fSent, sent));
            await rg.WriteColumnAsync(new DataColumn(fRecv, recv));
        });
    }

    // ----- MsQuic -----

    internal static async Task<long> WriteQuicAsync(List<QuicRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fProcName = DfStr("Process Name");
        var fPid = Df<long>("PID", true);
        var fTid = Df<long>("ThreadID", true);
        var fConn = Df<ulong>("ConnectionId", true);
        var fCid = DfStr("Cid");
        var fPkt = Df<ulong>("PacketNumber", true);
        var fSize = Df<long>("PacketSize", true);
        var fAck = Df<long>("AckDelayUs", true);
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fProcName, fPid, fTid, fConn, fCid, fPkt, fSize, fAck);

        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pn = new string?[n]; var pid = new long?[n]; var tid = new long?[n];
            var conn = new ulong?[n]; var cid = new string?[n]; var pkt = new ulong?[n];
            var sz = new long?[n]; var ack = new long?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; pn[i] = r.ProcessName; pid[i] = r.Pid; tid[i] = r.ThreadId; conn[i] = r.ConnectionId; cid[i] = r.Cid; pkt[i] = r.PacketNumber; sz[i] = r.PacketSize; ack[i] = r.AckDelayUs; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fProcName, pn));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fTid, tid));
            await rg.WriteColumnAsync(new DataColumn(fConn, conn));
            await rg.WriteColumnAsync(new DataColumn(fCid, cid));
            await rg.WriteColumnAsync(new DataColumn(fPkt, pkt));
            await rg.WriteColumnAsync(new DataColumn(fSize, sz));
            await rg.WriteColumnAsync(new DataColumn(fAck, ack));
        });
    }

    // ----- Process / Image / DiskIo / DPC-ISR -----

    internal static async Task<long> WriteProcessAsync(List<ProcessRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fKind = DfStr("Kind");
        var fPid = Df<long>("PID", false);
        var fParent = Df<long>("ParentPID", false);
        var fImg = DfStr("ImageFileName");
        var fCmd = DfStr("CommandLine");
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fKind, fPid, fParent, fImg, fCmd);
        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var kind = new string?[n]; var pid = new long[n]; var par = new long[n];
            var img = new string?[n]; var cmd = new string?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; kind[i] = r.Kind; pid[i] = r.Pid; par[i] = r.ParentPid; img[i] = r.ImageFileName; cmd[i] = r.CommandLine; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fKind, kind));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fParent, par));
            await rg.WriteColumnAsync(new DataColumn(fImg, img));
            await rg.WriteColumnAsync(new DataColumn(fCmd, cmd));
        });
    }

    /// <summary>
    /// Per-opcode Process parquet writer — filters by <c>Kind</c>. Schema matches
    /// <see cref="WriteProcessAsync"/> minus the <c>Kind</c> column.
    /// </summary>
    internal static async Task<long> WriteProcessByKindAsync(List<ProcessRow> rows, string kind, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fPid = Df<long>("PID", false);
        var fParent = Df<long>("ParentPID", false);
        var fImg = DfStr("ImageFileName");
        var fCmd = DfStr("CommandLine");
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fPid, fParent, fImg, fCmd);
        var filtered = new List<ProcessRow>(rows.Count);
        for (int i = 0; i < rows.Count; i++)
            if (string.Equals(rows[i].Kind, kind, StringComparison.Ordinal)) filtered.Add(rows[i]);
        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = filtered.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pid = new long[n]; var par = new long[n];
            var img = new string?[n]; var cmd = new string?[n];
            for (int i = 0; i < n; i++) { var r = filtered[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; pid[i] = r.Pid; par[i] = r.ParentPid; img[i] = r.ImageFileName; cmd[i] = r.CommandLine; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fParent, par));
            await rg.WriteColumnAsync(new DataColumn(fImg, img));
            await rg.WriteColumnAsync(new DataColumn(fCmd, cmd));
        });
    }

    internal static async Task<long> WriteImageAsync(List<ImageRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fKind = DfStr("Kind");
        var fPid = Df<long>("PID", false);
        var fBase = Df<ulong>("ImageBase", false);
        var fSize = Df<long>("ImageSize", false);
        var fTds = Df<long>("TimeDateStamp", false);
        var fName = DfStr("FileName");
        var fPdbGuid = DfStr("PdbGuid");
        var fPdbAge = Df<int>("PdbAge", true);
        var fPdbName = DfStr("PdbName");
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fKind, fPid, fBase, fSize, fTds, fName, fPdbGuid, fPdbAge, fPdbName);
        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var kind = new string?[n]; var pid = new long[n]; var bs = new ulong[n];
            var sz = new long[n]; var tds = new long[n]; var nm = new string?[n];
            var pdbGuid = new string?[n]; var pdbAge = new int?[n]; var pdbName = new string?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; kind[i] = r.Kind; pid[i] = r.Pid; bs[i] = r.ImageBase; sz[i] = r.ImageSize; tds[i] = r.TimeDateStamp; nm[i] = r.FileName; pdbGuid[i] = r.PdbGuid; pdbAge[i] = r.PdbAge; pdbName[i] = r.PdbName; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fKind, kind));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fBase, bs));
            await rg.WriteColumnAsync(new DataColumn(fSize, sz));
            await rg.WriteColumnAsync(new DataColumn(fTds, tds));
            await rg.WriteColumnAsync(new DataColumn(fName, nm));
            await rg.WriteColumnAsync(new DataColumn(fPdbGuid, pdbGuid));
            await rg.WriteColumnAsync(new DataColumn(fPdbAge, pdbAge));
            await rg.WriteColumnAsync(new DataColumn(fPdbName, pdbName));
        });
    }

    /// <summary>
    /// Per-opcode Image parquet writer — filters by <c>Kind</c>. Schema matches
    /// <see cref="WriteImageAsync"/> minus the <c>Kind</c> column. Powers the
    /// Python symbolizer build (image_load + image_dcstart together provide the
    /// full per-process module map).
    /// </summary>
    internal static async Task<long> WriteImageByKindAsync(List<ImageRow> rows, string kind, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fPid = Df<long>("PID", false);
        var fBase = Df<ulong>("ImageBase", false);
        var fSize = Df<long>("ImageSize", false);
        var fTds = Df<long>("TimeDateStamp", false);
        var fName = DfStr("FileName");
        var fPdbGuid = DfStr("PdbGuid");
        var fPdbAge = Df<int>("PdbAge", true);
        var fPdbName = DfStr("PdbName");
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fPid, fBase, fSize, fTds, fName, fPdbGuid, fPdbAge, fPdbName);
        var filtered = new List<ImageRow>(rows.Count);
        for (int i = 0; i < rows.Count; i++)
            if (string.Equals(rows[i].Kind, kind, StringComparison.Ordinal)) filtered.Add(rows[i]);
        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = filtered.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pid = new long[n]; var bs = new ulong[n];
            var sz = new long[n]; var tds = new long[n]; var nm = new string?[n];
            var pdbGuid = new string?[n]; var pdbAge = new int?[n]; var pdbName = new string?[n];
            for (int i = 0; i < n; i++) { var r = filtered[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; pid[i] = r.Pid; bs[i] = r.ImageBase; sz[i] = r.ImageSize; tds[i] = r.TimeDateStamp; nm[i] = r.FileName; pdbGuid[i] = r.PdbGuid; pdbAge[i] = r.PdbAge; pdbName[i] = r.PdbName; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fBase, bs));
            await rg.WriteColumnAsync(new DataColumn(fSize, sz));
            await rg.WriteColumnAsync(new DataColumn(fTds, tds));
            await rg.WriteColumnAsync(new DataColumn(fName, nm));
            await rg.WriteColumnAsync(new DataColumn(fPdbGuid, pdbGuid));
            await rg.WriteColumnAsync(new DataColumn(fPdbAge, pdbAge));
            await rg.WriteColumnAsync(new DataColumn(fPdbName, pdbName));
        });
    }

    internal static async Task<long> WriteDiskIoAsync(List<DiskIoRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fKind = DfStr("Kind");
        var fDisk = Df<long>("DiskNumber", true);
        var fOff = Df<ulong>("ByteOffset", true);
        var fSize = Df<long>("TransferSize", true);
        var fPid = Df<long>("PID", true);
        var fFile = DfStr("FileName");
        var fEla = Df<long>("ElapsedMicros", true);
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fKind, fDisk, fOff, fSize, fPid, fFile, fEla);
        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var kind = new string?[n]; var disk = new long?[n]; var off = new ulong?[n];
            var sz = new long?[n]; var pid = new long?[n]; var fn = new string?[n]; var ela = new long?[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; kind[i] = r.Kind; disk[i] = r.DiskNumber; off[i] = r.ByteOffset; sz[i] = r.TransferSize; pid[i] = r.Pid; fn[i] = r.FileName; ela[i] = r.ElapsedMicros; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fKind, kind));
            await rg.WriteColumnAsync(new DataColumn(fDisk, disk));
            await rg.WriteColumnAsync(new DataColumn(fOff, off));
            await rg.WriteColumnAsync(new DataColumn(fSize, sz));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fFile, fn));
            await rg.WriteColumnAsync(new DataColumn(fEla, ela));
        });
    }

    /// <summary>
    /// Per-opcode DiskIo parquet writer — filters by <c>Kind</c>. Schema matches
    /// <see cref="WriteDiskIoAsync"/> minus the <c>Kind</c> column.
    /// </summary>
    internal static async Task<long> WriteDiskIoByKindAsync(List<DiskIoRow> rows, string kind, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fDisk = Df<long>("DiskNumber", true);
        var fOff = Df<ulong>("ByteOffset", true);
        var fSize = Df<long>("TransferSize", true);
        var fPid = Df<long>("PID", true);
        var fFile = DfStr("FileName");
        var fEla = Df<long>("ElapsedMicros", true);
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fDisk, fOff, fSize, fPid, fFile, fEla);
        var filtered = new List<DiskIoRow>(rows.Count);
        for (int i = 0; i < rows.Count; i++)
            if (string.Equals(rows[i].Kind, kind, StringComparison.Ordinal)) filtered.Add(rows[i]);
        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = filtered.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var disk = new long?[n]; var off = new ulong?[n];
            var sz = new long?[n]; var pid = new long?[n]; var fn = new string?[n]; var ela = new long?[n];
            for (int i = 0; i < n; i++) { var r = filtered[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; disk[i] = r.DiskNumber; off[i] = r.ByteOffset; sz[i] = r.TransferSize; pid[i] = r.Pid; fn[i] = r.FileName; ela[i] = r.ElapsedMicros; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fDisk, disk));
            await rg.WriteColumnAsync(new DataColumn(fOff, off));
            await rg.WriteColumnAsync(new DataColumn(fSize, sz));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fFile, fn));
            await rg.WriteColumnAsync(new DataColumn(fEla, ela));
        });
    }

    internal static async Task<long> WriteDpcIsrAsync(List<DpcIsrRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fKind = DfStr("Kind");
        var fRoutine = Df<ulong>("Routine", false);
        var fEla = Df<long>("ElapsedMicros", false);
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fKind, fRoutine, fEla);
        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var kind = new string?[n]; var rt = new ulong[n]; var ela = new long[n];
            for (int i = 0; i < n; i++) { var r = rows[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; kind[i] = r.Kind; rt[i] = r.Routine; ela[i] = r.ElapsedMicros; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fKind, kind));
            await rg.WriteColumnAsync(new DataColumn(fRoutine, rt));
            await rg.WriteColumnAsync(new DataColumn(fEla, ela));
        });
    }

    /// <summary>
    /// Per-opcode DPC/ISR parquet writer — filters a combined DpcIsr buffer by
    /// the <c>Kind</c> discriminator. Schema matches <see cref="WriteDpcIsrAsync"/>
    /// minus the <c>Kind</c> column (each file is a single opcode).
    /// </summary>
    internal static async Task<long> WriteDpcIsrByKindAsync(List<DpcIsrRow> rows, string kind, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fRoutine = Df<ulong>("Routine", false);
        var fEla = Df<long>("ElapsedMicros", false);
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fRoutine, fEla);
        var filtered = new List<DpcIsrRow>(rows.Count);
        for (int i = 0; i < rows.Count; i++)
            if (string.Equals(rows[i].Kind, kind, StringComparison.Ordinal)) filtered.Add(rows[i]);
        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = filtered.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var rt = new ulong[n]; var ela = new long[n];
            for (int i = 0; i < n; i++) { var r = filtered[i]; es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu; rt[i] = r.Routine; ela[i] = r.ElapsedMicros; }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fRoutine, rt));
            await rg.WriteColumnAsync(new DataColumn(fEla, ela));
        });
    }

    /// <summary>
    /// Per-opcode Thread parquet writer. Single-Kind output (Start/End/DCStart/DCEnd).
    /// </summary>
    internal static async Task<long> WriteThreadByKindAsync(List<ThreadRow> rows, string kind, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fPid = Df<long>("PID", false);
        var fTid = Df<long>("TID", false);
        var fParentPid = Df<long>("ParentPID", true);
        var fParentTid = Df<long>("ParentTID", true);
        var fStart = Df<ulong>("StartAddr", false);
        var fWin32Start = Df<ulong>("Win32StartAddr", false);
        var fStackBase = Df<ulong>("StackBase", false);
        var fStackLimit = Df<ulong>("StackLimit", false);
        var fUserStackBase = Df<ulong>("UserStackBase", false);
        var fUserStackLimit = Df<ulong>("UserStackLimit", false);
        var fBasePri = Df<int>("BasePriority", true);
        var fName = DfStr("ThreadName");
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fPid, fTid, fParentPid, fParentTid,
            fStart, fWin32Start, fStackBase, fStackLimit, fUserStackBase, fUserStackLimit, fBasePri, fName);
        var filtered = new List<ThreadRow>(rows.Count);
        for (int i = 0; i < rows.Count; i++)
            if (string.Equals(rows[i].Kind, kind, StringComparison.Ordinal)) filtered.Add(rows[i]);
        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = filtered.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pid = new long[n]; var tid = new long[n];
            var ppid = new long?[n]; var ptid = new long?[n];
            var sa = new ulong[n]; var wsa = new ulong[n];
            var sb = new ulong[n]; var sl = new ulong[n]; var usb = new ulong[n]; var usl = new ulong[n];
            var bp = new int?[n]; var tn = new string?[n];
            for (int i = 0; i < n; i++)
            {
                var r = filtered[i];
                es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu;
                pid[i] = r.Pid; tid[i] = r.Tid;
                ppid[i] = r.ParentPid; ptid[i] = r.ParentTid;
                sa[i] = r.StartAddr; wsa[i] = r.Win32StartAddr;
                sb[i] = r.StackBase; sl[i] = r.StackLimit; usb[i] = r.UserStackBase; usl[i] = r.UserStackLimit;
                bp[i] = r.BasePriority; tn[i] = r.ThreadName;
            }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fPid, pid));
            await rg.WriteColumnAsync(new DataColumn(fTid, tid));
            await rg.WriteColumnAsync(new DataColumn(fParentPid, ppid));
            await rg.WriteColumnAsync(new DataColumn(fParentTid, ptid));
            await rg.WriteColumnAsync(new DataColumn(fStart, sa));
            await rg.WriteColumnAsync(new DataColumn(fWin32Start, wsa));
            await rg.WriteColumnAsync(new DataColumn(fStackBase, sb));
            await rg.WriteColumnAsync(new DataColumn(fStackLimit, sl));
            await rg.WriteColumnAsync(new DataColumn(fUserStackBase, usb));
            await rg.WriteColumnAsync(new DataColumn(fUserStackLimit, usl));
            await rg.WriteColumnAsync(new DataColumn(fBasePri, bp));
            await rg.WriteColumnAsync(new DataColumn(fName, tn));
        });
    }

    /// <summary>EventTrace/Header parquet — one row per ETL with authoritative metadata.</summary>
    internal static async Task<long> WriteEventTraceHeaderAsync(List<EventTraceHeaderRow> rows, string path)
    {
        var fEventSeq = Df<ulong>("EventSequence", false);
        var fQpc = Df<long>("TimeStampQpc", false);
        var fCpu = Df<int>("CPU", false);
        var fPerfFreq = Df<long>("PerfFreq", false);
        var fNumProc = Df<int>("NumberOfProcessors", false);
        var fTimerRes = Df<int>("TimerResolution", false);
        var fStart = Df<long>("StartTime100Ns", false);
        var fEnd = Df<long>("EndTime100Ns", false);
        var fBoot = Df<long>("BootTime100Ns", false);
        var fCpuSpeed = Df<int>("CpuSpeedMHz", false);
        var fPointerSize = Df<int>("PointerSize", false);
        var fLogMode = Df<int>("LogFileMode", false);
        var fBuffers = Df<int>("BuffersWritten", false);
        var fLost = Df<int>("EventsLost", false);
        var fSession = DfStr("SessionName");
        var fLogFile = DfStr("LogFileName");
        var schema = new ParquetSchema(fEventSeq, fQpc, fCpu, fPerfFreq, fNumProc, fTimerRes,
            fStart, fEnd, fBoot, fCpuSpeed, fPointerSize, fLogMode, fBuffers, fLost, fSession, fLogFile);
        return await WriteRowGroupAsync(path, schema, async rg =>
        {
            int n = rows.Count;
            var es = new ulong[n]; var qpc = new long[n]; var cpu = new int[n];
            var pf = new long[n]; var np = new int[n]; var tr = new int[n];
            var st = new long[n]; var en = new long[n]; var bt = new long[n];
            var cs = new int[n]; var ps = new int[n]; var lm = new int[n];
            var bw = new int[n]; var el = new int[n];
            var sn = new string?[n]; var lf = new string?[n];
            for (int i = 0; i < n; i++)
            {
                var r = rows[i];
                es[i] = r.EventSequence; qpc[i] = r.TimeStampQpc; cpu[i] = r.Cpu;
                pf[i] = r.PerfFreq; np[i] = r.NumberOfProcessors; tr[i] = r.TimerResolution;
                st[i] = r.StartTime100Ns; en[i] = r.EndTime100Ns; bt[i] = r.BootTime100Ns;
                cs[i] = r.CpuSpeedMHz; ps[i] = r.PointerSize; lm[i] = r.LogFileMode;
                bw[i] = r.BuffersWritten; el[i] = r.EventsLost;
                sn[i] = r.SessionName; lf[i] = r.LogFileName;
            }
            await rg.WriteColumnAsync(new DataColumn(fEventSeq, es));
            await rg.WriteColumnAsync(new DataColumn(fQpc, qpc));
            await rg.WriteColumnAsync(new DataColumn(fCpu, cpu));
            await rg.WriteColumnAsync(new DataColumn(fPerfFreq, pf));
            await rg.WriteColumnAsync(new DataColumn(fNumProc, np));
            await rg.WriteColumnAsync(new DataColumn(fTimerRes, tr));
            await rg.WriteColumnAsync(new DataColumn(fStart, st));
            await rg.WriteColumnAsync(new DataColumn(fEnd, en));
            await rg.WriteColumnAsync(new DataColumn(fBoot, bt));
            await rg.WriteColumnAsync(new DataColumn(fCpuSpeed, cs));
            await rg.WriteColumnAsync(new DataColumn(fPointerSize, ps));
            await rg.WriteColumnAsync(new DataColumn(fLogMode, lm));
            await rg.WriteColumnAsync(new DataColumn(fBuffers, bw));
            await rg.WriteColumnAsync(new DataColumn(fLost, el));
            await rg.WriteColumnAsync(new DataColumn(fSession, sn));
            await rg.WriteColumnAsync(new DataColumn(fLogFile, lf));
        });
    }
}
