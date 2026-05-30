using System.Diagnostics;
using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using WprMcpExtract.Rows;
namespace WprMcpExtract;

/// <summary>
/// Owns the TraceEvent session lifecycle: open ETL, hook events, run
/// ProcessTrace to completion, populate buffers, and emit progress.
/// </summary>
internal sealed class ExtractRunner
{
    // Provider GUIDs for manifest-based events (spike-contract §6).
    private static readonly Guid AfdProviderGuid = new("e53c6823-7bb8-44bb-90dc-3f86090d48a6");
    private static readonly Guid NdisManifestGuid = new("cdeb2c52-5d52-4d97-9fd0-7a13a3a4cdfa");
    private static readonly Guid NdisPacketCaptureGuid = new("2ed6006e-4f4a-4a6d-b5c3-83e3bc8cc3a4");
    private static readonly Guid TcpipManifestGuid = new("2f07e2ee-15db-40f1-90ef-9d7ba282188a");
    // KernelTraceControl / EventTrace meta-provider (rundown, partition info, etc.).
    private static readonly Guid s_kernelTraceGuid = new("9e814aad-3204-11d2-9a82-006008a86939");

    private readonly Request _req;
    private readonly JsonlEmitter _emit;
    public readonly EventCollector Collector = new();
    public readonly SysconfigCollector Sysconfig = new();
    public long EventsLost;
    public long QpcOrigin;

    private readonly bool _wantSampled, _wantCSwitch, _wantReady, _wantTcpip, _wantAfd, _wantNdisDrop, _wantSysconfig;
    private readonly bool _includeTracelogging;
    private readonly bool _panicCallback;
    private bool _panicFired;

    // (ProviderGuid, EventID) pairs already routed to a typed buffer; skip those in
    // the generic TraceLogging path so we don't double-record known events.
    private readonly HashSet<(Guid, int)> _consumedKeys = new();

    public ExtractRunner(Request req, JsonlEmitter emit)
    {
        _req = req;
        _emit = emit;
        var lc = req.RequestedEventClasses.Select(s => s.ToLowerInvariant()).ToHashSet();
        bool Want(params string[] aliases) => aliases.Any(a => lc.Contains(a.ToLowerInvariant()));
        _wantSampled = Want("SampledProfile", "sampled_profile");
        _wantCSwitch = Want("CSwitch", "cswitch");
        _wantReady = Want("ReadyThread", "readythread");
        _wantTcpip = Want("TcpIp/Recv", "tcpip_recv");
        _wantAfd = Want("AFD/Recv", "afd_recv");
        _wantNdisDrop = Want("NdisDrop", "ndis_drops");
        _wantSysconfig = Want("SystemConfig", "sysconfig");
        _includeTracelogging = req.IncludeTracelogging;
        _panicCallback = req.PanicProbe == "callback_panic";
    }

    public void Run()
    {
        using var source = new ETWTraceEventSource(_req.EtlPath);

        // Capture origin from the very first event.
        bool gotOrigin = false;

        Sysconfig.Hostname = Environment.MachineName;
        Sysconfig.OsArch = source.PointerSize == 8 ? "x64" : "x86";

        var kernel = source.Kernel;

        Exception? fatalError = null;
        void Wrap(Action fn)
        {
            try { fn(); }
            catch (Exception ex) when (!IsFatalPanic(ex))
            {
                Collector.CallbackExceptions++;
                _emit.Log("WARN", "callback", $"caught {ex.GetType().Name}: {ex.Message}");
            }
            catch (Exception ex)
            {
                // panic_probe — let it escape to abort the trace processing.
                fatalError = ex;
                try { source.StopProcessing(); } catch { /* swallow */ }
                throw;
            }
        }
        bool IsFatalPanic(Exception ex)
            => _panicCallback && ex.Message.Contains("panic_probe");

        void OnEvent(TraceEvent data)
        {
            if (!gotOrigin) { QpcOrigin = data.TimeStampQPC; gotOrigin = true; }
            Collector.EventsDecoded++;
            if (_panicCallback && !_panicFired)
            {
                _panicFired = true;
                throw new InvalidOperationException("panic_probe=callback_panic triggered");
            }
        }

        if (_wantSampled)
        {
            kernel.PerfInfoSample += (SampledProfileTraceData data) => Wrap(() =>
            {
                var row = new SampledProfileRow
                {
                    EventSequence = Collector.NextSeq(),
                    TimeStampQpc = data.TimeStampQPC,
                    Cpu = data.ProcessorNumber,
                    ProcessId = data.ProcessID,
                    ThreadId = data.ThreadID,
                    PayloadThreadId = data.ThreadID,
                    InstructionPointer = (ulong)data.InstructionPointer,
                    Weight = 1,
                    ProfileWeight = data.Count > 0 ? data.Count : 1,
                };
                Collector.SampledProfile.Add(row);
                Collector.StackEligibleEvents++;
                var thisRow = row;
                Collector.Pending.Add(thisRow.TimeStampQpc, thisRow.ThreadId ?? 0, addr => thisRow.Stack = addr);
            });
        }

        if (_wantCSwitch)
        {
            kernel.ThreadCSwitch += (CSwitchTraceData data) => Wrap(() =>
            {
                var row = new CSwitchRow
                {
                    EventSequence = Collector.NextSeq(),
                    TimeStampQpc = data.TimeStampQPC,
                    Cpu = data.ProcessorNumber,
                    NewTid = data.NewThreadID,
                    OldTid = data.OldThreadID,
                    NewPid = data.NewProcessID,
                    OldPid = data.OldProcessID,
                    WaitReason = data.OldThreadWaitReason.ToString(),
                };
                Collector.CSwitch.Add(row);
                Collector.StackEligibleEvents++;
                var thisRow = row;
                // Stacks on CSwitch pair to the NEW thread (the one being scheduled in).
                Collector.Pending.Add(thisRow.TimeStampQpc, thisRow.NewTid ?? 0, addr => thisRow.Stack = addr);
            });
        }

        if (_wantReady)
        {
            kernel.DispatcherReadyThread += (DispatcherReadyThreadTraceData data) => Wrap(() =>
            {
                var row = new ReadyThreadRow
                {
                    EventSequence = Collector.NextSeq(),
                    TimeStampQpc = data.TimeStampQPC,
                    Cpu = data.ProcessorNumber,
                    ProcessId = data.ProcessID,
                    ThreadId = data.ThreadID,
                    AdjustReason = (int)data.AdjustReason,
                    AdjustIncrement = data.AdjustIncrement,
                    Flag = (int)data.Flags,
                };
                Collector.ReadyThread.Add(row);
                Collector.StackEligibleEvents++;
                var thisRow = row;
                // The stack belongs to the readying (current) thread, not awakened.
                Collector.Pending.Add(thisRow.TimeStampQpc, thisRow.ThreadId ?? 0, addr => thisRow.Stack = addr);
            });
        }

        // StackWalk pairing — always hook even if a wantable class is off,
        // because some flush ordering rules require it.
        kernel.StackWalkStack += (StackWalkStackTraceData data) => Wrap(() =>
        {
            Collector.StackWalksSeen++;
            int n = data.FrameCount;
            if (n <= 0) return;
            var addrs = new List<ulong>(n);
            for (int i = 0; i < n; i++)
                addrs.Add((ulong)data.InstructionPointer(i));
            if (Collector.Pending.TryPair(data.EventTimeStampQPC, data.ThreadID, addrs))
                Collector.StacksPaired++;
        });

        if (_wantTcpip)
        {
            // MOF route — kernel TCP/IP provider
            kernel.TcpIpRecv += (TcpIpTraceData data) => Wrap(() => EmitTcpipRecv(data, isV6: false));
            kernel.TcpIpRecvIPV6 += (TcpIpV6TraceData data) => Wrap(() => EmitTcpipRecvV6(data));
        }

        if (_wantSysconfig)
        {
            kernel.SystemConfigCPU += (SystemConfigCPUTraceData data) => Wrap(() =>
            {
                Sysconfig.CpuCores = data.NumberOfProcessors;
                Sysconfig.CpuSockets = data.HyperThreadingFlag != 0 ? Math.Max(1, data.NumberOfProcessors / 2) : data.NumberOfProcessors;
                if (string.IsNullOrEmpty(Sysconfig.CpuModel))
                    Sysconfig.CpuModel = $"CPU @ {data.MHz}MHz";
                if (!string.IsNullOrEmpty(data.ComputerName))
                    Sysconfig.Hostname = data.ComputerName;
            });
            kernel.SystemConfigNIC += (SystemConfigNICTraceData data) => Wrap(() =>
            {
                var mac = FormatMacInt64(data.PhysicalAddr, data.PhysicalAddrLen);
                Sysconfig.Nics.Add(new SysconfigCollector.NicInfo(
                    data.NICDescription ?? "Unknown",
                    data.NICDescription ?? "Unknown",
                    mac,
                    0L));
            });
            kernel.SystemConfigPhyDisk += (SystemConfigPhyDiskTraceData data) => Wrap(() =>
            {
                long size = (long)data.BytesPerSector * data.SectorsPerTrack * data.TracksPerCylinder * data.Cylinders;
                Sysconfig.Disks.Add(new SysconfigCollector.DiskInfo(
                    data.Manufacturer ?? "Unknown",
                    size,
                    data.PartitionCount));
            });
            kernel.SystemConfigPnP += (SystemConfigPnPTraceData data) => Wrap(() =>
            {
                // PnP descriptions often include the CPU model string.
                var desc = data.DeviceDescription ?? "";
                if (desc.Contains("Intel", StringComparison.OrdinalIgnoreCase) || desc.Contains("AMD", StringComparison.OrdinalIgnoreCase))
                {
                    if (desc.Contains("CPU", StringComparison.OrdinalIgnoreCase) || desc.Contains("Processor", StringComparison.OrdinalIgnoreCase) || desc.Contains("Xeon", StringComparison.OrdinalIgnoreCase))
                    {
                        if (string.IsNullOrEmpty(Sysconfig.CpuModel) || Sysconfig.CpuModel!.StartsWith("CPU @"))
                            Sysconfig.CpuModel = desc.Trim();
                    }
                }
            });
        }

        // Dynamic (manifest) events: AFD, NDIS, TCPIP-manifest.
        // Force-register the manifest parsers TraceEvent ships so their All
        // callbacks fire for offline ETLs (Dynamic.All alone isn't enough
        // when no parser instance has materialized the provider's manifest).
        var tcpipManifest = new MicrosoftWindowsTCPIPTraceEventParser(source);
        var ndisCapture = new MicrosoftWindowsNDISPacketCaptureTraceEventParser(source);
        var registered = new RegisteredTraceEventParser(source);
        var dynamic = source.Dynamic;

        void DispatchManifest(TraceEvent data)
        {
            // Counter bookkeeping is done by AllEvents; do not double-count.
            if (_wantAfd && data.ProviderGuid == AfdProviderGuid)
            {
                var name = (data.TaskName ?? "") + "/" + (data.OpcodeName ?? "") + "/" + (data.EventName ?? "");
                if (name.Contains("Receive", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Recv", StringComparison.OrdinalIgnoreCase))
                {
                    EmitAfdRecv(data);
                    _consumedKeys.Add((data.ProviderGuid, (int)data.ID));
                    return;
                }
            }
            if (_wantNdisDrop && (data.ProviderGuid == NdisManifestGuid || data.ProviderGuid == NdisPacketCaptureGuid))
            {
                var name = (data.TaskName ?? "") + "/" + (data.OpcodeName ?? "") + "/" + (data.EventName ?? "");
                if (name.Contains("Drop", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Discard", StringComparison.OrdinalIgnoreCase))
                {
                    EmitNdisDrop(data);
                    _consumedKeys.Add((data.ProviderGuid, (int)data.ID));
                    return;
                }
            }
            if (_wantTcpip && data.ProviderGuid == TcpipManifestGuid)
            {
                var name = (data.TaskName ?? "") + "/" + (data.EventName ?? "");
                if (name.Contains("Receive", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Recv", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("DataTransferReceive", StringComparison.OrdinalIgnoreCase))
                {
                    EmitTcpipManifestRecv(data);
                    _consumedKeys.Add((data.ProviderGuid, (int)data.ID));
                    return;
                }
            }
        }

        // Subscribe to the typed manifest parsers' .All events. TraceEvent
        // does not decode manifest provider events unless something subscribes
        // to that parser. RegisteredTraceEventParser covers any TDH-registered
        // provider (incl. Microsoft-Windows-Winsock-AFD). The typed TCPIP /
        // NDIS-PacketCapture parsers cover providers whose manifests ship in
        // TraceEvent. We also keep Dynamic for self-describing providers.
        tcpipManifest.All += (TraceEvent data) => Wrap(() => { OnEvent(data); DispatchManifest(data); });
        ndisCapture.All += (TraceEvent data) => Wrap(() => { OnEvent(data); DispatchManifest(data); });
        registered.All += (TraceEvent data) => Wrap(() => { OnEvent(data); DispatchManifest(data); });
        dynamic.All += (TraceEvent data) => Wrap(() => { OnEvent(data); DispatchManifest(data); });

        // Diagnostic catch-all (logs unique provider GUIDs once each at DEBUG level).
        // Also the home of the generic TraceLogging path: AllEvents fires once per
        // event regardless of which parser decoded it, so we get coverage for
        // RegisteredTraceEventParser-routed self-describing providers (which is
        // most of the SDN trace) without double-counting.
        var seenProviders = new HashSet<Guid>();
        void HandleAll(TraceEvent data, string via)
        {
            if (_req.LogLevel is "debug" or "trace")
            {
                if (seenProviders.Add(data.ProviderGuid))
                    _emit.Log("DEBUG", "providers", $"[{via}] provider={data.ProviderGuid} name={data.ProviderName} task={data.TaskName}");
            }
            if (_includeTracelogging && !_consumedKeys.Contains((data.ProviderGuid, (int)data.ID)))
            {
                if (data.ProviderGuid == s_kernelTraceGuid) return;
                EmitTraceloggingRow(data);
            }
        }
        // AllEvents fires exactly once per decoded event regardless of which parser
        // handled it, so it's the single safe place to populate the generic
        // TraceLogging buffer without duplicating rows.
        source.AllEvents += (TraceEvent data) => Wrap(() => HandleAll(data, "All"));
        source.UnhandledEvents += (TraceEvent data) => Wrap(() =>
        {
            if (_req.LogLevel is "debug" or "trace" && seenProviders.Add(data.ProviderGuid))
                _emit.Log("DEBUG", "providers", $"[Unhandled] provider={data.ProviderGuid} name={data.ProviderName} task={data.TaskName}");
        });

        // Heartbeat thread.
        using var stop = new ManualResetEventSlim(false);
        var hbThread = new Thread(() =>
        {
            var phase = "decoding";
            long lastEvents = -1;
            while (!stop.IsSet)
            {
                _emit.Heartbeat(phase);
                if (Collector.EventsDecoded != lastEvents)
                {
                    _emit.Progress(phase, Collector.EventsDecoded, Collector.StacksPaired, 0);
                    lastEvents = Collector.EventsDecoded;
                }
                stop.Wait(Math.Max(250, _req.HeartbeatIntervalMs));
            }
        }) { IsBackground = true, Name = "wpr-mcp-heartbeat" };
        hbThread.Start();

        try
        {
            source.Process();
        }
        finally
        {
            stop.Set();
            hbThread.Join(2000);
            EventsLost = source.EventsLost;
        }
        if (fatalError != null) throw fatalError;
    }

    // ----- TcpIp -----

    private void EmitTcpipRecv(TcpIpTraceData data, bool isV6)
    {
        var row = new TcpipRecvRow
        {
            EventSequence = Collector.NextSeq(),
            TimeStampQpc = data.TimeStampQPC,
            Cpu = data.ProcessorNumber,
            ProcessName = data.ProcessName,
            Pid = data.ProcessID,
            ThreadId = data.ThreadID,
            LocalAddr = data.daddr?.ToString(),
            LocalPort = data.dport,
            RemoteAddr = data.saddr?.ToString(),
            RemotePort = data.sport,
            Size = data.size,
            SeqNo = (ulong)(uint)data.seqnum,
            ConnId = (ulong)data.connid,
        };
        Collector.TcpipRecv.Add(row);
    }

    private void EmitTcpipRecvV6(TcpIpV6TraceData data)
    {
        var row = new TcpipRecvRow
        {
            EventSequence = Collector.NextSeq(),
            TimeStampQpc = data.TimeStampQPC,
            Cpu = data.ProcessorNumber,
            ProcessName = data.ProcessName,
            Pid = data.ProcessID,
            ThreadId = data.ThreadID,
            LocalAddr = data.daddr?.ToString(),
            LocalPort = data.dport,
            RemoteAddr = data.saddr?.ToString(),
            RemotePort = data.sport,
            Size = data.size,
            SeqNo = (ulong)(uint)data.seqnum,
            ConnId = (ulong)data.connid,
        };
        Collector.TcpipRecv.Add(row);
    }

    private void EmitTcpipManifestRecv(TraceEvent data)
    {
        var row = new TcpipRecvRow
        {
            EventSequence = Collector.NextSeq(),
            TimeStampQpc = data.TimeStampQPC,
            Cpu = data.ProcessorNumber,
            ProcessName = data.ProcessName,
            Pid = data.ProcessID,
            ThreadId = data.ThreadID,
            LocalAddr = AsString(data.PayloadByName("LocalAddress")) ?? AsString(data.PayloadByName("daddr")),
            LocalPort = AsLong(data.PayloadByName("LocalPort") ?? data.PayloadByName("dport")),
            RemoteAddr = AsString(data.PayloadByName("RemoteAddress")) ?? AsString(data.PayloadByName("saddr")),
            RemotePort = AsLong(data.PayloadByName("RemotePort") ?? data.PayloadByName("sport")),
            Size = AsLong(data.PayloadByName("NumBytes") ?? data.PayloadByName("size")),
            SeqNo = AsUlong(data.PayloadByName("SeqNo") ?? data.PayloadByName("seqnum")),
            ConnId = AsUlong(data.PayloadByName("CompartmentId") ?? data.PayloadByName("connid")),
        };
        Collector.TcpipRecv.Add(row);
    }

    // ----- AFD -----

    private void EmitAfdRecv(TraceEvent data)
    {
        var row = new AfdRecvRow
        {
            EventSequence = Collector.NextSeq(),
            TimeStampQpc = data.TimeStampQPC,
            Cpu = data.ProcessorNumber,
            ProcessName = data.ProcessName,
            Pid = data.ProcessID,
            ThreadId = data.ThreadID,
            SocketHandle = AsUlong(data.PayloadByName("Endpoint") ?? data.PayloadByName("SocketHandle") ?? data.PayloadByName("EndpointAddr")),
            Size = AsLong(data.PayloadByName("BytesTransferred") ?? data.PayloadByName("Size") ?? data.PayloadByName("NumBytes")),
            CompletionStatus = AsLong(data.PayloadByName("Status") ?? data.PayloadByName("CompletionStatus")),
        };
        Collector.AfdRecv.Add(row);
    }

    // ----- NDIS drop -----

    private void EmitNdisDrop(TraceEvent data)
    {
        var row = new NdisDropRow
        {
            EventSequence = Collector.NextSeq(),
            TimeStampQpc = data.TimeStampQPC,
            Cpu = data.ProcessorNumber,
            ProcessName = data.ProcessName,
            Pid = data.ProcessID,
            ThreadId = data.ThreadID,
            MiniportName = AsString(data.PayloadByName("FriendlyName") ?? data.PayloadByName("MiniportName") ?? data.PayloadByName("MiniportIfName")),
            Reason = AsString(data.PayloadByName("Reason") ?? data.PayloadByName("DropReason") ?? data.PayloadByName("DroppedReason"))
                     ?? data.OpcodeName ?? data.EventName,
            Size = AsLong(data.PayloadByName("Size") ?? data.PayloadByName("NumBytes") ?? data.PayloadByName("FragmentSize")),
        };
        Collector.NdisDrops.Add(row);
    }

    // ----- Generic TraceLogging -----

    private static readonly System.Text.Json.JsonSerializerOptions s_jsonOpts = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private void EmitTraceloggingRow(TraceEvent data)
    {
        var fields = new Dictionary<string, object?>();
        var names = data.PayloadNames;
        if (names != null)
        {
            foreach (var name in names)
            {
                try { fields[name] = NormalizeForJson(data.PayloadByName(name)); }
                catch (Exception ex) { fields[name] = $"<error: {ex.GetType().Name}>"; }
            }
        }
        string fieldsJson;
        try { fieldsJson = System.Text.Json.JsonSerializer.Serialize(fields, s_jsonOpts); }
        catch { fieldsJson = "{}"; }

        Collector.Tracelogging.Add(new TraceloggingRow
        {
            TimeStampQpc = data.TimeStampQPC,
            ProviderGuid = data.ProviderGuid.ToString("D"),
            ProviderName = data.ProviderName ?? "",
            EventName = data.EventName ?? data.OpcodeName ?? data.TaskName ?? $"Event({(int)data.ID})",
            ProcessId = data.ProcessID,
            ThreadId = data.ThreadID,
            Cpu = data.ProcessorNumber,
            Level = (int)data.Level,
            Keywords = (ulong)data.Keywords,
            FieldsJson = fieldsJson,
        });
    }

    private static object? NormalizeForJson(object? v) => v switch
    {
        null => null,
        string => v,
        bool or sbyte or byte or short or ushort or int or uint or long or ulong or float or double or decimal => v,
        byte[] b => Convert.ToHexString(b),
        IPAddress ip => ip.ToString(),
        Guid g => g.ToString("D"),
        DateTime dt => dt.ToString("O"),
        Enum e => e.ToString(),
        System.Collections.IEnumerable enu => EnumerableToList(enu),
        _ => v.ToString(),
    };

    private static List<object?> EnumerableToList(System.Collections.IEnumerable enu)
    {
        var list = new List<object?>();
        foreach (var item in enu) list.Add(NormalizeForJson(item));
        return list;
    }

    // ----- helpers -----

    private static string? AsString(object? v) => v switch
    {
        null => null,
        string s => s,
        IPAddress ip => ip.ToString(),
        byte[] b => Convert.ToHexString(b),
        _ => v.ToString(),
    };

    private static long? AsLong(object? v) => v switch
    {
        null => null,
        long l => l,
        int i => i,
        uint u => u,
        ulong ul => (long)ul,
        short s => s,
        ushort us => us,
        byte b => b,
        sbyte sb => sb,
        bool bo => bo ? 1 : 0,
        _ => long.TryParse(v.ToString(), out var n) ? n : null,
    };

    private static ulong? AsUlong(object? v) => v switch
    {
        null => null,
        ulong ul => ul,
        long l => (ulong)l,
        int i => (ulong)(uint)i,
        uint u => u,
        _ => ulong.TryParse(v.ToString(), out var n) ? n : null,
    };

    private static string FormatMacInt64(long packed, int len)
    {
        if (len <= 0) return "";
        var n = Math.Min(len, 8);
        var bytes = BitConverter.GetBytes(packed);
        return string.Join(":", bytes.Take(n).Select(b => b.ToString("X2")));
    }
}
