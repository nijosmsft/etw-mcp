using System.Diagnostics;
using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using EtwExtract.Rows;
namespace EtwExtract;

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
    public double PerfFreq;

    private readonly bool _wantSampled, _wantCSwitch, _wantReady, _wantSysconfig;
    private readonly bool _wantTcpipRecv, _wantTcpipSend, _wantTcpipConnect, _wantTcpipAccept;
    private readonly bool _wantTcpipRetransmit, _wantTcpipDisconnect;
    private readonly bool _wantUdpRecv, _wantUdpSend;
    private readonly bool _wantAfdRecv, _wantAfdSend, _wantAfdConnect, _wantAfdAccept, _wantAfdClose, _wantAfdBind;
    private readonly bool _wantNdisDrop, _wantNdisPacketCapture;
    private readonly bool _wantHttpRecv, _wantHttpDeliver, _wantHttpSend, _wantHttpClose;
    private readonly bool _wantQuicCreate, _wantQuicClose, _wantQuicPktRecv, _wantQuicPktSend, _wantQuicAck;
    private readonly bool _wantProcess, _wantImage, _wantDiskIo, _wantDpcIsr;
    private readonly bool _wantThread, _wantEventTraceHeader;
    private readonly bool _includeTracelogging;
    private readonly bool _panicCallback;
    private bool _panicFired;

    // Provider GUIDs for the manifest providers we route by ProviderGuid below.
    private static readonly Guid s_httpServiceGuid = new("dd5ef90a-6398-47a4-ad34-4dcecdef795f");
    // MsQuic ETW provider (well-known GUID).
    private static readonly Guid s_msquicGuid = new("ff15e657-4f26-570e-88ab-0796b258d11c");

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
        _wantCSwitch = Want("CSwitch", "cswitch", "cswitch_events");
        _wantReady = Want("ReadyThread", "readythread");
        _wantTcpipRecv = Want("TcpIp/Recv", "tcpip_recv");
        _wantTcpipSend = Want("TcpIp/Send", "tcpip_send");
        _wantTcpipConnect = Want("TcpIp/Connect", "tcpip_connect");
        _wantTcpipAccept = Want("TcpIp/Accept", "tcpip_accept");
        _wantTcpipRetransmit = Want("TcpIp/Retransmit", "tcpip_retransmit");
        _wantTcpipDisconnect = Want("TcpIp/Disconnect", "tcpip_disconnect");
        _wantUdpRecv = Want("UdpIp/Recv", "udp_recv");
        _wantUdpSend = Want("UdpIp/Send", "udp_send");
        _wantAfdRecv = Want("AFD/Recv", "afd_recv");
        _wantAfdSend = Want("AFD/Send", "afd_send");
        _wantAfdConnect = Want("AFD/Connect", "afd_connect");
        _wantAfdAccept = Want("AFD/Accept", "afd_accept");
        _wantAfdClose = Want("AFD/Close", "afd_close");
        _wantAfdBind = Want("AFD/Bind", "afd_bind");
        _wantNdisDrop = Want("NdisDrop", "ndis_drops");
        _wantNdisPacketCapture = Want("NdisPacketCapture", "packet_capture");
        _wantHttpRecv = Want("HttpService/Recv", "http_recv");
        _wantHttpDeliver = Want("HttpService/Deliver", "http_deliver");
        _wantHttpSend = Want("HttpService/Send", "http_send");
        _wantHttpClose = Want("HttpService/Close", "http_close");
        _wantQuicCreate = Want("Quic/ConnectionCreated", "quic_conn_created");
        _wantQuicClose = Want("Quic/ConnectionClosed", "quic_conn_closed");
        _wantQuicPktRecv = Want("Quic/PacketRecv", "quic_packet_recv");
        _wantQuicPktSend = Want("Quic/PacketSend", "quic_packet_send");
        _wantQuicAck = Want("Quic/AckReceived", "quic_ack_recv");
        _wantProcess = Want("Process", "process", "Process/Start", "Process/End", "Process/DCStart",
                            "Process/DCEnd", "Process/Defunct",
                            "process_start", "process_end", "process_dcstart", "process_dcend", "process_defunct");
        _wantImage = Want("Image/Load", "Image/DCStart", "image", "images", "image_load", "image_dcstart");
        _wantDiskIo = Want("DiskIo", "diskio", "DiskIo/Read", "DiskIo/Write", "DiskIo/FlushBuffers",
                            "diskio_read", "diskio_write", "diskio_flushbuffers");
        _wantDpcIsr = Want("PerfInfo", "PerfInfo/DPC", "PerfInfo/ThreadedDPC", "PerfInfo/TimerDPC", "PerfInfo/ISR",
                            "dpcisr", "dpc_isr", "perfinfo_dpc", "perfinfo_threaded_dpc", "perfinfo_timer_dpc", "perfinfo_isr");
        _wantThread = Want("Thread", "thread", "Thread/Start", "Thread/End", "Thread/DCStart", "Thread/DCEnd",
                            "thread_start", "thread_end", "thread_dcstart", "thread_dcend");
        _wantEventTraceHeader = Want("EventTrace", "EventTrace/Header", "eventtrace_header");
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

        // QueryPerformanceFrequency from the ETL header — required by the
        // event-store-streaming manifest's timebase.perf_freq field.
        // TraceEvent 3.1 exposes QPCFreq as an internal property; access via
        // reflection so we stay compatible without forking the package.
        try
        {
            var prop = typeof(ETWTraceEventSource).GetProperty("QPCFreq",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public);
            if (prop?.GetValue(source) is long qpcFreq) PerfFreq = qpcFreq;
        }
        catch { PerfFreq = 0.0; }

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

        if (_wantTcpipRecv)
        {
            // MOF route — kernel TCP/IP provider
            kernel.TcpIpRecv += (TcpIpTraceData data) => Wrap(() => AddFlow(Collector.TcpipRecv, BuildFlowRow(data)));
            kernel.TcpIpRecvIPV6 += (TcpIpV6TraceData data) => Wrap(() => AddFlow(Collector.TcpipRecv, BuildFlowRowV6(data)));
        }
        if (_wantTcpipSend)
        {
            kernel.TcpIpSend += (TcpIpSendTraceData data) => Wrap(() => Collector.TcpipSend.Add(BuildFlowRow(data)));
            kernel.TcpIpSendIPV6 += (TcpIpV6SendTraceData data) => Wrap(() => Collector.TcpipSend.Add(BuildFlowRowV6(data)));
        }
        if (_wantTcpipConnect)
        {
            kernel.TcpIpConnect += (TcpIpConnectTraceData data) => Wrap(() => Collector.TcpipConnect.Add(BuildFlowRow(data)));
            kernel.TcpIpConnectIPV6 += (TcpIpV6ConnectTraceData data) => Wrap(() => Collector.TcpipConnect.Add(BuildFlowRowV6(data)));
        }
        if (_wantTcpipAccept)
        {
            kernel.TcpIpAccept += (TcpIpConnectTraceData data) => Wrap(() => Collector.TcpipAccept.Add(BuildFlowRow(data)));
            kernel.TcpIpAcceptIPV6 += (TcpIpV6ConnectTraceData data) => Wrap(() => Collector.TcpipAccept.Add(BuildFlowRowV6(data)));
        }
        if (_wantTcpipRetransmit)
        {
            kernel.TcpIpRetransmit += (TcpIpTraceData data) => Wrap(() => Collector.TcpipRetransmit.Add(BuildFlowRow(data)));
            kernel.TcpIpRetransmitIPV6 += (TcpIpV6TraceData data) => Wrap(() => Collector.TcpipRetransmit.Add(BuildFlowRowV6(data)));
        }
        if (_wantTcpipDisconnect)
        {
            kernel.TcpIpDisconnect += (TcpIpTraceData data) => Wrap(() => Collector.TcpipDisconnect.Add(BuildFlowRow(data)));
            kernel.TcpIpDisconnectIPV6 += (TcpIpV6TraceData data) => Wrap(() => Collector.TcpipDisconnect.Add(BuildFlowRowV6(data)));
        }
        if (_wantUdpRecv)
        {
            kernel.UdpIpRecv += (UdpIpTraceData data) => Wrap(() => Collector.UdpRecv.Add(BuildFlowRow(data)));
            kernel.UdpIpRecvIPV6 += (UpdIpV6TraceData data) => Wrap(() => Collector.UdpRecv.Add(BuildFlowRowV6(data)));
        }
        if (_wantUdpSend)
        {
            kernel.UdpIpSend += (UdpIpTraceData data) => Wrap(() => Collector.UdpSend.Add(BuildFlowRow(data)));
            kernel.UdpIpSendIPV6 += (UpdIpV6TraceData data) => Wrap(() => Collector.UdpSend.Add(BuildFlowRowV6(data)));
        }
        if (_wantProcess)
        {
            kernel.ProcessStart += (ProcessTraceData data) => Wrap(() => AddProcess(data, "Start"));
            kernel.ProcessStop += (ProcessTraceData data) => Wrap(() => AddProcess(data, "End"));
            kernel.ProcessDCStart += (ProcessTraceData data) => Wrap(() => AddProcess(data, "DCStart"));
            kernel.ProcessDCStop += (ProcessTraceData data) => Wrap(() => AddProcess(data, "DCEnd"));
            kernel.ProcessDefunct += (ProcessTraceData data) => Wrap(() => AddProcess(data, "Defunct"));
        }
        if (_wantThread)
        {
            kernel.ThreadStart += (ThreadTraceData data) => Wrap(() => AddThread(data, "Start"));
            kernel.ThreadStop += (ThreadTraceData data) => Wrap(() => AddThread(data, "End"));
            kernel.ThreadDCStart += (ThreadTraceData data) => Wrap(() => AddThread(data, "DCStart"));
            kernel.ThreadDCStop += (ThreadTraceData data) => Wrap(() => AddThread(data, "DCEnd"));
        }
        if (_wantEventTraceHeader)
        {
            kernel.EventTraceHeader += (EventTraceHeaderTraceData data) => Wrap(() =>
            {
                Collector.EventTraceHeader.Add(new EventTraceHeaderRow
                {
                    EventSequence = Collector.NextSeq(),
                    TimeStampQpc = data.TimeStampQPC,
                    Cpu = data.ProcessorNumber,
                    PerfFreq = data.PerfFreq,
                    NumberOfProcessors = data.NumberOfProcessors,
                    TimerResolution = data.TimerResolution,
                    StartTime100Ns = data.StartTime.ToFileTimeUtc(),
                    EndTime100Ns = data.EndTime != DateTime.MinValue ? data.EndTime.ToFileTimeUtc() : 0,
                    BootTime100Ns = data.BootTime != DateTime.MinValue ? data.BootTime.ToFileTimeUtc() : 0,
                    CpuSpeedMHz = data.CPUSpeed,
                    PointerSize = source.PointerSize,
                    LogFileMode = data.LogFileMode,
                    BuffersWritten = data.BuffersWritten,
                    EventsLost = data.EventsLost,
                    SessionName = data.SessionName,
                    LogFileName = data.LogFileName,
                });
                // Promote header values into the QPC origin & PerfFreq fields when
                // they weren't picked up via reflection from the source header.
                if (PerfFreq <= 0 && data.PerfFreq > 0) PerfFreq = data.PerfFreq;
            });
        }
        if (_wantImage)
        {
            kernel.ImageLoad += (ImageLoadTraceData data) => Wrap(() => AddImage(data, "Load"));
            kernel.ImageDCStart += (ImageLoadTraceData data) => Wrap(() => AddImage(data, "DCStart"));
        }
        if (_wantDiskIo)
        {
            kernel.DiskIORead += (DiskIOTraceData data) => Wrap(() => AddDiskIo(data, "Read"));
            kernel.DiskIOWrite += (DiskIOTraceData data) => Wrap(() => AddDiskIo(data, "Write"));
            kernel.DiskIOFlushBuffers += (DiskIOFlushBuffersTraceData data) => Wrap(() => Collector.DiskIo.Add(new DiskIoRow
            {
                EventSequence = Collector.NextSeq(),
                TimeStampQpc = data.TimeStampQPC,
                Cpu = data.ProcessorNumber,
                Kind = "FlushBuffers",
                DiskNumber = data.DiskNumber,
            }));
        }
        if (_wantDpcIsr)
        {
            kernel.PerfInfoDPC += (DPCTraceData data) => Wrap(() => Collector.DpcIsr.Add(new DpcIsrRow
            {
                EventSequence = Collector.NextSeq(),
                TimeStampQpc = data.TimeStampQPC,
                Cpu = data.ProcessorNumber,
                Kind = "DPC",
                Routine = (ulong)data.Routine,
                ElapsedMicros = (long)((data.ElapsedTimeMSec) * 1000.0),
            }));
            kernel.PerfInfoThreadedDPC += (DPCTraceData data) => Wrap(() => Collector.DpcIsr.Add(new DpcIsrRow
            {
                EventSequence = Collector.NextSeq(),
                TimeStampQpc = data.TimeStampQPC,
                Cpu = data.ProcessorNumber,
                Kind = "ThreadedDPC",
                Routine = (ulong)data.Routine,
                ElapsedMicros = (long)((data.ElapsedTimeMSec) * 1000.0),
            }));
            kernel.PerfInfoISR += (ISRTraceData data) => Wrap(() => Collector.DpcIsr.Add(new DpcIsrRow
            {
                EventSequence = Collector.NextSeq(),
                TimeStampQpc = data.TimeStampQPC,
                Cpu = data.ProcessorNumber,
                Kind = "ISR",
                Routine = (ulong)data.Routine,
                ElapsedMicros = (long)((data.ElapsedTimeMSec) * 1000.0),
            }));
            kernel.PerfInfoTimerDPC += (DPCTraceData data) => Wrap(() => Collector.DpcIsr.Add(new DpcIsrRow
            {
                EventSequence = Collector.NextSeq(),
                TimeStampQpc = data.TimeStampQPC,
                Cpu = data.ProcessorNumber,
                Kind = "TimerDPC",
                Routine = (ulong)data.Routine,
                ElapsedMicros = (long)((data.ElapsedTimeMSec) * 1000.0),
            }));
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
            if (data.ProviderGuid == AfdProviderGuid)
            {
                var name = (data.TaskName ?? "") + "/" + (data.OpcodeName ?? "") + "/" + (data.EventName ?? "");
                if (_wantAfdRecv && (name.Contains("Receive", StringComparison.OrdinalIgnoreCase) || name.Contains("Recv", StringComparison.OrdinalIgnoreCase)))
                {
                    EmitAfd(data, Collector.AfdRecv);
                    _consumedKeys.Add((data.ProviderGuid, (int)data.ID));
                    return;
                }
                if (_wantAfdSend && name.Contains("Send", StringComparison.OrdinalIgnoreCase))
                {
                    EmitAfdEvent(data, Collector.AfdSend);
                    _consumedKeys.Add((data.ProviderGuid, (int)data.ID));
                    return;
                }
                if (_wantAfdConnect && name.Contains("Connect", StringComparison.OrdinalIgnoreCase))
                {
                    EmitAfdEvent(data, Collector.AfdConnect);
                    _consumedKeys.Add((data.ProviderGuid, (int)data.ID));
                    return;
                }
                if (_wantAfdAccept && name.Contains("Accept", StringComparison.OrdinalIgnoreCase))
                {
                    EmitAfdEvent(data, Collector.AfdAccept);
                    _consumedKeys.Add((data.ProviderGuid, (int)data.ID));
                    return;
                }
                if (_wantAfdClose && name.Contains("Close", StringComparison.OrdinalIgnoreCase))
                {
                    EmitAfdEvent(data, Collector.AfdClose);
                    _consumedKeys.Add((data.ProviderGuid, (int)data.ID));
                    return;
                }
                if (_wantAfdBind && name.Contains("Bind", StringComparison.OrdinalIgnoreCase))
                {
                    EmitAfdEvent(data, Collector.AfdBind);
                    _consumedKeys.Add((data.ProviderGuid, (int)data.ID));
                    return;
                }
            }
            if (data.ProviderGuid == NdisManifestGuid || data.ProviderGuid == NdisPacketCaptureGuid)
            {
                var name = (data.TaskName ?? "") + "/" + (data.OpcodeName ?? "") + "/" + (data.EventName ?? "");
                if (_wantNdisDrop && (name.Contains("Drop", StringComparison.OrdinalIgnoreCase) || name.Contains("Discard", StringComparison.OrdinalIgnoreCase)))
                {
                    EmitNdisDrop(data);
                    _consumedKeys.Add((data.ProviderGuid, (int)data.ID));
                    return;
                }
                if (_wantNdisPacketCapture && data.ProviderGuid == NdisPacketCaptureGuid &&
                    (name.Contains("Packet", StringComparison.OrdinalIgnoreCase) || name.Contains("Capture", StringComparison.OrdinalIgnoreCase) || name.Contains("Fragment", StringComparison.OrdinalIgnoreCase)))
                {
                    EmitNdisPacketCapture(data);
                    _consumedKeys.Add((data.ProviderGuid, (int)data.ID));
                    return;
                }
            }
            if (_wantTcpipRecv && data.ProviderGuid == TcpipManifestGuid)
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
            if (data.ProviderGuid == s_httpServiceGuid)
            {
                var name = (data.TaskName ?? "") + "/" + (data.OpcodeName ?? "") + "/" + (data.EventName ?? "");
                if (_wantHttpRecv && name.Contains("Recv", StringComparison.OrdinalIgnoreCase))
                { EmitHttp(data, Collector.HttpRecv); _consumedKeys.Add((data.ProviderGuid, (int)data.ID)); return; }
                if (_wantHttpDeliver && name.Contains("Deliver", StringComparison.OrdinalIgnoreCase))
                { EmitHttp(data, Collector.HttpDeliver); _consumedKeys.Add((data.ProviderGuid, (int)data.ID)); return; }
                if (_wantHttpSend && name.Contains("Send", StringComparison.OrdinalIgnoreCase))
                { EmitHttp(data, Collector.HttpSend); _consumedKeys.Add((data.ProviderGuid, (int)data.ID)); return; }
                if (_wantHttpClose && name.Contains("Close", StringComparison.OrdinalIgnoreCase))
                { EmitHttp(data, Collector.HttpClose); _consumedKeys.Add((data.ProviderGuid, (int)data.ID)); return; }
            }
            if (data.ProviderGuid == s_msquicGuid)
            {
                var name = (data.TaskName ?? "") + "/" + (data.OpcodeName ?? "") + "/" + (data.EventName ?? "");
                if (_wantQuicCreate && (name.Contains("ConnectionCreated", StringComparison.OrdinalIgnoreCase) || name.Contains("Created", StringComparison.OrdinalIgnoreCase)))
                { EmitQuic(data, Collector.QuicConnCreated); _consumedKeys.Add((data.ProviderGuid, (int)data.ID)); return; }
                if (_wantQuicClose && (name.Contains("ConnectionClosed", StringComparison.OrdinalIgnoreCase) || name.Contains("Closed", StringComparison.OrdinalIgnoreCase)))
                { EmitQuic(data, Collector.QuicConnClosed); _consumedKeys.Add((data.ProviderGuid, (int)data.ID)); return; }
                if (_wantQuicPktRecv && name.Contains("PacketRecv", StringComparison.OrdinalIgnoreCase))
                { EmitQuic(data, Collector.QuicPacketRecv); _consumedKeys.Add((data.ProviderGuid, (int)data.ID)); return; }
                if (_wantQuicPktSend && name.Contains("PacketSend", StringComparison.OrdinalIgnoreCase))
                { EmitQuic(data, Collector.QuicPacketSend); _consumedKeys.Add((data.ProviderGuid, (int)data.ID)); return; }
                if (_wantQuicAck && name.Contains("Ack", StringComparison.OrdinalIgnoreCase))
                { EmitQuic(data, Collector.QuicAckReceived); _consumedKeys.Add((data.ProviderGuid, (int)data.ID)); return; }
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
        }) { IsBackground = true, Name = "etw-mcp-heartbeat" };
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

    // ----- TcpIp / UdpIp helpers (MOF kernel) -----

    private NetworkFlowRow BuildFlowRow(TcpIpTraceData data) => new()
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

    private NetworkFlowRow BuildFlowRow(TcpIpSendTraceData data) => new()
    {
        EventSequence = Collector.NextSeq(),
        TimeStampQpc = data.TimeStampQPC,
        Cpu = data.ProcessorNumber,
        ProcessName = data.ProcessName,
        Pid = data.ProcessID,
        ThreadId = data.ThreadID,
        LocalAddr = data.saddr?.ToString(),
        LocalPort = data.sport,
        RemoteAddr = data.daddr?.ToString(),
        RemotePort = data.dport,
        Size = data.size,
        SeqNo = (ulong)(uint)data.startime,
        ConnId = (ulong)data.connid,
    };

    private NetworkFlowRow BuildFlowRow(TcpIpConnectTraceData data) => new()
    {
        EventSequence = Collector.NextSeq(),
        TimeStampQpc = data.TimeStampQPC,
        Cpu = data.ProcessorNumber,
        ProcessName = data.ProcessName,
        Pid = data.ProcessID,
        ThreadId = data.ThreadID,
        LocalAddr = data.saddr?.ToString(),
        LocalPort = data.sport,
        RemoteAddr = data.daddr?.ToString(),
        RemotePort = data.dport,
        Size = data.size,
        ConnId = (ulong)data.connid,
    };

    private NetworkFlowRow BuildFlowRowV6(TcpIpV6TraceData data) => new()
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

    private NetworkFlowRow BuildFlowRowV6(TcpIpV6SendTraceData data) => new()
    {
        EventSequence = Collector.NextSeq(),
        TimeStampQpc = data.TimeStampQPC,
        Cpu = data.ProcessorNumber,
        ProcessName = data.ProcessName,
        Pid = data.ProcessID,
        ThreadId = data.ThreadID,
        LocalAddr = data.saddr?.ToString(),
        LocalPort = data.sport,
        RemoteAddr = data.daddr?.ToString(),
        RemotePort = data.dport,
        Size = data.size,
        SeqNo = (ulong)(uint)data.startime,
        ConnId = (ulong)data.connid,
    };

    private NetworkFlowRow BuildFlowRowV6(TcpIpV6ConnectTraceData data) => new()
    {
        EventSequence = Collector.NextSeq(),
        TimeStampQpc = data.TimeStampQPC,
        Cpu = data.ProcessorNumber,
        ProcessName = data.ProcessName,
        Pid = data.ProcessID,
        ThreadId = data.ThreadID,
        LocalAddr = data.saddr?.ToString(),
        LocalPort = data.sport,
        RemoteAddr = data.daddr?.ToString(),
        RemotePort = data.dport,
        Size = data.size,
        ConnId = (ulong)data.connid,
    };

    private NetworkFlowRow BuildFlowRow(UdpIpTraceData data) => new()
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
    };

    private NetworkFlowRow BuildFlowRowV6(UpdIpV6TraceData data) => new()
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
    };

    private static void AddFlow(RowBuffer<TcpipRecvRow> dest, NetworkFlowRow src)
        => dest.Add(new TcpipRecvRow
        {
            EventSequence = src.EventSequence,
            TimeStampQpc = src.TimeStampQpc,
            Cpu = src.Cpu,
            ProcessName = src.ProcessName,
            Pid = src.Pid,
            ThreadId = src.ThreadId,
            LocalAddr = src.LocalAddr,
            LocalPort = src.LocalPort,
            RemoteAddr = src.RemoteAddr,
            RemotePort = src.RemotePort,
            Size = src.Size,
            SeqNo = src.SeqNo,
            ConnId = src.ConnId,
        });

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

    private void EmitAfd(TraceEvent data, RowBuffer<AfdRecvRow> dest)
    {
        dest.Add(new AfdRecvRow
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
        });
    }

    private void EmitAfdEvent(TraceEvent data, RowBuffer<AfdEventRow> dest)
    {
        dest.Add(new AfdEventRow
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
        });
    }

    // ----- NDIS drop / packet capture -----

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

    private void EmitNdisPacketCapture(TraceEvent data)
    {
        var fragment = data.PayloadByName("Fragment") as byte[];
        Collector.NdisPacketCapture.Add(new NdisPacketCaptureRow
        {
            EventSequence = Collector.NextSeq(),
            TimeStampQpc = data.TimeStampQPC,
            Cpu = data.ProcessorNumber,
            MiniportName = AsString(data.PayloadByName("MiniportName") ?? data.PayloadByName("FriendlyName") ?? data.PayloadByName("MiniportIfName")),
            Direction = data.OpcodeName ?? data.EventName,
            FragmentSize = AsLong(data.PayloadByName("FragmentSize") ?? data.PayloadByName("Size")) ?? fragment?.Length,
            Fragment = fragment,
        });
    }

    // ----- HTTP.sys -----

    private void EmitHttp(TraceEvent data, RowBuffer<HttpRow> dest)
    {
        dest.Add(new HttpRow
        {
            EventSequence = Collector.NextSeq(),
            TimeStampQpc = data.TimeStampQPC,
            Cpu = data.ProcessorNumber,
            ProcessName = data.ProcessName,
            Pid = data.ProcessID,
            ThreadId = data.ThreadID,
            RequestId = AsUlong(data.PayloadByName("RequestId") ?? data.PayloadByName("RequestObj")),
            ConnectionId = AsUlong(data.PayloadByName("ConnectionId") ?? data.PayloadByName("ConnObj")),
            UrlGroupId = AsUlong(data.PayloadByName("UrlGroupId")),
            Url = AsString(data.PayloadByName("Url")),
            Verb = AsString(data.PayloadByName("Verb")),
            Status = AsLong(data.PayloadByName("StatusCode") ?? data.PayloadByName("Status")),
            BytesSent = AsLong(data.PayloadByName("BytesSent")),
            BytesReceived = AsLong(data.PayloadByName("BytesReceived")),
        });
    }

    // ----- MsQuic -----

    private void EmitQuic(TraceEvent data, RowBuffer<QuicRow> dest)
    {
        dest.Add(new QuicRow
        {
            EventSequence = Collector.NextSeq(),
            TimeStampQpc = data.TimeStampQPC,
            Cpu = data.ProcessorNumber,
            ProcessName = data.ProcessName,
            Pid = data.ProcessID,
            ThreadId = data.ThreadID,
            ConnectionId = AsUlong(data.PayloadByName("ConnectionId") ?? data.PayloadByName("Connection")),
            Cid = AsString(data.PayloadByName("Cid") ?? data.PayloadByName("ClientCid") ?? data.PayloadByName("SrcCid") ?? data.PayloadByName("DstCid")),
            PacketNumber = AsUlong(data.PayloadByName("PacketNumber") ?? data.PayloadByName("PacketNum") ?? data.PayloadByName("PktNum")),
            PacketSize = AsLong(data.PayloadByName("PacketSize") ?? data.PayloadByName("PktSize") ?? data.PayloadByName("Length")),
            AckDelayUs = AsLong(data.PayloadByName("AckDelay") ?? data.PayloadByName("AckDelayUs")),
        });
    }

    // ----- Process / Image / DiskIo -----

    private void AddProcess(ProcessTraceData data, string kind)
    {
        Collector.Process.Add(new ProcessRow
        {
            EventSequence = Collector.NextSeq(),
            TimeStampQpc = data.TimeStampQPC,
            Cpu = data.ProcessorNumber,
            Kind = kind,
            Pid = data.ProcessID,
            ParentPid = data.ParentID,
            ImageFileName = data.ImageFileName,
            CommandLine = data.CommandLine,
        });
    }

    private void AddThread(ThreadTraceData data, string kind)
    {
        Collector.Thread.Add(new ThreadRow
        {
            EventSequence = Collector.NextSeq(),
            TimeStampQpc = data.TimeStampQPC,
            Cpu = data.ProcessorNumber,
            Kind = kind,
            Pid = data.ProcessID,
            Tid = data.ThreadID,
            ParentPid = data.ParentProcessID,
            ParentTid = data.ParentThreadID,
            StartAddr = data.StartAddr,
            Win32StartAddr = data.Win32StartAddr,
            StackBase = data.StackBase,
            StackLimit = data.StackLimit,
            UserStackBase = data.UserStackBase,
            UserStackLimit = data.UserStackLimit,
            BasePriority = data.BasePriority,
            ThreadName = data.ThreadName,
        });
    }

    private void AddImage(ImageLoadTraceData data, string kind)
    {
        Collector.Image.Add(new ImageRow
        {
            EventSequence = Collector.NextSeq(),
            TimeStampQpc = data.TimeStampQPC,
            Cpu = data.ProcessorNumber,
            Kind = kind,
            Pid = data.ProcessID,
            ImageBase = (ulong)data.ImageBase,
            ImageSize = data.ImageSize,
            TimeDateStamp = data.TimeDateStamp,
            FileName = data.FileName,
        });
    }

    private void AddDiskIo(DiskIOTraceData data, string kind)
    {
        Collector.DiskIo.Add(new DiskIoRow
        {
            EventSequence = Collector.NextSeq(),
            TimeStampQpc = data.TimeStampQPC,
            Cpu = data.ProcessorNumber,
            Kind = kind,
            DiskNumber = data.DiskNumber,
            ByteOffset = (ulong)data.ByteOffset,
            TransferSize = data.TransferSize,
            Pid = data.ProcessID,
            FileName = data.FileName,
            ElapsedMicros = (long)(data.ElapsedTimeMSec * 1000.0),
        });
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
