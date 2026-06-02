using System.Text;

namespace EtwExtract;

/// <summary>
/// Collects SystemConfig data from the trace and emits sysconfig.txt
/// in the §6.8 format (CPU / NIC / Disk / OS lines).
/// </summary>
internal sealed class SysconfigCollector
{
    public string? CpuModel;
    public int CpuCores;
    public int CpuSockets;
    public string? OsBuild;
    public string? OsArch;
    public string? Hostname;

    public readonly List<NicInfo> Nics = new();
    public readonly List<DiskInfo> Disks = new();

    public sealed record NicInfo(string FriendlyName, string Driver, string Mac, long Speed);
    public sealed record DiskInfo(string Model, long Size, int Partitions);

    public long WriteFile(string stagingDir)
    {
        var sb = new StringBuilder();
        sb.Append("CPU: ").Append(CpuModel ?? "Unknown").Append(" cores=").Append(CpuCores).Append(" sockets=").Append(CpuSockets).Append('\n');
        foreach (var n in Nics)
            sb.Append("NIC: ").Append(n.FriendlyName).Append(" driver=").Append(n.Driver).Append(" mac=").Append(n.Mac).Append(" speed=").Append(n.Speed).Append('\n');
        foreach (var d in Disks)
            sb.Append("Disk: ").Append(d.Model).Append(" size=").Append(d.Size).Append(" partitions=").Append(d.Partitions).Append('\n');
        sb.Append("OS: build=").Append(OsBuild ?? "Unknown").Append(" arch=").Append(OsArch ?? "Unknown").Append(" hostname=").Append(Hostname ?? "Unknown").Append('\n');
        var path = Path.Combine(stagingDir, "sysconfig.txt");
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
        return new FileInfo(path).Length;
    }
}
