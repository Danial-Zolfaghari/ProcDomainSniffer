namespace ProcDomainSniffer.GUI.Models;

public sealed class ObservationRow
{
    public string Time { get; set; } = "";
    public string Source { get; set; } = "";
    public int Pid { get; set; }
    public string Domain { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string Local { get; set; } = "";
    public string Remote { get; set; } = "";
}

public sealed class DomainCountRow
{
    public string Domain { get; set; } = "";
    public int Count { get; set; }
    public string Sources { get; set; } = "";
}

public sealed class DomainIpRow
{
    public string Domain { get; set; } = "";
    public string ResolvedIps { get; set; } = "";
    public int IpCount { get; set; }
    public string Status { get; set; } = "UNRESOLVED";
    public string Sources { get; set; } = "";
}


public sealed class NetworkPacketRow
{
    public string Time { get; set; } = "";
    public string SourceIp { get; set; } = "";
    public string DestinationIp { get; set; } = "";
    public int DestinationPort { get; set; }
    public string Protocol { get; set; } = "";
    public string Domain { get; set; } = "—";
    public long Requests { get; set; } = 1;

    // Normalized endpoint from the target process point of view. These fields are
    // intentionally not displayed; they are used to collapse request/response
    // traffic into one unique row when "Ignore source IP" is enabled.
    public string RemoteIp { get; set; } = "";
    public int RemotePort { get; set; }
}

public sealed class LogRow
{
    public string Time { get; set; } = "";
    public string Level { get; set; } = "";
    public string Message { get; set; } = "";
}
