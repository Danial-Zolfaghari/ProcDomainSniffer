using System.Net;

namespace ProcDomainSniffer.Core;

public sealed record SnifferOptions(
    int? Pid,
    string? ProcessName,
    bool IncludeChildren,
    IReadOnlyList<string> Interfaces,
    string? TsharkPath,
    string OutputDirectory,
    bool ShowRepeats,
    IReadOnlyList<int> ExtraTlsPorts);

public sealed record DomainObservation(
    DateTimeOffset Timestamp,
    string Domain,
    string Source,
    int Pid,
    string? Protocol,
    string? Local,
    string? Remote,
    IReadOnlyList<string>? ResolvedIps = null);

public sealed record NetworkPacketObservation(
    DateTimeOffset Timestamp,
    int Pid,
    string Protocol,
    string SourceIp,
    string DestinationIp,
    int DestinationPort,
    string? Domain,
    string RemoteIp,
    int RemotePort);

public sealed record LogMessage(DateTimeOffset Timestamp, string Level, string Message);

public sealed record TsharkInterface(string Id, string Description, bool IsNpcap)
{
    public string Display => $"{Id} - {Description}";
}

public sealed record ProcessDescriptor(int Pid, string Name, string? Path)
{
    public string Display => $"{Name} ({Pid})";
}
