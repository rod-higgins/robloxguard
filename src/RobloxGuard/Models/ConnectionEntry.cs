using System;

namespace RobloxGuard.Models;

public class ConnectionEntry
{
    public DateTime Timestamp { get; set; }
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public string HostName { get; set; } = "";
    public string Status { get; set; } = "";
    public bool IsSuspicious { get; set; }
    public string Reason { get; set; } = "";

    public string DisplayTime => Timestamp.ToString("HH:mm:ss");
    public string DisplayAddress => string.IsNullOrEmpty(HostName) ? RemoteAddress : $"{HostName} ({RemoteAddress})";
    public string DisplayFlag => IsSuspicious ? "⚠ SUSPICIOUS" : "✓ OK";
}
