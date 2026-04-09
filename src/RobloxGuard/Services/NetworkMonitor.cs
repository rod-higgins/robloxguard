using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using RobloxGuard.Models;

namespace RobloxGuard.Services;

public class NetworkMonitor
{
    // Known safe Roblox domains/suffixes
    private static readonly string[] KnownSafeDomains = new[]
    {
        "roblox.com",
        "rbxcdn.com",
        "roblox.cn",
        "rbx.com",
        "akamai.net",
        "akamaized.net",
        "cloudflare.com",
        "cloudflare.net",
        "amazonaws.com",
        "azure.com",
        "microsoft.com",
        "windows.com",
        "windowsupdate.com",
        "fastly.net",
        "sentry.io",           // error reporting
        "google-analytics.com", // common analytics
    };

    // Known suspicious patterns
    private static readonly string[] SuspiciousDomains = new[]
    {
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "api.telegram.org",
        "webhook.site",
        "requestbin.com",
        "ngrok.io",
        "pastebin.com",
        "hastebin.com",
        "iplogger.org",
        "grabify.link",
        "iplogger.com",
        "2no.co",
        "yip.su",
    };

    private readonly List<ConnectionEntry> _connections = new();
    private readonly HashSet<string> _seenEndpoints = new();
    private readonly object _lock = new();
    private CancellationTokenSource? _cts;

    public event Action<ConnectionEntry>? ConnectionFound;
    public event Action<string>? StatusChanged;

    public IReadOnlyList<ConnectionEntry> Connections
    {
        get { lock (_lock) return _connections.ToList(); }
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        Task.Run(() => MonitorLoop(_cts.Token));
        StatusChanged?.Invoke("Monitoring started");
    }

    public void Stop()
    {
        _cts?.Cancel();
        StatusChanged?.Invoke("Monitoring stopped");
    }

    private async Task MonitorLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                ScanConnections();
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Scan error: {ex.Message}");
            }

            await Task.Delay(2000, ct);
        }
    }

    private void ScanConnections()
    {
        // Find Roblox processes
        var robloxProcesses = Process.GetProcesses()
            .Where(p =>
            {
                try
                {
                    return p.ProcessName.Contains("Roblox", StringComparison.OrdinalIgnoreCase);
                }
                catch { return false; }
            })
            .Select(p => p.Id)
            .ToHashSet();

        if (robloxProcesses.Count == 0)
        {
            StatusChanged?.Invoke("Roblox not running — waiting...");
            return;
        }

        StatusChanged?.Invoke($"Monitoring {robloxProcesses.Count} Roblox process(es)");

        // Get TCP connections for Roblox PIDs
        var tcpConnections = GetTcpConnectionsForProcesses(robloxProcesses);

        foreach (var (remoteIp, remotePort, state) in tcpConnections)
        {
            var endpoint = $"{remoteIp}:{remotePort}";

            lock (_lock)
            {
                if (_seenEndpoints.Contains(endpoint))
                    continue;
                _seenEndpoints.Add(endpoint);
            }

            var entry = new ConnectionEntry
            {
                Timestamp = DateTime.Now,
                RemoteAddress = remoteIp,
                RemotePort = remotePort,
                Status = state,
            };

            // Resolve hostname
            try
            {
                var hostEntry = Dns.GetHostEntry(remoteIp);
                entry.HostName = hostEntry.HostName;
            }
            catch
            {
                entry.HostName = "";
            }

            // Check if suspicious
            ClassifyConnection(entry);

            lock (_lock)
            {
                _connections.Add(entry);
            }

            ConnectionFound?.Invoke(entry);
        }
    }

    private void ClassifyConnection(ConnectionEntry entry)
    {
        var host = (entry.HostName ?? "").ToLowerInvariant();
        var ip = entry.RemoteAddress;

        // Check against known suspicious domains
        foreach (var suspicious in SuspiciousDomains)
        {
            if (host.Contains(suspicious))
            {
                entry.IsSuspicious = true;
                entry.Reason = $"Known suspicious destination: {suspicious}";
                return;
            }
        }

        // Check if it's a known safe domain
        foreach (var safe in KnownSafeDomains)
        {
            if (host.EndsWith(safe, StringComparison.OrdinalIgnoreCase))
            {
                entry.IsSuspicious = false;
                entry.Reason = "Known Roblox/CDN infrastructure";
                return;
            }
        }

        // Private/local IPs are fine
        if (ip.StartsWith("127.") || ip.StartsWith("10.") ||
            ip.StartsWith("192.168.") || ip.StartsWith("172.16.") ||
            ip == "::1" || ip == "0.0.0.0")
        {
            entry.IsSuspicious = false;
            entry.Reason = "Local/private network";
            return;
        }

        // Unknown external destination — flag for review
        if (string.IsNullOrEmpty(host) || !KnownSafeDomains.Any(d => host.EndsWith(d)))
        {
            entry.IsSuspicious = true;
            entry.Reason = "Unknown external destination — review recommended";
        }
    }

    // P/Invoke to get TCP table with owning PIDs (Windows API)
    private static List<(string ip, int port, string state)> GetTcpConnectionsForProcesses(HashSet<int> pids)
    {
        var results = new List<(string, int, string)>();

        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2 /* AF_INET */, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            int ret = GetExtendedTcpTable(buffer, ref bufferSize, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return results;

            int numEntries = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                if (pids.Contains(row.owningPid))
                {
                    var remoteIp = new IPAddress(row.remoteAddr).ToString();
                    int remotePort = (row.remotePort >> 8) | ((row.remotePort & 0xFF) << 8);
                    var state = ((TcpState)row.state).ToString();

                    if (remoteIp != "0.0.0.0" && remotePort != 0)
                    {
                        results.Add((remoteIp, remotePort, state));
                    }
                }

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return results;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TCP_TABLE_CLASS tableClass, int reserved);

    private enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public int localPort;
        public uint remoteAddr;
        public int remotePort;
        public int owningPid;
    }
}
