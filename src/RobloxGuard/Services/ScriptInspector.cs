using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using RobloxGuard.Models;

namespace RobloxGuard.Services;

public class ScriptInspector
{
    // Suspicious patterns in Luau scripts
    private static readonly (string Pattern, string Warning)[] SuspiciousPatterns = new[]
    {
        (@"HttpService\s*:\s*(?:GetAsync|PostAsync|RequestAsync)", "Makes HTTP requests — check the URL"),
        (@"https?://(?!(?:www\.)?roblox\.com|(?:www\.)?rbxcdn\.com)[^\s""'\)]+", "Connects to non-Roblox URL"),
        (@"discord\.com/api/webhooks", "Sends data to Discord webhook"),
        (@"api\.telegram\.org", "Sends data to Telegram"),
        (@"webhook\.site|requestbin|ngrok", "Sends data to known data-capture service"),
        (@"getfenv|setfenv|loadstring", "Uses dynamic code execution (potential obfuscation)"),
        (@"Players\.LocalPlayer\s*\.\s*(?:UserId|Name|DisplayName)", "Reads player identity info"),
        (@"game:HttpGet|game:HttpPost", "Uses legacy HTTP methods"),
        (@"MarketplaceService.*PromptPurchase", "Prompts in-game purchases"),
        (@"TeleportService.*Teleport", "Teleports player to another game"),
        (@"\\x[0-9a-fA-F]{2}", "Contains hex-escaped strings (possible obfuscation)"),
        (@"string\.char\s*\(", "Builds strings from char codes (possible obfuscation)"),
        (@"_G\[", "Uses global table (possible code injection vector)"),
        (@"require\s*\(\s*\d{5,}", "Requires module by large numeric ID (external module)"),
    };

    // File extensions that may contain Luau/Lua scripts
    private static readonly string[] ScriptExtensions = { ".lua", ".luau", ".rbxm", ".rbxmx", ".rbxl", ".rbxlx" };
    private static readonly string[] TextScriptExtensions = { ".lua", ".luau" };

    private readonly List<ScriptEntry> _scripts = new();
    private readonly HashSet<string> _seenFiles = new();
    private readonly object _lock = new();
    private CancellationTokenSource? _cts;
    private FileSystemWatcher? _watcher;

    public event Action<ScriptEntry>? ScriptFound;
    public event Action<string>? StatusChanged;

    public IReadOnlyList<ScriptEntry> Scripts
    {
        get { lock (_lock) return _scripts.ToList(); }
    }

    private static string[] GetRobloxCachePaths()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();

        return new[]
        {
            Path.Combine(localAppData, "Roblox"),
            Path.Combine(localAppData, "Roblox", "Versions"),
            Path.Combine(temp, "Roblox"),
        };
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();

        // Initial scan
        Task.Run(() => ScanExistingFiles());

        // Watch for new files
        foreach (var path in GetRobloxCachePaths())
        {
            if (Directory.Exists(path))
            {
                WatchDirectory(path);
            }
        }

        StatusChanged?.Invoke("Script inspector started");
    }

    public void Stop()
    {
        _cts?.Cancel();
        _watcher?.Dispose();
        StatusChanged?.Invoke("Script inspector stopped");
    }

    private void WatchDirectory(string path)
    {
        try
        {
            _watcher = new FileSystemWatcher(path)
            {
                IncludeSubdirectories = true,
                EnableRaisingEvents = true,
            };

            _watcher.Created += (_, e) => ProcessFile(e.FullPath);
            _watcher.Changed += (_, e) => ProcessFile(e.FullPath);

            StatusChanged?.Invoke($"Watching: {path}");
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke($"Cannot watch {path}: {ex.Message}");
        }
    }

    private void ScanExistingFiles()
    {
        foreach (var basePath in GetRobloxCachePaths())
        {
            if (!Directory.Exists(basePath)) continue;

            StatusChanged?.Invoke($"Scanning: {basePath}");

            try
            {
                foreach (var file in Directory.EnumerateFiles(basePath, "*.*", SearchOption.AllDirectories))
                {
                    if (_cts?.IsCancellationRequested == true) return;
                    ProcessFile(file);
                }
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke($"Scan error in {basePath}: {ex.Message}");
            }
        }

        StatusChanged?.Invoke($"Initial scan complete — {_scripts.Count} scripts found");
    }

    private void ProcessFile(string filePath)
    {
        try
        {
            var ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (!ScriptExtensions.Contains(ext)) return;

            lock (_lock)
            {
                if (_seenFiles.Contains(filePath)) return;
                _seenFiles.Add(filePath);
            }

            string content;

            if (TextScriptExtensions.Contains(ext))
            {
                // Plain text Lua/Luau files
                content = File.ReadAllText(filePath, Encoding.UTF8);
            }
            else
            {
                // Binary RBXM/RBXL files — extract any readable text
                content = ExtractTextFromBinary(filePath);
            }

            if (string.IsNullOrWhiteSpace(content)) return;

            var entry = new ScriptEntry
            {
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                Content = content,
                DiscoveredAt = DateTime.Now,
                FileSize = new FileInfo(filePath).Length,
            };

            AnalyzeScript(entry);

            lock (_lock)
            {
                _scripts.Add(entry);
            }

            ScriptFound?.Invoke(entry);
        }
        catch
        {
            // File might be locked by Roblox — skip silently
        }
    }

    private static string ExtractTextFromBinary(string filePath)
    {
        try
        {
            var bytes = File.ReadAllBytes(filePath);
            var sb = new StringBuilder();
            var current = new StringBuilder();

            foreach (var b in bytes)
            {
                if (b >= 0x20 && b <= 0x7E) // printable ASCII
                {
                    current.Append((char)b);
                }
                else
                {
                    if (current.Length > 20) // only keep strings longer than 20 chars (likely script content)
                    {
                        sb.AppendLine(current.ToString());
                    }
                    current.Clear();
                }
            }

            if (current.Length > 20)
                sb.AppendLine(current.ToString());

            return sb.ToString();
        }
        catch
        {
            return "";
        }
    }

    private static void AnalyzeScript(ScriptEntry entry)
    {
        foreach (var (pattern, warning) in SuspiciousPatterns)
        {
            try
            {
                if (Regex.IsMatch(entry.Content, pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1)))
                {
                    entry.IsSuspicious = true;
                    entry.Warnings.Add(warning);
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Skip patterns that take too long on large files
            }
        }
    }
}
