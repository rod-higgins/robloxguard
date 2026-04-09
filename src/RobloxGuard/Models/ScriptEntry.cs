using System;
using System.Collections.Generic;

namespace RobloxGuard.Models;

public class ScriptEntry
{
    public string FilePath { get; set; } = "";
    public string FileName { get; set; } = "";
    public string Content { get; set; } = "";
    public DateTime DiscoveredAt { get; set; }
    public long FileSize { get; set; }
    public bool IsSuspicious { get; set; }
    public List<string> Warnings { get; set; } = new();

    public string DisplayName => FileName;
    public string DisplayFlag => IsSuspicious ? "⚠ FLAGGED" : "✓ OK";
    public string DisplaySize => FileSize < 1024 ? $"{FileSize} B" : $"{FileSize / 1024.0:F1} KB";
}
