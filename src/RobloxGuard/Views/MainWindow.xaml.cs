using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using RobloxGuard.Models;
using RobloxGuard.Services;

namespace RobloxGuard.Views;

public partial class MainWindow : Window
{
    private readonly NetworkMonitor _networkMonitor = new();
    private readonly ScriptInspector _scriptInspector = new();
    private readonly ObservableCollection<ConnectionEntry> _connections = new();
    private readonly ObservableCollection<ScriptEntry> _scripts = new();

    public MainWindow()
    {
        InitializeComponent();

        ConnectionsGrid.ItemsSource = _connections;
        ScriptsGrid.ItemsSource = _scripts;

        _networkMonitor.ConnectionFound += OnConnectionFound;
        _networkMonitor.StatusChanged += OnStatusChanged;
        _scriptInspector.ScriptFound += OnScriptFound;
        _scriptInspector.StatusChanged += OnStatusChanged;
    }

    private void StartButton_Click(object sender, RoutedEventArgs e)
    {
        _networkMonitor.Start();
        _scriptInspector.Start();

        StartButton.IsEnabled = false;
        StopButton.IsEnabled = true;
    }

    private void StopButton_Click(object sender, RoutedEventArgs e)
    {
        _networkMonitor.Stop();
        _scriptInspector.Stop();

        StartButton.IsEnabled = true;
        StopButton.IsEnabled = false;
    }

    private void OnConnectionFound(ConnectionEntry entry)
    {
        Dispatcher.Invoke(() =>
        {
            _connections.Add(entry);
            UpdateConnectionStats();
        });
    }

    private void OnScriptFound(ScriptEntry entry)
    {
        Dispatcher.Invoke(() =>
        {
            _scripts.Add(entry);
            UpdateScriptStats();
        });
    }

    private void OnStatusChanged(string status)
    {
        Dispatcher.Invoke(() =>
        {
            StatusText.Text = status;
        });
    }

    private void UpdateConnectionStats()
    {
        int total = _connections.Count;
        int suspicious = 0;
        foreach (var c in _connections)
            if (c.IsSuspicious) suspicious++;

        TotalConnectionsRun.Text = total.ToString();
        SuspiciousConnectionsRun.Text = suspicious.ToString();
        SafeConnectionsRun.Text = (total - suspicious).ToString();

        RobloxStatusText.Text = $"({total} connections tracked)";
    }

    private void UpdateScriptStats()
    {
        int total = _scripts.Count;
        int flagged = 0;
        foreach (var s in _scripts)
            if (s.IsSuspicious) flagged++;

        TotalScriptsRun.Text = total.ToString();
        FlaggedScriptsRun.Text = flagged.ToString();
    }

    private void ScriptsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ScriptsGrid.SelectedItem is ScriptEntry script)
        {
            CodeViewer.Text = script.Content;

            if (script.IsSuspicious && script.Warnings.Count > 0)
            {
                WarningsPanel.Visibility = Visibility.Visible;
                WarningsList.ItemsSource = script.Warnings;
            }
            else
            {
                WarningsPanel.Visibility = Visibility.Collapsed;
                WarningsList.ItemsSource = null;
            }
        }
    }

    protected override void OnClosed(System.EventArgs e)
    {
        _networkMonitor.Stop();
        _scriptInspector.Stop();
        base.OnClosed(e);
    }
}
