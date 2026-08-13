using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
// NEWLY ADDED ETW LIBRARIES
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

class Program
{
    // ==========================================
    // EDR AGENT CONFIGURATION
    // ==========================================
    static string SERVER_IP = "192.168.1.16";
    static string SERVER_PORT = "5000";
    // ==========================================

    static HttpClient client = new HttpClient();
    static List<string> bannedProcesses = new List<string>();
    static int myPid = Process.GetCurrentProcess().Id;

    static void Main(string[] args)
    {
        Console.WriteLine("🛡️ EDR Agent: Network Monitor Mode Active...");
        Console.WriteLine($"[+] Connecting to Central Server at {SERVER_IP}:{SERVER_PORT}");

        // Start the rule-fetching loop in the background
        _ = Task.Run(() => UpdateRulesLoop());

        // NEW ARCHITECTURE: STARTING ETW ENGINE
        // ETW requires Administrator privileges to run
        if (!(TraceEventSession.IsElevated() ?? false))
        {
            Console.WriteLine("[!] ERROR: You must run PowerShell as Administrator for the ETW Engine!");
            Console.ReadLine();
            return;
        }

        string sessionName = "MyEDR_ETW_Session";

        // Clean up any lingering sessions from previous tests
        using (var oldSession = new TraceEventSession(sessionName)) { oldSession.Stop(); }

        // Open a new Kernel listening session
        using (var session = new TraceEventSession(sessionName))
        {
            // SPEED OPTIMIZATION:
            session.BufferSizeMB = 1;

            Console.WriteLine("⚡ ETW Engine Active: Listening directly to the Kernel at 0ms latency...");

            // Instruct the Kernel to listen only for "Process" events
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

            // Event triggered when the Kernel starts a new process
            session.Source.Kernel.ProcessStart += data =>
            {
                // ETW provides data without the ".exe" extension (e.g., "notepad"). Appending it to match our rules.
                string processName = data.ProcessName.ToLower();
                if (!processName.EndsWith(".exe")) processName += ".exe";

                ProcessStartedETW(processName, data.ProcessID, data.ParentID);
            };

            // Start ETW listening. (This blocks the thread, so Console.ReadLine() is not needed)
            session.Source.Process();
        }
    }

    static async Task UpdateRulesLoop()
    {
        while (true)
        {
            try
            {
                string response = await client.GetStringAsync($"http://{SERVER_IP}:{SERVER_PORT}/api/rules");
                var newRules = JsonSerializer.Deserialize<List<string>>(response);
                if (newRules != null) bannedProcesses = newRules;
            }
            catch { }
            Thread.Sleep(10000);
        }
    }

    // NEW FUNCTION: Central processor for ETW data
    static void ProcessStartedETW(string processName, int pid, int parentPid)
    {
        // 1. Ignore our own processes (Prevents infinite loops)
        if (parentPid == myPid) return;

        // 2. Threat Check (High Priority)
        if (bannedProcesses.Contains(processName))
        {
            Console.WriteLine($"[🚨] THREAT DETECTED: {processName} (PID: {pid})");
            try
            {
                Process targetProcess = Process.GetProcessById(pid);
                targetProcess.Kill();
                Console.WriteLine($"[🛑] RESPONSE SUCCESSFUL: {processName} blocked!");
                _ = SendTelemetryAsync(processName, pid, "KILLED", new List<string>());
            }
            catch { }
            return;
        }

        // 3. Background Noise Filter (CPU Optimization)
        string[] systemNoise = {
            "svchost.exe", "dllhost.exe", "taskhostw.exe", "runtimebroker.exe",
            "searchindexer.exe", "backgroundtaskhost.exe", "conhost.exe",
            "wmiadap.exe", "sihost.exe", "explorer.exe", "wmiprvse.exe", "fontdrvhost.exe"
        };

        // If not noise, start network scanning
        if (!Array.Exists(systemNoise, noise => noise == processName))
        {
            _ = Task.Run(() => CheckNetworkConnections(processName, pid));
        }
    }

    static async Task CheckNetworkConnections(string processName, int pid)
    {
        await Task.Delay(2000);

        List<string> activeConnections = new List<string>();

        try
        {
            Process netstat = new Process();
            netstat.StartInfo.FileName = "netstat.exe";
            netstat.StartInfo.Arguments = "-ano";
            netstat.StartInfo.UseShellExecute = false;
            netstat.StartInfo.RedirectStandardOutput = true;
            netstat.StartInfo.CreateNoWindow = true;
            netstat.Start();

            string output = await netstat.StandardOutput.ReadToEndAsync();
            netstat.WaitForExit();

            string[] lines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                if (line.Contains("ESTABLISHED") && line.EndsWith(pid.ToString()))
                {
                    string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 5)
                    {
                        string foreignAddress = parts[2];

                        if (!foreignAddress.StartsWith("127.0.0.1") && !foreignAddress.StartsWith("[::1]"))
                        {
                            activeConnections.Add(foreignAddress);
                        }
                    }
                }
            }
        }
        catch { }

        if (activeConnections.Count > 0)
        {
            Console.WriteLine($"[🌐] NETWORK ACTIVITY: {processName} is connecting out! Targets: {string.Join(", ", activeConnections)}");
            await SendTelemetryAsync(processName, pid, "NETWORK_MONITOR", activeConnections);
        }
    }

    static async Task SendTelemetryAsync(string processName, int pid, string action, List<string> networkConnections)
    {
        var payload = new
        {
            machine_name = Environment.MachineName,
            process_name = processName,
            pid = pid,
            action = action,
            network_connections = networkConnections
        };

        string jsonPayload = JsonSerializer.Serialize(payload);
        var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

        try
        {
            await client.PostAsync($"http://{SERVER_IP}:{SERVER_PORT}/api/telemetry", content);
        }
        catch { }
    }
}