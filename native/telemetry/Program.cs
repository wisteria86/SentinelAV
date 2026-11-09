// Purpose: Collect kernel file-write events and read bounded metadata frames inside test guests.
// Works with: monitoring/kernel_telemetry.py; lab/qualification/backend_transport.py; scripts/Build-
//   KernelCollector.ps1
// Used by: the matching native executable or library entry point

// Read-only ETW collection. No injection, process modification or file writes.
// Kernel ETW authorization is required; do not weaken ACLs to grant access.
using System.Diagnostics;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

internal static class Program
{
    private static long dropped;
    private static long unresolvedPaths;
    private static long unresolvedIdentities;
    private static long outsideProbeScope;
    private static readonly Channel<object> Events = Channel.CreateBounded<object>(
        new BoundedChannelOptions(1024) { SingleReader = true, SingleWriter = false, FullMode = BoundedChannelFullMode.Wait });

    private static void Publish(object value)
    {
        if (!Events.Writer.TryWrite(value)) Interlocked.Increment(ref dropped);
    }

    private static object? Identity(int pid, DateTime observed)
    {
        try
        {
            using Process process = Process.GetProcessById(pid);
            DateTime started = process.StartTime.ToUniversalTime();
            if (started > observed.ToUniversalTime()) return null; // PID reuse
            return new { pid, creation = new DateTimeOffset(started).ToUnixTimeMilliseconds() / 1000.0 };
        }
        catch { return null; } // Never guess an inaccessible/exited identity.
    }

    private static int ReadLabFrame(string identity, string offsetText)
    {
        if (!string.Equals(Environment.UserName, "WDAGUtilityAccount", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(@"C:\SentinelAV-Test\preflight.json"))
            throw new InvalidOperationException("Lab metadata export requires the Sandbox account and bootstrap");
        string path;
        if (identity == "setup") path = @"C:\SentinelAV-Test\TelemetrySetup\result.json";
        else if (Guid.TryParseExact(identity, "N", out _))
            path = @"C:\SentinelAV-Test\Qualification\" + identity + @"\export.bin";
        else throw new ArgumentException("Invalid lab metadata identity");
        for (FileSystemInfo? entry = new FileInfo(path); entry is not null;
            entry = entry is FileInfo file ? file.Directory : ((DirectoryInfo)entry).Parent)
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Linked lab metadata path refused");
        byte[] bytes = File.ReadAllBytes(path);
        if (bytes.Length == 0 || bytes.Length > 32768 || !int.TryParse(offsetText, out int offset) || offset < -1 || offset >= bytes.Length)
            throw new ArgumentException("Invalid bounded metadata frame");
        if (offset == -1) return 0x40000000 + bytes.Length;
        int value = 0;
        for (int i = 0; i < 3 && offset + i < bytes.Length; i++) value |= bytes[offset + i] << (8 * i);
        return 0x40000000 + value;
    }

    private static async Task<int> Main(string[] arguments)
    {
        try
        {
            if (arguments.Length == 3 && arguments[0] == "--lab-export")
                return ReadLabFrame(arguments[1], arguments[2]);
            if (arguments.Length == 1 && arguments[0] == "--self-check")
            {
                Console.WriteLine(JsonSerializer.Serialize(new { kind = "self_check", dependency = typeof(TraceEventSession).Assembly.GetName().Name, etw_started = false }));
                return 0;
            }
            if (arguments is ["--lab-probe-writer"]) return LabProbeWriter.Run();
            if (arguments.Length == 0) return await RunCollector(null);
            if (arguments.Length == 2 && arguments[0] == "--probe-pid" &&
                int.TryParse(arguments[1], out int probePid) && probePid > 0)
                return await RunCollector(probePid);
            throw new ArgumentException("Unknown collector argument");
        }
        catch (Exception error)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { kind = "unavailable", reason = error.Message }));
            return 1;
        }
    }

    private static async Task<int> RunCollector(int? probePid)
    {
        Console.OutputEncoding = new System.Text.UTF8Encoding(false);
        string sessionName = "SentinelAV-FileIO-" + Guid.NewGuid().ToString("N");
        using var session = new TraceEventSession(sessionName);
        session.StopOnDispose = true;
        // Source access starts a session; the kernel provider must be first.
        session.EnableKernelProvider(KernelTraceEventParser.Keywords.FileIO |
            KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Thread);
        var source = session.Source;
        object Health(string kind) => new { kind, dropped = Interlocked.Read(ref dropped),
            unresolved_paths = Interlocked.Read(ref unresolvedPaths),
            unresolved_identities = Interlocked.Read(ref unresolvedIdentities),
            outside_probe_scope = Interlocked.Read(ref outsideProbeScope), etw_lost = source.EventsLost };
        using var heartbeat = new Timer(_ => Publish(Health("health")), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
        Console.CancelKeyPress += (_, args) => { args.Cancel = true; session.Stop(); };
        _ = Task.Run(() => { if (Console.ReadLine() == "stop") session.Stop(); });
        Task writer = Task.Run(async () =>
        {
            await foreach (object value in Events.Reader.ReadAllAsync())
                Console.WriteLine(JsonSerializer.Serialize(value));
        });
        try
        {
            // Associate writes with the kernel file object from an earlier open.
            // Close and cleanup invalidate the association before object reuse.
            var openFiles = new Dictionary<ulong, (int Pid, string Path)>();
            source.Kernel.FileIOCreate += data =>
            {
                if (probePid.HasValue && data.ProcessID != probePid.Value) return;
                ulong fileObject = data.FileObject;
                if (fileObject == 0) return;
                openFiles.Remove(fileObject);
                string path = data.FileName ?? "";
                if (path.Length == 0 || path.Length > 32768) return;
                if (openFiles.Count >= 4096) openFiles.Clear();
                openFiles[fileObject] = (data.ProcessID, path);
            };
            source.Kernel.FileIOCleanup += data => openFiles.Remove(data.FileObject);
            source.Kernel.FileIOClose += data => openFiles.Remove(data.FileObject);
            source.Kernel.FileIOWrite += data =>
            {
                if (probePid.HasValue && data.ProcessID != probePid.Value)
                { Interlocked.Increment(ref outsideProbeScope); return; }
                string path = data.FileName ?? "";
                if (path.Length == 0 && data.FileObject != 0 &&
                    openFiles.TryGetValue(data.FileObject, out var opened) && opened.Pid == data.ProcessID)
                    path = opened.Path;
                DateTime observed = data.TimeStamp.ToUniversalTime();
                if (path.Length == 0 || path.Length > 32768)
                { Interlocked.Increment(ref unresolvedPaths); return; }
                object? identity = Identity(data.ProcessID, observed);
                if (identity is null)
                { Interlocked.Increment(ref unresolvedIdentities); return; }
                Publish(new { kind = "file_write", identity, path, bytes = data.IoSize,
                    timestamp = new DateTimeOffset(observed).ToUnixTimeMilliseconds() / 1000.0 });
            };
            Publish(new { kind = "ready", source = "Windows kernel ETW", mutation = false, session = sessionName, probe_pid = probePid });
            source.Process();
            Publish(Health("stopped"));
            return 0;
        }
        catch (Exception error)
        {
            Publish(new { kind = "unavailable", reason = error.Message, dropped = Interlocked.Read(ref dropped) });
            return 1;
        }
        finally
        {
            await heartbeat.DisposeAsync();
            Events.Writer.TryComplete();
            await writer;
        }
    }
}
