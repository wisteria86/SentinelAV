// Purpose: Write the dedicated harmless ETW fixture inside an owned Sandbox.
// Works with: Program.cs; lab/qualification/probe_writer.py.

using System.Text.RegularExpressions;

internal static class LabProbeWriter
{
    public static int Run()
    {
        const string root = @"C:\SentinelAV-Test";
        if (!string.Equals(Environment.UserName, "WDAGUtilityAccount", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(Path.Combine(root, "preflight.json")))
            throw new InvalidOperationException("Probe writer requires the Sandbox account and bootstrap");

        string path = Path.GetFullPath(Environment.GetEnvironmentVariable("SENTINELAV_PROBE_FILE") ?? "");
        if (!Regex.IsMatch(path, @"^C:\\SentinelAV-Test\\Qualification\\[a-f0-9]{32}\\SentinelAVLabProbe-[a-f0-9]{32}\.txt$",
                           RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            throw new ArgumentException("Invalid harmless fixture path");
        for (DirectoryInfo? directory = new FileInfo(path).Directory; directory is not null; directory = directory.Parent)
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Linked harmless fixture path");

        using (FileStream ready = new(Path.ChangeExtension(path, ".ready"), FileMode.CreateNew))
            ready.Write("ready"u8);
        if (!WaitFor(Path.ChangeExtension(path, ".start"), TimeSpan.FromSeconds(25))) return 1;
        using (FileStream output = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        {
            output.Write("harmless collector probe"u8);
            output.Flush(true);
        }
        return WaitFor(Path.ChangeExtension(path, ".stop"), TimeSpan.FromSeconds(100)) ? 0 : 1;
    }

    private static bool WaitFor(string marker, TimeSpan budget)
    {
        long began = System.Diagnostics.Stopwatch.GetTimestamp();
        while (System.Diagnostics.Stopwatch.GetElapsedTime(began) < budget)
        {
            if (File.Exists(marker)) return true;
            Thread.Sleep(50);
        }
        return false;
    }
}
