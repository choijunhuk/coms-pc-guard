using System.Security.Principal;
using System.Text.Json;

namespace Guard.WindowsPoc.Fixtures
{
    internal static class HarmlessFixture
    {
        public static int Run(string[] args)
        {
            ArgumentNullException.ThrowIfNull(args);
            if (!OperatingSystem.IsWindows()) { Console.WriteLine("NOT_RUN_WINDOWS_ONLY"); return 2; }
            if (args.Length != 1 || !Guid.TryParseExact(args[0], "D", out Guid runId)) { return 2; }
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            using WindowsIdentity? impersonation = WindowsIdentity.GetCurrent(ifImpersonating: true);
            using System.Diagnostics.Process process = System.Diagnostics.Process.GetCurrentProcess();
            if (impersonation is not null || process.SessionId <= 0 || !Environment.UserInteractive) { return 3; }
            string? sid = identity.User?.Value;
            if (sid is null) { return 3; }
            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ComsPcGuardPoc", "Runs");
            _ = Directory.CreateDirectory(directory);
            string? executablePath = Environment.ProcessPath;
            string? name = Path.GetFileNameWithoutExtension(executablePath);
            if (name is not "target" and not "control") { return 3; }
            string marker = JsonSerializer.Serialize(new
            {
                runId,
                startedAtUtc = DateTimeOffset.UtcNow,
                tokenSid = sid,
                executablePath,
                sessionId = process.SessionId,
                processId = process.Id,
                interactive = Environment.UserInteractive
            });
            using FileStream file = new(Path.Combine(directory, runId.ToString("D") + "." + name + ".json"), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            using StreamWriter writer = new(file);
            writer.WriteLine(marker);
            writer.Flush();
            file.Flush(flushToDisk: true);
            Console.WriteLine(marker);
            return 0;
        }
    }
}
