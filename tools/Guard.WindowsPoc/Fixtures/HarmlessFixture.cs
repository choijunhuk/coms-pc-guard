using System.Security.Principal;
using System.Text.Json;
using System.IO.Pipes;
using System.Text;

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
            using CancellationTokenSource deadline = new(TimeSpan.FromMinutes(2));
            using NamedPipeClientStream pipe = new(".", "ComsPcGuardPoc.Probe." + runId.ToString("D") + "." + name, PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                pipe.ConnectAsync(deadline.Token).GetAwaiter().GetResult();
                using StreamReader input = new(pipe, Encoding.UTF8, true, 1024, leaveOpen: true);
                using StreamWriter output = new(pipe, new UTF8Encoding(false), 1024, leaveOpen: true) { AutoFlush = true };
                char[] challenge = new char[65];
                if (input.ReadBlockAsync(challenge.AsMemory(), deadline.Token).AsTask().GetAwaiter().GetResult() != 65 || challenge[64] != '\n') { return 3; }
                string nonce = new(challenge, 0, 64);
                if (!nonce.All(char.IsAsciiHexDigit)) { return 3; }
                output.WriteAsync((nonce + "\n").AsMemory(), deadline.Token).GetAwaiter().GetResult();
                output.FlushAsync(deadline.Token).GetAwaiter().GetResult();
                _ = input.ReadAsync(new char[1].AsMemory(), deadline.Token).AsTask().GetAwaiter().GetResult();
                return 0;
            }
            catch (Exception error) when (error is IOException or OperationCanceledException) { return 3; }
        }
    }
}
