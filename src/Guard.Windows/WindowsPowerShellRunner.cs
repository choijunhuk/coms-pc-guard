using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;

namespace Guard.Windows
{
    /// <summary>
    /// Runs a fixed script in Windows PowerShell 5.1 (the host of the AppLocker module) from its System32 path.
    /// Data never becomes script text: it travels through environment variables or base64 on stdin.
    /// Scripts must print ASCII-only JSON so the console code page cannot corrupt identity strings.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal sealed class WindowsPowerShellRunner
    {
        private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(2);

        internal static string PowerShellPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");

        internal static async Task<string> RunAsync(string script, IReadOnlyDictionary<string, string>? environment, string? standardInput, CancellationToken cancellationToken)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(script);
            ProcessStartInfo info = new(PowerShellPath)
            {
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (string argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-ExecutionPolicy", "Bypass", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) })
            {
                info.ArgumentList.Add(argument);
            }

            foreach ((string name, string value) in environment ?? new Dictionary<string, string>())
            {
                info.Environment[name] = value;
            }

            using Process process = Process.Start(info) ?? throw new InvalidOperationException("Windows PowerShell could not be started.");
            Task<string> output = process.StandardOutput.ReadToEndAsync(cancellationToken);
            Task<string> error = process.StandardError.ReadToEndAsync(cancellationToken);
            if (standardInput is not null)
            {
                await process.StandardInput.WriteAsync(standardInput.AsMemory(), cancellationToken).ConfigureAwait(false);
            }

            process.StandardInput.Close();
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(DefaultTimeout);
            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                process.Kill(entireProcessTree: true);
                throw cancellationToken.IsCancellationRequested
                    ? new OperationCanceledException(cancellationToken)
                    : new TimeoutException("Windows PowerShell did not finish within the time limit.");
            }

            string standardOutput = await output.ConfigureAwait(false);
            string standardError = await error.ConfigureAwait(false);
            return process.ExitCode == 0
                ? standardOutput
                : throw new InvalidOperationException($"Windows PowerShell exited with {process.ExitCode}: {standardError.Trim()}");
        }
    }
}
