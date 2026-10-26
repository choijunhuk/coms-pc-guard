using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace Guard.Windows
{
    /// <summary>
    /// One long-lived Windows PowerShell 5.1 process running <see cref="PowerShellHostScript"/>. Requests are serialized;
    /// a dead or timed-out process is killed and restarted on the next request.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal sealed class PowerShellSession : IDisposable
    {
        private static readonly TimeSpan StartTimeout = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan RequestTimeout = TimeSpan.FromMinutes(2);

        private readonly SemaphoreSlim _lock = new(1, 1);
        private readonly ConcurrentQueue<string> _stderr = new();
        private Process? _process;
        private long _nextId;
        private bool _disposed;

        internal static string PowerShellPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");

        /// <summary>Sends one request and returns the raw JSON of its "result".</summary>
        internal async Task<string> InvokeAsync(string operation, IReadOnlyDictionary<string, object?> arguments, CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                Process process = await EnsureStartedAsync(cancellationToken).ConfigureAwait(false);
                long id = ++_nextId;
                string request = JsonSerializer.Serialize(new Dictionary<string, object?> { ["id"] = id, ["op"] = operation, ["args"] = arguments });
                using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(RequestTimeout);
                try
                {
                    await process.StandardInput.WriteLineAsync(request.AsMemory(), timeout.Token).ConfigureAwait(false);
                    await process.StandardInput.FlushAsync(timeout.Token).ConfigureAwait(false);
                    while (true)
                    {
                        string line = await process.StandardOutput.ReadLineAsync(timeout.Token).ConfigureAwait(false)
                            ?? throw Died("Windows PowerShell host exited");
                        if (!line.StartsWith('{'))
                        {
                            continue;
                        }

                        using JsonDocument response = JsonDocument.Parse(line);
                        JsonElement root = response.RootElement;
                        if (!root.TryGetProperty("id", out JsonElement responseId) || responseId.ValueKind != JsonValueKind.Number || responseId.GetInt64() != id)
                        {
                            continue;
                        }

                        return root.TryGetProperty("ok", out JsonElement ok) && ok.ValueKind == JsonValueKind.True
                            ? root.TryGetProperty("result", out JsonElement result) ? result.GetRawText() : "null"
                            : throw new InvalidOperationException($"Windows PowerShell '{operation}' failed: {(root.TryGetProperty("error", out JsonElement error) ? error.GetString() : "unknown error")}");
                    }
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    Stop();
                    throw new TimeoutException($"Windows PowerShell '{operation}' did not answer within {RequestTimeout.TotalSeconds:N0} s.");
                }
                catch (IOException)
                {
                    Stop();
                    throw;
                }
            }
            finally
            {
                _ = _lock.Release();
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            Stop();
            _lock.Dispose();
        }

        private async Task<Process> EnsureStartedAsync(CancellationToken cancellationToken)
        {
            if (_process is { HasExited: false } running)
            {
                return running;
            }

            Stop();
            ProcessStartInfo info = new(PowerShellPath)
            {
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.ASCII,
            };
            foreach (string argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-ExecutionPolicy", "Bypass", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(PowerShellHostScript.Text)) })
            {
                info.ArgumentList.Add(argument);
            }

            Process process = Process.Start(info) ?? throw new InvalidOperationException("Windows PowerShell could not be started.");
            _process = process;
            _ = Task.Run(() => DrainErrors(process), CancellationToken.None);
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(StartTimeout);
            try
            {
                while (true)
                {
                    string line = await process.StandardOutput.ReadLineAsync(timeout.Token).ConfigureAwait(false)
                        ?? throw Died("Windows PowerShell host exited while starting");
                    if (line == PowerShellHostScript.ReadyLine)
                    {
                        return process;
                    }
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                Stop();
                throw new TimeoutException("Windows PowerShell host did not start in time.");
            }
        }

        private void DrainErrors(Process process)
        {
            try
            {
                while (process.StandardError.ReadLine() is { } line)
                {
                    _stderr.Enqueue(line);
                    while (_stderr.Count > 20 && _stderr.TryDequeue(out _))
                    {
                    }
                }
            }
            catch (IOException)
            {
            }
            catch (InvalidOperationException)
            {
            }
        }

        private IOException Died(string message)
        {
            string detail = string.Join(" | ", _stderr);
            Stop();
            return new IOException(detail.Length == 0 ? message : $"{message}: {detail}");
        }

        private void Stop()
        {
            Process? process = _process;
            _process = null;
            if (process is null)
            {
                return;
            }

            try
            {
                if (!process.HasExited)
                {
                    process.StandardInput.Close();
                    if (!process.WaitForExit(2000))
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
            }
            catch (InvalidOperationException)
            {
            }
            catch (IOException)
            {
            }
            finally
            {
                process.Dispose();
            }
        }
    }
}
