using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Guard.Service.AppLocker;

namespace Guard.Windows
{
    /// <summary>
    /// Native AppLocker and process access through one long-lived Windows PowerShell host (see <see cref="PowerShellHostScript"/>).
    /// Applying policy or stopping processes requires an elevated or SYSTEM caller.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed partial class PowerShellAppLockerGateway : IAppLockerNativeGateway, INativeProcessGateway, IDisposable
    {
        private readonly PowerShellSession _session = new();

        public async Task<NativeAppLockerState> ReadStateAsync(CancellationToken cancellationToken)
        {
            return NativeResponseParser.ParseState(await _session.InvokeAsync("read", new Dictionary<string, object?>(), cancellationToken).ConfigureAwait(false));
        }

        public async Task ApplyLocalPolicyAsync(string policyXml, CancellationToken cancellationToken)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(policyXml);
            _ = await _session.InvokeAsync("apply", new Dictionary<string, object?> { ["xmlBase64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(policyXml)) }, cancellationToken).ConfigureAwait(false);
        }

        public async Task<NativeFileIdentity> ReadFileIdentityAsync(string path, CancellationToken cancellationToken)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(path);
            return NativeResponseParser.ParseIdentity(await _session.InvokeAsync("identify", new Dictionary<string, object?> { ["path"] = Path.GetFullPath(path) }, cancellationToken).ConfigureAwait(false));
        }

        public async Task<IReadOnlyList<RunningProcess>> FindProcessesAsync(IReadOnlyCollection<string> binaryNames, IReadOnlyCollection<string> ownerSids, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(binaryNames);
            ArgumentNullException.ThrowIfNull(ownerSids);
            if (binaryNames.Count == 0 || ownerSids.Count == 0)
            {
                return [];
            }

            string json = await _session.InvokeAsync(
                "processes",
                new Dictionary<string, object?> { ["binaries"] = binaryNames.ToArray(), ["ownerSids"] = ownerSids.ToArray() },
                cancellationToken).ConfigureAwait(false);
            return NativeResponseParser.ParseProcesses(json);
        }

        public async Task<bool> TerminateAsync(int processId, DateTimeOffset startedAtUtc, CancellationToken cancellationToken)
        {
            string json = await _session.InvokeAsync(
                "terminate",
                new Dictionary<string, object?> { ["pid"] = processId, ["startUtc"] = startedAtUtc.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture) },
                cancellationToken).ConfigureAwait(false);
            return NativeResponseParser.ParseTerminated(json);
        }

        public Task NotifySessionAsync(int sessionId, string title, string message, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(title);
            ArgumentNullException.ThrowIfNull(message);
            // WTSSendMessage shows a message box in another session (the service runs in session 0); bWait=false returns at once.
            _ = WTSSendMessageW(IntPtr.Zero, sessionId, title, title.Length * 2, message, message.Length * 2, MessageBoxWarning, 60, out _, false);
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            _session.Dispose();
        }

        private const int MessageBoxWarning = 0x00000030;

        [LibraryImport("wtsapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool WTSSendMessageW(
            IntPtr server,
            int sessionId,
            string title,
            int titleLength,
            string message,
            int messageLength,
            int style,
            int timeoutSeconds,
            out int response,
            [MarshalAs(UnmanagedType.Bool)] bool wait);
    }
}
