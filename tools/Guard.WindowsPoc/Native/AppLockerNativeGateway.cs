using System.Security.Cryptography;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    public sealed class AppLockerNativeGateway(IWindowsCommandRunner runner, PolicyMutationGuard guard, VmAttestationResult attestation, bool elevated) : IAppLockerNativeGateway
    {
        public async Task<AppLockerNativeSnapshot> CaptureAsync(CancellationToken cancellationToken = default)
        {
            return (await RunAsync(new(WindowsCommand.Capture), cancellationToken).ConfigureAwait(false)).Snapshot
                        ?? throw new InvalidOperationException("Inventory unavailable.");
        }

        public async Task<AppLockerNativeSnapshot> ObserveAsync(CancellationToken cancellationToken = default)
        {
            return (await RunAsync(new(WindowsCommand.Observe), cancellationToken).ConfigureAwait(false)).Snapshot
                        ?? throw new InvalidOperationException("Observation unavailable.");
        }

        public async Task ApplyAsync(string xml, CancellationToken cancellationToken = default)
        {
            AppLockerNativeSnapshot snapshot = await CaptureAsync(cancellationToken).ConfigureAwait(false);
            PolicyMutationDecision decision = guard.Evaluate(attestation, snapshot, elevated);
            if (!decision.Allowed)
            {
                throw new InvalidOperationException("Policy mutation refused.");
            }

            using FileStream fixture = new(guard.FixturePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            string hash = Convert.ToHexString(await SHA256.HashDataAsync(fixture, cancellationToken).ConfigureAwait(false));
            if (!decision.Authorizes(xml, guard.FixturePath, hash))
            {
                throw new InvalidOperationException("Compiler or fixture binding mismatch.");
            }
            // The next task must provide durable write-ahead recovery before enabling this boundary.
            throw new InvalidOperationException("Durable journal authorization is not yet installed; no native write permitted.");
        }

        public Task RestoreAsync(AppLockerNativeSnapshot snapshot, CancellationToken cancellationToken = default)
        {
            EnsureWindows();
            ArgumentNullException.ThrowIfNull(snapshot);
            cancellationToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException("Restoration requires journaled ownership and fresh drift validation.");
        }

        public async Task CleanupAsync(AppLockerNativeSnapshot snapshot)
        {
            using CancellationTokenSource cleanup = new(TimeSpan.FromSeconds(30));
            await RestoreAsync(snapshot, cleanup.Token).ConfigureAwait(false);
        }

        private async Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken)
        {
            EnsureWindows();
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            return await runner.RunAsync(request, timeout.Token).WaitAsync(timeout.Token).ConfigureAwait(false);
        }

        private static void EnsureWindows()
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("Windows VM only.");
            }
        }
    }
}
