using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    public sealed class AppLockerNativeGateway : IAppLockerNativeGateway
    {
        private readonly IWindowsCommandRunner _runner;
        private readonly PolicyMutationGuard _guard;
        private readonly VmAttestationResult _attestation;
        private readonly bool _elevated;
        private readonly Action _ensureWindows;
        private readonly TimeSpan _timeout;

        public AppLockerNativeGateway(IWindowsCommandRunner runner, PolicyMutationGuard guard, VmAttestationResult attestation, bool elevated)
            : this(runner, guard, attestation, elevated, EnsureWindows, TimeSpan.FromSeconds(30)) { }

        // Friend-test seam changes only platform detection and wait duration. The real runner independently
        // refuses native execution, and this gateway never dispatches a mutation command.
        internal AppLockerNativeGateway(IWindowsCommandRunner runner, PolicyMutationGuard guard, VmAttestationResult attestation, bool elevated, Action ensureWindows, TimeSpan timeout)
        {
            ArgumentNullException.ThrowIfNull(runner);
            ArgumentNullException.ThrowIfNull(guard);
            ArgumentNullException.ThrowIfNull(attestation);
            ArgumentNullException.ThrowIfNull(ensureWindows);
            if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30))
            {
                throw new ArgumentOutOfRangeException(nameof(timeout));
            }

            _runner = runner;
            _guard = guard;
            _attestation = attestation;
            _elevated = elevated;
            _ensureWindows = ensureWindows;
            _timeout = timeout;
        }

        public async Task<AppLockerNativeSnapshot> CaptureAsync(CancellationToken cancellationToken = default)
        {
            return RequireComplete(await RunAsync(new(WindowsCommand.Capture), cancellationToken).ConfigureAwait(false));
        }

        public async Task<AppLockerNativeSnapshot> ObserveAsync(CancellationToken cancellationToken = default)
        {
            return RequireComplete(await RunAsync(new(WindowsCommand.Observe), cancellationToken).ConfigureAwait(false));
        }

        public async Task ApplyAsync(string xml, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(xml);
            AppLockerNativeSnapshot snapshot = await CaptureAsync(cancellationToken).ConfigureAwait(false);
            PolicyMutationDecision decision = _guard.Evaluate(_attestation, snapshot, _elevated);
            if (!decision.Allowed || !decision.Authorizes(xml, decision.FixturePath, decision.FixtureHash))
            {
                throw new InvalidOperationException("Policy mutation refused.");
            }
            // Refuse before touching fixtures or dispatching writes. Journal integration must restore the
            // locked runtime fixture rehash immediately before any future native policy mutation.
            throw new InvalidOperationException("Durable journal authorization is not yet installed; no native write permitted.");
        }

        public async Task RestoreAsync(AppLockerNativeSnapshot snapshot, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(snapshot);
            _ = await CaptureAsync(cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("Restoration requires journaled ownership and fresh drift validation.");
        }

        public async Task CleanupAsync(AppLockerNativeSnapshot snapshot)
        {
            using CancellationTokenSource cleanup = new(_timeout);
            await RestoreAsync(snapshot, cleanup.Token).ConfigureAwait(false);
        }

        private async Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken)
        {
            _ensureWindows();
            cancellationToken.ThrowIfCancellationRequested();
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_timeout);
            return await _runner.RunAsync(request, timeout.Token).WaitAsync(timeout.Token).ConfigureAwait(false);
        }

        private static AppLockerNativeSnapshot RequireComplete(WindowsCommandResult result)
        {
            return result.Snapshot is { IsComplete: true } snapshot
            ? snapshot : throw new InvalidOperationException("Native inventory unavailable.");
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
