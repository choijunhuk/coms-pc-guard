using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Execution
{
    internal sealed class NativePocPolicyGateway : IPocPolicyGateway
    {
        private readonly IWindowsCommandRunner _runner;
        private readonly PocProtectedMutationAuthority? _authority;
        private readonly PocNativeAuthorityFactory? _factory;
        private readonly IPocSessionProbe? _probe;

        internal NativePocPolicyGateway(IWindowsCommandRunner runner, PocProtectedMutationAuthority? authority = null,
            PocNativeAuthorityFactory? factory = null, IPocSessionProbe? probe = null)
        {
            _runner = runner;
            _authority = authority;
            _factory = factory;
            _probe = probe;
        }

        public async Task<AppLockerPolicySnapshot> CaptureAsync(CancellationToken token)
        {
            WindowsCommandResult result = await _runner.RunAsync(new(WindowsCommand.Capture), token).ConfigureAwait(false);
            return Convert(result);
        }

        public async Task WriteAsync(PocTransactionJournal journal, bool restore, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(journal);
            if (_factory is not null)
            {
                using PocNativeAuthorityLease lease = await _factory.CreateAsync(journal, restore, token).ConfigureAwait(false);
                await NativePocPolicyWriteOrchestrator.WriteAsync(_runner, lease.Authority, Convert, journal, restore, token).ConfigureAwait(false);
                return;
            }
            if (_authority is null) { throw new InvalidOperationException("Protected mutation authorization is required."); }
            await NativePocPolicyWriteOrchestrator.WriteAsync(_runner, _authority, Convert, journal, restore, token).ConfigureAwait(false);
        }

        public Task<bool> ProbeAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return _probe?.ProbeAsync(token) ?? throw new InvalidOperationException("Interactive fixture probe evidence is not available.");
        }

        internal static AppLockerPolicySnapshot Convert(WindowsCommandResult result)
        {
            AppLockerNativeSnapshot snapshot = result.Snapshot is { IsComplete: true } complete
                ? complete : throw new InvalidOperationException("Native inventory unavailable.");
            PolicyPresence csp = snapshot.Inventory.CspMdm;
            PolicyPresence wdac = snapshot.Inventory.Wdac;
            return new(snapshot.CapturedAtUtc, snapshot.LocalPolicyXml, snapshot.EffectivePolicyXml!,
                csp, wdac, snapshot.AppIdServiceRunning, snapshot.AppIdServiceAutomatic)
            { NativeRevision = snapshot.Revision, RawLocalPolicySha256 = snapshot.RawLocalPolicySha256 };
        }
    }
}
