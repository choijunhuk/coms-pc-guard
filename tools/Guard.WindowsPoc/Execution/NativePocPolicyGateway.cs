using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Execution
{
    internal sealed class NativePocPolicyGateway : IPocPolicyGateway
    {
        private readonly IWindowsCommandRunner _runner;
        private readonly PocProtectedMutationAuthority? _authority;

        internal NativePocPolicyGateway(IWindowsCommandRunner runner, PocProtectedMutationAuthority? authority = null)
        {
            _runner = runner;
            _authority = authority;
        }

        public async Task<AppLockerPolicySnapshot> CaptureAsync(CancellationToken token)
        {
            WindowsCommandResult result = await _runner.RunAsync(new(WindowsCommand.Capture), token).ConfigureAwait(false);
            return Convert(result);
        }

        public async Task WriteAsync(PocTransactionJournal journal, bool restore, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(journal);
            if (_authority is null) { throw new InvalidOperationException("Protected mutation authorization is required."); }
            await NativePocPolicyWriteOrchestrator.WriteAsync(_runner, _authority, Convert, journal, restore, token).ConfigureAwait(false);
        }

        public Task<bool> ProbeAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            throw new InvalidOperationException("Interactive fixture probe evidence is not available.");
        }

        private static AppLockerPolicySnapshot Convert(WindowsCommandResult result)
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
