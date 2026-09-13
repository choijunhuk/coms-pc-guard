using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Execution
{
    internal sealed class NativePocPolicyGateway : IPocPolicyGateway
    {
        private readonly IWindowsCommandRunner _runner;
        private readonly IPocProtectedMutationAuthority? _authority;

        internal NativePocPolicyGateway(IWindowsCommandRunner runner, IPocProtectedMutationAuthority? authority = null)
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
            await _authority.PrearmNativeRecheckAsync(journal, token).ConfigureAwait(false);
            AppLockerPolicySnapshot fresh = await CaptureAsync(token).ConfigureAwait(false);
            IPocMutationAuthorization authorization = await _authority.AuthorizeAsync(journal, restore, fresh, token).ConfigureAwait(false);
            WindowsCommandRequest request = restore ? WindowsCommandRequest.Restore(authorization) : WindowsCommandRequest.Apply(authorization);
            await _authority.MarkNativeWriteInFlightAsync(journal, token).ConfigureAwait(false);
            _ = await _runner.RunAsync(request, token).ConfigureAwait(false);
            await _authority.MarkNativeWriteVerifiedAsync(journal, token).ConfigureAwait(false);
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
