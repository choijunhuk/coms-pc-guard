using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Execution
{
    internal sealed class NativePocPolicyGateway : IPocPolicyGateway
    {
        private readonly IWindowsCommandRunner _runner;
        private readonly Func<PocTransactionJournal, bool, CancellationToken, Task<PocMutationAuthorization>>? _authorize;

        internal NativePocPolicyGateway(IWindowsCommandRunner runner,
            Func<PocTransactionJournal, bool, CancellationToken, Task<PocMutationAuthorization>>? authorize = null)
        {
            _runner = runner;
            _authorize = authorize;
        }

        public async Task<AppLockerPolicySnapshot> CaptureAsync(CancellationToken token)
        {
            WindowsCommandResult result = await _runner.RunAsync(new(WindowsCommand.Capture), token).ConfigureAwait(false);
            return Convert(result);
        }

        public async Task WriteAsync(PocTransactionJournal journal, bool restore, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(journal);
            if (_authorize is null) { throw new InvalidOperationException("Protected mutation authorization is required."); }
            PocMutationAuthorization authorization = await _authorize(journal, restore, token).ConfigureAwait(false);
            WindowsCommandRequest request = restore ? WindowsCommandRequest.Restore(authorization) : WindowsCommandRequest.Apply(authorization);
            _ = await _runner.RunAsync(request, token).ConfigureAwait(false);
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
                csp, wdac, snapshot.AppIdServiceRunning, snapshot.AppIdServiceAutomatic);
        }
    }
}
