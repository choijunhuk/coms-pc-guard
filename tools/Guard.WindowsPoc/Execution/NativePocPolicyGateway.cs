using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Execution
{
    internal sealed class NativePocPolicyGateway(IWindowsCommandRunner runner) : IPocPolicyGateway
    {
        public async Task<AppLockerPolicySnapshot> CaptureAsync(CancellationToken token)
        {
            WindowsCommandResult result = await runner.RunAsync(new(WindowsCommand.Capture), token).ConfigureAwait(false);
            return Convert(result);
        }

        public async Task WriteAsync(PocTransactionJournal journal, bool restore, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(journal);
            WindowsCommandRequest request = restore ? WindowsCommandRequest.Restore(journal) : WindowsCommandRequest.Apply(journal);
            _ = await runner.RunAsync(request, token).ConfigureAwait(false);
        }

        public async Task<bool> ProbeAsync(CancellationToken token)
        {
            WindowsCommandResult result = await runner.RunAsync(new(WindowsCommand.Capture), token).ConfigureAwait(false);
            _ = Convert(result);
            return true;
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
