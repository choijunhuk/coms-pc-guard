using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Execution
{
    internal static class NativePocPolicyWriteOrchestrator
    {
        internal static async Task WriteAsync(IWindowsCommandRunner runner, IPocProtectedMutationAuthority authority,
            Func<WindowsCommandResult, AppLockerPolicySnapshot> convert, PocTransactionJournal journal, bool restore, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(runner);
            ArgumentNullException.ThrowIfNull(authority);
            ArgumentNullException.ThrowIfNull(convert);
            ArgumentNullException.ThrowIfNull(journal);
            await authority.PrearmNativeRecheckAsync(journal, token).ConfigureAwait(false);
            WindowsCommandResult result = await runner.RunAsync(new(WindowsCommand.Capture), token).ConfigureAwait(false);
            AppLockerPolicySnapshot fresh = convert(result);
            IPocMutationAuthorization authorization = await authority.AuthorizeAsync(journal, restore, fresh, token).ConfigureAwait(false);
            WindowsCommandRequest request = restore ? WindowsCommandRequest.Restore(authorization) : WindowsCommandRequest.Apply(authorization);
            await authority.MarkNativeWriteInFlightAsync(journal, token).ConfigureAwait(false);
            _ = await runner.RunAsync(request, token).ConfigureAwait(false);
            await authority.MarkNativeWriteVerifiedAsync(journal, token).ConfigureAwait(false);
        }
    }
}
