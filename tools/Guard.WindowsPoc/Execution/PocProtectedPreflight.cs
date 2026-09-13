using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Execution
{
    internal static class PocProtectedPreflight
    {
        internal static async Task<AppLockerNativeSnapshot> CaptureAsync(IWindowsCommandRunner native, IPocJournalStore store,
            TimeProvider clock, CancellationToken token)
        {
            if (await store.ReadAsync(token).ConfigureAwait(false) is not null
                || await store.HasHostRecoveryRequiredAsync(token).ConfigureAwait(false)
                || await store.HasRecoveryBarrierAsync(token).ConfigureAwait(false))
            { throw new InvalidOperationException("Existing recovery evidence requires recovery."); }
            await store.SetRecoveryBarrierAsync(PocRecoveryBarrier.Capture, token).ConfigureAwait(false);
            AppLockerNativeSnapshot snapshot = (await native.RunAsync(new(WindowsCommand.Capture), token).ConfigureAwait(false)).Snapshot
                ?? throw new InvalidOperationException("Native preflight unavailable.");
            AppLockerPolicySnapshot current = NativePocPolicyGateway.Convert(new(snapshot));
            if (!current.IsReady(clock.GetUtcNow()) || !current.IsEmpty || !snapshot.Inventory.IsEmpty)
            { throw new InvalidOperationException("Native preflight policy is not empty and known."); }
            // Only a completed, fully validated empty observation may disarm this preflight barrier.
            await store.SetRecoveryBarrierAsync(false, token).ConfigureAwait(false);
            return snapshot;
        }
    }
}
