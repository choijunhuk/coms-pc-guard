using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Execution
{
    internal enum PocRunResult { Success, ProbeFailed, Refused, HostCloneRecoveryRequired }
    internal interface IPocPolicyGateway
    {
        Task<AppLockerPolicySnapshot> CaptureAsync(CancellationToken token);
        Task WriteAsync(PocTransactionJournal journal, bool restore, CancellationToken token);
        Task<bool> ProbeAsync(CancellationToken token);
    }

    /// <summary>Portable orchestration. Native gateway wiring remains prohibited until independently trusted.</summary>
    internal sealed class WindowsPocRunner(IPocPolicyGateway gateway, IPocJournalStore store, IPolicyGate gate,
        TimeProvider clock, string ownershipEvidence, string recoveryLease, Func<PocRunResult, Task> evidence)
    {
        private bool _hostRecoveryRequired;
        public Task<PocRunResult> RunAsync(IReadOnlyList<AppLockerPolicySnapshot> transitions, CancellationToken token = default)
        {
            ArgumentNullException.ThrowIfNull(transitions);
            return gate.RunAsync(() => RunLockedAsync(transitions, token), token);
        }

        public Task<PocRunResult> RecoverAsync(CancellationToken token = default)
        {
            return gate.RunAsync(RecoverLockedAsync, token);
        }

        private async Task<PocRunResult> RunLockedAsync(IReadOnlyList<AppLockerPolicySnapshot> transitions, CancellationToken token)
        {
            PocRunResult result = PocRunResult.ProbeFailed;
            bool drift = false;
            try
            {
                if (_hostRecoveryRequired || await store.HasHostRecoveryRequiredAsync(token).ConfigureAwait(false)
                    || await store.HasRecoveryBarrierAsync(token).ConfigureAwait(false))
                { _hostRecoveryRequired = true; return PocRunResult.HostCloneRecoveryRequired; }
                if (await store.ReadAsync(token).ConfigureAwait(false) is not null)
                { throw new InvalidOperationException("Existing journal must be recovered before a new run."); }
                AppLockerPolicySnapshot baseline = await CaptureProtectedAsync(token).ConfigureAwait(false);
                if (!baseline.IsReady(clock.GetUtcNow()) || !baseline.IsEmpty)
                { drift = true; throw new InvalidOperationException("Initial inventory is not eligible."); }
                await store.SetRecoveryBarrierAsync(false, token).ConfigureAwait(false);
                AppLockerPolicySnapshot expected = baseline;
                foreach (AppLockerPolicySnapshot desired in transitions)
                {
                    token.ThrowIfCancellationRequested();
                    AppLockerPolicySnapshot fresh = await CaptureProtectedAsync(token).ConfigureAwait(false);
                    if (!fresh.IsReady(clock.GetUtcNow()) || !fresh.SamePolicy(expected)) { drift = true; break; }
                    AppLockerPolicySnapshot after = desired with { CapturedAtUtc = clock.GetUtcNow() };
                    await store.SetRecoveryBarrierAsync(PocRecoveryBarrier.ValidationComplete, token).ConfigureAwait(false);
                    PocTransactionJournal journal = PocTransactionJournal.Prepare(baseline, fresh, after, ownershipEvidence, recoveryLease, clock.GetUtcNow());
                    await store.SaveAsync(journal, token).ConfigureAwait(false);
                    journal = journal.WithPhase(PocJournalPhase.WritePending);
                    await store.SaveAsync(journal, token).ConfigureAwait(false);
                    await gateway.WriteAsync(journal, false, token).ConfigureAwait(false);
                    fresh = await CaptureProtectedAsync(token).ConfigureAwait(false);
                    if (!fresh.IsReady(clock.GetUtcNow()) || !fresh.SamePolicy(after)) { drift = true; break; }
                    await store.SetRecoveryBarrierAsync(PocRecoveryBarrier.ValidationComplete, token).ConfigureAwait(false);
                    await store.SaveAsync(journal.WithPhase(PocJournalPhase.Mutated), token).ConfigureAwait(false);
                    await store.SetRecoveryBarrierAsync(false, token).ConfigureAwait(false);
                    if (!await gateway.ProbeAsync(token).ConfigureAwait(false)) { throw new InvalidOperationException("Observation mismatch."); }
                    expected = after;
                }
                if (!drift)
                {
                    result = PocRunResult.Success;
                }
            }
            catch (PocPolicyDriftException) { drift = true; result = PocRunResult.HostCloneRecoveryRequired; }
            catch (Exception exception) when (Recoverable(exception)) { result = PocRunResult.ProbeFailed; }
            finally
            {
                // Once drift is observed it is sticky: even apparent later convergence cannot authorize a write.
                if (drift) { await MarkHostRecoveryAsync().ConfigureAwait(false); }
                if (drift || await RecoverLockedAsync().ConfigureAwait(false) == PocRunResult.HostCloneRecoveryRequired)
                { result = PocRunResult.HostCloneRecoveryRequired; }
            }
            try { await evidence(result).ConfigureAwait(false); }
            catch (Exception exception) when (Recoverable(exception))
            { if (result != PocRunResult.HostCloneRecoveryRequired) { result = PocRunResult.ProbeFailed; } }
            return result;
        }

        private async Task<PocRunResult> RecoverLockedAsync()
        {
            using CancellationTokenSource cleanup = new(TimeSpan.FromSeconds(30));
            try
            {
                if (_hostRecoveryRequired || await store.HasHostRecoveryRequiredAsync(cleanup.Token).ConfigureAwait(false))
                { _hostRecoveryRequired = true; return PocRunResult.HostCloneRecoveryRequired; }
                PocTransactionJournal? journal = await store.ReadAsync(cleanup.Token).ConfigureAwait(false);
                PocRecoveryBarrier recoveryBarrier = await store.ReadRecoveryBarrierAsync(cleanup.Token).ConfigureAwait(false);
                if (journal is null)
                {
                    if (recoveryBarrier != PocRecoveryBarrier.None) { _hostRecoveryRequired = true; return PocRunResult.HostCloneRecoveryRequired; }
                    return PocRunResult.Success;
                }
                if (recoveryBarrier is PocRecoveryBarrier.Drift or PocRecoveryBarrier.UnknownFailClosed or PocRecoveryBarrier.Capture or PocRecoveryBarrier.NativeWriteInFlight)
                { _hostRecoveryRequired = true; return PocRunResult.HostCloneRecoveryRequired; }
                if (recoveryBarrier == PocRecoveryBarrier.ValidationComplete && journal.Phase == PocJournalPhase.Prepared
                    && journal.Before.SamePolicy(journal.InitialBaseline))
                { _hostRecoveryRequired = true; return PocRunResult.HostCloneRecoveryRequired; }
                if (journal.Phase == PocJournalPhase.HostCloneRecoveryRequired) { return PocRunResult.HostCloneRecoveryRequired; }
                AppLockerPolicySnapshot fresh = await CaptureProtectedAsync(cleanup.Token).ConfigureAwait(false);
                if (!fresh.IsReady(clock.GetUtcNow()) || !journal.Recognizes(fresh))
                { await MarkHostRecoveryAsync().ConfigureAwait(false); return PocRunResult.HostCloneRecoveryRequired; }
                if (!fresh.SamePolicy(journal.InitialBaseline))
                {
                    // Re-read immediately before preparing the cleanup OS write. Gateway must repeat this
                    // comparison inside its trusted native boundary as protection against external actors.
                    fresh = await CaptureProtectedAsync(cleanup.Token).ConfigureAwait(false);
                    if (!fresh.IsReady(clock.GetUtcNow()) || !journal.Recognizes(fresh))
                    { await MarkHostRecoveryAsync().ConfigureAwait(false); return PocRunResult.HostCloneRecoveryRequired; }
                    if (!fresh.SamePolicy(journal.InitialBaseline))
                    {
                        PocTransactionJournal restore = PocTransactionJournal.Prepare(journal.InitialBaseline, fresh,
                            journal.InitialBaseline with { CapturedAtUtc = clock.GetUtcNow() }, journal.OwnershipEvidence, journal.RecoveryLease, clock.GetUtcNow());
                        await store.SetRecoveryBarrierAsync(PocRecoveryBarrier.ValidationComplete, cleanup.Token).ConfigureAwait(false);
                        await store.SaveAsync(restore, cleanup.Token).ConfigureAwait(false);
                        restore = restore.WithPhase(PocJournalPhase.WritePending);
                        await store.SaveAsync(restore, cleanup.Token).ConfigureAwait(false);
                        await gateway.WriteAsync(restore, true, cleanup.Token).ConfigureAwait(false);
                        fresh = await CaptureProtectedAsync(cleanup.Token).ConfigureAwait(false);
                        if (!fresh.IsReady(clock.GetUtcNow()) || !fresh.SamePolicy(journal.InitialBaseline))
                        { await MarkHostRecoveryAsync().ConfigureAwait(false); return PocRunResult.HostCloneRecoveryRequired; }
                        await store.SetRecoveryBarrierAsync(false, cleanup.Token).ConfigureAwait(false);
                        journal = restore;
                    }
                }
                await store.SetRecoveryBarrierAsync(false, cleanup.Token).ConfigureAwait(false);
                await store.SaveAsync(journal.WithPhase(PocJournalPhase.Recovered), cleanup.Token).ConfigureAwait(false);
                return PocRunResult.Success;
            }
            catch (PocPolicyDriftException) { await MarkHostRecoveryAsync().ConfigureAwait(false); return PocRunResult.HostCloneRecoveryRequired; }
            catch (Exception exception) when (Recoverable(exception)) { return PocRunResult.HostCloneRecoveryRequired; }
        }

        private async Task MarkHostRecoveryAsync()
        {
            _hostRecoveryRequired = true;
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(30));
            try
            {
                try { await store.SetHostRecoveryRequiredAsync(timeout.Token).ConfigureAwait(false); }
                catch (Exception exception) when (Recoverable(exception))
                { await store.SetRecoveryBarrierAsync(PocRecoveryBarrier.Drift, timeout.Token).ConfigureAwait(false); }
                PocTransactionJournal? journal = await store.ReadAsync(timeout.Token).ConfigureAwait(false);
                if (journal is not null)
                { await store.SaveAsync(journal.WithPhase(PocJournalPhase.HostCloneRecoveryRequired), timeout.Token).ConfigureAwait(false); }
            }
            catch (Exception exception) when (Recoverable(exception)) { /* The pre-capture durable barrier remains armed. */ }
        }

        private async Task<AppLockerPolicySnapshot> CaptureProtectedAsync(CancellationToken token)
        {
            // Persist before observing: a crash or failed drift-marker save cannot erase an observation.
            // An interrupted capture requires host recovery even if the last policy state is recognizable.
            await store.SetRecoveryBarrierAsync(PocRecoveryBarrier.Capture, token).ConfigureAwait(false);
            return await gateway.CaptureAsync(token).ConfigureAwait(false);
        }

        private static bool Recoverable(Exception exception)
        {
            return exception is IOException or InvalidOperationException
            or UnauthorizedAccessException or OperationCanceledException or System.Text.Json.JsonException;
        }
    }
}
