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
                if (await store.ReadAsync(token).ConfigureAwait(false) is not null)
                { throw new InvalidOperationException("Existing journal must be recovered before a new run."); }
                AppLockerPolicySnapshot baseline = await gateway.CaptureAsync(token).ConfigureAwait(false);
                if (!baseline.IsReady(clock.GetUtcNow()) || !baseline.IsEmpty)
                { drift = true; throw new InvalidOperationException("Initial inventory is not eligible."); }
                AppLockerPolicySnapshot expected = baseline;
                foreach (AppLockerPolicySnapshot after in transitions)
                {
                    token.ThrowIfCancellationRequested();
                    AppLockerPolicySnapshot fresh = await gateway.CaptureAsync(token).ConfigureAwait(false);
                    if (!fresh.IsReady(clock.GetUtcNow()) || !fresh.SamePolicy(expected)) { drift = true; break; }
                    PocTransactionJournal journal = PocTransactionJournal.Prepare(baseline, fresh, after, ownershipEvidence, recoveryLease, clock.GetUtcNow());
                    await store.SaveAsync(journal, token).ConfigureAwait(false);
                    journal = journal.WithPhase(PocJournalPhase.WritePending);
                    await store.SaveAsync(journal, token).ConfigureAwait(false);
                    await gateway.WriteAsync(journal, false, token).ConfigureAwait(false);
                    fresh = await gateway.CaptureAsync(token).ConfigureAwait(false);
                    if (!fresh.IsReady(clock.GetUtcNow()) || !fresh.SamePolicy(after)) { drift = true; break; }
                    await store.SaveAsync(journal.WithPhase(PocJournalPhase.Mutated), token).ConfigureAwait(false);
                    if (!await gateway.ProbeAsync(token).ConfigureAwait(false)) { throw new InvalidOperationException("Observation mismatch."); }
                    expected = after;
                }
                if (!drift)
                {
                    result = PocRunResult.Success;
                }
            }
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
                PocTransactionJournal? journal = await store.ReadAsync(cleanup.Token).ConfigureAwait(false);
                if (journal is null) { return PocRunResult.Success; }
                if (journal.Phase == PocJournalPhase.HostCloneRecoveryRequired) { return PocRunResult.HostCloneRecoveryRequired; }
                AppLockerPolicySnapshot fresh = await gateway.CaptureAsync(cleanup.Token).ConfigureAwait(false);
                if (!fresh.IsReady(clock.GetUtcNow()) || !journal.Recognizes(fresh))
                { await MarkHostRecoveryAsync().ConfigureAwait(false); return PocRunResult.HostCloneRecoveryRequired; }
                if (!fresh.SamePolicy(journal.InitialBaseline))
                {
                    // Re-read immediately before preparing the cleanup OS write. Gateway must repeat this
                    // comparison inside its trusted native boundary as protection against external actors.
                    fresh = await gateway.CaptureAsync(cleanup.Token).ConfigureAwait(false);
                    if (!fresh.IsReady(clock.GetUtcNow()) || !journal.Recognizes(fresh))
                    { await MarkHostRecoveryAsync().ConfigureAwait(false); return PocRunResult.HostCloneRecoveryRequired; }
                    if (!fresh.SamePolicy(journal.InitialBaseline))
                    {
                        PocTransactionJournal restore = PocTransactionJournal.Prepare(journal.InitialBaseline, fresh,
                            journal.InitialBaseline with { CapturedAtUtc = clock.GetUtcNow() }, journal.OwnershipEvidence, journal.RecoveryLease, clock.GetUtcNow())
                            .WithPhase(PocJournalPhase.WritePending);
                        await store.SaveAsync(restore, cleanup.Token).ConfigureAwait(false);
                        await gateway.WriteAsync(restore, true, cleanup.Token).ConfigureAwait(false);
                        fresh = await gateway.CaptureAsync(cleanup.Token).ConfigureAwait(false);
                        if (!fresh.IsReady(clock.GetUtcNow()) || !fresh.SamePolicy(journal.InitialBaseline))
                        { await MarkHostRecoveryAsync().ConfigureAwait(false); return PocRunResult.HostCloneRecoveryRequired; }
                        journal = restore;
                    }
                }
                await store.SaveAsync(journal.WithPhase(PocJournalPhase.Recovered), cleanup.Token).ConfigureAwait(false);
                return PocRunResult.Success;
            }
            catch (Exception exception) when (Recoverable(exception)) { return PocRunResult.HostCloneRecoveryRequired; }
        }

        private async Task MarkHostRecoveryAsync()
        {
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(30));
            try
            {
                PocTransactionJournal? journal = await store.ReadAsync(timeout.Token).ConfigureAwait(false);
                if (journal is not null)
                { await store.SaveAsync(journal.WithPhase(PocJournalPhase.HostCloneRecoveryRequired), timeout.Token).ConfigureAwait(false); }
            }
            catch (Exception exception) when (Recoverable(exception)) { /* Failure cannot authorize another policy write. */ }
        }

        private static bool Recoverable(Exception exception)
        {
            return exception is IOException or InvalidOperationException
            or UnauthorizedAccessException or OperationCanceledException or System.Text.Json.JsonException;
        }
    }
}
