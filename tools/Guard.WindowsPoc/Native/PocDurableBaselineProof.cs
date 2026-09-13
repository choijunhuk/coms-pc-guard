using Guard.WindowsPoc.Execution;
using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    internal sealed class PocDurableBaselineProof
    {
        private readonly OwnerTokenPolicyGateCapability _capability;
        private readonly WindowsPocStateLease _state;
        private readonly DurablePocJournalStore _store;
        private readonly PocTransactionJournal _journal;
        private readonly string _revision;
        internal string OwnerSid => _capability.OwnerSid;

        private PocDurableBaselineProof(OwnerTokenPolicyGateCapability capability, WindowsPocStateLease state,
            DurablePocJournalStore store, PocTransactionJournal journal, string revision)
        { _capability = capability; _state = state; _store = store; _journal = journal; _revision = revision; }

        internal static async Task<PocDurableBaselineProof> CreateAsync(OwnerTokenPolicyGateCapability capability,
            WindowsPocStateLease state, DurablePocJournalStore store, PocTransactionJournal journal, AppLockerNativeSnapshot snapshot, CancellationToken token)
        {
            CrossProcessPolicyGate.RequireHeld(capability);
            state.Revalidate();
            return !state.IsBoundTo(capability) || !store.Owns(state) || await store.ReadAsync(token).ConfigureAwait(false) != journal
                || !await store.HasPreparedWritePendingProofAsync(journal, token).ConfigureAwait(false)
                || await store.ReadRecoveryBarrierAsync(token).ConfigureAwait(false) != PocRecoveryBarrier.Capture
                || await store.HasHostRecoveryRequiredAsync(token).ConfigureAwait(false) || !MatchesBaseline(snapshot, journal)
                ? throw new InvalidOperationException("Retained durable initial baseline proof required.")
                : new(capability, state, store, journal, snapshot.Revision);
        }

        internal bool Authorizes(AppLockerNativeSnapshot snapshot, PocTransactionJournal journal)
        {
            CrossProcessPolicyGate.RequireHeld(_capability);
            _state.Revalidate();
            return _journal == journal && _revision == snapshot.Revision && MatchesBaseline(snapshot, journal)
                && _store.ReadAsync(CancellationToken.None).GetAwaiter().GetResult() == journal;
        }

        private static bool MatchesBaseline(AppLockerNativeSnapshot snapshot, PocTransactionJournal journal)
        {
            return snapshot.IsComplete && snapshot.Inventory.IsEmpty && journal.Phase == PocJournalPhase.WritePending
                && journal.InitialBaseline.IsEmpty && journal.Before.SamePolicy(journal.InitialBaseline)
                && NativePocPolicyGateway.Convert(new(snapshot)).SamePolicy(journal.InitialBaseline);
        }
    }
}
