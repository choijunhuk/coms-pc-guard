using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    internal interface IPocProtectedMutationAuthority
    {
        Task PrearmNativeRecheckAsync(PocTransactionJournal journal, CancellationToken token);
        Task<IPocMutationAuthorization> AuthorizeAsync(PocTransactionJournal journal, bool restore,
            AppLockerPolicySnapshot trustedCurrent, CancellationToken token);
        Task MarkNativeWriteInFlightAsync(PocTransactionJournal journal, CancellationToken token);
        Task MarkNativeWriteVerifiedAsync(PocTransactionJournal journal, CancellationToken token);
    }

    internal sealed class PocProtectedMutationAuthority : IPocProtectedMutationAuthority
    {
        private readonly OwnerTokenPolicyGateCapability _gateCapability;
        private readonly WindowsPocStateLease _stateLease;
        private readonly DurablePocJournalStore _journalStore;
        private readonly PolicyMutationDecision _decision;
        private readonly VmAttestationResult _attestation;
        private readonly bool _elevated;
        private readonly PocFixtureLease _fixtureLease;
        private readonly TimeProvider _clock;

        internal PocProtectedMutationAuthority(OwnerTokenPolicyGateCapability gateCapability, WindowsPocStateLease stateLease,
            DurablePocJournalStore journalStore, PolicyMutationDecision decision, VmAttestationResult attestation, bool elevated,
            PocFixtureLease fixtureLease, TimeProvider clock)
        {
            _gateCapability = gateCapability ?? throw new ArgumentNullException(nameof(gateCapability));
            _stateLease = stateLease ?? throw new ArgumentNullException(nameof(stateLease));
            _journalStore = journalStore ?? throw new ArgumentNullException(nameof(journalStore));
            _decision = decision ?? throw new ArgumentNullException(nameof(decision));
            _attestation = attestation ?? throw new ArgumentNullException(nameof(attestation));
            _fixtureLease = fixtureLease ?? throw new ArgumentNullException(nameof(fixtureLease));
            ArgumentNullException.ThrowIfNull(clock);
            if (!journalStore.Owns(stateLease)) { throw new InvalidOperationException("Protected journal store must use the retained state lease."); }
            _elevated = elevated;
            _clock = clock;
        }

        public async Task<IPocMutationAuthorization> AuthorizeAsync(PocTransactionJournal journal, bool restore,
            AppLockerPolicySnapshot trustedCurrent, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(journal);
            ArgumentNullException.ThrowIfNull(trustedCurrent);
            CrossProcessPolicyGate.RequireHeld(_gateCapability);
            _stateLease.Revalidate();
            PocTransactionJournal? durable = await _journalStore.ReadAsync(token).ConfigureAwait(false);
            bool hostRecovery = await _journalStore.HasHostRecoveryRequiredAsync(token).ConfigureAwait(false);
            PocRecoveryBarrier recoveryBarrier = await _journalStore.ReadRecoveryBarrierAsync(token).ConfigureAwait(false);
            bool writePendingProof = await _journalStore.HasPreparedWritePendingProofAsync(journal, token).ConfigureAwait(false);
            _stateLease.Revalidate();
            if (durable != journal || journal.Phase != PocJournalPhase.WritePending
                || trustedCurrent.RawLocalPolicySha256 is null || !trustedCurrent.IsReady(_clock.GetUtcNow())
                || hostRecovery || recoveryBarrier != PocRecoveryBarrier.Capture || !writePendingProof
                || !_attestation.Attested || !_attestation.AllowWrite || !_elevated
                || (!restore && trustedCurrent.NativeRevision != _decision.InventoryRevision))
            {
                throw new InvalidOperationException("Protected mutation authorization refused.");
            }

            if (restore)
            {
                _ = journal.Recognizes(trustedCurrent) && !trustedCurrent.SamePolicy(journal.InitialBaseline)
                    ? true : throw new InvalidOperationException("Protected mutation authorization refused.");
                _fixtureLease.Revalidate(_decision);
                await _journalStore.SetRecoveryBarrierAsync(PocRecoveryBarrier.ValidationComplete, token).ConfigureAwait(false);
                _stateLease.Revalidate();
                return new PocMutationAuthorization(journal, Restore: true, trustedCurrent.RawLocalPolicySha256,
                    PolicyMutationDecision.Hash(journal.InitialBaseline.LocalPolicyXml), journal.InitialBaseline.LocalPolicyXml, RevalidateScope);
            }

            _ = trustedCurrent.SamePolicy(journal.Before) && _decision.Allowed
                && _decision.Authorizes(journal.After.LocalPolicyXml, _decision.FixturePath, _decision.FixtureHash)
                ? true : throw new InvalidOperationException("Protected mutation authorization refused.");
            _fixtureLease.Revalidate(_decision);

            await _journalStore.SetRecoveryBarrierAsync(PocRecoveryBarrier.ValidationComplete, token).ConfigureAwait(false);
            _stateLease.Revalidate();
            return new PocMutationAuthorization(journal, Restore: false, trustedCurrent.RawLocalPolicySha256,
                PolicyMutationDecision.Hash(journal.After.LocalPolicyXml), journal.After.LocalPolicyXml, RevalidateScope);
        }

        public async Task PrearmNativeRecheckAsync(PocTransactionJournal journal, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(journal);
            CrossProcessPolicyGate.RequireHeld(_gateCapability);
            _stateLease.Revalidate();
            if (await _journalStore.ReadAsync(token).ConfigureAwait(false) != journal)
            { throw new InvalidOperationException("Protected mutation authorization refused."); }
            if (await _journalStore.ReadRecoveryBarrierAsync(token).ConfigureAwait(false) != PocRecoveryBarrier.ValidationComplete)
            { throw new InvalidOperationException("Protected mutation authorization refused."); }
            await _journalStore.SetRecoveryBarrierAsync(PocRecoveryBarrier.Capture, token).ConfigureAwait(false);
            _stateLease.Revalidate();
        }

        public Task MarkNativeWriteInFlightAsync(PocTransactionJournal journal, CancellationToken token)
        {
            return SetNativeWriteBarrierAsync(journal, PocRecoveryBarrier.NativeWriteInFlight, token);
        }

        public Task MarkNativeWriteVerifiedAsync(PocTransactionJournal journal, CancellationToken token)
        {
            return SetNativeWriteBarrierAsync(journal, PocRecoveryBarrier.ValidationComplete, token);
        }

        private async Task SetNativeWriteBarrierAsync(PocTransactionJournal journal, PocRecoveryBarrier barrier, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(journal);
            CrossProcessPolicyGate.RequireHeld(_gateCapability);
            _stateLease.Revalidate();
            if (await _journalStore.ReadAsync(token).ConfigureAwait(false) != journal)
            { throw new InvalidOperationException("Protected mutation authorization refused."); }
            await _journalStore.SetRecoveryBarrierAsync(barrier, token).ConfigureAwait(false);
            _stateLease.Revalidate();
        }

        private void RevalidateScope()
        {
            CrossProcessPolicyGate.RequireHeld(_gateCapability);
            _stateLease.Revalidate();
            _fixtureLease.Revalidate(_decision);
        }

        private sealed record PocMutationAuthorization(PocTransactionJournal Journal, bool Restore, string ExpectedCurrentSha256,
            string ExpectedPayloadSha256, string PayloadXml, Action RevalidateAction) : IPocMutationAuthorization
        {
            public void Revalidate()
            {
                RevalidateAction();
            }
        }
    }
}
