using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    internal sealed class PocProtectedMutationAuthority
    {
        private readonly OwnerTokenPolicyGateCapability _gateCapability;
        private readonly WindowsPocStateLease _stateLease;
        private readonly DurablePocJournalStore _journalStore;
        private readonly PolicyMutationDecision _decision;
        private readonly VmAttestationResult _attestation;
        private readonly bool _elevated;
        private readonly string _fixturePath;
        private readonly string _fixtureHash;
        private readonly TimeProvider _clock;

        internal PocProtectedMutationAuthority(OwnerTokenPolicyGateCapability gateCapability, WindowsPocStateLease stateLease,
            DurablePocJournalStore journalStore, PolicyMutationDecision decision, VmAttestationResult attestation, bool elevated,
            string fixturePath, string fixtureHash, TimeProvider clock)
        {
            _gateCapability = gateCapability ?? throw new ArgumentNullException(nameof(gateCapability));
            _stateLease = stateLease ?? throw new ArgumentNullException(nameof(stateLease));
            _journalStore = journalStore ?? throw new ArgumentNullException(nameof(journalStore));
            _decision = decision ?? throw new ArgumentNullException(nameof(decision));
            _attestation = attestation ?? throw new ArgumentNullException(nameof(attestation));
            ArgumentNullException.ThrowIfNull(clock);
            ArgumentException.ThrowIfNullOrWhiteSpace(fixturePath);
            ArgumentException.ThrowIfNullOrWhiteSpace(fixtureHash);
            _elevated = elevated;
            _fixturePath = fixturePath;
            _fixtureHash = fixtureHash;
            _clock = clock;
        }

        internal async Task<IPocMutationAuthorization> AuthorizeAsync(PocTransactionJournal journal, bool restore,
            AppLockerPolicySnapshot trustedCurrent, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(journal);
            ArgumentNullException.ThrowIfNull(trustedCurrent);
            CrossProcessPolicyGate.RequireHeld(_gateCapability);
            _stateLease.Revalidate();
            PocTransactionJournal? durable = await _journalStore.ReadAsync(token).ConfigureAwait(false);
            _stateLease.Revalidate();
            if (durable != journal || journal.Phase != PocJournalPhase.WritePending
                || trustedCurrent.RawLocalPolicySha256 is null || !trustedCurrent.IsReady(_clock.GetUtcNow())
                || !_attestation.Attested || !_attestation.AllowWrite || !_elevated)
            {
                throw new InvalidOperationException("Protected mutation authorization refused.");
            }

            if (restore)
            {
                _ = journal.Recognizes(trustedCurrent) && !trustedCurrent.SamePolicy(journal.InitialBaseline)
                    ? true : throw new InvalidOperationException("Protected mutation authorization refused.");
                return new PocMutationAuthorization(journal, Restore: true, trustedCurrent.RawLocalPolicySha256,
                    PolicyMutationDecision.Hash(journal.InitialBaseline.LocalPolicyXml), journal.InitialBaseline.LocalPolicyXml);
            }

            _ = trustedCurrent.SamePolicy(journal.Before) && _decision.Allowed
                && _decision.Authorizes(journal.After.LocalPolicyXml, _fixturePath, _fixtureHash)
                ? true : throw new InvalidOperationException("Protected mutation authorization refused.");

            return new PocMutationAuthorization(journal, Restore: false, trustedCurrent.RawLocalPolicySha256,
                PolicyMutationDecision.Hash(journal.After.LocalPolicyXml), journal.After.LocalPolicyXml);
        }

        private sealed record PocMutationAuthorization(PocTransactionJournal Journal, bool Restore, string ExpectedCurrentSha256,
            string ExpectedPayloadSha256, string PayloadXml) : IPocMutationAuthorization;
    }
}
