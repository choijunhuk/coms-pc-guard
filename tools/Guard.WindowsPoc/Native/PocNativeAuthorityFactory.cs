using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Execution;
using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    internal sealed class PocNativeAuthorityFactory(OwnerTokenPolicyGateCapability capability, WindowsPocStateLease state,
        DurablePocJournalStore store, PocConfigurationLease configuration, PocFixtureLeaseEvidence fixtures,
        PowerShellCommandRunner runner)
    {
        internal async Task<PocNativeAuthorityLease> CreateAsync(PocTransactionJournal journal, bool restore, CancellationToken token)
        {
            CrossProcessPolicyGate.RequireHeld(capability);
            configuration.Revalidate();
            state.Revalidate();
            PocConfiguration config = configuration.Value;
            if (!state.IsBoundTo(capability) || !store.Owns(state) || await store.ReadAsync(token).ConfigureAwait(false) != journal
                || fixtures.ClosureManifestHash is null || fixtures.ClosureOwnerSid != config.OwnerSid
                || journal.RecoveryLease != PolicyMutationDecision.Hash(config.Nonce)
                || journal.OwnershipEvidence != PolicyMutationDecision.Hash(config.OwnerSid + fixtures.TargetSha256 + fixtures.ControlSha256 + fixtures.ClosureManifestHash)
                || await store.ReadRecoveryBarrierAsync(token).ConfigureAwait(false) != PocRecoveryBarrier.ValidationComplete)
            { throw new InvalidOperationException("Native authority scope refused."); }
            await store.SetRecoveryBarrierAsync(PocRecoveryBarrier.Capture, token).ConfigureAwait(false);
            AppLockerNativeSnapshot snapshot = (await runner.RunAsync(new(WindowsCommand.Capture), token).ConfigureAwait(false)).Snapshot
                ?? throw new InvalidOperationException("Fresh native inventory required.");
            AppLockerPolicySnapshot current = NativePocPolicyGateway.Convert(new(snapshot));
            if (!current.IsReady(TimeProvider.System.GetUtcNow()) || !journal.Recognizes(current) || !journal.InitialBaseline.IsEmpty)
            { throw new PocPolicyDriftException(); }
            VmAttestationResult attestation = PocNativeController.Attest(configuration, capability);
            IReadOnlyList<PocCompiledStage> stages = PocTransitionCompiler.Compile(config, fixtures.Publisher, snapshot,
                TimeProvider.System.GetUtcNow(), !current.IsEmpty);
            PocCompiledStage? stage = stages.FirstOrDefault(candidate => candidate.Xml == journal.After.LocalPolicyXml);
            PolicyMutationDecision decision;
            if (restore)
            {
                if (!journal.After.SamePolicy(journal.InitialBaseline)) { throw new PocPolicyDriftException(); }
                decision = new(false, journal.InitialBaseline.LocalPolicyXml, fixtures.TargetPath, fixtures.TargetSha256, snapshot.Revision);
            }
            else
            {
                if (stage is null) { throw new InvalidOperationException("Exact compiler transition required."); }
                PolicyMutationGuard guard = new(stage.Preview, config.OwnerSid, fixtures.TargetPath, fixtures.TargetSha256, TimeProvider.System);
                decision = current.IsEmpty
                    ? guard.EvaluateInitial(attestation, snapshot, true, journal,
                        await PocDurableBaselineProof.CreateAsync(capability, state, store, journal, snapshot, token).ConfigureAwait(false))
                    : guard.EvaluateTransition(attestation, snapshot, true, journal);
                if (!decision.Allowed) { throw new InvalidOperationException("Transition policy guard refused."); }
            }
            PocFixtureLease lease = PocFixtureLease.Open(fixtures with { InventoryRevision = snapshot.Revision });
            try
            {
                lease.Revalidate(decision);
                configuration.Revalidate();
                await store.SetRecoveryBarrierAsync(PocRecoveryBarrier.ValidationComplete, token).ConfigureAwait(false);
                return new(new(capability, state, store, decision, attestation, true, lease, TimeProvider.System,
                    () => { configuration.Revalidate(); if (!PocNativeController.Attest(configuration, capability).AllowWrite) { throw new InvalidOperationException("VM attestation changed."); } }), lease);
            }
            catch { lease.Dispose(); throw; }
        }
    }

    internal sealed class PocNativeAuthorityLease(PocProtectedMutationAuthority authority, PocFixtureLease fixtures) : IDisposable
    {
        internal PocProtectedMutationAuthority Authority { get; } = authority;
        public void Dispose() { fixtures.Dispose(); }
    }
}
