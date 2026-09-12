using System.Security.Cryptography;
using System.Text;
using Guard.Service.Enforcement;
using Guard.Service.Storage;
using Guard.Service.Tests.TestSupport;
using Microsoft.Data.Sqlite;

namespace Guard.Service.Tests.Storage
{
    [TestClass]
    public sealed class SqlitePolicyStateStoreTests
    {
        private static readonly DateTimeOffset Now = new(2026, 9, 12, 0, 0, 0, TimeSpan.Zero);
        private const string Json = /*lang=json,strict*/ "{\"policy\":1}";
        private static string Hash(string json)
        {
            return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
        }

        private static PolicyArtifact Artifact(long version = 1, EnforcementProtectionLevel protection = EnforcementProtectionLevel.PreExecutionBlock, OwnedPolicyState owned = OwnedPolicyState.Present)
        {
            return new(version, Json, Hash(Json), protection, owned, Now);
        }

        private static ReconciliationAttempt Attempt(PolicyArtifact artifact)
        {
            return new(Guid.NewGuid(), artifact.PolicyVersion, artifact.Sha256Hex, Now);
        }

        private static EffectivePolicyObservation Observation(PolicyArtifact artifact, DateTimeOffset? time = null, EnforcementProtectionLevel? protection = null, OwnedPolicyState? owned = null)
        {
            return new(Guid.NewGuid(), artifact.PolicyVersion, artifact.Sha256Hex, time ?? Now, protection ?? artifact.RequiredProtection, owned ?? artifact.ExpectedOwnedState, false, "{}");
        }

        private static SqlitePolicyStateStore Store(TemporarySqliteDatabase database)
        {
            return new(new SqliteConnectionFactory(new SqliteDatabaseOptions(database.DatabasePath)));
        }

        [TestMethod]
        public void ArtifactRejectsHashSubstitutionAndMalformedInputs()
        {
            foreach (string hash in new[] { new string('0', 64), Hash(Json).ToUpperInvariant(), "", "abc" })
            {
                _ = Assert.ThrowsExactly<ArgumentException>(() => new PolicyArtifact(1, Json, hash, EnforcementProtectionLevel.PreExecutionBlock, OwnedPolicyState.Present, Now));
            }

            foreach (string json in new[] { "", "[]", "null", "{bad" })
            {
                _ = Assert.ThrowsExactly<ArgumentException>(() => new PolicyArtifact(1, json, Hash(json), EnforcementProtectionLevel.PreExecutionBlock, OwnedPolicyState.Present, Now));
            }

            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Artifact(0));
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Artifact(protection: (EnforcementProtectionLevel)4));
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Artifact(owned: OwnedPolicyState.Unknown));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Artifact(protection: EnforcementProtectionLevel.None));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new PolicyArtifact(1, Json, Hash(Json), EnforcementProtectionLevel.PreExecutionBlock, OwnedPolicyState.Present, Now.ToOffset(TimeSpan.FromHours(9))));
        }

        [TestMethod]
        public void ConfirmationChecksEveryProtectionPairAndOwnedState()
        {
            bool[,] expected = { { true, false, false, false }, { false, true, true, true }, { false, false, true, true }, { false, false, false, true } };
            for (int required = 0; required < 4; required++)
            {
                PolicyArtifact artifact = Artifact(protection: (EnforcementProtectionLevel)required, owned: required == 0 ? OwnedPolicyState.Absent : OwnedPolicyState.Present);
                for (int actual = 0; actual < 4; actual++)
                {
                    Assert.AreEqual(expected[required, actual], PolicyConfirmationPolicy.IsConfirmed(artifact, Observation(artifact, protection: (EnforcementProtectionLevel)actual), Now));
                }

                Assert.IsFalse(PolicyConfirmationPolicy.IsConfirmed(artifact, Observation(artifact, owned: OwnedPolicyState.Unknown), Now));
                Assert.IsFalse(PolicyConfirmationPolicy.IsConfirmed(artifact, Observation(artifact, owned: required == 0 ? OwnedPolicyState.Present : OwnedPolicyState.Absent), Now));
            }
            Assert.IsTrue(PolicyConfirmationPolicy.IsConfirmed(Artifact(owned: OwnedPolicyState.Absent), Observation(Artifact(owned: OwnedPolicyState.Absent)), Now));
        }

        [TestMethod]
        public void ConfirmationRejectsStaleFutureAndWrongIdentity()
        {
            PolicyArtifact artifact = Artifact();
            Assert.IsTrue(PolicyConfirmationPolicy.IsConfirmed(artifact, Observation(artifact, Now.AddSeconds(-15)), Now));
            Assert.IsFalse(PolicyConfirmationPolicy.IsConfirmed(artifact, Observation(artifact, Now.AddSeconds(-15).AddTicks(-1)), Now));
            Assert.IsFalse(PolicyConfirmationPolicy.IsConfirmed(artifact, Observation(artifact, Now.AddTicks(1)), Now));
            Assert.IsFalse(PolicyConfirmationPolicy.IsConfirmed(artifact, Observation(Artifact(2)), Now));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new EffectivePolicyObservation(Guid.NewGuid(), 1, artifact.Sha256Hex, Now, artifact.RequiredProtection, OwnedPolicyState.Present, false, "["));
        }

        [TestMethod]
        public async Task BeginIsAtomicAndExactRetryIsIdempotent()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            PolicyArtifact first = Artifact();
            ReconciliationAttempt attempt = Attempt(first);
            await store.SaveCandidateAndBeginAttemptAsync(first, attempt, CancellationToken.None);
            await store.SaveCandidateAndBeginAttemptAsync(first, attempt, CancellationToken.None);
            Assert.AreEqual(attempt, await store.GetPendingAttemptAsync(CancellationToken.None));
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.SaveCandidateAndBeginAttemptAsync(Artifact(2), Attempt(Artifact(2)), CancellationToken.None));
            Assert.IsNull(await store.GetArtifactAsync(2, CancellationToken.None));
            Assert.IsNull(await store.GetLastGoodArtifactAsync(CancellationToken.None));
        }

        [TestMethod]
        public async Task ObservedCommitPromotesSoleLastGoodAndPreservesFailedCandidate()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            await Commit(store, Artifact());
            await Commit(store, Artifact(2));
            Assert.AreEqual(PolicyArtifactState.Candidate, (await store.GetArtifactAsync(1, CancellationToken.None))!.State);
            Assert.AreEqual(2L, (await store.GetLastGoodArtifactAsync(CancellationToken.None))!.PolicyVersion);
            Assert.AreEqual(2L, (await store.GetLastGoodObservationAsync(CancellationToken.None))!.PolicyVersion);
            PolicyArtifact third = Artifact(3);
            ReconciliationAttempt attempt = Attempt(third);
            await store.SaveCandidateAndBeginAttemptAsync(third, attempt, CancellationToken.None);
            await store.MarkApplyReportedAsync(attempt.AttemptId, Now, CancellationToken.None);
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.CommitObservedSuccessAsync(attempt.AttemptId, Observation(third, Now.AddSeconds(-16)), Now, CancellationToken.None));
            Assert.AreEqual(ReconciliationPhase.ApplyReported, (await store.GetPendingAttemptAsync(CancellationToken.None))!.Phase);
            Assert.AreEqual(2L, (await store.GetLastGoodArtifactAsync(CancellationToken.None))!.PolicyVersion);
            await store.MarkFailedAsync(attempt.AttemptId, "NoChange", Now, CancellationToken.None);
            await store.MarkFailedAsync(attempt.AttemptId, "NoChange", Now, CancellationToken.None);
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.MarkFailedAsync(attempt.AttemptId, "Different", Now, CancellationToken.None));
            Assert.IsNull(await store.GetPendingAttemptAsync(CancellationToken.None));
        }

        [TestMethod]
        public async Task RestoreRetainsDirectionAndCommitsRecoveryEvidenceOnly()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            await Commit(store, Artifact());
            PolicyArtifact lastGood = (await store.GetLastGoodArtifactAsync(CancellationToken.None))!;
            PolicyArtifact desired = Artifact(2);
            ReconciliationAttempt attempt = Attempt(desired);
            await store.SaveCandidateAndBeginAttemptAsync(desired, attempt, CancellationToken.None);
            await store.MarkDesiredUncertainAsync(attempt.AttemptId, "Unknown", CancellationToken.None);
            await store.PrepareRestoreAsync(attempt.AttemptId, lastGood, "Mismatch", CancellationToken.None);
            ReconciliationAttempt prepared = (await store.GetPendingAttemptAsync(CancellationToken.None))!;
            Assert.AreNotEqual(prepared.DesiredActionIdentity, prepared.RestoreActionIdentity);
            await store.MarkRecoveryBlockedAsync(attempt.AttemptId, "Conflict", CancellationToken.None);
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.MarkDesiredUncertainAsync(attempt.AttemptId, "WrongDirection", CancellationToken.None));
            await store.PrepareRestoreAsync(attempt.AttemptId, lastGood, "Mismatch", CancellationToken.None);
            Assert.AreEqual(prepared.RestoreActionIdentity, (await store.GetPendingAttemptAsync(CancellationToken.None))!.RestoreActionIdentity);
            await store.MarkRestoreApplyReportedAsync(attempt.AttemptId, Now, CancellationToken.None);
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.CommitObservedSuccessAsync(attempt.AttemptId, Observation(desired), Now, CancellationToken.None));
            EffectivePolicyObservation restored = Observation(lastGood, Now.AddSeconds(1));
            await store.CompleteRestoredLastGoodAsync(attempt.AttemptId, restored, "Restored", Now.AddSeconds(1), CancellationToken.None);
            Assert.IsNull(await store.GetPendingAttemptAsync(CancellationToken.None));
            Assert.AreEqual(1L, (await store.GetLastGoodArtifactAsync(CancellationToken.None))!.PolicyVersion);
            Assert.AreEqual(restored, await store.GetLastGoodObservationAsync(CancellationToken.None));
        }

        [TestMethod]
        public async Task InvalidTransitionAndMetadataSubstitutionLeaveRowsUnchanged()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            PolicyArtifact artifact = Artifact();
            ReconciliationAttempt attempt = Attempt(artifact);
            await store.SaveCandidateAndBeginAttemptAsync(artifact, attempt, CancellationToken.None);
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.MarkRestoreApplyReportedAsync(attempt.AttemptId, Now, CancellationToken.None));
            await store.MarkApplyReportedAsync(attempt.AttemptId, Now, CancellationToken.None);
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.MarkApplyReportedAsync(attempt.AttemptId, Now, CancellationToken.None));
            await store.MarkFailedAsync(attempt.AttemptId, "NoChange", Now, CancellationToken.None);
            PolicyArtifact substitute = Artifact(protection: EnforcementProtectionLevel.AuditOnly);
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.SaveCandidateAndBeginAttemptAsync(substitute, Attempt(substitute), CancellationToken.None));
            Assert.AreEqual(artifact, await store.GetArtifactAsync(1, CancellationToken.None));
        }

        [TestMethod]
        public async Task CancellationBeforeBeginLeavesNoRows()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            using CancellationTokenSource cancellation = new();
            await cancellation.CancelAsync();
            _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => store.SaveCandidateAndBeginAttemptAsync(Artifact(), Attempt(Artifact()), cancellation.Token));
            Assert.IsNull(await store.GetArtifactAsync(1, CancellationToken.None));
            Assert.IsNull(await store.GetPendingAttemptAsync(CancellationToken.None));
        }

        [TestMethod]
        public async Task ReadsRejectCorruptArtifactAndAttemptRows()
        {
            foreach (string sql in new[] { "UPDATE policy_artifacts SET sha256_hex='bad'", "UPDATE policy_artifacts SET created_utc='yesterday'", "UPDATE policy_artifacts SET required_protection=9", "UPDATE policy_artifacts SET expected_owned_state=2", "UPDATE policy_artifacts SET state=9" })
            {
                await using TemporarySqliteDatabase database = new();
                SqlitePolicyStateStore store = Store(database);
                await store.InitializeAsync(CancellationToken.None);
                await store.SaveCandidateAndBeginAttemptAsync(Artifact(), Attempt(Artifact()), CancellationToken.None);
                await Corrupt(database, sql);
                _ = await Assert.ThrowsExactlyAsync<InvalidDataException>(() => store.GetArtifactAsync(1, CancellationToken.None));
            }
            foreach (string sql in new[] { "UPDATE reconciliation_attempts SET phase=9", "UPDATE reconciliation_attempts SET prepared_utc='bad'", "UPDATE reconciliation_attempts SET desired_action_id='bad'" })
            {
                await using TemporarySqliteDatabase database = new();
                SqlitePolicyStateStore store = Store(database);
                await store.InitializeAsync(CancellationToken.None);
                await store.SaveCandidateAndBeginAttemptAsync(Artifact(), Attempt(Artifact()), CancellationToken.None);
                await Corrupt(database, sql);
                _ = await Assert.ThrowsExactlyAsync<InvalidDataException>(() => store.GetPendingAttemptAsync(CancellationToken.None));
            }
        }

        [TestMethod]
        public async Task TerminalUpdateFailureRollsBackObservationAndPromotion()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            await Commit(store, Artifact());
            PolicyArtifact desired = Artifact(2);
            ReconciliationAttempt attempt = Attempt(desired);
            await store.SaveCandidateAndBeginAttemptAsync(desired, attempt, CancellationToken.None);
            await Corrupt(database, "CREATE TRIGGER fail_completion BEFORE UPDATE ON reconciliation_attempts WHEN NEW.phase=6 BEGIN SELECT RAISE(ABORT,'injected failure'); END;");
            _ = await Assert.ThrowsExactlyAsync<SqliteException>(() => store.CommitObservedSuccessAsync(attempt.AttemptId, Observation(desired), Now, CancellationToken.None));
            Assert.AreEqual(1L, (await store.GetLastGoodArtifactAsync(CancellationToken.None))!.PolicyVersion);
            Assert.AreEqual(1L, await Count(database, "SELECT count(*) FROM applied_observations"));
            Assert.AreEqual(ReconciliationPhase.Prepared, (await store.GetPendingAttemptAsync(CancellationToken.None))!.Phase);
        }

        [TestMethod]
        public async Task RecoveryCompletionFailureRollsBackEvidenceAndKeepsAttemptPending()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            await Commit(store, Artifact());
            PolicyArtifact lastGood = (await store.GetLastGoodArtifactAsync(CancellationToken.None))!;
            ReconciliationAttempt attempt = Attempt(Artifact(2));
            await store.SaveCandidateAndBeginAttemptAsync(Artifact(2), attempt, CancellationToken.None);
            await store.PrepareRestoreAsync(attempt.AttemptId, lastGood, "Restore", CancellationToken.None);
            await Corrupt(database, "CREATE TRIGGER fail_completion BEFORE UPDATE ON reconciliation_attempts WHEN NEW.phase=7 BEGIN SELECT RAISE(ABORT,'injected failure'); END;");
            _ = await Assert.ThrowsExactlyAsync<SqliteException>(() => store.CompleteRestoredLastGoodAsync(attempt.AttemptId, Observation(lastGood), "Restored", Now, CancellationToken.None));
            Assert.AreEqual(1L, await Count(database, "SELECT count(*) FROM applied_observations"));
            Assert.AreEqual(ReconciliationPhase.RestorePrepared, (await store.GetPendingAttemptAsync(CancellationToken.None))!.Phase);
        }

        [TestMethod]
        public async Task OldCommittedRetryCannotReplaceNewLastGood()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            ReconciliationAttempt attempt = Attempt(Artifact());
            EffectivePolicyObservation observation = Observation(Artifact());
            await store.SaveCandidateAndBeginAttemptAsync(Artifact(), attempt, CancellationToken.None);
            await store.CommitObservedSuccessAsync(attempt.AttemptId, observation, Now, CancellationToken.None);
            await store.CommitObservedSuccessAsync(attempt.AttemptId, observation, Now, CancellationToken.None);
            await Commit(store, Artifact(2));
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.CommitObservedSuccessAsync(attempt.AttemptId, observation, Now, CancellationToken.None));
            Assert.AreEqual(2L, (await store.GetLastGoodArtifactAsync(CancellationToken.None))!.PolicyVersion);
        }

        [TestMethod]
        public async Task StaleRestoreArtifactAndObservationAreRejected()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            await Commit(store, Artifact());
            PolicyArtifact stale = (await store.GetLastGoodArtifactAsync(CancellationToken.None))!;
            await Commit(store, Artifact(2));
            PolicyArtifact current = (await store.GetLastGoodArtifactAsync(CancellationToken.None))!;
            ReconciliationAttempt attempt = Attempt(Artifact(3));
            await store.SaveCandidateAndBeginAttemptAsync(Artifact(3), attempt, CancellationToken.None);
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.PrepareRestoreAsync(attempt.AttemptId, stale, "Restore", CancellationToken.None));
            await store.PrepareRestoreAsync(attempt.AttemptId, current, "Restore", CancellationToken.None);
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.CompleteRestoredLastGoodAsync(attempt.AttemptId, Observation(stale), "Restore", Now, CancellationToken.None));
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.CompleteRestoredLastGoodAsync(attempt.AttemptId, Observation(current, Now.AddSeconds(-16)), "Restore", Now, CancellationToken.None));
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.PrepareRestoreAsync(attempt.AttemptId, stale, "Restore", CancellationToken.None));
            Assert.AreEqual(2L, (await store.GetLastGoodArtifactAsync(CancellationToken.None))!.PolicyVersion);
        }

        [TestMethod]
        public async Task CorruptObservationRowsAreRejected()
        {
            foreach (string assignment in new[] { "protection_level=9", "observed_owned_state=9", "external_deny_present=2", "observed_utc='bad'", "sha256_hex='bad'", "evidence_json='['", "observation_id='bad'" })
            {
                await using TemporarySqliteDatabase database = new();
                SqlitePolicyStateStore store = Store(database);
                await store.InitializeAsync(CancellationToken.None);
                await Commit(store, Artifact());
                await Corrupt(database, "UPDATE applied_observations SET " + assignment);
                _ = await Assert.ThrowsExactlyAsync<InvalidDataException>(() => store.GetLastGoodObservationAsync(CancellationToken.None));
            }
        }

        [TestMethod]
        public async Task SqliteChecksRejectInvalidDurableEnumValuesAndBoolean()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            await Commit(store, Artifact());
            await using SqliteConnection connection = await new SqliteConnectionFactory(new SqliteDatabaseOptions(database.DatabasePath)).OpenAsync(CancellationToken.None);
            foreach (string sql in new[] { "UPDATE policy_artifacts SET state=2", "UPDATE policy_artifacts SET required_protection=4", "UPDATE policy_artifacts SET expected_owned_state=2", "UPDATE reconciliation_attempts SET phase=8", "UPDATE applied_observations SET protection_level=-1", "UPDATE applied_observations SET observed_owned_state=3", "UPDATE applied_observations SET external_deny_present=2" })
            {
                await using SqliteCommand command = connection.CreateCommand();
                command.CommandText = sql;
                _ = await Assert.ThrowsExactlyAsync<SqliteException>(command.ExecuteNonQueryAsync);
            }
            Assert.AreEqual("None=0,AuditOnly=1,PostLaunchTermination=2,PreExecutionBlock=3", string.Join(',', Enum.GetValues<EnforcementProtectionLevel>().Select(v => $"{v}={(int)v}")));
            Assert.AreEqual("Absent=0,Present=1,Unknown=2", string.Join(',', Enum.GetValues<OwnedPolicyState>().Select(v => $"{v}={(int)v}")));
            Assert.AreEqual("Desired=0,Restore=1", string.Join(',', Enum.GetValues<EnforcementActionKind>().Select(v => $"{v}={(int)v}")));
            Assert.AreEqual("Candidate=0,LastGood=1", string.Join(',', Enum.GetValues<PolicyArtifactState>().Select(v => $"{v}={(int)v}")));
            Assert.AreEqual("Prepared=0,ApplyReported=1,DesiredUncertain=2,RestorePrepared=3,RestoreApplyReported=4,RecoveryBlocked=5,Committed=6,Failed=7", string.Join(',', Enum.GetValues<ReconciliationPhase>().Select(v => $"{v}={(int)v}")));
        }

        [TestMethod]
        public void ActionIdentityIsDeterministicSeparatedAndValidated()
        {
            Guid id = Guid.Parse("c0874cb2-6cbe-4f31-8d2f-2b1d40a1c420");
            string hash = new('a', 64);
            EnforcementActionIdentity desired = new(id, EnforcementActionKind.Desired, 2, hash);
            Assert.AreEqual("c0874cb2-6cbe-4f31-8d2f-2b1d40a1c420:0:2:" + hash, desired.ActionId);
            Assert.AreEqual(desired, new EnforcementActionIdentity(id, EnforcementActionKind.Desired, 2, hash));
            Assert.AreNotEqual(desired.ActionId, new EnforcementActionIdentity(id, EnforcementActionKind.Restore, 2, hash).ActionId);
            _ = Assert.ThrowsExactly<ArgumentException>(() => new EnforcementActionIdentity(Guid.Empty, EnforcementActionKind.Desired, 1, hash));
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new EnforcementActionIdentity(id, (EnforcementActionKind)2, 1, hash));
            Assert.IsFalse(PolicyConfirmationPolicy.IsConfirmed(Artifact(), null, Now));
        }

        [TestMethod]
        public async Task CancellationAfterPreparedKeepsDurablePendingAttempt()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            ReconciliationAttempt attempt = Attempt(Artifact());
            await store.SaveCandidateAndBeginAttemptAsync(Artifact(), attempt, CancellationToken.None);
            using CancellationTokenSource cancellation = new();
            await cancellation.CancelAsync();
            _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => store.CommitObservedSuccessAsync(attempt.AttemptId, Observation(Artifact()), Now, cancellation.Token));
            SqlitePolicyStateStore reopened = Store(database);
            Assert.AreEqual(attempt, await reopened.GetPendingAttemptAsync(CancellationToken.None));
            Assert.IsNull(await reopened.GetLastGoodArtifactAsync(CancellationToken.None));
        }

        [TestMethod]
        public async Task InvalidFailedPhaseWithoutDiagnosticIsRejectedOnRead()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            ReconciliationAttempt attempt = Attempt(Artifact());
            await store.SaveCandidateAndBeginAttemptAsync(Artifact(), attempt, CancellationToken.None);
            await store.MarkFailedAsync(attempt.AttemptId, "NoChange", Now, CancellationToken.None);
            await Corrupt(database, "UPDATE reconciliation_attempts SET error_code=NULL");
            _ = await Assert.ThrowsExactlyAsync<InvalidDataException>(() => store.GetPendingAttemptAsync(CancellationToken.None));
        }

        [TestMethod]
        [DataRow(0, "11101101")]
        [DataRow(1, "01101101")]
        [DataRow(2, "01101101")]
        [DataRow(3, "00111010")]
        [DataRow(4, "00111010")]
        [DataRow(5, "01101101")]
        [DataRow(6, "00000000")]
        [DataRow(7, "00000001")]
        [DataRow(8, "00111010")]
        public async Task PhaseGraphRejectsEveryUnsupportedTransition(int phase, string allowed)
        {
            for (int operation = 0; operation < 8; operation++)
            {
                await using TemporarySqliteDatabase database = new();
                SqlitePolicyStateStore store = Store(database);
                await store.InitializeAsync(CancellationToken.None);
                await Commit(store, Artifact());
                PolicyArtifact lastGood = (await store.GetLastGoodArtifactAsync(CancellationToken.None))!;
                PolicyArtifact desired = Artifact(2);
                ReconciliationAttempt attempt = Attempt(desired);
                await store.SaveCandidateAndBeginAttemptAsync(desired, attempt, CancellationToken.None);
                switch (phase)
                {
                    case 1: await store.MarkApplyReportedAsync(attempt.AttemptId, Now, CancellationToken.None); break;
                    case 2: await store.MarkDesiredUncertainAsync(attempt.AttemptId, "Error", CancellationToken.None); break;
                    case 3:
                    case 4:
                    case 8:
                        await store.PrepareRestoreAsync(attempt.AttemptId, lastGood, "Error", CancellationToken.None);
                        if (phase == 4)
                        {
                            await store.MarkRestoreApplyReportedAsync(attempt.AttemptId, Now, CancellationToken.None);
                        }

                        if (phase == 8)
                        {
                            await store.MarkRecoveryBlockedAsync(attempt.AttemptId, "Error", CancellationToken.None);
                        }

                        break;
                    case 5: await store.MarkRecoveryBlockedAsync(attempt.AttemptId, "Error", CancellationToken.None); break;
                    case 6: await store.CommitObservedSuccessAsync(attempt.AttemptId, Observation(desired), Now, CancellationToken.None); break;
                    case 7: await store.MarkFailedAsync(attempt.AttemptId, "Error", Now, CancellationToken.None); break;
                    default:
                        break;
                }
                Func<Task> action = operation switch
                {
                    0 => () => store.MarkApplyReportedAsync(attempt.AttemptId, Now, CancellationToken.None),
                    1 => () => store.MarkDesiredUncertainAsync(attempt.AttemptId, "Error", CancellationToken.None),
                    2 => () => store.PrepareRestoreAsync(attempt.AttemptId, lastGood, "Error", CancellationToken.None),
                    3 => () => store.MarkRestoreApplyReportedAsync(attempt.AttemptId, Now, CancellationToken.None),
                    4 => () => store.MarkRecoveryBlockedAsync(attempt.AttemptId, "Error", CancellationToken.None),
                    5 => () => store.CommitObservedSuccessAsync(attempt.AttemptId, Observation(desired), Now, CancellationToken.None),
                    6 => () => store.CompleteRestoredLastGoodAsync(attempt.AttemptId, Observation(lastGood), "Error", Now, CancellationToken.None),
                    _ => () => store.MarkFailedAsync(attempt.AttemptId, "Error", Now, CancellationToken.None),
                };
                ReconciliationAttempt? before = await store.GetPendingAttemptAsync(CancellationToken.None);
                if (allowed[operation] == '1')
                {
                    await action();
                }
                else
                {
                    _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(action, $"phase={phase}, operation={operation}");
                    Assert.AreEqual(before, await store.GetPendingAttemptAsync(CancellationToken.None));
                }
            }
        }

        [TestMethod]
        [DataRow("policy_artifacts", "state")]
        [DataRow("policy_artifacts", "required_protection")]
        [DataRow("policy_artifacts", "expected_owned_state")]
        [DataRow("reconciliation_attempts", "phase")]
        [DataRow("applied_observations", "protection_level")]
        [DataRow("applied_observations", "observed_owned_state")]
        [DataRow("applied_observations", "external_deny_present")]
        public async Task FractionalDurableIntegerIsRejectedWithoutTruncation(string table, string column)
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            if (table == "reconciliation_attempts")
            {
                await store.SaveCandidateAndBeginAttemptAsync(Artifact(), Attempt(Artifact()), CancellationToken.None);
            }
            else
            {
                await Commit(store, Artifact());
            }

            string fractional = column == "required_protection" ? "1.5" : "0.5";
            await Corrupt(database, $"UPDATE {table} SET {column}={fractional}");
            Assert.AreEqual(1L, await Count(database, $"SELECT count(*) FROM {table} WHERE typeof({column})='real'"));
            Func<Task> read = table switch
            {
                "policy_artifacts" => () => store.GetArtifactAsync(1, CancellationToken.None),
                "reconciliation_attempts" => () => store.GetPendingAttemptAsync(CancellationToken.None),
                _ => () => store.GetLastGoodObservationAsync(CancellationToken.None),
            };
            _ = await Assert.ThrowsExactlyAsync<InvalidDataException>(read);
        }

        [TestMethod]
        public async Task TerminalCompletionBeforeApplyReportIsRejectedOnRead()
        {
            await using TemporarySqliteDatabase database = new();
            SqlitePolicyStateStore store = Store(database);
            await store.InitializeAsync(CancellationToken.None);
            ReconciliationAttempt attempt = Attempt(Artifact());
            await store.SaveCandidateAndBeginAttemptAsync(Artifact(), attempt, CancellationToken.None);
            await store.MarkApplyReportedAsync(attempt.AttemptId, Now.AddSeconds(10), CancellationToken.None);
            await store.MarkFailedAsync(attempt.AttemptId, "NoChange", Now.AddSeconds(10), CancellationToken.None);
            await Corrupt(database, "UPDATE reconciliation_attempts SET completed_utc='2026-09-12T00:00:05.0000000+00:00'");
            _ = await Assert.ThrowsExactlyAsync<InvalidDataException>(() => store.GetPendingAttemptAsync(CancellationToken.None));
        }

        private static async Task<long> Count(TemporarySqliteDatabase database, string sql)
        {
            await using SqliteConnection connection = await new SqliteConnectionFactory(new SqliteDatabaseOptions(database.DatabasePath)).OpenAsync(CancellationToken.None);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            return (long)(await command.ExecuteScalarAsync())!;
        }

        private static async Task Commit(SqlitePolicyStateStore store, PolicyArtifact artifact)
        {
            ReconciliationAttempt attempt = Attempt(artifact);
            await store.SaveCandidateAndBeginAttemptAsync(artifact, attempt, CancellationToken.None);
            await store.CommitObservedSuccessAsync(attempt.AttemptId, Observation(artifact), Now, CancellationToken.None);
        }

        private static async Task Corrupt(TemporarySqliteDatabase database, string sql)
        {
            await using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = database.DatabasePath, Pooling = false }.ConnectionString);
            await connection.OpenAsync();
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON; " + sql;
            _ = await command.ExecuteNonQueryAsync();
        }
    }
}
