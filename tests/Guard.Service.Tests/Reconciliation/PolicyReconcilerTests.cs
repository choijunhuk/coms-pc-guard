using System.Security.Cryptography;
using System.Text;
using Guard.Service.Enforcement;
using Guard.Service.Reconciliation;
using Guard.Service.Storage;
using Guard.Service.Tests.TestSupport;
using Microsoft.Data.Sqlite;

namespace Guard.Service.Tests.Reconciliation
{
    [TestClass]
    public sealed class PolicyReconcilerTests
    {
        private static readonly DateTimeOffset Now = new(2026, 9, 12, 0, 0, 0, TimeSpan.Zero);
        private static PolicyArtifact Artifact(long version = 1, bool absent = false)
        {
            const string json = "{}";
            return new(version, json, Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json))), absent ? EnforcementProtectionLevel.None : EnforcementProtectionLevel.PreExecutionBlock, absent ? OwnedPolicyState.Absent : OwnedPolicyState.Present, Now);
        }
        private static EffectivePolicyObservation Observation(PolicyArtifact artifact, DateTimeOffset? at = null, OwnedPolicyState? owned = null, EnforcementProtectionLevel? protection = null, long? version = null)
        {
            return new(Guid.NewGuid(), version ?? artifact.PolicyVersion, artifact.Sha256Hex, at ?? Now, protection ?? artifact.RequiredProtection, owned ?? artifact.ExpectedOwnedState, true, "{}");
        }

        private static SqlitePolicyStateStore Store(TemporarySqliteDatabase db)
        {
            return new(new(new(db.DatabasePath)));
        }

        private static ScriptedEnforcementAdapter Adapter(PolicyArtifact artifact)
        {
            return new() { Observe = _ => Task.FromResult(Observation(artifact)) };
        }

        private static PolicyReconciler Reconciler(IPolicyStateStore store, IEnforcementAdapter adapter, PolicyOperationGate gate, TimeProvider? clock = null)
        {
            return new(store, adapter, clock ?? new ManualTimeProvider(Now), gate);
        }

        private static async Task<long> Sql(TemporarySqliteDatabase db, string sql)
        {
            await using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = db.DatabasePath, Pooling = false }.ConnectionString);
            await connection.OpenAsync();
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = sql;
            return Convert.ToInt64(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
        }

        [TestMethod]
        [DataRow(true, ReconciliationOutcomeKind.Conflict)]
        [DataRow(false, ReconciliationOutcomeKind.Rejected)]
        public async Task InvalidValidationNeverJournalsOrApplies(bool conflict, ReconciliationOutcomeKind expected)
        {
            await using TemporarySqliteDatabase db = new();
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(CancellationToken.None);
            ScriptedEnforcementAdapter adapter = Adapter(Artifact());
            adapter.Validation = new(false, conflict, "Invalid");
            using PolicyOperationGate gate = new();
            Assert.AreEqual(expected, (await Reconciler(store, adapter, gate).ReconcileAsync(Artifact(), CancellationToken.None)).Kind);
            Assert.AreEqual(0, adapter.ApplyCalls);
            Assert.AreEqual(0L, await Sql(db, "SELECT count(*) FROM policy_artifacts"));
            Assert.AreEqual(0L, await Sql(db, "SELECT count(*) FROM reconciliation_attempts"));
        }

        [TestMethod]
        public async Task UnsupportedCapabilityNeverJournalsOrApplies()
        {
            await using TemporarySqliteDatabase db = new();
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(CancellationToken.None);
            ScriptedEnforcementAdapter adapter = Adapter(Artifact());
            adapter.Capabilities = new(true, true, true, false);
            using PolicyOperationGate gate = new();
            Assert.AreEqual(ReconciliationOutcomeKind.Unsupported, (await Reconciler(store, adapter, gate).ReconcileAsync(Artifact(), CancellationToken.None)).Kind);
            Assert.AreEqual(0, adapter.ApplyCalls);
            Assert.AreEqual(0L, await Sql(db, "SELECT count(*) FROM reconciliation_attempts"));
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task ExactObservationCommitsIncludingExpectedAbsence(bool absent)
        {
            await using TemporarySqliteDatabase db = new();
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(CancellationToken.None);
            PolicyArtifact desired = Artifact(absent: absent);
            ScriptedEnforcementAdapter adapter = Adapter(desired);
            adapter.Apply = async (artifact, identity, _) =>
            {
                ReconciliationAttempt pending = (await store.GetPendingAttemptAsync(CancellationToken.None))!;
                Assert.AreEqual(pending.DesiredActionIdentity, identity);
                Assert.AreEqual(desired, artifact);
                Assert.IsNull(await store.GetLastGoodArtifactAsync(CancellationToken.None));
                return new(true, EnforcementMutationStatus.Changed, null);
            };
            using PolicyOperationGate gate = new();
            PolicyReconciler reconciler = Reconciler(store, adapter, gate);
            Assert.AreEqual(ReconciliationOutcomeKind.Applied, (await reconciler.ReconcileAsync(desired, CancellationToken.None)).Kind);
            Assert.AreEqual(1L, (await store.GetLastGoodArtifactAsync(CancellationToken.None))!.PolicyVersion);
            Assert.IsTrue((await store.GetLastGoodObservationAsync(CancellationToken.None))!.ExternalDenyPresent);
            Assert.IsNull(await store.GetPendingAttemptAsync(CancellationToken.None));
            Assert.AreEqual(ReconciliationOutcomeKind.AlreadyApplied, (await reconciler.ReconcileAsync(desired, CancellationToken.None)).Kind);
            Assert.AreEqual(1, adapter.ApplyCalls);
            Assert.AreEqual(1L, await Sql(db, "SELECT count(*) FROM reconciliation_attempts"));
        }

        [TestMethod]
        [DataRow("version")]
        [DataRow("owned")]
        [DataRow("protection")]
        [DataRow("hash")]
        [DataRow("unknown")]
        public async Task MismatchNeverPromotesAndPreservesLastGood(string mismatch)
        {
            await using TemporarySqliteDatabase db = new();
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(CancellationToken.None);
            using PolicyOperationGate gate = new();
            ScriptedEnforcementAdapter adapter = Adapter(Artifact());
            Assert.AreEqual(ReconciliationOutcomeKind.Applied, (await Reconciler(store, adapter, gate).ReconcileAsync(Artifact(), CancellationToken.None)).Kind);
            PolicyArtifact desired = Artifact(2);
            adapter.Observe = _ => Task.FromResult(mismatch == "hash"
                ? new EffectivePolicyObservation(Guid.NewGuid(), 2, new string('a', 64), Now, EnforcementProtectionLevel.PreExecutionBlock, OwnedPolicyState.Present, false, "{}")
                : Observation(desired, owned: mismatch == "owned" ? OwnedPolicyState.Absent : mismatch == "unknown" ? OwnedPolicyState.Unknown : null, protection: mismatch == "protection" ? EnforcementProtectionLevel.AuditOnly : null, version: mismatch == "version" ? 3 : null));
            ReconciliationOutcome outcome = await Reconciler(store, adapter, gate).ReconcileAsync(desired, CancellationToken.None);
            Assert.AreEqual(ReconciliationOutcomeKind.RecoveryRequired, outcome.Kind);
            Assert.AreEqual(ReconciliationPhase.ApplyReported, (await store.GetPendingAttemptAsync(CancellationToken.None))!.Phase);
            Assert.AreEqual(1L, (await store.GetLastGoodArtifactAsync(CancellationToken.None))!.PolicyVersion);
        }

        [TestMethod]
        public async Task ProtectionDowngradeReturnsStableDiagnostic()
        {
            await using TemporarySqliteDatabase db = new();
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(CancellationToken.None);
            PolicyArtifact desired = Artifact();
            ScriptedEnforcementAdapter adapter = Adapter(desired);
            adapter.Observe = _ => Task.FromResult(Observation(desired, protection: EnforcementProtectionLevel.PostLaunchTermination));
            using PolicyOperationGate gate = new();

            ReconciliationOutcome outcome = await Reconciler(store, adapter, gate).ReconcileAsync(desired, CancellationToken.None);

            Assert.AreEqual(ReconciliationOutcomeKind.RecoveryRequired, outcome.Kind);
            Assert.AreEqual("ProtectionLevelMismatch", outcome.DiagnosticCode);
            Assert.AreEqual(ReconciliationPhase.ApplyReported, (await store.GetPendingAttemptAsync(CancellationToken.None))!.Phase);
        }

        [TestMethod]
        [DataRow(EnforcementMutationStatus.NoChange, ReconciliationOutcomeKind.Rejected)]
        [DataRow(EnforcementMutationStatus.Changed, ReconciliationOutcomeKind.RecoveryRequired)]
        [DataRow(EnforcementMutationStatus.Unknown, ReconciliationOutcomeKind.RecoveryRequired)]
        public async Task RejectionUsesExplicitMutationStatus(EnforcementMutationStatus mutation, ReconciliationOutcomeKind expected)
        {
            await using TemporarySqliteDatabase db = new();
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(CancellationToken.None);
            ScriptedEnforcementAdapter adapter = Adapter(Artifact());
            adapter.Apply = (_, _, _) => Task.FromResult(new EnforcementApplyResult(false, mutation, "Rejected"));
            using PolicyOperationGate gate = new();
            Assert.AreEqual(expected, (await Reconciler(store, adapter, gate).ReconcileAsync(Artifact(), CancellationToken.None)).Kind);
            Assert.AreEqual(0, adapter.ObservationCalls);
            Assert.AreEqual(mutation == EnforcementMutationStatus.NoChange ? 7L : 2L, await Sql(db, "SELECT phase FROM reconciliation_attempts"));
            Assert.IsNull(await store.GetLastGoodArtifactAsync(CancellationToken.None));
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task AdapterExceptionPreservesOriginalAndPending(bool observe)
        {
            await using TemporarySqliteDatabase db = new();
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(CancellationToken.None);
            ScriptedEnforcementAdapter adapter = Adapter(Artifact());
            IOException failure = new("adapter failure");
            if (observe)
            {
                adapter.Observe = _ => throw failure;
            }
            else
            {
                adapter.Apply = (_, _, _) => throw failure;
            }

            using PolicyOperationGate gate = new();
            ReconciliationOutcome outcome = await Reconciler(store, adapter, gate).ReconcileAsync(Artifact(), CancellationToken.None);
            Assert.AreEqual(ReconciliationOutcomeKind.RecoveryRequired, outcome.Kind);
            Assert.AreSame(failure, outcome.Exception);
            Assert.AreEqual(observe ? "ObservationFailed" : "ApplyFailed", outcome.DiagnosticCode);
            Assert.AreEqual(observe ? ReconciliationPhase.ApplyReported : ReconciliationPhase.DesiredUncertain, (await store.GetPendingAttemptAsync(CancellationToken.None))!.Phase);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task CancellationBeforeJournalThrowsAndAfterJournalPreservesPending(bool after)
        {
            await using TemporarySqliteDatabase db = new();
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(CancellationToken.None);
            ScriptedEnforcementAdapter adapter = Adapter(Artifact());
            using CancellationTokenSource cancellation = new();
            using PolicyOperationGate gate = new();
            if (after)
            {
                adapter.Apply = async (_, _, token) => { await cancellation.CancelAsync(); token.ThrowIfCancellationRequested(); return new(true, EnforcementMutationStatus.Unknown, null); };
                ReconciliationOutcome outcome = await Reconciler(store, adapter, gate).ReconcileAsync(Artifact(), cancellation.Token);
                Assert.AreEqual(ReconciliationOutcomeKind.RecoveryRequired, outcome.Kind);
                _ = Assert.IsInstanceOfType<OperationCanceledException>(outcome.Exception);
                Assert.IsNotNull(await store.GetPendingAttemptAsync(CancellationToken.None));
            }
            else
            {
                await cancellation.CancelAsync();
                _ = await Assert.ThrowsAsync<OperationCanceledException>(() => Reconciler(store, adapter, gate).ReconcileAsync(Artifact(), cancellation.Token));
                Assert.AreEqual(0L, await Sql(db, "SELECT count(*) FROM reconciliation_attempts"));
            }
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task SharedGateReturnsBusyBeforeStateReadOrAdapterCall(bool secondInstance)
        {
            await using TemporarySqliteDatabase db = new();
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(CancellationToken.None);
            ScriptedEnforcementAdapter adapter = Adapter(Artifact());
            using PolicyOperationGate gate = new();
            TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
            adapter.Apply = async (_, _, _) => { entered.SetResult(); await release.Task; return new(true, EnforcementMutationStatus.Changed, null); };
            PolicyReconciler first = Reconciler(store, adapter, gate);
            Task<ReconciliationOutcome> running = first.ReconcileAsync(Artifact(), CancellationToken.None);
            await entered.Task;
            try
            {
                // Corrupt a row so an accidental read cannot quietly pass.
                _ = await Sql(db, "PRAGMA ignore_check_constraints=ON; UPDATE policy_artifacts SET state=9");
                PolicyReconciler second = secondInstance ? Reconciler(Store(db), adapter, gate) : first;
                Assert.AreEqual(ReconciliationOutcomeKind.Busy, (await second.ReconcileAsync(Artifact(), CancellationToken.None)).Kind);
                Assert.AreEqual(1, adapter.ValidationCalls);
                Assert.AreEqual(1, adapter.ApplyCalls);
            }
            finally { _ = await Sql(db, "UPDATE policy_artifacts SET state=0"); release.SetResult(); }
            Assert.AreEqual(ReconciliationOutcomeKind.Applied, (await running).Kind);
        }

        [TestMethod]
        [DataRow(0, ReconciliationOutcomeKind.Applied)]
        [DataRow(150000000, ReconciliationOutcomeKind.Applied)]
        [DataRow(150000001, ReconciliationOutcomeKind.RecoveryRequired)]
        public async Task ConfirmationReadsAdvancedClockAndHonorsInclusiveFreshness(long ageTicks, ReconciliationOutcomeKind expected)
        {
            await using TemporarySqliteDatabase db = new();
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(CancellationToken.None);
            ManualTimeProvider clock = new(Now);
            ScriptedEnforcementAdapter adapter = Adapter(Artifact());
            adapter.Apply = (_, _, _) => { clock.Advance(TimeSpan.FromMinutes(1)); return Task.FromResult(new EnforcementApplyResult(true, EnforcementMutationStatus.Changed, null)); };
            adapter.Observe = _ => Task.FromResult(Observation(Artifact(), clock.GetUtcNow().AddTicks(-ageTicks)));
            using PolicyOperationGate gate = new();
            Assert.AreEqual(expected, (await Reconciler(store, adapter, gate, clock).ReconcileAsync(Artifact(), CancellationToken.None)).Kind);
        }

        [TestMethod]
        [DataRow(1, ReconciliationPhase.Prepared)]
        [DataRow(6, ReconciliationPhase.ApplyReported)]
        public async Task StoreFailureAfterApplySurvivesCoordinatorRecreation(int failedPhase, ReconciliationPhase expected)
        {
            await using TemporarySqliteDatabase db = new();
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(CancellationToken.None);
            _ = await Sql(db, $"CREATE TRIGGER fail_transition BEFORE UPDATE ON reconciliation_attempts WHEN NEW.phase={failedPhase} BEGIN SELECT RAISE(ABORT,'injected failure'); END;");
            ScriptedEnforcementAdapter adapter = Adapter(Artifact());
            using PolicyOperationGate gate = new();
            ReconciliationOutcome outcome = await Reconciler(store, adapter, gate).ReconcileAsync(Artifact(), CancellationToken.None);
            Assert.AreEqual(ReconciliationOutcomeKind.RecoveryRequired, outcome.Kind);
            Assert.AreEqual("StoreFailed", outcome.DiagnosticCode);
            _ = Assert.IsInstanceOfType<SqliteException>(outcome.Exception);
            SqlitePolicyStateStore reopened = Store(db);
            ReconciliationAttempt pending = (await reopened.GetPendingAttemptAsync(CancellationToken.None))!;
            Assert.AreEqual(expected, pending.Phase);
            Assert.IsNull(await reopened.GetLastGoodArtifactAsync(CancellationToken.None));
            int observations = adapter.ObservationCalls;
            Assert.AreEqual(ReconciliationOutcomeKind.Busy, (await Reconciler(reopened, adapter, gate).ReconcileAsync(Artifact(), CancellationToken.None)).Kind);
            Assert.AreEqual(pending, await reopened.GetPendingAttemptAsync(CancellationToken.None));
            Assert.AreEqual(1, adapter.ApplyCalls);
            Assert.AreEqual(observations, adapter.ObservationCalls);
        }

        [TestMethod]
        public async Task PendingInsertedAfterInitialReadTranslatesStoreCollisionToBusy()
        {
            await using TemporarySqliteDatabase db = new();
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(CancellationToken.None);
            ScriptedEnforcementAdapter adapter = Adapter(Artifact());
            ReconciliationAttempt other = new(Guid.NewGuid(), 1, Artifact().Sha256Hex, Now);
            adapter.BeforeValidation = () => Store(db).SaveCandidateAndBeginAttemptAsync(Artifact(), other, CancellationToken.None);
            using PolicyOperationGate gate = new();
            Assert.AreEqual(ReconciliationOutcomeKind.Busy, (await Reconciler(store, adapter, gate).ReconcileAsync(Artifact(), CancellationToken.None)).Kind);
            Assert.AreEqual(other, await store.GetPendingAttemptAsync(CancellationToken.None));
            Assert.AreEqual(0, adapter.ApplyCalls);
        }
    }
}
