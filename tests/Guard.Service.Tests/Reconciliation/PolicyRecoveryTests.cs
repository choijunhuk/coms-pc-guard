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
    public sealed class PolicyRecoveryTests
    {
        private static readonly DateTimeOffset Now = new(2026, 9, 12, 0, 0, 0, TimeSpan.Zero);
        private static PolicyArtifact Artifact(long version = 2)
        {
            return new(version, "{}", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("{}"))), EnforcementProtectionLevel.PreExecutionBlock, OwnedPolicyState.Present, Now);
        }

        private static EffectivePolicyObservation Observation(long version = 2)
        {
            return new(Guid.NewGuid(), version, Artifact(version).Sha256Hex, Now, EnforcementProtectionLevel.PreExecutionBlock, OwnedPolicyState.Present, true, "{}");
        }

        private static SqlitePolicyStateStore Store(TemporarySqliteDatabase db)
        {
            return new(new(new(db.DatabasePath)));
        }

        private static PolicyReconciler Coordinator(TemporarySqliteDatabase db, ScriptedEnforcementAdapter adapter, PolicyOperationGate gate)
        {
            return new(Store(db), adapter, new ManualTimeProvider(Now), gate);
        }

        private static ScriptedEnforcementAdapter Adapter()
        {
            return new() { Observe = _ => Task.FromResult(Observation(99)) };
        }

        private static Task<ReconciliationOutcome> Recover(PolicyReconciler reconciler, CancellationToken token = default)
        {
            return reconciler.RecoverPendingAsync(token);
        }

        private static async Task<ReconciliationAttempt> Seed(TemporarySqliteDatabase db, bool lastGood = false, ReconciliationPhase phase = ReconciliationPhase.Prepared)
        {
            SqlitePolicyStateStore store = Store(db);
            await store.InitializeAsync(default);
            if (lastGood)
            {
                ReconciliationAttempt good = new(Guid.NewGuid(), 1, Artifact(1).Sha256Hex, Now);
                await store.SaveCandidateAndBeginAttemptAsync(Artifact(1), good, default);
                await store.CommitObservedSuccessAsync(good.AttemptId, Observation(1), Now, default);
            }
            ReconciliationAttempt pending = new(Guid.NewGuid(), 2, Artifact().Sha256Hex, Now);
            await store.SaveCandidateAndBeginAttemptAsync(Artifact(), pending, default);
            if (phase == ReconciliationPhase.ApplyReported)
            {
                await store.MarkApplyReportedAsync(pending.AttemptId, Now, default);
            }

            if (phase == ReconciliationPhase.DesiredUncertain)
            {
                await store.MarkDesiredUncertainAsync(pending.AttemptId, "Interrupted", default);
            }

            return (await store.GetPendingAttemptAsync(default))!;
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
        public async Task NoPendingDoesNotCallAdapter()
        {
            await using TemporarySqliteDatabase db = new();
            await Store(db).InitializeAsync(default);
            ScriptedEnforcementAdapter adapter = Adapter();
            using PolicyOperationGate gate = new();
            Assert.AreEqual("NoWork", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
            Assert.AreEqual(0, adapter.ObservationCalls + adapter.ValidationCalls + adapter.ApplyCalls);
        }

        [TestMethod]
        public async Task MatchingDesiredCommitsBeforeValidationOrApplyAndThenNoWork()
        {
            await using TemporarySqliteDatabase db = new();
            _ = await Seed(db);
            ScriptedEnforcementAdapter adapter = Adapter();
            adapter.Observe = _ => Task.FromResult(Observation());
            adapter.Validation = new(false, true, "Conflict");
            using PolicyOperationGate gate = new();
            Assert.AreEqual("Applied", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
            Assert.AreEqual(2L, (await Store(db).GetLastGoodArtifactAsync(default))!.PolicyVersion);
            Assert.AreEqual(0, adapter.ApplyCalls + adapter.ValidationCalls);
            Assert.AreEqual("NoWork", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
            Assert.AreEqual(1, adapter.ObservationCalls);
        }

        [TestMethod]
        [DataRow(ReconciliationPhase.Prepared)]
        [DataRow(ReconciliationPhase.ApplyReported)]
        [DataRow(ReconciliationPhase.DesiredUncertain)]
        public async Task DesiredRetryObservesThenValidatesAndReusesDurableIdentity(ReconciliationPhase phase)
        {
            await using TemporarySqliteDatabase db = new();
            ReconciliationAttempt pending = await Seed(db, phase: phase);
            ScriptedEnforcementAdapter adapter = Adapter();
            adapter.BeforeValidation = () => { Assert.AreEqual(1, adapter.ObservationCalls); return Task.CompletedTask; };
            adapter.Apply = (_, identity, _) =>
            {
                Assert.AreEqual(1, adapter.ValidationCalls);
                Assert.AreEqual(pending.DesiredActionIdentity, identity);
                adapter.Observe = _ => Task.FromResult(Observation());
                return Task.FromResult(new EnforcementApplyResult(true, EnforcementMutationStatus.Changed, null));
            };
            using PolicyOperationGate gate = new();
            Assert.AreEqual("Applied", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
            Assert.AreEqual(1, adapter.ApplyCalls);
            Assert.IsNull(await Store(db).GetPendingAttemptAsync(default));
        }

        [TestMethod]
        [DataRow("conflict")]
        [DataRow("invalid")]
        [DataRow("capability")]
        public async Task CurrentUnsafeDesiredBlocksWithoutFallbackThenCanResume(string unsafeKind)
        {
            await using TemporarySqliteDatabase db = new();
            _ = await Seed(db, true);
            ScriptedEnforcementAdapter adapter = Adapter();
            if (unsafeKind == "capability")
            {
                adapter.Capabilities = new(true, true, true, false);
            }
            else
            {
                adapter.Validation = new(false, unsafeKind == "conflict", "Unsafe");
            }

            using PolicyOperationGate gate = new();
            Assert.AreEqual("RecoveryBlocked", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
            ReconciliationAttempt pending = (await Store(db).GetPendingAttemptAsync(default))!;
            Assert.AreEqual(ReconciliationPhase.RecoveryBlocked, pending.Phase);
            Assert.IsNull(pending.RestoreActionIdentity);
            Assert.AreEqual(0, adapter.ApplyCalls);
            adapter.Capabilities = new(true, true, true, true);
            adapter.Validation = new(true, false, null);
            adapter.Apply = (_, _, _) => { adapter.Observe = _ => Task.FromResult(Observation()); return Task.FromResult(new EnforcementApplyResult(true, EnforcementMutationStatus.Changed, null)); };
            Assert.AreEqual("Applied", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
        }

        [TestMethod]
        [DataRow("apply")]
        [DataRow("observe")]
        [DataRow("report-db")]
        [DataRow("commit-db")]
        public async Task PartialDesiredFailureRecoversObservedStateAfterRecreation(string failure)
        {
            await using TemporarySqliteDatabase db = new();
            await Store(db).InitializeAsync(default);
            if (failure.EndsWith("db", StringComparison.Ordinal))
            {
                _ = await Sql(db, $"CREATE TRIGGER fail_transition BEFORE UPDATE ON reconciliation_attempts WHEN NEW.phase={(failure == "report-db" ? 1 : 6)} BEGIN SELECT RAISE(ABORT,'injected'); END;");
            }

            ScriptedEnforcementAdapter adapter = Adapter();
            adapter.Apply = (_, _, _) => { adapter.Observe = _ => failure == "observe" ? throw new IOException("observe") : Task.FromResult(Observation()); return failure == "apply" ? throw new IOException("partial mutation") : Task.FromResult(new EnforcementApplyResult(true, EnforcementMutationStatus.Changed, null)); };
            using PolicyOperationGate gate = new();
            Assert.AreEqual(ReconciliationOutcomeKind.RecoveryRequired, (await Coordinator(db, adapter, gate).ReconcileAsync(Artifact(), default)).Kind);
            Assert.IsNotNull(await Store(db).GetPendingAttemptAsync(default));
            if (failure.EndsWith("db", StringComparison.Ordinal))
            {
                _ = await Sql(db, "DROP TRIGGER fail_transition");
            }

            adapter.Observe = _ => Task.FromResult(Observation());
            Assert.AreEqual("Applied", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
            Assert.AreEqual(1, adapter.ApplyCalls);
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task FailedDesiredDurablyPreparesDistinctRestoreBeforeValidationAndRecordsRollback(bool rejection)
        {
            await using TemporarySqliteDatabase db = new();
            ReconciliationAttempt pending = await Seed(db, true);
            ScriptedEnforcementAdapter adapter = Adapter();
            adapter.BeforeValidation = async () =>
            {
                if (adapter.ValidationCalls == 2)
                {
                    ReconciliationAttempt durable = (await Store(db).GetPendingAttemptAsync(default))!;
                    Assert.AreEqual(ReconciliationPhase.RestorePrepared, durable.Phase);
                    Assert.AreEqual(new EnforcementActionIdentity(pending.AttemptId, EnforcementActionKind.Restore, 1, Artifact(1).Sha256Hex), durable.RestoreActionIdentity);
                    Assert.AreNotEqual(pending.DesiredActionIdentity.ActionId, durable.RestoreActionIdentity!.ActionId);
                }
            };
            adapter.Apply = (artifact, identity, _) =>
            {
                if (identity.ActionKind == EnforcementActionKind.Restore)
                {
                    Assert.AreEqual(1L, artifact.PolicyVersion);
                    Assert.AreEqual(2, adapter.ValidationCalls);
                    adapter.Observe = _ => Task.FromResult(Observation(1));
                }
                return Task.FromResult(new EnforcementApplyResult(!rejection || identity.ActionKind == EnforcementActionKind.Restore, EnforcementMutationStatus.Changed, "DesiredRejected"));
            };
            using PolicyOperationGate gate = new();
            Assert.AreEqual("RestoredLastGood", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
            Assert.AreEqual(2, adapter.ApplyCalls);
            Assert.IsNull(await Store(db).GetPendingAttemptAsync(default));
            Assert.AreEqual(1L, (await Store(db).GetLastGoodArtifactAsync(default))!.PolicyVersion);
            Assert.AreEqual(2L, await Sql(db, "SELECT count(*) FROM applied_observations"));
            Assert.AreEqual(7L, await Sql(db, "SELECT phase FROM reconciliation_attempts WHERE policy_version=2"));
            Assert.AreEqual("NoWork", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
        }

        [TestMethod]
        [DataRow("conflict")]
        [DataRow("capability")]
        public async Task BlockedRestoreDirectionSurvivesRestartAndNeverReappliesDesired(string unsafeKind)
        {
            await using TemporarySqliteDatabase db = new();
            _ = await Seed(db, true);
            ScriptedEnforcementAdapter adapter = Adapter();
            adapter.Apply = (_, _, _) =>
            {
                if (unsafeKind == "capability")
                {
                    adapter.Capabilities = new(true, true, true, false);
                }
                else
                {
                    adapter.Validation = new(false, true, "ExternalConflict");
                }

                return Task.FromResult(new EnforcementApplyResult(false, EnforcementMutationStatus.NoChange, "Rejected"));
            };
            using PolicyOperationGate gate = new();
            Assert.AreEqual("RecoveryBlocked", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
            ReconciliationAttempt blocked = (await Store(db).GetPendingAttemptAsync(default))!;
            Assert.AreEqual(ReconciliationPhase.RecoveryBlocked, blocked.Phase);
            Assert.IsNotNull(blocked.RestoreActionIdentity);
            Assert.AreEqual(1, adapter.ApplyCalls);
            adapter.Capabilities = new(true, true, true, true);
            adapter.Validation = new(true, false, null);
            // Even exact desired state cannot reverse a durable restore decision.
            adapter.Observe = _ => Task.FromResult(Observation());
            adapter.Apply = (_, identity, _) => { Assert.AreEqual(blocked.RestoreActionIdentity, identity); adapter.Observe = _ => Task.FromResult(Observation(1)); return Task.FromResult(new EnforcementApplyResult(true, EnforcementMutationStatus.Changed, null)); };
            Assert.AreEqual("RestoredLastGood", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
        }

        [TestMethod]
        public async Task NoLastGoodFailsDesiredWithoutInventingPolicy()
        {
            await using TemporarySqliteDatabase db = new();
            _ = await Seed(db);
            ScriptedEnforcementAdapter adapter = Adapter();
            adapter.Apply = (_, _, _) => Task.FromResult(new EnforcementApplyResult(false, EnforcementMutationStatus.NoChange, "Rejected"));
            using PolicyOperationGate gate = new();
            ReconciliationOutcome result = await Recover(Coordinator(db, adapter, gate));
            Assert.AreEqual("NoLastGood", result.Kind.ToString());
            Assert.AreEqual("NO_LAST_GOOD", result.DiagnosticCode);
            Assert.AreEqual(1, adapter.ApplyCalls);
            Assert.IsNull(await Store(db).GetPendingAttemptAsync(default));
            Assert.IsNull(await Store(db).GetLastGoodArtifactAsync(default));
            Assert.AreEqual(1L, await Sql(db, "SELECT count(*) FROM policy_artifacts"));
            Assert.AreEqual("NoWork", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
        }

        [TestMethod]
        public async Task RestoreMismatchIsNonterminalAndPhysicalRetriesShareOneLogicalIdentity()
        {
            await using TemporarySqliteDatabase db = new();
            _ = await Seed(db, true);
            ScriptedEnforcementAdapter adapter = Adapter();
            HashSet<string> logicalEffects = [];
            List<EnforcementActionIdentity> restoreCalls = [];
            adapter.Apply = (_, identity, _) =>
            {
                if (identity.ActionKind == EnforcementActionKind.Restore) { restoreCalls.Add(identity); _ = logicalEffects.Add(identity.ActionId); }
                return Task.FromResult(new EnforcementApplyResult(true, EnforcementMutationStatus.Changed, null));
            };
            using PolicyOperationGate gate = new();
            for (int i = 0; i < 3; i++)
            {
                Assert.AreEqual("RecoveryFailed", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
                Assert.AreEqual(ReconciliationPhase.RestoreApplyReported, (await Store(db).GetPendingAttemptAsync(default))!.Phase);
                Assert.AreEqual(1L, await Sql(db, "SELECT count(*) FROM applied_observations"));
            }
            Assert.AreEqual(3, restoreCalls.Count);
            Assert.AreEqual(1, logicalEffects.Count);
            Assert.AreEqual(4, adapter.ApplyCalls);
            Assert.IsTrue(restoreCalls.All(a => a == restoreCalls[0]));
            adapter.Observe = _ => Task.FromResult(Observation(1));
            Assert.AreEqual("RestoredLastGood", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
            Assert.AreEqual(4, adapter.ApplyCalls);
        }

        [TestMethod]
        public async Task RestoreProtectionDowngradeReturnsStableDiagnostic()
        {
            await using TemporarySqliteDatabase db = new();
            ReconciliationAttempt pending = await Seed(db, true);
            SqlitePolicyStateStore store = Store(db);
            PolicyArtifact lastGood = (await store.GetLastGoodArtifactAsync(default))!;
            await store.PrepareRestoreAsync(pending.AttemptId, lastGood, "Restore", default);
            ScriptedEnforcementAdapter adapter = Adapter();
            adapter.Observe = _ => Task.FromResult(new EffectivePolicyObservation(Guid.NewGuid(), 1, lastGood.Sha256Hex, Now, EnforcementProtectionLevel.PostLaunchTermination, OwnedPolicyState.Present, true, "{}"));
            using PolicyOperationGate gate = new();

            ReconciliationOutcome outcome = await Recover(Coordinator(db, adapter, gate));

            Assert.AreEqual("RecoveryFailed", outcome.Kind.ToString());
            Assert.AreEqual("ProtectionLevelMismatch", outcome.DiagnosticCode);
            Assert.AreEqual(ReconciliationPhase.RestoreApplyReported, (await store.GetPendingAttemptAsync(default))!.Phase);
        }

        [TestMethod]
        [DataRow("validation", ReconciliationPhase.RestorePrepared)]
        [DataRow("apply", ReconciliationPhase.RestorePrepared)]
        [DataRow("observation", ReconciliationPhase.RestoreApplyReported)]
        [DataRow("crash-validation", ReconciliationPhase.RestorePrepared)]
        [DataRow("crash-apply", ReconciliationPhase.RestorePrepared)]
        [DataRow("crash-observation", ReconciliationPhase.RestoreApplyReported)]
        [DataRow("cancel-after-apply", ReconciliationPhase.RestorePrepared)]
        [DataRow("report-db", ReconciliationPhase.RestorePrepared)]
        [DataRow("complete-db", ReconciliationPhase.RestoreApplyReported)]
        public async Task RestoreInterruptionRetainsDirectionAndEvidenceAcrossRestart(string failure, ReconciliationPhase phase)
        {
            await using TemporarySqliteDatabase db = new();
            _ = await Seed(db, true);
            if (failure.EndsWith("db", StringComparison.Ordinal))
            {
                _ = await Sql(db, $"CREATE TRIGGER fail_restore BEFORE UPDATE ON reconciliation_attempts WHEN NEW.policy_version=2 AND NEW.phase={(failure == "report-db" ? 4 : 7)} BEGIN SELECT RAISE(ABORT,'restore failure'); END;");
            }

            ScriptedEnforcementAdapter adapter = Adapter();
            using CancellationTokenSource cancellation = new();
            adapter.BeforeValidation = async () =>
            {
                if (adapter.ValidationCalls != 2)
                {
                    return;
                }

                if (failure == "crash-validation")
                {
                    throw new IOException("interrupted validation");
                }

                if (failure == "validation") { await cancellation.CancelAsync(); cancellation.Token.ThrowIfCancellationRequested(); }
            };
            adapter.Apply = async (_, identity, token) =>
            {
                if (identity.ActionKind == EnforcementActionKind.Restore)
                {
                    if (failure == "apply") { await cancellation.CancelAsync(); token.ThrowIfCancellationRequested(); }
                    if (failure == "crash-apply")
                    {
                        throw new IOException("interrupted apply");
                    }

                    if (failure == "cancel-after-apply")
                    {
                        await cancellation.CancelAsync();
                    }

                    adapter.Observe = async ct =>
                    {
                        if (failure == "observation") { await cancellation.CancelAsync(); ct.ThrowIfCancellationRequested(); }
                        return failure == "crash-observation" ? throw new IOException("interrupted observation") : Observation(1);
                    };
                }
                return new(true, EnforcementMutationStatus.Changed, null);
            };
            using PolicyOperationGate gate = new();
            ReconciliationOutcome result = await Recover(Coordinator(db, adapter, gate), cancellation.Token);
            Assert.AreEqual("RecoveryFailed", result.Kind.ToString());
            Assert.IsNotNull(result.Exception);
            ReconciliationAttempt interrupted = (await Store(db).GetPendingAttemptAsync(default))!;
            Assert.AreEqual(phase, interrupted.Phase);
            Assert.IsNotNull(interrupted.RestoreActionIdentity);
            Assert.AreEqual(1L, await Sql(db, "SELECT count(*) FROM applied_observations"));
            if (failure.EndsWith("db", StringComparison.Ordinal))
            {
                _ = await Sql(db, "DROP TRIGGER fail_restore");
            }

            adapter.BeforeValidation = null;
            adapter.Observe = _ => Task.FromResult(Observation(99));
            adapter.Apply = (_, identity, _) => { Assert.AreEqual(interrupted.RestoreActionIdentity, identity); adapter.Observe = _ => Task.FromResult(Observation(1)); return Task.FromResult(new EnforcementApplyResult(true, EnforcementMutationStatus.Changed, null)); };
            Assert.AreEqual("RestoredLastGood", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task CancellationPreservesPendingDesired(bool duringApply)
        {
            await using TemporarySqliteDatabase db = new();
            ReconciliationAttempt before = await Seed(db);
            ScriptedEnforcementAdapter adapter = Adapter();
            using CancellationTokenSource cancellation = new();
            using PolicyOperationGate gate = new();
            if (duringApply)
            {
                adapter.Apply = async (_, _, token) => { await cancellation.CancelAsync(); token.ThrowIfCancellationRequested(); return new(true, EnforcementMutationStatus.Unknown, null); };
                Assert.AreEqual("RecoveryFailed", (await Recover(Coordinator(db, adapter, gate), cancellation.Token)).Kind.ToString());
                Assert.IsNotNull(await Store(db).GetPendingAttemptAsync(default));
            }
            else
            {
                await cancellation.CancelAsync();
                _ = await Assert.ThrowsAsync<OperationCanceledException>(() => Recover(Coordinator(db, adapter, gate), cancellation.Token));
                Assert.AreEqual(before, await Store(db).GetPendingAttemptAsync(default));
                Assert.AreEqual(0, adapter.ApplyCalls + adapter.ObservationCalls);
            }
        }

        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task SharedGateBlocksRecoveryBeforeReadingPending(bool reconcileFirst)
        {
            await using TemporarySqliteDatabase db = new();
            if (reconcileFirst)
            {
                await Store(db).InitializeAsync(default);
            }
            else
            {
                _ = await Seed(db);
            }

            ScriptedEnforcementAdapter adapter = Adapter();
            TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
            if (reconcileFirst)
            {
                adapter.Apply = async (_, _, _) => { entered.SetResult(); await release.Task; adapter.Observe = _ => Task.FromResult(Observation()); return new(true, EnforcementMutationStatus.Changed, null); };
            }
            else
            {
                adapter.Observe = async _ => { entered.SetResult(); await release.Task; return Observation(); };
            }

            using PolicyOperationGate gate = new();
            Task<ReconciliationOutcome> first = reconcileFirst ? Coordinator(db, adapter, gate).ReconcileAsync(Artifact(), default) : Recover(Coordinator(db, adapter, gate));
            // Surface early coordinator failures instead of hanging at the rendezvous.
            Task completed = await Task.WhenAny(entered.Task, first);
            if (completed == first)
            {
                string detail;
                try
                {
                    ReconciliationOutcome outcome = await first;
                    detail = $"outcome {outcome.Kind} ({outcome.DiagnosticCode ?? "no diagnostic"})";
                }
                catch (Exception exception)
                {
                    detail = $"exception {exception.GetType().Name}: {exception.Message}";
                }

                Assert.Fail($"First operation completed before signaling rendezvous entry: {detail}");
            }

            await entered.Task;
            int observations = adapter.ObservationCalls;
            int applies = adapter.ApplyCalls;
            try
            {
                _ = await Sql(db, "PRAGMA ignore_check_constraints=ON; UPDATE policy_artifacts SET state=9");
                Assert.AreEqual("Busy", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
                Assert.AreEqual(observations, adapter.ObservationCalls);
                Assert.AreEqual(applies, adapter.ApplyCalls);
            }
            finally { _ = await Sql(db, "UPDATE policy_artifacts SET state=0"); release.SetResult(); }
            Assert.AreEqual("Applied", (await first).Kind.ToString());
        }

        [TestMethod]
        public async Task InitialObservationFailureDoesNotValidateApplyOrFallback()
        {
            await using TemporarySqliteDatabase db = new();
            ReconciliationAttempt before = await Seed(db, true);
            ScriptedEnforcementAdapter adapter = Adapter();
            IOException failure = new("cannot observe");
            adapter.Observe = _ => throw failure;
            using PolicyOperationGate gate = new();
            ReconciliationOutcome result = await Recover(Coordinator(db, adapter, gate));
            Assert.AreEqual("RecoveryFailed", result.Kind.ToString());
            Assert.AreEqual("ObservationFailed", result.DiagnosticCode);
            Assert.AreSame(failure, result.Exception);
            Assert.AreEqual(before, await Store(db).GetPendingAttemptAsync(default));
            Assert.AreEqual(0, adapter.ApplyCalls + adapter.ValidationCalls);
        }

        [TestMethod]
        [DataRow("apply")]
        [DataRow("observation")]
        [DataRow("report-db")]
        [DataRow("commit-db")]
        public async Task InterruptedRecoveryDesiredRetryKeepsIdentityAndObservesBeforeRetrying(string failure)
        {
            await using TemporarySqliteDatabase db = new();
            ReconciliationAttempt pending = await Seed(db, true);
            if (failure.EndsWith("db", StringComparison.Ordinal))
            {
                _ = await Sql(db, $"CREATE TRIGGER fail_retry BEFORE UPDATE ON reconciliation_attempts WHEN NEW.policy_version=2 AND NEW.phase={(failure == "report-db" ? 1 : 6)} BEGIN SELECT RAISE(ABORT,'retry failure'); END;");
            }

            ScriptedEnforcementAdapter adapter = Adapter();
            adapter.Apply = (_, identity, _) =>
            {
                Assert.AreEqual(pending.DesiredActionIdentity, identity);
                adapter.Observe = _ => failure == "observation" ? throw new IOException("retry observation") : Task.FromResult(Observation());
                return failure == "apply" ? throw new IOException("partial retry mutation") : Task.FromResult(new EnforcementApplyResult(true, EnforcementMutationStatus.Changed, null));
            };
            using PolicyOperationGate gate = new();
            ReconciliationOutcome result = await Recover(Coordinator(db, adapter, gate));
            Assert.AreEqual("RecoveryFailed", result.Kind.ToString());
            Assert.IsNotNull(result.Exception);
            ReconciliationAttempt interrupted = (await Store(db).GetPendingAttemptAsync(default))!;
            Assert.AreEqual(pending.DesiredActionIdentity, interrupted.DesiredActionIdentity);
            Assert.IsNull(interrupted.RestoreActionIdentity);
            if (failure.EndsWith("db", StringComparison.Ordinal))
            {
                _ = await Sql(db, "DROP TRIGGER fail_retry");
            }

            adapter.Observe = _ => Task.FromResult(Observation());
            Assert.AreEqual("Applied", (await Recover(Coordinator(db, adapter, gate))).Kind.ToString());
            Assert.AreEqual(1, adapter.ApplyCalls);
        }
    }
}
