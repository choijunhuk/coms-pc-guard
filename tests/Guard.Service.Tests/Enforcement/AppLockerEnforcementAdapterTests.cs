using Guard.Service.Enforcement;
using Guard.Service.Reconciliation;
using Guard.Service.Storage;
using Guard.Service.Tests.TestSupport;
using static Guard.Service.Tests.Configuration.GuardPolicyDocumentReaderTests;

namespace Guard.Service.Tests.Enforcement
{
    [TestClass]
    public sealed class AppLockerEnforcementAdapterTests
    {
        private static async Task<(PolicyReconciler Reconciler, FakeAppLockerGateway Gateway, SqlitePolicyStateStore Store, PolicyOperationGate Gate)> CreateAsync(TemporarySqliteDatabase db, ManualTimeProvider clock)
        {
            SqlitePolicyStateStore store = new(new(new(db.DatabasePath)));
            await store.InitializeAsync(CancellationToken.None);
            FakeAppLockerGateway gateway = new(clock);
            PolicyOperationGate gate = new();
            return (new PolicyReconciler(store, new AppLockerEnforcementAdapter(gateway, clock), clock, gate), gateway, store, gate);
        }

        private static PolicyArtifact Desired(string? document = null)
        {
            return AppLockerTestData.Artifact(document).ToPolicyArtifact(AppLockerTestData.InsideWindow);
        }

#pragma warning disable CA1707
        [TestMethod]
        public async Task Reconcile_CleanMachine_AppliesOnceThenReportsAlreadyApplied()
        {
            await using TemporarySqliteDatabase db = new();
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            (PolicyReconciler reconciler, FakeAppLockerGateway gateway, SqlitePolicyStateStore store, PolicyOperationGate gate) = await CreateAsync(db, clock);
            using (gate)
            {
                PolicyArtifact desired = Desired();

                Assert.AreEqual(ReconciliationOutcomeKind.Applied, (await reconciler.ReconcileAsync(desired, CancellationToken.None)).Kind);
                Assert.AreEqual(ReconciliationOutcomeKind.AlreadyApplied, (await reconciler.ReconcileAsync(desired, CancellationToken.None)).Kind);

                Assert.AreEqual(1, gateway.ApplyCount);
                Assert.AreEqual(desired.Sha256Hex, (await store.GetLastGoodArtifactAsync(CancellationToken.None))!.Sha256Hex);
            }
        }

        [TestMethod]
        public async Task Reconcile_NewVersion_ReplacesTheProductPolicy()
        {
            await using TemporarySqliteDatabase db = new();
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            (PolicyReconciler reconciler, FakeAppLockerGateway gateway, SqlitePolicyStateStore store, PolicyOperationGate gate) = await CreateAsync(db, clock);
            using (gate)
            {
                Assert.AreEqual(ReconciliationOutcomeKind.Applied, (await reconciler.ReconcileAsync(Desired(), CancellationToken.None)).Kind);
                PolicyArtifact audit = Desired(Document(auditOnly: true).Replace("\"policyVersion\": 7", "\"policyVersion\": 8", StringComparison.Ordinal));

                Assert.AreEqual(ReconciliationOutcomeKind.Applied, (await reconciler.ReconcileAsync(audit, CancellationToken.None)).Kind);

                Assert.AreEqual(2, gateway.ApplyCount);
                Assert.AreEqual(8, (await store.GetLastGoodArtifactAsync(CancellationToken.None))!.PolicyVersion);
                StringAssert.Contains(gateway.LocalPolicyXml, "EnforcementMode=\"AuditOnly\"");
            }
        }

        [TestMethod]
        public async Task Reconcile_ForeignLocalPolicy_IsConflictAndNeverWrites()
        {
            await using TemporarySqliteDatabase db = new();
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            (PolicyReconciler reconciler, FakeAppLockerGateway gateway, _, PolicyOperationGate gate) = await CreateAsync(db, clock);
            using (gate)
            {
                gateway.LocalPolicyXml = AppLockerTestData.ForeignPathRulePolicy();

                ReconciliationOutcome outcome = await reconciler.ReconcileAsync(Desired(), CancellationToken.None);

                Assert.AreEqual(ReconciliationOutcomeKind.Conflict, outcome.Kind);
                Assert.AreEqual("ExternalLocalPolicy", outcome.DiagnosticCode);
                Assert.AreEqual(0, gateway.ApplyCount);
            }
        }

        [TestMethod]
        public async Task Reconcile_ManualAppIdService_IsRejectedWithoutWriting()
        {
            await using TemporarySqliteDatabase db = new();
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            (PolicyReconciler reconciler, FakeAppLockerGateway gateway, _, PolicyOperationGate gate) = await CreateAsync(db, clock);
            using (gate)
            {
                gateway.AppIdServiceStartMode = "Manual";

                ReconciliationOutcome outcome = await reconciler.ReconcileAsync(Desired(), CancellationToken.None);

                Assert.AreEqual(ReconciliationOutcomeKind.Rejected, outcome.Kind);
                Assert.AreEqual("AppIdServiceNotReady", outcome.DiagnosticCode);
                Assert.AreEqual(0, gateway.ApplyCount);
            }
        }

        [TestMethod]
        public async Task Recover_AfterFailureFollowingWrite_ConfirmsWhatWindowsActuallyEnforces()
        {
            await using TemporarySqliteDatabase db = new();
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            (PolicyReconciler reconciler, FakeAppLockerGateway gateway, SqlitePolicyStateStore store, PolicyOperationGate gate) = await CreateAsync(db, clock);
            using (gate)
            {
                PolicyArtifact desired = Desired();
                gateway.FailAfterApply = true;
                Assert.AreEqual(ReconciliationOutcomeKind.RecoveryRequired, (await reconciler.ReconcileAsync(desired, CancellationToken.None)).Kind);

                gateway.FailAfterApply = false;
                clock.Advance(TimeSpan.FromSeconds(1));
                Assert.AreEqual(ReconciliationOutcomeKind.Applied, (await reconciler.RecoverPendingAsync(CancellationToken.None)).Kind);

                Assert.AreEqual(1, gateway.ApplyCount);
                Assert.IsNull(await store.GetPendingAttemptAsync(CancellationToken.None));
            }
        }

        [TestMethod]
        public async Task Observe_UnrecognizedPolicy_ReportsSentinelThatCannotConfirm()
        {
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            FakeAppLockerGateway gateway = new(clock) { LocalPolicyXml = AppLockerTestData.ForeignPathRulePolicy() };

            EffectivePolicyObservation observation = await new AppLockerEnforcementAdapter(gateway, clock).ObserveEffectiveAsync(CancellationToken.None);

            Assert.AreEqual(AppLockerEnforcementAdapter.UnrecognizedPolicyVersion, observation.PolicyVersion);
            Assert.AreEqual(OwnedPolicyState.Unknown, observation.ObservedOwnedState);
            Assert.AreEqual(EnforcementProtectionLevel.None, observation.ProtectionLevel);
            Assert.IsFalse(PolicyConfirmationPolicy.IsConfirmed(Desired(), observation, clock.GetUtcNow()));
        }
#pragma warning restore CA1707
    }
}
