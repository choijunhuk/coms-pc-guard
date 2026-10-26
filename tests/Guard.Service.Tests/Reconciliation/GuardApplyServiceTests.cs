using Guard.Service.AppLocker;
using Guard.Service.Configuration;
using Guard.Service.Enforcement;
using Guard.Service.Reconciliation;
using Guard.Service.Storage;
using Guard.Service.Tests.TestSupport;
using static Guard.Service.Tests.Configuration.GuardPolicyDocumentReaderTests;

namespace Guard.Service.Tests.Reconciliation
{
    [TestClass]
    public sealed class GuardApplyServiceTests
    {
        private static GuardConfiguration Configuration(string? document = null)
        {
            return GuardPolicyDocumentReader.Parse(document ?? Document());
        }

        private static async Task<(GuardApplyService Service, FakeAppLockerGateway Gateway, SqlitePolicyStateStore Store, PolicyOperationGate Gate)> CreateAsync(TemporarySqliteDatabase db, ManualTimeProvider clock)
        {
            SqlitePolicyStateStore store = new(new(new(db.DatabasePath)));
            await store.InitializeAsync(CancellationToken.None);
            FakeAppLockerGateway gateway = new(clock);
            PolicyOperationGate gate = new();
            return (new GuardApplyService(gateway, store, clock, gate), gateway, store, gate);
        }

#pragma warning disable CA1707
        [TestMethod]
        public async Task Apply_TwiceOnACleanMachine_WritesOnceAtRevisionOne()
        {
            await using TemporarySqliteDatabase db = new();
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            (GuardApplyService service, FakeAppLockerGateway gateway, _, PolicyOperationGate gate) = await CreateAsync(db, clock);
            using (gate)
            {
                GuardApplyResult first = await service.ApplyAsync(Configuration(), CancellationToken.None);
                clock.Advance(TimeSpan.FromSeconds(30));
                GuardApplyResult second = await service.ApplyAsync(Configuration(), CancellationToken.None);

                Assert.AreEqual(GuardApplyStatus.Applied, first.Status);
                Assert.AreEqual(1, first.Artifact!.PolicyVersion);
                Assert.AreEqual(GuardApplyStatus.Unchanged, second.Status);
                Assert.AreEqual(1, gateway.ApplyCount);
            }
        }

        [TestMethod]
        public async Task Apply_GrantChangesTheRules_UsesTheNextRevision()
        {
            await using TemporarySqliteDatabase db = new();
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            (GuardApplyService service, FakeAppLockerGateway gateway, SqlitePolicyStateStore store, PolicyOperationGate gate) = await CreateAsync(db, clock);
            using (gate)
            {
                _ = await service.ApplyAsync(Configuration(), CancellationToken.None);
                string granted = Document(grants: $$"""[{ "id": "g1", "memberSid": "{{MemberA}}", "issuedAtUtc": "2026-10-26T00:30:00Z", "expiresAtUtc": "2026-10-26T03:00:00Z" }]""");

                GuardApplyResult result = await service.ApplyAsync(Configuration(granted), CancellationToken.None);

                Assert.AreEqual(GuardApplyStatus.Applied, result.Status);
                Assert.AreEqual(2, result.Artifact!.PolicyVersion);
                Assert.AreEqual(2, result.Artifact.Rules.Count);
                Assert.AreEqual(2, (await store.GetLastGoodArtifactAsync(CancellationToken.None))!.PolicyVersion);
                Assert.AreEqual(2, gateway.ApplyCount);
            }
        }

        [TestMethod]
        public async Task Apply_AfterSomeoneClearedThePolicy_ReappliesTheSameRevision()
        {
            await using TemporarySqliteDatabase db = new();
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            (GuardApplyService service, FakeAppLockerGateway gateway, _, PolicyOperationGate gate) = await CreateAsync(db, clock);
            using (gate)
            {
                _ = await service.ApplyAsync(Configuration(), CancellationToken.None);
                gateway.LocalPolicyXml = AppLockerTestData.EmptyWindowsPolicy();
                clock.Advance(TimeSpan.FromSeconds(30));

                GuardApplyResult result = await service.ApplyAsync(Configuration(), CancellationToken.None);

                Assert.AreEqual(GuardApplyStatus.Applied, result.Status, result.Outcome?.DiagnosticCode);
                Assert.AreEqual(1, result.Artifact!.PolicyVersion);
                Assert.AreEqual(2, gateway.ApplyCount);
            }
        }

        [TestMethod]
        public async Task Apply_AfterUpgradeFromAnExeOnlyRelease_ReplacesThePolicySoPackagedAppsRun()
        {
            await using TemporarySqliteDatabase db = new();
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            (GuardApplyService service, FakeAppLockerGateway gateway, SqlitePolicyStateStore store, PolicyOperationGate gate) = await CreateAsync(db, clock);
            using (gate)
            {
                // What an earlier release left behind: an EXE-only local policy and the same revision stored as last good.
                string legacyXml = AppLockerTestData.AsWindowsReports(AppLockerTestData.WithoutPackagedApps(AppLockerTestData.Artifact().Xml));
                Assert.IsTrue(AppLockerArtifact.TryFromObserved(ObservedAppLockerPolicy.Parse(legacyXml), out AppLockerArtifact? legacy, out _));
                DateTimeOffset now = clock.GetUtcNow();
                ReconciliationAttempt attempt = new(Guid.NewGuid(), legacy!.PolicyVersion, legacy.Sha256Hex, now);
                await store.SaveCandidateAndBeginAttemptAsync(legacy.ToPolicyArtifact(now), attempt, CancellationToken.None);
                await store.CommitObservedSuccessAsync(attempt.AttemptId, new EffectivePolicyObservation(Guid.NewGuid(), legacy.PolicyVersion, legacy.Sha256Hex, now, legacy.RequiredProtection, OwnedPolicyState.Present, false, "{}"), now, CancellationToken.None);
                gateway.LocalPolicyXml = legacyXml;

                GuardApplyResult result = await service.ApplyAsync(Configuration(), CancellationToken.None);

                Assert.AreEqual(GuardApplyStatus.Applied, result.Status, result.Outcome?.DiagnosticCode);
                Assert.IsTrue(result.Artifact!.AllowsPackagedApps);
                Assert.AreEqual(legacy.PolicyVersion + 1, result.Artifact.PolicyVersion);
                StringAssert.Contains(gateway.LocalPolicyXml, "<RuleCollection Type=\"Appx\" EnforcementMode=\"Enabled\"><FilePublisherRule");
                Assert.AreEqual(result.Artifact.Sha256Hex, (await store.GetLastGoodArtifactAsync(CancellationToken.None))!.Sha256Hex);
            }
        }

        [TestMethod]
        public async Task Apply_ForeignLocalPolicy_StopsBeforeAnyWrite()
        {
            await using TemporarySqliteDatabase db = new();
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            (GuardApplyService service, FakeAppLockerGateway gateway, _, PolicyOperationGate gate) = await CreateAsync(db, clock);
            using (gate)
            {
                gateway.LocalPolicyXml = AppLockerTestData.ForeignPathRulePolicy();

                GuardApplyResult result = await service.ApplyAsync(Configuration(), CancellationToken.None);

                Assert.AreEqual(GuardApplyStatus.Blocked, result.Status);
                Assert.IsNull(result.Artifact);
                Assert.AreEqual(0, gateway.ApplyCount);
            }
        }

        [TestMethod]
        public async Task Apply_MdmAppLockerPolicy_IsBlocked()
        {
            await using TemporarySqliteDatabase db = new();
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            (GuardApplyService service, FakeAppLockerGateway gateway, _, PolicyOperationGate gate) = await CreateAsync(db, clock);
            using (gate)
            {
                gateway.MdmPresent = true;

                GuardApplyResult result = await service.ApplyAsync(Configuration(), CancellationToken.None);

                Assert.AreEqual(GuardApplyStatus.Blocked, result.Status);
                Assert.AreEqual(0, gateway.ApplyCount);
            }
        }

        [TestMethod]
        public async Task Apply_FailureAfterWrite_ReportsFailedThenRecoversNextPass()
        {
            await using TemporarySqliteDatabase db = new();
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            (GuardApplyService service, FakeAppLockerGateway gateway, _, PolicyOperationGate gate) = await CreateAsync(db, clock);
            using (gate)
            {
                gateway.FailAfterApply = true;
                GuardApplyResult failed = await service.ApplyAsync(Configuration(), CancellationToken.None);

                gateway.FailAfterApply = false;
                clock.Advance(TimeSpan.FromSeconds(15));
                GuardApplyResult next = await service.ApplyAsync(Configuration(), CancellationToken.None);

                Assert.AreEqual(GuardApplyStatus.Failed, failed.Status);
                Assert.AreEqual(GuardApplyStatus.Unchanged, next.Status);
                Assert.AreEqual(1, gateway.ApplyCount);
            }
        }
#pragma warning restore CA1707
    }
}
