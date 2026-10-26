using Guard.Core.Policies;
using Guard.Service.AppLocker;
using Guard.Service.Configuration;
using Guard.Service.Reconciliation;
using Guard.Service.Status;
using Guard.Service.Tests.TestSupport;
using static Guard.Service.Tests.Configuration.GuardPolicyDocumentReaderTests;

namespace Guard.Service.Tests.Status
{
    [TestClass]
    public sealed class GuardStatusTests
    {
        private static readonly TimeZoneInfo Korea = TimeZoneInfo.FindSystemTimeZoneById("Korea Standard Time");

        private static GuardStatusSnapshot Snapshot(string? document = null, GuardApplyStatus status = GuardApplyStatus.Applied)
        {
            GuardConfiguration configuration = GuardPolicyDocumentReader.Parse(document ?? Document());
            AppLockerPipelineResult pipeline = new AppLockerPolicyPipeline().Run(configuration, AppLockerTestData.CleanInventory(AppLockerTestData.InsideWindow), AppLockerTestData.InsideWindow);
            return GuardStatusFile.Build(configuration, new GuardApplyResult(status, null, pipeline, null), AppLockerTestData.InsideWindow);
        }

        private static GuardMemberStatus Member(PolicyDecisionKind decision, DateTimeOffset? until)
        {
            return new GuardMemberStatus(MemberA, "MemberA", [new GuardAppStatus("charmap", "문자표", decision, until)]);
        }

#pragma warning disable CA1707
        [TestMethod]
        public void Build_ListsEveryMemberWithEveryGameAndTheFileVersion()
        {
            GuardStatusSnapshot snapshot = Snapshot();

            Assert.AreEqual(GuardStatusFile.HealthOk, snapshot.Health);
            Assert.AreEqual(7, snapshot.PolicyVersion);
            Assert.HasCount(2, snapshot.Members);
            foreach (GuardMemberStatus member in snapshot.Members)
            {
                GuardAppStatus app = member.Apps.Single();
                Assert.AreEqual("charmap", app.AppId);
                Assert.AreEqual(PolicyDecisionKind.Restricted, app.Decision);
                // Monday 10:00 KST is inside the 09:00-18:00 window, so the next change is 18:00 KST.
                Assert.AreEqual(new DateTimeOffset(2026, 10, 26, 9, 0, 0, TimeSpan.Zero), app.UntilUtc);
            }
        }

        [TestMethod]
        public void Build_AuditOnlyAndFailedResults_AreExplainedInKorean()
        {
            Assert.AreEqual(GuardStatusFile.HealthAuditOnly, Snapshot(Document(auditOnly: true)).Health);
            Assert.AreEqual(GuardStatusFile.HealthFailed, Snapshot(status: GuardApplyStatus.Failed).Health);
        }

        [TestMethod]
        public void Build_WithoutDecisions_ReportsUnknownNotAllowed()
        {
            GuardConfiguration configuration = GuardPolicyDocumentReader.Parse(Document());

            GuardStatusSnapshot snapshot = GuardStatusFile.Build(configuration, new GuardApplyResult(GuardApplyStatus.RecoveryPending, null, null, null), AppLockerTestData.InsideWindow);
            GuardAppStatus app = snapshot.Members[0].Apps.Single();
            HashSet<string> warned = [];
            IReadOnlyList<string> alerts = GuardStatusMessages.Alerts(Member(PolicyDecisionKind.Restricted, null), new GuardMemberStatus(MemberA, "MemberA", [app]), AppLockerTestData.InsideWindow, Korea, warned);

            Assert.IsNull(app.Decision);
            Assert.AreEqual("문자표: 지금 상태를 확인하는 중이에요", GuardStatusMessages.Describe(app, AppLockerTestData.InsideWindow, Korea));
            Assert.IsEmpty(alerts);
        }

        [TestMethod]
        public void WriteThenTryRead_RoundTrips_AndBrokenFilesReadAsNull()
        {
            string directory = Path.Combine(Path.GetTempPath(), $"guard-status-{Guid.NewGuid():N}");
            try
            {
                string path = Path.Combine(directory, "status", "status.json");
                Assert.IsNull(GuardStatusFile.TryRead(path));

                GuardStatusSnapshot snapshot = Snapshot();
                GuardStatusFile.Write(path, snapshot);
                GuardStatusSnapshot? read = GuardStatusFile.TryRead(path);

                Assert.IsNotNull(read);
                Assert.AreEqual(snapshot.PolicyVersion, read.PolicyVersion);
                Assert.AreEqual(PolicyDecisionKind.Restricted, read.Members[0].Apps[0].Decision);
                Assert.IsEmpty(Directory.GetFiles(Path.GetDirectoryName(path)!, "*.tmp"));

                File.WriteAllText(path, "{ not json");
                Assert.IsNull(GuardStatusFile.TryRead(path));
            }
            finally
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
        }

        [TestMethod]
        public void Alerts_ReportChangesAndWarnOnceBeforeARestriction()
        {
            DateTimeOffset now = new(2026, 10, 26, 8, 56, 0, TimeSpan.Zero);
            DateTimeOffset starts = new(2026, 10, 26, 9, 0, 0, TimeSpan.Zero);
            HashSet<string> warned = [];

            IReadOnlyList<string> first = GuardStatusMessages.Alerts(null, Member(PolicyDecisionKind.Allowed, starts), now, Korea, warned);
            IReadOnlyList<string> again = GuardStatusMessages.Alerts(Member(PolicyDecisionKind.Allowed, starts), Member(PolicyDecisionKind.Allowed, starts), now.AddSeconds(15), Korea, warned);
            IReadOnlyList<string> changed = GuardStatusMessages.Alerts(Member(PolicyDecisionKind.Allowed, starts), Member(PolicyDecisionKind.Restricted, null), starts, Korea, warned);

            StringAssert.Contains(first.Single(), "4분 뒤 제한이 시작돼요");
            Assert.IsEmpty(again);
            StringAssert.Contains(changed.Single(), "지금은 제한 시간이에요");
        }

        [TestMethod]
        public void Alerts_WarnBeforeATemporaryAllowanceEnds()
        {
            DateTimeOffset now = new(2026, 10, 26, 3, 0, 0, TimeSpan.Zero);
            HashSet<string> warned = [];

            IReadOnlyList<string> alerts = GuardStatusMessages.Alerts(null, Member(PolicyDecisionKind.TemporaryAllow, now.AddMinutes(2)), now, Korea, warned);

            StringAssert.Contains(alerts.Single(), "잠깐 허용이 2분 뒤 끝나요");
        }

        [TestMethod]
        public void Describe_UsesLocalClockAndDateWhenNotToday()
        {
            DateTimeOffset now = new(2026, 10, 26, 3, 0, 0, TimeSpan.Zero);

            string today = GuardStatusMessages.Describe(new GuardAppStatus("charmap", "문자표", PolicyDecisionKind.Restricted, new DateTimeOffset(2026, 10, 26, 9, 0, 0, TimeSpan.Zero)), now, Korea);
            string tomorrow = GuardStatusMessages.Describe(new GuardAppStatus("charmap", "문자표", PolicyDecisionKind.Allowed, new DateTimeOffset(2026, 10, 27, 0, 0, 0, TimeSpan.Zero)), now, Korea);

            Assert.AreEqual("문자표: 지금은 제한 시간이에요 (18:00까지)", today);
            Assert.AreEqual("문자표: 사용할 수 있어요 (다음 제한 10월 27일 09:00)", tomorrow);
        }
#pragma warning restore CA1707
    }
}
