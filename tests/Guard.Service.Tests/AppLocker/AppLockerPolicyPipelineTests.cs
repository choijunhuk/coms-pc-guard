using System.Xml.Linq;
using Guard.Core.Policies;
using Guard.Service.AppLocker;
using Guard.Service.Configuration;
using static Guard.Service.Tests.Configuration.GuardPolicyDocumentReaderTests;

namespace Guard.Service.Tests.AppLocker
{
    [TestClass]
    public sealed class AppLockerPolicyPipelineTests
    {
        // Monday 2026-10-26 10:00 KST is inside the 09:00-18:00 weekday window.
        private static readonly DateTimeOffset InsideWindow = new(2026, 10, 26, 1, 0, 0, TimeSpan.Zero);

        // Monday 2026-10-26 19:00 KST is after the window; Tuesday 09:00 KST is the next start.
        private static readonly DateTimeOffset AfterWindow = new(2026, 10, 26, 10, 0, 0, TimeSpan.Zero);

        private static AppLockerInventorySnapshot CleanInventory(DateTimeOffset now, AppLockerPolicyPresence local = AppLockerPolicyPresence.Absent)
        {
            return new AppLockerInventorySnapshot(
                now,
                "rev-1",
                local,
                AppLockerPolicyPresence.Absent,
                AppLockerPolicyPresence.Absent,
                AppLockerPolicyPresence.Absent,
                appIdServiceRunning: true,
                appIdServiceAutomatic: true,
                []);
        }

        private static AppLockerPipelineResult Run(string json, DateTimeOffset now, AppLockerPolicyPresence local = AppLockerPolicyPresence.Absent)
        {
            return new AppLockerPolicyPipeline().Run(GuardPolicyDocumentReader.Parse(json), CleanInventory(now, local), now);
        }

        private static XElement[] DenyRules(string xml)
        {
            return [.. XDocument.Parse(xml).Descendants("FilePublisherRule").Where(rule => (string?)rule.Attribute("Action") == "Deny")];
        }

#pragma warning disable CA1707
        [TestMethod]
        public void Run_InsideWindow_DeniesEveryMemberForEveryIdentity()
        {
            AppLockerPipelineResult result = Run(Document(), InsideWindow);

            Assert.IsTrue(result.Decisions.All(decision => decision.Decision == PolicyDecisionKind.Restricted));
            Assert.IsNotNull(result.PolicyXml);
            XElement collection = XDocument.Parse(result.PolicyXml).Descendants("RuleCollection").Single(element => (string?)element.Attribute("Type") == "Exe");
            Assert.AreEqual("Enabled", (string?)collection.Attribute("EnforcementMode"));
            CollectionAssert.AreEquivalent(
                new[] { MemberA, MemberB },
                DenyRules(result.PolicyXml).Select(rule => (string?)rule.Attribute("UserOrGroupSid")).ToArray());
            Assert.AreEqual(1, collection.Elements("FilePathRule").Count());
            Assert.AreEqual(new DateTimeOffset(2026, 10, 26, 9, 0, 0, TimeSpan.Zero), result.NextTransitionUtc);
        }

        [TestMethod]
        public void Run_ActiveGrant_RemovesOnlyThatMembersDeny()
        {
            string json = Document(grants: $$"""[{ "id": "g1", "memberSid": "{{MemberA}}", "issuedAtUtc": "2026-10-26T00:30:00Z", "expiresAtUtc": "2026-10-26T01:30:00Z" }]""");

            AppLockerPipelineResult result = Run(json, InsideWindow);

            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, result.Decisions.Single(decision => decision.MemberSid == MemberA).Decision);
            Assert.AreEqual(PolicyDecisionKind.Restricted, result.Decisions.Single(decision => decision.MemberSid == MemberB).Decision);
            Assert.IsNotNull(result.PolicyXml);
            Assert.AreEqual(MemberB, (string?)DenyRules(result.PolicyXml).Single().Attribute("UserOrGroupSid"));
            Assert.AreEqual(new DateTimeOffset(2026, 10, 26, 1, 30, 0, TimeSpan.Zero), result.NextTransitionUtc);
        }

        [TestMethod]
        public void Run_AuditOnly_KeepsDenyRulesInAuditOnlyCollection()
        {
            AppLockerPipelineResult result = Run(Document(auditOnly: true), InsideWindow);

            Assert.IsTrue(result.Decisions.All(decision => decision.Decision == PolicyDecisionKind.AuditOnly));
            Assert.IsNotNull(result.PolicyXml);
            Assert.AreEqual("AuditOnly", (string?)XDocument.Parse(result.PolicyXml).Descendants("RuleCollection").Single(element => (string?)element.Attribute("Type") == "Exe").Attribute("EnforcementMode"));
            Assert.AreEqual(2, DenyRules(result.PolicyXml).Length);
        }

        [TestMethod]
        public void Run_AfterWindow_EmitsBaselineOnlyAndNextStart()
        {
            AppLockerPipelineResult result = Run(Document(), AfterWindow);

            Assert.IsTrue(result.Decisions.All(decision => decision.Decision == PolicyDecisionKind.Allowed));
            Assert.IsNotNull(result.PolicyXml);
            Assert.AreEqual(0, DenyRules(result.PolicyXml).Length);
            Assert.AreEqual(new DateTimeOffset(2026, 10, 27, 0, 0, 0, TimeSpan.Zero), result.NextTransitionUtc);
        }

        [TestMethod]
        public void Run_ExternalLocalPolicy_ProducesNoXml()
        {
            AppLockerPipelineResult result = Run(Document(), InsideWindow, AppLockerPolicyPresence.External);

            Assert.IsNull(result.PolicyXml);
            CollectionAssert.Contains(result.Preview.Blockers.ToArray(), AppLockerPreviewBlocker.UnsafeInventory);
        }
#pragma warning restore CA1707
    }
}
