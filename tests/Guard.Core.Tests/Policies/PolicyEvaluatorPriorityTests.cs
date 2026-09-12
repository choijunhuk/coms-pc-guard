using Guard.Core.Policies;
using Guard.Core.Schedules;
using Guard.Core.Tests.TestData;

namespace Guard.Core.Tests.Policies
{
    [TestClass]
    public sealed class PolicyEvaluatorPriorityTests
    {
        private static readonly string[] BothGrantIds = ["grant-a", "grant-z"];
        private static readonly string[] EmptyIds = [];

#pragma warning disable CA1707 // Test names state the policy contract.
        [TestMethod]
        public void Evaluate_MaintenanceOverridesEmergencyRestriction()
        {
            PolicyDecision actual = new PolicyEvaluator().Evaluate(
                CreateRestrictedPolicy() with { EmergencyRestriction = true },
                CreateRequest(maintenanceMode: true));

            Assert.AreEqual(PolicyDecisionKind.Allowed, actual.Decision);
            Assert.AreEqual(PolicyReasonCode.MaintenanceMode, actual.ReasonCode);
            CollectionAssert.AreEqual(EmptyIds, actual.MatchedRuleIds.ToArray());
            Assert.IsNull(actual.NextTransition);
        }

        [TestMethod]
        public void Evaluate_EmergencyOverridesMatchingTrustedGrant()
        {
            PolicyDecision actual = new PolicyEvaluator().Evaluate(
                CreateRestrictedPolicy() with
                {
                    EmergencyRestriction = true,
                    TemporaryGrants = [Grant("trusted", "member-a", "app-x")],
                },
                CreateRequest(memberSid: "member-a", appId: "app-x"));

            Assert.AreEqual(PolicyDecisionKind.Restricted, actual.Decision);
            Assert.AreEqual(PolicyReasonCode.EmergencyRestriction, actual.ReasonCode);
            CollectionAssert.AreEqual(EmptyIds, actual.MatchedRuleIds.ToArray());
            Assert.IsNull(actual.NextTransition);
        }

        [TestMethod]
        public void Evaluate_TrustedGrantMatchesOnlyItsMemberAndApp()
        {
            PolicyDefinition policy = CreateRestrictedPolicy() with
            {
                TemporaryGrants = [Grant("member-a-app-x", "member-a", "app-x")],
            };
            PolicyEvaluator evaluator = new();

            PolicyDecision matched = evaluator.Evaluate(policy, CreateRequest(memberSid: "member-a", appId: "app-x"));
            PolicyDecision otherMember = evaluator.Evaluate(policy, CreateRequest(memberSid: "member-b", appId: "app-x"));
            PolicyDecision otherApp = evaluator.Evaluate(policy, CreateRequest(memberSid: "member-a", appId: "app-y"));

            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, matched.Decision);
            Assert.AreEqual(PolicyReasonCode.TemporaryGrant, matched.ReasonCode);
            CollectionAssert.AreEqual(new[] { "member-a-app-x" }, matched.MatchedRuleIds.ToArray());
            Assert.AreEqual(PolicyDecisionKind.Restricted, otherMember.Decision);
            Assert.AreEqual(PolicyDecisionKind.Restricted, otherApp.Decision);
        }

        [TestMethod]
        public void Evaluate_NullMemberSidScopesGrantToAllMembersForOneApp()
        {
            PolicyDefinition policy = CreateRestrictedPolicy() with
            {
                TemporaryGrants = [Grant("all-members-app-x", null, "app-x")],
            };
            PolicyEvaluator evaluator = new();

            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, evaluator.Evaluate(policy, CreateRequest(memberSid: "member-b", appId: "app-x")).Decision);
            Assert.AreEqual(PolicyDecisionKind.Restricted, evaluator.Evaluate(policy, CreateRequest(memberSid: "member-b", appId: "app-y")).Decision);
        }

        [TestMethod]
        public void Evaluate_NullAppIdScopesGrantToAllRegisteredAppsForOneMember()
        {
            PolicyDefinition policy = CreateRestrictedPolicy() with
            {
                TemporaryGrants = [Grant("member-a-all-apps", "member-a", null)],
            };
            PolicyEvaluator evaluator = new();

            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, evaluator.Evaluate(policy, CreateRequest(memberSid: "member-a", appId: "app-y")).Decision);
            Assert.AreEqual(PolicyDecisionKind.Restricted, evaluator.Evaluate(policy, CreateRequest(memberSid: "member-b", appId: "app-y")).Decision);
            Assert.AreEqual(PolicyDecisionKind.Allowed, evaluator.Evaluate(policy, CreateRequest(memberSid: "member-a", appId: "app-y", isRegisteredApp: false)).Decision);
        }

        [TestMethod]
        public void Evaluate_GlobalGrantScopesToAllRegisteredAppsAndMembers()
        {
            PolicyDefinition policy = CreateRestrictedPolicy() with
            {
                TemporaryGrants = [Grant("global", null, null)],
            };
            PolicyEvaluator evaluator = new();

            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, evaluator.Evaluate(policy, CreateRequest(memberSid: "member-b", appId: "app-y")).Decision);
            Assert.AreEqual(PolicyDecisionKind.Allowed, evaluator.Evaluate(policy, CreateRequest(memberSid: "member-b", appId: "app-y", isRegisteredApp: false)).Decision);
        }

        [TestMethod]
        public void Evaluate_GrantUsesInclusiveIssueAndExclusiveExpiryBounds()
        {
            DateTimeOffset issued = new(2026, 9, 14, 0, 0, 0, TimeSpan.Zero);
            DateTimeOffset expires = issued.AddMinutes(30);
            PolicyDefinition policy = CreateRestrictedPolicy() with
            {
                TemporaryGrants = [new TemporaryGrant("bounded", "member-a", "app-x", issued, expires, TemporaryGrantTrust.Trusted)],
            };
            PolicyEvaluator evaluator = new();

            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, evaluator.Evaluate(policy, CreateRequest(issued, "member-a", "app-x")).Decision);
            Assert.AreEqual(PolicyDecisionKind.Restricted, evaluator.Evaluate(policy, CreateRequest(expires, "member-a", "app-x")).Decision);
        }

        [TestMethod]
        public void Evaluate_IgnoresUntrustedGrants()
        {
            PolicyDefinition policy = CreateRestrictedPolicy() with
            {
                TemporaryGrants =
                [
                    Grant("suspicious", "member-a", "app-x", TemporaryGrantTrust.SuspiciousClock),
                    Grant("revoked", "member-a", "app-x", TemporaryGrantTrust.Revoked),
                ],
            };

            PolicyDecision actual = new PolicyEvaluator().Evaluate(policy, CreateRequest(memberSid: "member-a", appId: "app-x"));

            Assert.AreEqual(PolicyDecisionKind.Restricted, actual.Decision);
            Assert.AreEqual(PolicyReasonCode.WeeklySchedule, actual.ReasonCode);
        }

        [TestMethod]
        public void Evaluate_MultipleGrantsReturnSortedIdsAndEarliestExpiry()
        {
            DateTimeOffset now = new(2026, 9, 14, 0, 0, 0, TimeSpan.Zero);
            DateTimeOffset earliestExpiry = now.AddMinutes(10);
            PolicyDefinition policy = CreateRestrictedPolicy() with
            {
                TemporaryGrants =
                [
                    new TemporaryGrant("grant-z", "member-a", "app-x", now.AddMinutes(-1), now.AddMinutes(20), TemporaryGrantTrust.Trusted),
                    new TemporaryGrant("grant-a", "member-a", "app-x", now.AddMinutes(-1), earliestExpiry, TemporaryGrantTrust.Trusted),
                ],
            };

            PolicyDecision actual = new PolicyEvaluator().Evaluate(policy, CreateRequest(now, "member-a", "app-x"));

            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, actual.Decision);
            CollectionAssert.AreEqual(BothGrantIds, actual.MatchedRuleIds.ToArray());
            Assert.AreEqual(earliestExpiry, actual.NextTransition);
        }

        [TestMethod]
        public void Evaluate_AuditOnlyProjectsRestrictionWithoutLosingDecisionMetadata()
        {
            PolicyDefinition policy = CreateRestrictedPolicy() with { EmergencyRestriction = true, AuditOnly = true };
            PolicyDecision actual = new PolicyEvaluator().Evaluate(policy, CreateRequest());

            Assert.AreEqual(PolicyDecisionKind.AuditOnly, actual.Decision);
            Assert.AreEqual(PolicyReasonCode.EmergencyRestriction, actual.ReasonCode);
            CollectionAssert.AreEqual(EmptyIds, actual.MatchedRuleIds.ToArray());
            Assert.IsNull(actual.NextTransition);
            Assert.AreEqual(PolicyTestData.DefaultPolicyVersion, actual.PolicyVersion);
        }

        [TestMethod]
        public void Evaluate_AuditOnlyProjectsWeeklyRestrictionWithoutLosingDecisionMetadata()
        {
            PolicyDefinition policy = CreateRestrictedPolicy() with { AuditOnly = true };
            PolicyDecision actual = new PolicyEvaluator().Evaluate(policy, CreateRequest());

            Assert.AreEqual(PolicyDecisionKind.AuditOnly, actual.Decision);
            Assert.AreEqual(PolicyReasonCode.WeeklySchedule, actual.ReasonCode);
            CollectionAssert.AreEqual(new[] { "weekly-mon" }, actual.MatchedRuleIds.ToArray());
            Assert.AreEqual(new DateTimeOffset(2026, 9, 14, 9, 0, 0, TimeSpan.Zero), actual.NextTransition);
            Assert.AreEqual(PolicyTestData.DefaultPolicyVersion, actual.PolicyVersion);
        }

        [TestMethod]
        public void Evaluate_RejectsInvalidOrDuplicateGrantIdsBeforeShortCircuit()
        {
            PolicyEvaluationRequest unregistered = CreateRequest(isRegisteredApp: false);

            _ = Assert.ThrowsExactly<ArgumentException>(() => new PolicyEvaluator().Evaluate(
                CreateRestrictedPolicy() with { TemporaryGrants = [Grant("", null, null)] }, unregistered));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new PolicyEvaluator().Evaluate(
                CreateRestrictedPolicy() with { TemporaryGrants = [Grant("duplicate", null, null), Grant("duplicate", "member-a", null)] }, unregistered));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new PolicyEvaluator().Evaluate(
                CreateRestrictedPolicy() with { TemporaryGrants = [new TemporaryGrant("bad-time", null, null, new DateTimeOffset(2026, 9, 14, 1, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 9, 14, 1, 0, 0, TimeSpan.Zero), TemporaryGrantTrust.Trusted)] }, unregistered));
        }

        [TestMethod]
        public void Evaluate_SnapshotsCallerOwnedGrantList()
        {
            List<TemporaryGrant> grants = [Grant("snapshot", "member-a", "app-x")];
            PolicyDefinition policy = CreateRestrictedPolicy() with { TemporaryGrants = grants };
            grants.Clear();

            PolicyDecision actual = new PolicyEvaluator().Evaluate(policy, CreateRequest());

            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, actual.Decision);
            _ = Assert.ThrowsExactly<NotSupportedException>(() => ((IList<TemporaryGrant>)policy.TemporaryGrants).Clear());
        }

        private static TemporaryGrant Grant(string id, string? memberSid, string? appId, TemporaryGrantTrust trust = TemporaryGrantTrust.Trusted)
        {
            DateTimeOffset now = new(2026, 9, 14, 0, 0, 0, TimeSpan.Zero);
            return new TemporaryGrant(id, memberSid, appId, now.AddMinutes(-1), now.AddHours(1), trust);
        }

        private static PolicyDefinition CreateRestrictedPolicy()
        {
            return PolicyTestData.CreateDefaultPolicy();
        }

        private static PolicyEvaluationRequest CreateRequest(
            DateTimeOffset? nowUtc = null,
            string memberSid = "member-a",
            string appId = "app-x",
            bool isRegisteredApp = true,
            bool maintenanceMode = false)
        {
            return new PolicyEvaluationRequest(
                nowUtc ?? new DateTimeOffset(2026, 9, 14, 0, 0, 0, TimeSpan.Zero),
                memberSid,
                appId,
                isRegisteredApp,
                maintenanceMode);
        }
#pragma warning restore CA1707
    }
}
