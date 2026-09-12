using Guard.Core.Policies;
using Guard.Core.Tests.TestData;

namespace Guard.Core.Tests.Policies
{
    [TestClass]
    public sealed class PolicyEvaluatorPriorityTests
    {
        private static readonly DateTimeOffset RestrictedNow =
            new(2026, 9, 14, 0, 0, 0, TimeSpan.Zero);

#pragma warning disable CA1707 // Test names use requirement terminology as a readable behavior contract.
        [TestMethod]
        public void Evaluate_UnregisteredAppWithEmergency_AllowsBeforeEmergency()
        {
            PolicyDefinition policy = RestrictedPolicy() with { EmergencyRestriction = true };

            PolicyDecision actual = Evaluate(policy, memberSid: "member-a", appId: "other", isRegisteredApp: false);

            AssertDecision(actual, PolicyDecisionKind.Allowed, PolicyReasonCode.UnregisteredApp, [], null);
        }

        [TestMethod]
        public void Evaluate_MaintenanceWithEmergency_AllowsBeforeEmergency()
        {
            PolicyDefinition policy = RestrictedPolicy() with { EmergencyRestriction = true };

            PolicyDecision actual = Evaluate(policy, maintenanceMode: true);

            AssertDecision(actual, PolicyDecisionKind.Allowed, PolicyReasonCode.MaintenanceMode, [], null);
        }

        [TestMethod]
        public void Evaluate_EmergencyWithMatchingGrant_RestrictsBeforeGrant()
        {
            PolicyDefinition policy = RestrictedPolicy() with
            {
                EmergencyRestriction = true,
                TemporaryGrants = [Grant("grant-a", "member-a", "app-x")],
            };

            PolicyDecision actual = Evaluate(policy);

            AssertDecision(actual, PolicyDecisionKind.Restricted, PolicyReasonCode.EmergencyRestriction, [], null);
        }

        [TestMethod]
        public void Evaluate_MemberAndAppScopedGrant_DoesNotLeakAcrossEitherScope()
        {
            PolicyDefinition policy = RestrictedPolicy() with
            {
                TemporaryGrants = [Grant("grant-a-x", "member-a", "app-x")],
            };

            AssertDecision(
                Evaluate(policy, memberSid: "member-a", appId: "app-x"),
                PolicyDecisionKind.TemporaryAllow,
                PolicyReasonCode.TemporaryGrant,
                ["grant-a-x"],
                RestrictedNow.AddMinutes(30));
            Assert.AreEqual(PolicyDecisionKind.Restricted, Evaluate(policy, memberSid: "member-b", appId: "app-x").Decision);
            Assert.AreEqual(PolicyDecisionKind.Restricted, Evaluate(policy, memberSid: "member-a", appId: "app-y").Decision);
        }

        [TestMethod]
        public void Evaluate_NullGrantScopes_MatchAllMembersOrRegisteredAppsOnly()
        {
            PolicyDefinition memberWildcard = RestrictedPolicy() with
            {
                TemporaryGrants = [Grant("all-members", null, "app-x")],
            };
            PolicyDefinition appWildcard = RestrictedPolicy() with
            {
                TemporaryGrants = [Grant("all-apps", "member-a", null)],
            };
            PolicyDefinition global = RestrictedPolicy() with
            {
                TemporaryGrants = [Grant("global", null, null)],
            };

            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, Evaluate(memberWildcard, memberSid: "member-b").Decision);
            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, Evaluate(appWildcard, appId: "app-y").Decision);
            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, Evaluate(global, memberSid: "member-z", appId: "app-z").Decision);
            Assert.AreEqual(
                PolicyDecisionKind.Allowed,
                Evaluate(global, memberSid: "member-z", appId: "app-z", isRegisteredApp: false).Decision);
        }

        [TestMethod]
        public void Evaluate_GrantWindow_IsIssuedInclusiveAndExpiryExclusiveWithoutExtension()
        {
            TemporaryGrant grant = Grant(
                "boundary",
                "member-a",
                "app-x",
                issuedAtUtc: RestrictedNow,
                expiresAtUtc: RestrictedNow.AddMinutes(15));
            PolicyDefinition policy = RestrictedPolicy() with { TemporaryGrants = [grant] };

            PolicyDecision atIssue = Evaluate(policy, nowUtc: RestrictedNow);
            PolicyDecision beforeExpiry = Evaluate(policy, nowUtc: RestrictedNow.AddMinutes(15).AddTicks(-1));
            PolicyDecision atExpiry = Evaluate(policy, nowUtc: RestrictedNow.AddMinutes(15));

            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, atIssue.Decision);
            Assert.AreEqual(RestrictedNow.AddMinutes(15), atIssue.NextTransition);
            Assert.AreEqual(PolicyDecisionKind.TemporaryAllow, beforeExpiry.Decision);
            Assert.AreEqual(RestrictedNow.AddMinutes(15), beforeExpiry.NextTransition);
            Assert.AreEqual(PolicyDecisionKind.Restricted, atExpiry.Decision);
            Assert.AreEqual(RestrictedNow.AddMinutes(15), grant.ExpiresAtUtc);
        }

        [TestMethod]
        public void Evaluate_UntrustedGrants_AreIgnored()
        {
            PolicyDefinition policy = RestrictedPolicy() with
            {
                TemporaryGrants =
                [
                    Grant("suspicious", "member-a", "app-x", trust: TemporaryGrantTrust.SuspiciousClock),
                    Grant("revoked", "member-a", "app-x", trust: TemporaryGrantTrust.Revoked),
                ],
            };

            PolicyDecision actual = Evaluate(policy);

            AssertDecision(
                actual,
                PolicyDecisionKind.Restricted,
                PolicyReasonCode.WeeklySchedule,
                ["weekly-mon"],
                new DateTimeOffset(2026, 9, 14, 9, 0, 0, TimeSpan.Zero));
        }

        [TestMethod]
        public void Evaluate_OverlappingMatchingGrants_SkipsExpiryThatLeavesTemporaryAllowEffective()
        {
            PolicyDefinition policy = RestrictedPolicy() with
            {
                TemporaryGrants =
                [
                    Grant("zeta", "member-a", "app-x", expiresAtUtc: RestrictedNow.AddMinutes(45)),
                    Grant("alpha", null, "app-x", expiresAtUtc: RestrictedNow.AddMinutes(20)),
                ],
            };

            PolicyDecision actual = Evaluate(policy);

            AssertDecision(
                actual,
                PolicyDecisionKind.TemporaryAllow,
                PolicyReasonCode.TemporaryGrant,
                ["alpha", "zeta"],
                RestrictedNow.AddMinutes(45));
        }

        [TestMethod]
        public void Evaluate_FutureMatchingGrant_TransitionsAtIssuanceBeforeScheduleBoundary()
        {
            DateTimeOffset issuedAt = RestrictedNow.AddMinutes(15);
            DateTimeOffset expiresAt = RestrictedNow.AddMinutes(45);
            PolicyDefinition policy = RestrictedPolicy() with
            {
                TemporaryGrants =
                [
                    Grant(
                        "future",
                        "member-a",
                        "app-x",
                        issuedAtUtc: issuedAt,
                        expiresAtUtc: expiresAt),
                ],
            };

            PolicyDecision immediatelyBefore = Evaluate(policy, nowUtc: issuedAt.AddTicks(-1));
            PolicyDecision atIssuance = Evaluate(policy, nowUtc: issuedAt);

            AssertDecision(
                immediatelyBefore,
                PolicyDecisionKind.Restricted,
                PolicyReasonCode.WeeklySchedule,
                ["weekly-mon"],
                issuedAt);
            AssertDecision(
                atIssuance,
                PolicyDecisionKind.TemporaryAllow,
                PolicyReasonCode.TemporaryGrant,
                ["future"],
                expiresAt);
        }

        [TestMethod]
        public void Evaluate_GrantDrivenTransitions_AreReturnedAsUtc()
        {
            DateTimeOffset issuedAt = new(2026, 9, 14, 9, 15, 0, TimeSpan.FromHours(9));
            DateTimeOffset expiresAt = new(2026, 9, 14, 9, 45, 0, TimeSpan.FromHours(9));
            PolicyDefinition policy = RestrictedPolicy() with
            {
                TemporaryGrants =
                [
                    Grant(
                        "kst-grant",
                        "member-a",
                        "app-x",
                        issuedAtUtc: issuedAt,
                        expiresAtUtc: expiresAt),
                ],
            };

            PolicyDecision beforeIssuance = Evaluate(policy, nowUtc: issuedAt.AddTicks(-1));
            PolicyDecision atIssuance = Evaluate(policy, nowUtc: issuedAt);

            Assert.AreEqual(new DateTimeOffset(2026, 9, 14, 0, 15, 0, TimeSpan.Zero), beforeIssuance.NextTransition);
            Assert.AreEqual(TimeSpan.Zero, beforeIssuance.NextTransition?.Offset);
            Assert.AreEqual(new DateTimeOffset(2026, 9, 14, 0, 45, 0, TimeSpan.Zero), atIssuance.NextTransition);
            Assert.AreEqual(TimeSpan.Zero, atIssuance.NextTransition?.Offset);
        }

        [TestMethod]
        public void Evaluate_AuditOnlyWeeklyRestriction_RetainsScheduleMetadata()
        {
            PolicyDefinition enforced = RestrictedPolicy();
            PolicyDefinition auditOnly = enforced with { AuditOnly = true };
            PolicyDecision expectedMetadata = Evaluate(enforced);

            PolicyDecision actual = Evaluate(auditOnly);

            AssertDecision(
                actual,
                PolicyDecisionKind.AuditOnly,
                expectedMetadata.ReasonCode,
                expectedMetadata.MatchedRuleIds,
                expectedMetadata.NextTransition);
        }

        [TestMethod]
        public void Evaluate_AuditOnlyEmergency_RetainsEmergencyMetadata()
        {
            PolicyDefinition policy = RestrictedPolicy() with
            {
                EmergencyRestriction = true,
                AuditOnly = true,
            };

            PolicyDecision actual = Evaluate(policy);

            AssertDecision(actual, PolicyDecisionKind.AuditOnly, PolicyReasonCode.EmergencyRestriction, [], null);
        }

        [TestMethod]
        public void TemporaryGrant_InvalidIdentifiersOrWindow_AreRejected()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() => Grant(" ", "member-a", "app-x"));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Grant("grant", " ", "app-x"));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Grant("grant", "member-a", " "));
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                Grant("grant", "member-a", "app-x", RestrictedNow, RestrictedNow));
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                Grant("grant", "member-a", "app-x", RestrictedNow, RestrictedNow.AddTicks(-1)));
        }

        [TestMethod]
        public void Evaluate_DuplicateIdAcrossScheduleAndGrant_IsRejectedBeforeShortCircuit()
        {
            PolicyDefinition policy = RestrictedPolicy() with
            {
                TemporaryGrants = [Grant("weekly-mon", null, null)],
            };

            _ = Assert.ThrowsExactly<ArgumentException>(() =>
                Evaluate(policy, isRegisteredApp: false));
        }

        [TestMethod]
        public void Evaluate_DuplicateGrantIds_AreRejectedBeforeShortCircuit()
        {
            PolicyDefinition policy = RestrictedPolicy() with
            {
                TemporaryGrants =
                [
                    Grant("duplicate", "member-a", "app-x"),
                    Grant("duplicate", "member-b", "app-y"),
                ],
            };

            _ = Assert.ThrowsExactly<ArgumentException>(() =>
                Evaluate(policy, isRegisteredApp: false));
        }

        private static PolicyDefinition RestrictedPolicy()
        {
            return PolicyTestData.CreateDefaultPolicy();
        }

        private static TemporaryGrant Grant(
            string grantId,
            string? memberSid,
            string? appId,
            DateTimeOffset? issuedAtUtc = null,
            DateTimeOffset? expiresAtUtc = null,
            TemporaryGrantTrust trust = TemporaryGrantTrust.Trusted)
        {
            return new TemporaryGrant(
                grantId,
                memberSid,
                appId,
                issuedAtUtc ?? RestrictedNow.AddMinutes(-15),
                expiresAtUtc ?? RestrictedNow.AddMinutes(30),
                trust);
        }

        private static PolicyDecision Evaluate(
            PolicyDefinition policy,
            DateTimeOffset? nowUtc = null,
            string memberSid = "member-a",
            string appId = "app-x",
            bool isRegisteredApp = true,
            bool maintenanceMode = false)
        {
            return new PolicyEvaluator().Evaluate(
                policy,
                new PolicyEvaluationRequest(
                    nowUtc ?? RestrictedNow,
                    memberSid,
                    appId,
                    isRegisteredApp,
                    maintenanceMode));
        }

        private static void AssertDecision(
            PolicyDecision actual,
            PolicyDecisionKind decision,
            PolicyReasonCode reasonCode,
            IReadOnlyList<string> matchedIds,
            DateTimeOffset? nextTransition)
        {
            Assert.AreEqual(decision, actual.Decision);
            Assert.AreEqual(reasonCode, actual.ReasonCode);
            CollectionAssert.AreEqual(matchedIds.ToArray(), actual.MatchedRuleIds.ToArray());
            Assert.AreEqual(nextTransition, actual.NextTransition);
            Assert.AreEqual(PolicyTestData.DefaultPolicyVersion, actual.PolicyVersion);
        }
#pragma warning restore CA1707
    }
}
