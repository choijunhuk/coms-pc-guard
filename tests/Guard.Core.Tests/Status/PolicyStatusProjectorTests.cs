using Guard.Core.Policies;
using Guard.Core.Status;

namespace Guard.Core.Tests.Status
{
    [TestClass]
    public sealed class PolicyStatusProjectorTests
    {
        private static readonly DateTimeOffset NowUtc = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);
        private static readonly TimeSpan Freshness = TimeSpan.FromMinutes(5);

#pragma warning disable CA1707 // Test names use requirement terminology as a readable behavior contract.
        [TestMethod]
        [DataRow(PolicyHealth.Initializing, DisplayState.Initializing, "HEALTH_INITIALIZING")]
        [DataRow(PolicyHealth.Applying, DisplayState.Applying, "HEALTH_APPLYING")]
        [DataRow(PolicyHealth.Error, DisplayState.Error, "HEALTH_ERROR")]
        [DataRow(PolicyHealth.Degraded, DisplayState.Degraded, "HEALTH_DEGRADED")]
        public void Project_NonHealthyHealth_ProjectsHealthState(
            PolicyHealth health,
            DisplayState expectedState,
            string expectedExplanationCode)
        {
            PolicyDecision desired = Desired(PolicyDecisionKind.Restricted);

            PolicyStatus actual = Project(desired, Applied(AppliedDecisionKind.Restricted), health);

            Assert.AreEqual(expectedState, actual.DisplayState);
            Assert.AreEqual(expectedExplanationCode, actual.ExplanationCode);
            Assert.AreSame(desired, actual.Desired);
            Assert.AreEqual(health, actual.Health);
        }

        [TestMethod]
        public void Project_RestrictedWithFreshMatchingObservation_ProjectsRestricted()
        {
            PolicyDecision desired = Desired(PolicyDecisionKind.Restricted);
            AppliedObservation applied = Applied(AppliedDecisionKind.Restricted);

            PolicyStatus actual = Project(desired, applied);

            Assert.AreEqual(DisplayState.Restricted, actual.DisplayState);
            Assert.AreEqual("OBSERVED_RESTRICTED", actual.ExplanationCode);
            Assert.AreSame(applied, actual.Applied);
        }

        [TestMethod]
        [DataRow(AppliedDecisionKind.Allowed, 42L, "member-a", "app-a", "APPLIED_DECISION_MISMATCH")]
        [DataRow(AppliedDecisionKind.Unknown, 42L, "member-a", "app-a", "APPLIED_DECISION_MISMATCH")]
        [DataRow(AppliedDecisionKind.Restricted, 41L, "member-a", "app-a", "POLICY_VERSION_MISMATCH")]
        [DataRow(AppliedDecisionKind.Restricted, 42L, "member-b", "app-a", "MEMBER_SCOPE_MISMATCH")]
        [DataRow(AppliedDecisionKind.Restricted, 42L, "member-a", "app-b", "APP_SCOPE_MISMATCH")]
        public void Project_RestrictedWithoutExactMatchingObservation_Degrades(
            AppliedDecisionKind appliedDecision,
            long policyVersion,
            string memberSid,
            string appId,
            string expectedExplanationCode)
        {
            AppliedObservation applied = Applied(appliedDecision, policyVersion, memberSid, appId);

            PolicyStatus actual = Project(Desired(PolicyDecisionKind.Restricted), applied);

            Assert.AreEqual(DisplayState.Degraded, actual.DisplayState);
            Assert.AreEqual(expectedExplanationCode, actual.ExplanationCode);
        }

        [TestMethod]
        public void Project_RestrictedWithoutObservation_Degrades()
        {
            PolicyStatus actual = Project(Desired(PolicyDecisionKind.Restricted), applied: null);

            Assert.AreEqual(DisplayState.Degraded, actual.DisplayState);
            Assert.AreEqual("OBSERVATION_MISSING", actual.ExplanationCode);
        }

        [TestMethod]
        public void Project_AllowedWithFreshMatchingObservation_ProjectsAllowed()
        {
            PolicyStatus actual = Project(
                Desired(PolicyDecisionKind.Allowed),
                Applied(AppliedDecisionKind.Allowed));

            Assert.AreEqual(DisplayState.Allowed, actual.DisplayState);
            Assert.AreEqual("OBSERVED_ALLOWED", actual.ExplanationCode);
        }

        [TestMethod]
        public void Project_TemporaryAllowWithFreshAllowedObservation_ProjectsTemporaryAllow()
        {
            PolicyStatus actual = Project(
                Desired(PolicyDecisionKind.TemporaryAllow),
                Applied(AppliedDecisionKind.Allowed));

            Assert.AreEqual(DisplayState.TemporaryAllow, actual.DisplayState);
            Assert.AreEqual("TEMPORARY_ALLOW_OBSERVED", actual.ExplanationCode);
        }

        [TestMethod]
        [DataRow(PolicyDecisionKind.Allowed)]
        [DataRow(PolicyDecisionKind.TemporaryAllow)]
        public void Project_NonRestrictedDesiredWithExternalDeny_Degrades(PolicyDecisionKind desiredDecision)
        {
            PolicyStatus actual = Project(
                Desired(desiredDecision),
                Applied(AppliedDecisionKind.Allowed, externalDenyPresent: true));

            Assert.AreEqual(DisplayState.Degraded, actual.DisplayState);
            Assert.AreEqual("EXTERNAL_DENY_PRESENT", actual.ExplanationCode);
        }

        [TestMethod]
        public void Project_AuditOnlyWhenHealthy_ProjectsAuditOnlyWithoutAppliedRestrictionClaim()
        {
            PolicyStatus actual = Project(Desired(PolicyDecisionKind.AuditOnly), applied: null);

            Assert.AreEqual(DisplayState.AuditOnly, actual.DisplayState);
            Assert.AreEqual("AUDIT_ONLY", actual.ExplanationCode);
            Assert.IsNull(actual.Applied);
        }

        [TestMethod]
        public void Project_ObservationExactlyAtFreshnessLimit_IsFresh()
        {
            AppliedObservation applied = Applied(
                AppliedDecisionKind.Restricted,
                observedAtUtc: NowUtc - Freshness);

            PolicyStatus actual = Project(Desired(PolicyDecisionKind.Restricted), applied);

            Assert.AreEqual(DisplayState.Restricted, actual.DisplayState);
        }

        [TestMethod]
        public void Project_ObservationOneTickPastFreshnessLimit_IsStale()
        {
            AppliedObservation applied = Applied(
                AppliedDecisionKind.Restricted,
                observedAtUtc: NowUtc - Freshness - TimeSpan.FromTicks(1));

            PolicyStatus actual = Project(Desired(PolicyDecisionKind.Restricted), applied);

            Assert.AreEqual(DisplayState.Degraded, actual.DisplayState);
            Assert.AreEqual("OBSERVATION_STALE", actual.ExplanationCode);
        }

        [TestMethod]
        public void Project_NonPositiveFreshness_IsRejected()
        {
            PolicyStatusProjector projector = new();
            PolicyDecision desired = Desired(PolicyDecisionKind.Allowed);

            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                projector.Project(desired, null, PolicyHealth.Healthy, NowUtc, TimeSpan.Zero));
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                projector.Project(desired, null, PolicyHealth.Healthy, NowUtc, TimeSpan.FromTicks(-1)));
        }

        [TestMethod]
        public void Project_FutureObservation_IsRejected()
        {
            AppliedObservation applied = Applied(
                AppliedDecisionKind.Allowed,
                observedAtUtc: NowUtc.AddTicks(1));

            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                Project(Desired(PolicyDecisionKind.Allowed), applied));
        }
#pragma warning restore CA1707

        private static PolicyStatus Project(
            PolicyDecision desired,
            AppliedObservation? applied,
            PolicyHealth health = PolicyHealth.Healthy)
        {
            return new PolicyStatusProjector().Project(desired, applied, health, NowUtc, Freshness);
        }

        private static PolicyDecision Desired(PolicyDecisionKind decision)
        {
            return new PolicyDecision(
                decision,
                PolicyReasonCode.WeeklySchedule,
                [],
                null,
                policyVersion: 42,
                memberSid: "member-a",
                appId: "app-a");
        }

        private static AppliedObservation Applied(
            AppliedDecisionKind decision,
            long policyVersion = 42,
            string memberSid = "member-a",
            string appId = "app-a",
            bool externalDenyPresent = false,
            DateTimeOffset? observedAtUtc = null)
        {
            return new AppliedObservation(
                policyVersion,
                decision,
                observedAtUtc ?? NowUtc,
                memberSid,
                appId,
                externalDenyPresent,
                errorCode: null);
        }
    }
}
