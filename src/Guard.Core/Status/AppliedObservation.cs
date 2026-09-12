namespace Guard.Core.Status
{
    public sealed record AppliedObservation
    {
        public AppliedObservation(
            long policyVersion,
            AppliedDecisionKind appliedDecision,
            DateTimeOffset observedAtUtc,
            string memberSid,
            string appId,
            bool externalDenyPresent,
            string? errorCode = null)
        {
            if (policyVersion <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(policyVersion), "Policy versions must be positive.");
            }

            if (string.IsNullOrWhiteSpace(memberSid))
            {
                throw new ArgumentException("Member SIDs are required.", nameof(memberSid));
            }

            if (string.IsNullOrWhiteSpace(appId))
            {
                throw new ArgumentException("App IDs are required.", nameof(appId));
            }

            PolicyVersion = policyVersion;
            AppliedDecision = appliedDecision;
            ObservedAtUtc = observedAtUtc;
            MemberSid = memberSid;
            AppId = appId;
            ExternalDenyPresent = externalDenyPresent;
            ErrorCode = errorCode;
        }

        public long PolicyVersion { get; }

        public AppliedDecisionKind AppliedDecision { get; }

        public DateTimeOffset ObservedAtUtc { get; }

        public string MemberSid { get; }

        public string AppId { get; }

        public bool ExternalDenyPresent { get; }

        public string? ErrorCode { get; }
    }
}
