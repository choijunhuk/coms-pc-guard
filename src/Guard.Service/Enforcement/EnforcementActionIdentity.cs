using System.Globalization;
using Guard.Service.Storage;

namespace Guard.Service.Enforcement
{
    public sealed record EnforcementActionIdentity
    {
        public EnforcementActionIdentity(Guid attemptId, EnforcementActionKind actionKind, long policyVersion, string sha256Hex)
        {
            PolicyArtifact.ValidateIdentity(policyVersion, sha256Hex);
            if (attemptId == Guid.Empty)
            {
                throw new ArgumentException("An attempt identifier is required.", nameof(attemptId));
            }

            if (!Enum.IsDefined(actionKind))
            {
                throw new ArgumentOutOfRangeException(nameof(actionKind));
            }

            AttemptId = attemptId;
            ActionKind = actionKind;
            PolicyVersion = policyVersion;
            Sha256Hex = sha256Hex;
        }
        public Guid AttemptId { get; }
        public EnforcementActionKind ActionKind { get; }
        public long PolicyVersion { get; }
        public string Sha256Hex { get; }
        public string ActionId => string.Create(CultureInfo.InvariantCulture, $"{AttemptId:D}:{(int)ActionKind}:{PolicyVersion}:{Sha256Hex}");
    }
}
