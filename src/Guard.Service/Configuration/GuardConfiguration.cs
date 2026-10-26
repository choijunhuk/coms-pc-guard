using Guard.Core.Identity;
using Guard.Core.Policies;

namespace Guard.Service.Configuration
{
    /// <summary>A validated policy file: explicit Owner, registered Members, approved applications, and the Core policy.</summary>
    public sealed class GuardConfiguration
    {
        internal GuardConfiguration(
            string ownerSid,
            IReadOnlyList<GuardMember> members,
            IReadOnlyList<GuardApplication> applications,
            PolicyDefinition policy)
        {
            OwnerSid = ownerSid;
            Members = members;
            Applications = applications;
            Policy = policy;
        }

        public string OwnerSid { get; }

        public IReadOnlyList<GuardMember> Members { get; }

        public IReadOnlyList<GuardApplication> Applications { get; }

        public PolicyDefinition Policy { get; }
    }

    public sealed record GuardMember(string Name, string Sid);

    public sealed class GuardApplication
    {
        internal GuardApplication(string appId, string displayName, IReadOnlyList<PublisherApplicationIdentity> identities)
        {
            AppId = appId;
            DisplayName = displayName;
            Identities = identities;
        }

        public string AppId { get; }

        public string DisplayName { get; }

        public IReadOnlyList<PublisherApplicationIdentity> Identities { get; }
    }
}
