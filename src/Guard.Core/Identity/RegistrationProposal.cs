using System.Collections.ObjectModel;

namespace Guard.Core.Identity
{
    public sealed class RegistrationProposal
    {
        public RegistrationProposal(IEnumerable<ApplicationIdentity> proposedIdentities, IEnumerable<string> warnings)
        {
            ArgumentNullException.ThrowIfNull(proposedIdentities);
            ArgumentNullException.ThrowIfNull(warnings);

            ApplicationIdentity[] identitySnapshot = [.. proposedIdentities];
            if (identitySnapshot.Any(identity => identity is null))
            {
                throw new ArgumentException("Proposed identities cannot contain null values.", nameof(proposedIdentities));
            }

            string[] warningSnapshot = [.. warnings];
            if (warningSnapshot.Any(string.IsNullOrEmpty))
            {
                throw new ArgumentException("Warnings cannot contain null or empty values.", nameof(warnings));
            }

            ProposedIdentities = Array.AsReadOnly(identitySnapshot);
            Warnings = Array.AsReadOnly(warningSnapshot);
            RequiresOwnerConfirmation = true;
        }

        public bool RequiresOwnerConfirmation { get; }

        public ReadOnlyCollection<ApplicationIdentity> ProposedIdentities { get; }

        public ReadOnlyCollection<string> Warnings { get; }
    }
}
