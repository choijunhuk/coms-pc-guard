using System.Collections.ObjectModel;

namespace Guard.Core.Identity
{
    public sealed class RegistrationProposal
    {
        public RegistrationProposal(IEnumerable<ApplicationIdentity> proposedIdentities, IEnumerable<string> warnings)
        {
            ArgumentNullException.ThrowIfNull(proposedIdentities);
            ArgumentNullException.ThrowIfNull(warnings);

            ProposedIdentities = Array.AsReadOnly([.. proposedIdentities]);
            Warnings = Array.AsReadOnly([.. warnings]);
            RequiresOwnerConfirmation = true;
        }

        public bool RequiresOwnerConfirmation { get; }

        public ReadOnlyCollection<ApplicationIdentity> ProposedIdentities { get; }

        public ReadOnlyCollection<string> Warnings { get; }
    }
}
