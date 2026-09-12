namespace Guard.Core.Identity
{
    public static class CandidateProposalFactory
    {
        public static RegistrationProposal Create(DiscoveredApplicationCandidate candidate, string proposedIdentityId)
        {
            ArgumentNullException.ThrowIfNull(candidate);

            return candidate.VerifierEvidence switch
            {
                PublisherApplicationEvidence { Trust: SignatureTrust.Trusted } evidence =>
                    new RegistrationProposal(
                        [new PublisherApplicationIdentity(proposedIdentityId, evidence.Publisher, evidence.Product, evidence.Binary, evidence.Version, evidence.Version)],
                        []),
                FileHashApplicationEvidence evidence =>
                    new RegistrationProposal([new FileHashApplicationIdentity(proposedIdentityId, evidence.Sha256)], []),
                PackagedApplicationEvidence { Trust: PackageVerificationTrust.Verified } evidence =>
                    new RegistrationProposal(
                        [new PackagedApplicationIdentity(proposedIdentityId, evidence.PublisherId, evidence.PackageFamilyName, evidence.ApplicationUserModelId)],
                        []),
                PublisherApplicationEvidence =>
                    new RegistrationProposal([], ["Publisher verification was not trusted; no identity was proposed."]),
                PackagedApplicationEvidence =>
                    new RegistrationProposal([], ["Package verification did not succeed; no identity was proposed."]),
                null =>
                    new RegistrationProposal([], ["No verified identity evidence was available; no identity was proposed."]),
                _ =>
                    new RegistrationProposal([], ["Unsupported verifier evidence was supplied; no identity was proposed."]),
            };
        }
    }
}
