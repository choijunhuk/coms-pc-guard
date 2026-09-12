using System.Collections;
using Guard.Core.Identity;

namespace Guard.Core.Tests.Identity
{
    [TestClass]
    public sealed class ApplicationIdentityWorkflowTests
    {
        private const string HashA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private const string HashB = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private static readonly string[] FirstIdentityId = ["first"];
        private static readonly string[] SecondIdentityId = ["second"];
        private static readonly string[] HashAIdentityId = ["hash-a"];
        private static readonly string[] HashBIdentityId = ["hash-b"];
        private static readonly string[] PackageBIdentityId = ["package-b"];
        private static readonly string[] OrderedConstructorIdentityIds = ["a", "z"];

#pragma warning disable CA1707 // Test names use requirement terminology as a readable behavior contract.
        [TestMethod]
        public void Create_RawDiscoveryMetadata_RequiresOwnerConfirmationAndProposesNoIdentity()
        {
            DiscoveredApplicationCandidate candidate = new(@"C:\\Games\\game.exe", "game.exe", "Game", "Games Inc.");

            RegistrationProposal proposal = CandidateProposalFactory.Create(candidate, "discovered");

            Assert.IsTrue(proposal.RequiresOwnerConfirmation);
            Assert.HasCount(0, proposal.ProposedIdentities);
        }

        [TestMethod]
        public void Create_TrustedPublisherEvidence_ProposesOnlyTheExactEvidenceDerivedIdentity()
        {
            PublisherApplicationEvidence evidence = PublisherEvidence(version: new Version(1, 2, 3, 4));

            RegistrationProposal proposal = CandidateProposalFactory.Create(Candidate(evidence), "publisher");

            Assert.IsTrue(proposal.RequiresOwnerConfirmation);
            Assert.HasCount(1, proposal.ProposedIdentities);
            PublisherApplicationIdentity identity = (PublisherApplicationIdentity)proposal.ProposedIdentities[0];
            Assert.AreEqual("publisher", identity.IdentityId);
            Assert.AreEqual(evidence.Publisher, identity.Publisher);
            Assert.AreEqual(evidence.Product, identity.Product);
            Assert.AreEqual(evidence.Binary, identity.Binary);
            Assert.AreEqual(evidence.Version, identity.MinimumVersion);
            Assert.AreEqual(evidence.Version, identity.MaximumVersion);
        }

        [TestMethod]
        public void Create_HashEvidence_ProposesOnlyTheExactEvidenceDerivedIdentity()
        {
            FileHashApplicationEvidence evidence = new(HashA);

            RegistrationProposal proposal = CandidateProposalFactory.Create(Candidate(evidence), "hash");

            Assert.IsTrue(proposal.RequiresOwnerConfirmation);
            Assert.HasCount(1, proposal.ProposedIdentities);
            FileHashApplicationIdentity identity = (FileHashApplicationIdentity)proposal.ProposedIdentities[0];
            Assert.AreEqual("hash", identity.IdentityId);
            Assert.AreEqual(evidence.Sha256, identity.Sha256);
        }

        [TestMethod]
        public void Create_VerifiedPackageEvidence_ProposesOnlyTheExactEvidenceDerivedIdentity()
        {
            PackagedApplicationEvidence evidence = PackageEvidence();

            RegistrationProposal proposal = CandidateProposalFactory.Create(Candidate(evidence), "package");

            Assert.IsTrue(proposal.RequiresOwnerConfirmation);
            Assert.HasCount(1, proposal.ProposedIdentities);
            PackagedApplicationIdentity identity = (PackagedApplicationIdentity)proposal.ProposedIdentities[0];
            Assert.AreEqual("package", identity.IdentityId);
            Assert.AreEqual(evidence.PublisherId, identity.PublisherId);
            Assert.AreEqual(evidence.PackageFamilyName, identity.PackageFamilyName);
            Assert.AreEqual(evidence.ApplicationUserModelId, identity.ApplicationUserModelId);
        }

        [TestMethod]
        public void Construct_RegistrationProposal_SnapshotsInputsAndProtectsOutputCollections()
        {
            List<ApplicationIdentity> identities = [new FileHashApplicationIdentity("hash", HashA)];
            List<string> warnings = ["warning"];

            RegistrationProposal proposal = new(identities, warnings);
            identities.Clear();
            warnings.Clear();

            Assert.HasCount(1, proposal.ProposedIdentities);
            Assert.HasCount(1, proposal.Warnings);
            _ = Assert.ThrowsExactly<NotSupportedException>(() => ((IList)proposal.ProposedIdentities).Add(new FileHashApplicationIdentity("other", HashB)));
            _ = Assert.ThrowsExactly<NotSupportedException>(() => ((IList)proposal.Warnings).Add("other"));
        }

        [TestMethod]
        public void Construct_RegistrationProposal_RejectsInvalidCollectionElements()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() => new RegistrationProposal([null!], []));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new RegistrationProposal([], [null!]));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new RegistrationProposal([], [""]));
        }

        [TestMethod]
        public void Construct_IdentityRevalidationResult_RejectsInvalidOrContradictoryState()
        {
            ApplicationEvidence evidence = new FileHashApplicationEvidence(HashA);

            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new IdentityRevalidationResult((IdentityRevalidationStatus)999, ApplicationMatchReason.Matched, ["matched"], evidence));
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new IdentityRevalidationResult(IdentityRevalidationStatus.StillApproved, (ApplicationMatchReason)999, ["matched"], evidence));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new IdentityRevalidationResult(IdentityRevalidationStatus.StillApproved, ApplicationMatchReason.NoApprovedIdentityMatched, ["matched"], evidence));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new IdentityRevalidationResult(IdentityRevalidationStatus.RequiresOwnerReview, ApplicationMatchReason.Matched, [], evidence));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new IdentityRevalidationResult(IdentityRevalidationStatus.StillApproved, ApplicationMatchReason.Matched, [], evidence));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new IdentityRevalidationResult(IdentityRevalidationStatus.RequiresOwnerReview, ApplicationMatchReason.NoApprovedIdentityMatched, ["matched"], evidence));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new IdentityRevalidationResult(IdentityRevalidationStatus.StillApproved, ApplicationMatchReason.Matched, [null!], evidence));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new IdentityRevalidationResult(IdentityRevalidationStatus.StillApproved, ApplicationMatchReason.Matched, [""], evidence));
        }

        [TestMethod]
        public void Construct_IdentityRevalidationResult_NormalizesAndSnapshotsIdentityIds()
        {
            List<string> identityIds = ["z", "a", "z"];

            IdentityRevalidationResult result = new(
                IdentityRevalidationStatus.StillApproved,
                ApplicationMatchReason.Matched,
                identityIds,
                new FileHashApplicationEvidence(HashA));
            identityIds.Clear();

            CollectionAssert.AreEqual(OrderedConstructorIdentityIds, result.MatchedIdentityIds.ToArray());
            _ = Assert.ThrowsExactly<NotSupportedException>(() => ((IList)result.MatchedIdentityIds).Add("other"));
        }

        [TestMethod]
        public void Create_UntrustedPublisherAndFailedPackageEvidence_ProduceWarningsWithoutProposals()
        {
            RegistrationProposal untrusted = CandidateProposalFactory.Create(Candidate(PublisherEvidence(trust: SignatureTrust.Untrusted)), "publisher");
            RegistrationProposal missing = CandidateProposalFactory.Create(Candidate(PublisherEvidence(trust: SignatureTrust.Missing)), "publisher");
            RegistrationProposal failed = CandidateProposalFactory.Create(Candidate(PackageEvidence(PackageVerificationTrust.Failed)), "package");

            Assert.HasCount(0, untrusted.ProposedIdentities);
            Assert.HasCount(0, missing.ProposedIdentities);
            Assert.HasCount(0, failed.ProposedIdentities);
            Assert.IsTrue(untrusted.Warnings.Count > 0);
            Assert.IsTrue(missing.Warnings.Count > 0);
            Assert.IsTrue(failed.Warnings.Count > 0);
        }

        [TestMethod]
        public void Revalidate_PublisherEvidence_UsesTheCompleteApprovedOrSet()
        {
            RegisteredApplication application = Registered(
                Publisher("first", "CN=First", new Version(1, 0, 0, 0), new Version(1, 9, 9, 9)),
                Publisher("second", "CN=Second", new Version(2, 0, 0, 0), new Version(2, 9, 9, 9)));

            IdentityRevalidationResult rangeMatch = ApplicationIdentityRevalidator.Revalidate(application, PublisherEvidence("CN=First", new Version(1, 2, 0, 0)));
            IdentityRevalidationResult secondIdentityMatch = ApplicationIdentityRevalidator.Revalidate(application, PublisherEvidence("CN=Second", new Version(2, 1, 0, 0)));
            IdentityRevalidationResult unknown = ApplicationIdentityRevalidator.Revalidate(application, PublisherEvidence("CN=Other", new Version(1, 2, 0, 0)));
            IdentityRevalidationResult untrusted = ApplicationIdentityRevalidator.Revalidate(application, PublisherEvidence("CN=First", new Version(1, 2, 0, 0), SignatureTrust.Untrusted));
            IdentityRevalidationResult outOfRange = ApplicationIdentityRevalidator.Revalidate(application, PublisherEvidence("CN=First", new Version(3, 0, 0, 0)));

            Assert.AreEqual(IdentityRevalidationStatus.StillApproved, rangeMatch.Status);
            CollectionAssert.AreEqual(FirstIdentityId, rangeMatch.MatchedIdentityIds.ToArray());
            Assert.AreEqual(IdentityRevalidationStatus.StillApproved, secondIdentityMatch.Status);
            CollectionAssert.AreEqual(SecondIdentityId, secondIdentityMatch.MatchedIdentityIds.ToArray());
            Assert.AreEqual(IdentityRevalidationStatus.RequiresOwnerReview, unknown.Status);
            Assert.AreEqual(IdentityRevalidationStatus.RequiresOwnerReview, untrusted.Status);
            Assert.AreEqual(IdentityRevalidationStatus.RequiresOwnerReview, outOfRange.Status);
        }

        [TestMethod]
        public void Revalidate_HashChangeToSeparatelyApprovedHash_RemainsApprovedButUnknownHashRequiresReview()
        {
            RegisteredApplication application = Registered(new FileHashApplicationIdentity("hash-a", HashA), new FileHashApplicationIdentity("hash-b", HashB));

            IdentityRevalidationResult unchanged = ApplicationIdentityRevalidator.Revalidate(application, new FileHashApplicationEvidence(HashA));
            IdentityRevalidationResult approvedChange = ApplicationIdentityRevalidator.Revalidate(application, new FileHashApplicationEvidence(HashB));
            IdentityRevalidationResult unknownChange = ApplicationIdentityRevalidator.Revalidate(application, new FileHashApplicationEvidence("2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));

            Assert.AreEqual(IdentityRevalidationStatus.StillApproved, unchanged.Status);
            CollectionAssert.AreEqual(HashAIdentityId, unchanged.MatchedIdentityIds.ToArray());
            Assert.AreEqual(IdentityRevalidationStatus.StillApproved, approvedChange.Status);
            CollectionAssert.AreEqual(HashBIdentityId, approvedChange.MatchedIdentityIds.ToArray());
            Assert.AreEqual(IdentityRevalidationStatus.RequiresOwnerReview, unknownChange.Status);
            Assert.HasCount(0, unknownChange.MatchedIdentityIds);
        }

        [TestMethod]
        public void Revalidate_PackageFieldChange_RequiresReviewUnlessAnotherApprovedPackageMatchesAllFields()
        {
            RegisteredApplication application = Registered(
                Package("package-a", "Games.Game_123", "Games.Game!App"),
                Package("package-b", "Games.Game_123", "Games.Game!Other"));

            IdentityRevalidationResult secondMatch = ApplicationIdentityRevalidator.Revalidate(application, PackageEvidence(applicationUserModelId: "Games.Game!Other"));
            IdentityRevalidationResult unknown = ApplicationIdentityRevalidator.Revalidate(application, PackageEvidence(packageFamilyName: "Games.Other_123"));

            Assert.AreEqual(IdentityRevalidationStatus.StillApproved, secondMatch.Status);
            CollectionAssert.AreEqual(PackageBIdentityId, secondMatch.MatchedIdentityIds.ToArray());
            Assert.AreEqual(IdentityRevalidationStatus.RequiresOwnerReview, unknown.Status);
        }

        [TestMethod]
        public void Revalidate_ResultAndInputCollectionsCannotMutateTheRegisteredApplication()
        {
            List<ApplicationIdentity> identities = [new FileHashApplicationIdentity("hash-a", HashA), new FileHashApplicationIdentity("hash-b", HashB)];
            RegisteredApplication application = new("game", "Game", identities);
            IdentityRevalidationResult result = ApplicationIdentityRevalidator.Revalidate(application, new FileHashApplicationEvidence(HashA));

            identities.Clear();
            _ = Assert.ThrowsExactly<NotSupportedException>(() => ((IList)result.MatchedIdentityIds).Add("other"));

            Assert.AreEqual(2, application.ApprovedIdentities.Count);
            CollectionAssert.AreEqual(HashAIdentityId, result.MatchedIdentityIds.ToArray());
            FileHashApplicationEvidence actualEvidence = Assert.IsInstanceOfType<FileHashApplicationEvidence>(result.NewEvidence);
            Assert.AreEqual(HashA, actualEvidence.Sha256);
        }
#pragma warning restore CA1707

        private static DiscoveredApplicationCandidate Candidate(ApplicationEvidence? evidence = null)
        {
            return new(@"C:\\Games\\game.exe", "game.exe", "Game", "Games Inc.", evidence);
        }

        private static RegisteredApplication Registered(params ApplicationIdentity[] identities)
        {
            return new("game", "Game", identities);
        }

        private static PublisherApplicationIdentity Publisher(string identityId, string publisher, Version minimumVersion, Version maximumVersion)
        {
            return new(identityId, publisher, "Game", "game.exe", minimumVersion, maximumVersion);
        }

        private static PublisherApplicationEvidence PublisherEvidence(
            string publisher = "CN=Games",
            Version? version = null,
            SignatureTrust trust = SignatureTrust.Trusted)
        {
            return new(trust, publisher, "Game", "game.exe", version ?? new Version(1, 0, 0, 0));
        }

        private static PackagedApplicationIdentity Package(string identityId, string packageFamilyName, string applicationUserModelId)
        {
            return new(identityId, "CN=Games", packageFamilyName, applicationUserModelId);
        }

        private static PackagedApplicationEvidence PackageEvidence(
            PackageVerificationTrust trust = PackageVerificationTrust.Verified,
            string packageFamilyName = "Games.Game_123",
            string applicationUserModelId = "Games.Game!App")
        {
            return new(trust, "CN=Games", packageFamilyName, applicationUserModelId);
        }
    }
}
