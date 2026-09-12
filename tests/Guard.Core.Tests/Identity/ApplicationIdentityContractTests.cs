using System.Collections;
using System.Reflection;
using Guard.Core.Identity;

namespace Guard.Core.Tests.Identity
{
    [TestClass]
    public sealed class ApplicationIdentityContractTests
    {
        private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#pragma warning disable CA1707 // Test names use requirement terminology as a readable behavior contract.
        [TestMethod]
        public void Construct_PublisherIdentity_RequiresEveryPublisherField()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(publisher: ""));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(product: ""));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(binary: ""));
        }

        [TestMethod]
        public void Construct_VerifiedText_RejectsWhitespaceControlAndNonNfcValues()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(publisher: " CN=Games"));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(product: "Game "));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(binary: "game\u0000.exe"));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(product: "Cafe\u0301"));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Package(publisherId: "CN=Games\n"));
        }

        [TestMethod]
        public void Construct_PublisherIdentity_RejectsPathLikeBinaryNames()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(binary: @"games\game.exe"));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(binary: "games/game.exe"));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(binary: "C:game.exe"));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(binary: "game.exe:stream"));
        }

        [TestMethod]
        public void Construct_PublisherEvidence_RejectsColonContainingBinaryNames()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() => new PublisherApplicationEvidence(
                SignatureTrust.Trusted,
                "CN=Games",
                "Game",
                "C:game.exe",
                new Version(1, 0, 0, 0)));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new PublisherApplicationEvidence(
                SignatureTrust.Trusted,
                "CN=Games",
                "Game",
                "game.exe:stream",
                new Version(1, 0, 0, 0)));
        }

        [TestMethod]
        public void Construct_PublisherIdentity_RequiresFourPartBoundedVersions()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(minimumVersion: new Version(1, 2)));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Publisher(maximumVersion: new Version(1, 2, 3)));
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                Publisher(maximumVersion: new Version(65536, 0, 0, 0)));
        }

        [TestMethod]
        public void Construct_PublisherIdentity_RejectsInvertedVersionRange()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() =>
                Publisher(new Version(2, 0, 0, 0), new Version(1, 0, 0, 0)));
        }

        [TestMethod]
        public void Construct_FileHashIdentity_RequiresExactLowercaseSha256()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() => new FileHashApplicationIdentity("hash", Hash[..^1]));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new FileHashApplicationIdentity("hash", Hash.ToUpperInvariant()));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new FileHashApplicationIdentity("hash", new string('g', 64)));
        }

        [TestMethod]
        public void Construct_PackagedIdentity_RequiresEveryPackageField()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() => Package(publisherId: ""));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Package(packageFamilyName: ""));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Package(applicationUserModelId: ""));
        }

        [TestMethod]
        public void Construct_Evidence_RejectsInvalidTrustValues()
        {
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new PublisherApplicationEvidence(
                (SignatureTrust)999,
                "CN=Games",
                "Game",
                "game.exe",
                new Version(1, 0, 0, 0)));
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new PackagedApplicationEvidence(
                (PackageVerificationTrust)999,
                "CN=Games",
                "Games.Game_123",
                "Games.Game!App"));
        }

        [TestMethod]
        public void Construct_Evidence_RejectsPartialOrMalformedVerifierOutput()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() => new PublisherApplicationEvidence(
                SignatureTrust.Trusted,
                "CN=Games",
                "Game",
                "",
                new Version(1, 0, 0, 0)));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new PublisherApplicationEvidence(
                SignatureTrust.Trusted,
                "CN=Games",
                "Game",
                "game.exe",
                new Version(1, 0)));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new PackagedApplicationEvidence(
                PackageVerificationTrust.Verified,
                "CN=Games",
                "Games.Game_123",
                ""));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new FileHashApplicationEvidence(Hash.ToUpperInvariant()));
        }

        [TestMethod]
        public void Construct_ConcreteContracts_ExposeDefinedKindsAndAreSealed()
        {
            ApplicationIdentity[] identities = [Publisher(), new FileHashApplicationIdentity("hash", Hash), Package()];
            ApplicationEvidence[] evidence =
            [
                new PublisherApplicationEvidence(
                    SignatureTrust.Trusted,
                    "CN=Games",
                    "Game",
                    "game.exe",
                    new Version(1, 0, 0, 0)),
                new FileHashApplicationEvidence(Hash),
                new PackagedApplicationEvidence(
                    PackageVerificationTrust.Verified,
                    "CN=Games",
                    "Games.Game_123",
                    "Games.Game!App"),
            ];

            CollectionAssert.AreEqual(
                new[] { ApplicationIdentityKind.Publisher, ApplicationIdentityKind.FileHash, ApplicationIdentityKind.PackagedApp },
                identities.Select(identity => identity.Kind).ToArray());
            CollectionAssert.AreEqual(
                new[] { ApplicationIdentityKind.Publisher, ApplicationIdentityKind.FileHash, ApplicationIdentityKind.PackagedApp },
                evidence.Select(item => item.Kind).ToArray());
            Assert.IsFalse(Enum.IsDefined((ApplicationIdentityKind)999));
            Assert.IsTrue(identities.All(identity => identity.GetType().IsSealed));
            Assert.IsTrue(evidence.All(item => item.GetType().IsSealed));
            Assert.IsTrue(typeof(RegisteredApplication).IsSealed);
        }

        [TestMethod]
        public void Construct_AbstractContracts_RestrictDerivationToTheirAssembly()
        {
            ConstructorInfo identityConstructor = AssertSingleConstructor(typeof(ApplicationIdentity));
            ConstructorInfo evidenceConstructor = AssertSingleConstructor(typeof(ApplicationEvidence));

            Assert.IsTrue(identityConstructor.IsFamilyAndAssembly);
            Assert.IsTrue(evidenceConstructor.IsFamilyAndAssembly);
        }

        [TestMethod]
        public void Construct_RegisteredApplication_RejectsMissingApplicationData()
        {
            _ = Assert.ThrowsExactly<ArgumentException>(() => new RegisteredApplication("", "Game", [Publisher()]));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new RegisteredApplication("game", "", [Publisher()]));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new RegisteredApplication("game", "Game", []));
            _ = Assert.ThrowsExactly<ArgumentNullException>(() => new RegisteredApplication("game", "Game", null!));
        }

        [TestMethod]
        public void Construct_RegisteredApplication_RejectsNullAndDuplicateIdentities()
        {
            IReadOnlyList<ApplicationIdentity> withNull = [Publisher(), null!];
            IReadOnlyList<ApplicationIdentity> duplicates = [Publisher(identityId: "same"), Package(identityId: "same")];

            _ = Assert.ThrowsExactly<ArgumentException>(() => new RegisteredApplication("game", "Game", withNull));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new RegisteredApplication("game", "Game", duplicates));
        }

        [TestMethod]
        public void Construct_RegisteredApplication_UsesOrdinalIdentityIds()
        {
            RegisteredApplication application = new(
                "game",
                "Game",
                [Publisher(identityId: "GAME"), Package(identityId: "game")]);

            Assert.AreEqual(2, application.ApprovedIdentities.Count);
        }

        [TestMethod]
        public void Construct_RegisteredApplication_SnapshotsAndProtectsIdentityList()
        {
            List<ApplicationIdentity> callerOwned = [Publisher()];
            RegisteredApplication application = new("game", "Game", callerOwned);
            callerOwned.Clear();

            Assert.AreEqual(1, application.ApprovedIdentities.Count);
            IList output = (IList)application.ApprovedIdentities;
            _ = Assert.ThrowsExactly<NotSupportedException>(() => output.Add(Package()));
        }

        [TestMethod]
        public void Construct_ValidContracts_PreserveExactApprovedAndVerifierValues()
        {
            Version minimum = new(1, 2, 3, 4);
            Version maximum = new(5, 6, 7, 8);
            PublisherApplicationIdentity publisher = Publisher(minimum, maximum);
            FileHashApplicationIdentity hash = new("hash", Hash);
            PackagedApplicationIdentity package = Package();
            PublisherApplicationEvidence publisherEvidence = new(
                SignatureTrust.Trusted,
                "CN=Games",
                "Game",
                "game.exe",
                maximum);
            PackagedApplicationEvidence packageEvidence = new(
                PackageVerificationTrust.Verified,
                "CN=Games",
                "Games.Game_123",
                "Games.Game!App");

            Assert.AreEqual("publisher", publisher.IdentityId);
            Assert.AreEqual("CN=Games", publisher.Publisher);
            Assert.AreEqual("Game", publisher.Product);
            Assert.AreEqual("game.exe", publisher.Binary);
            Assert.AreEqual(minimum, publisher.MinimumVersion);
            Assert.AreEqual(maximum, publisher.MaximumVersion);
            Assert.AreEqual(Hash, hash.Sha256);
            Assert.AreEqual("CN=Games", package.PublisherId);
            Assert.AreEqual("Games.Game_123", package.PackageFamilyName);
            Assert.AreEqual("Games.Game!App", package.ApplicationUserModelId);
            Assert.AreEqual(SignatureTrust.Trusted, publisherEvidence.Trust);
            Assert.AreEqual(maximum, publisherEvidence.Version);
            Assert.AreEqual(PackageVerificationTrust.Verified, packageEvidence.Trust);
        }
#pragma warning restore CA1707

        private static PublisherApplicationIdentity Publisher(
            Version? minimumVersion = null,
            Version? maximumVersion = null,
            string identityId = "publisher",
            string publisher = "CN=Games",
            string product = "Game",
            string binary = "game.exe")
        {
            return new PublisherApplicationIdentity(
                identityId,
                publisher,
                product,
                binary,
                minimumVersion ?? new Version(1, 0, 0, 0),
                maximumVersion ?? new Version(2, 0, 0, 0));
        }

        private static PackagedApplicationIdentity Package(
            string identityId = "package",
            string publisherId = "CN=Games",
            string packageFamilyName = "Games.Game_123",
            string applicationUserModelId = "Games.Game!App")
        {
            return new PackagedApplicationIdentity(
                identityId,
                publisherId,
                packageFamilyName,
                applicationUserModelId);
        }

        private static ConstructorInfo AssertSingleConstructor(Type type)
        {
            ConstructorInfo[] constructors = type.GetConstructors(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            Assert.HasCount(1, constructors);
            return constructors[0];
        }
    }
}
