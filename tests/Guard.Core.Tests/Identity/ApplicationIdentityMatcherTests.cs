using System.Globalization;
using Guard.Core.Identity;

namespace Guard.Core.Tests.Identity
{
    [TestClass]
    public sealed class ApplicationIdentityMatcherTests
    {
        private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private static readonly string[] OrderedHashIdentityIds = ["a-hash", "z-hash"];
        private static readonly string[] OrderedConstructorIdentityIds = ["a", "z"];

#pragma warning disable CA1707 // Test names use requirement terminology as a readable behavior contract.
        [TestMethod]
        public void Match_PublisherEvidence_RequiresTrustedCompleteEvidenceAndInclusiveVersionRange()
        {
            RegisteredApplication application = Registered(Publisher(minimumVersion: new Version(1, 2, 3, 4), maximumVersion: new Version(2, 3, 4, 5)));
            Assert.IsTrue(ApplicationIdentityMatcher.Match(application, PublisherEvidence(version: new Version(1, 2, 3, 4))).IsMatch);
            Assert.IsTrue(ApplicationIdentityMatcher.Match(application, PublisherEvidence(version: new Version(2, 3, 4, 5))).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(application, PublisherEvidence(publisher: "CN=Other", version: new Version(1, 2, 3, 4))).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(application, PublisherEvidence(product: "Other", version: new Version(1, 2, 3, 4))).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(application, PublisherEvidence(binary: "other.exe", version: new Version(1, 2, 3, 4))).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(application, PublisherEvidence(trust: SignatureTrust.Missing, version: new Version(1, 2, 3, 4))).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(application, PublisherEvidence(trust: SignatureTrust.Untrusted, version: new Version(1, 2, 3, 4))).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(application, PublisherEvidence(version: new Version(1, 2, 3, 3))).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(application, PublisherEvidence(version: new Version(2, 3, 4, 6))).IsMatch);
        }

        [TestMethod]
        public void Match_PublisherAndPackageText_UsesOrdinalIgnoreCaseIndependentOfCurrentCulture()
        {
            CultureInfo originalCulture = CultureInfo.CurrentCulture;
            CultureInfo originalUiCulture = CultureInfo.CurrentUICulture;
            try
            {
                CultureInfo turkish = CultureInfo.GetCultureInfo("tr-TR");
                CultureInfo.CurrentCulture = turkish;
                CultureInfo.CurrentUICulture = turkish;

                Assert.IsTrue(ApplicationIdentityMatcher.Match(Registered(Publisher(publisher: "PUBLISHER", product: "IDENTITY", binary: "GAME.EXE")), PublisherEvidence(publisher: "publisher", product: "identity", binary: "game.exe")).IsMatch);
                Assert.IsTrue(ApplicationIdentityMatcher.Match(Registered(Package(publisherId: "PUBLISHER", packageFamilyName: "IDENTITY.APP", applicationUserModelId: "IDENTITY.APP!MAIN")), PackageEvidence(publisherId: "publisher", packageFamilyName: "identity.app", applicationUserModelId: "identity.app!main")).IsMatch);
            }
            finally
            {
                CultureInfo.CurrentCulture = originalCulture;
                CultureInfo.CurrentUICulture = originalUiCulture;
            }
        }

        [TestMethod]
        public void Match_HashEvidence_RequiresExactLowercaseSha256RegardlessOfDisplayMetadata()
        {
            RegisteredApplication application = Registered(new FileHashApplicationIdentity("hash", Hash));

            Assert.IsTrue(ApplicationIdentityMatcher.Match(application, new FileHashApplicationEvidence(Hash)).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(application, new FileHashApplicationEvidence("1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")).IsMatch);
        }

        [TestMethod]
        public void Match_PackagedEvidence_RequiresVerifiedTrustAndAllThreeFields()
        {
            RegisteredApplication application = Registered(Package());

            Assert.IsTrue(ApplicationIdentityMatcher.Match(application, PackageEvidence()).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(application, PackageEvidence(trust: PackageVerificationTrust.Failed)).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(application, PackageEvidence(publisherId: "CN=Other")).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(application, PackageEvidence(packageFamilyName: "Other.Game_123")).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(application, PackageEvidence(applicationUserModelId: "Games.Game!Other")).IsMatch);
        }

        [TestMethod]
        public void Match_EvidenceKindNeverCrossMatchesAnotherApprovedKind()
        {
            Assert.IsFalse(ApplicationIdentityMatcher.Match(Registered(Publisher()), new FileHashApplicationEvidence(Hash)).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(Registered(new FileHashApplicationIdentity("hash", Hash)), PackageEvidence()).IsMatch);
            Assert.IsFalse(ApplicationIdentityMatcher.Match(Registered(Package()), PublisherEvidence()).IsMatch);
        }

        [TestMethod]
        public void Match_MultipleApprovedIdentities_UsesOrAndReturnsUniqueOrdinalSortedIds()
        {
            RegisteredApplication application = Registered(
                new FileHashApplicationIdentity("z-hash", Hash),
                new FileHashApplicationIdentity("a-hash", Hash),
                Publisher());

            ApplicationMatchResult result = ApplicationIdentityMatcher.Match(application, new FileHashApplicationEvidence(Hash));

            Assert.IsTrue(result.IsMatch);
            Assert.AreEqual(ApplicationMatchReason.Matched, result.Reason);
            CollectionAssert.AreEqual(OrderedHashIdentityIds, result.MatchedIdentityIds.ToArray());
        }

        [TestMethod]
        public void Match_NoApprovedIdentity_ReturnsStableNoMatchReason()
        {
            ApplicationMatchResult result = ApplicationIdentityMatcher.Match(Registered(Publisher()), PublisherEvidence(trust: SignatureTrust.Untrusted));

            Assert.IsFalse(result.IsMatch);
            Assert.AreEqual(ApplicationMatchReason.NoApprovedIdentityMatched, result.Reason);
            Assert.HasCount(0, result.MatchedIdentityIds);
        }

        [TestMethod]
        public void Construct_ApplicationMatchResult_RejectsInvalidReasonAndIdentityIdState()
        {
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new ApplicationMatchResult((ApplicationMatchReason)999, []));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new ApplicationMatchResult(ApplicationMatchReason.Matched, []));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new ApplicationMatchResult(ApplicationMatchReason.NoApprovedIdentityMatched, ["matched"]));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new ApplicationMatchResult(ApplicationMatchReason.Matched, [null!]));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new ApplicationMatchResult(ApplicationMatchReason.Matched, [""]));
        }

        [TestMethod]
        public void Construct_ApplicationMatchResult_NormalizesAndSnapshotsIdentityIds()
        {
            List<string> identityIds = ["z", "a", "z"];

            ApplicationMatchResult result = new(ApplicationMatchReason.Matched, identityIds);
            identityIds.Clear();

            CollectionAssert.AreEqual(OrderedConstructorIdentityIds, result.MatchedIdentityIds.ToArray());
            _ = Assert.ThrowsExactly<NotSupportedException>(() => ((System.Collections.IList)result.MatchedIdentityIds).Add("other"));
        }
#pragma warning restore CA1707

        private static RegisteredApplication Registered(params ApplicationIdentity[] identities)
        {
            return new("game", "Game", identities);
        }

        private static PublisherApplicationIdentity Publisher(
            string identityId = "publisher",
            string publisher = "CN=Games",
            string product = "Game",
            string binary = "game.exe",
            Version? minimumVersion = null,
            Version? maximumVersion = null)
        {
            return new(identityId, publisher, product, binary, minimumVersion ?? new Version(1, 0, 0, 0), maximumVersion ?? new Version(2, 0, 0, 0));
        }

        private static PublisherApplicationEvidence PublisherEvidence(
            SignatureTrust trust = SignatureTrust.Trusted,
            string publisher = "CN=Games",
            string product = "Game",
            string binary = "game.exe",
            Version? version = null)
        {
            return new(trust, publisher, product, binary, version ?? new Version(1, 0, 0, 0));
        }

        private static PackagedApplicationIdentity Package(
            string identityId = "package",
            string publisherId = "CN=Games",
            string packageFamilyName = "Games.Game_123",
            string applicationUserModelId = "Games.Game!App")
        {
            return new(identityId, publisherId, packageFamilyName, applicationUserModelId);
        }

        private static PackagedApplicationEvidence PackageEvidence(
            PackageVerificationTrust trust = PackageVerificationTrust.Verified,
            string publisherId = "CN=Games",
            string packageFamilyName = "Games.Game_123",
            string applicationUserModelId = "Games.Game!App")
        {
            return new(trust, publisherId, packageFamilyName, applicationUserModelId);
        }
    }
}
