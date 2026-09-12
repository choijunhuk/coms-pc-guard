using Guard.Core.Identity;

namespace Guard.Core.Tests.Identity
{
    [TestClass]
    public sealed class FileIdentityCachePolicyTests
    {
        private static readonly DateTimeOffset NowUtc = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

#pragma warning disable CA1707 // Test names use requirement terminology as a readable behavior contract.
        [TestMethod]
        public void Evaluate_AllReliableFieldsMatch_ReusesCachedIdentity()
        {
            FileIdentityCacheKey key = Key();

            Assert.AreEqual(IdentityCacheDecision.ReuseCachedIdentity, FileIdentityCachePolicy.Evaluate(key, key, NowUtc));
        }

        [TestMethod]
        public void Evaluate_AnyCacheFieldChanges_RequiresIdentityRevalidation()
        {
            FileIdentityCacheKey cached = Key();
            FileIdentityCacheKey[] changedKeys =
            [
                Key(registrationRevision: 8),
                Key(canonicalPath: @"C:\Games\other.exe"),
                Key(length: 4_097),
                Key(lastWriteUtc: NowUtc.AddTicks(-2)),
                Key(stableFileId: "volume-1:file-43"),
                Key(contentStamp: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ];

            foreach (FileIdentityCacheKey current in changedKeys)
            {
                Assert.AreEqual(IdentityCacheDecision.RevalidateIdentity, FileIdentityCachePolicy.Evaluate(cached, current, NowUtc));
            }
        }

        [TestMethod]
        public void Construct_MissingOrUnreliableCacheFields_AreRejected()
        {
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Key(registrationRevision: 0));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Key(canonicalPath: ""));
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Key(length: -1));
            _ = Assert.ThrowsExactly<ArgumentException>(() => new FileIdentityCacheKey(
                7,
                @"C:\Games\game.exe",
                4_096,
                default,
                "volume-1:file-42",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Key(lastWriteUtc: NowUtc.ToOffset(TimeSpan.FromHours(9))));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Key(stableFileId: ""));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Key(contentStamp: ""));
        }

        [TestMethod]
        public void Evaluate_NowUtcMustBeExplicitUtcAndLastWriteCannotBeFuture()
        {
            FileIdentityCacheKey atNow = Key(lastWriteUtc: NowUtc);
            FileIdentityCacheKey oneTickFuture = Key(lastWriteUtc: NowUtc.AddTicks(1));

            Assert.AreEqual(IdentityCacheDecision.ReuseCachedIdentity, FileIdentityCachePolicy.Evaluate(atNow, atNow, NowUtc));
            Assert.AreEqual(IdentityCacheDecision.RevalidateIdentity, FileIdentityCachePolicy.Evaluate(oneTickFuture, oneTickFuture, NowUtc));
            _ = Assert.ThrowsExactly<ArgumentException>(() => FileIdentityCachePolicy.Evaluate(atNow, atNow, NowUtc.ToOffset(TimeSpan.FromHours(9))));
        }
#pragma warning restore CA1707

        private static FileIdentityCacheKey Key(
            long registrationRevision = 7,
            string canonicalPath = @"C:\Games\game.exe",
            long length = 4_096,
            DateTimeOffset? lastWriteUtc = null,
            string stableFileId = "volume-1:file-42",
            string contentStamp = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        {
            return new(
                registrationRevision,
                canonicalPath,
                length,
                lastWriteUtc ?? NowUtc.AddMinutes(-1),
                stableFileId,
                contentStamp);
        }
    }
}
