using Guard.Core.Identity;
using Guard.Core.Processes;

namespace Guard.Core.Tests.Processes
{
    [TestClass]
    public sealed class ProcessTargetVerifierTests
    {
        private const string ApprovedHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private const string OtherHash = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        private static readonly DateTimeOffset CreationUtc = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);
        private static readonly string[] ApprovedIdentityIds = ["approved-hash"];
        private static readonly string[] OrderedIdentityIds = ["a-hash", "z-hash"];

#pragma warning disable CA1707 // Test names use requirement terminology as a readable behavior contract.
        [TestMethod]
        public void Verify_CreationTimeChanges_RejectsReusedPid()
        {
            ProcessTargetVerificationResult result = ProcessTargetVerifier.Verify(
                Registered(),
                Snapshot(42, CreationUtc, @"C:\Games\game.exe", ApprovedHash),
                Snapshot(42, CreationUtc.AddTicks(1), @"C:\Games\game.exe", ApprovedHash));

            Assert.IsFalse(result.IsVerified);
            Assert.HasCount(0, result.MatchedIdentityIds);
        }

        [TestMethod]
        public void Verify_PidChanges_RejectsEvenMatchingImageIdentity()
        {
            ProcessTargetVerificationResult result = ProcessTargetVerifier.Verify(
                Registered(),
                Snapshot(42, CreationUtc, @"C:\Games\game.exe", ApprovedHash),
                Snapshot(43, CreationUtc, @"C:\Games\game.exe", ApprovedHash));

            Assert.IsFalse(result.IsVerified);
            Assert.HasCount(0, result.MatchedIdentityIds);
        }

        [TestMethod]
        public void Verify_ImageIdentityDoesNotMatch_RejectsEqualPidAndCreationTime()
        {
            ProcessTargetVerificationResult result = ProcessTargetVerifier.Verify(
                Registered(),
                Snapshot(42, CreationUtc, @"C:\Games\game.exe", ApprovedHash),
                Snapshot(42, CreationUtc, @"C:\Games\game.exe", OtherHash));

            Assert.IsFalse(result.IsVerified);
            Assert.HasCount(0, result.MatchedIdentityIds);
        }

        [TestMethod]
        public void Verify_PathMatchAloneNeverAuthorizesTarget()
        {
            ProcessTargetVerificationResult result = ProcessTargetVerifier.Verify(
                Registered(),
                Snapshot(42, CreationUtc, @"C:\Games\game.exe", ApprovedHash),
                Snapshot(42, CreationUtc, @"C:\Games\game.exe", OtherHash));

            Assert.IsFalse(result.IsVerified);
        }

        [TestMethod]
        public void Verify_PathDifferenceWithSameApprovedHash_CanPass()
        {
            ProcessTargetVerificationResult result = ProcessTargetVerifier.Verify(
                Registered(),
                Snapshot(42, CreationUtc, @"C:\Games\game.exe", ApprovedHash),
                Snapshot(42, CreationUtc, @"D:\Moved\renamed.exe", ApprovedHash));

            Assert.IsTrue(result.IsVerified);
            CollectionAssert.AreEqual(ApprovedIdentityIds, result.MatchedIdentityIds.ToArray());
        }

        [TestMethod]
        public void Verify_EqualPidCreationAndApprovedIdentity_ReturnsMatchedIdentityIds()
        {
            RegisteredApplication application = new(
                "game",
                "Game",
                [
                    new FileHashApplicationIdentity("z-hash", ApprovedHash),
                    new FileHashApplicationIdentity("a-hash", ApprovedHash),
                ]);

            ProcessTargetVerificationResult result = ProcessTargetVerifier.Verify(
                application,
                Snapshot(42, CreationUtc, @"C:\Games\game.exe", ApprovedHash),
                Snapshot(42, CreationUtc, @"C:\Games\game.exe", ApprovedHash));

            Assert.IsTrue(result.IsVerified);
            CollectionAssert.AreEqual(OrderedIdentityIds, result.MatchedIdentityIds.ToArray());
        }

        [TestMethod]
        public void Construct_ProcessSnapshot_RejectsUnreliableProcessEvidence()
        {
            _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Snapshot(0, CreationUtc, @"C:\Games\game.exe", ApprovedHash));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Snapshot(42, default, @"C:\Games\game.exe", ApprovedHash));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Snapshot(42, CreationUtc.ToOffset(TimeSpan.FromHours(9)), @"C:\Games\game.exe", ApprovedHash));
            _ = Assert.ThrowsExactly<ArgumentException>(() => Snapshot(42, CreationUtc, "", ApprovedHash));
            _ = Assert.ThrowsExactly<ArgumentNullException>(() => new ProcessImageSnapshot(42, CreationUtc, @"C:\Games\game.exe", null!));
        }
#pragma warning restore CA1707

        private static RegisteredApplication Registered()
        {
            return new("game", "Game", [new FileHashApplicationIdentity("approved-hash", ApprovedHash)]);
        }

        private static ProcessImageSnapshot Snapshot(int processId, DateTimeOffset creationTimeUtc, string observedPath, string hash)
        {
            return new(processId, creationTimeUtc, observedPath, new FileHashApplicationEvidence(hash));
        }
    }
}
