using System.Security.Cryptography;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Tests.Recovery
{
    [TestClass]
    public sealed class WindowsPocStateLeaseTests
    {
        private const string Owner = "S-1-5-21-1-2-3-1001";

        [TestMethod]
        public void UntrustedPathsRefuseBeforeOpeningJournal()
        {
            foreach (StatePathEvidence evidence in new[]
            {
                new StatePathEvidence(true, Owner, true, false), new(false, Owner, true, true),
                new(false, "S-1-5-32-544", true, false), new(false, Owner, false, false)
            })
            {
                bool opened = false;
                _ = Assert.ThrowsExactly<InvalidOperationException>(() => WindowsPocStateLease.Open(Owner, () => [evidence], () => { opened = true; throw new InvalidOperationException(); }, _ => throw new InvalidOperationException()));
                Assert.IsFalse(opened);
            }
        }

        [TestMethod]
        public async Task RetainedLeaseRevalidatesBeforeReadAppendAndFlush()
        {
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            bool trustworthy = true;
            try
            {
                using WindowsPocStateLease lease = WindowsPocStateLease.Open(Owner,
                    () => [new(false, Owner, trustworthy, false)],
                    () => new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 1), Evidence);
                using DurablePocJournalStore store = new(lease);
                await store.SetRecoveryBarrierAsync(true, CancellationToken.None);
                Assert.IsTrue(await store.HasRecoveryBarrierAsync(CancellationToken.None));
                trustworthy = false;
                _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.ReadAsync(CancellationToken.None));
                _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.SetRecoveryBarrierAsync(false, CancellationToken.None));
            }
            finally { File.Delete(path); }
        }

        [TestMethod]
        public async Task ChangedHandleEvidenceRefusesInsteadOfAcceptingNewBaseline()
        {
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            bool changed = false;
            try
            {
                using WindowsPocStateLease lease = WindowsPocStateLease.Open(Owner, () => [new(false, Owner, true, false)],
                    () => new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 1),
                    file => changed ? Evidence(file) with { LastWriteUtc = DateTime.UnixEpoch } : Evidence(file));
                using DurablePocJournalStore store = new(lease);
                changed = true;
                _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.ReadAsync(CancellationToken.None));
            }
            finally { File.Delete(path); }
        }

        [TestMethod]
        public void NativeOpenRefusesOnNonWindows()
        {
            if (!OperatingSystem.IsWindows())
            { _ = Assert.ThrowsExactly<PlatformNotSupportedException>(() => WindowsPocStateLease.Open(Owner)); }
        }

        [TestMethod]
        public void WindowsRetainedHandleDeniesReplacementAndOtherWriters()
        {
            if (!OperatingSystem.IsWindows()) { return; }
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            try
            {
                using WindowsPocStateLease lease = WindowsPocStateLease.Open(Owner, () => [new(false, Owner, true, false)],
                    () => new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 1), Evidence);
                _ = Assert.ThrowsExactly<IOException>(() => File.Delete(path));
                _ = Assert.ThrowsExactly<IOException>(() => { using FileStream other = new(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); });
            }
            finally { File.Delete(path); }
        }

        private static StateFileEvidence Evidence(FileStream file)
        {
            file.Position = 0;
            string hash = Convert.ToHexString(SHA256.HashData(file));
            return new(hash, file.Length, File.GetLastWriteTimeUtc(file.SafeFileHandle));
        }
    }
}
