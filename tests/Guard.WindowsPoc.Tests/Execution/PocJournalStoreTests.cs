using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class PocJournalStoreTests
    {
        [TestMethod]
        public async Task DurableJournalReopensAndRejectsTruncatedTail()
        {
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".journal");
            DateTimeOffset now = DateTimeOffset.UtcNow;
            AppLockerPolicySnapshot baseline = new(now, "<AppLockerPolicy Version=\"1\" />", "<AppLockerPolicy Version=\"1\" />", PolicyPresence.Absent, PolicyPresence.Absent, true, true);
            PocTransactionJournal journal = PocTransactionJournal.Prepare(baseline, baseline, baseline, "ownership", "lease", now);
            try
            {
                await using (FileStream file = new(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read))
                {
                    DurablePocJournalStore store = new(file);
                    await store.SaveAsync(journal, CancellationToken.None);
                    await store.SaveAsync(journal.WithPhase(PocJournalPhase.WritePending), CancellationToken.None);
                }
                await using (FileStream file = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
                {
                    DurablePocJournalStore store = new(file);
                    PocTransactionJournal? restored = await store.ReadAsync(CancellationToken.None);
                    Assert.AreEqual(PocJournalPhase.WritePending, restored!.Phase);
                    Assert.AreEqual(baseline, restored.InitialBaseline);
                    file.SetLength(file.Length - 1);
                    _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => store.ReadAsync(CancellationToken.None));
                }
            }
            finally { File.Delete(path); }
        }
    }
}
