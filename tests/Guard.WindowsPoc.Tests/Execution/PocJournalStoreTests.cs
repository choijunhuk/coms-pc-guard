using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;
using System.Text.Json;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class PocJournalStoreTests
    {
        [TestMethod]
        public async Task RecoveryBarrierSurvivesReopenWithoutAnyTransactionJournal()
        {
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".journal");
            try
            {
                await using (FileStream file = new(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read))
                { await new DurablePocJournalStore(file).SetRecoveryBarrierAsync(true, CancellationToken.None); }
                await using (FileStream file = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
                {
                    DurablePocJournalStore store = new(file);
                    Assert.IsTrue(await store.HasRecoveryBarrierAsync(CancellationToken.None));
                    Assert.AreEqual(PocRecoveryBarrier.UnknownFailClosed, await store.ReadRecoveryBarrierAsync(CancellationToken.None));
                    Assert.IsNull(await store.ReadAsync(CancellationToken.None));
                }
            }
            finally { File.Delete(path); }
        }

        [TestMethod]
        [DataRow("numeric-drift", (int)PocRecoveryBarrier.Drift)]
        [DataRow("named-drift", (int)PocRecoveryBarrier.Drift)]
        [DataRow("named-validation-complete", (int)PocRecoveryBarrier.ValidationComplete)]
        [DataRow("legacy-bool", (int)PocRecoveryBarrier.UnknownFailClosed)]
        public async Task HistoricalRecoveryBarrierWireValuesRemainFailClosedOrExplicitlyVersioned(string caseName, int expected)
        {
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".journal");
            try
            {
                string payload = BarrierPayload(caseName);
                await File.WriteAllTextAsync(path, Envelope("", payload) + "\n");
                await using FileStream file = new(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
                DurablePocJournalStore store = new(file);
                Assert.AreEqual((PocRecoveryBarrier)expected, await store.ReadRecoveryBarrierAsync(CancellationToken.None));
            }
            finally { File.Delete(path); }
        }

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

        private static string Envelope(string previousHash, string payload)
        {
            string hash = PolicyMutationDecision.Hash(previousHash + payload);
            return JsonSerializer.Serialize(new { PreviousHash = previousHash, Payload = payload, Hash = hash });
        }

        private static string BarrierPayload(string caseName)
        {
            return caseName switch
            {
                "numeric-drift" => JsonSerializer.Serialize(new { Journal = (object?)null, RecoveryBarrier = true, RecoveryBarrierKind = 2, HostRecoveryRequired = (bool?)null }),
                "named-drift" => JsonSerializer.Serialize(new { Journal = (object?)null, RecoveryBarrier = true, RecoveryBarrierKind = "Drift", HostRecoveryRequired = (bool?)null }),
                "named-validation-complete" => JsonSerializer.Serialize(new { Journal = (object?)null, RecoveryBarrier = true, RecoveryBarrierKind = "ValidationComplete", HostRecoveryRequired = (bool?)null }),
                "legacy-bool" => JsonSerializer.Serialize(new { Journal = (object?)null, RecoveryBarrier = true, HostRecoveryRequired = (bool?)null }),
                _ => throw new ArgumentOutOfRangeException(nameof(caseName))
            };
        }
    }
}
