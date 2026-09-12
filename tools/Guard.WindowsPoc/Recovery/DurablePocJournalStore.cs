using System.Text;
using System.Text.Json;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Recovery
{
    /// <summary>Caller owns the protected, non-replaceable handle and global gate. No native trust is inferred from a path.</summary>
    internal sealed class DurablePocJournalStore(FileStream file) : IPocJournalStore
    {
        private const int MaximumBytes = 16_000_000;
        private sealed record Entry(AppLockerPolicySnapshot InitialBaseline, AppLockerPolicySnapshot Before, AppLockerPolicySnapshot After,
            string OwnershipEvidence, string RecoveryLease, DateTimeOffset PreparedAtUtc, PocJournalPhase Phase);
        private sealed record Envelope(string PreviousHash, string Payload, string Hash);

        public async Task<PocTransactionJournal?> ReadAsync(CancellationToken token)
        {
            (PocTransactionJournal? journal, _) = await ReadLogAsync(token).ConfigureAwait(false);
            return journal;
        }

        public async Task SaveAsync(PocTransactionJournal journal, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(journal);
            (PocTransactionJournal? previous, string hash) = await ReadLogAsync(token).ConfigureAwait(false);
            if (previous is not null && previous.InitialBaseline != journal.InitialBaseline)
            { throw new InvalidOperationException("Initial baseline cannot change."); }
            string payload = JsonSerializer.Serialize(new Entry(journal.InitialBaseline, journal.Before, journal.After,
                journal.OwnershipEvidence, journal.RecoveryLease, journal.PreparedAtUtc, journal.Phase));
            string nextHash = PolicyMutationDecision.Hash(hash + payload);
            byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new Envelope(hash, payload, nextHash)) + "\n");
            if (file.Length + bytes.Length > MaximumBytes) { throw new InvalidOperationException("Journal size limit exceeded."); }
            file.Position = file.Length;
            await file.WriteAsync(bytes, token).ConfigureAwait(false);
            await file.FlushAsync(token).ConfigureAwait(false);
            file.Flush(flushToDisk: true);
        }

        private async Task<(PocTransactionJournal? Journal, string Hash)> ReadLogAsync(CancellationToken token)
        {
            if (file.Length > MaximumBytes) { throw new InvalidOperationException("Journal size limit exceeded."); }
            file.Position = 0;
            byte[] bytes = new byte[(int)file.Length];
            await file.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
            if (bytes.Length > 0 && bytes[^1] != '\n') { throw new InvalidOperationException("Incomplete journal requires host recovery."); }
            PocTransactionJournal? journal = null;
            string hash = "";
            try
            {
                foreach (string line in Encoding.UTF8.GetString(bytes).Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    Envelope envelope = JsonSerializer.Deserialize<Envelope>(line) ?? throw new InvalidOperationException("Invalid journal.");
                    if (envelope.PreviousHash != hash || envelope.Hash != PolicyMutationDecision.Hash(hash + envelope.Payload))
                    { throw new InvalidOperationException("Journal integrity failure."); }
                    Entry entry = JsonSerializer.Deserialize<Entry>(envelope.Payload) ?? throw new InvalidOperationException("Invalid journal.");
                    if (!Enum.IsDefined(entry.Phase) || (journal is not null && journal.InitialBaseline != entry.InitialBaseline))
                    { throw new InvalidOperationException("Invalid journal transition."); }
                    journal = PocTransactionJournal.Prepare(entry.InitialBaseline, entry.Before, entry.After, entry.OwnershipEvidence,
                        entry.RecoveryLease, entry.PreparedAtUtc).WithPhase(entry.Phase);
                    hash = envelope.Hash;
                }
            }
            catch (JsonException) { throw new InvalidOperationException("Invalid journal."); }
            return (journal, hash);
        }
    }
}
