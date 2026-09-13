using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Recovery
{
    /// <summary>Caller owns the protected, non-replaceable handle and global gate. No native trust is inferred from a path.</summary>
    internal sealed class DurablePocJournalStore(FileStream file) : IPocJournalStore, IDisposable
    {
        private readonly WindowsPocStateLease? _lease;
        internal DurablePocJournalStore(WindowsPocStateLease lease) : this(lease.File) { _lease = lease; }
        public void Dispose() { _lease?.Dispose(); }
        internal bool Owns(WindowsPocStateLease lease)
        {
            ArgumentNullException.ThrowIfNull(lease);
            return ReferenceEquals(_lease, lease) && ReferenceEquals(file, lease.File);
        }
        private const int MaximumBytes = 16_000_000;
        private sealed record Entry(AppLockerPolicySnapshot InitialBaseline, AppLockerPolicySnapshot Before, AppLockerPolicySnapshot After,
            string OwnershipEvidence, string RecoveryLease, DateTimeOffset PreparedAtUtc, PocJournalPhase Phase);
        private sealed record Envelope(string PreviousHash, string Payload, string Hash);
        private sealed record LogRecord(Entry? Journal, bool? RecoveryBarrier, PocRecoveryBarrier? RecoveryBarrierKind, bool? HostRecoveryRequired);
        private static readonly JsonSerializerOptions JournalJson = new()
        {
            Converters = { new PocRecoveryBarrierJsonConverter() }
        };

        public async Task<bool> HasHostRecoveryRequiredAsync(CancellationToken token)
        {
            (_, _, _, bool required) = await ReadLogAsync(token).ConfigureAwait(false);
            return required;
        }

        public async Task SetHostRecoveryRequiredAsync(CancellationToken token)
        {
            (_, string hash, _, _) = await ReadLogAsync(token).ConfigureAwait(false);
            await AppendAsync(new(null, null, null, true), hash, token).ConfigureAwait(false);
        }

        public async Task<bool> HasRecoveryBarrierAsync(CancellationToken token)
        {
            return await ReadRecoveryBarrierAsync(token).ConfigureAwait(false) != PocRecoveryBarrier.None;
        }

        public async Task<PocRecoveryBarrier> ReadRecoveryBarrierAsync(CancellationToken token)
        {
            (_, _, PocRecoveryBarrier barrier, _) = await ReadLogAsync(token).ConfigureAwait(false);
            return barrier;
        }

        public async Task SetRecoveryBarrierAsync(bool required, CancellationToken token)
        {
            await SetRecoveryBarrierAsync(required ? PocRecoveryBarrier.UnknownFailClosed : PocRecoveryBarrier.None, token).ConfigureAwait(false);
        }

        public async Task SetRecoveryBarrierAsync(PocRecoveryBarrier barrier, CancellationToken token)
        {
            (_, string hash, _, _) = await ReadLogAsync(token).ConfigureAwait(false);
            await AppendAsync(new(null, barrier != PocRecoveryBarrier.None, barrier, null), hash, token).ConfigureAwait(false);
        }

        public async Task<PocTransactionJournal?> ReadAsync(CancellationToken token)
        {
            (PocTransactionJournal? journal, _, _, _) = await ReadLogAsync(token).ConfigureAwait(false);
            return journal;
        }

        internal async Task<bool> HasPreparedWritePendingProofAsync(PocTransactionJournal journal, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(journal);
            _lease?.Revalidate();
            if (file.Length > MaximumBytes) { throw new InvalidOperationException("Journal size limit exceeded."); }
            file.Position = 0;
            byte[] bytes = new byte[(int)file.Length];
            await file.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
            _lease?.Revalidate();
            if (bytes.Length > 0 && bytes[^1] != '\n') { throw new InvalidOperationException("Incomplete journal requires host recovery."); }
            string hash = "";
            bool prepared = false;
            try
            {
                foreach (string line in Encoding.UTF8.GetString(bytes).Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    Envelope envelope = JsonSerializer.Deserialize<Envelope>(line) ?? throw new InvalidOperationException("Invalid journal.");
                    if (envelope.PreviousHash != hash || envelope.Hash != PolicyMutationDecision.Hash(hash + envelope.Payload))
                    { throw new InvalidOperationException("Journal integrity failure."); }
                    LogRecord record = JsonSerializer.Deserialize<LogRecord>(envelope.Payload, JournalJson) ?? throw new InvalidOperationException("Invalid journal.");
                    hash = envelope.Hash;
                    if (record.Journal is null) { continue; }
                    Entry entry = record.Journal;
                    PocTransactionJournal logged = PocTransactionJournal.Prepare(entry.InitialBaseline, entry.Before, entry.After,
                        entry.OwnershipEvidence, entry.RecoveryLease, entry.PreparedAtUtc).WithPhase(entry.Phase);
                    if (logged == journal.WithPhase(PocJournalPhase.Prepared)) { prepared = true; }
                    if (logged == journal) { return prepared; }
                }
            }
            catch (JsonException) { throw new InvalidOperationException("Invalid journal."); }
            return false;
        }

        public async Task SaveAsync(PocTransactionJournal journal, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(journal);
            (PocTransactionJournal? previous, string hash, _, _) = await ReadLogAsync(token).ConfigureAwait(false);
            if (previous is not null && previous.InitialBaseline != journal.InitialBaseline)
            { throw new InvalidOperationException("Initial baseline cannot change."); }
            await AppendAsync(new(new(journal.InitialBaseline, journal.Before, journal.After,
                journal.OwnershipEvidence, journal.RecoveryLease, journal.PreparedAtUtc, journal.Phase), null, null, null), hash, token).ConfigureAwait(false);
        }

        private async Task AppendAsync(LogRecord record, string hash, CancellationToken token)
        {
            string payload = JsonSerializer.Serialize(record, JournalJson);
            string nextHash = PolicyMutationDecision.Hash(hash + payload);
            byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new Envelope(hash, payload, nextHash)) + "\n");
            if (_lease is not null) { await _lease.AppendAsync(bytes, token).ConfigureAwait(false); return; }
            if (file.Length + bytes.Length > MaximumBytes) { throw new InvalidOperationException("Journal size limit exceeded."); }
            file.Position = file.Length;
            await file.WriteAsync(bytes, token).ConfigureAwait(false);
            await file.FlushAsync(token).ConfigureAwait(false);
            file.Flush(flushToDisk: true);
        }

        private async Task<(PocTransactionJournal? Journal, string Hash, PocRecoveryBarrier RecoveryBarrier, bool HostRecoveryRequired)> ReadLogAsync(CancellationToken token)
        {
            _lease?.Revalidate();
            if (file.Length > MaximumBytes) { throw new InvalidOperationException("Journal size limit exceeded."); }
            file.Position = 0;
            byte[] bytes = new byte[(int)file.Length];
            await file.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
            _lease?.Revalidate();
            if (bytes.Length > 0 && bytes[^1] != '\n') { throw new InvalidOperationException("Incomplete journal requires host recovery."); }
            PocTransactionJournal? journal = null;
            string hash = "";
            PocRecoveryBarrier recoveryBarrier = PocRecoveryBarrier.None;
            bool hostRecoveryRequired = false;
            try
            {
                foreach (string line in Encoding.UTF8.GetString(bytes).Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    Envelope envelope = JsonSerializer.Deserialize<Envelope>(line) ?? throw new InvalidOperationException("Invalid journal.");
                    if (envelope.PreviousHash != hash || envelope.Hash != PolicyMutationDecision.Hash(hash + envelope.Payload))
                    { throw new InvalidOperationException("Journal integrity failure."); }
                    LogRecord record = JsonSerializer.Deserialize<LogRecord>(envelope.Payload, JournalJson) ?? throw new InvalidOperationException("Invalid journal.");
                    hash = envelope.Hash;
                    if (record.HostRecoveryRequired is true && record.Journal is null && record.RecoveryBarrier is null && record.RecoveryBarrierKind is null)
                    { hostRecoveryRequired = true; continue; }
                    if (record.RecoveryBarrier is bool required && record.Journal is null && record.HostRecoveryRequired is null)
                    {
                        if (record.RecoveryBarrierKind is { } kind && !Enum.IsDefined(kind)) { throw new InvalidOperationException("Invalid journal."); }
                        recoveryBarrier = required ? record.RecoveryBarrierKind ?? PocRecoveryBarrier.UnknownFailClosed : PocRecoveryBarrier.None;
                        continue;
                    }
                    Entry entry = record.Journal ?? throw new InvalidOperationException("Invalid journal.");
                    if (record.RecoveryBarrier is not null || record.RecoveryBarrierKind is not null || record.HostRecoveryRequired is not null) { throw new InvalidOperationException("Invalid journal."); }
                    if (!Enum.IsDefined(entry.Phase) || (journal is not null && journal.InitialBaseline != entry.InitialBaseline))
                    { throw new InvalidOperationException("Invalid journal transition."); }
                    journal = PocTransactionJournal.Prepare(entry.InitialBaseline, entry.Before, entry.After, entry.OwnershipEvidence,
                        entry.RecoveryLease, entry.PreparedAtUtc).WithPhase(entry.Phase);
                }
            }
            catch (JsonException) { throw new InvalidOperationException("Invalid journal."); }
            return (journal, hash, recoveryBarrier, hostRecoveryRequired);
        }

        private sealed class PocRecoveryBarrierJsonConverter : JsonConverter<PocRecoveryBarrier>
        {
#pragma warning disable IDE0046, IDE0072
            public override PocRecoveryBarrier Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                return reader.TokenType switch
                {
                    JsonTokenType.String => ReadString(reader),
                    JsonTokenType.Number when reader.TryGetInt32(out int value) => value switch
                    {
                        0 => PocRecoveryBarrier.None,
                        1 => PocRecoveryBarrier.Capture,
                        2 => PocRecoveryBarrier.Drift,
                        3 => PocRecoveryBarrier.UnknownFailClosed,
                        4 => PocRecoveryBarrier.UnknownFailClosed,
                        _ => throw new JsonException("Invalid recovery barrier.")
                    },
                    _ => throw new JsonException("Invalid recovery barrier.")
                };
            }
#pragma warning restore IDE0046, IDE0072

            private static PocRecoveryBarrier ReadString(Utf8JsonReader reader)
            {
                return Enum.TryParse(reader.GetString(), ignoreCase: false, out PocRecoveryBarrier barrier)
                    && Enum.IsDefined(barrier)
                    ? barrier : throw new JsonException("Invalid recovery barrier.");
            }

            public override void Write(Utf8JsonWriter writer, PocRecoveryBarrier value, JsonSerializerOptions options)
            {
                if (!Enum.IsDefined(value)) { throw new JsonException("Invalid recovery barrier."); }
                writer.WriteStringValue(value.ToString());
            }
        }
    }
}
