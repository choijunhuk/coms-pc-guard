using Guard.WindowsPoc.Native;

namespace Guard.WindowsPoc.Recovery
{
    internal enum PocJournalPhase { Prepared, WritePending, Mutated, Recovered, HostCloneRecoveryRequired }
    internal enum PocRecoveryBarrier { None = 0, Capture = 1, Drift = 2, UnknownFailClosed = 3, ValidationComplete = 5, NativeWriteInFlight = 6 }

    // Internal pending native trust integration: caller-supplied journal data is never mutation authority.
    internal sealed record PocTransactionJournal
    {
        private PocTransactionJournal(AppLockerPolicySnapshot initialBaseline, AppLockerPolicySnapshot before, AppLockerPolicySnapshot after,
            string ownershipEvidence, string recoveryLease, DateTimeOffset preparedAtUtc)
        {
            InitialBaseline = initialBaseline; Before = before; After = after;
            OwnershipEvidence = ownershipEvidence; RecoveryLease = recoveryLease; PreparedAtUtc = preparedAtUtc;
        }

        public AppLockerPolicySnapshot InitialBaseline { get; }
        public AppLockerPolicySnapshot Before { get; }
        public AppLockerPolicySnapshot After { get; }
        public string OwnershipEvidence { get; }
        public string RecoveryLease { get; }
        public DateTimeOffset PreparedAtUtc { get; }
        public PocJournalPhase Phase { get; private init; }

        public static PocTransactionJournal Prepare(AppLockerPolicySnapshot initialBaseline, AppLockerPolicySnapshot before,
            AppLockerPolicySnapshot after, string ownershipEvidence, string recoveryLease, DateTimeOffset now)
        {
            ArgumentNullException.ThrowIfNull(initialBaseline);
            ArgumentNullException.ThrowIfNull(before);
            ArgumentNullException.ThrowIfNull(after);
            ArgumentException.ThrowIfNullOrWhiteSpace(ownershipEvidence);
            ArgumentException.ThrowIfNullOrWhiteSpace(recoveryLease);
            return !initialBaseline.IsEmpty || !initialBaseline.IsReady(initialBaseline.CapturedAtUtc) || !before.IsReady(now) || !after.IsReady(now)
                ? throw new InvalidOperationException("Complete initial baseline and transition evidence required.")
                : new(initialBaseline, before, after, ownershipEvidence, recoveryLease, now);
        }

        public PocTransactionJournal WithPhase(PocJournalPhase phase)
        {
            return this with { Phase = phase };
        }

        public bool Recognizes(AppLockerPolicySnapshot snapshot)
        {
            return snapshot.SamePolicy(InitialBaseline)
                    || snapshot.SamePolicy(Before) || snapshot.SamePolicy(After);
        }
    }

    internal interface IPocJournalStore
    {
        Task<bool> HasHostRecoveryRequiredAsync(CancellationToken token);
        Task SetHostRecoveryRequiredAsync(CancellationToken token);
        Task<bool> HasRecoveryBarrierAsync(CancellationToken token);
        Task SetRecoveryBarrierAsync(bool required, CancellationToken token);
        async Task<PocRecoveryBarrier> ReadRecoveryBarrierAsync(CancellationToken token)
        {
            return await HasRecoveryBarrierAsync(token).ConfigureAwait(false) ? PocRecoveryBarrier.UnknownFailClosed : PocRecoveryBarrier.None;
        }
        Task SetRecoveryBarrierAsync(PocRecoveryBarrier barrier, CancellationToken token)
        {
            return SetRecoveryBarrierAsync(barrier != PocRecoveryBarrier.None, token);
        }
        Task<PocTransactionJournal?> ReadAsync(CancellationToken token);
        Task SaveAsync(PocTransactionJournal journal, CancellationToken token);
    }
}
