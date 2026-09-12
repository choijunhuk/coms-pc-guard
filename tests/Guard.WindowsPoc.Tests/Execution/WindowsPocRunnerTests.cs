using Guard.WindowsPoc.Execution;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Inventory;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class WindowsPocRunnerTests
    {
        private static readonly DateTimeOffset Now = new(2026, 9, 13, 0, 0, 0, TimeSpan.Zero);
        private static readonly AppLockerPolicySnapshot Empty = Snapshot("<AppLockerPolicy Version=\"1\" />");
        private static readonly AppLockerPolicySnapshot First = Snapshot("<AppLockerPolicy Version=\"1\"><RuleCollection Type=\"Exe\" EnforcementMode=\"AuditOnly\" /></AppLockerPolicy>");
        private static readonly AppLockerPolicySnapshot Second = Snapshot("<AppLockerPolicy Version=\"1\"><RuleCollection Type=\"Exe\" EnforcementMode=\"Enabled\" /></AppLockerPolicy>");

        [TestMethod]
        public async Task SuccessRestoresInitialBaselineAfterBothTransitions()
        {
            ScriptedGateway gateway = new();
            MemoryJournal store = new();
            PocRunResult result = await Runner(gateway, store).RunAsync([First, Second]);
            Assert.AreEqual(PocRunResult.Success, result);
            Assert.AreEqual(Empty, gateway.Current);
            CollectionAssert.AreEqual(new[] { First, Second, Empty }, gateway.Writes);
            Assert.AreEqual(PocJournalPhase.Recovered, store.Value!.Phase);
            Assert.AreEqual(Empty, store.Value.InitialBaseline);
        }

        [TestMethod]
        [DataRow(1, false)]
        [DataRow(1, true)]
        [DataRow(2, false)]
        [DataRow(2, true)]
        public async Task FailedOrUnacknowledgedNativeWritesRestoreInitialBaseline(int failedWrite, bool afterMutation)
        {
            ScriptedGateway gateway = new() { FailWrite = failedWrite, FailAfterMutation = afterMutation };
            MemoryJournal store = new();
            PocRunResult result = await Runner(gateway, store).RunAsync([First, Second]);
            Assert.AreEqual(PocRunResult.ProbeFailed, result);
            Assert.AreEqual(Empty, gateway.Current);
            Assert.AreEqual(failedWrite == 1 && !afterMutation ? 0 : 1, gateway.RestoreWrites);
        }

        [TestMethod]
        [DataRow(0, false)]
        [DataRow(1, false)]
        [DataRow(1, true)]
        [DataRow(2, true)]
        public async Task ResumedSecondTransitionRecognizesBothSidesAndRecoveryIsIdempotent(int phase, bool after)
        {
            ScriptedGateway gateway = new() { Current = after ? Second : First };
            MemoryJournal store = new() { Value = PocTransactionJournal.Prepare(Empty, First, Second, "owner-proof", "lease", Now).WithPhase((PocJournalPhase)phase) };
            Assert.AreEqual(PocRunResult.Success, await Runner(gateway, store).RecoverAsync());
            Assert.AreEqual(PocRunResult.Success, await Runner(gateway, store).RecoverAsync());
            Assert.AreEqual(Empty, gateway.Current);
            Assert.AreEqual(1, gateway.RestoreWrites);
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(3)]
        [DataRow(4)]
        public async Task DriftBeforeApplyAfterApplyOrBeforeCleanupCausesNoFurtherWrite(int capture)
        {
            ScriptedGateway gateway = new() { DriftAtCapture = capture };
            PocRunResult result = await Runner(gateway, new()).RunAsync([First]);
            Assert.AreEqual(PocRunResult.HostCloneRecoveryRequired, result);
            Assert.AreEqual(0, gateway.RestoreWrites);
            Assert.AreEqual(capture == 1 ? 0 : 1, gateway.Writes.Count);
        }

        [TestMethod]
        [DataRow("observation")]
        [DataRow("fixture")]
        [DataRow("cancellation")]
        [DataRow("evidence")]
        public async Task ProbeAndEvidenceFailuresStillRestoreWithIndependentCancellation(string failure)
        {
            ScriptedGateway gateway = new() { ProbeFailure = failure };
            MemoryJournal store = new();
            Assert.AreEqual(PocRunResult.ProbeFailed, await Runner(gateway, store, failure == "evidence").RunAsync([First]));
            Assert.AreEqual(Empty, gateway.Current);
            Assert.AreEqual(1, gateway.RestoreWrites);
        }

        [TestMethod]
        public async Task CleanupFailureDominatesEarlierProbeFailure()
        {
            ScriptedGateway gateway = new() { ProbeFailure = "fixture", FailRestore = true };
            Assert.AreEqual(PocRunResult.HostCloneRecoveryRequired, await Runner(gateway, new()).RunAsync([First]));
            Assert.AreEqual(First, gateway.Current);
        }

        [TestMethod]
        public async Task ServiceNotReadyAndUnknownInventoryNeverWrite()
        {
            foreach (AppLockerPolicySnapshot invalid in new[] { Empty with { AppIdServiceRunning = false }, Empty with { CspMdm = PolicyPresence.Unknown }, Empty with { Wdac = PolicyPresence.External } })
            {
                ScriptedGateway gateway = new() { Current = invalid };
                Assert.AreNotEqual(PocRunResult.Success, await Runner(gateway, new()).RunAsync([First]));
                Assert.AreEqual(0, gateway.Writes.Count);
            }
        }

        [TestMethod]
        public async Task WritePendingPersistenceFailurePreventsNativeWrite()
        {
            ScriptedGateway gateway = new();
            MemoryJournal store = new() { FailPending = true };
            Assert.AreEqual(PocRunResult.ProbeFailed, await Runner(gateway, store).RunAsync([First]));
            Assert.AreEqual(0, gateway.Writes.Count);
        }

        [TestMethod]
        public async Task RecordedDriftRemainsHostRecoveryAfterExternalPolicyDisappears()
        {
            ScriptedGateway gateway = new() { DriftAtCapture = 3 };
            MemoryJournal store = new();
            Assert.AreEqual(PocRunResult.HostCloneRecoveryRequired, await Runner(gateway, store).RunAsync([First]));
            gateway.Current = First;
            Assert.AreEqual(PocRunResult.HostCloneRecoveryRequired, await Runner(gateway, store).RecoverAsync());
            Assert.AreEqual(0, gateway.RestoreWrites);
        }

        [TestMethod]
        public async Task ExistingUnrecoverableJournalDominatesRefusalToStartAnotherRun()
        {
            ScriptedGateway gateway = new() { Current = First, FailRestore = true };
            MemoryJournal store = new() { Value = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now).WithPhase(PocJournalPhase.WritePending) };
            Assert.AreEqual(PocRunResult.HostCloneRecoveryRequired, await Runner(gateway, store).RunAsync([Second]));
            Assert.AreEqual(0, gateway.Writes.Count);
        }

        [TestMethod]
        public async Task EvidenceNeverReportsSuccessBeforeCleanupOutcome()
        {
            ScriptedGateway gateway = new() { FailRestore = true };
            MemoryJournal store = new();
            gateway.Store = store;
            List<PocRunResult> reported = [];
            WindowsPocRunner runner = new(gateway, store, new TestGate(), new FixedClock(), "owner-proof", "lease", value =>
            { reported.Add(value); return Task.CompletedTask; });
            Assert.AreEqual(PocRunResult.HostCloneRecoveryRequired, await runner.RunAsync([First]));
            CollectionAssert.AreEqual(new[] { PocRunResult.HostCloneRecoveryRequired }, reported);
        }

        private static WindowsPocRunner Runner(ScriptedGateway gateway, MemoryJournal store, bool failEvidence = false)
        {
            gateway.Store = store;
            return new(gateway, store, new TestGate(), new FixedClock(), "owner-proof", "lease", _ => failEvidence ? Task.FromException(new IOException("evidence")) : Task.CompletedTask);
        }

        private static AppLockerPolicySnapshot Snapshot(string xml)
        {
            return new(Now, xml, xml, PolicyPresence.Absent, PolicyPresence.Absent, true, true);
        }

        private sealed class FixedClock : TimeProvider
        {
            public override DateTimeOffset GetUtcNow()
            {
                return Now;
            }
        }
        private sealed class TestGate : IPolicyGate
        {
            public Task<T> RunAsync<T>(Func<Task<T>> action, CancellationToken cancellationToken)
            {
                return action();
            }
        }
        private sealed class MemoryJournal : IPocJournalStore
        {
            public PocTransactionJournal? Value { get; set; }
            public bool FailPending { get; set; }
            public Task<PocTransactionJournal?> ReadAsync(CancellationToken token)
            {
                return Task.FromResult(Value);
            }

            public Task SaveAsync(PocTransactionJournal journal, CancellationToken token)
            {
                if (FailPending && journal.Phase == PocJournalPhase.WritePending) { throw new IOException("journal"); }
                Value = journal;
                return Task.CompletedTask;
            }
        }
        private sealed class ScriptedGateway : IPocPolicyGateway
        {
            public AppLockerPolicySnapshot Current { get; set; } = Empty;
            public MemoryJournal? Store { get; set; }
            public List<AppLockerPolicySnapshot> Writes { get; } = [];
            public int RestoreWrites { get; private set; }
            public int FailWrite { get; init; }
            public bool FailAfterMutation { get; init; }
            public bool FailRestore { get; init; }
            public int DriftAtCapture { get; init; }
            public string? ProbeFailure { get; init; }
            private int _captures;
            private int _applies;
            public Task<AppLockerPolicySnapshot> CaptureAsync(CancellationToken token)
            {
                if (++_captures == DriftAtCapture) { Current = Snapshot("<AppLockerPolicy Version=\"1\"><external /></AppLockerPolicy>"); }
                return Task.FromResult(Current);
            }
            public Task WriteAsync(PocTransactionJournal journal, bool restore, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                Assert.AreEqual(PocJournalPhase.WritePending, Store!.Value!.Phase, "Native write must follow durable WritePending.");
                if (restore)
                {
                    if (FailRestore) { throw new IOException("restore"); }
                    RestoreWrites++;
                }
                else if (++_applies == FailWrite && !FailAfterMutation) { throw new IOException("before"); }
                Current = restore ? journal.InitialBaseline : journal.After;
                Writes.Add(Current);
                return !restore && _applies == FailWrite && FailAfterMutation ? throw new IOException("after") : Task.CompletedTask;
            }
            public Task<bool> ProbeAsync(CancellationToken token)
            {
                return ProbeFailure switch
                {
                    "observation" => Task.FromResult(false),
                    "fixture" => Task.FromException<bool>(new IOException("fixture")),
                    "cancellation" => Task.FromException<bool>(new OperationCanceledException()),
                    _ => Task.FromResult(true)
                };
            }
        }
    }
}
