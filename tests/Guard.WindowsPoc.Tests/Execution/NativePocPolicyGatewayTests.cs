using Guard.WindowsPoc.Execution;
using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Tests.Native;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class NativePocPolicyGatewayTests
    {
        private static readonly DateTimeOffset Now = new(2026, 9, 13, 0, 0, 0, TimeSpan.Zero);
        private static readonly AppLockerPolicySnapshot Empty = Snapshot("<AppLockerPolicy Version=\"1\" />");
        private static readonly AppLockerPolicySnapshot First = Snapshot("<AppLockerPolicy Version=\"1\"><RuleCollection Type=\"Exe\" EnforcementMode=\"AuditOnly\" /></AppLockerPolicy>");

        [TestMethod]
        public async Task CaptureConvertsTrustedNativeSnapshotIntoPortablePolicySnapshot()
        {
            RecordingRunner runner = new();
            NativePocPolicyGateway gateway = new(runner);
            AppLockerPolicySnapshot snapshot = await gateway.CaptureAsync(CancellationToken.None);
            Assert.IsTrue(snapshot.IsReady(Now));
            Assert.IsTrue(snapshot.IsEmpty);
            Assert.AreEqual(WindowsCommand.Capture, runner.Requests.Single().Command);
        }

        [TestMethod]
        public async Task InMemoryJournalCannotDispatchNativeWriteWithoutProtectedAuthorization()
        {
            RecordingRunner runner = new();
            NativePocPolicyGateway gateway = new(runner);
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.WriteAsync(journal, restore: false, CancellationToken.None));
            Assert.HasCount(0, runner.Requests);
        }

        [TestMethod]
        public async Task ProtectedAuthorizationDispatchesOnlyApplyOrRestoreRequests()
        {
            RecordingRunner runner = new();
            NativePocPolicyGateway gateway = new(runner, (journal, restore, _) =>
                Task.FromResult(PocMutationAuthorization.AuthorizeForTest(journal, restore, restore ? First : Empty, "proof")));
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            await gateway.WriteAsync(journal, restore: false, CancellationToken.None);
            await gateway.WriteAsync(journal, restore: true, CancellationToken.None);
            Assert.AreEqual(WindowsCommand.Apply, runner.Requests[0].Command);
            Assert.AreSame(journal, runner.Requests[0].Authorization!.Journal);
            Assert.AreEqual(WindowsCommand.Restore, runner.Requests[1].Command);
            Assert.AreSame(journal, runner.Requests[1].Authorization!.Journal);
        }

        [TestMethod]
        public void ProtectedAuthorizationRejectsDriftBetweenCaptureAndWrite()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            AppLockerPolicySnapshot drift = Snapshot("<AppLockerPolicy Version=\"1\"><external /></AppLockerPolicy>");
            Assert.IsFalse(PocMutationAuthorization.TryAuthorize(journal, restore: false, drift, "proof", out _));
            Assert.IsFalse(PocMutationAuthorization.TryAuthorize(journal, restore: true, drift, "proof", out _));
        }

        [TestMethod]
        public async Task CaptureOnlyProbeIsUnavailableUntilInteractiveFixtureEvidenceExists()
        {
            RecordingRunner runner = new();
            NativePocPolicyGateway gateway = new(runner);
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.ProbeAsync(CancellationToken.None));
            Assert.HasCount(0, runner.Requests);
        }

        private sealed class RecordingRunner : IWindowsCommandRunner
        {
            public List<WindowsCommandRequest> Requests { get; } = [];
            public Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken)
            {
                Requests.Add(request);
                return Task.FromResult(new WindowsCommandResult(PowerShellCommandRunner.ParseSnapshot(PowerShellCommandRunnerTests.Complete)));
            }
        }

        private static AppLockerPolicySnapshot Snapshot(string xml)
        {
            return new(Now, xml, xml, PolicyPresence.Absent, PolicyPresence.Absent, true, true);
        }
    }
}
