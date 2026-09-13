using Guard.WindowsPoc.Execution;
using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;
using Guard.WindowsPoc.Tests.Native;
using System.Text.Json.Nodes;

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
                Task.FromResult<IPocMutationAuthorization>(new FakeAuthorization(journal, restore,
                    restore ? First.RawLocalPolicySha256! : Empty.RawLocalPolicySha256!,
                    restore ? journal.InitialBaseline.LocalHash : journal.After.LocalHash,
                    restore ? journal.InitialBaseline.LocalPolicyXml : journal.After.LocalPolicyXml)));
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
            Assert.IsFalse(drift.SamePolicy(journal.Before));
            Assert.IsFalse(journal.Recognizes(drift));
        }

        [TestMethod]
        public async Task CapturePreservesTransportedRawPolicyHashAcrossEquivalentFormatting()
        {
            const string formattedEmpty = "<AppLockerPolicy Version=\"1\"></AppLockerPolicy>";
            const string rawHash = "00C785D262C6873D62CC0FDFCC5F120D91EC687939708E3BDCB0AB136F0918C4";
            JsonObject input = JsonNode.Parse(PowerShellCommandRunnerTests.Complete)!.AsObject();
            input["LocalPolicyXml"] = formattedEmpty;
            input["RawLocalPolicySha256"] = rawHash;
            RecordingRunner runner = new(input.ToJsonString());
            AppLockerPolicySnapshot snapshot = await new NativePocPolicyGateway(runner).CaptureAsync(CancellationToken.None);
            Assert.AreEqual(rawHash, snapshot.RawLocalPolicySha256);
            Assert.AreNotEqual(snapshot.LocalHash, snapshot.RawLocalPolicySha256);
        }

        [TestMethod]
        public async Task CaptureOnlyProbeIsUnavailableUntilInteractiveFixtureEvidenceExists()
        {
            RecordingRunner runner = new();
            NativePocPolicyGateway gateway = new(runner);
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.ProbeAsync(CancellationToken.None));
            Assert.HasCount(0, runner.Requests);
        }

        private sealed class RecordingRunner(string captureJson) : IWindowsCommandRunner
        {
            public List<WindowsCommandRequest> Requests { get; } = [];
            public RecordingRunner() : this(PowerShellCommandRunnerTests.Complete) { }
            public Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken)
            {
                Requests.Add(request);
                return Task.FromResult(new WindowsCommandResult(PowerShellCommandRunner.ParseSnapshot(captureJson)));
            }
        }

        private static AppLockerPolicySnapshot Snapshot(string xml)
        {
            return new(Now, xml, xml, PolicyPresence.Absent, PolicyPresence.Absent, true, true)
            { RawLocalPolicySha256 = PolicyMutationDecision.Hash(xml) };
        }

        private sealed record FakeAuthorization(PocTransactionJournal Journal, bool Restore, string ExpectedCurrentSha256,
            string ExpectedPayloadSha256, string PayloadXml) : IPocMutationAuthorization;
    }
}
