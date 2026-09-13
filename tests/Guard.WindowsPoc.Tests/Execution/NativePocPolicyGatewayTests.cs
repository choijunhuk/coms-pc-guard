using Guard.WindowsPoc.Execution;
using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;
using Guard.WindowsPoc.Tests.Native;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class NativePocPolicyGatewayTests
    {
        private static readonly DateTimeOffset Now = new(2026, 9, 13, 0, 0, 0, TimeSpan.Zero);
        private const string Owner = "S-1-5-21-1-2-3-1001";
        private const string FixturePath = @"C:\ComsPcGuardPoc\Fixtures\target.exe";
        private static readonly string FixtureHash = new('A', 64);
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
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            await WithGatewayAsync(journal, CompleteFor(Empty.LocalPolicyXml), async (gateway, runner) =>
            {
                await gateway.WriteAsync(journal, restore: false, CancellationToken.None);
                Assert.AreEqual(WindowsCommand.Capture, runner.Requests[0].Command);
                Assert.AreEqual(WindowsCommand.Apply, runner.Requests[1].Command);
                Assert.AreSame(journal, runner.Requests[1].Authorization!.Journal);
                Assert.AreEqual(runner.Requests[1].Authorization!.ExpectedCurrentSha256, Empty.RawLocalPolicySha256);
                Assert.AreEqual(runner.Requests[1].Authorization!.ExpectedPayloadSha256, journal.After.LocalHash);
            });
            await WithGatewayAsync(journal, CompleteFor(First.LocalPolicyXml), async (gateway, runner) =>
            {
                await gateway.WriteAsync(journal, restore: true, CancellationToken.None);
                Assert.AreEqual(WindowsCommand.Capture, runner.Requests[0].Command);
                Assert.AreEqual(WindowsCommand.Restore, runner.Requests[1].Command);
                Assert.AreSame(journal, runner.Requests[1].Authorization!.Journal);
                Assert.AreEqual(runner.Requests[1].Authorization!.ExpectedCurrentSha256, PolicyMutationDecision.Hash(First.LocalPolicyXml));
                Assert.AreEqual(runner.Requests[1].Authorization!.ExpectedPayloadSha256, journal.InitialBaseline.LocalHash);
            });
        }

        [TestMethod]
        public async Task ProtectedAuthorizationRejectsDriftBetweenCaptureAndWrite()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            AppLockerPolicySnapshot drift = Snapshot("<AppLockerPolicy Version=\"1\"><external /></AppLockerPolicy>");
            Assert.IsFalse(drift.SamePolicy(journal.Before));
            Assert.IsFalse(journal.Recognizes(drift));
            await WithGatewayAsync(journal, CompleteFor(drift.LocalPolicyXml), async (gateway, runner) =>
            {
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.WriteAsync(journal, restore: false, CancellationToken.None));
                Assert.AreEqual(WindowsCommand.Capture, runner.Requests.Single().Command);
            });
        }

        [TestMethod]
        public async Task ProductionAuthorityRefusesOutsideHeldPolicyGate()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            try
            {
                WindowsPocStateLease lease = WindowsPocStateLease.Open(Owner,
                    () => [new(false, Owner, true, false)],
                    () => new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 1), Evidence);
                using DurablePocJournalStore store = new(lease);
                await store.SaveAsync(journal, CancellationToken.None);
                PocProtectedMutationAuthority authority = Authority(lease, store, journal);
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => authority.AuthorizeAsync(journal, restore: false, Empty, CancellationToken.None));
            }
            finally { File.Delete(path); }
        }

        [TestMethod]
        public async Task ProductionAuthorityRequiresDurableWritePendingJournalAndFreshRawInventory()
        {
            PocTransactionJournal prepared = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now);
            await WithGatewayAsync(prepared, CompleteFor(Empty.LocalPolicyXml), async (gateway, runner) =>
            {
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.WriteAsync(prepared, restore: false, CancellationToken.None));
            });
            PocTransactionJournal journal = prepared.WithPhase(PocJournalPhase.WritePending);
            JsonObject stale = JsonNode.Parse(CompleteFor(Empty.LocalPolicyXml))!.AsObject();
            stale["CapturedAtUtc"] = Now.AddSeconds(-16);
            await WithGatewayAsync(journal, stale.ToJsonString(), async (gateway, runner) =>
            {
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.WriteAsync(journal, restore: false, CancellationToken.None));
            });
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

        private static async Task WithGatewayAsync(PocTransactionJournal journal, string captureJson,
            Func<NativePocPolicyGateway, RecordingRunner, Task> action)
        {
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            try
            {
                WindowsPocStateLease lease = WindowsPocStateLease.Open(Owner,
                    () => [new(false, Owner, true, false)],
                    () => new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 1), Evidence);
                using DurablePocJournalStore store = new(lease);
                await store.SaveAsync(journal, CancellationToken.None);
                RecordingRunner runner = new(captureJson);
                NativePocPolicyGateway gateway = new(runner, Authority(lease, store, journal));
                CrossProcessPolicyGate gate = new(() => new ImmediateMutex(), TimeSpan.FromSeconds(2), Owner);
                _ = await gate.RunAsync<object?>(async () =>
                {
                    await action(gateway, runner);
                    return null;
                }, CancellationToken.None);
            }
            finally { File.Delete(path); }
        }

        private static PocProtectedMutationAuthority Authority(WindowsPocStateLease lease, DurablePocJournalStore store, PocTransactionJournal journal)
        {
            return new(CapabilityForTest(), lease, store,
                new PolicyMutationDecision(true, journal.After.LocalPolicyXml, FixturePath, FixtureHash),
                new VmAttestationResult(true, true), elevated: true, FixturePath, FixtureHash, new FixedClock());
        }

        private static string CompleteFor(string xml)
        {
            JsonObject input = JsonNode.Parse(PowerShellCommandRunnerTests.Complete)!.AsObject();
            input["LocalPolicyXml"] = xml;
            input["EffectivePolicyXml"] = xml;
            input["RawLocalPolicySha256"] = PolicyMutationDecision.Hash(xml);
            return input.ToJsonString();
        }

        private static StateFileEvidence Evidence(FileStream file)
        {
            file.Position = 0;
            return new(Convert.ToHexString(SHA256.HashData(file)), file.Length, File.GetLastWriteTimeUtc(file.SafeFileHandle));
        }

        private static OwnerTokenPolicyGateCapability CapabilityForTest()
        {
            const string nonce = "0123456789abcdef0123456789abcdef";
            const string vmName = "COMS-PC-Guard-x64-Lab";
            string vmHash = new('a', 64);
            ConstructorInfo constructor = typeof(OwnerTokenPolicyGateCapability).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null, [typeof(string), typeof(string), typeof(string), typeof(string), typeof(Func<OwnerTokenAttestationContext>)], modifiers: null)
                ?? throw new InvalidOperationException("Expected private capability constructor.");
            OwnerTokenPolicyGateCapability capability = (OwnerTokenPolicyGateCapability)constructor.Invoke(
                [Owner, nonce, vmName, vmHash, () => new OwnerTokenAttestationContext(Owner, false, true, null)]);
            _ = capability.Revalidate();
            return capability;
        }

        private sealed class FixedClock : TimeProvider
        {
            public override DateTimeOffset GetUtcNow()
            {
                return Now;
            }
        }

        private sealed class ImmediateMutex : IPolicyMutex
        {
            public bool Wait(TimeSpan timeout, CancellationToken token) { return true; }
            public void Validate() { }
            public void Release() { }
            public void Dispose() { }
        }
    }
}
