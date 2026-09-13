using Guard.WindowsPoc.Execution;
using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;
using Guard.WindowsPoc.Tests.Native;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class NativePocPolicyGatewayTests
    {
        private static readonly DateTimeOffset Now = new(2026, 9, 13, 0, 0, 0, TimeSpan.Zero);
        private const string Owner = "S-1-5-21-1-2-3-1001";
        private const string FixturePath = @"C:\ComsPcGuardPoc\Fixtures\target.exe";
        private const string ControlPath = @"C:\ComsPcGuardPoc\Fixtures\control.exe";
        private const string DecisionRevision = "D000000000000000000000000000000000000000000000000000000000000001";
        private static readonly byte[] FixtureBytes = Encoding.UTF8.GetBytes("target-fixture");
        private static readonly byte[] ControlBytes = Encoding.UTF8.GetBytes("control-fixture");
        private static readonly string FixtureHash = Convert.ToHexString(SHA256.HashData(FixtureBytes));
        private static readonly string ControlHash = Convert.ToHexString(SHA256.HashData(ControlBytes));
        private static readonly AppLockerPolicySnapshot Empty = Snapshot("<AppLockerPolicy Version=\"1\" />");
        private static readonly AppLockerPolicySnapshot First = Snapshot("<AppLockerPolicy Version=\"1\"><RuleCollection Type=\"Exe\" EnforcementMode=\"AuditOnly\" /></AppLockerPolicy>");
        private static readonly string[] AuthenticodeEnvironmentKeys = ["COMS_POC_FIXTURE_PATH", "PSModulePath", "SystemRoot", "WINDIR"];
        private static readonly string[] ProductionFixtureLeaseFactoryNames = ["Open"];
        private static readonly string FixtureScratchRoot = Path.Combine(Environment.CurrentDirectory, "poc-fixture-tests");

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
        public void CommandRequestsRejectApplyRestoreAuthorizationMismatch()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            IPocMutationAuthorization apply = new FakeAuthorization(journal, Restore: false, Empty.RawLocalPolicySha256!, journal.After.LocalHash, journal.After.LocalPolicyXml);
            IPocMutationAuthorization restore = new FakeAuthorization(journal, Restore: true, First.RawLocalPolicySha256!, journal.InitialBaseline.LocalHash, journal.InitialBaseline.LocalPolicyXml);
            Assert.AreEqual(WindowsCommand.Apply, WindowsCommandRequest.Apply(apply).Command);
            Assert.AreEqual(WindowsCommand.Restore, WindowsCommandRequest.Restore(restore).Command);
            _ = Assert.ThrowsExactly<ArgumentException>(() => WindowsCommandRequest.Apply(restore));
            _ = Assert.ThrowsExactly<ArgumentException>(() => WindowsCommandRequest.Restore(apply));
        }

        [TestMethod]
        public async Task FakePolicyGateCannotSatisfyProductionMutationAuthority()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            await WithGatewayAsync(journal, CompleteFor(Empty.LocalPolicyXml), async (gateway, runner) =>
            {
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.WriteAsync(journal, restore: false, CancellationToken.None));
                Assert.HasCount(0, runner.Requests);
            }, holdProtectedGate: false);
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
        public async Task NativeGatewayPrearmsFailClosedBeforeInternalCaptureRecheck()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            AppLockerPolicySnapshot drift = Snapshot("<AppLockerPolicy Version=\"1\"><external /></AppLockerPolicy>");
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            try
            {
                WindowsPocStateLease lease = WindowsPocStateLease.Open(Owner,
                    () => [new(false, Owner, true, false)],
                    () => new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 1), Evidence);
                using DurablePocJournalStore store = new(lease);
                await store.SaveAsync(journal.WithPhase(PocJournalPhase.Prepared), CancellationToken.None);
                await store.SaveAsync(journal, CancellationToken.None);
                await store.SetRecoveryBarrierAsync(PocRecoveryBarrier.ValidationComplete, CancellationToken.None);
                OwnerTokenPolicyGateCapability capability = CapabilityForTest();
                RecordingRunner runner = new(CompleteFor(drift.LocalPolicyXml));
                NativePocPolicyGateway gateway = new(runner, Authority(lease, store, journal, capability: capability));
                CrossProcessPolicyGate gate = new(() => new ImmediateMutex(), TimeSpan.FromSeconds(2));
                typeof(CrossProcessPolicyGate).GetField("_heldCapability", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .SetValue(gate, capability);
                _ = await gate.RunAsync<object?>(async () =>
                {
                    _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.WriteAsync(journal, restore: false, CancellationToken.None));
                    return null;
                }, CancellationToken.None);
                Assert.AreEqual(PocRecoveryBarrier.Capture, await store.ReadRecoveryBarrierAsync(CancellationToken.None));
            }
            finally { File.Delete(path); }
        }

        [TestMethod]
        public async Task NativeGatewayLeavesWriteInFlightBarrierWhenMutationScriptReportsDrift()
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
                await store.SaveAsync(journal.WithPhase(PocJournalPhase.Prepared), CancellationToken.None);
                await store.SaveAsync(journal, CancellationToken.None);
                await store.SetRecoveryBarrierAsync(PocRecoveryBarrier.ValidationComplete, CancellationToken.None);
                DriftOnMutationRunner runner = new();
                _ = await Assert.ThrowsAsync<PocPolicyDriftException>(() => NativePocPolicyWriteOrchestrator.WriteAsync(runner,
                    new StoreBackedFakeAuthority(store), ConvertForTest, journal, restore: false, CancellationToken.None));
                Assert.AreEqual(PocRecoveryBarrier.NativeWriteInFlight, await store.ReadRecoveryBarrierAsync(CancellationToken.None));
            }
            finally { File.Delete(path); }
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
        public async Task ProductionAuthorityRefusesAfterPolicyGateScopeIsReleased()
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
                await store.SaveAsync(journal.WithPhase(PocJournalPhase.Prepared), CancellationToken.None);
                await store.SaveAsync(journal, CancellationToken.None);
                await store.SetRecoveryBarrierAsync(PocRecoveryBarrier.ValidationComplete, CancellationToken.None);
                OwnerTokenPolicyGateCapability capability = CapabilityForTest();
                RecordingRunner runner = new(CompleteFor(Empty.LocalPolicyXml));
                NativePocPolicyGateway gateway = new(runner, Authority(lease, store, journal, capability: capability));
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.WriteAsync(journal, restore: false, CancellationToken.None));
                Assert.HasCount(0, runner.Requests);
            }
            finally { File.Delete(path); }
        }

        [TestMethod]
        public void ProductionAuthorityRequiresJournalStoreBackedBySameRetainedLease()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            string leasePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            string otherPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            try
            {
                using WindowsPocStateLease lease = WindowsPocStateLease.Open(Owner,
                    () => [new(false, Owner, true, false)],
                    () => new FileStream(leasePath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 1), Evidence);
                using FileStream other = new(otherPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 1);
                using DurablePocJournalStore store = new(other);
                _ = Assert.ThrowsExactly<InvalidOperationException>(() => Authority(lease, store, journal));
            }
            finally
            {
                File.Delete(leasePath);
                File.Delete(otherPath);
            }
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
        public async Task ProductionAuthorityRejectsDirectWritePendingWithoutPreparedHistory()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            await WithGatewayAsync(journal, CompleteFor(Empty.LocalPolicyXml), async (gateway, runner) =>
            {
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.WriteAsync(journal, restore: false, CancellationToken.None));
                Assert.AreEqual(WindowsCommand.Capture, runner.Requests.Single().Command);
            }, savePreparedFirst: false, armRecoveryBarrier: true);
        }

        [TestMethod]
        public async Task ProductionAuthorityRequiresArmedRecoveryBarrierAndNoHostRecoveryLatch()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            await WithGatewayAsync(journal, CompleteFor(Empty.LocalPolicyXml), async (gateway, runner) =>
            {
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.WriteAsync(journal, restore: false, CancellationToken.None));
            }, savePreparedFirst: true, armRecoveryBarrier: false);
            await WithGatewayAsync(journal, CompleteFor(Empty.LocalPolicyXml), async (gateway, runner) =>
            {
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.WriteAsync(journal, restore: false, CancellationToken.None));
            }, savePreparedFirst: true, armRecoveryBarrier: true, hostRecoveryLatch: true);
        }

        [TestMethod]
        public async Task ProductionAuthorityRejectsLegacyBooleanBarrierAsUnknownFailClosed()
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
                await store.SaveAsync(journal.WithPhase(PocJournalPhase.Prepared), CancellationToken.None);
                await store.SaveAsync(journal, CancellationToken.None);
                await store.SetRecoveryBarrierAsync(true, CancellationToken.None);
                Assert.AreEqual(PocRecoveryBarrier.UnknownFailClosed, await store.ReadRecoveryBarrierAsync(CancellationToken.None));
                OwnerTokenPolicyGateCapability capability = CapabilityForTest();
                RecordingRunner runner = new(CompleteFor(Empty.LocalPolicyXml));
                NativePocPolicyGateway gateway = new(runner, Authority(lease, store, journal, capability: capability));
                CrossProcessPolicyGate gate = new(() => new ImmediateMutex(), TimeSpan.FromSeconds(2));
                typeof(CrossProcessPolicyGate).GetField("_heldCapability", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .SetValue(gate, capability);
                _ = await gate.RunAsync<object?>(async () =>
                {
                    _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.WriteAsync(journal, restore: false, CancellationToken.None));
                    return null;
                }, CancellationToken.None);
            }
            finally { File.Delete(path); }
        }

        [TestMethod]
        public async Task ProductionAuthorityBindsCurrentInventoryRevisionToDecisionRevision()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            JsonObject capture = JsonNode.Parse(CompleteFor(Empty.LocalPolicyXml))!.AsObject();
            capture["Revision"] = "D000000000000000000000000000000000000000000000000000000000000002";
            await WithGatewayAsync(journal, capture.ToJsonString(), async (gateway, runner) =>
            {
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.WriteAsync(journal, restore: false, CancellationToken.None));
            }, savePreparedFirst: true, armRecoveryBarrier: true);
        }

        [TestMethod]
        public async Task RestoreAuthorizationAllowsRecognizedAppliedPolicyWithDifferentContentRevision()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, First, Empty, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            RecordingRunner runner = new(CompleteFor(First.LocalPolicyXml, "E000000000000000000000000000000000000000000000000000000000000001"));
            await NativePocPolicyWriteOrchestrator.WriteAsync(runner, new PassthroughFakeAuthority(), ConvertForTest,
                journal, restore: true, CancellationToken.None);
            CollectionAssert.AreEqual(new[] { WindowsCommand.Capture, WindowsCommand.Restore }, runner.Requests.Select(request => request.Command).ToArray());
        }

        [TestMethod]
        public void ProductionGatewayConstructorsDoNotAcceptFakeAuthorityInterfaces()
        {
            ConstructorInfo[] constructors = typeof(NativePocPolicyGateway)
                .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            Assert.IsFalse(constructors.Any(constructor => constructor.GetParameters()
                .Any(parameter => parameter.ParameterType == typeof(IPocProtectedMutationAuthority)
                    || parameter.ParameterType == typeof(IPocMutationAuthorization))));
            Assert.IsTrue(constructors.Any(constructor => constructor.GetParameters()
                .Any(parameter => parameter.ParameterType == typeof(PocProtectedMutationAuthority))));
        }

        [TestMethod]
        public void ProductionFixtureOpenRejectsHashSwapAfterDecisionWithoutPublisherEcho()
        {
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => OpenProductionFixtureLease(Encoding.UTF8.GetBytes("swapped-target-fixture")));
        }

        [TestMethod]
        public void FixtureLeaseDoesNotExposeInternalFactoryThatMintsProductionLeaseWithoutAuthenticode()
        {
            MethodInfo[] staticMethods = typeof(PocFixtureLease).GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
            CollectionAssert.AreEquivalent(ProductionFixtureLeaseFactoryNames, staticMethods
                .Where(method => method.ReturnType == typeof(PocFixtureLease))
                .Select(method => method.Name)
                .ToArray());
            Assert.IsFalse(typeof(PocFixtureLease).GetNestedTypes(BindingFlags.Public | BindingFlags.NonPublic)
                .Any(type => type.Name.Contains("TestHook", StringComparison.OrdinalIgnoreCase)
                    || type.Name.Contains("DelegatePublisher", StringComparison.OrdinalIgnoreCase)));
            Assert.IsFalse(staticMethods.Any(method => method.Name.Contains("ForTest", StringComparison.OrdinalIgnoreCase)));
        }

        [TestMethod]
        public async Task ProductionAuthorityRejectsFixtureSwapAfterDecision()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, Empty, First, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            byte[] currentTargetBytes = Encoding.UTF8.GetBytes("swapped-target-fixture");
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => WithGatewayAsync(journal, CompleteFor(Empty.LocalPolicyXml), async (gateway, runner) =>
            {
                await gateway.WriteAsync(journal, restore: false, CancellationToken.None);
            }, savePreparedFirst: true, armRecoveryBarrier: true, targetBytes: currentTargetBytes));
        }

        [TestMethod]
        public void FixtureLeaseDoesNotExposeCallerStreamOrPublisherFuncConstructor()
        {
            ConstructorInfo[] constructors = typeof(PocFixtureLease)
                .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            Assert.IsFalse(constructors.Any(constructor => constructor.GetParameters()
                .Any(parameter => parameter.ParameterType == typeof(Stream)
                    || (parameter.ParameterType.IsGenericType && parameter.ParameterType.GetGenericTypeDefinition() == typeof(Func<>)))));
        }

        [TestMethod]
        public void FixtureLeaseRejectsCallerEchoPublisherWhenRetainedTargetIdentityDiffers()
        {
            byte[] replacement = Encoding.UTF8.GetBytes("replacement-target");
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => FileFixtureLease(replacement));
        }

        [TestMethod]
        public void ProductionFixtureOpenRejectsMissingCanonicalTargetBeforePublisherEvidence()
        {
            _ = Directory.CreateDirectory(FixtureScratchRoot);
            string controlPath = Path.Combine(FixtureScratchRoot, Guid.NewGuid().ToString("N") + "-control.exe");
            File.WriteAllBytes(controlPath, ControlBytes);
            PocFixtureLeaseEvidence evidence = FixtureEvidence(
                Path.Combine(FixtureScratchRoot, Guid.NewGuid().ToString("N") + "-other-target.exe"), controlPath);
            try
            {
                _ = PocFixtureLease.Open(evidence);
                Assert.Fail("Expected fixture open failure.");
            }
            catch (IOException) { }
            File.Delete(controlPath);
        }

        [TestMethod]
        public void ProductionFixtureOpenRetainsReadHandleThatDeniesWritersAndDeleteOnWindows()
        {
            if (!OperatingSystem.IsWindows()) { return; }
            _ = Directory.CreateDirectory(FixtureScratchRoot);
            string targetPath = Path.Combine(FixtureScratchRoot, Guid.NewGuid().ToString("N") + "-target.exe");
            string controlPath = Path.Combine(FixtureScratchRoot, Guid.NewGuid().ToString("N") + "-control.exe");
            File.WriteAllBytes(targetPath, FixtureBytes);
            File.WriteAllBytes(controlPath, ControlBytes);
            try
            {
                using PocFixtureLease lease = PocFixtureLease.Open(FixtureEvidence(targetPath, controlPath));
                _ = Assert.ThrowsExactly<IOException>(() => File.Delete(targetPath));
                _ = Assert.ThrowsExactly<IOException>(() => { using FileStream other = new(targetPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); });
            }
            finally
            {
                File.Delete(targetPath);
                File.Delete(controlPath);
            }
        }

        [TestMethod]
        public void ProductionFixtureOpenRejectsReparsePathBeforeTrustingPublisherEvidence()
        {
            if (OperatingSystem.IsWindows()) { return; }
            string realTargetPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + "-target-real.exe");
            string targetLinkPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + "-target-link.exe");
            string controlPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + "-control.exe");
            try
            {
                File.WriteAllBytes(realTargetPath, FixtureBytes);
                File.WriteAllBytes(controlPath, ControlBytes);
                _ = File.CreateSymbolicLink(targetLinkPath, realTargetPath);
                _ = Assert.ThrowsExactly<InvalidOperationException>(() => PocFixtureLease.Open(FixtureEvidence(targetLinkPath, controlPath)));
            }
            finally
            {
                File.Delete(targetLinkPath);
                File.Delete(realTargetPath);
                File.Delete(controlPath);
            }
        }

        [TestMethod]
        public void ProductionFixtureOpenRejectsReparseAncestorBeforeTrustingPublisherEvidence()
        {
            if (OperatingSystem.IsWindows()) { return; }
            string realDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + "-real");
            string linkDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + "-link");
            string controlPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + "-control.exe");
            try
            {
                _ = Directory.CreateDirectory(realDirectory);
                string targetPath = Path.Combine(realDirectory, "target.exe");
                string targetLinkPath = Path.Combine(linkDirectory, "target.exe");
                File.WriteAllBytes(targetPath, FixtureBytes);
                File.WriteAllBytes(controlPath, ControlBytes);
                _ = Directory.CreateSymbolicLink(linkDirectory, realDirectory);
                _ = Assert.ThrowsExactly<InvalidOperationException>(() => PocFixtureLease.Open(FixtureEvidence(targetLinkPath, controlPath)));
            }
            finally
            {
                Directory.Delete(linkDirectory);
                Directory.Delete(realDirectory, recursive: true);
                File.Delete(controlPath);
            }
        }

        [TestMethod]
        public void AuthenticodeVerifierUsesFixedPowerShellAndEncodedCommandWithBoundedEnvironment()
        {
            ProcessStartInfo info = PocFixtureLease.CreateAuthenticodeStartInfo(@"C:\ComsPcGuardPoc\Fixtures\target.exe");
            Assert.AreEqual(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", info.FileName);
            CollectionAssert.DoesNotContain(info.ArgumentList.ToArray(), "-Command");
            CollectionAssert.Contains(info.ArgumentList.ToArray(), "-EncodedCommand");
            Assert.IsTrue(info.ArgumentList.All(argument => !argument.Contains("target.exe", StringComparison.OrdinalIgnoreCase)));
            CollectionAssert.AreEquivalent(AuthenticodeEnvironmentKeys, info.Environment.Keys.ToArray());
            Assert.AreEqual(@"C:\Windows\System32", info.WorkingDirectory);
        }

        [TestMethod]
        public void NativeFixtureCaptureRefusesOutsideWindows()
        {
            if (!OperatingSystem.IsWindows())
            { _ = Assert.ThrowsExactly<PlatformNotSupportedException>(() => PocFixtureLease.ReadNativeEvidence(DecisionRevision)); }
        }

        [TestMethod]
        public void AuthenticodeProcessReaderFailsClosedOnStdoutOverflowBeforeExit()
        {
            if (OperatingSystem.IsWindows()) { return; }
            ProcessStartInfo info = ShellProcess("python3 - <<'PY'\nprint('x' * 20000)\nPY");
            _ = Assert.ThrowsExactly<InvalidOperationException>(() =>
                PocFixtureLease.ExecuteAuthenticodeProcess(info, TimeSpan.FromSeconds(5), maxChars: 1024));
        }

        [TestMethod]
        public void AuthenticodeProcessReaderFailsClosedOnEndlessStderr()
        {
            if (OperatingSystem.IsWindows()) { return; }
            ProcessStartInfo info = ShellProcess("while true; do printf x >&2; done");
            _ = Assert.ThrowsExactly<InvalidOperationException>(() =>
                PocFixtureLease.ExecuteAuthenticodeProcess(info, TimeSpan.FromSeconds(1), maxChars: 4096));
        }

        [TestMethod]
        public void AuthenticodeProcessReaderFailsClosedWhenChildKeepsPipeOpenAfterParentExit()
        {
            if (OperatingSystem.IsWindows()) { return; }
            ProcessStartInfo info = ShellProcess("(sleep 5; printf late)& printf parent");
            _ = Assert.ThrowsExactly<InvalidOperationException>(() =>
                PocFixtureLease.ExecuteAuthenticodeProcess(info, TimeSpan.FromMilliseconds(300), maxChars: 4096));
        }

        [TestMethod]
        public async Task ProductionAuthorityRejectsFixtureSwapBeforeRestore()
        {
            PocTransactionJournal journal = PocTransactionJournal.Prepare(Empty, First, Empty, "owner-proof", "lease", Now)
                .WithPhase(PocJournalPhase.WritePending);
            byte[] currentTargetBytes = Encoding.UTF8.GetBytes("swapped-target-fixture");
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => WithGatewayAsync(journal, CompleteFor(First.LocalPolicyXml), async (gateway, runner) =>
            {
                await gateway.WriteAsync(journal, restore: true, CancellationToken.None);
            }, savePreparedFirst: true, armRecoveryBarrier: true, targetBytes: currentTargetBytes));
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

        private sealed class DriftOnMutationRunner : IWindowsCommandRunner
        {
            public Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken)
            {
                return request.Command == WindowsCommand.Capture
                    ? Task.FromResult(new WindowsCommandResult(PowerShellCommandRunner.ParseSnapshot(CompleteFor(Empty.LocalPolicyXml))))
                    : Task.FromException<WindowsCommandResult>(new PocPolicyDriftException());
            }
        }

        private static ProcessStartInfo ShellProcess(string script)
        {
            ProcessStartInfo info = new("/bin/sh")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            info.ArgumentList.Add("-c");
            info.ArgumentList.Add(script);
            return info;
        }

        private static AppLockerPolicySnapshot Snapshot(string xml)
        {
            return new(Now, xml, xml, PolicyPresence.Absent, PolicyPresence.Absent, true, true)
            { RawLocalPolicySha256 = PolicyMutationDecision.Hash(xml) };
        }

        private static AppLockerPolicySnapshot ConvertForTest(WindowsCommandResult result)
        {
            AppLockerNativeSnapshot snapshot = result.Snapshot is { IsComplete: true } complete
                ? complete : throw new InvalidOperationException("Native inventory unavailable.");
            return new(snapshot.CapturedAtUtc, snapshot.LocalPolicyXml, snapshot.EffectivePolicyXml!,
                snapshot.Inventory.CspMdm, snapshot.Inventory.Wdac, snapshot.AppIdServiceRunning, snapshot.AppIdServiceAutomatic)
            { NativeRevision = snapshot.Revision, RawLocalPolicySha256 = snapshot.RawLocalPolicySha256 };
        }

        private static async Task WithGatewayAsync(PocTransactionJournal journal, string captureJson,
            Func<NativePocPolicyGateway, RecordingRunner, Task> action, bool savePreparedFirst = true,
            bool armRecoveryBarrier = true, bool hostRecoveryLatch = false, byte[]? targetBytes = null, byte[]? controlBytes = null,
            bool holdProtectedGate = true)
        {
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            try
            {
                WindowsPocStateLease lease = WindowsPocStateLease.Open(Owner,
                    () => [new(false, Owner, true, false)],
                    () => new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 1), Evidence);
                using DurablePocJournalStore store = new(lease);
                if (savePreparedFirst) { await store.SaveAsync(journal.WithPhase(PocJournalPhase.Prepared), CancellationToken.None); }
                await store.SaveAsync(journal, CancellationToken.None);
                if (armRecoveryBarrier) { await store.SetRecoveryBarrierAsync(PocRecoveryBarrier.ValidationComplete, CancellationToken.None); }
                if (hostRecoveryLatch) { await store.SetHostRecoveryRequiredAsync(CancellationToken.None); }
                OwnerTokenPolicyGateCapability capability = CapabilityForTest();
                RecordingRunner runner = new(captureJson);
                NativePocPolicyGateway gateway = new(runner, Authority(lease, store, journal, targetBytes, controlBytes, capability));
                _ = holdProtectedGate;
                CrossProcessPolicyGate gate = new(() => new ImmediateMutex(), TimeSpan.FromSeconds(2));
                if (holdProtectedGate)
                {
                    typeof(CrossProcessPolicyGate).GetField("_heldCapability", BindingFlags.Instance | BindingFlags.NonPublic)!
                        .SetValue(gate, capability);
                }
                _ = await gate.RunAsync<object?>(async () =>
                {
                    await action(gateway, runner);
                    return null;
                }, CancellationToken.None);
            }
            finally { File.Delete(path); }
        }

        private static PocProtectedMutationAuthority Authority(WindowsPocStateLease lease, DurablePocJournalStore store,
            PocTransactionJournal journal, byte[]? targetBytes = null, byte[]? controlBytes = null, OwnerTokenPolicyGateCapability? capability = null)
        {
            (PocFixtureLease fixtureLease, PocFixtureLeaseEvidence fixtureEvidence) = FileFixtureLease(targetBytes, controlBytes);
            return new(capability ?? CapabilityForTest(), lease, store,
                new PolicyMutationDecision(true, journal.After.LocalPolicyXml, fixtureEvidence.TargetPath, fixtureEvidence.TargetSha256, DecisionRevision),
                new VmAttestationResult(true, true), elevated: true, fixtureLease, new FixedClock());
        }

        private static (PocFixtureLease Lease, PocFixtureLeaseEvidence Evidence) FileFixtureLease(byte[]? targetBytes = null, byte[]? controlBytes = null)
        {
            _ = Directory.CreateDirectory(FixtureScratchRoot);
            string targetPath = Path.Combine(FixtureScratchRoot, Guid.NewGuid().ToString("N") + "-target.exe");
            string controlPath = Path.Combine(FixtureScratchRoot, Guid.NewGuid().ToString("N") + "-control.exe");
            PocFixtureLeaseEvidence evidence = FixtureEvidence(targetPath, controlPath);
            File.WriteAllBytes(targetPath, targetBytes ?? FixtureBytes);
            File.WriteAllBytes(controlPath, controlBytes ?? ControlBytes);
            return (PocFixtureLease.Open(evidence), evidence);
        }

        private static PocFixtureLease OpenProductionFixtureLease(byte[]? targetBytes = null, byte[]? controlBytes = null)
        {
            return FileFixtureLease(targetBytes, controlBytes).Lease;
        }

        private static PocFixtureLeaseEvidence FixtureEvidence(string targetPath = FixturePath, string controlPath = ControlPath)
        {
            return new(targetPath, FixtureHash, controlPath, ControlHash,
                new("CN=COMS Test", "Harmless", "target.exe", new(1, 0, 0, 0), new(1, 0, 0, 0)), DecisionRevision);
        }

        private static string CompleteFor(string xml, string? revision = null)
        {
            JsonObject input = JsonNode.Parse(PowerShellCommandRunnerTests.Complete)!.AsObject();
            input["LocalPolicyXml"] = xml;
            input["EffectivePolicyXml"] = xml;
            input["RawLocalPolicySha256"] = PolicyMutationDecision.Hash(xml);
            input["Revision"] = revision ?? DecisionRevision;
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

        private sealed class StoreBackedFakeAuthority(DurablePocJournalStore store) : IPocProtectedMutationAuthority
        {
            public Task PrearmNativeRecheckAsync(PocTransactionJournal journal, CancellationToken token)
            {
                return store.SetRecoveryBarrierAsync(PocRecoveryBarrier.Capture, token);
            }

            public Task<IPocMutationAuthorization> AuthorizeAsync(PocTransactionJournal journal, bool restore,
                AppLockerPolicySnapshot trustedCurrent, CancellationToken token)
            {
                return Task.FromResult<IPocMutationAuthorization>(new FakeAuthorization(journal, restore,
                    trustedCurrent.RawLocalPolicySha256!, restore ? journal.InitialBaseline.LocalHash : journal.After.LocalHash,
                    restore ? journal.InitialBaseline.LocalPolicyXml : journal.After.LocalPolicyXml));
            }

            public Task MarkNativeWriteInFlightAsync(PocTransactionJournal journal, CancellationToken token)
            {
                return store.SetRecoveryBarrierAsync(PocRecoveryBarrier.NativeWriteInFlight, token);
            }

            public Task MarkNativeWriteVerifiedAsync(PocTransactionJournal journal, CancellationToken token)
            {
                return store.SetRecoveryBarrierAsync(PocRecoveryBarrier.ValidationComplete, token);
            }
        }

        private sealed class PassthroughFakeAuthority : IPocProtectedMutationAuthority
        {
            public Task PrearmNativeRecheckAsync(PocTransactionJournal journal, CancellationToken token)
            {
                return Task.CompletedTask;
            }

            public Task<IPocMutationAuthorization> AuthorizeAsync(PocTransactionJournal journal, bool restore,
                AppLockerPolicySnapshot trustedCurrent, CancellationToken token)
            {
                return Task.FromResult<IPocMutationAuthorization>(new FakeAuthorization(journal, restore,
                    trustedCurrent.RawLocalPolicySha256!, restore ? journal.InitialBaseline.LocalHash : journal.After.LocalHash,
                    restore ? journal.InitialBaseline.LocalPolicyXml : journal.After.LocalPolicyXml));
            }

            public Task MarkNativeWriteInFlightAsync(PocTransactionJournal journal, CancellationToken token)
            {
                return Task.CompletedTask;
            }

            public Task MarkNativeWriteVerifiedAsync(PocTransactionJournal journal, CancellationToken token)
            {
                return Task.CompletedTask;
            }
        }

        private sealed record FakeAuthorization(PocTransactionJournal Journal, bool Restore, string ExpectedCurrentSha256,
            string ExpectedPayloadSha256, string PayloadXml) : IPocMutationAuthorization
        {
            public void Revalidate() { }
        }
    }
}
