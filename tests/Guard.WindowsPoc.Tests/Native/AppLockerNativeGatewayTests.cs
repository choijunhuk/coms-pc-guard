using Guard.WindowsPoc.Evidence;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Tests.Safety;

namespace Guard.WindowsPoc.Tests.Native
{
    [TestClass]
    public sealed class AppLockerNativeGatewayTests
    {
        private sealed class ControlledRunner(Func<WindowsCommandRequest, CancellationToken, Task<WindowsCommandResult>> run) : IWindowsCommandRunner
        {
            public Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken)
            {
                return run(request, cancellationToken);
            }
        }

        private static AppLockerNativeGateway Portable(IWindowsCommandRunner runner, TimeSpan? timeout = null)
        {
            return new(runner, PolicyMutationGuardTests.Guard, PolicyMutationGuardTests.Attestation, true, static () => { }, timeout ?? TimeSpan.FromSeconds(2));
        }

        [TestMethod]
        public async Task InjectedRunnerReceivesCallerCancellation()
        {
            TaskCompletionSource started = new(TaskCreationOptions.RunContinuationsAsynchronously);
            CancellationToken observed = default;
            ControlledRunner runner = new(async (_, token) => { observed = token; started.SetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); return new(null); });
            using CancellationTokenSource caller = new();
            Task<AppLockerNativeSnapshot> capture = Portable(runner).CaptureAsync(caller.Token);
            await started.Task;
            caller.Cancel();
            _ = await Assert.ThrowsAsync<OperationCanceledException>(() => capture);
            Assert.IsTrue(observed.IsCancellationRequested);
        }

        [TestMethod]
        public async Task BoundsAnInjectedRunnerThatIgnoresCancellation()
        {
            CancellationToken observed = default;
            TaskCompletionSource<WindowsCommandResult> pending = new(TaskCreationOptions.RunContinuationsAsynchronously);
            ControlledRunner runner = new((_, token) => { observed = token; return pending.Task; });
            Task<AppLockerNativeSnapshot> capture = Portable(runner, TimeSpan.FromMilliseconds(30)).CaptureAsync();
            _ = await Assert.ThrowsAsync<OperationCanceledException>(() => capture.WaitAsync(TimeSpan.FromSeconds(3)));
            Assert.IsTrue(observed.IsCancellationRequested);
            pending.SetResult(new(PolicyMutationGuardTests.Snapshot));
        }

        [TestMethod]
        public async Task ValidAuthorizationStillCannotCrossJournalBarrier()
        {
            List<WindowsCommand> commands = [];
            ControlledRunner runner = new((request, _) => { commands.Add(request.Command); return Task.FromResult(new WindowsCommandResult(PolicyMutationGuardTests.Snapshot)); });
            Assert.IsTrue(PolicyMutationGuardTests.Guard.Evaluate(PolicyMutationGuardTests.Attestation, PolicyMutationGuardTests.Snapshot, true).Allowed);
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => Portable(runner).ApplyAsync(PolicyMutationGuardTests.Xml));
            CollectionAssert.AreEqual(new List<WindowsCommand> { WindowsCommand.Capture }, commands);
        }

        [TestMethod]
        public async Task CleanupAfterFailedOperationUsesIndependentTokenAndStillRefusesWrites()
        {
            using CancellationTokenSource caller = new();
            List<CancellationToken> tokens = [];
            ControlledRunner runner = new((request, token) =>
            {
                Assert.AreEqual(WindowsCommand.Capture, request.Command);
                tokens.Add(token);
                if (tokens.Count == 1) { caller.Cancel(); token.ThrowIfCancellationRequested(); }
                Assert.IsFalse(token.IsCancellationRequested);
                return Task.FromResult(new WindowsCommandResult(PolicyMutationGuardTests.Snapshot));
            });
            AppLockerNativeGateway gateway = Portable(runner);
            try { _ = await Assert.ThrowsAsync<OperationCanceledException>(() => gateway.ApplyAsync(PolicyMutationGuardTests.Xml, caller.Token)); }
            finally { _ = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.CleanupAsync(PolicyMutationGuardTests.Snapshot)); }
            Assert.HasCount(2, tokens);
            Assert.AreNotEqual(tokens[0], tokens[1]);
        }

        [TestMethod]
        public async Task IncompleteInjectedSnapshotBecomesControlledUnavailable()
        {
            ControlledRunner runner = new((_, _) => Task.FromResult(new WindowsCommandResult(PolicyMutationGuardTests.Snapshot with { Inventory = null! })));
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => Portable(runner).CaptureAsync());
        }

        [TestMethod]
        public async Task CompilerDecisionAloneCannotCreatePayloadBeforeJournalAuthorization()
        {
            WindowsPoc.Safety.PolicyMutationDecision decision = PolicyMutationGuardTests.Guard.Evaluate(
                PolicyMutationGuardTests.Attestation, PolicyMutationGuardTests.Snapshot, true);
            Assert.IsTrue(decision.Allowed);
            _ = await Assert.ThrowsAsync<InvalidOperationException>(() => PowerShellCommandRunner.CreateLockedPayloadAsync(
                new(WindowsCommand.Apply, PolicyMutationGuardTests.Xml, decision), CancellationToken.None));
        }

        [TestMethod]
        public async Task RefusesNativeCallsOnNonWindows()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            AppLockerNativeGateway gateway = new(new PowerShellCommandRunner(), PolicyMutationGuardTests.Guard, PolicyMutationGuardTests.Attestation, true);
            _ = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => gateway.CaptureAsync());
            _ = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => gateway.ApplyAsync(PolicyMutationGuardTests.Xml));
            _ = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => gateway.ObserveAsync());
            _ = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => gateway.RestoreAsync(PolicyMutationGuardTests.Snapshot));
            _ = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => gateway.CleanupAsync(PolicyMutationGuardTests.Snapshot));
        }

        [TestMethod]
        public void CommandsUseFixedScriptAndSeparateArguments()
        {
            System.Diagnostics.ProcessStartInfo info = PowerShellCommandRunner.CreateStartInfo(WindowsCommand.Apply, @"C:\ProgramData\ComsPcGuardPoc\payload.xml");
            Assert.IsFalse(info.UseShellExecute);
            string[] expected = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", @"C:\ProgramData\ComsPcGuardPoc\Scripts\Apply.ps1", "-PolicyPath", @"C:\ProgramData\ComsPcGuardPoc\payload.xml"];
            CollectionAssert.AreEqual(expected, info.ArgumentList.ToArray());
            _ = Assert.Throws<ArgumentException>(() => PowerShellCommandRunner.CreateStartInfo(WindowsCommand.Apply, "<xml>;evil"));
        }

        [TestMethod]
        public async Task EvidenceNeverEmitsUntrustedIdentityOrPayload()
        {
            using StringWriter output = new();
            await new PocEvidenceWriter(output).WriteAsync(PocExitCode.Refused, "S-1-5-21-1-2-3-1000", "alice password=secret <AppLockerPolicy/>");
            string json = output.ToString();
            foreach (string secret in new[] { "S-1-", "alice", "password", "secret", "AppLockerPolicy" })
            {
                Assert.IsFalse(json.Contains(secret, StringComparison.Ordinal));
            }

            Assert.IsTrue(json.Contains("sha256", StringComparison.Ordinal));
            Assert.AreEqual(1, json.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
        }
    }
}
