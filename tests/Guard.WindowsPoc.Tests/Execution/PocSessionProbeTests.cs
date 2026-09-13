using Guard.WindowsPoc.Execution;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Recovery;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class PocSessionProbeTests
    {
        [TestMethod]
        public async Task InjectedSessionProbeCannotAuthorizeAnyNativeMutation()
        {
            CaptureOnlyRunner transport = new();
            NativePocPolicyGateway gateway = new(transport, probe: new SessionProbe());
            Assert.IsTrue(await gateway.ProbeAsync(CancellationToken.None));
            DateTimeOffset now = DateTimeOffset.UtcNow;
            AppLockerPolicySnapshot empty = new(now, "<AppLockerPolicy Version=\"1\" />", "<AppLockerPolicy Version=\"1\" />",
                PolicyPresence.Absent, PolicyPresence.Absent, true, true);
            PocTransactionJournal journal = PocTransactionJournal.Prepare(empty, empty, empty, "test", "test", now);
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => gateway.WriteAsync(journal, false, CancellationToken.None));
        }

        private sealed class SessionProbe : IPocSessionProbe
        {
            public Task<bool> ProbeAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); return Task.FromResult(true); }
        }

        private sealed class CaptureOnlyRunner : IWindowsCommandRunner
        {
            public Task<WindowsCommandResult> RunAsync(WindowsCommandRequest request, CancellationToken cancellationToken)
            { throw new InvalidOperationException("Test transport cannot connect to native mutation."); }
        }

        [TestMethod]
        public void ProbeRequiresFreshIdentityBoundMarkersAndRuleCorrelatedEvents()
        {
            DateTimeOffset start = DateTimeOffset.UtcNow.AddSeconds(-2);
            Guid run = Guid.NewGuid();
            PocProbeRequest request = new(run, "S-1-5-21-1-2-3-1001", @"C:\ComsPcGuardPoc\Fixtures\target.exe", start, "rule-1", 8004, false);
            PocProbeMarker control = new(run, request.TokenSid, @"C:\ComsPcGuardPoc\Fixtures\control.exe", start.AddSeconds(1)) { SessionId = 1, Interactive = true, ProcessId = 42 };
            PocProbeEvent denied = new(request.TokenSid, request.TargetPath, "rule-1", 8004, start.AddSeconds(1)) { ProcessId = 43 };
            Assert.IsTrue(PocProbeEvidence.Validate(request, control, null, [denied], start.AddSeconds(2)));
            Assert.IsFalse(PocProbeEvidence.Validate(request, control with { RunId = Guid.NewGuid() }, null, [denied], start.AddSeconds(2)));
            Assert.IsFalse(PocProbeEvidence.Validate(request, control with { StartedAtUtc = start.AddSeconds(-1) }, null, [denied], start.AddSeconds(2)));
            Assert.IsFalse(PocProbeEvidence.Validate(request, control with { TokenSid = "S-1-5-18" }, null, [denied], start.AddSeconds(2)));
            Assert.IsFalse(PocProbeEvidence.Validate(request, control with { SessionId = 0 }, null, [denied], start.AddSeconds(2)));
            Assert.IsFalse(PocProbeEvidence.Validate(request, control with { Interactive = false }, null, [denied], start.AddSeconds(2)));
            Assert.IsFalse(PocProbeEvidence.Validate(request, control, null, [], start.AddSeconds(2)));
            Assert.IsFalse(PocProbeEvidence.Validate(request, control, null, [denied with { RuleId = "other" }], start.AddSeconds(2)));
            Assert.IsFalse(PocProbeEvidence.Validate(request, control, null, [denied with { TimeCreatedUtc = start.AddSeconds(-1) }], start.AddSeconds(2)));
            PocProbeMarker target = control with { ExecutablePath = request.TargetPath, ProcessId = 43 };
            Assert.IsFalse(PocProbeEvidence.Validate(request, control, target, [denied], start.AddSeconds(2)));
            PocProbeRequest allowed = request with { ExpectedAllowed = true, EventId = 8002, RuleId = null };
            Assert.IsTrue(PocProbeEvidence.Validate(allowed, control, target, [denied with { EventId = 8002 }], start.AddSeconds(2)));
            Assert.IsFalse(PocProbeEvidence.Validate(allowed, control, target with { ExecutablePath = control.ExecutablePath }, [denied with { EventId = 8002 }], start.AddSeconds(2)));
            Assert.IsFalse(PocProbeEvidence.Validate(allowed, control, target with { ProcessId = 44 }, [denied with { EventId = 8002 }], start.AddSeconds(2)));
            Guid rule = Guid.NewGuid();
            Assert.IsTrue(PocProbeEvidence.Validate(request with { RuleId = rule.ToString("D") }, control, null,
                [denied with { RuleId = rule.ToString("B").ToUpperInvariant() }], start.AddSeconds(2)));
        }
    }
}
