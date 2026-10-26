using Guard.Core.Policies;
using Guard.Service.AppLocker;
using Guard.Service.Configuration;
using Guard.Service.Enforcement;
using Guard.Service.Tests.TestSupport;
using static Guard.Service.Tests.Configuration.GuardPolicyDocumentReaderTests;

namespace Guard.Service.Tests.Enforcement
{
    [TestClass]
    public sealed class RunningGameEnforcerTests
    {
        private const string Publisher = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
        private const string Product = "MICROSOFT® WINDOWS® OPERATING SYSTEM";
        private static readonly DateTimeOffset Started = new(2026, 10, 26, 0, 50, 0, TimeSpan.Zero);
        private static readonly int[] expected = [4100];

        private sealed class FakeProcesses : INativeProcessGateway
        {
            public List<RunningProcess> Running { get; } = [];

            public List<int> Notified { get; } = [];

            public List<int> Terminated { get; } = [];

            public bool StartChanged { get; set; }

            public Task<IReadOnlyList<RunningProcess>> FindProcessesAsync(IReadOnlyCollection<string> binaryNames, IReadOnlyCollection<string> ownerSids, CancellationToken cancellationToken)
            {
                return Task.FromResult<IReadOnlyList<RunningProcess>>([.. Running.Where(process => ownerSids.Contains(process.OwnerSid))]);
            }

            public Task<bool> TerminateAsync(int processId, DateTimeOffset startedAtUtc, CancellationToken cancellationToken)
            {
                if (StartChanged)
                {
                    return Task.FromResult(false);
                }

                Terminated.Add(processId);
                _ = Running.RemoveAll(process => process.ProcessId == processId);
                return Task.FromResult(true);
            }

            public Task NotifySessionAsync(int sessionId, string title, string message, CancellationToken cancellationToken)
            {
                Notified.Add(sessionId);
                return Task.CompletedTask;
            }
        }

        private static RunningProcess Game(int pid, string owner, string publisher = Publisher, string binary = "CHARMAP.EXE")
        {
            return new RunningProcess(pid, Started, $"C:\\Games\\{pid}.exe", owner, 2, publisher, Product, binary, "5.2.3668.0");
        }

        private static (GuardConfiguration Configuration, IReadOnlyList<PolicyDecision> Decisions) Restricted()
        {
            GuardConfiguration configuration = GuardPolicyDocumentReader.Parse(Document());
            IReadOnlyList<PolicyDecision> decisions = new AppLockerPolicyPipeline().Run(configuration, AppLockerTestData.CleanInventory(AppLockerTestData.InsideWindow), AppLockerTestData.InsideWindow).Decisions;
            return (configuration, decisions);
        }

#pragma warning disable CA1707
        [TestMethod]
        public async Task Sweep_WarnsFirstThenStopsAfterTheGracePeriod()
        {
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            FakeProcesses processes = new();
            processes.Running.Add(Game(4100, MemberA));
            RunningGameEnforcer enforcer = new(processes, clock);
            (GuardConfiguration configuration, IReadOnlyList<PolicyDecision> decisions) = Restricted();

            RunningGameSweep first = await enforcer.SweepAsync(configuration, decisions, CancellationToken.None);
            clock.Advance(TimeSpan.FromSeconds(10));
            RunningGameSweep early = await enforcer.SweepAsync(configuration, decisions, CancellationToken.None);
            clock.Advance(TimeSpan.FromSeconds(6));
            RunningGameSweep due = await enforcer.SweepAsync(configuration, decisions, CancellationToken.None);

            Assert.AreEqual(1, first.Warned.Count);
            Assert.AreEqual(AppLockerTestData.InsideWindow + RunningGameEnforcer.GracePeriod, first.NextDeadlineUtc);
            Assert.AreEqual(0, early.Stopped.Count);
            CollectionAssert.AreEqual(expected, processes.Terminated);
            Assert.AreEqual(1, due.Stopped.Count);
            Assert.AreEqual(1, processes.Notified.Count);
        }

        [TestMethod]
        public async Task Sweep_IgnoresOtherPublishersAndAllowedMembers()
        {
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            FakeProcesses processes = new();
            processes.Running.Add(Game(4200, MemberA, publisher: "O=SOMEONE ELSE"));
            processes.Running.Add(Game(4300, "S-1-5-21-1-2-3-1500"));
            RunningGameEnforcer enforcer = new(processes, clock);
            (GuardConfiguration configuration, IReadOnlyList<PolicyDecision> decisions) = Restricted();

            RunningGameSweep sweep = await enforcer.SweepAsync(configuration, decisions, CancellationToken.None);

            Assert.AreEqual(0, sweep.Warned.Count);
            Assert.AreEqual(0, processes.Notified.Count);
        }

        [TestMethod]
        public async Task Sweep_NoRestrictedDecisions_DoesNothing()
        {
            DateTimeOffset evening = new(2026, 10, 26, 10, 0, 0, TimeSpan.Zero);
            ManualTimeProvider clock = new(evening);
            FakeProcesses processes = new();
            processes.Running.Add(Game(4400, MemberA));
            RunningGameEnforcer enforcer = new(processes, clock);
            GuardConfiguration configuration = GuardPolicyDocumentReader.Parse(Document());
            IReadOnlyList<PolicyDecision> allowed = new AppLockerPolicyPipeline().Run(configuration, AppLockerTestData.CleanInventory(evening), evening).Decisions;

            RunningGameSweep sweep = await enforcer.SweepAsync(configuration, allowed, CancellationToken.None);

            Assert.AreEqual(0, sweep.Warned.Count);
            Assert.IsNull(sweep.NextDeadlineUtc);
        }

        [TestMethod]
        public async Task Sweep_ReusedPid_IsNotReportedAsStopped()
        {
            ManualTimeProvider clock = new(AppLockerTestData.InsideWindow);
            FakeProcesses processes = new();
            processes.Running.Add(Game(4500, MemberA));
            RunningGameEnforcer enforcer = new(processes, clock);
            (GuardConfiguration configuration, IReadOnlyList<PolicyDecision> decisions) = Restricted();
            _ = await enforcer.SweepAsync(configuration, decisions, CancellationToken.None);
            processes.StartChanged = true;
            clock.Advance(TimeSpan.FromSeconds(20));

            RunningGameSweep sweep = await enforcer.SweepAsync(configuration, decisions, CancellationToken.None);

            Assert.AreEqual(0, sweep.Stopped.Count);
            Assert.AreEqual(0, processes.Terminated.Count);
        }
#pragma warning restore CA1707
    }
}
