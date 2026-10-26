using Guard.Core.Identity;
using Guard.Core.Policies;
using Guard.Service.AppLocker;
using Guard.Service.Configuration;

namespace Guard.Service.Enforcement
{
    /// <summary>
    /// PLAN §8: when a restriction starts, a game the member already runs gets a warning, then is stopped after a 15 s grace period.
    /// Only processes whose OWN signed image matches an approved identity of a restricted app, owned by that member, are touched;
    /// the PID and its start time are re-verified at termination so a reused PID is never killed.
    /// </summary>
    public sealed class RunningGameEnforcer(INativeProcessGateway gateway, TimeProvider clock)
    {
        public static readonly TimeSpan GracePeriod = TimeSpan.FromSeconds(15);

        private readonly INativeProcessGateway _gateway = gateway ?? throw new ArgumentNullException(nameof(gateway));
        private readonly TimeProvider _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        private readonly Dictionary<(int ProcessId, DateTimeOffset StartedAtUtc), DateTimeOffset> _warned = [];

        /// <summary>Runs one sweep. Call only after the restriction is confirmed enforced (not in AuditOnly).</summary>
        public async Task<RunningGameSweep> SweepAsync(GuardConfiguration configuration, IReadOnlyList<PolicyDecision> decisions, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentNullException.ThrowIfNull(decisions);
            (string MemberSid, GuardApplication App)[] restricted =
            [
                .. decisions
                    .Where(decision => decision.Decision == PolicyDecisionKind.Restricted)
                    .Select(decision => (decision.MemberSid, App: configuration.Applications.FirstOrDefault(app => app.AppId == decision.AppId)))
                    .Where(pair => pair.App is not null)
                    .Select(pair => (pair.MemberSid, pair.App!)),
            ];
            if (restricted.Length == 0)
            {
                _warned.Clear();
                return new RunningGameSweep([], [], null);
            }

            string[] binaries = [.. restricted.SelectMany(pair => pair.App.Identities).Select(identity => identity.Binary).Distinct(StringComparer.OrdinalIgnoreCase)];
            string[] owners = [.. restricted.Select(pair => pair.MemberSid).Distinct(StringComparer.Ordinal)];
            IReadOnlyList<RunningProcess> processes = await _gateway.FindProcessesAsync(binaries, owners, cancellationToken).ConfigureAwait(false);

            DateTimeOffset now = _clock.GetUtcNow();
            List<RunningGameAction> warned = [];
            List<RunningGameAction> stopped = [];
            HashSet<(int, DateTimeOffset)> seen = [];
            foreach (RunningProcess process in processes)
            {
                GuardApplication? app = restricted
                    .Where(pair => pair.MemberSid == process.OwnerSid)
                    .Select(pair => pair.App)
                    .FirstOrDefault(candidate => candidate.Identities.Any(identity => Matches(identity, process)));
                if (app is null)
                {
                    continue;
                }

                (int, DateTimeOffset) key = (process.ProcessId, process.StartedAtUtc);
                _ = seen.Add(key);
                RunningGameAction action = new(process.ProcessId, process.OwnerSid, app.AppId, app.DisplayName, process.SessionId);
                if (!_warned.TryGetValue(key, out DateTimeOffset warnedAt))
                {
                    _warned[key] = now;
                    await _gateway.NotifySessionAsync(
                        process.SessionId,
                        "COMS PC Guard",
                        $"지금은 '{app.DisplayName}' 제한 시간입니다.\n{GracePeriod.TotalSeconds:N0}초 뒤 게임이 종료됩니다. 지금 저장하세요.",
                        cancellationToken).ConfigureAwait(false);
                    warned.Add(action);
                }
                else if (now - warnedAt >= GracePeriod)
                {
                    if (await _gateway.TerminateAsync(process.ProcessId, process.StartedAtUtc, cancellationToken).ConfigureAwait(false))
                    {
                        stopped.Add(action);
                    }

                    _ = _warned.Remove(key);
                }
            }

            foreach ((int, DateTimeOffset) gone in _warned.Keys.Where(key => !seen.Contains(key)).ToArray())
            {
                _ = _warned.Remove(gone);
            }

            DateTimeOffset? nextDeadline = _warned.Count == 0 ? null : _warned.Values.Min() + GracePeriod;
            return new RunningGameSweep(warned, stopped, nextDeadline);
        }

        /// <summary>Forgets pending warnings (restriction lifted or enforcement not confirmed).</summary>
        public void Reset()
        {
            _warned.Clear();
        }

        private static bool Matches(PublisherApplicationIdentity identity, RunningProcess process)
        {
            return process.Publisher == identity.Publisher
                && process.Product == identity.Product
                && string.Equals(process.Binary, identity.Binary, StringComparison.OrdinalIgnoreCase)
                && Version.TryParse(process.BinaryVersion, out Version? version)
                && version >= identity.MinimumVersion
                && version <= identity.MaximumVersion;
        }
    }

    public sealed record RunningGameAction(int ProcessId, string MemberSid, string AppId, string AppName, int SessionId);

    /// <summary><see cref="NextDeadlineUtc"/> is when the earliest warned game becomes due for termination.</summary>
    public sealed record RunningGameSweep(IReadOnlyList<RunningGameAction> Warned, IReadOnlyList<RunningGameAction> Stopped, DateTimeOffset? NextDeadlineUtc);
}
