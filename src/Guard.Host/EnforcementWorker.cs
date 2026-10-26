using System.Runtime.Versioning;
using Guard.Service.AppLocker;
using Guard.Service.Configuration;
using Guard.Service.Enforcement;
using Guard.Service.Reconciliation;
using Guard.Service.Status;
using Guard.Service.Storage;
using Guard.Windows;

namespace Guard.Host
{
    /// <summary>Paths the service owns. The data directory must be writable only by SYSTEM and Administrators.</summary>
    public sealed record GuardHostOptions(string DataDirectory)
    {
        public string PolicyPath => Path.Combine(DataDirectory, "policy.json");

        public string StatePath => Path.Combine(DataDirectory, "state.db");

        /// <summary>Readable by every user (installer ACL) so the notifier can show members their state.</summary>
        public string StatusPath => Path.Combine(DataDirectory, "status", "status.json");
    }

    /// <summary>
    /// Runs one enforcement pass at every decision boundary and at least once a minute, and immediately after the policy
    /// file changes. Each pass re-reads Windows, so drift or tampering is corrected on the next pass.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed partial class EnforcementWorker(ILogger<EnforcementWorker> logger, GuardHostOptions options, TimeProvider clock) : BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _ = Directory.CreateDirectory(options.DataDirectory);
            SqlitePolicyStateStore store = new(new(new(options.StatePath)));
            await store.InitializeAsync(stoppingToken).ConfigureAwait(false);
            using PolicyOperationGate gate = new();
            using PowerShellAppLockerGateway gateway = new();
            GuardApplyService service = new(gateway, store, clock, gate);
            RunningGameEnforcer enforcer = new(gateway, clock);

            using SemaphoreSlim wake = new(0);
            using FileSystemWatcher watcher = new(options.DataDirectory, Path.GetFileName(options.PolicyPath))
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.CreationTime,
            };
            void Wake(object? sender, EventArgs args)
            {
                if (wake.CurrentCount == 0)
                {
                    _ = wake.Release();
                }
            }

            watcher.Changed += Wake;
            watcher.Created += Wake;
            watcher.Renamed += Wake;
            watcher.EnableRaisingEvents = true;
            LogStarted(options.DataDirectory);

            while (!stoppingToken.IsCancellationRequested)
            {
                TimeSpan delay = await RunPassAsync(service, enforcer, stoppingToken).ConfigureAwait(false);
                try
                {
                    if (await wake.WaitAsync(delay, stoppingToken).ConfigureAwait(false))
                    {
                        LogPolicyFileChanged();
                        await Task.Delay(TimeSpan.FromMilliseconds(500), stoppingToken).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
            }
        }

        private async Task<TimeSpan> RunPassAsync(GuardApplyService service, RunningGameEnforcer enforcer, CancellationToken cancellationToken)
        {
            GuardConfiguration configuration;
            try
            {
                GuardPolicyLoad load = GuardPolicyStore.Load(options.PolicyPath);
                if (load.FromBackup)
                {
                    LogPolicyFromBackup(options.PolicyPath, load.CurrentFileError);
                }

                configuration = load.Configuration;
            }
            catch (Exception exception) when (exception is GuardConfigurationException or IOException or UnauthorizedAccessException)
            {
                LogPolicyUnreadable(options.PolicyPath, exception.Message);
                return EnforcementSchedule.PeriodicInterval;
            }

            try
            {
                GuardApplyResult result = await service.ApplyAsync(configuration, cancellationToken).ConfigureAwait(false);
                PublishStatus(configuration, result);
                long? revision = result.Artifact?.PolicyVersion;
                switch (result.Status)
                {
                    case GuardApplyStatus.Applied:
                        LogApplied(revision, result.Artifact?.EnforcementMode);
                        break;
                    case GuardApplyStatus.Unchanged:
                        LogUnchanged(revision);
                        break;
                    case GuardApplyStatus.Blocked:
                        if (logger.IsEnabled(LogLevel.Warning))
                        {
                            LogBlocked(string.Join(", ", result.Pipeline?.Preview.Blockers ?? []));
                        }
                        break;
                    case GuardApplyStatus.Conflict:
                        break;
                    case GuardApplyStatus.Rejected:
                        break;
                    case GuardApplyStatus.Busy:
                        break;
                    case GuardApplyStatus.RecoveryPending:
                        break;
                    case GuardApplyStatus.Failed:
                        break;
                    default:
                        LogNotApplied(result.Status.ToString(), result.Outcome?.Kind.ToString(), result.Outcome?.DiagnosticCode);
                        break;
                }

                TimeSpan delay = EnforcementSchedule.NextRunDelay(clock.GetUtcNow(), result.Pipeline?.NextTransitionUtc, result.Status);
                bool enforced = result.Status is GuardApplyStatus.Applied or GuardApplyStatus.Unchanged
                    && result.Artifact?.EnforcementMode == AppLockerEnforcementMode.Enabled
                    && result.Pipeline is not null;
                if (!enforced)
                {
                    enforcer.Reset();
                    return delay;
                }

                RunningGameSweep sweep = await enforcer.SweepAsync(configuration, result.Pipeline!.Decisions, cancellationToken).ConfigureAwait(false);
                foreach (RunningGameAction warned in sweep.Warned)
                {
                    LogGameWarned(warned.AppName, warned.ProcessId, warned.SessionId);
                }

                foreach (RunningGameAction stopped in sweep.Stopped)
                {
                    LogGameStopped(stopped.AppName, stopped.ProcessId, stopped.SessionId);
                }

                if (sweep.NextDeadlineUtc is { } deadline)
                {
                    TimeSpan untilDeadline = deadline - clock.GetUtcNow() + EnforcementSchedule.BoundaryMargin;
                    delay = untilDeadline < delay ? (untilDeadline > TimeSpan.Zero ? untilDeadline : EnforcementSchedule.BoundaryMargin) : delay;
                }

                return delay;
            }
            catch (Exception exception) when (exception is InvalidOperationException or TimeoutException or FormatException or IOException or UnauthorizedAccessException)
            {
                LogPassFailed(exception);
                return EnforcementSchedule.RetryInterval;
            }
        }

        private void PublishStatus(GuardConfiguration configuration, GuardApplyResult result)
        {
            try
            {
                GuardStatusFile.Write(options.StatusPath, GuardStatusFile.Build(configuration, result, clock.GetUtcNow()));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                LogStatusUnwritable(exception.Message);
            }
        }

        [LoggerMessage(EventId = 1012, Level = LogLevel.Warning, Message = "Status file could not be written: {Reason}")]
        private partial void LogStatusUnwritable(string reason);

        [LoggerMessage(EventId = 1000, Level = LogLevel.Information, Message = "COMS PC Guard started; data directory {DataDirectory}")]
        private partial void LogStarted(string dataDirectory);

        [LoggerMessage(EventId = 1001, Level = LogLevel.Information, Message = "Applied revision {Revision} ({Mode}) and confirmed it from the local AppLocker policy")]
        private partial void LogApplied(long? revision, AppLockerEnforcementMode? mode);

        [LoggerMessage(EventId = 1002, Level = LogLevel.Debug, Message = "Revision {Revision} already enforced")]
        private partial void LogUnchanged(long? revision);

        [LoggerMessage(EventId = 1003, Level = LogLevel.Warning, Message = "Policy not applied; preview blockers: {Blockers}")]
        private partial void LogBlocked(string blockers);

        [LoggerMessage(EventId = 1004, Level = LogLevel.Warning, Message = "Policy not applied: {Status} ({Outcome} {Diagnostic})")]
        private partial void LogNotApplied(string status, string? outcome, string? diagnostic);

        [LoggerMessage(EventId = 1005, Level = LogLevel.Error, Message = "Policy file {Path} is unreadable: {Reason}")]
        private partial void LogPolicyUnreadable(string path, string reason);

        [LoggerMessage(EventId = 1006, Level = LogLevel.Error, Message = "Enforcement pass failed; retrying soon")]
        private partial void LogPassFailed(Exception exception);

        [LoggerMessage(EventId = 1007, Level = LogLevel.Information, Message = "Policy file changed; running an enforcement pass")]
        private partial void LogPolicyFileChanged();

        [LoggerMessage(EventId = 1008, Level = LogLevel.Warning, Message = "Policy file {Path} is unreadable ({Reason}); using the previous version (.bak)")]
        private partial void LogPolicyFromBackup(string path, string? reason);

        [LoggerMessage(EventId = 1010, Level = LogLevel.Information, Message = "Warned session {SessionId}: {App} (PID {ProcessId}) will be stopped after the grace period")]
        private partial void LogGameWarned(string app, int processId, int sessionId);

        [LoggerMessage(EventId = 1011, Level = LogLevel.Warning, Message = "Stopped {App} (PID {ProcessId}) in session {SessionId} because its restriction started")]
        private partial void LogGameStopped(string app, int processId, int sessionId);
    }
}
