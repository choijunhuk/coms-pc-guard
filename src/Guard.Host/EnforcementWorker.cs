using System.Globalization;
using System.Runtime.Versioning;
using Guard.Service.AppLocker;
using Guard.Service.Audit;
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

        /// <summary>Last AppLocker event record already copied into the activity record.</summary>
        public string EventBookmarkPath => Path.Combine(DataDirectory, "logs", "applocker-events.bookmark");
    }

    /// <summary>
    /// Runs one enforcement pass at every decision boundary and at least once a minute, and immediately after the policy
    /// file changes. Each pass re-reads Windows, so drift or tampering is corrected on the next pass.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed partial class EnforcementWorker(ILogger<EnforcementWorker> logger, GuardHostOptions options, TimeProvider clock) : BackgroundService
    {
        private readonly GuardAuditLog _audit = GuardAuditLog.ForDataDirectory(options.DataDirectory);
        private string? _lastProblem;
        private string? _lastBackupReason;
        private DateOnly _lastPruned;
        private long? _eventBookmark;

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _ = Directory.CreateDirectory(options.DataDirectory);
            Record(new GuardAuditEntry(clock.GetUtcNow(), GuardAuditKind.ServiceStarted, null, null, "서비스가 시작됐어요."));
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
                TimeSpan delay = await RunPassAsync(service, enforcer, gateway, stoppingToken).ConfigureAwait(false);
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

        private async Task<TimeSpan> RunPassAsync(GuardApplyService service, RunningGameEnforcer enforcer, IAppLockerEventSource events, CancellationToken cancellationToken)
        {
            GuardConfiguration configuration;
            try
            {
                GuardPolicyLoad load = GuardPolicyStore.Load(options.PolicyPath);
                if (load.FromBackup)
                {
                    LogPolicyFromBackup(options.PolicyPath, load.CurrentFileError);
                    if (load.CurrentFileError != _lastBackupReason)
                    {
                        _lastBackupReason = load.CurrentFileError;
                        Record(new GuardAuditEntry(clock.GetUtcNow(), GuardAuditKind.ApplyProblem, null, null, $"정책 파일이 망가져서 바로 전 설정(.bak)으로 동작해요: {load.CurrentFileError}"));
                    }
                }
                else
                {
                    _lastBackupReason = null;
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
                LogResult(configuration, result);
                await RecordLaunchEventsAsync(events, configuration, cancellationToken).ConfigureAwait(false);
                PruneDaily();

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
                DateTimeOffset now = clock.GetUtcNow();
                foreach (RunningGameAction warned in sweep.Warned)
                {
                    LogGameWarned(warned.AppName, warned.ProcessId, warned.SessionId);
                    Record(new GuardAuditEntry(now, GuardAuditKind.GameWarned, MemberName(configuration, warned.MemberSid), warned.AppName, "제한 시간이라 15초 뒤 종료한다고 알렸어요."));
                }

                foreach (RunningGameAction stopped in sweep.Stopped)
                {
                    LogGameStopped(stopped.AppName, stopped.ProcessId, stopped.SessionId);
                    Record(new GuardAuditEntry(now, GuardAuditKind.GameStopped, MemberName(configuration, stopped.MemberSid), stopped.AppName, "경고 15초 뒤에 게임을 종료했어요."));
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

        private void LogResult(GuardConfiguration configuration, GuardApplyResult result)
        {
            long? revision = result.Artifact?.PolicyVersion;
            string? diagnostic = result.Outcome?.DiagnosticCode;
            string? problem = null;
            switch (result.Status)
            {
                case GuardApplyStatus.Applied:
                    LogApplied(revision, result.Artifact?.EnforcementMode);
                    string mode = result.Artifact?.EnforcementMode == AppLockerEnforcementMode.Enabled ? "차단" : "시험 운영";
                    Record(new GuardAuditEntry(clock.GetUtcNow(), GuardAuditKind.Applied, null, null, $"설정 {configuration.Policy.Version}번을 {mode} 모드로 적용했어요 (적용 번호 {revision})."));
                    break;
                case GuardApplyStatus.Unchanged:
                    LogUnchanged(revision);
                    break;
                case GuardApplyStatus.Busy:
                    // Another apply holds the gate (for example the command line); the next pass retries.
                    return;
                case GuardApplyStatus.Blocked:
                    string blockers = string.Join(", ", result.Pipeline?.Preview.Blockers ?? []);
                    if (logger.IsEnabled(LogLevel.Warning))
                    {
                        LogBlocked(blockers);
                    }

                    problem = $"규칙을 적용하지 않았어요. 먼저 해결할 문제: {blockers}";
                    break;
                case GuardApplyStatus.Conflict:
                case GuardApplyStatus.Rejected:
                case GuardApplyStatus.RecoveryPending:
                case GuardApplyStatus.Failed:
                default:
                    LogNotApplied(result.Status.ToString(), result.Outcome?.Kind.ToString(), diagnostic);
                    problem = result.Status switch
                    {
                        GuardApplyStatus.Conflict => $"이 프로그램이 만들지 않은 AppLocker 정책이 있어서 덮어쓰지 않았어요 ({diagnostic}).",
                        GuardApplyStatus.Rejected => $"Windows가 규칙을 받아들이지 않았어요 ({diagnostic}).",
                        GuardApplyStatus.RecoveryPending => "이전 적용이 중간에 끊겨서 복구하는 중이에요.",
                        _ => $"규칙 적용에 실패했어요: {result.Status} ({diagnostic}). 잠시 뒤 다시 시도해요.",
                    };
                    break;
            }

            // A problem is recorded once until it changes or clears, not on every retry.
            if (problem is not null && problem != _lastProblem)
            {
                Record(new GuardAuditEntry(clock.GetUtcNow(), GuardAuditKind.ApplyProblem, null, null, problem));
            }

            _lastProblem = problem;
        }

        private async Task RecordLaunchEventsAsync(IAppLockerEventSource events, GuardConfiguration configuration, CancellationToken cancellationToken)
        {
            if (configuration.Members.Count == 0)
            {
                return;
            }

            try
            {
                _eventBookmark ??= ReadBookmark();
                if (_eventBookmark is not { } after)
                {
                    // First run: start from now instead of importing older history.
                    AppLockerLaunchEvents latest = await events.ReadLaunchEventsAsync(-1, cancellationToken).ConfigureAwait(false);
                    SaveBookmark(latest.LatestRecordId);
                    return;
                }

                AppLockerLaunchEvents batch = await events.ReadLaunchEventsAsync(after, cancellationToken).ConfigureAwait(false);
                if (batch.LatestRecordId < after)
                {
                    // The AppLocker log was cleared; record IDs start again from 1.
                    SaveBookmark(0);
                    return;
                }

                if (batch.Events.Count > 0)
                {
                    Record([.. LaunchEventAuditor.ToEntries(configuration, batch.Events)]);
                    SaveBookmark(batch.Events.Max(launch => launch.RecordId));
                }
            }
            catch (Exception exception) when (exception is InvalidOperationException or TimeoutException or FormatException or IOException or UnauthorizedAccessException)
            {
                LogAuditUnavailable(exception.Message);
            }
        }

        private long? ReadBookmark()
        {
            return File.Exists(options.EventBookmarkPath)
                && long.TryParse(File.ReadAllText(options.EventBookmarkPath).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long saved)
                ? saved
                : null;
        }

        private void SaveBookmark(long recordId)
        {
            _eventBookmark = recordId;
            _ = Directory.CreateDirectory(Path.GetDirectoryName(options.EventBookmarkPath)!);
            File.WriteAllText(options.EventBookmarkPath, recordId.ToString(CultureInfo.InvariantCulture));
        }

        private void PruneDaily()
        {
            DateOnly today = DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime);
            if (today == _lastPruned)
            {
                return;
            }

            try
            {
                _ = _audit.Prune(clock.GetUtcNow());
                _lastPruned = today;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                LogAuditUnavailable(exception.Message);
            }
        }

        /// <summary>Activity-record failures are logged and never stop enforcement.</summary>
        private void Record(params GuardAuditEntry[] entries)
        {
            if (entries.Length == 0)
            {
                return;
            }

            try
            {
                _audit.Append(entries);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                LogAuditUnavailable(exception.Message);
            }
        }

        private static string MemberName(GuardConfiguration configuration, string sid)
        {
            return configuration.Members.FirstOrDefault(member => member.Sid == sid)?.Name ?? sid;
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

        [LoggerMessage(EventId = 1013, Level = LogLevel.Warning, Message = "Activity record could not be read or written: {Reason}")]
        private partial void LogAuditUnavailable(string reason);

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
