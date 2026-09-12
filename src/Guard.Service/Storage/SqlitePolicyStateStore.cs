using System.Globalization;
using Guard.Service.Enforcement;
using Microsoft.Data.Sqlite;

namespace Guard.Service.Storage
{
    public sealed class SqlitePolicyStateStore : IPolicyStateStore
    {
        private readonly SqliteConnectionFactory _factory;
        public SqlitePolicyStateStore(SqliteConnectionFactory connectionFactory)
        {
            ArgumentNullException.ThrowIfNull(connectionFactory);
            _factory = connectionFactory;
        }

        public Task InitializeAsync(CancellationToken cancellationToken)
        {
            return new SqliteDatabaseInitializer(_factory).InitializeAsync(cancellationToken);
        }

        public Task SaveCandidateAndBeginAttemptAsync(PolicyArtifact artifact, ReconciliationAttempt attempt, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(artifact);
            ArgumentNullException.ThrowIfNull(attempt);
            return artifact.State != PolicyArtifactState.Candidate || attempt.Phase != ReconciliationPhase.Prepared || artifact.PolicyVersion != attempt.PolicyVersion || artifact.Sha256Hex != attempt.Sha256Hex
                ? throw new ArgumentException("A candidate and matching Prepared attempt are required.")
                : (Task)Write(async session =>
            {
                List<PolicyArtifact> artifacts = await session.Artifacts().ConfigureAwait(false);
                PolicyArtifact? existing = artifacts.SingleOrDefault(a => a.PolicyVersion == artifact.PolicyVersion);
                if (existing is not null && !SameArtifact(existing, artifact))
                {
                    throw new InvalidOperationException("Policy version metadata cannot be substituted.");
                }

                List<ReconciliationAttempt> attempts = await session.Attempts().ConfigureAwait(false);
                ReconciliationAttempt? same = attempts.SingleOrDefault(a => a.AttemptId == attempt.AttemptId);
                if (same is not null)
                {
                    if (same != attempt)
                    {
                        throw new InvalidOperationException("Attempt identity has already been used.");
                    }

                    return;
                }
                if (attempts.Any(IsPending))
                {
                    throw new InvalidOperationException("An active attempt already exists.");
                }

                if (existing is null)
                {
                    await session.Execute("INSERT INTO policy_artifacts VALUES ($v,$j,$h,$p,$o,$t,0)", ("$v", artifact.PolicyVersion), ("$j", artifact.CanonicalJson), ("$h", artifact.Sha256Hex), ("$p", (int)artifact.RequiredProtection), ("$o", (int)artifact.ExpectedOwnedState), ("$t", Stamp(artifact.CreatedAtUtc))).ConfigureAwait(false);
                }

                await session.Execute("INSERT INTO reconciliation_attempts(attempt_id,policy_version,sha256_hex,phase,desired_action_id,prepared_utc) VALUES($id,$v,$h,0,$action,$t)", ("$id", attempt.AttemptId.ToString("D")), ("$v", attempt.PolicyVersion), ("$h", attempt.Sha256Hex), ("$action", attempt.DesiredActionIdentity.ActionId), ("$t", Stamp(attempt.PreparedAtUtc))).ConfigureAwait(false);
            }, cancellationToken);
        }

        public Task MarkApplyReportedAsync(Guid attemptId, DateTimeOffset reportedAtUtc, CancellationToken cancellationToken)
        {
            return Change(attemptId, async (s, a) =>
        {
            Require(a.Phase == ReconciliationPhase.Prepared);
            CheckTime(a, reportedAtUtc);
            await s.Execute("UPDATE reconciliation_attempts SET phase=1,apply_reported_utc=$t WHERE attempt_id=$id", ("$t", Stamp(reportedAtUtc)), Id(a)).ConfigureAwait(false);
        }, cancellationToken);
        }

        public Task MarkDesiredUncertainAsync(Guid attemptId, string errorCode, CancellationToken cancellationToken)
        {
            return Change(attemptId, async (s, a) =>
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(errorCode);
            Require(IsDesired(a));
            await s.Execute("UPDATE reconciliation_attempts SET phase=2,error_code=$e WHERE attempt_id=$id", ("$e", errorCode), Id(a)).ConfigureAwait(false);
        }, cancellationToken);
        }

        public Task PrepareRestoreAsync(Guid attemptId, PolicyArtifact lastGood, string errorCode, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(lastGood);
            ArgumentException.ThrowIfNullOrWhiteSpace(errorCode);
            return Change(attemptId, async (s, a) =>
            {
                Require(IsPending(a));
                PolicyArtifact? current = (await s.Artifacts().ConfigureAwait(false)).SingleOrDefault(p => p.State == PolicyArtifactState.LastGood);
                Require(current is not null && lastGood.State == PolicyArtifactState.LastGood && SameArtifact(current, lastGood));
                EnforcementActionIdentity restore = new(a.AttemptId, EnforcementActionKind.Restore, lastGood.PolicyVersion, lastGood.Sha256Hex);
                Require(a.RestoreActionIdentity is null || a.RestoreActionIdentity == restore);
                if (a.Phase is ReconciliationPhase.RestorePrepared or ReconciliationPhase.RestoreApplyReported)
                {
                    return;
                }

                await s.Execute("UPDATE reconciliation_attempts SET phase=3,restore_action_id=$r,restore_policy_version=$v,restore_sha256_hex=$h,error_code=$e WHERE attempt_id=$id", ("$r", restore.ActionId), ("$v", lastGood.PolicyVersion), ("$h", lastGood.Sha256Hex), ("$e", errorCode), Id(a)).ConfigureAwait(false);
            }, cancellationToken);
        }

        public Task MarkRestoreApplyReportedAsync(Guid attemptId, DateTimeOffset reportedAtUtc, CancellationToken cancellationToken)
        {
            return Change(attemptId, async (s, a) =>
        {
            Require(a.RestoreActionIdentity is not null && a.Phase is ReconciliationPhase.RestorePrepared or ReconciliationPhase.RestoreApplyReported or ReconciliationPhase.RecoveryBlocked);
            CheckTime(a, reportedAtUtc);
            await s.Execute("UPDATE reconciliation_attempts SET phase=4,apply_reported_utc=$t WHERE attempt_id=$id", ("$t", Stamp(reportedAtUtc)), Id(a)).ConfigureAwait(false);
        }, cancellationToken);
        }

        public Task MarkRecoveryBlockedAsync(Guid attemptId, string errorCode, CancellationToken cancellationToken)
        {
            return Change(attemptId, async (s, a) =>
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(errorCode);
            Require(IsPending(a));
            await s.Execute("UPDATE reconciliation_attempts SET phase=5,error_code=$e WHERE attempt_id=$id", ("$e", errorCode), Id(a)).ConfigureAwait(false);
        }, cancellationToken);
        }

        public Task CommitObservedSuccessAsync(Guid attemptId, EffectivePolicyObservation observation, DateTimeOffset confirmedAtUtc, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(observation);
            return Change(attemptId, async (s, a) =>
            {
                CheckTime(a, confirmedAtUtc);
                List<PolicyArtifact> artifacts = await s.Artifacts().ConfigureAwait(false);
                PolicyArtifact artifact = artifacts.Single(p => p.PolicyVersion == a.PolicyVersion);
                Require(PolicyConfirmationPolicy.IsConfirmed(artifact, observation, confirmedAtUtc));
                if (a.Phase == ReconciliationPhase.Committed)
                {
                    Require(a.CompletedAtUtc == confirmedAtUtc && artifact.State == PolicyArtifactState.LastGood && (await s.Observations().ConfigureAwait(false)).Contains(observation));
                    return;
                }
                Require(IsDesired(a));
                await s.SaveObservation(observation).ConfigureAwait(false);
                await s.Execute("UPDATE policy_artifacts SET state=0 WHERE state=1").ConfigureAwait(false);
                await s.Execute("UPDATE policy_artifacts SET state=1 WHERE policy_version=$v", ("$v", a.PolicyVersion)).ConfigureAwait(false);
                await s.Execute("UPDATE reconciliation_attempts SET phase=6,completed_utc=$t,error_code=NULL WHERE attempt_id=$id", ("$t", Stamp(confirmedAtUtc)), Id(a)).ConfigureAwait(false);
            }, cancellationToken);
        }

        public Task CompleteRestoredLastGoodAsync(Guid attemptId, EffectivePolicyObservation observation, string errorCode, DateTimeOffset completedAtUtc, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(observation);
            ArgumentException.ThrowIfNullOrWhiteSpace(errorCode);
            return Change(attemptId, async (s, a) =>
            {
                CheckTime(a, completedAtUtc);
                PolicyArtifact? artifact = (await s.Artifacts().ConfigureAwait(false)).SingleOrDefault(p => p.State == PolicyArtifactState.LastGood);
                Require(artifact is not null && a.RestoreActionIdentity is not null && artifact.PolicyVersion == a.RestoreActionIdentity.PolicyVersion && artifact.Sha256Hex == a.RestoreActionIdentity.Sha256Hex && PolicyConfirmationPolicy.IsConfirmed(artifact, observation, completedAtUtc));
                if (a.Phase == ReconciliationPhase.Failed)
                {
                    Require(a.ErrorCode == errorCode && a.CompletedAtUtc == completedAtUtc && (await s.Observations().ConfigureAwait(false)).Contains(observation));
                    return;
                }
                Require(a.Phase is ReconciliationPhase.RestorePrepared or ReconciliationPhase.RestoreApplyReported or ReconciliationPhase.RecoveryBlocked);
                await s.SaveObservation(observation).ConfigureAwait(false);
                await s.Execute("UPDATE reconciliation_attempts SET phase=7,completed_utc=$t,error_code=$e WHERE attempt_id=$id", ("$t", Stamp(completedAtUtc)), ("$e", errorCode), Id(a)).ConfigureAwait(false);
            }, cancellationToken);
        }

        public Task MarkFailedAsync(Guid attemptId, string errorCode, DateTimeOffset completedAtUtc, CancellationToken cancellationToken)
        {
            return Change(attemptId, async (s, a) =>
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(errorCode);
            CheckTime(a, completedAtUtc);
            if (a.Phase == ReconciliationPhase.Failed)
            {
                Require(a.ErrorCode == errorCode && a.CompletedAtUtc == completedAtUtc);
                return;
            }
            Require(IsDesired(a));
            await s.Execute("UPDATE reconciliation_attempts SET phase=7,completed_utc=$t,error_code=$e WHERE attempt_id=$id", ("$t", Stamp(completedAtUtc)), ("$e", errorCode), Id(a)).ConfigureAwait(false);
        }, cancellationToken);
        }

        public Task<ReconciliationAttempt?> GetPendingAttemptAsync(CancellationToken cancellationToken)
        {
            return Read(async s => (await s.Attempts().ConfigureAwait(false)).SingleOrDefault(IsPending), cancellationToken);
        }

        public Task<PolicyArtifact?> GetArtifactAsync(long policyVersion, CancellationToken cancellationToken)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(policyVersion);
            return Read(async s => (await s.Artifacts().ConfigureAwait(false)).SingleOrDefault(a => a.PolicyVersion == policyVersion), cancellationToken);
        }
        public Task<PolicyArtifact?> GetLastGoodArtifactAsync(CancellationToken cancellationToken)
        {
            return Read(async s => (await s.Artifacts().ConfigureAwait(false)).SingleOrDefault(a => a.State == PolicyArtifactState.LastGood), cancellationToken);
        }

        public Task<EffectivePolicyObservation?> GetLastGoodObservationAsync(CancellationToken cancellationToken)
        {
            return Read(async s =>
                {
                    PolicyArtifact? artifact = (await s.Artifacts().ConfigureAwait(false)).SingleOrDefault(a => a.State == PolicyArtifactState.LastGood);
                    List<EffectivePolicyObservation> observations = await s.Observations().ConfigureAwait(false);
                    return observations.Where(o => o.PolicyVersion == artifact?.PolicyVersion && o.Sha256Hex == artifact.Sha256Hex).OrderByDescending(o => o.ObservedAtUtc).FirstOrDefault();
                }, cancellationToken);
        }

        private Task<bool> Change(Guid attemptId, Func<Session, ReconciliationAttempt, Task> change, CancellationToken ct)
        {
            return attemptId == Guid.Empty
                ? throw new ArgumentException("Attempt identifier is required.", nameof(attemptId))
                : Write(async s =>
            {
                ReconciliationAttempt a = (await s.Attempts().ConfigureAwait(false)).SingleOrDefault(a => a.AttemptId == attemptId) ?? throw new InvalidOperationException("Attempt does not exist.");
                await change(s, a).ConfigureAwait(false);
            }, ct);
        }
        private Task<bool> Write(Func<Session, Task> action, CancellationToken ct)
        {
            return Read(async s =>
            {
                await action(s).ConfigureAwait(false);
                return true;
            }, ct);
        }

        private async Task<T> Read<T>(Func<Session, Task<T>> action, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            await using SqliteConnection connection = await _factory.OpenAsync(ct).ConfigureAwait(false);
            await using SqliteTransaction transaction = connection.BeginTransaction();
            T result = await action(new Session(connection, transaction, ct)).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            await transaction.CommitAsync(ct).ConfigureAwait(false);
            return result;
        }
        private static bool SameArtifact(PolicyArtifact left, PolicyArtifact right)
        {
            return left.PolicyVersion == right.PolicyVersion && left.Sha256Hex == right.Sha256Hex && left.CanonicalJson == right.CanonicalJson && left.RequiredProtection == right.RequiredProtection && left.ExpectedOwnedState == right.ExpectedOwnedState && left.CreatedAtUtc == right.CreatedAtUtc;
        }

        private static bool IsPending(ReconciliationAttempt a)
        {
            return a.Phase is not (ReconciliationPhase.Committed or ReconciliationPhase.Failed);
        }

        private static bool IsDesired(ReconciliationAttempt a)
        {
            return a.RestoreActionIdentity is null && a.Phase is ReconciliationPhase.Prepared or ReconciliationPhase.ApplyReported or ReconciliationPhase.DesiredUncertain or ReconciliationPhase.RecoveryBlocked;
        }

        private static void Require(bool condition)
        {
            if (!condition)
            {
                throw new InvalidOperationException("Reconciliation state or confirmation does not permit this operation.");
            }
        }
        private static (string, object?) Id(ReconciliationAttempt a)
        {
            return ("$id", a.AttemptId.ToString("D"));
        }

        private static string Stamp(DateTimeOffset value)
        {
            return value.ToString("O", CultureInfo.InvariantCulture);
        }

        private static void CheckTime(ReconciliationAttempt a, DateTimeOffset time)
        {
            PolicyArtifact.ValidateUtc(time, nameof(time));
            Require(time >= a.PreparedAtUtc && (!a.ApplyReportedAtUtc.HasValue || time >= a.ApplyReportedAtUtc));
        }

        private sealed class Session(SqliteConnection connection, SqliteTransaction transaction, CancellationToken ct)
        {
            private SqliteCommand Command(string sql, params (string Key, object? Value)[] parameters)
            {
                SqliteCommand command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = sql;
                foreach ((string key, object? value) in parameters)
                {
                    _ = command.Parameters.AddWithValue(key, value ?? DBNull.Value);
                }

                return command;
            }
            internal async Task Execute(string sql, params (string Key, object? Value)[] parameters)
            {
                ct.ThrowIfCancellationRequested();
                await using SqliteCommand command = Command(sql, parameters);
                _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }
            private async Task<List<T>> Query<T>(string sql, Func<SqliteDataReader, T> map)
            {
                ct.ThrowIfCancellationRequested();
                await using SqliteCommand command = Command(sql);
                await using SqliteDataReader reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
                List<T> rows = [];
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                {
                    try
                    {
                        rows.Add(map(reader));
                    }
                    catch (Exception exception) when (exception is ArgumentException or FormatException or OverflowException or InvalidCastException)
                    {
                        throw new InvalidDataException("Corrupt persisted policy state.", exception);
                    }
                }
                return rows;
            }
            internal Task<List<PolicyArtifact>> Artifacts()
            {
                return Query("SELECT * FROM policy_artifacts", r => new PolicyArtifact(r.GetInt64(0), r.GetString(1), r.GetString(2), (EnforcementProtectionLevel)ReadInteger(r, 3, 3), (OwnedPolicyState)ReadInteger(r, 4, 1), ParseTime(r.GetString(5)), (PolicyArtifactState)ReadInteger(r, 6, 1)));
            }

            internal async Task<List<ReconciliationAttempt>> Attempts()
            {
                List<PolicyArtifact> artifacts = await Artifacts().ConfigureAwait(false);
                List<ReconciliationAttempt> attempts = await Query("SELECT * FROM reconciliation_attempts", r =>
                {
                    Guid id = Guid.ParseExact(r.GetString(0), "D");
                    EnforcementActionIdentity? restore = null;
                    if (!r.IsDBNull(5))
                    {
                        if (r.IsDBNull(6) || r.IsDBNull(7))
                        {
                            throw new ArgumentException("Partial restore identity.");
                        }

                        restore = new(id, EnforcementActionKind.Restore, r.GetInt64(6), r.GetString(7));
                        if (restore.ActionId != r.GetString(5))
                        {
                            throw new ArgumentException("Substituted restore identity.");
                        }
                    }
                    else if (!r.IsDBNull(6) || !r.IsDBNull(7))
                    {
                        throw new ArgumentException("Partial restore identity.");
                    }

                    ReconciliationAttempt attempt = new(id, r.GetInt64(1), r.GetString(2), ParseTime(r.GetString(8)), (ReconciliationPhase)ReadInteger(r, 3, 7), restore, NullableTime(r, 9), NullableTime(r, 10), r.IsDBNull(11) ? null : r.GetString(11));
                    return attempt.DesiredActionIdentity.ActionId != r.GetString(4)
                        ? throw new ArgumentException("Substituted desired identity.")
                        : !artifacts.Any(p => p.PolicyVersion == attempt.PolicyVersion && p.Sha256Hex == attempt.Sha256Hex) || (restore is not null && !artifacts.Any(p => p.PolicyVersion == restore.PolicyVersion && p.Sha256Hex == restore.Sha256Hex))
                        ? throw new ArgumentException("Missing referenced artifact.")
                        : attempt;
                }).ConfigureAwait(false);
                return attempts;
            }
            internal async Task<List<EffectivePolicyObservation>> Observations()
            {
                List<PolicyArtifact> artifacts = await Artifacts().ConfigureAwait(false);
                return await Query("SELECT * FROM applied_observations ORDER BY rowid DESC", r =>
                {
                    int flag = ReadInteger(r, 6, 1);

                    EffectivePolicyObservation observation = new(Guid.ParseExact(r.GetString(0), "D"), r.GetInt64(1), r.GetString(2), ParseTime(r.GetString(3)), (EnforcementProtectionLevel)ReadInteger(r, 4, 3), (OwnedPolicyState)ReadInteger(r, 5, 2), flag == 1, r.GetString(7));
                    return !artifacts.Any(p => p.PolicyVersion == observation.PolicyVersion && p.Sha256Hex == observation.Sha256Hex)
                        ? throw new ArgumentException("Missing observation artifact.")
                        : observation;
                }).ConfigureAwait(false);
            }
            internal async Task SaveObservation(EffectivePolicyObservation observation)
            {
                EffectivePolicyObservation? existing = (await Observations().ConfigureAwait(false)).SingleOrDefault(o => o.ObservationId == observation.ObservationId);
                if (existing is not null)
                {
                    Require(existing == observation);
                    return;
                }
                await Execute("INSERT INTO applied_observations VALUES($id,$v,$h,$t,$p,$o,$d,$e)", ("$id", observation.ObservationId.ToString("D")), ("$v", observation.PolicyVersion), ("$h", observation.Sha256Hex), ("$t", Stamp(observation.ObservedAtUtc)), ("$p", (int)observation.ProtectionLevel), ("$o", (int)observation.ObservedOwnedState), ("$d", observation.ExternalDenyPresent ? 1 : 0), ("$e", observation.EvidenceJson)).ConfigureAwait(false);
            }
            private static int ReadInteger(SqliteDataReader reader, int ordinal, int maximum)
            {
                // GetValue preserves the SQLite storage class; GetInt32 would truncate REAL values.
                return reader.GetValue(ordinal) is not long value || value < 0 || value > maximum
                    ? throw new InvalidDataException("Persisted enum or boolean must be an in-range SQLite INTEGER.")
                    : checked((int)value);
            }

            private static DateTimeOffset? NullableTime(SqliteDataReader reader, int ordinal)
            {
                return reader.IsDBNull(ordinal) ? null : ParseTime(reader.GetString(ordinal));
            }

            private static DateTimeOffset ParseTime(string value)
            {
                DateTimeOffset time = DateTimeOffset.ParseExact(value, "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
                PolicyArtifact.ValidateUtc(time, nameof(value));
                return time.ToUniversalTime();
            }
        }
    }
}
