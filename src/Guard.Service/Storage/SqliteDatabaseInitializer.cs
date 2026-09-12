using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Guard.Service.Storage
{
    public sealed class SqliteDatabaseInitializer
    {
        private static readonly Dictionary<string, string[]> RequiredColumns =
            new(StringComparer.Ordinal)
            {
                ["schema_migrations"] = ["version", "applied_utc"],
                ["policy_artifacts"] =
                ["policy_version", "canonical_json", "sha256_hex", "required_protection", "expected_owned_state", "created_utc", "state"],
                ["applied_observations"] =
                ["observation_id", "policy_version", "sha256_hex", "observed_utc", "protection_level", "observed_owned_state", "external_deny_present", "evidence_json"],
                ["reconciliation_attempts"] =
                ["attempt_id", "policy_version", "sha256_hex", "phase", "desired_action_id", "restore_action_id", "restore_policy_version", "restore_sha256_hex", "prepared_utc", "apply_reported_utc", "completed_utc", "error_code"],
            };

        private static readonly Dictionary<string, string[]> RequiredCheckFragments =
            new(StringComparer.Ordinal)
            {
                ["policy_artifacts"] =
                ["CHECK(REQUIRED_PROTECTIONBETWEEN0AND3)", "CHECK(EXPECTED_OWNED_STATEBETWEEN0AND1)", "CHECK(STATEBETWEEN0AND1)"],
                ["applied_observations"] =
                ["CHECK(PROTECTION_LEVELBETWEEN0AND3)", "CHECK(OBSERVED_OWNED_STATEBETWEEN0AND2)", "CHECK(EXTERNAL_DENY_PRESENTIN(0,1))"],
                ["reconciliation_attempts"] = ["CHECK(PHASEBETWEEN0AND7)"],
            };

        private readonly SqliteConnectionFactory _connectionFactory;

        public SqliteDatabaseInitializer(SqliteConnectionFactory connectionFactory)
        {
            ArgumentNullException.ThrowIfNull(connectionFactory);
            _connectionFactory = connectionFactory;
        }

        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            await using SqliteConnection connection = await _connectionFactory.OpenAsync(cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, SqliteSchema.CreateMigrationsTable, cancellationToken).ConfigureAwait(false);

            long latestVersion = await GetLatestVersionAsync(connection, cancellationToken).ConfigureAwait(false);
            if (latestVersion > SqliteSchema.CurrentVersion)
            {
                throw new InvalidOperationException($"Database schema version {latestVersion} is newer than supported version {SqliteSchema.CurrentVersion}.");
            }

            if (latestVersion == SqliteSchema.CurrentVersion)
            {
                await VerifyVersionOneSchemaAsync(connection, cancellationToken).ConfigureAwait(false);
                return;
            }

            await using SqliteTransaction transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await ExecuteAsync(connection, SqliteSchema.CreateVersionOneTables, transaction, cancellationToken).ConfigureAwait(false);
                await RecordMigrationAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
                throw;
            }
        }

        private static async Task<long> GetLatestVersionAsync(SqliteConnection connection, CancellationToken cancellationToken)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "SELECT COALESCE(MAX(version), 0) FROM schema_migrations;";
            object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            return Convert.ToInt64(result, CultureInfo.InvariantCulture);
        }

        private static async Task VerifyVersionOneSchemaAsync(SqliteConnection connection, CancellationToken cancellationToken)
        {
            foreach ((string tableName, string[] requiredColumns) in RequiredColumns)
            {
                ISet<string> actualColumns = await ReadColumnNamesAsync(connection, tableName, cancellationToken).ConfigureAwait(false);
                if (!requiredColumns.All(actualColumns.Contains))
                {
                    throw new InvalidOperationException($"Database schema version 1 has an incomplete {tableName} table.");
                }

                string schemaSql = await ReadSchemaSqlAsync(connection, "table", tableName, cancellationToken).ConfigureAwait(false);
                if (RequiredCheckFragments.TryGetValue(tableName, out string[]? requiredChecks)
                    && !requiredChecks.All(NormalizeSql(schemaSql).Contains))
                {
                    throw new InvalidOperationException($"Database schema version 1 has invalid constraints on {tableName}.");
                }
            }

            await VerifyCompositeForeignKeyAsync(
                connection,
                "applied_observations",
                [("policy_version", "policy_version"), ("sha256_hex", "sha256_hex")],
                cancellationToken).ConfigureAwait(false);
            await VerifyCompositeForeignKeyAsync(
                connection,
                "reconciliation_attempts",
                [("policy_version", "policy_version"), ("sha256_hex", "sha256_hex")],
                cancellationToken).ConfigureAwait(false);
            await VerifyCompositeForeignKeyAsync(
                connection,
                "reconciliation_attempts",
                [("restore_policy_version", "policy_version"), ("restore_sha256_hex", "sha256_hex")],
                cancellationToken).ConfigureAwait(false);
            await VerifyRequiredIndexAsync(
                connection,
                "ux_reconciliation_attempts_one_nonterminal",
                "CREATEUNIQUEINDEXUX_RECONCILIATION_ATTEMPTS_ONE_NONTERMINALONRECONCILIATION_ATTEMPTS((1))WHEREPHASEBETWEEN0AND5",
                cancellationToken).ConfigureAwait(false);
            await VerifyRequiredIndexAsync(
                connection,
                "ux_policy_artifacts_one_last_good",
                "CREATEUNIQUEINDEXUX_POLICY_ARTIFACTS_ONE_LAST_GOODONPOLICY_ARTIFACTS(STATE)WHERESTATE=1",
                cancellationToken).ConfigureAwait(false);
        }

        private static async Task<HashSet<string>> ReadColumnNamesAsync(
            SqliteConnection connection,
            string tableName,
            CancellationToken cancellationToken)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = $"PRAGMA table_info({QuoteIdentifier(tableName)});";
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            HashSet<string> columnNames = new(StringComparer.Ordinal);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                _ = columnNames.Add(reader.GetString(1));
            }

            return columnNames;
        }

        private static async Task VerifyCompositeForeignKeyAsync(
            SqliteConnection connection,
            string tableName,
            (string From, string To)[] expectedColumns,
            CancellationToken cancellationToken)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = $"PRAGMA foreign_key_list({QuoteIdentifier(tableName)});";
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            Dictionary<long, HashSet<(string From, string To)>> foreignKeys = [];
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (!string.Equals(reader.GetString(2), "policy_artifacts", StringComparison.Ordinal))
                {
                    continue;
                }

                long id = reader.GetInt64(0);
                if (!foreignKeys.TryGetValue(id, out HashSet<(string From, string To)>? columns))
                {
                    columns = [];
                    foreignKeys.Add(id, columns);
                }

                _ = columns.Add((reader.GetString(3), reader.GetString(4)));
            }

            if (!foreignKeys.Values.Any(columns => columns.SetEquals(expectedColumns)))
            {
                throw new InvalidOperationException($"Database schema version 1 has no policy artifact foreign key on {tableName}.");
            }
        }

        private static async Task VerifyRequiredIndexAsync(
            SqliteConnection connection,
            string indexName,
            string expectedSql,
            CancellationToken cancellationToken)
        {
            string tableName = indexName == "ux_reconciliation_attempts_one_nonterminal"
                ? "reconciliation_attempts"
                : "policy_artifacts";
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = $"PRAGMA index_list({QuoteIdentifier(tableName)});";
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            bool isUniquePartialIndex = false;
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (string.Equals(reader.GetString(1), indexName, StringComparison.Ordinal))
                {
                    isUniquePartialIndex = reader.GetInt64(2) == 1 && reader.GetInt64(4) == 1;
                    break;
                }
            }

            string schemaSql = await ReadSchemaSqlAsync(connection, "index", indexName, cancellationToken).ConfigureAwait(false);
            if (!isUniquePartialIndex || !NormalizeSql(schemaSql).Contains(expectedSql, StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"Database schema version 1 has an invalid {indexName} index.");
            }
        }

        private static async Task<string> ReadSchemaSqlAsync(
            SqliteConnection connection,
            string objectType,
            string objectName,
            CancellationToken cancellationToken)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "SELECT sql FROM sqlite_master WHERE type = $type AND name = $name;";
            _ = command.Parameters.AddWithValue("$type", objectType);
            _ = command.Parameters.AddWithValue("$name", objectName);
            object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            return Convert.ToString(result, CultureInfo.InvariantCulture) ?? string.Empty;
        }

        private static string NormalizeSql(string sql)
        {
            return new string([.. sql.Where(character => !char.IsWhiteSpace(character))]).ToUpperInvariant();
        }

        private static string QuoteIdentifier(string identifier)
        {
            return $"\"{identifier.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
        }

        private static async Task RecordMigrationAsync(
            SqliteConnection connection,
            SqliteTransaction transaction,
            CancellationToken cancellationToken)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO schema_migrations(version, applied_utc) VALUES ($version, $appliedUtc);";
            _ = command.Parameters.AddWithValue("$version", SqliteSchema.CurrentVersion);
            _ = command.Parameters.AddWithValue("$appliedUtc", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        private static async Task ExecuteAsync(
            SqliteConnection connection,
            string commandText,
            CancellationToken cancellationToken)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = commandText;
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        private static async Task ExecuteAsync(
            SqliteConnection connection,
            string commandText,
            SqliteTransaction transaction,
            CancellationToken cancellationToken)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = commandText;
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
