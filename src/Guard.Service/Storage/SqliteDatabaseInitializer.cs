using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Guard.Service.Storage
{
    public sealed class SqliteDatabaseInitializer
    {
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
            await VerifyCanonicalObjectAsync(connection, "table", "schema_migrations", SqliteSchema.SchemaMigrationsDefinition, cancellationToken).ConfigureAwait(false);
            await VerifyCanonicalObjectAsync(connection, "table", "policy_artifacts", SqliteSchema.PolicyArtifactsDefinition, cancellationToken).ConfigureAwait(false);
            await VerifyCanonicalObjectAsync(connection, "table", "applied_observations", SqliteSchema.AppliedObservationsDefinition, cancellationToken).ConfigureAwait(false);
            await VerifyCanonicalObjectAsync(connection, "table", "reconciliation_attempts", SqliteSchema.ReconciliationAttemptsDefinition, cancellationToken).ConfigureAwait(false);
            await VerifyCanonicalObjectAsync(connection, "index", "ux_reconciliation_attempts_one_nonterminal", SqliteSchema.NonterminalAttemptIndexDefinition, cancellationToken).ConfigureAwait(false);
            await VerifyCanonicalObjectAsync(connection, "index", "ux_policy_artifacts_one_last_good", SqliteSchema.LastGoodArtifactIndexDefinition, cancellationToken).ConfigureAwait(false);
        }

        private static async Task VerifyCanonicalObjectAsync(
            SqliteConnection connection,
            string objectType,
            string objectName,
            string expectedSql,
            CancellationToken cancellationToken)
        {
            string actualSql = await ReadSchemaSqlAsync(connection, objectType, objectName, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(NormalizeSql(actualSql), NormalizeSql(expectedSql), StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"Database schema version 1 has an invalid {objectName} {objectType} definition.");
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
            return new string([
                .. sql.Where(character => !char.IsWhiteSpace(character) && character != ';'),
            ]).ToUpperInvariant();
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
