using Guard.Service.Storage;
using Guard.Service.Tests.TestSupport;
using Microsoft.Data.Sqlite;

namespace Guard.Service.Tests.Storage
{
    [TestClass]
    public sealed class SqliteDatabaseInitializerTests
    {
#pragma warning disable CA1707 // Test names use requirement terminology as a readable behavior contract.
        private static readonly string[] VersionOneTableNames =
            ["schema_migrations", "policy_artifacts", "applied_observations", "reconciliation_attempts"];

        [TestMethod]
        public async Task InitializeAsync_CreatesVersionOneTables()
        {
            await using TemporarySqliteDatabase database = new();
            SqliteConnectionFactory factory = CreateFactory(database);
            SqliteDatabaseInitializer initializer = new(factory);

            await initializer.InitializeAsync(CancellationToken.None);

            await using SqliteConnection connection = await factory.OpenAsync(CancellationToken.None);
            string tables = await ScalarStringAsync(
                connection,
                "SELECT group_concat(name, ',') FROM sqlite_master WHERE type = 'table' ORDER BY name;");
            CollectionAssert.IsSubsetOf(
                VersionOneTableNames,
                tables.Split(','));
        }

        [TestMethod]
        public async Task InitializeAsync_WhenCalledTwice_RecordsVersionOneExactlyOnce()
        {
            await using TemporarySqliteDatabase database = new();
            SqliteDatabaseInitializer initializer = new(CreateFactory(database));

            await initializer.InitializeAsync(CancellationToken.None);
            await initializer.InitializeAsync(CancellationToken.None);

            await using SqliteConnection connection = await CreateFactory(database).OpenAsync(CancellationToken.None);
            long count = await ScalarInt64Async(connection, "SELECT COUNT(*) FROM schema_migrations WHERE version = 1;");
            Assert.AreEqual(1L, count);
        }

        [TestMethod]
        public async Task InitializeAsync_WhenVersionOneIsMissingAStateTable_RejectsPartialMigration()
        {
            await using TemporarySqliteDatabase database = new();
            SqliteConnectionFactory factory = CreateFactory(database);
            await using (SqliteConnection connection = await factory.OpenAsync(CancellationToken.None))
            {
                await ExecuteAsync(connection, "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_utc TEXT NOT NULL);");
                await ExecuteAsync(connection, "INSERT INTO schema_migrations(version, applied_utc) VALUES (1, '2026-09-12T00:00:00Z');");
                await ExecuteAsync(connection, "CREATE TABLE policy_artifacts(policy_version INTEGER PRIMARY KEY);");
            }

            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                async () => await new SqliteDatabaseInitializer(factory).InitializeAsync(CancellationToken.None));
        }

        [TestMethod]
        public async Task InitializeAsync_WhenVersionOneIsMissingRequiredPartialIndex_RejectsWithoutRestoringIt()
        {
            await using TemporarySqliteDatabase database = new();
            SqliteConnectionFactory factory = CreateFactory(database);
            SqliteDatabaseInitializer initializer = new(factory);
            await initializer.InitializeAsync(CancellationToken.None);

            await using (SqliteConnection connection = await factory.OpenAsync(CancellationToken.None))
            {
                await ExecuteAsync(connection, "DROP INDEX ux_reconciliation_attempts_one_nonterminal;");
            }

            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                async () => await initializer.InitializeAsync(CancellationToken.None));

            await using SqliteConnection verification = await factory.OpenAsync(CancellationToken.None);
            Assert.AreEqual(0L, await ScalarInt64Async(
                verification,
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'ux_reconciliation_attempts_one_nonterminal';"));
        }

        [TestMethod]
        public async Task InitializeAsync_WhenVersionOneTablesAreMalformed_RejectsWithoutModifyingThem()
        {
            await using TemporarySqliteDatabase database = new();
            SqliteConnectionFactory factory = CreateFactory(database);
            await using SqliteConnection connection = await factory.OpenAsync(CancellationToken.None);
            await CreateMalformedVersionOneSchemaAsync(connection);
            string before = await SchemaDefinitionAsync(connection);

            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                async () => await new SqliteDatabaseInitializer(factory).InitializeAsync(CancellationToken.None));

            Assert.AreEqual(before, await SchemaDefinitionAsync(connection));
        }

        [TestMethod]
        public async Task OpenAsync_AppliesForeignKeysAndBusyTimeout()
        {
            await using TemporarySqliteDatabase database = new();
            SqliteConnectionFactory factory = CreateFactory(database);

            await using SqliteConnection connection = await factory.OpenAsync(CancellationToken.None);

            Assert.AreEqual(1L, await ScalarInt64Async(connection, "PRAGMA foreign_keys;"));
            Assert.AreEqual(5000L, await ScalarInt64Async(connection, "PRAGMA busy_timeout;"));
        }

        [TestMethod]
        public async Task OpenAsync_ForFileDatabase_UsesWalAndFullSynchronous()
        {
            await using TemporarySqliteDatabase database = new();
            SqliteConnectionFactory factory = CreateFactory(database);

            await using SqliteConnection connection = await factory.OpenAsync(CancellationToken.None);

            Assert.AreEqual("wal", await ScalarStringAsync(connection, "PRAGMA journal_mode;"));
            Assert.AreEqual(2L, await ScalarInt64Async(connection, "PRAGMA synchronous;"));
        }

        [TestMethod]
        public async Task OpenAsync_WhenCanceledBeforeOpening_ThrowsOperationCanceledException()
        {
            await using TemporarySqliteDatabase database = new();
            using CancellationTokenSource cancellation = new();
            cancellation.Cancel();

            _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(
                async () => await CreateFactory(database).OpenAsync(cancellation.Token));
        }

        [TestMethod]
        public async Task OpenAsync_WithConnectionStringPunctuationInFileName_OpensTheIntendedDatabase()
        {
            await using TemporarySqliteDatabase database = new("guard;mode=memory=value.db");

            await using SqliteConnection connection = await CreateFactory(database).OpenAsync(CancellationToken.None);

            StringAssert.EndsWith(await DatabaseFilePathAsync(connection), "guard;mode=memory=value.db");
        }

        [TestMethod]
        public async Task InitializeAsync_WhenDatabaseHasFutureVersion_RejectsWithoutCreatingStateTables()
        {
            await using TemporarySqliteDatabase database = new();
            SqliteConnectionFactory factory = CreateFactory(database);
            await using (SqliteConnection connection = await factory.OpenAsync(CancellationToken.None))
            {
                await ExecuteAsync(connection, "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_utc TEXT NOT NULL);");
                await ExecuteAsync(connection, "INSERT INTO schema_migrations(version, applied_utc) VALUES (2, '2026-09-12T00:00:00Z');");
            }

            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                async () => await new SqliteDatabaseInitializer(factory).InitializeAsync(CancellationToken.None));

            await using SqliteConnection verification = await factory.OpenAsync(CancellationToken.None);
            long tableCount = await ScalarInt64Async(
                verification,
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('policy_artifacts', 'applied_observations', 'reconciliation_attempts');");
            Assert.AreEqual(0L, tableCount);
        }

        [TestMethod]
        public async Task InitializeAsync_WhenCanceledBeforeOpening_ThrowsOperationCanceledException()
        {
            await using TemporarySqliteDatabase database = new();
            using CancellationTokenSource cancellation = new();
            cancellation.Cancel();

            _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(
                async () => await new SqliteDatabaseInitializer(CreateFactory(database)).InitializeAsync(cancellation.Token));
        }
#pragma warning restore CA1707

        private static SqliteConnectionFactory CreateFactory(TemporarySqliteDatabase database)
        {
            return new SqliteConnectionFactory(new SqliteDatabaseOptions(database.DatabasePath));
        }

        private static async Task ExecuteAsync(SqliteConnection connection, string commandText)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = commandText;
            _ = await command.ExecuteNonQueryAsync();
        }

        private static async Task CreateMalformedVersionOneSchemaAsync(SqliteConnection connection)
        {
            await ExecuteAsync(connection, "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_utc TEXT NOT NULL);");
            await ExecuteAsync(connection, "INSERT INTO schema_migrations(version, applied_utc) VALUES (1, '2026-09-12T00:00:00Z');");
            await ExecuteAsync(connection, "CREATE TABLE policy_artifacts(policy_version INTEGER PRIMARY KEY, canonical_json TEXT NOT NULL, sha256_hex TEXT NOT NULL, required_protection INTEGER NOT NULL, expected_owned_state INTEGER NOT NULL, created_utc TEXT NOT NULL, state INTEGER NOT NULL);");
            await ExecuteAsync(connection, "CREATE TABLE applied_observations(observation_id TEXT PRIMARY KEY, policy_version INTEGER NOT NULL, sha256_hex TEXT NOT NULL, observed_utc TEXT NOT NULL, protection_level INTEGER NOT NULL, observed_owned_state INTEGER NOT NULL, external_deny_present INTEGER NOT NULL, evidence_json TEXT NOT NULL);");
            await ExecuteAsync(connection, "CREATE TABLE reconciliation_attempts(attempt_id TEXT PRIMARY KEY, policy_version INTEGER NOT NULL, sha256_hex TEXT NOT NULL, phase INTEGER NOT NULL, desired_action_id TEXT NOT NULL, restore_action_id TEXT NULL, restore_policy_version INTEGER NULL, restore_sha256_hex TEXT NULL, prepared_utc TEXT NOT NULL, apply_reported_utc TEXT NULL, completed_utc TEXT NULL, error_code TEXT NULL);");
        }

        private static async Task<string> DatabaseFilePathAsync(SqliteConnection connection)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "PRAGMA database_list;";
            await using SqliteDataReader reader = await command.ExecuteReaderAsync();
            _ = await reader.ReadAsync();
            return reader.GetString(2);
        }

        private static async Task<string> SchemaDefinitionAsync(SqliteConnection connection)
        {
            return await ScalarStringAsync(
                connection,
                "SELECT group_concat(sql, '\n') FROM sqlite_master WHERE type = 'table' ORDER BY name;");
        }

        private static async Task<long> ScalarInt64Async(SqliteConnection connection, string commandText)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = commandText;
            return Convert.ToInt64(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
        }

        private static async Task<string> ScalarStringAsync(SqliteConnection connection, string commandText)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = commandText;
            return Convert.ToString(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
        }
    }
}
