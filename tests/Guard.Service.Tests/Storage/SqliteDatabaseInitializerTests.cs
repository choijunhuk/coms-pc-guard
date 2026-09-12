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
