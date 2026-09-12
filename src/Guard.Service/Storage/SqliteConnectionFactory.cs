using Microsoft.Data.Sqlite;

namespace Guard.Service.Storage
{
    public sealed class SqliteConnectionFactory
    {
        private readonly string _connectionString;

        public SqliteConnectionFactory(SqliteDatabaseOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);

            _connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = options.DatabasePath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Pooling = false,
            }.ConnectionString;
        }

        public async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            SqliteConnection connection = new(_connectionString);
            try
            {
                await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
                await ConfigureAsync(connection, cancellationToken).ConfigureAwait(false);
                return connection;
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        private static async Task ConfigureAsync(SqliteConnection connection, CancellationToken cancellationToken)
        {
            await ExecutePragmaAsync(connection, "PRAGMA foreign_keys = ON;", cancellationToken).ConfigureAwait(false);
            await ExecutePragmaAsync(connection, "PRAGMA busy_timeout = 5000;", cancellationToken).ConfigureAwait(false);
            await ExecutePragmaAsync(connection, "PRAGMA journal_mode = WAL;", cancellationToken).ConfigureAwait(false);
            await ExecutePragmaAsync(connection, "PRAGMA synchronous = FULL;", cancellationToken).ConfigureAwait(false);
        }

        private static async Task ExecutePragmaAsync(
            SqliteConnection connection,
            string commandText,
            CancellationToken cancellationToken)
        {
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = commandText;
            _ = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
