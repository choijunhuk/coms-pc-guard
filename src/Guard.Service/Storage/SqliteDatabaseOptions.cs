namespace Guard.Service.Storage
{
    public sealed class SqliteDatabaseOptions
    {
        public SqliteDatabaseOptions(string databasePath)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
            DatabasePath = databasePath;
        }

        public string DatabasePath { get; }
    }
}
