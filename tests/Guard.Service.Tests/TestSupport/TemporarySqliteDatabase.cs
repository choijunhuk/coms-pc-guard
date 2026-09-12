namespace Guard.Service.Tests.TestSupport
{
    internal sealed class TemporarySqliteDatabase : IAsyncDisposable
    {
        private readonly string _directoryPath;

        public TemporarySqliteDatabase(string databaseFileName = "guard.db")
        {
            _directoryPath = Path.Combine(Path.GetTempPath(), "coms-pc-guard-tests", Guid.NewGuid().ToString("N"));
            _ = Directory.CreateDirectory(_directoryPath);
            DatabasePath = Path.Combine(_directoryPath, databaseFileName);
        }

        public string DatabasePath { get; }

        public ValueTask DisposeAsync()
        {
            if (Directory.Exists(_directoryPath))
            {
                Directory.Delete(_directoryPath, recursive: true);
            }

            return ValueTask.CompletedTask;
        }
    }
}
