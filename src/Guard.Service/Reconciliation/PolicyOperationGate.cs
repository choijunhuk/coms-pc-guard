namespace Guard.Service.Reconciliation
{
    // Inject the same gate into every coordinator operating on one database.
    public sealed class PolicyOperationGate : IDisposable
    {
        private readonly SemaphoreSlim _semaphore = new(1, 1);
        public async ValueTask<IDisposable?> TryAcquireAsync(CancellationToken cancellationToken)
        {
            return await _semaphore.WaitAsync(0, cancellationToken).ConfigureAwait(false) ? new Lease(_semaphore) : null;
        }
        public void Dispose()
        {
            _semaphore.Dispose();
        }

        private sealed class Lease(SemaphoreSlim semaphore) : IDisposable
        {
            private SemaphoreSlim? _semaphore = semaphore;
            public void Dispose()
            {
                _ = Interlocked.Exchange(ref _semaphore, null)?.Release();
            }
        }
    }
}
