namespace Guard.WindowsPoc.Recovery
{
    internal interface IPolicyGate
    {
        Task<T> RunAsync<T>(Func<Task<T>> action, CancellationToken cancellationToken);
    }

    // This barrier cannot be replaced by an ordinary Mutex: creation/opening must establish the DACL
    // and keep ownership on one OS thread throughout async controller/recovery/watchdog work.
    internal sealed class CrossProcessPolicyGate : IPolicyGate
    {
        public Task<T> RunAsync<T>(Func<Task<T>> action, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(action);
            cancellationToken.ThrowIfCancellationRequested();
            if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("NOT_RUN_WINDOWS_ONLY"); }
            throw new InvalidOperationException("Verified global mutex provisioning is required before native execution.");
        }
    }
}
