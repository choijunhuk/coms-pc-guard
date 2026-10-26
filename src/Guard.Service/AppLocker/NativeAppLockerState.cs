namespace Guard.Service.AppLocker
{
    /// <summary>Raw facts read from Windows in one pass. Interpretation belongs to <see cref="AppLockerInventoryReader"/>.</summary>
    public sealed record NativeAppLockerState(
        DateTimeOffset CapturedAtUtc,
        string LocalPolicyXml,
        string EffectivePolicyXml,
        string AppIdServiceStartMode,
        string AppIdServiceState,
        bool MdmAppLockerPolicyPresent,
        IReadOnlyList<string> EnforcedCustomCodeIntegrityPolicies);

    /// <summary>Publisher identity exactly as AppLocker derives it from a file (never typed by hand).</summary>
    public sealed record NativeFileIdentity(string Path, string Publisher, string Product, string Binary, string BinaryVersion, string Sha256Hex);

    /// <summary>The only boundary that touches Windows AppLocker. Implementations run fixed commands, never caller-built scripts.</summary>
    public interface IAppLockerNativeGateway
    {
        Task<NativeAppLockerState> ReadStateAsync(CancellationToken cancellationToken);

        /// <summary>Replaces the local AppLocker policy with <paramref name="policyXml"/>.</summary>
        Task ApplyLocalPolicyAsync(string policyXml, CancellationToken cancellationToken);

        Task<NativeFileIdentity> ReadFileIdentityAsync(string path, CancellationToken cancellationToken);
    }

    /// <summary>A running process whose image name matches a registered binary, owned by a registered member.</summary>
    public sealed record RunningProcess(
        int ProcessId,
        DateTimeOffset StartedAtUtc,
        string Path,
        string OwnerSid,
        int SessionId,
        string? Publisher,
        string? Product,
        string? Binary,
        string? BinaryVersion);

    /// <summary>Process discovery, warning, and termination for games already running when a restriction starts.</summary>
    public interface INativeProcessGateway
    {
        Task<IReadOnlyList<RunningProcess>> FindProcessesAsync(IReadOnlyCollection<string> binaryNames, IReadOnlyCollection<string> ownerSids, CancellationToken cancellationToken);

        /// <summary>Terminates only if the PID still belongs to the same process start; returns false when it changed or exited.</summary>
        Task<bool> TerminateAsync(int processId, DateTimeOffset startedAtUtc, CancellationToken cancellationToken);

        /// <summary>Shows a message box in the given interactive session without waiting for an answer.</summary>
        Task NotifySessionAsync(int sessionId, string title, string message, CancellationToken cancellationToken);
    }
}
