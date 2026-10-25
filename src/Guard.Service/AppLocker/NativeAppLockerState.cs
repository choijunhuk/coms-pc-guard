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
}
