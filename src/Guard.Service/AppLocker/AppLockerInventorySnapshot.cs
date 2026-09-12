namespace Guard.Service.AppLocker
{
    public enum AppLockerPolicyPresence { Absent = 0, ProductOwned = 1, External = 2, Unknown = 3 }

    /// <summary>Trusted provider assertions, never an IPC/raw caller payload. Construction does not authenticate the provider.</summary>
    public sealed class AppLockerInventorySnapshot(
        DateTimeOffset capturedAtUtc,
        string revision,
        AppLockerPolicyPresence local,
        AppLockerPolicyPresence effectiveGroupPolicy,
        AppLockerPolicyPresence cspMdm,
        AppLockerPolicyPresence wdac,
        bool appIdServiceRunning,
        bool appIdServiceAutomatic,
        IReadOnlyList<AppLockerExistingRule> existingRules)
    {
        public DateTimeOffset CapturedAtUtc { get; } = capturedAtUtc.ToUniversalTime();
        public string Revision { get; } = AppLockerInput.Text(revision, nameof(revision));
        public AppLockerPolicyPresence Local { get; } = AppLockerInput.Defined(local, nameof(local));
        public AppLockerPolicyPresence EffectiveGroupPolicy { get; } = AppLockerInput.Defined(effectiveGroupPolicy, nameof(effectiveGroupPolicy));
        public AppLockerPolicyPresence CspMdm { get; } = AppLockerInput.Defined(cspMdm, nameof(cspMdm));
        public AppLockerPolicyPresence Wdac { get; } = AppLockerInput.Defined(wdac, nameof(wdac));
        public bool AppIdServiceRunning { get; } = appIdServiceRunning;
        public bool AppIdServiceAutomatic { get; } = appIdServiceAutomatic;
        public IReadOnlyList<AppLockerExistingRule> ExistingRules { get; } = AppLockerInput.Snapshot(existingRules, nameof(existingRules));
    }

    /// <summary>Ownership evidence must come from a verified product manifest/provider, never a display name.</summary>
    public sealed class AppLockerExistingRule(AppLockerOwnedRule rule, string contentHash, string revision, string? ownershipEvidence)
    {
        public AppLockerOwnedRule Rule { get; } = rule ?? throw new ArgumentNullException(nameof(rule));
        public string ContentHash { get; } = AppLockerInput.Text(contentHash, nameof(contentHash));
        public string Revision { get; } = AppLockerInput.Text(revision, nameof(revision));
        public string? OwnershipEvidence { get; } = ownershipEvidence;
    }
}
