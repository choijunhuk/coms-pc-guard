namespace Guard.Service.AppLocker
{
    public enum AppLockerPreviewBlocker
    {
        UnsafeInventory = 0,
        UnverifiedOwnership = 1,
        AppIdServiceNotReady = 2,
        StaleInventory = 3,
        FutureInventory = 4,
        UnsupportedCollection = 5,
        MissingNativeHashProvenance = 6,
        MissingPackageMetadataAndApproval = 7,
        UnsupportedIdentity = 8,
        InconsistentDecision = 9,
        RuleIdCollision = 10,
    }
}
