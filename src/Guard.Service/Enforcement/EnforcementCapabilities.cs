namespace Guard.Service.Enforcement
{
    public sealed record EnforcementCapabilities(bool OwnedRemoval, bool AuditOnly, bool PostLaunchTermination, bool PreExecutionBlock)
    {
        public bool Supports(EnforcementProtectionLevel protection)
        {
            return protection switch
            {
                EnforcementProtectionLevel.None => OwnedRemoval,
                EnforcementProtectionLevel.AuditOnly => AuditOnly,
                EnforcementProtectionLevel.PostLaunchTermination => PostLaunchTermination,
                EnforcementProtectionLevel.PreExecutionBlock => PreExecutionBlock,
                _ => false,
            };
        }
    }
}
