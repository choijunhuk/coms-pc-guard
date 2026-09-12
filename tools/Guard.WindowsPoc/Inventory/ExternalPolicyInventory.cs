namespace Guard.WindowsPoc.Inventory
{
    public enum PolicyPresence { Unknown = 0, Absent = 1, External = 2 }

    /// <summary>Absent must be explicitly established independently for every provider; missing evidence is Unknown.</summary>
    public sealed record ExternalPolicyInventory(PolicyPresence Local = PolicyPresence.Unknown, PolicyPresence EffectiveGroupPolicy = PolicyPresence.Unknown, PolicyPresence CspMdm = PolicyPresence.Unknown, PolicyPresence Wdac = PolicyPresence.Unknown)
    {
        public bool IsEmpty => Local == PolicyPresence.Absent && EffectiveGroupPolicy == PolicyPresence.Absent
            && CspMdm == PolicyPresence.Absent && Wdac == PolicyPresence.Absent;
    }
}
