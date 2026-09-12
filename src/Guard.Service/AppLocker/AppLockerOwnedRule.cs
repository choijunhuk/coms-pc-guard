namespace Guard.Service.AppLocker
{
    public enum AppLockerRuleAction { Allow = 0, Deny = 1 }

    public sealed class AppLockerOwnedRule
    {
        internal AppLockerOwnedRule(string id, AppLockerRuleAction action, string sid, string appId, string identityId, AppLockerCondition condition)
        {
            Id = Guid.ParseExact(id, "D").ToString("D").ToUpperInvariant();
            Action = action;
            Sid = sid;
            AppId = appId;
            IdentityId = identityId;
            Condition = condition;
            ContentHash = Convert.ToHexString(DeterministicRuleId.HashParts([Collection.ToString(), Action.ToString(), Sid, AppId, IdentityId, .. condition.KeyParts]));
        }

        public string Id { get; }
        public AppLockerCollectionType Collection { get; } = AppLockerCollectionType.Exe;
        public AppLockerRuleAction Action { get; }
        public string Sid { get; }
        public string AppId { get; }
        public string IdentityId { get; }
        public AppLockerCondition Condition { get; }
        public string ContentHash { get; }
    }
}
