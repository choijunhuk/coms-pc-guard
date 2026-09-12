using Guard.Core.Identity;

namespace Guard.Service.AppLocker
{
    public abstract class AppLockerCondition
    {
        private protected AppLockerCondition() { }
        internal abstract string[] KeyParts { get; }
    }

    public sealed class AppLockerPathCondition : AppLockerCondition
    {
        internal AppLockerPathCondition() { }
        public string Path { get; } = "*";
        internal override string[] KeyParts => ["Path", Path];
    }

    public sealed class AppLockerPublisherCondition : AppLockerCondition
    {
        internal AppLockerPublisherCondition(PublisherApplicationIdentity identity)
        {
            Publisher = identity.Publisher;
            Product = identity.Product;
            Binary = identity.Binary;
            MinimumVersion = identity.MinimumVersion;
            MaximumVersion = identity.MaximumVersion;
        }

        public string Publisher { get; }
        public string Product { get; }
        public string Binary { get; }
        public Version MinimumVersion { get; }
        public Version MaximumVersion { get; }
        internal override string[] KeyParts => ["Publisher", Publisher, Product, Binary, MinimumVersion.ToString(), MaximumVersion.ToString()];
    }
}
