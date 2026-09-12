namespace Guard.Core.Identity
{
    public abstract class ApplicationEvidence
    {
        private protected ApplicationEvidence()
        {
        }

        public abstract ApplicationIdentityKind Kind { get; }
    }
}
