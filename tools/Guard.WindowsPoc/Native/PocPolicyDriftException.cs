namespace Guard.WindowsPoc.Native
{
    internal sealed class PocPolicyDriftException : InvalidOperationException
    {
        internal PocPolicyDriftException() : base("Policy drift detected before native mutation.")
        {
        }
    }
}
