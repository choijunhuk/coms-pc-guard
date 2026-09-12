namespace Guard.WindowsPoc.Native
{
    public interface IScriptTrustVerifier
    {
        IScriptTrustLease Verify(string scriptPath);
    }

    public interface IScriptTrustLease : IDisposable
    {
        void Revalidate();
    }
}
