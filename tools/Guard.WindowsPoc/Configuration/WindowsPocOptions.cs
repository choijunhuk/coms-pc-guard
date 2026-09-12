namespace Guard.WindowsPoc.Configuration
{
    public sealed record WindowsPocOptions(bool AllowWrite, string ExpectedVmName, string ExpectedNonce, string FixtureRoot)
    {
        public const string AuthorizedVmName = "COMS-PC-Guard-x64-Lab";
        public const string AuthorizedFixtureRoot = @"C:\ComsPcGuardPoc\Fixtures";
    }
}
