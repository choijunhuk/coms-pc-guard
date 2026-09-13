using Guard.WindowsPoc.Configuration;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class PocConfigurationTests
    {
        private const string Valid = /*lang=json,strict*/ """
            {"Version":1,"OwnerSid":"S-1-5-21-1-2-3-1000","MemberSids":["S-1-5-21-1-2-3-1001","S-1-5-21-1-2-3-1002"],"Nonce":"0123456789abcdef0123456789abcdef","ExpectedVmName":"COMS-PC-Guard-x64-Lab","FixtureRoot":"C:\\ComsPcGuardPoc\\Fixtures"}
            """;

        [TestMethod]
        public void ConfigurationRejectsUnknownDuplicateOversizedAndWrongScope()
        {
            Assert.AreEqual(2, PocConfiguration.Parse(Valid).MemberSids.Length);
            string[] invalid = [Valid.Replace("\"Version\":1", "\"Version\":1,\"Version\":1", StringComparison.Ordinal),
                Valid.Replace("\"Version\":1", "\"Password\":\"secret\",\"Version\":1", StringComparison.Ordinal),
                Valid.Replace("1001", "1000", StringComparison.Ordinal), Valid.Replace("1002", "1001", StringComparison.Ordinal),
                Valid.Replace("COMS-PC-Guard-x64-Lab", "physical", StringComparison.Ordinal),
                Valid.Replace("0123456789abcdef0123456789abcdef", "", StringComparison.Ordinal),
                Valid.Replace("Fixtures", "Other", StringComparison.Ordinal), new string(' ', 65537)];
            foreach (string json in invalid) { _ = Assert.ThrowsExactly<InvalidOperationException>(() => PocConfiguration.Parse(json)); }
        }

        [TestMethod]
        public void ProtectedConfigurationCannotOpenOutsideWindows()
        {
            if (!OperatingSystem.IsWindows())
            { _ = Assert.ThrowsExactly<PlatformNotSupportedException>(PocConfigurationLease.Open); }
        }
    }
}
