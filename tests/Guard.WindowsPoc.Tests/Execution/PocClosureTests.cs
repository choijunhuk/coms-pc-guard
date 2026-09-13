using Guard.WindowsPoc.Native;

namespace Guard.WindowsPoc.Tests.Execution
{
    [TestClass]
    public sealed class PocClosureTests
    {
        [TestMethod]
        public void SamePublisherNameDoesNotSubstituteForTheSameSigningCertificate()
        {
            PocFixturePublisherEvidence target = new("CN=COMS", "Target", "target.exe", new(1, 0), new(1, 0)) { CertificateThumbprint = new('A', 40) };
            PocFixturePublisherEvidence control = target with { Product = "Control", Binary = "control.exe" };
            Assert.IsTrue(target.SharesSignerWithDistinctFixture(control));
            Assert.IsFalse(target.SharesSignerWithDistinctFixture(control with { CertificateThumbprint = new('B', 40) }));
            Assert.IsFalse(target.SharesSignerWithDistinctFixture(control with { CertificateThumbprint = null }));
        }

        [TestMethod]
        public void ClosureRejectsMissingExtraAndSwappedCodeAndRuntimeProbing()
        {
            Dictionary<string, string> expected = new(StringComparer.OrdinalIgnoreCase) { ["target.exe"] = new('A', 64), ["target.dll"] = new('B', 64) };
            Assert.IsTrue(PocFixtureClosureManifest.MatchesFiles(expected, expected));
            Assert.IsFalse(PocFixtureClosureManifest.MatchesFiles(expected, new Dictionary<string, string> { ["target.exe"] = new('A', 64) }));
            Assert.IsFalse(PocFixtureClosureManifest.MatchesFiles(expected, new Dictionary<string, string>(expected) { ["extra.dll"] = new('C', 64) }));
            Assert.IsFalse(PocFixtureClosureManifest.MatchesFiles(expected, new Dictionary<string, string>(expected) { ["target.dll"] = new('C', 64) }));
            Assert.IsFalse(PocFixtureClosureManifest.MatchesFiles(expected, new Dictionary<string, string>(expected) { ["target.exe"] = new('C', 64) }));
            const string valid = /*lang=json,strict*/ """{"runtimeOptions":{"tfm":"net10.0","includedFrameworks":[{"name":"Microsoft.NETCore.App","version":"10.0.12"}]}}""";
            Assert.IsTrue(PocFixtureClosureManifest.IsSelfContainedRuntimeConfig(valid));
            Assert.IsFalse(PocFixtureClosureManifest.IsSelfContainedRuntimeConfig(valid.Replace("\"tfm\":", "\"additionalProbingPaths\":[\"C:/evil\"],\"tfm\":", StringComparison.Ordinal)));
            Assert.IsFalse(PocFixtureClosureManifest.IsSelfContainedRuntimeConfig(/*lang=json,strict*/ """{"runtimeOptions":{"tfm":"net10.0","framework":{"name":"Microsoft.NETCore.App","version":"10.0.12"}}}"""));
        }
    }
}
