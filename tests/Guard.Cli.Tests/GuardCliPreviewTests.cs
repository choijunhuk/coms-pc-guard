using System.Xml.Linq;

namespace Guard.Cli.Tests
{
    [TestClass]
    public sealed class GuardCliPreviewTests
    {
        private const string MemberA = "S-1-5-21-1-2-3-1001";

        private const string Policy = $$"""
            {
              "schemaVersion": 1,
              "policyVersion": 1,
              "timeZoneId": "Korea Standard Time",
              "ownerSid": "S-1-5-21-1-2-3-1000",
              "members": [{ "name": "MemberA", "sid": "{{MemberA}}" }],
              "applications": [{
                "appId": "hostname",
                "publisherIdentities": [{
                  "identityId": "hostname-ms",
                  "publisher": "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US",
                  "product": "MICROSOFT® WINDOWS® OPERATING SYSTEM",
                  "binary": "HOSTNAME.EXE",
                  "minimumVersion": "0.0.0.0",
                  "maximumVersion": "65535.65535.65535.65535"
                }]
              }],
              "weeklyRules": [{ "id": "all-day", "days": ["Monday"], "allDay": true }]
            }
            """;

        private string _directory = string.Empty;

        [TestInitialize]
        public void CreateDirectory()
        {
            _directory = Directory.CreateTempSubdirectory("guard-cli-tests-").FullName;
        }

        [TestCleanup]
        public void DeleteDirectory()
        {
            Directory.Delete(_directory, recursive: true);
        }

        private static (int Code, string Output, string Error) Run(params string[] args)
        {
            using StringWriter output = new();
            using StringWriter error = new();
            int code = GuardCli.Run(args, output, error, TimeProvider.System);
            return (code, output.ToString(), error.ToString());
        }

        private string WritePolicy(string json)
        {
            string path = Path.Combine(_directory, "policy.json");
            File.WriteAllText(path, json);
            return path;
        }

#pragma warning disable CA1707
        [TestMethod]
        public void Preview_WithoutAssumeCleanInventory_IsRefused()
        {
            (int code, _, string error) = Run("preview", "--policy", WritePolicy(Policy));

            Assert.AreEqual(GuardCli.UsageError, code);
            StringAssert.Contains(error, "--assume-clean-inventory");
        }

        [TestMethod]
        public void Preview_ValidPolicy_WritesDenyXmlAndDecisions()
        {
            string xmlPath = Path.Combine(_directory, "policy.xml");

            (int code, string output, _) = Run(
                "preview", "--policy", WritePolicy(Policy), "--assume-clean-inventory",
                "--now", "2026-10-26T10:00:00+09:00", "--xml-out", xmlPath);

            Assert.AreEqual(GuardCli.Success, code);
            StringAssert.Contains(output, "Restricted");
            StringAssert.Contains(output, "XML SHA-256:");
            XElement deny = XDocument.Load(xmlPath).Descendants("FilePublisherRule").Single();
            Assert.AreEqual(MemberA, (string?)deny.Attribute("UserOrGroupSid"));
            Assert.AreEqual("MICROSOFT® WINDOWS® OPERATING SYSTEM", (string?)deny.Element("Conditions")!.Element("FilePublisherCondition")!.Attribute("ProductName"));
        }

        [TestMethod]
        public void Preview_InvalidPolicy_ReturnsConfigurationError()
        {
            (int code, _, string error) = Run("preview", "--policy", WritePolicy(/*lang=json,strict*/ "{ \"schemaVersion\": 9 }"), "--assume-clean-inventory");

            Assert.AreEqual(GuardCli.ConfigurationError, code);
            StringAssert.Contains(error, "schemaVersion");
        }

        [TestMethod]
        public void UnknownCommand_IsUsageError()
        {
            (int code, _, string error) = Run("apply-everything");

            Assert.AreEqual(GuardCli.UsageError, code);
            StringAssert.Contains(error, "apply-everything");
        }
#pragma warning restore CA1707
    }
}
