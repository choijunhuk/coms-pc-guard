using System.Text.Json.Nodes;
using Guard.WindowsPoc.Inventory;
using Guard.WindowsPoc.Native;

namespace Guard.WindowsPoc.Tests.Native
{
    [TestClass]
    public sealed class PowerShellCommandRunnerTests
    {
        private const string Complete = """
        {"CapturedAtUtc":"2026-09-13T00:00:00Z","Revision":"r1","Inventory":{"Local":1,"EffectiveGroupPolicy":1,"CspMdm":1,"Wdac":1},"LocalPolicyXml":"<AppLockerPolicy Version=\"1\" />","RestorationEligible":true,"AppIdServiceRunning":true,"AppIdServiceAutomatic":true}
        """;

        [TestMethod]
        public async Task RefusesEveryScriptCommandUntilFileAndAncestorTrustIsVerified()
        {
            foreach (WindowsCommand command in Enum.GetValues<WindowsCommand>())
            {
                _ = await Assert.ThrowsAsync<InvalidOperationException>(() => new PowerShellCommandRunner().RunAsync(new(command), CancellationToken.None));
            }
        }

        [TestMethod]
        public void RejectsMalformedOrMissingRequiredSnapshotStructure()
        {
            foreach (string json in new[] { "{}", "null", "[]", "not-json" })
            {
                _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(json));
            }

            foreach (string field in new[] { "CapturedAtUtc", "Revision", "LocalPolicyXml", "RestorationEligible", "AppIdServiceRunning", "AppIdServiceAutomatic" })
            {
                JsonObject document = JsonNode.Parse(Complete)!.AsObject();
                _ = document.Remove(field);
                _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(document.ToJsonString()));
                document[field] = null;
                _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(document.ToJsonString()));
                document[field] = "";
                _ = Assert.Throws<InvalidOperationException>(() => PowerShellCommandRunner.ParseSnapshot(document.ToJsonString()));
            }
            Assert.IsTrue(PowerShellCommandRunner.ParseSnapshot(Complete).IsComplete);
        }

        [TestMethod]
        public void UnavailableProviderEvidenceRemainsUnknownAndCannotReportSuccess()
        {
            foreach (string field in new[] { "Local", "EffectiveGroupPolicy", "CspMdm", "Wdac" })
            {
                foreach (JsonNode? value in new JsonNode?[] { null, JsonValue.Create(99), JsonValue.Create("Absent") })
                {
                    JsonObject document = JsonNode.Parse(Complete)!.AsObject();
                    document["Inventory"]![field] = value;
                    Assert.IsFalse(PowerShellCommandRunner.ParseSnapshot(document.ToJsonString()).IsComplete);
                }
                JsonObject missing = JsonNode.Parse(Complete)!.AsObject();
                _ = missing["Inventory"]!.AsObject().Remove(field);
                Assert.IsFalse(PowerShellCommandRunner.ParseSnapshot(missing.ToJsonString()).IsComplete);
            }
            JsonObject noInventory = JsonNode.Parse(Complete)!.AsObject();
            _ = noInventory.Remove("Inventory");
            AppLockerNativeSnapshot snapshot = PowerShellCommandRunner.ParseSnapshot(noInventory.ToJsonString());
            Assert.AreEqual(PolicyPresence.Unknown, snapshot.Inventory.CspMdm);
            Assert.IsFalse(snapshot.IsComplete);
        }
    }
}
