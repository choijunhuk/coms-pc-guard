using Guard.Service.AppLocker;
using Guard.Service.Configuration;

namespace Guard.Service.Tests.Configuration
{
    [TestClass]
    public sealed class GuardPolicyEditorTests
    {
        private const string Owner = "S-1-5-21-1-2-3-1000";
        private static readonly TimeZoneInfo Korea = TimeZoneInfo.FindSystemTimeZoneById("Korea Standard Time");
        private static readonly string[] expected = ["LAUNCHER.EXE", "CLIENT.EXE"];

#pragma warning disable CA1707
        [TestMethod]
        public void CreateDefault_IsValidAuditOnlyDailyNineToSix()
        {
            GuardConfiguration configuration = GuardPolicyDocumentReader.ToConfiguration(GuardPolicyEditor.CreateDefault(Owner));

            Assert.IsTrue(configuration.Policy.AuditOnly);
            Assert.AreEqual(7, configuration.Policy.WeeklyRules.Count);
            Assert.AreEqual(new TimeOnly(9, 0), configuration.Policy.WeeklyRules[0].Window.StartInclusive);
        }

        [TestMethod]
        public void AddApplication_SecondBinaryJoinsTheSameGame()
        {
            GuardPolicyDocument document = GuardPolicyEditor.CreateDefault(Owner);
            NativeFileIdentity launcher = new("C:\\Games\\launcher.exe", "O=GAME CO", "GAME", "LAUNCHER.EXE", "1.0.0.0", "aa");
            NativeFileIdentity client = new("C:\\Games\\client.exe", "O=GAME CO", "GAME", "CLIENT.EXE", "1.0.0.0", "bb");

            document = GuardPolicyEditor.AddApplication(document, "game", "게임", launcher);
            document = GuardPolicyEditor.AddApplication(document, "game", null, client);

            GuardApplicationDocument app = document.Applications!.Single();
            CollectionAssert.AreEqual(expected, app.PublisherIdentities!.Select(identity => identity.Binary).ToArray());
            Assert.AreEqual("게임", app.DisplayName);
            _ = GuardPolicyDocumentReader.ToConfiguration(document);
            _ = Assert.ThrowsExactly<GuardConfigurationException>(() => GuardPolicyEditor.AddApplication(document, "game", null, client));
        }

        [TestMethod]
        public void EndOfLocalDay_IsNextKoreanMidnight()
        {
            DateTimeOffset now = new(2026, 10, 26, 14, 30, 0, TimeSpan.Zero);

            Assert.AreEqual(new DateTimeOffset(2026, 10, 26, 15, 0, 0, TimeSpan.Zero), GuardPolicyEditor.EndOfLocalDay(now, Korea));
        }

        [TestMethod]
        [DataRow("평일", 5)]
        [DataRow("주말", 2)]
        [DataRow("mon-wed,sat", 4)]
        [DataRow("월,수,금", 3)]
        [DataRow("all", 7)]
        public void ParseDays_UnderstandsKoreanAndEnglish(string specification, int count)
        {
            Assert.AreEqual(count, GuardPolicyEditor.ParseDays(specification).Count);
        }

        [TestMethod]
        public void RemoveMember_DropsTheirGrants()
        {
            GuardPolicyDocument document = GuardPolicyEditor.AddMember(GuardPolicyEditor.CreateDefault(Owner), "MemberA", "S-1-5-21-1-2-3-1001");
            DateTimeOffset now = new(2026, 10, 26, 1, 0, 0, TimeSpan.Zero);
            document = GuardPolicyEditor.AddGrant(document, "membera", null, now, now.AddHours(1));

            document = GuardPolicyEditor.RemoveMember(document, "MemberA");

            Assert.AreEqual(0, document.Members!.Count);
            Assert.AreEqual(0, document.TemporaryGrants!.Count);
        }

        [TestMethod]
        public void Store_FallsBackToBackupWhenTheFileIsZeroFilled()
        {
            string directory = Directory.CreateTempSubdirectory("guard-store-").FullName;
            try
            {
                string path = Path.Combine(directory, "policy.json");
                GuardPolicyDocument document = GuardPolicyEditor.CreateDefault(Owner);
                _ = GuardPolicyStore.Write(path, document);
                _ = GuardPolicyStore.Write(path, GuardPolicyEditor.SetEmergency(document, true));
                File.WriteAllBytes(path, new byte[2976]);

                GuardPolicyLoad load = GuardPolicyStore.Load(path);

                Assert.IsTrue(load.FromBackup);
                Assert.IsFalse(load.Configuration.Policy.EmergencyRestriction);
                Assert.IsNotNull(load.CurrentFileError);
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }
#pragma warning restore CA1707
    }
}
