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
        private static readonly string[] SeparateGames = ["알파", "베타"];

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
        public void SuggestAppId_KeepsDifferentGamesWithTheSameFileNameApart()
        {
            GuardPolicyDocument document = GuardPolicyEditor.CreateDefault(Owner);
            NativeFileIdentity first = new("C:\\A\\game.exe", "O=STUDIO A", "ALPHA", "GAME.EXE", "1.0.0.0", "aa");
            NativeFileIdentity second = new("C:\\B\\game.exe", "O=STUDIO B", "BETA", "GAME.EXE", "1.0.0.0", "bb");
            NativeFileIdentity firstAgain = new("C:\\A2\\game.exe", "o=studio a", "alpha", "GAME.EXE", "2.0.0.0", "cc");

            Assert.AreEqual("game", GuardPolicyEditor.SuggestAppId(document, first));
            document = GuardPolicyEditor.AddApplication(document, GuardPolicyEditor.SuggestAppId(document, first), "알파", first);
            string secondId = GuardPolicyEditor.SuggestAppId(document, second);
            document = GuardPolicyEditor.AddApplication(document, secondId, "베타", second);

            Assert.AreEqual("game-2", secondId);
            CollectionAssert.AreEqual(SeparateGames, document.Applications!.Select(app => app.DisplayName).ToArray());
            // The same game again keeps its ID, so adding it is reported as a duplicate instead of becoming a third game.
            Assert.AreEqual("game", GuardPolicyEditor.SuggestAppId(document, firstAgain));
        }

        [TestMethod]
        public async Task StoreUpdate_SerialisesConcurrentEdits()
        {
            string directory = Directory.CreateTempSubdirectory("guard-policy-lock-").FullName;
            try
            {
                string path = Path.Combine(directory, "policy.json");
                Assert.IsTrue(GuardPolicyStore.Create(path, GuardPolicyEditor.CreateDefault(Owner), overwrite: false));
                Assert.IsFalse(GuardPolicyStore.Create(path, GuardPolicyEditor.CreateDefault(Owner), overwrite: false));

                // Both edits sleep between read and write; without the lock both would write version 2.
                Task[] edits =
                [
                    .. Enumerable.Range(0, 2).Select(_ => Task.Run(() => GuardPolicyStore.Update(path, document =>
                    {
                        Thread.Sleep(300);
                        return GuardPolicyEditor.SetEmergency(document, !document.EmergencyRestriction);
                    }))),
                ];
                await Task.WhenAll(edits);

                Assert.AreEqual(3, GuardPolicyStore.ReadDocument(path).PolicyVersion);
                using (GuardPolicyStore.Lock(path))
                {
                    GuardConfigurationException busy = Assert.ThrowsExactly<GuardConfigurationException>(() =>
                        GuardPolicyStore.Update(path, document => document, TimeSpan.FromMilliseconds(200)));
                    StringAssert.Contains(busy.Message, "바꾸는 중");
                }
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
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
