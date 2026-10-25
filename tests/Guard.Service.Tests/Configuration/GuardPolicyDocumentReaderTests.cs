using Guard.Core.Policies;
using Guard.Service.Configuration;

namespace Guard.Service.Tests.Configuration
{
    [TestClass]
    public sealed class GuardPolicyDocumentReaderTests
    {
        internal const string Owner = "S-1-5-21-1-2-3-1000";
        internal const string MemberA = "S-1-5-21-1-2-3-1001";
        internal const string MemberB = "S-1-5-21-1-2-3-1002";
        private static readonly string[] expected = ["weekday:Monday", "weekday:Tuesday"];

        internal static string Document(
            string weeklyRules = /*lang=json,strict*/ """[{ "id": "weekday", "days": ["Monday", "Tuesday"], "start": "09:00", "end": "18:00" }]""",
            string grants = "[]",
            string extra = "",
            bool auditOnly = false,
            string members = $$"""[{ "name": "MemberA", "sid": "{{MemberA}}" }, { "name": "MemberB", "sid": "{{MemberB}}" }]""",
            string minimumVersion = "0.0.0.0")
        {
            return $$"""
                {
                  "schemaVersion": 1,
                  "policyVersion": 7,
                  "timeZoneId": "Korea Standard Time",
                  "ownerSid": "{{Owner}}",
                  "members": {{members}},
                  "applications": [
                    {
                      "appId": "charmap",
                      "displayName": "문자표",
                      "publisherIdentities": [
                        {
                          "identityId": "charmap-ms",
                          "publisher": "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US",
                          "product": "MICROSOFT® WINDOWS® OPERATING SYSTEM",
                          "binary": "CHARMAP.EXE",
                          "minimumVersion": "{{minimumVersion}}",
                          "maximumVersion": "65535.65535.65535.65535"
                        }
                      ]
                    }
                  ],
                  "weeklyRules": {{weeklyRules}},
                  "dateOverrides": [],
                  "temporaryGrants": {{grants}},
                  "emergencyRestriction": false,
                  {{extra}}
                  "auditOnly": {{(auditOnly ? "true" : "false")}}
                }
                """;
        }

#pragma warning disable CA1707
        [TestMethod]
        public void Parse_ValidDocument_ExpandsWeeklyDaysAndMapsGrants()
        {
            GuardConfiguration configuration = GuardPolicyDocumentReader.Parse(Document(
                grants: $$"""[{ "id": "g1", "memberSid": "{{MemberA}}", "appId": "charmap", "issuedAtUtc": "2026-10-26T00:00:00+00:00", "expiresAtUtc": "2026-10-26T02:00:00+00:00", "revoked": true }]"""));

            Assert.AreEqual(Owner, configuration.OwnerSid);
            CollectionAssert.AreEqual(new[] { MemberA, MemberB }, configuration.Members.Select(member => member.Sid).ToArray());
            Assert.AreEqual("문자표", configuration.Applications.Single().DisplayName);
            Assert.AreEqual("CHARMAP.EXE", configuration.Applications.Single().Identities.Single().Binary);
            Assert.AreEqual(7, configuration.Policy.Version);
            CollectionAssert.AreEqual(
                expected,
                configuration.Policy.WeeklyRules.Select(rule => rule.Id).ToArray());
            Assert.AreEqual(new TimeOnly(9, 0), configuration.Policy.WeeklyRules[0].Window.StartInclusive);
            TemporaryGrant grant = configuration.Policy.TemporaryGrants.Single();
            Assert.AreEqual(TemporaryGrantTrust.Revoked, grant.Trust);
            Assert.AreEqual(TimeSpan.Zero, grant.ExpiresAtUtc.Offset);
        }

        [TestMethod]
        public void Parse_UnknownProperty_IsRejected()
        {
            GuardConfigurationException exception = Assert.ThrowsExactly<GuardConfigurationException>(
                () => GuardPolicyDocumentReader.Parse(Document(extra: "\"emergencyRestrictoin\": true,")));
            StringAssert.Contains(exception.Message, "not valid JSON");
        }

        [TestMethod]
        public void Parse_GrantForUnregisteredMember_IsRejected()
        {
            GuardConfigurationException exception = Assert.ThrowsExactly<GuardConfigurationException>(
                () => GuardPolicyDocumentReader.Parse(Document(
                    grants: /*lang=json,strict*/ """[{ "id": "g1", "memberSid": "S-1-5-21-9-9-9-1999", "issuedAtUtc": "2026-10-26T00:00:00Z", "expiresAtUtc": "2026-10-26T01:00:00Z" }]""")));
            StringAssert.Contains(exception.Message, "temporaryGrants[0].memberSid");
        }

        [TestMethod]
        public void Parse_UnsupportedSchemaVersion_IsRejected()
        {
            string json = Document().Replace("\"schemaVersion\": 1", "\"schemaVersion\": 2", StringComparison.Ordinal);
            GuardConfigurationException exception = Assert.ThrowsExactly<GuardConfigurationException>(() => GuardPolicyDocumentReader.Parse(json));
            StringAssert.Contains(exception.Message, "schemaVersion");
        }

        [TestMethod]
        public void Parse_ThreePartVersion_IsRejected()
        {
            GuardConfigurationException exception = Assert.ThrowsExactly<GuardConfigurationException>(
                () => GuardPolicyDocumentReader.Parse(Document(minimumVersion: "1.0.0")));
            StringAssert.Contains(exception.Message, "minimumVersion");
        }

        [TestMethod]
        public void Parse_OversizedDocument_IsRejected()
        {
            string json = Document().Replace("\"auditOnly\"", $"\"{new string('x', GuardPolicyDocumentReader.MaximumDocumentBytes)}\": 0, \"auditOnly\"", StringComparison.Ordinal);
            GuardConfigurationException exception = Assert.ThrowsExactly<GuardConfigurationException>(() => GuardPolicyDocumentReader.Parse(json));
            StringAssert.Contains(exception.Message, "exceeds");
        }

        [TestMethod]
        public void Parse_MemberEqualToOwner_IsRejected()
        {
            GuardConfigurationException exception = Assert.ThrowsExactly<GuardConfigurationException>(
                () => GuardPolicyDocumentReader.Parse(Document(members: $$"""[{ "name": "Owner", "sid": "{{Owner}}" }]""")));
            StringAssert.Contains(exception.Message, "members[0].sid");
        }

        [TestMethod]
        public void Parse_AllDayWithExplicitTimes_IsRejected()
        {
            GuardConfigurationException exception = Assert.ThrowsExactly<GuardConfigurationException>(
                () => GuardPolicyDocumentReader.Parse(Document(
                    weeklyRules: /*lang=json,strict*/ """[{ "id": "all", "days": ["Sunday"], "allDay": true, "start": "09:00", "end": "18:00" }]""")));
            StringAssert.Contains(exception.Message, "allDay");
        }
#pragma warning restore CA1707
    }
}
