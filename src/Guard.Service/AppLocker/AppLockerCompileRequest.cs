using System.Globalization;
using Guard.Core.Identity;
using Guard.Core.Policies;

namespace Guard.Service.AppLocker
{
    /// <summary>Trusted service input: identities are approved and decisions are pre-evaluated for this exact version/time/scope.
    /// SID syntax validation proves neither token membership nor Owner identity. Never deserialize this contract from IPC.</summary>
    public sealed class AppLockerCompileRequest
    {
        public AppLockerCompileRequest(
            string ownerSid,
            IReadOnlyList<string> memberSids,
            IReadOnlyList<AppLockerApprovedApplication> applications,
            IReadOnlyList<PolicyDecision> decisions,
            AppLockerInventorySnapshot inventory,
            DateTimeOffset nowUtc,
            long policyVersion,
            AppLockerEnforcementMode enforcementMode,
            AppLockerCollectionType collection = AppLockerCollectionType.Exe)
        {
            OwnerSid = AppLockerInput.Sid(ownerSid, nameof(ownerSid));
            if (AppLockerInput.IsBroadSid(OwnerSid))
            {
                throw new ArgumentException("Owner must be an explicit account SID.", nameof(ownerSid));
            }

            MemberSids = AppLockerInput.Snapshot(memberSids, nameof(memberSids));
            foreach (string member in MemberSids)
            {
                _ = AppLockerInput.Sid(member, nameof(memberSids));
                if (member == OwnerSid || AppLockerInput.IsBroadSid(member))
                {
                    throw new ArgumentException("Members cannot include Owner, Everyone, or Administrators.", nameof(memberSids));
                }
            }

            AppLockerInput.Unique(MemberSids, nameof(memberSids));
            Applications = AppLockerInput.Snapshot(applications, nameof(applications));
            AppLockerInput.Unique(Applications.Select(app => app.AppId), nameof(applications));
            AppLockerInput.Unique(Applications.SelectMany(app => app.Identities.Select(identity => identity.IdentityId)), nameof(applications));
            Decisions = AppLockerInput.Snapshot(decisions, nameof(decisions));
            Inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
            NowUtc = nowUtc.ToUniversalTime();
            ArgumentOutOfRangeException.ThrowIfNegative(policyVersion);
            PolicyVersion = policyVersion;
            EnforcementMode = AppLockerInput.Defined(enforcementMode, nameof(enforcementMode));
            Collection = AppLockerInput.Defined(collection, nameof(collection));
        }

        public string OwnerSid { get; }
        public IReadOnlyList<string> MemberSids { get; }
        public IReadOnlyList<AppLockerApprovedApplication> Applications { get; }
        public IReadOnlyList<PolicyDecision> Decisions { get; }
        public AppLockerInventorySnapshot Inventory { get; }
        public DateTimeOffset NowUtc { get; }
        public long PolicyVersion { get; }
        public AppLockerEnforcementMode EnforcementMode { get; }
        public AppLockerCollectionType Collection { get; }
    }

    public sealed class AppLockerApprovedApplication
    {
        public AppLockerApprovedApplication(string appId, IReadOnlyList<ApplicationIdentity> identities)
        {
            AppId = AppLockerInput.Text(appId, nameof(appId));
            Identities = AppLockerInput.Snapshot(identities, nameof(identities));
            if (Identities.Count == 0)
            {
                throw new ArgumentException("An approved identity is required.", nameof(identities));
            }

            AppLockerInput.Unique(Identities.Select(identity => identity.IdentityId), nameof(identities));
        }

        public string AppId { get; }
        public IReadOnlyList<ApplicationIdentity> Identities { get; }
    }

    internal static class AppLockerInput
    {
        internal static string Text(string value, string parameterName)
        {
            ArgumentNullException.ThrowIfNull(value, parameterName);
            return string.IsNullOrWhiteSpace(value) || value != value.Trim() || value.Any(char.IsControl)
                ? throw new ArgumentException("Non-empty text without surrounding whitespace/control characters is required.", parameterName)
                : value;
        }

        internal static T Defined<T>(T value, string parameterName) where T : struct, Enum
        {
            return Enum.IsDefined(value)
            ? value : throw new ArgumentOutOfRangeException(parameterName);
        }

        internal static IReadOnlyList<T> Snapshot<T>(IReadOnlyList<T> values, string parameterName)
        {
            ArgumentNullException.ThrowIfNull(values, parameterName);
            T[] snapshot = [.. values];
            return snapshot.Any(value => value is null)
                ? throw new ArgumentException("Null entries are not permitted.", parameterName)
                : (IReadOnlyList<T>)Array.AsReadOnly(snapshot);
        }

        internal static void Unique(IEnumerable<string> values, string parameterName)
        {
            HashSet<string> seen = new(StringComparer.Ordinal);
            if (values.Any(value => !seen.Add(value)))
            {
                throw new ArgumentException("Duplicate identifiers are not permitted.", parameterName);
            }
        }

        internal static bool IsBroadSid(string sid)
        {
            return sid is "S-1-1-0" or "S-1-5-32-544";
        }

        internal static string Sid(string sid, string parameterName)
        {
            _ = Text(sid, parameterName);
            string[] parts = sid.Split('-');
            return parts.Length < 4 || parts.Length > 18 || parts[0] != "S" || parts[1] != "1"
                || !CanonicalNumber(parts[2], 281474976710655)
                || parts.Skip(3).Any(part => !CanonicalNumber(part, uint.MaxValue))
                ? throw new ArgumentException("A canonical S-1 SID with 1 to 15 subauthorities is required.", parameterName)
                : sid;
        }

        private static bool CanonicalNumber(string value, ulong maximum)
        {
            return ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out ulong number)
            && number <= maximum && value == number.ToString(CultureInfo.InvariantCulture);
        }
    }
}
