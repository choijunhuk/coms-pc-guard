using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Guard.Service.Enforcement;

namespace Guard.Service.Storage
{
    public sealed record PolicyArtifact
    {
        public PolicyArtifact(long policyVersion, string canonicalJson, string sha256Hex, EnforcementProtectionLevel requiredProtection, OwnedPolicyState expectedOwnedState, DateTimeOffset createdAtUtc, PolicyArtifactState state = PolicyArtifactState.Candidate)
        {
            ValidateIdentity(policyVersion, sha256Hex);
            ValidateJson(canonicalJson, nameof(canonicalJson));
            if (Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJson))) != sha256Hex)
            {
                throw new ArgumentException("Hash does not match the exact JSON bytes.", nameof(sha256Hex));
            }

            if (!Enum.IsDefined(requiredProtection))
            {
                throw new ArgumentOutOfRangeException(nameof(requiredProtection));
            }

            if (expectedOwnedState is not (OwnedPolicyState.Absent or OwnedPolicyState.Present))
            {
                throw new ArgumentOutOfRangeException(nameof(expectedOwnedState));
            }

            if (requiredProtection == EnforcementProtectionLevel.None && expectedOwnedState != OwnedPolicyState.Absent)
            {
                throw new ArgumentException("None protection requires expected absence.", nameof(expectedOwnedState));
            }

            if (!Enum.IsDefined(state))
            {
                throw new ArgumentOutOfRangeException(nameof(state));
            }

            ValidateUtc(createdAtUtc, nameof(createdAtUtc));
            PolicyVersion = policyVersion; CanonicalJson = canonicalJson; Sha256Hex = sha256Hex;
            RequiredProtection = requiredProtection; ExpectedOwnedState = expectedOwnedState; CreatedAtUtc = createdAtUtc.ToUniversalTime(); State = state;
        }
        public long PolicyVersion { get; }
        public string CanonicalJson { get; }
        public string Sha256Hex { get; }
        public EnforcementProtectionLevel RequiredProtection { get; }
        public OwnedPolicyState ExpectedOwnedState { get; }
        public DateTimeOffset CreatedAtUtc { get; }
        public PolicyArtifactState State { get; }

        internal static void ValidateIdentity(long version, string hash)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(version);
            if (hash is null || hash.Length != 64 || hash.Any(c => c is not ((>= '0' and <= '9') or (>= 'a' and <= 'f'))))
            {
                throw new ArgumentException("SHA-256 must be 64 lowercase hexadecimal characters.", nameof(hash));
            }
        }
        internal static void ValidateUtc(DateTimeOffset value, string name)
        {
            if (value.Offset != TimeSpan.Zero)
            {
                throw new ArgumentException("Timestamp must have UTC offset zero.", name);
            }
        }
        internal static void ValidateJson(string json, string name)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                throw new ArgumentException("JSON object is required.", name);
            }

            try
            {
                using JsonDocument document = JsonDocument.Parse(json);
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    throw new ArgumentException("JSON must have a top-level object.", name);
                }
            }
            catch (JsonException exception) { throw new ArgumentException("Malformed JSON.", name, exception); }
        }
    }
}
