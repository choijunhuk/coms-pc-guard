using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Guard.Service.AppLocker
{
    public static class DeterministicRuleId
    {
        public const string NamespaceId = "8a94cabe-7b64-4e3f-9f8f-88da59e734dc";

        /// <summary>UUIDv8: SHA-256(namespace in network byte order || uint32 big-endian UTF-8 lengths and bytes).
        /// Logical components are collection, action, SID, AppId, IdentityId; names/culture are never used.</summary>
        public static string Create(AppLockerCollectionType collection, AppLockerRuleAction action, string sid, string appId, string identityId)
        {
            _ = AppLockerInput.Defined(collection, nameof(collection));
            _ = AppLockerInput.Defined(action, nameof(action));
            _ = AppLockerInput.Sid(sid, nameof(sid));
            ArgumentNullException.ThrowIfNull(appId);
            ArgumentNullException.ThrowIfNull(identityId);
            byte[] hash = HashParts([collection.ToString(), action.ToString(), sid, appId, identityId], new Guid(NamespaceId).ToByteArray(bigEndian: true));
            hash[6] = (byte)((hash[6] & 0x0f) | 0x80);
            hash[8] = (byte)((hash[8] & 0x3f) | 0x80);
            return new Guid(hash.AsSpan(0, 16), bigEndian: true).ToString("D").ToUpperInvariant();
        }

        internal static byte[] HashParts(IEnumerable<string> parts, byte[]? prefix = null)
        {
            using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            if (prefix is not null)
            {
                hash.AppendData(prefix);
            }

            Span<byte> length = stackalloc byte[4];
            foreach (string part in parts)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(part);
                BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
                hash.AppendData(length);
                hash.AppendData(bytes);
            }

            return hash.GetHashAndReset();
        }
    }
}
