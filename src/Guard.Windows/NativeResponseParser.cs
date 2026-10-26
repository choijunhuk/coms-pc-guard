using System.Globalization;
using System.Text.Json;
using Guard.Service.AppLocker;

namespace Guard.Windows
{
    /// <summary>Parses the ASCII JSON printed by the fixed PowerShell scripts. Platform-neutral so it is testable everywhere.</summary>
    internal static class NativeResponseParser
    {
        internal static NativeAppLockerState ParseState(string json)
        {
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            return new NativeAppLockerState(
                DateTimeOffset.Parse(Required(root, "capturedUtc"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).ToUniversalTime(),
                Optional(root, "localPolicyXml") ?? string.Empty,
                Optional(root, "effectivePolicyXml") ?? string.Empty,
                Optional(root, "appIdStartMode") ?? "Unknown",
                Optional(root, "appIdState") ?? "Unknown",
                root.GetProperty("mdmPresent").GetBoolean(),
                Strings(root, "customCiPolicies"));
        }

        internal static NativeFileIdentity ParseIdentity(string json)
        {
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            string path = Required(root, "path");
            string? publisher = Optional(root, "publisher");
            return string.IsNullOrEmpty(publisher)
                ? throw new InvalidOperationException($"'{path}' is not signed; only publisher identities are supported.")
                : new NativeFileIdentity(path, publisher, Required(root, "product"), Required(root, "binary"), Required(root, "version"), Required(root, "sha256"));
        }

        private static string Required(JsonElement root, string name)
        {
            return Optional(root, name) is { Length: > 0 } value ? value : throw new FormatException($"Native response is missing '{name}'.");
        }

        private static string? Optional(JsonElement root, string name)
        {
            return root.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        }

        private static string[] Strings(JsonElement root, string name)
        {
            if (!root.TryGetProperty(name, out JsonElement value))
            {
                return [];
            }

            // ConvertTo-Json in Windows PowerShell 5.1 collapses a one-item array into a scalar.
            return value.ValueKind == JsonValueKind.String
                ? [value.GetString()!]
                : value.ValueKind == JsonValueKind.Array
                ? [.. value.EnumerateArray().Select(item => item.GetString() ?? string.Empty)]
                : [];
        }
    }
}
