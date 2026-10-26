using System.Globalization;
using System.Text.Json;
using Guard.Service.AppLocker;
using Guard.Service.Audit;

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
                ? throw new InvalidOperationException($"'{path}'은(는) 회사 서명이 없는 파일이라 등록할 수 없습니다. 게임 회사가 서명한 실행 파일을 골라 주세요.")
                : new NativeFileIdentity(path, publisher, Required(root, "product"), Required(root, "binary"), Required(root, "version"), Required(root, "sha256"));
        }

        internal static IReadOnlyList<RunningProcess> ParseProcesses(string json)
        {
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            IEnumerable<JsonElement> items = root.ValueKind switch
            {
                JsonValueKind.Array => root.EnumerateArray(),
                JsonValueKind.Object => [root],
                _ => [],
            };
            return [.. items.Select(item => new RunningProcess(
                item.GetProperty("pid").GetInt32(),
                DateTimeOffset.Parse(Required(item, "startUtc"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).ToUniversalTime(),
                Required(item, "path"),
                Required(item, "ownerSid"),
                item.GetProperty("sessionId").GetInt32(),
                Optional(item, "publisher"),
                Optional(item, "product"),
                Optional(item, "binary"),
                Optional(item, "version")))];
        }

        internal static IReadOnlyList<LocalAccount> ParseLocalAccounts(string json)
        {
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            IEnumerable<JsonElement> items = root.ValueKind switch
            {
                JsonValueKind.Array => root.EnumerateArray(),
                JsonValueKind.Object => [root],
                _ => [],
            };
            return [.. items.Select(item => new LocalAccount(Required(item, "name"), Required(item, "sid"), Optional(item, "fullName") is { Length: > 0 } full ? full : null))];
        }

        internal static AppLockerLaunchEvents ParseLaunchEvents(string json)
        {
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            long latest = root.TryGetProperty("latest", out JsonElement latestValue) && latestValue.ValueKind == JsonValueKind.Number ? latestValue.GetInt64() : 0;
            IEnumerable<JsonElement> items = root.TryGetProperty("events", out JsonElement events)
                ? events.ValueKind switch
                {
                    JsonValueKind.Array => events.EnumerateArray(),
                    JsonValueKind.Object => [events],
                    _ => [],
                }
                : [];
            return new AppLockerLaunchEvents(latest, [.. items.Select(item => new AppLockerLaunchEvent(
                item.GetProperty("recordId").GetInt64(),
                DateTimeOffset.Parse(Required(item, "timeUtc"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).ToUniversalTime(),
                item.GetProperty("id").GetInt32(),
                Optional(item, "userSid"),
                Optional(item, "path"),
                Optional(item, "fqbn")))]);
        }

        internal static bool ParseTerminated(string json)
        {
            using JsonDocument document = JsonDocument.Parse(json);
            return document.RootElement.TryGetProperty("terminated", out JsonElement value) && value.ValueKind == JsonValueKind.True;
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
