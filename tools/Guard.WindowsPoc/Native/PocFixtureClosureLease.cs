using System.Security.Cryptography;
using System.Text.Json;
using Guard.WindowsPoc.Configuration;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Native
{
    internal sealed record PocFixtureClosureManifest(IReadOnlyDictionary<string, string> Files)
    {
        internal const string ManifestPath = @"C:\ProgramData\ComsPcGuardPoc\fixture-closure.json";
        internal static PocFixtureClosureManifest Parse(string json)
        {
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            if (root.EnumerateObject().Count() != 3 || root.GetProperty("Version").GetInt32() != 1
                || root.GetProperty("RuntimeIdentifier").GetString() != "win-x64") { throw Refused(); }
            Dictionary<string, string> files = new(StringComparer.OrdinalIgnoreCase);
            foreach (JsonProperty item in root.GetProperty(nameof(Files)).EnumerateObject())
            {
                string name = item.Name.Replace('/', '\\');
                string hash = item.Value.GetString() ?? "";
                if (!ValidRelativePath(name) || name.EndsWith(".runtimeconfig.dev.json", StringComparison.OrdinalIgnoreCase)
                    || hash.Length != 64 || !hash.All(char.IsAsciiHexDigit) || !files.TryAdd(name, hash.ToUpperInvariant())) { throw Refused(); }
            }
            string[] required = ["target.exe", "control.exe", "hostfxr.dll", "hostpolicy.dll", "coreclr.dll", "System.Private.CoreLib.dll",
                "ComsPcGuardPoc.DenyTarget.dll", "ComsPcGuardPoc.PublisherControl.dll", "ComsPcGuardPoc.DenyTarget.runtimeconfig.json", "ComsPcGuardPoc.PublisherControl.runtimeconfig.json",
                "ComsPcGuardPoc.DenyTarget.deps.json", "ComsPcGuardPoc.PublisherControl.deps.json"];
            return files.Count <= 512 && required.All(files.ContainsKey) ? new(files) : throw Refused();
        }

        internal static bool MatchesFiles(IReadOnlyDictionary<string, string> expected, IReadOnlyDictionary<string, string> actual)
        { return expected.Count == actual.Count && expected.All(item => actual.TryGetValue(item.Key, out string? hash) && hash == item.Value); }

        internal static bool IsSelfContainedRuntimeConfig(string json)
        {
            try
            {
                using JsonDocument document = JsonDocument.Parse(json);
                JsonElement options = document.RootElement.GetProperty("runtimeOptions");
                string[] allowed = ["tfm", "includedFrameworks", "configProperties"];
                if (options.EnumerateObject().Any(item => !allowed.Contains(item.Name, StringComparer.Ordinal))
                    || options.GetProperty("tfm").GetString() != "net10.0") { return false; }
                JsonElement frameworks = options.GetProperty("includedFrameworks");
                if (frameworks.GetArrayLength() != 1 || frameworks[0].GetProperty("name").GetString() != "Microsoft.NETCore.App"
                    || !(frameworks[0].GetProperty("version").GetString()?.StartsWith("10.", StringComparison.Ordinal) ?? false)) { return false; }
                string[] properties = ["System.Reflection.Metadata.MetadataUpdater.IsSupported", "System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization", "System.Runtime.Loader.UseRidGraph"];
                return !options.TryGetProperty("configProperties", out JsonElement config)
                    || config.EnumerateObject().All(item => properties.Contains(item.Name, StringComparer.Ordinal) && item.Value.ValueKind is JsonValueKind.False);
            }
            catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException) { return false; }
        }

        internal void ValidateDeps(string json)
        {
            using JsonDocument document = JsonDocument.Parse(json);
            string name = document.RootElement.GetProperty("runtimeTarget").GetProperty("name").GetString() ?? "";
            if (!name.EndsWith("/win-x64", StringComparison.Ordinal)) { throw Refused(); }
            foreach (JsonProperty library in document.RootElement.GetProperty("targets").GetProperty(name).EnumerateObject())
            {
                foreach (string type in new[] { "runtime", "native", "resources", "runtimeTargets" })
                {
                    if (!library.Value.TryGetProperty(type, out JsonElement assets)) { continue; }
                    foreach (JsonProperty asset in assets.EnumerateObject())
                    {
                        string relative = asset.Name.Replace('/', '\\');
                        if (!ValidRelativePath(relative) || (!Files.ContainsKey(relative) && !Files.ContainsKey(relative.Split('\\')[^1]))) { throw Refused(); }
                        if (asset.Value.TryGetProperty("rid", out JsonElement rid) && rid.GetString() != "win-x64") { throw Refused(); }
                    }
                }
            }
        }

        private static bool ValidRelativePath(string path)
        { return path.Length is > 0 and < 240 && !path.Any(c => c is ':' or '*' or '?' or '"' || char.IsControl(c)) && path.Split('\\').All(part => part is not "" and not "." and not ".." && !part.EndsWith('.') && !part.EndsWith(' ')); }
        private static InvalidOperationException Refused() { return new("Complete protected self-contained fixture closure required."); }
    }

    internal sealed class PocFixtureClosureLease : IDisposable
    {
        private readonly FileStream _manifest;
        private readonly string _ownerSid;
        private readonly Dictionary<string, FileStream> _files = new(StringComparer.OrdinalIgnoreCase);
        private readonly PocFixtureClosureManifest _expected;
        internal string ManifestHash { get; }

        private PocFixtureClosureLease(FileStream manifest, string ownerSid, string? expectedHash)
        {
            _manifest = manifest; _ownerSid = ownerSid;
            try
            {
                if (manifest.Length is <= 0 or > 65536) { throw new InvalidOperationException("Closure manifest bound exceeded."); }
                ManifestHash = Hash(manifest);
                if (expectedHash is not null && ManifestHash != expectedHash) { throw new InvalidOperationException("Closure manifest changed."); }
                using StreamReader reader = new(manifest, leaveOpen: true);
                manifest.Position = 0;
                _expected = PocFixtureClosureManifest.Parse(reader.ReadToEnd());
                foreach (string name in _expected.Files.Keys)
                {
                    string path = Path.Combine(WindowsPocOptions.AuthorizedFixtureRoot, name);
                    _files.Add(name, new(path, FileMode.Open, FileAccess.Read, FileShare.Read));
                }
                Revalidate();
                foreach (string name in new[] { "ComsPcGuardPoc.DenyTarget", "ComsPcGuardPoc.PublisherControl" })
                {
                    if (!PocFixtureClosureManifest.IsSelfContainedRuntimeConfig(ReadText(_files[name + ".runtimeconfig.json"]))) { throw new InvalidOperationException("External runtime probing refused."); }
                    _expected.ValidateDeps(ReadText(_files[name + ".deps.json"]));
                }
            }
            catch { Dispose(); throw; }
        }

        internal static PocFixtureClosureLease Open(string ownerSid, string? expectedHash = null)
        {
            return !OperatingSystem.IsWindows()
                ? throw new PlatformNotSupportedException("NOT_RUN_WINDOWS_ONLY")
                : new(new FileStream(PocFixtureClosureManifest.ManifestPath, FileMode.Open, FileAccess.Read, FileShare.Read), ownerSid, expectedHash);
        }

        internal void Revalidate()
        {
            if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("NOT_RUN_WINDOWS_ONLY"); }
            OwnerTokenAttestation.ValidateProtectedFile(_manifest, _ownerSid);
            PocConfigurationLease.ValidateRetainedPath(_manifest);
            if (Hash(_manifest) != ManifestHash) { throw new InvalidOperationException("Closure manifest changed."); }
            Dictionary<string, string> actual = new(StringComparer.OrdinalIgnoreCase);
            OwnerTokenAttestation.ValidateFixtureEntry(new DirectoryInfo(@"C:\ComsPcGuardPoc"));
            OwnerTokenAttestation.ValidateFixtureEntry(new DirectoryInfo(WindowsPocOptions.AuthorizedFixtureRoot));
            foreach (string path in Directory.EnumerateFileSystemEntries(WindowsPocOptions.AuthorizedFixtureRoot, "*", SearchOption.AllDirectories))
            {
                if (Directory.Exists(path)) { OwnerTokenAttestation.ValidateFixtureEntry(new DirectoryInfo(path)); continue; }
                string relative = Path.GetRelativePath(WindowsPocOptions.AuthorizedFixtureRoot, path);
                if (!_files.TryGetValue(relative, out FileStream? file)) { throw new InvalidOperationException("Unlisted fixture closure file."); }
                OwnerTokenAttestation.ValidateFixtureEntry(new FileInfo(path), file);
                PocConfigurationLease.ValidateRetainedPath(file);
                actual.Add(relative, Hash(file));
            }
            if (!PocFixtureClosureManifest.MatchesFiles(_expected.Files, actual)) { throw new InvalidOperationException("Fixture closure changed."); }
        }

        private static string Hash(FileStream file)
        {
            if (file.Length > 256_000_000) { throw new InvalidOperationException("Fixture file bound exceeded."); }
            file.Position = 0; string hash = Convert.ToHexString(SHA256.HashData(file)); file.Position = 0; return hash;
        }
        private static string ReadText(FileStream file)
        {
            if (file.Length > 4_000_000) { throw new InvalidOperationException("Fixture configuration bound exceeded."); }
            file.Position = 0; using StreamReader reader = new(file, leaveOpen: true); return reader.ReadToEnd();
        }
        public void Dispose() { foreach (FileStream file in _files.Values) { file.Dispose(); } _manifest.Dispose(); }
    }
}
