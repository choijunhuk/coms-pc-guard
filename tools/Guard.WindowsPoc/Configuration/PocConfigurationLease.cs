using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Configuration
{
    internal sealed class PocConfigurationLease : IDisposable
    {
        private readonly FileStream _file;
        private readonly string _hash;
        private readonly List<(FileStream File, string Hash)> _attestations = [];
        internal PocConfiguration Value { get; }

        private PocConfigurationLease(FileStream file)
        {
            _file = file;
            if (file.Length is <= 0 or > 65536) { throw new InvalidOperationException("Controller configuration refused."); }
            using StreamReader reader = new(file, Encoding.UTF8, false, 4096, leaveOpen: true);
            Value = PocConfiguration.Parse(reader.ReadToEnd());
            file.Position = 0;
            _hash = Convert.ToHexString(SHA256.HashData(file));
            Revalidate();
            try
            {
                foreach (string path in new[] { OwnerTokenAttestation.VmMarkerPath, OwnerTokenAttestation.ProofPath, Native.PocFixtureClosureManifest.ManifestPath })
                {
                    if (path == OwnerTokenAttestation.ProofPath && !File.Exists(path)) { continue; }
                    FileStream retained = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                    try
                    {
                        if (retained.Length is <= 0 or > 65536) { throw new InvalidOperationException("Attestation exceeded bound."); }
                        _attestations.Add((retained, Convert.ToHexString(SHA256.HashData(retained))));
                    }
                    catch { retained.Dispose(); throw; }
                }
                Revalidate();
            }
            catch { foreach ((FileStream held, _) in _attestations) { held.Dispose(); } throw; }
        }

        internal static PocConfigurationLease Open()
        {
            if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("NOT_RUN_WINDOWS_ONLY"); }
            FileStream file = new(PocConfiguration.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try { return new(file); }
            catch { file.Dispose(); throw; }
        }

        internal void Revalidate()
        {
            if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("NOT_RUN_WINDOWS_ONLY"); }
            ValidateFile(_file, _hash);
            foreach ((FileStream file, string hash) in _attestations) { ValidateFile(file, hash); }
        }

        [SupportedOSPlatform("windows")]
        private void ValidateFile(FileStream file, string hash)
        {
            OwnerTokenAttestation.ValidateProtectedFile(file, Value.OwnerSid);
            ValidateRetainedPath(file);
            file.Position = 0;
            if (file.Length is <= 0 or > 65536 || Convert.ToHexString(SHA256.HashData(file)) != hash)
            { throw new InvalidOperationException("Controller configuration changed."); }
        }

        [SupportedOSPlatform("windows")]
        internal static void ValidateRetainedPath(FileStream file)
        {
            char[] path = new char[1024];
            uint length = GetFinalPathNameByHandle(file.SafeFileHandle, path, 1024, 0);
            if (length == 0 || length >= 1024 || !string.Equals(new string(path, 0, (int)length), @"\\?\" + file.Name, StringComparison.OrdinalIgnoreCase))
            { throw new InvalidOperationException("Controller configuration changed."); }
        }

        [SupportedOSPlatform("windows")]
#pragma warning disable SYSLIB1054
        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle file, [System.Runtime.InteropServices.Out] char[] path, uint length, uint flags);
#pragma warning restore SYSLIB1054

        public void Dispose()
        {
            foreach ((FileStream file, _) in _attestations) { file.Dispose(); }
            _file.Dispose();
        }
    }
}
