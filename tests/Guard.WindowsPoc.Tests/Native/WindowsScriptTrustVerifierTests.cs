using Guard.WindowsPoc.Native;

namespace Guard.WindowsPoc.Tests.Native
{
    [TestClass]
    public sealed class WindowsScriptTrustVerifierTests
    {
        private sealed class HeldFile : IDisposable
        {
            public bool Disposed { get; private set; }
            public void Dispose()
            {
                Disposed = true;
            }
        }

        private static readonly string[] Paths = [@"C:\", @"C:\ProgramData", @"C:\ProgramData\ComsPcGuardPoc", @"C:\ProgramData\ComsPcGuardPoc\Scripts", WindowsScriptTrustVerifier.ScriptPath];
        private static ScriptFileEvidence GoodFile => new("held-handle", new string('A', 64), 42, new DateTime(2026, 9, 13, 0, 0, 0, DateTimeKind.Utc));
        private static ScriptPathEvidence GoodPath(string path)
        {
            return new(path, false, "S-1-5-18", true, false);
        }

        [TestMethod]
        public void TrustedCaptureRetainsIdentityUntilLeaseIsDisposed()
        {
            HeldFile held = new();
            List<string> seen = [];
            WindowsScriptTrustVerifier verifier = new(path => { seen.Add(path); return GoodPath(path); }, () => GoodFile, () => held);
            using (IScriptTrustLease lease = verifier.Verify(WindowsScriptTrustVerifier.ScriptPath))
            {
                lease.Revalidate();
                Assert.IsFalse(held.Disposed);
                foreach (string path in Paths) { Assert.Contains(path, seen); }
            }
            Assert.IsTrue(held.Disposed);
        }

        [TestMethod]
        public void RejectsReparseUnknownOwnerUnknownAclAndWritableAncestorsOrScript()
        {
            foreach (string badPath in Paths)
            {
                foreach (Func<ScriptPathEvidence, ScriptPathEvidence> corrupt in new Func<ScriptPathEvidence, ScriptPathEvidence>[]
                {
                    e => e with { ReparsePoint = true }, e => e with { Owner = null }, e => e with { Owner = "S-1-5-21-member" },
                    e => e with { AclKnown = false }, e => e with { UntrustedWrite = true }, e => e with { Path = "other" }
                })
                {
                    WindowsScriptTrustVerifier verifier = new(path => path == badPath ? corrupt(GoodPath(path)) : GoodPath(path), () => GoodFile, () => new HeldFile());
                    _ = Assert.Throws<InvalidOperationException>(() => verifier.Verify(WindowsScriptTrustVerifier.ScriptPath));
                }
            }
        }

        [TestMethod]
        public void RejectsReplacementOrContentMetadataChangesImmediatelyBeforeLaunch()
        {
            foreach (ScriptFileEvidence changed in new[] { GoodFile with { Identity = "replacement" }, GoodFile with { Hash = new string('B', 64) }, GoodFile with { Length = 43 }, GoodFile with { LastWriteUtc = GoodFile.LastWriteUtc.AddSeconds(1) } })
            {
                ScriptFileEvidence current = GoodFile;
                WindowsScriptTrustVerifier verifier = new(GoodPath, () => current, () => new HeldFile());
                using IScriptTrustLease lease = verifier.Verify(WindowsScriptTrustVerifier.ScriptPath);
                current = changed;
                _ = Assert.Throws<InvalidOperationException>(lease.Revalidate);
            }
        }

        [TestMethod]
        public void RejectsOutsideAlternateStreamAndTraversalPaths()
        {
            foreach (string path in new[] { @"C:\temp\Get-ComsPocInventory.ps1", WindowsScriptTrustVerifier.ScriptPath + ":stream", @"C:\ProgramData\ComsPcGuardPoc\Scripts\..\Get-ComsPocInventory.ps1" })
            {
                WindowsScriptTrustVerifier verifier = new(GoodPath, () => GoodFile, () => new HeldFile());
                _ = Assert.Throws<InvalidOperationException>(() => verifier.Verify(path));
            }
        }

        [TestMethod]
        public void ReadExecuteAcesAreSafeButAllUntrustedWriteRightsAreRejected()
        {
            foreach (string sid in new[] { "S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-21-member" })
            {
                Assert.IsFalse(WindowsScriptTrustVerifier.AllowsUntrustedMutation(sid, 0x200A9));
                foreach (int mask in new[] { 2, 4, 16, 64, 256, 65536, 262144, 524288, 0x40000000, 0x10000000, 0x301BF, 0x1F01FF })
                { Assert.IsTrue(WindowsScriptTrustVerifier.AllowsUntrustedMutation(sid, mask)); }
            }
            Assert.IsFalse(WindowsScriptTrustVerifier.AllowsUntrustedMutation("S-1-5-18", 0x1F01FF));
            Assert.IsFalse(WindowsScriptTrustVerifier.AllowsUntrustedMutation("S-1-5-32-544", 0x1F01FF));
        }

        [TestMethod]
        public void UnknownSecurityProviderErrorsAreControlledRefusals()
        {
            WindowsScriptTrustVerifier verifier = new(_ => throw new System.Security.SecurityException("sensitive-owner"), () => GoodFile, () => new HeldFile());
            InvalidOperationException failure = Assert.Throws<InvalidOperationException>(() => verifier.Verify(WindowsScriptTrustVerifier.ScriptPath));
            Assert.IsFalse(failure.Message.Contains("sensitive", StringComparison.Ordinal));
        }
    }
}
