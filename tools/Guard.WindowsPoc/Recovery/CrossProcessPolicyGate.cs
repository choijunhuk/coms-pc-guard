using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Recovery
{
    internal interface IPolicyMutex : IDisposable
    {
        bool Wait(TimeSpan timeout, CancellationToken token);
        void Validate();
        void Release();
    }
    internal sealed record PolicyGateAccess(string Sid, int Rights);
    internal interface IPolicyGate
    {
        Task<T> RunAsync<T>(Func<Task<T>> action, CancellationToken cancellationToken);
    }

    internal sealed class CrossProcessPolicyGate : IPolicyGate
    {
        internal const string Name = @"Global\ComsPcGuard.WindowsPoc.PolicyGate";
        // READ_CONTROL is necessary to validate the opened object, in addition to wait/release.
        private const int RequiredRights = 0x120001;
        private static readonly AsyncLocal<OwnerTokenPolicyGateCapability?> HeldCapability = new();
        private readonly Func<IPolicyMutex> _open;
        private readonly TimeSpan _timeout;
        private readonly OwnerTokenPolicyGateCapability? _heldCapability;

        internal CrossProcessPolicyGate(string ownerSid)
        {
            ValidateOwner(ownerSid);
            _timeout = TimeSpan.FromSeconds(30);
            _open = () => OperatingSystem.IsWindows() ? NativeMutex.Open(ownerSid) : throw new PlatformNotSupportedException("NOT_RUN_WINDOWS_ONLY");
        }
        internal CrossProcessPolicyGate(OwnerTokenPolicyGateCapability capability)
        {
            ArgumentNullException.ThrowIfNull(capability);
            _ = capability.RevalidateNativePrincipal();
            _timeout = TimeSpan.FromSeconds(30);
            _open = () => OperatingSystem.IsWindows() ? NativeMutex.Open(capability) : throw new PlatformNotSupportedException("NOT_RUN_WINDOWS_ONLY");
            _heldCapability = capability;
        }
        internal CrossProcessPolicyGate(Func<IPolicyMutex> open, TimeSpan timeout)
        {
            ArgumentNullException.ThrowIfNull(open);
            if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(5)) { throw new ArgumentOutOfRangeException(nameof(timeout)); }
            _open = open; _timeout = timeout;
        }
        internal static void RequireHeld(OwnerTokenPolicyGateCapability capability)
        {
            ArgumentNullException.ThrowIfNull(capability);
            _ = capability.RevalidateNativePrincipal();
            if (!ReferenceEquals(HeldCapability.Value, capability))
            { throw new InvalidOperationException("Protected policy gate is not held."); }
        }
        internal static void ValidateOwner(string ownerSid)
        {
            string[] parts = ownerSid.Split('-');
            if (parts.Length != 8 || !ownerSid.StartsWith("S-1-5-21-", StringComparison.Ordinal)
                || parts.Skip(4).Any(part => !uint.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out uint value) || value == 0 || part != value.ToString(CultureInfo.InvariantCulture)))
            { throw new ArgumentException("One designated account SID is required.", nameof(ownerSid)); }
        }
        internal static void ValidateOwnerIdentity(string ownerSid, string? tokenUserSid)
        {
            ValidateOwner(ownerSid);
            if (tokenUserSid != ownerSid) { throw new InvalidOperationException("Designated Owner token required; SYSTEM attestation is not provisioned."); }
        }
        [SupportedOSPlatform("windows")]
        internal static void ValidateNativeOwner(string ownerSid)
        {
            ValidateNativeOwner(ownerSid, () =>
            {
                using WindowsIdentity? impersonated = WindowsIdentity.GetCurrent(ifImpersonating: true);
                return impersonated is not null;
            }, () =>
            {
                // No impersonation is permitted above, so this reads the process identity.
                using WindowsIdentity? identity = WindowsIdentity.GetCurrent(ifImpersonating: false);
                return identity?.User?.Value;
            });
        }

        internal static void ValidateNativeOwner(string ownerSid, Func<bool> isImpersonating, Func<string?> readProcessSid)
        {
            _ = ValidateNativeOwnerAndReadPrincipal(ownerSid, isImpersonating, readProcessSid);
        }
        internal static string ValidateNativeOwnerAndReadPrincipal(string ownerSid, Func<bool> isImpersonating, Func<string?> readProcessSid)
        {
            if (isImpersonating()) { throw new InvalidOperationException("Impersonated Owner attestation is not permitted."); }
            string? processSid = readProcessSid();
            ValidateOwnerIdentity(ownerSid, processSid);
            return ValidateCreationOwner(ownerSid, processSid);
        }
        internal static string ValidateCreationOwner(string ownerSid, string? currentPrincipalSid)
        {
            ValidateOwner(ownerSid);
            return currentPrincipalSid == ownerSid || currentPrincipalSid == "S-1-5-18"
                ? currentPrincipalSid
                : throw new InvalidOperationException("Policy gate creation requires a validated Owner or SYSTEM principal.");
        }
        internal static bool CanBootstrapGlobalGate(string? currentPrincipalSid)
        {
            return currentPrincipalSid == "S-1-5-18";
        }
        internal static void ValidateSecurity(string ownerSid, string? actualOwner, bool known, IReadOnlyList<PolicyGateAccess> rules)
        {
            ValidateOwner(ownerSid);
            if (!known || (actualOwner != ownerSid && actualOwner != "S-1-5-18") || rules.Count != 2
                || !rules.Any(rule => rule.Sid == ownerSid && rule.Rights == RequiredRights)
                || !rules.Any(rule => rule.Sid == "S-1-5-18" && rule.Rights == RequiredRights))
            { throw new InvalidOperationException("Policy gate security unavailable or mismatched."); }
        }
        public Task<T> RunAsync<T>(Func<Task<T>> action, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(action);
            cancellationToken.ThrowIfCancellationRequested();
            TaskCompletionSource<T> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Thread owner = new(() =>
            {
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    using IPolicyMutex mutex = _open();
                    bool acquired = false;
                    try
                    {
                        Stopwatch elapsed = Stopwatch.StartNew();
                        while (!acquired)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            TimeSpan remaining = _timeout - elapsed.Elapsed;
                            if (remaining <= TimeSpan.Zero) { throw new TimeoutException("Policy gate acquisition timed out."); }
                            try { acquired = mutex.Wait(remaining, cancellationToken); }
                            catch (AbandonedMutexException) { acquired = true; }
                        }
                        cancellationToken.ThrowIfCancellationRequested();
                        mutex.Validate();
                        // Block this dedicated OS thread through lease/reload/action/acknowledgement.
                        OwnerTokenPolicyGateCapability? previous = HeldCapability.Value;
                        if (_heldCapability is not null) { HeldCapability.Value = _heldCapability; }
                        T result;
                        try { result = action().GetAwaiter().GetResult(); }
                        finally { HeldCapability.Value = previous; }
                        acquired = false; mutex.Release();
                        _ = completion.TrySetResult(result);
                    }
                    finally { if (acquired) { mutex.Release(); } }
                }
                catch (OperationCanceledException error) { _ = completion.TrySetCanceled(error.CancellationToken); }
                catch (Exception error) { _ = completion.TrySetException(error); }
            })
            { IsBackground = true, Name = "Windows PoC policy gate owner" };
            owner.Start();
            return completion.Task;
        }

        [SupportedOSPlatform("windows")]
        private sealed class NativeMutex(Mutex mutex, string ownerSid) : IPolicyMutex
        {
            internal static NativeMutex Open(string ownerSid)
            {
                string creationOwnerSid = ValidateNativeOwnerAndReadPrincipal(ownerSid, () =>
                {
                    using WindowsIdentity? impersonated = WindowsIdentity.GetCurrent(ifImpersonating: true);
                    return impersonated is not null;
                }, () =>
                {
                    using WindowsIdentity? identity = WindowsIdentity.GetCurrent(ifImpersonating: false);
                    return identity?.User?.Value;
                });
                return OpenValidated(ownerSid, creationOwnerSid);
            }
            internal static NativeMutex Open(OwnerTokenPolicyGateCapability capability)
            {
                OwnerTokenNativePrincipal principal = capability.RevalidateNativePrincipal();
                return OpenValidated(principal.OwnerSid, principal.CurrentPrincipalSid);
            }
            private static NativeMutex OpenValidated(string ownerSid, string creationOwnerSid)
            {
                _ = ValidateCreationOwner(ownerSid, creationOwnerSid);
                MutexSecurity security = new();
                security.SetAccessRuleProtection(true, false);
                security.SetOwner(new SecurityIdentifier(creationOwnerSid));
                foreach (string sid in new[] { "S-1-5-18", ownerSid })
                { security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(sid), (MutexRights)RequiredRights, AccessControlType.Allow)); }
                Mutex mutex;
                try { mutex = MutexAcl.OpenExisting(Name, (MutexRights)RequiredRights); }
                catch (WaitHandleCannotBeOpenedException)
                {
                    if (!CanBootstrapGlobalGate(creationOwnerSid)) { throw new InvalidOperationException("SYSTEM policy gate bootstrap is required before Owner access."); }
                    mutex = MutexAcl.Create(false, Name, out _, security);
                }
                catch (UnauthorizedAccessException) when (!CanBootstrapGlobalGate(creationOwnerSid))
                {
                    throw new InvalidOperationException("SYSTEM policy gate bootstrap is required before Owner access.");
                }
                NativeMutex backend = new(mutex, ownerSid);
                try { backend.Validate(); return backend; }
                catch { backend.Dispose(); throw; }
            }
            public bool Wait(TimeSpan timeout, CancellationToken token)
            {
                // Cancellation wins when both handles are signaled; no mutex ownership in that case.
                int result = WaitHandle.WaitAny([token.WaitHandle, mutex], timeout);
                if (result == 0) { token.ThrowIfCancellationRequested(); }
                return result == 1;
            }
            public void Release() { mutex.ReleaseMutex(); }
            public void Dispose() { mutex.Dispose(); }
            public void Validate()
            {
                MutexSecurity security = mutex.GetAccessControl();
                RawSecurityDescriptor descriptor = new(security.GetSecurityDescriptorBinaryForm(), 0);
                List<PolicyGateAccess> rules = [];
                bool known = descriptor.DiscretionaryAcl is not null && security.AreAccessRulesProtected;
                if (descriptor.DiscretionaryAcl is not null)
                {
                    foreach (GenericAce ace in descriptor.DiscretionaryAcl)
                    {
                        if (ace is not CommonAce common || common.IsCallback || common.AceQualifier != AceQualifier.AccessAllowed || common.AceFlags != AceFlags.None)
                        { known = false; continue; }
                        rules.Add(new(common.SecurityIdentifier.Value, common.AccessMask));
                    }
                }
                ValidateSecurity(ownerSid, descriptor.Owner?.Value, known, rules);
            }
        }
    }
}
