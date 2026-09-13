using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Guard.WindowsPoc.Native;
using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Guard.WindowsPoc.Execution
{
    internal sealed record PocOsProcessEvidence(int Pid, string Path, DateTimeOffset CreatedAtUtc, string Sid, int Session, uint LogonType, bool Active);

    internal static class PocSessionBroker
    {
        private static readonly object LaunchKey = new();
        internal static string BuildEnvironment(string profile)
        {
            return !profile.StartsWith(@"C:\Users\", StringComparison.OrdinalIgnoreCase) || profile.Length > 512 || profile.Any(char.IsControl)
                || profile.Split('\\').Any(part => part is "." or "..")
                ? throw new InvalidOperationException("Native profile refused.")
                : string.Join('\0', new[] { @"SystemRoot=C:\Windows", @"WINDIR=C:\Windows", @"PATH=C:\Windows\System32",
                "USERPROFILE=" + profile, "LOCALAPPDATA=" + profile + @"\AppData\Local", "TEMP=" + profile + @"\AppData\Local\Temp",
                "TMP=" + profile + @"\AppData\Local\Temp" }.Order(StringComparer.OrdinalIgnoreCase)) + "\0\0";
        }

        internal static bool Matches(PocOsProcessEvidence actual, int pid, string path, string sid, DateTimeOffset start)
        {
            return actual.Pid == pid && string.Equals(actual.Path, path, StringComparison.OrdinalIgnoreCase) && actual.Sid == sid
                && actual.CreatedAtUtc >= start && actual.Session > 0 && actual.LogonType is 2 or 10 or 11 && actual.Active;
        }

        [SupportedOSPlatform("windows")]
        internal static async Task<PocBrokerAttempt?> TryStartAsync(PocProbeRequest request, PocFixtureLease fixtures, OwnerTokenPolicyGateCapability capability, CancellationToken token)
        {
            CrossProcessPolicyGate.RequireHeld(capability);
            using WindowsIdentity? impersonated = WindowsIdentity.GetCurrent(ifImpersonating: true);
            using WindowsIdentity current = WindowsIdentity.GetCurrent();
            if (impersonated is not null || current.User?.Value != "S-1-5-18") { throw new InvalidOperationException("Protected SYSTEM broker required."); }
            using SafeAccessTokenHandle? interactive = FindActiveToken(request.TokenSid);
            if (interactive is null) { return null; }
            using RegistryKey? profileKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + request.TokenSid);
            string profile = profileKey?.GetValue("ProfileImagePath") as string ?? throw new InvalidOperationException("Native profile unavailable.");
            string environment = BuildEnvironment(profile);
            fixtures.RevalidateClosure();
            PocBrokerChild? control = null;
            PocBrokerChild? target = null;
            try
            {
                control = await StartAsync(interactive, request, "control", environment, fixtures, token).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("Control fixture was blocked.");
                DateTimeOffset attemptedAt = DateTimeOffset.UtcNow;
                target = await StartAsync(interactive, request, "target", environment, fixtures, token).ConfigureAwait(false);
                fixtures.RevalidateClosure();
                return new(LaunchKey, control, target, attemptedAt, target is null, capability);
            }
            catch { try { target?.Dispose(); } finally { control?.Dispose(); } throw; }
        }

        [SupportedOSPlatform("windows")]
        private static async Task<PocBrokerChild?> StartAsync(SafeAccessTokenHandle tokenHandle, PocProbeRequest request, string name,
            string environment, PocFixtureLease fixtures, CancellationToken token)
        {
            PipeSecurity security = new();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(new SecurityIdentifier("S-1-5-18"));
            security.AddAccessRule(new(new SecurityIdentifier("S-1-5-18"), PipeAccessRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new(new SecurityIdentifier(request.TokenSid), PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
            security.AddAccessRule(new(new SecurityIdentifier("S-1-5-2"), PipeAccessRights.FullControl, AccessControlType.Deny));
            NamedPipeServerStream pipe = NamedPipeServerStreamAcl.Create("ComsPcGuardPoc.Probe." + request.RunId.ToString("D") + "." + name,
                PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, security);
            PocBrokerChild? child = null;
            IntPtr descriptor = IntPtr.Zero;
            IntPtr environmentPointer = IntPtr.Zero;
            try
            {
                if (!ConvertStringSecurityDescriptorToSecurityDescriptor("O:SYD:P(A;;GA;;;SY)", 1, out descriptor, out _)) { throw NativeFailure(); }
                SecurityAttributes attributes = new() { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor };
                StartupInfo startup = new() { Size = Marshal.SizeOf<StartupInfo>(), Desktop = @"winsta0\default" };
                environmentPointer = Marshal.StringToHGlobalUni(environment);
                string path = @"C:\ComsPcGuardPoc\Fixtures\" + name + ".exe";
                char[] command = ("\"" + path + "\" " + request.RunId.ToString("D") + "\0").ToCharArray();
                fixtures.RevalidateClosure();
                DateTimeOffset started = DateTimeOffset.UtcNow;
                if (!CreateProcessAsUser(tokenHandle, path, command, ref attributes, ref attributes, false, 0x414,
                    environmentPointer, @"C:\ComsPcGuardPoc\Fixtures", ref startup, out ProcessInformation process))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 1260) { pipe.Dispose(); return null; }
                    throw new Win32Exception(error);
                }
                using SafeWaitHandle thread = new(process.Thread, true);
                child = new(LaunchKey, new SafeProcessHandle(process.Process, true), pipe, (int)process.ProcessId, path, request.TokenSid, started);
                child.Revalidate();
                fixtures.RevalidateClosure();
                if (ResumeThread(thread) == uint.MaxValue) { throw NativeFailure(); }
                using CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                deadline.CancelAfter(TimeSpan.FromSeconds(30));
                await pipe.WaitForConnectionAsync(deadline.Token).ConfigureAwait(false);
                if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint clientPid) || clientPid != process.ProcessId) { throw new InvalidOperationException("Unrelated pipe client refused."); }
                child.Revalidate();
                string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
                using StreamWriter writer = new(pipe, new UTF8Encoding(false), 1024, leaveOpen: true) { AutoFlush = true };
                using StreamReader reader = new(pipe, Encoding.UTF8, false, 1024, leaveOpen: true);
                await writer.WriteAsync((nonce + "\n").AsMemory(), deadline.Token).ConfigureAwait(false);
                await writer.FlushAsync(deadline.Token).ConfigureAwait(false);
                char[] response = new char[65];
                int count = await reader.ReadBlockAsync(response.AsMemory(), deadline.Token).ConfigureAwait(false);
                if (count != 65 || new string(response, 0, 64) != nonce || response[64] != '\n') { throw new InvalidOperationException("Fixture challenge refused."); }
                child.Revalidate();
                return child;
            }
            catch { if (child is null) { pipe.Dispose(); } else { child.Dispose(); } throw; }
            finally { if (descriptor != IntPtr.Zero) { _ = LocalFree(descriptor); } if (environmentPointer != IntPtr.Zero) { Marshal.FreeHGlobal(environmentPointer); } }
        }

        [SupportedOSPlatform("windows")]
        private static SafeAccessTokenHandle? FindActiveToken(string sid)
        {
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out IntPtr sessions, out int count)) { throw NativeFailure(); }
            SafeAccessTokenHandle? found = null;
            try
            {
                if (count > 64) { throw new InvalidOperationException("Session enumeration exceeded bound."); }
                for (int index = 0; index < count; index++)
                {
                    WtsSession session = Marshal.PtrToStructure<WtsSession>(sessions + (index * Marshal.SizeOf<WtsSession>()));
                    if (session.SessionId <= 0 || session.State != 0) { continue; }
                    if (!WTSQueryUserToken((uint)session.SessionId, out SafeAccessTokenHandle candidate)) { throw NativeFailure(); }
                    using (candidate)
                    using (WindowsIdentity identity = new(candidate.DangerousGetHandle()))
                    {
                        if (identity.User?.Value != sid) { continue; }
                        if (found is not null) { throw new InvalidOperationException("Ambiguous active session."); }
                        if (!DuplicateTokenEx(candidate, 0x02000000, IntPtr.Zero, 2, 1, out found)) { throw NativeFailure(); }
                    }
                }
                return found;
            }
            catch { found?.Dispose(); throw; }
            finally { WTSFreeMemory(sessions); }
        }

        [SupportedOSPlatform("windows")]
        internal sealed class PocBrokerAttempt : IDisposable
        {
            internal PocBrokerChild Control { get; }
            internal PocBrokerChild? Target { get; }
            internal DateTimeOffset TargetAttemptedAtUtc { get; }
            internal bool PolicyDenied { get; }
            private readonly OwnerTokenPolicyGateCapability _capability;
            internal PocBrokerAttempt(object key, PocBrokerChild control, PocBrokerChild? target, DateTimeOffset attemptedAt, bool denied, OwnerTokenPolicyGateCapability capability)
            {
                if (!ReferenceEquals(key, LaunchKey)) { throw new InvalidOperationException("Native launch capability required."); }
                Control = control; Target = target; TargetAttemptedAtUtc = attemptedAt; PolicyDenied = denied;
                _capability = capability;
            }
            internal void Revalidate() { CrossProcessPolicyGate.RequireHeld(_capability); Control.Revalidate(); Target?.Revalidate(); }
            public void Dispose() { try { Target?.Dispose(); } finally { Control.Dispose(); } }
        }

        [SupportedOSPlatform("windows")]
        internal sealed class PocBrokerChild : IDisposable
        {
            private readonly SafeProcessHandle _process;
            private readonly SafeAccessTokenHandle _token;
            private readonly NamedPipeServerStream _pipe;
            private readonly string _path;
            private readonly string _sid;
            private readonly DateTimeOffset _started;
            internal int Pid { get; }
            internal PocOsProcessEvidence Evidence { get; private set; } = null!;
            internal PocBrokerChild(object key, SafeProcessHandle process, NamedPipeServerStream pipe, int pid, string path, string sid, DateTimeOffset started)
            {
                if (!ReferenceEquals(key, LaunchKey)) { throw new InvalidOperationException("Native launch capability required."); }
                _process = process; _pipe = pipe; Pid = pid; _path = path; _sid = sid; _started = started;
                if (!OpenProcessToken(process, 8, out _token)) { _ = TerminateProcess(process, 3); process.Dispose(); pipe.Dispose(); throw NativeFailure(); }
            }
            internal void Revalidate()
            {
                char[] path = new char[1024]; uint length = (uint)path.Length;
                if (!GetExitCodeProcess(_process, out uint exitCode) || exitCode != 259 || !QueryFullProcessImageName(_process, 0, path, ref length)
                    || !GetProcessTimes(_process, out long created, out _, out _, out _)) { throw NativeFailure(); }
                using WindowsIdentity identity = new(_token.DangerousGetHandle());
                TokenStatistics stats = ReadToken<TokenStatistics>(_token, 10);
                int session = ReadToken<int>(_token, 12);
                if (stats.Type != 1 || LsaGetLogonSessionData(ref stats.AuthenticationId, out IntPtr data) != 0) { throw new InvalidOperationException("Interactive primary logon required."); }
                uint logonType;
                try
                {
                    LogonSession logon = Marshal.PtrToStructure<LogonSession>(data);
                    if (logon.Session != session || logon.Sid == IntPtr.Zero || new SecurityIdentifier(logon.Sid).Value != _sid) { throw new InvalidOperationException("Interactive logon mismatch."); }
                    logonType = logon.LogonType;
                }
                finally { _ = LsaFreeReturnBuffer(data); }
                if (!WTSQuerySessionInformation(IntPtr.Zero, session, 8, out IntPtr state, out int bytes)) { throw NativeFailure(); }
                bool active;
                try { active = bytes == 4 && Marshal.ReadInt32(state) == 0; } finally { WTSFreeMemory(state); }
                Evidence = new(Pid, new string(path, 0, (int)length), new(DateTime.FromFileTimeUtc(created)), identity.User?.Value ?? "", session, logonType, active);
                if (!Matches(Evidence, Pid, _path, _sid, _started)) { throw new InvalidOperationException("OS process proof mismatch."); }
            }
            public void Dispose()
            {
                bool stopped = _process.IsClosed;
                try
                {
                    if (!stopped) { _ = TerminateProcess(_process, 0); stopped = WaitForSingleObject(_process, 5000) == 0; }
                }
                finally { _pipe.Dispose(); _token.Dispose(); _process.Dispose(); }
                if (!stopped) { throw new InvalidOperationException("Fixture process cleanup timed out."); }
            }
        }

        [SupportedOSPlatform("windows")]
        private static T ReadToken<T>(SafeAccessTokenHandle token, int information) where T : struct
        {
            int length = Marshal.SizeOf<T>(); IntPtr buffer = Marshal.AllocHGlobal(length);
            try { return GetTokenInformation(token, information, buffer, length, out int returned) && returned == length ? Marshal.PtrToStructure<T>(buffer) : throw NativeFailure(); }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        private static Win32Exception NativeFailure() { return new(Marshal.GetLastWin32Error()); }

        [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes { internal int Length; internal IntPtr Descriptor; internal int Inherit; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            internal int Size; internal IntPtr Reserved; internal string? Desktop; internal string? Title;
            internal int X; internal int Y; internal int XSize; internal int YSize; internal int XCount; internal int YCount;
            internal int Fill; internal int Flags; internal short Show; internal short ReservedCount; internal IntPtr ReservedBytes;
            internal IntPtr Input; internal IntPtr Output; internal IntPtr Error;
        }
        [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation { internal IntPtr Process; internal IntPtr Thread; internal uint ProcessId; internal uint ThreadId; }
        [StructLayout(LayoutKind.Sequential)] private struct WtsSession { internal int SessionId; internal IntPtr Name; internal int State; }
        [StructLayout(LayoutKind.Sequential)] private struct Luid { internal uint Low; internal int High; }
        [StructLayout(LayoutKind.Sequential)] private struct TokenStatistics { internal Luid TokenId; internal Luid AuthenticationId; internal long Expiry; internal int Type; internal int Impersonation; internal uint Charged; internal uint Available; internal uint Groups; internal uint Privileges; internal Luid Modified; }
        [StructLayout(LayoutKind.Sequential)] private struct UnicodeString { internal ushort Length; internal ushort Maximum; internal IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)] private struct LogonSession { internal uint Size; internal Luid Id; internal UnicodeString User; internal UnicodeString Domain; internal UnicodeString Package; internal uint LogonType; internal int Session; internal IntPtr Sid; }

#pragma warning disable SYSLIB1054
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateProcessAsUserW")]
        private static extern bool CreateProcessAsUser(SafeAccessTokenHandle token, string application, [In, Out] char[] command, ref SecurityAttributes processAttributes, ref SecurityAttributes threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInformation process);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW")] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string descriptor, uint revision, out IntPtr result, out uint size);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int information, IntPtr buffer, int length, out int returned);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool DuplicateTokenEx(SafeAccessTokenHandle token, uint access, IntPtr attributes, int level, int type, out SafeAccessTokenHandle duplicate);
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WTSEnumerateSessionsW")] private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
        [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSQueryUserToken(uint session, out SafeAccessTokenHandle token);
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WTSQuerySessionInformationW")] private static extern bool WTSQuerySessionInformation(IntPtr server, int session, int information, out IntPtr buffer, out int bytes);
        [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr memory);
        [DllImport("secur32.dll")] private static extern uint LsaGetLogonSessionData(ref Luid id, out IntPtr data);
        [DllImport("secur32.dll")] private static extern uint LsaFreeReturnBuffer(IntPtr data);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(SafeWaitHandle thread);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "QueryFullProcessImageNameW")] private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, [Out] char[] path, ref uint length);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
#pragma warning restore SYSLIB1054
    }
}
