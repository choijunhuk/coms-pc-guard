using System.Security.Principal;
using Guard.Service.Configuration;

namespace Guard.Windows
{
    /// <summary>An enabled local Windows account.</summary>
    public sealed record LocalAccount(string Name, string Sid, string? FullName);

    /// <summary>Account name and SID lookups shared by the Owner command line and the Owner screen.</summary>
    public static class WindowsAccounts
    {
        /// <summary>Resolves "name", "PC\name" or "DOMAIN\name" to the short name and SID; errors are plain Korean.</summary>
        public static (string Name, string Sid) Resolve(string account)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(account);
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("계정 확인은 Windows에서만 할 수 있습니다.");
            }

            try
            {
                SecurityIdentifier sid = (SecurityIdentifier)new NTAccount(account.Trim()).Translate(typeof(SecurityIdentifier));
                string full = ((NTAccount)sid.Translate(typeof(NTAccount))).Value;
                return (full[(full.LastIndexOf('\\') + 1)..], sid.Value);
            }
            catch (IdentityNotMappedException exception)
            {
                throw new GuardConfigurationException($"'{account}' 계정을 이 PC에서 찾을 수 없습니다.", exception);
            }
        }

        public static string? CurrentUserSid()
        {
            return OperatingSystem.IsWindows() ? WindowsIdentity.GetCurrent().User?.Value : null;
        }
    }
}
