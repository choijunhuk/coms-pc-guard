using System.Text;

namespace Guard.Core.Identity
{
    public abstract class ApplicationIdentity
    {
        private protected ApplicationIdentity(string identityId)
        {
            IdentityId = ApplicationIdentityValidation.RequiredText(identityId, nameof(identityId));
        }

        public string IdentityId { get; }

        public abstract ApplicationIdentityKind Kind { get; }
    }

    internal static class ApplicationIdentityValidation
    {
        internal static string RequiredText(string value, string parameterName)
        {
            ArgumentNullException.ThrowIfNull(value, parameterName);

            return string.IsNullOrWhiteSpace(value)
                || char.IsWhiteSpace(value[0])
                || char.IsWhiteSpace(value[^1])
                || value.Any(char.IsControl)
                || !value.IsNormalized(NormalizationForm.FormC)
                ? throw new ArgumentException(
                    "A non-empty NFC value without surrounding whitespace or control characters is required.",
                    parameterName)
                : value;
        }

        internal static string BinaryName(string value, string parameterName)
        {
            string binary = WindowsIdentityText(value, parameterName);
            return binary.Contains('/') || binary.Contains('\\') || binary.Contains(':') || binary is "." or ".."
                ? throw new ArgumentException("A leaf binary file name is required.", parameterName)
                : binary;
        }

        internal static string WindowsIdentityText(string value, string parameterName)
        {
            string text = RequiredText(value, parameterName);
            return text.Contains('*') || text.Contains('?')
                ? throw new ArgumentException("Wildcard characters are not permitted in Windows identity text.", parameterName)
                : text;
        }

        internal static Version FourPartVersion(Version value, string parameterName)
        {
            ArgumentNullException.ThrowIfNull(value, parameterName);

            return value.Build < 0 || value.Revision < 0
                ? throw new ArgumentException("A four-part version is required.", parameterName)
                : value.Major > ushort.MaxValue
                || value.Minor > ushort.MaxValue
                || value.Build > ushort.MaxValue
                || value.Revision > ushort.MaxValue
                ? throw new ArgumentOutOfRangeException(
                    parameterName,
                    "Every version component must be between 0 and 65535.")
                : value;
        }

        internal static string Sha256(string value, string parameterName)
        {
            ArgumentNullException.ThrowIfNull(value, parameterName);

            return value.Length != 64 || value.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
                ? throw new ArgumentException(
                    "SHA-256 must be exactly 64 lowercase hexadecimal characters.",
                    parameterName)
                : value;
        }

        internal static TEnum DefinedEnum<TEnum>(TEnum value, string parameterName)
            where TEnum : struct, Enum
        {
            return Enum.IsDefined(value)
                ? value
                : throw new ArgumentOutOfRangeException(parameterName, "A defined enum value is required.");
        }
    }
}
