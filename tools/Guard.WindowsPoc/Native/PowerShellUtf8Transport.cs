using System.Diagnostics;
using System.Text;

namespace Guard.WindowsPoc.Native
{
    internal static class PowerShellUtf8Transport
    {
        internal const string Preamble = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false, $true); [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false, $true); $OutputEncoding = [Console]::OutputEncoding; ";
        private static readonly UTF8Encoding StrictUtf8 = new(false, true);

        internal static StreamReader OpenReader(Stream stream)
        {
            return new(stream, StrictUtf8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
        }

        internal static void Configure(ProcessStartInfo info)
        {
            ArgumentNullException.ThrowIfNull(info);
            if (info.RedirectStandardOutput) { info.StandardOutputEncoding = StrictUtf8; }
            if (info.RedirectStandardError) { info.StandardErrorEncoding = StrictUtf8; }
            if (info.RedirectStandardInput) { info.StandardInputEncoding = StrictUtf8; }
        }
    }
}
