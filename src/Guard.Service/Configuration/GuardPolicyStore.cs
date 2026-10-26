using System.Text;
using System.Text.Json;

namespace Guard.Service.Configuration
{
    /// <summary>
    /// Reads and writes the Owner policy file. Writes validate first, go to a temporary file flushed to disk, then replace the
    /// policy atomically while keeping the previous version as ".bak" (a hard power-off zero-filled a plainly copied file in the lab).
    /// </summary>
    public static class GuardPolicyStore
    {
        private static readonly JsonSerializerOptions WriteOptions = new(GuardPolicyDocumentReader.Options) { WriteIndented = true };

        public static string BackupPath(string policyPath)
        {
            return policyPath + ".bak";
        }

        public static GuardPolicyDocument ReadDocument(string policyPath)
        {
            return GuardPolicyDocumentReader.ParseDocument(File.ReadAllText(policyPath, Encoding.UTF8));
        }

        public static string Serialize(GuardPolicyDocument document)
        {
            ArgumentNullException.ThrowIfNull(document);
            return JsonSerializer.Serialize(document, WriteOptions);
        }

        /// <summary>Validates <paramref name="document"/> and atomically replaces the policy file.</summary>
        public static GuardConfiguration Write(string policyPath, GuardPolicyDocument document)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(policyPath);
            GuardConfiguration configuration = GuardPolicyDocumentReader.ToConfiguration(document);
            byte[] bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(Serialize(document));
            string directory = Path.GetDirectoryName(Path.GetFullPath(policyPath))!;
            _ = Directory.CreateDirectory(directory);
            string temporary = Path.Combine(directory, $"{Path.GetFileName(policyPath)}.{Guid.NewGuid():N}.tmp");
            try
            {
                using (FileStream stream = new(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    stream.Write(bytes);
                    stream.Flush(flushToDisk: true);
                }

                if (File.Exists(policyPath))
                {
                    File.Replace(temporary, policyPath, BackupPath(policyPath), ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(temporary, policyPath);
                }
            }
            finally
            {
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }

            return configuration;
        }

        /// <summary>Loads the policy, falling back to the previous version when the current file is unreadable or invalid.</summary>
        public static GuardPolicyLoad Load(string policyPath)
        {
            try
            {
                return new GuardPolicyLoad(GuardPolicyDocumentReader.Parse(File.ReadAllText(policyPath, Encoding.UTF8)), FromBackup: false, null);
            }
            catch (Exception exception) when (exception is GuardConfigurationException or IOException or UnauthorizedAccessException)
            {
                string backup = BackupPath(policyPath);
                if (!File.Exists(backup))
                {
                    throw;
                }

                return new GuardPolicyLoad(GuardPolicyDocumentReader.Parse(File.ReadAllText(backup, Encoding.UTF8)), FromBackup: true, exception.Message);
            }
        }
    }

    /// <summary><see cref="CurrentFileError"/> explains why the backup was used.</summary>
    public sealed record GuardPolicyLoad(GuardConfiguration Configuration, bool FromBackup, string? CurrentFileError);
}
