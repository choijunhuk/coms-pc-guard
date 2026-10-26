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

        public static readonly TimeSpan DefaultLockTimeout = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Exclusive lock for a read-edit-write of <paramref name="policyPath"/> (a "&lt;policy&gt;.lock" file opened without sharing),
        /// so the Owner screen and the command line never both read version N and write N+1.
        /// </summary>
        public static IDisposable Lock(string policyPath, TimeSpan? timeout = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(policyPath);
            string lockPath = Path.GetFullPath(policyPath) + ".lock";
            DateTime deadline = DateTime.UtcNow + (timeout ?? DefaultLockTimeout);
            while (true)
            {
                try
                {
                    return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                }
                catch (DirectoryNotFoundException)
                {
                    throw;
                }
                catch (IOException exception)
                {
                    if (DateTime.UtcNow >= deadline)
                    {
                        throw new GuardConfigurationException("다른 곳(관리 화면이나 명령어)에서 설정을 바꾸는 중이에요. 잠시 뒤 다시 해 주세요.", exception);
                    }

                    Thread.Sleep(50);
                }
            }
        }

        /// <summary>Reads, edits and saves the policy under <see cref="Lock"/>. Returns the saved document.</summary>
        public static GuardPolicyDocument Update(string policyPath, Func<GuardPolicyDocument, GuardPolicyDocument> edit, TimeSpan? lockTimeout = null)
        {
            ArgumentNullException.ThrowIfNull(edit);
            using IDisposable gate = Lock(policyPath, lockTimeout);
            GuardPolicyDocument updated = edit(ReadDocument(policyPath));
            _ = Write(policyPath, updated);
            return updated;
        }

        /// <summary>Saves a new policy under <see cref="Lock"/>; returns false, writing nothing, when one exists and <paramref name="overwrite"/> is false.</summary>
        public static bool Create(string policyPath, GuardPolicyDocument document, bool overwrite)
        {
            ArgumentNullException.ThrowIfNull(document);
            _ = Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(policyPath))!);
            using IDisposable gate = Lock(policyPath);
            if (File.Exists(policyPath) && !overwrite)
            {
                return false;
            }

            _ = Write(policyPath, document);
            return true;
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
