namespace Guard.Service.Storage
{
    internal static class SqliteSchema
    {
        internal const long CurrentVersion = 1;

        internal const string CreateMigrationsTable = """
        CREATE TABLE IF NOT EXISTS schema_migrations(
            version INTEGER PRIMARY KEY,
            applied_utc TEXT NOT NULL
        );
        """;

        internal const string SchemaMigrationsDefinition = """
        CREATE TABLE schema_migrations(
            version INTEGER PRIMARY KEY,
            applied_utc TEXT NOT NULL
        );
        """;

        internal const string PolicyArtifactsDefinition = """
        CREATE TABLE policy_artifacts(
            policy_version INTEGER PRIMARY KEY,
            canonical_json TEXT NOT NULL,
            sha256_hex TEXT NOT NULL,
            required_protection INTEGER NOT NULL CHECK(required_protection BETWEEN 0 AND 3),
            expected_owned_state INTEGER NOT NULL CHECK(expected_owned_state BETWEEN 0 AND 1),
            created_utc TEXT NOT NULL,
            state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 1),
            UNIQUE(policy_version, sha256_hex)
        );
        """;

        internal const string AppliedObservationsDefinition = """
        CREATE TABLE applied_observations(
            observation_id TEXT PRIMARY KEY,
            policy_version INTEGER NOT NULL,
            sha256_hex TEXT NOT NULL,
            observed_utc TEXT NOT NULL,
            protection_level INTEGER NOT NULL CHECK(protection_level BETWEEN 0 AND 3),
            observed_owned_state INTEGER NOT NULL CHECK(observed_owned_state BETWEEN 0 AND 2),
            external_deny_present INTEGER NOT NULL CHECK(external_deny_present IN (0,1)),
            evidence_json TEXT NOT NULL,
            FOREIGN KEY(policy_version, sha256_hex)
                REFERENCES policy_artifacts(policy_version, sha256_hex)
        );
        """;

        internal const string ReconciliationAttemptsDefinition = """
        CREATE TABLE reconciliation_attempts(
            attempt_id TEXT PRIMARY KEY,
            policy_version INTEGER NOT NULL,
            sha256_hex TEXT NOT NULL,
            phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 7),
            desired_action_id TEXT NOT NULL UNIQUE,
            restore_action_id TEXT NULL UNIQUE,
            restore_policy_version INTEGER NULL,
            restore_sha256_hex TEXT NULL,
            prepared_utc TEXT NOT NULL,
            apply_reported_utc TEXT NULL,
            completed_utc TEXT NULL,
            error_code TEXT NULL,
            FOREIGN KEY(policy_version, sha256_hex)
                REFERENCES policy_artifacts(policy_version, sha256_hex),
            FOREIGN KEY(restore_policy_version, restore_sha256_hex)
                REFERENCES policy_artifacts(policy_version, sha256_hex)
        );
        """;

        internal const string NonterminalAttemptIndexDefinition = """
        CREATE UNIQUE INDEX ux_reconciliation_attempts_one_nonterminal
            ON reconciliation_attempts((1))
        WHERE phase BETWEEN 0 AND 5;
        """;

        internal const string LastGoodArtifactIndexDefinition = """
        CREATE UNIQUE INDEX ux_policy_artifacts_one_last_good
            ON policy_artifacts(state)
        WHERE state = 1;
        """;

        internal const string CreateVersionOneTables =
            PolicyArtifactsDefinition
            + AppliedObservationsDefinition
            + ReconciliationAttemptsDefinition
            + NonterminalAttemptIndexDefinition
            + LastGoodArtifactIndexDefinition;
    }
}
