using Guard.Service.Enforcement;
using Guard.Service.Storage;
using Microsoft.Data.Sqlite;

namespace Guard.Service.Reconciliation
{
    public sealed class PolicyReconciler
    {
        private readonly IPolicyStateStore _store;
        private readonly IEnforcementAdapter _adapter;
        private readonly TimeProvider _clock;
        private readonly PolicyOperationGate _gate;

        public PolicyReconciler(IPolicyStateStore store, IEnforcementAdapter adapter, TimeProvider timeProvider, PolicyOperationGate gate)
        {
            ArgumentNullException.ThrowIfNull(store);
            ArgumentNullException.ThrowIfNull(adapter);
            ArgumentNullException.ThrowIfNull(timeProvider);
            ArgumentNullException.ThrowIfNull(gate);
            _store = store;
            _adapter = adapter;
            _clock = timeProvider;
            _gate = gate;
        }

        public async Task<ReconciliationOutcome> RecoverPendingAsync(CancellationToken cancellationToken)
        {
            using IDisposable? lease = await _gate.TryAcquireAsync(cancellationToken).ConfigureAwait(false);
            if (lease is null)
            {
                return new(ReconciliationOutcomeKind.Busy);
            }

            string diagnostic = "StoreFailed";
            try
            {
                ReconciliationAttempt? attempt = await _store.GetPendingAttemptAsync(cancellationToken).ConfigureAwait(false);
                if (attempt is null)
                {
                    return new(ReconciliationOutcomeKind.NoWork);
                }
                PolicyArtifact desired = await _store.GetArtifactAsync(attempt.PolicyVersion, cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidDataException("Pending desired artifact is missing.");
                diagnostic = "ObservationFailed";
                EffectivePolicyObservation current = await _adapter.ObserveEffectiveAsync(cancellationToken).ConfigureAwait(false);
                // Restore identity is a durable direction, including while RecoveryBlocked.
                // Observing desired later must not reverse that decision.
                if (attempt.RestoreActionIdentity is not null)
                {
                    return await RestoreLastGoodAsync(attempt, current, cancellationToken).ConfigureAwait(false);
                }
                DateTimeOffset confirmedAt = _clock.GetUtcNow();
                if (PolicyConfirmationPolicy.IsConfirmed(desired, current, confirmedAt))
                {
                    diagnostic = "StoreFailed";
                    await _store.CommitObservedSuccessAsync(attempt.AttemptId, current, confirmedAt, cancellationToken).ConfigureAwait(false);
                    return new(ReconciliationOutcomeKind.Applied);
                }

                diagnostic = "ValidationFailed";
                ReconciliationOutcome? blocked = await ValidateRecoveryAsync(attempt, desired, cancellationToken).ConfigureAwait(false);
                if (blocked is not null)
                {
                    return blocked;
                }
                diagnostic = "ApplyFailed";
                cancellationToken.ThrowIfCancellationRequested();
                EnforcementApplyResult apply = await _adapter.ApplyOwnedDeltaAsync(desired, attempt.DesiredActionIdentity, cancellationToken).ConfigureAwait(false);
                if (!Enum.IsDefined(apply.MutationStatus))
                {
                    throw new InvalidOperationException("Adapter returned an invalid mutation status.");
                }
                string failure = string.IsNullOrWhiteSpace(apply.DiagnosticCode) ? "ApplyRejected" : apply.DiagnosticCode;
                if (apply.Accepted)
                {
                    diagnostic = "StoreFailed";
                    await _store.MarkDesiredRetryReportedAsync(attempt.AttemptId, _clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
                    diagnostic = "ObservationFailed";
                    current = await _adapter.ObserveEffectiveAsync(cancellationToken).ConfigureAwait(false);
                    confirmedAt = _clock.GetUtcNow();
                    if (PolicyConfirmationPolicy.IsConfirmed(desired, current, confirmedAt))
                    {
                        diagnostic = "StoreFailed";
                        await _store.CommitObservedSuccessAsync(attempt.AttemptId, current, confirmedAt, cancellationToken).ConfigureAwait(false);
                        return new(ReconciliationOutcomeKind.Applied);
                    }
                    failure = ObservationMismatchDiagnostic(desired, current, "ObservationMismatch");
                }

                diagnostic = "StoreFailed";
                PolicyArtifact? lastGood = await _store.GetLastGoodArtifactAsync(cancellationToken).ConfigureAwait(false);
                if (lastGood is null)
                {
                    await _store.MarkFailedAsync(attempt.AttemptId, "NO_LAST_GOOD", _clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
                    return new(ReconciliationOutcomeKind.NoLastGood, "NO_LAST_GOOD");
                }
                await _store.PrepareRestoreAsync(attempt.AttemptId, lastGood, failure, cancellationToken).ConfigureAwait(false);
                attempt = await _store.GetPendingAttemptAsync(cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidDataException("Prepared restore attempt is missing.");
                // The earlier observation may precede a rejected partial mutation. Restore
                // must use a fresh observation on restart, or validate/apply now.
                return await RestoreLastGoodAsync(attempt, null, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                // Keep the durable nonterminal phase. A later observer resolves uncertainty;
                // an exception alone is not evidence that fallback is safe or complete.
                return new(ReconciliationOutcomeKind.RecoveryFailed, diagnostic, exception);
            }
        }

        private async Task<ReconciliationOutcome?> ValidateRecoveryAsync(ReconciliationAttempt attempt, PolicyArtifact artifact, CancellationToken cancellationToken)
        {
            string? diagnostic;
            if (!_adapter.Capabilities.Supports(artifact.RequiredProtection))
            {
                diagnostic = "UnsupportedCapability";
            }
            else
            {
                EnforcementValidationResult validation = await _adapter.ValidateAsync(artifact, cancellationToken).ConfigureAwait(false);
                if (validation.IsValid && !validation.HasConflict)
                {
                    return null;
                }
                diagnostic = string.IsNullOrWhiteSpace(validation.DiagnosticCode) ? "UnsafeValidation" : validation.DiagnosticCode;
            }
            await _store.MarkRecoveryBlockedAsync(attempt.AttemptId, diagnostic, cancellationToken).ConfigureAwait(false);
            return new(ReconciliationOutcomeKind.RecoveryBlocked, diagnostic);
        }

        private async Task<ReconciliationOutcome> RestoreLastGoodAsync(ReconciliationAttempt attempt, EffectivePolicyObservation? current, CancellationToken cancellationToken)
        {
            string diagnostic = "StoreFailed";
            try
            {
                EnforcementActionIdentity identity = attempt.RestoreActionIdentity
                    ?? throw new InvalidDataException("Restore identity is missing.");
                PolicyArtifact artifact = await _store.GetArtifactAsync(identity.PolicyVersion, cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidDataException("Restore artifact is missing.");
                if (artifact.State != PolicyArtifactState.LastGood || artifact.Sha256Hex != identity.Sha256Hex)
                {
                    throw new InvalidDataException("Restore artifact does not match durable last good identity.");
                }
                if (current is null || !PolicyConfirmationPolicy.IsConfirmed(artifact, current, _clock.GetUtcNow()))
                {
                    diagnostic = "ValidationFailed";
                    ReconciliationOutcome? blocked = await ValidateRecoveryAsync(attempt, artifact, cancellationToken).ConfigureAwait(false);
                    if (blocked is not null)
                    {
                        return blocked;
                    }
                    diagnostic = "RestoreApplyFailed";
                    cancellationToken.ThrowIfCancellationRequested();
                    EnforcementApplyResult apply = await _adapter.ApplyOwnedDeltaAsync(artifact, identity, cancellationToken).ConfigureAwait(false);
                    if (!Enum.IsDefined(apply.MutationStatus))
                    {
                        throw new InvalidOperationException("Adapter returned an invalid mutation status.");
                    }
                    if (!apply.Accepted)
                    {
                        return new(ReconciliationOutcomeKind.RecoveryFailed, string.IsNullOrWhiteSpace(apply.DiagnosticCode) ? "RestoreApplyRejected" : apply.DiagnosticCode);
                    }
                    diagnostic = "StoreFailed";
                    await _store.MarkRestoreApplyReportedAsync(attempt.AttemptId, _clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
                    diagnostic = "RestoreObservationFailed";
                    current = await _adapter.ObserveEffectiveAsync(cancellationToken).ConfigureAwait(false);
                }
                DateTimeOffset confirmedAt = _clock.GetUtcNow();
                if (!PolicyConfirmationPolicy.IsConfirmed(artifact, current, confirmedAt))
                {
                    return new(ReconciliationOutcomeKind.RecoveryFailed, ObservationMismatchDiagnostic(artifact, current, "RestoreObservationMismatch"));
                }
                diagnostic = "StoreFailed";
                await _store.CompleteRestoredLastGoodAsync(attempt.AttemptId, current, "RESTORED_LAST_GOOD", confirmedAt, cancellationToken).ConfigureAwait(false);
                return new(ReconciliationOutcomeKind.RestoredLastGood);
            }
            catch (Exception exception)
            {
                return new(ReconciliationOutcomeKind.RecoveryFailed, diagnostic, exception);
            }
        }

        public async Task<ReconciliationOutcome> ReconcileAsync(PolicyArtifact desired, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(desired);
            using IDisposable? lease = await _gate.TryAcquireAsync(cancellationToken).ConfigureAwait(false);
            if (lease is null || await _store.GetPendingAttemptAsync(cancellationToken).ConfigureAwait(false) is not null)
            {
                return new(ReconciliationOutcomeKind.Busy);
            }
            if (!_adapter.Capabilities.Supports(desired.RequiredProtection))
            {
                return new(ReconciliationOutcomeKind.Unsupported, "UnsupportedCapability");
            }
            EnforcementValidationResult validation = await _adapter.ValidateAsync(desired, cancellationToken).ConfigureAwait(false);
            if (validation.HasConflict)
            {
                return new(ReconciliationOutcomeKind.Conflict, validation.DiagnosticCode);
            }
            if (!validation.IsValid)
            {
                return new(ReconciliationOutcomeKind.Rejected, validation.DiagnosticCode);
            }

            PolicyArtifact? lastGood = await _store.GetLastGoodArtifactAsync(cancellationToken).ConfigureAwait(false);
            if (lastGood is not null && lastGood.PolicyVersion == desired.PolicyVersion && lastGood.Sha256Hex == desired.Sha256Hex
                && lastGood.RequiredProtection == desired.RequiredProtection && lastGood.ExpectedOwnedState == desired.ExpectedOwnedState)
            {
                EffectivePolicyObservation current = await _adapter.ObserveEffectiveAsync(cancellationToken).ConfigureAwait(false);
                if (PolicyConfirmationPolicy.IsConfirmed(desired, current, _clock.GetUtcNow()))
                {
                    return new(ReconciliationOutcomeKind.AlreadyApplied);
                }
            }

            ReconciliationAttempt attempt = new(Guid.NewGuid(), desired.PolicyVersion, desired.Sha256Hex, _clock.GetUtcNow());
            try
            {
                await _store.SaveCandidateAndBeginAttemptAsync(desired, attempt, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is InvalidOperationException or SqliteException)
            {
                // The store's active-attempt guard and SQLite unique index are backstops
                // for callers that did not share the gate. Do not disguise other failures.
                if (await _store.GetPendingAttemptAsync(cancellationToken).ConfigureAwait(false) is not null)
                {
                    return new(ReconciliationOutcomeKind.Busy);
                }
                throw;
            }

            EnforcementApplyResult apply;
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                apply = await _adapter.ApplyOwnedDeltaAsync(desired, attempt.DesiredActionIdentity, cancellationToken).ConfigureAwait(false);
                if (!Enum.IsDefined(apply.MutationStatus))
                {
                    throw new InvalidOperationException("Adapter returned an invalid mutation status.");
                }
            }
            catch (Exception exception)
            {
                // Cancellation is recoverable only after Prepared has been persisted.
                try
                {
                    await _store.MarkDesiredUncertainAsync(attempt.AttemptId, "ApplyFailed", CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception persistenceException)
                {
                    return new(ReconciliationOutcomeKind.RecoveryRequired, "ApplyFailed", exception, persistenceException);
                }
                return new(ReconciliationOutcomeKind.RecoveryRequired, "ApplyFailed", exception);
            }

            string diagnostic = "StoreFailed";
            try
            {
                if (!apply.Accepted)
                {
                    string rejectionCode = string.IsNullOrWhiteSpace(apply.DiagnosticCode) ? "ApplyRejected" : apply.DiagnosticCode;
                    if (apply.MutationStatus == EnforcementMutationStatus.NoChange)
                    {
                        await _store.MarkFailedAsync(attempt.AttemptId, rejectionCode, _clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
                        return new(ReconciliationOutcomeKind.Rejected, rejectionCode);
                    }
                    await _store.MarkDesiredUncertainAsync(attempt.AttemptId, rejectionCode, cancellationToken).ConfigureAwait(false);
                    return new(ReconciliationOutcomeKind.RecoveryRequired, rejectionCode);
                }
                await _store.MarkApplyReportedAsync(attempt.AttemptId, _clock.GetUtcNow(), cancellationToken).ConfigureAwait(false);
                diagnostic = "ObservationFailed";
                EffectivePolicyObservation observation = await _adapter.ObserveEffectiveAsync(cancellationToken).ConfigureAwait(false);
                DateTimeOffset confirmedAt = _clock.GetUtcNow();
                if (!PolicyConfirmationPolicy.IsConfirmed(desired, observation, confirmedAt))
                {
                    return new(ReconciliationOutcomeKind.RecoveryRequired, ObservationMismatchDiagnostic(desired, observation, "ObservationMismatch"));
                }
                diagnostic = "StoreFailed";
                await _store.CommitObservedSuccessAsync(attempt.AttemptId, observation, confirmedAt, cancellationToken).ConfigureAwait(false);
                return new(ReconciliationOutcomeKind.Applied);
            }
            catch (Exception exception)
            {
                return new(ReconciliationOutcomeKind.RecoveryRequired, diagnostic, exception);
            }
        }

        private static string ObservationMismatchDiagnostic(PolicyArtifact artifact, EffectivePolicyObservation? observation, string fallback)
        {
            return observation is not null && !PolicyConfirmationPolicy.SatisfiesProtection(artifact.RequiredProtection, observation.ProtectionLevel)
                ? "ProtectionLevelMismatch"
                : fallback;
        }
    }
}
