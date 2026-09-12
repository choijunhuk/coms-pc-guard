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
                    return new(ReconciliationOutcomeKind.RecoveryRequired, "ObservationMismatch");
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
    }
}
