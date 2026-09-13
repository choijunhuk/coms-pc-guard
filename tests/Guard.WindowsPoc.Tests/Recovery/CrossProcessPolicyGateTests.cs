using Guard.WindowsPoc.Recovery;
using Guard.WindowsPoc.Safety;

namespace Guard.WindowsPoc.Tests.Recovery
{
    [TestClass]
    public sealed class CrossProcessPolicyGateTests
    {
        private const string Owner = "S-1-5-21-1-2-3-1001";

        [TestMethod]
        [DataRow(Owner, false, true)]
        [DataRow("S-1-5-18", true, false)]
        [DataRow("S-1-5-21-1-2-3-1002", true, false)]
        [DataRow("S-1-5-18", false, false)]
        public void NativeOwnerIdentityRejectsImpersonationBeforeReadingProcessToken(string processSid, bool ownerImpersonation, bool accepted)
        {
            bool processRead = false;
            void Validate()
            {
                CrossProcessPolicyGate.ValidateNativeOwner(Owner, () => ownerImpersonation, () =>
                {
                    processRead = true;
                    // GetCurrent(false) returns the impersonated Owner if called before rejection.
                    return ownerImpersonation ? Owner : processSid;
                });
            }
            if (accepted) { Validate(); }
            else { _ = Assert.ThrowsExactly<InvalidOperationException>(Validate); }
            Assert.AreEqual(!ownerImpersonation, processRead);
        }

        [TestMethod]
        public async Task AcquisitionReceivesCancellationSignalRatherThanOnlyPolling()
        {
            using Mutex mutex = new();
            using CancellationTokenSource cancellation = new();
            Backend backend = new(mutex);
            _ = await new CrossProcessPolicyGate(() => backend, TimeSpan.FromSeconds(2)).RunAsync(() => Task.FromResult(1), cancellation.Token);
            Assert.AreEqual(cancellation.Token, backend.WaitToken);
        }

        [TestMethod]
        public void NativeOwnerAttestationRejectsSystemOrOtherTokenIdentity()
        {
            CrossProcessPolicyGate.ValidateOwnerIdentity(Owner, Owner);
            foreach (string? identity in new[] { null, "S-1-5-18", "S-1-5-32-544", "S-1-5-21-1-2-3-1002" })
            { _ = Assert.ThrowsExactly<InvalidOperationException>(() => CrossProcessPolicyGate.ValidateOwnerIdentity(Owner, identity)); }
        }

        [TestMethod]
        public void PolicyGateConstructionRequiresNativeOwnerAttestationCapability()
        {
            OwnerTokenAttestationProof proof = OwnerTokenAttestation.CreateProof(Owner, "0123456789abcdef0123456789abcdef", "COMS-PC-Guard-x64-Lab", new string('a', 64));
            OwnerTokenPolicyGateCapability accepted = OwnerTokenAttestation.AuthorizePolicyGate(Owner, proof.Nonce, proof.ExpectedVmName, proof.VmIdentityHash,
                new OwnerTokenAttestationContext("S-1-5-18", false, true, proof));
            _ = new CrossProcessPolicyGate(accepted);

            _ = Assert.ThrowsExactly<InvalidOperationException>(() => OwnerTokenAttestation.AuthorizePolicyGate(Owner, proof.Nonce, proof.ExpectedVmName,
                proof.VmIdentityHash, new OwnerTokenAttestationContext("S-1-5-18", false, true, proof with { AclVerified = false })));
        }

        [TestMethod]
        public async Task ReleaseFailureIsNotRetried()
        {
            using Mutex mutex = new();
            Backend backend = new(mutex) { FailRelease = true };
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => new CrossProcessPolicyGate(() => backend, TimeSpan.FromSeconds(2)).RunAsync(() => Task.FromResult(1), CancellationToken.None));
            Assert.AreEqual(1, backend.Releases);
        }

        [TestMethod]
        public async Task AsyncActionAndFailureReleaseOnAcquiringThreadExactlyOnce()
        {
            using Mutex mutex = new();
            Backend backend = new(mutex);
            CrossProcessPolicyGate gate = new(() => backend, TimeSpan.FromSeconds(2));
            Assert.AreEqual(42, await gate.RunAsync(async () => { await Task.Yield(); return 42; }, CancellationToken.None));
            Assert.AreEqual(backend.AcquiredThread, backend.ReleasedThread);
            Assert.AreEqual(1, backend.Releases);
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => gate.RunAsync<int>(async () => { await Task.Yield(); throw new InvalidOperationException(); }, CancellationToken.None));
            Assert.AreEqual(2, backend.Releases);
            Assert.AreEqual(backend.AcquiredThread, backend.ReleasedThread);
        }

        [TestMethod]
        public async Task ControllersAndWatchdogsSerializeAcrossIndependentGates()
        {
            using Mutex mutex = new();
            int active = 0, completed = 0;
            Task<int>[] calls = [.. Enumerable.Range(0, 4).Select(_ => new CrossProcessPolicyGate(() => new Backend(mutex), TimeSpan.FromSeconds(5)).RunAsync(async () =>
            {
                Assert.AreEqual(1, Interlocked.Increment(ref active));
                await Task.Delay(30);
                _ = Interlocked.Decrement(ref active);
                return Interlocked.Increment(ref completed);
            }, CancellationToken.None))];
            _ = await Task.WhenAll(calls);
            Assert.AreEqual(4, completed);
        }

        [TestMethod]
        public async Task WaitingCancellationAndTimeoutNeverRunAction()
        {
            using Mutex mutex = new();
            using ManualResetEventSlim acquired = new();
            TaskCompletionSource<int> release = new(TaskCreationOptions.RunContinuationsAsynchronously);
            CrossProcessPolicyGate gate = new(() => new Backend(mutex), TimeSpan.FromMilliseconds(150));
            Task<int> first = gate.RunAsync(() => { acquired.Set(); return release.Task; }, CancellationToken.None);
            Assert.IsTrue(acquired.Wait(TimeSpan.FromSeconds(2)));
            int runs = 0;
            using CancellationTokenSource cancel = new(40);
            _ = await Assert.ThrowsAsync<OperationCanceledException>(() => gate.RunAsync(() => Task.FromResult(++runs), cancel.Token));
            _ = await Assert.ThrowsExactlyAsync<TimeoutException>(() => gate.RunAsync(() => Task.FromResult(++runs), CancellationToken.None));
            release.SetResult(1);
            _ = await first;
            Assert.AreEqual(0, runs);
        }

        [TestMethod]
        public async Task AbandonedOwnershipStillRunsAndReleasesOnOwnerThread()
        {
            using Mutex mutex = new();
            Thread abandoned = new(() => mutex.WaitOne());
            abandoned.Start(); abandoned.Join();
            Backend backend = new(mutex);
            Assert.AreEqual(7, await new CrossProcessPolicyGate(() => backend, TimeSpan.FromSeconds(2)).RunAsync(() => Task.FromResult(7), CancellationToken.None));
            Assert.AreEqual(1, backend.Releases);
            Assert.AreEqual(backend.AcquiredThread, backend.ReleasedThread);
        }

        [TestMethod]
        public void SecurityAllowlistRejectsOtherAccountsGroupsAndUnknownAcls()
        {
            PolicyGateAccess[] allowed = [new("S-1-5-18", 0x120001), new(Owner, 0x120001)];
            CrossProcessPolicyGate.ValidateSecurity(Owner, Owner, true, allowed);
            foreach (string sid in new[] { "S-1-1-0", "S-1-5-32-544", "S-1-5-32-545", "S-1-5-11", "S-1-5-21-1-2-3-1002" })
            {
                _ = Assert.ThrowsExactly<InvalidOperationException>(() => CrossProcessPolicyGate.ValidateSecurity(Owner, Owner, true, [.. allowed, new(sid, 1)]));
            }
            foreach (string owner in new[] { "S-1-5-18", "S-1-5-32-544", "S-1-1-0", "bad" })
            { _ = Assert.ThrowsExactly<ArgumentException>(() => CrossProcessPolicyGate.ValidateOwner(owner)); }
            _ = Assert.ThrowsExactly<InvalidOperationException>(() => CrossProcessPolicyGate.ValidateSecurity(Owner, Owner, false, allowed));
        }

        [TestMethod]
        public async Task NativeGateIsWindowsOnlyOrSerializesActualGlobalMutex()
        {
            if (!OperatingSystem.IsWindows())
            {
                _ = await Assert.ThrowsExactlyAsync<PlatformNotSupportedException>(() => new CrossProcessPolicyGate(Owner).RunAsync(() => Task.FromResult(1), CancellationToken.None));
                return;
            }
            string sid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
            CrossProcessPolicyGate first = new(sid), second = new(sid);
            int active = 0;
            async Task<int> Action() { Assert.AreEqual(1, Interlocked.Increment(ref active)); await Task.Delay(30); return Interlocked.Decrement(ref active); }
            _ = await Task.WhenAll(first.RunAsync(Action, CancellationToken.None), second.RunAsync(Action, CancellationToken.None));
        }

        private sealed class Backend(Mutex mutex) : IPolicyMutex
        {
            public int AcquiredThread { get; private set; }
            public int ReleasedThread { get; private set; }
            public int Releases { get; private set; }
            public bool FailRelease { get; init; }
            public CancellationToken WaitToken { get; private set; }
            public bool Wait(TimeSpan timeout, CancellationToken token)
            {
                WaitToken = token;
                try
                {
                    int result = WaitHandle.WaitAny([token.WaitHandle, mutex], timeout);
                    if (result == 0) { token.ThrowIfCancellationRequested(); }
                    bool acquired = result == 1;
                    if (acquired) { AcquiredThread = Environment.CurrentManagedThreadId; }
                    return acquired;
                }
                catch (AbandonedMutexException) { AcquiredThread = Environment.CurrentManagedThreadId; throw; }
            }
            public void Validate() { }
            public void Release() { ReleasedThread = Environment.CurrentManagedThreadId; Releases++; mutex.ReleaseMutex(); if (FailRelease) { throw new InvalidOperationException(); } }
            public void Dispose() { }
        }
    }
}
