# COMS PC Guard Windows x64 VM Enforcement PoC Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task-by-task. Use a fresh implementation agent per task, then a spec review and code-quality review before the next task.

**Goal:** Provision an authorized, isolated Windows 11 x64 evaluation VM and prove the current COMS PC Guard Publisher-EXE compiler subset against real AppLocker behavior using harmless fixtures, fail-closed safety guards, automatic evidence capture, and ownership-safe cleanup.

**Architecture:** UTM 4.5.4 runs an x64 Windows 11 Enterprise Evaluation guest under QEMU on the Apple Silicon host. A new `Guard.WindowsPoc` console tool remains test-only and invokes a narrow PowerShell gateway for AppLocker inventory/apply/observe/cleanup. Portable unit tests lock every destructive guard before the tool can write policy. The VM starts from an empty local AppLocker policy and an Automatic/running AppIDSvc baseline, creates only COMS-owned fixture rules, persists write-ahead crash-recovery state, and stores raw evidence outside Git. Exact snapshot restoration is allowed only while the current policy still equals a journaled expected COMS state. Any unexpected drift stops further live writes and triggers host-side recovery from the stopped pre-enforcement clone; live external-policy coexistence remains unproven.

**Tech Stack:** UTM 4.5.4, Windows 11 Enterprise Evaluation x64 (official Microsoft ISO, 24H2 build 26100 or newer), PowerShell 5.1, .NET SDK 10.0.401, C# 14, MSTest.Sdk 4.4.0, AppLocker PowerShell cmdlets.

**Spec:** `PLAN.md` P0-01/P0-04/P0-06/P0-07/P0-08 and master prompt sections 8, 14, 17, 20, and 21.

## Global constraints

- Work only in the user-authorized UTM VM named `COMS-PC-Guard-x64-Lab`. Never apply AppLocker, change AppIDSvc, create lab accounts, or execute fixture probes on the physical Windows host `CHOI` or on macOS.
- Use only an official Microsoft Enterprise Evaluation x64 ISO whose SHA-256 matches the corresponding Microsoft hash document. Do not use mirrors, repacks, consumer ARM media, or an unverified ISO.
- Prefer the current 25H2 evaluation when the live official download and hash document agree. Accept official 24H2 build 26100 or newer because `PLAN.md` defines that as the target floor. Record the exact edition, build, ISO filename, and SHA-256.
- UTM x64-on-Apple-Silicon is emulation, not hardware virtualization. Record evidence as `WINDOWS_X64_EMULATED_VM`; do not claim performance acceptance or physical-hardware compatibility from it.
- VM configuration: QEMU `x86_64`, Windows 10-or-higher wizard option, UEFI, Secure Boot, TPM 2.0, 2 emulated CPU cores, 8192 MiB RAM, 81920 MiB sparse disk, NAT/shared network, no port forwarding, and no host directory share during installation.
- UTM 4.5.4 has no named-snapshot CLI. Use fully shut-down UTM clones for durable checkpoints. Never patch the `.utm` bundle or invent unsupported AppleScript TPM fields.
- Host free-space gate: require at least 100 GiB before ISO download/VM creation and stop mutation if free space falls below 60 GiB. Current starting observation is 153 GiB free.
- Store VM/ISO/raw evidence outside the Git worktree. Suggested locations: `/Users/choi/Virtual Machines.localized/` for UTM bundles, `/Users/choi/Downloads/COMS-PC-Guard-VM/` for verified media, and `/Users/choi/Desktop/project/coms-pc-guard-vm-evidence/` for raw evidence.
- Lab passwords must never enter Git, issue/PR text, captured console output, or evidence JSON. Create strong random credentials interactively inside the guest and keep only the minimum needed for the VM lifetime.
- Initial AppLocker apply requires all of: Windows platform, QEMU manufacturer/model evidence, the exact VM name marker, a per-VM nonce file, an explicit `--allow-write` switch, elevated token, supported build, fresh inventory, empty local policy, no effective Group Policy, no AppLocker CSP/MDM instance, no enforced WDAC/App Control policy, and a restorable pre-change snapshot.
- A subsequent AuditOnly/Enabled/member-scope transition is authorized only when the freshly observed local policy hash and complete canonical rule content exactly equal the prior journaled expected state. The next expected state and ownership evidence must be durably journaled before each OS write.
- `Get-AppLockerPolicy` is not accepted as CSP/MDM evidence. Query `root\cimv2\mdm\dmmap` AppLocker WMI bridge instances as LocalSystem and use `CiTool -lp -json` for App Control/WDAC. Missing access or unparseable output is `Unknown` and blocks mutation.
- The PoC owns only the exact immutable compiler output: rule IDs, rule content hashes, collection/mode, Member SIDs, Publisher tuple/version bounds, inventory revision, and full XML SHA-256 must all match. Display names never prove ownership. Any unknown/external rule, same-ID altered content, widened condition, changed SID/action, or swapped fixture blocks mutation.
- Apply only an EXE collection containing the required `Allow Everyone Path *` baseline and exact Member-SID Publisher Deny rules for harmless fixtures. Never deny `Everyone`, Owner, Administrators, PowerShell, shells, editors, installers, service tools, or operating-system directories.
- Configure AppIDSvc to Automatic/running once during checkpointed VM provisioning with Microsoft's documented `sc.exe config appidsvc start=auto`; do not attempt to return it to Manual because the protected service cannot be changed back to Manual with `sc.exe`. Native probes preserve this Automatic/running baseline and record restart behavior only when actually observed.
- The native run must execute cleanup from a cancellation token independent of the cancelled test operation. The journal stores one immutable `InitialBaseline` and separate `Before`/`After` states for every transition. Terminal cleanup writes nothing only when the fresh current policy equals the empty `InitialBaseline`; every recognized nonempty COMS `Before` or `After` state is restored to `InitialBaseline`. Any unrecognized state is drift: perform no further live policy write, preserve evidence, stop the guest, and recover from `--02-pre-enforcement`. Do not claim live coexistence or drift preservation from the clone reset.
- A persisted write-ahead journal records `Prepared`, `WritePending`, `Mutated`, `RebootVerificationPending`, `Observed`, and `Cleaned` states plus immutable `InitialBaseline`, per-transition `Before`/`After` hashes and canonical content, exact owned rule content, lease deadline, and run ID. All data required to recognize an uncertain write outcome is durable before the OS write. Recovery is idempotent: `WritePending` compares fresh OS state with both sides, then terminal cleanup restores the initial baseline from either recognized nonempty side. A failed or crashed second transition must not strand the first transition's rules.
- Controller, recovery command, and watchdog acquire the same Windows global named mutex around journal reload, lease decision/renewal, fresh inventory validation, OS write, and journal acknowledgement. Use a bounded wait and a DACL limited to SYSTEM and the designated Owner; timeout performs no policy write. A SYSTEM scheduled watchdog runs at startup and every minute. It leaves an unexpired verification lease untouched, cleans an exact recognized COMS state after lease expiry, and requests host-side clone recovery on drift. A stopped clone is disaster recovery, not evidence that in-guest cleanup passed.
- Raw local/effective policy XML and full SIDs remain outside Git. Commit only redacted summaries, hashes, timestamps, commands, pass/fail states, and the final assertion that no product-owned rules remain.
- This PoC does not implement the production Windows Service, IPC, ACLs, UI, installer, process terminator, or update path. Those remain separately gated after the AppLocker contract is proven.

---

### Task 1: Commit the VM and native-PoC execution contract

**Files:**

- Create: `docs/superpowers/plans/2026-09-13-windows-vm-enforcement-poc.md`

- [ ] **Step 1: Review the plan against the approved master prompt**

Confirm the plan preserves the one-Owner/two-Member SID model, harmless-fixture-only rule, external-policy preservation, `PASS`/`FAIL`/`BLOCKED`/`NOT_RUN` distinctions, no physical-host mutation, and native-vs-portable evidence boundary.

- [ ] **Step 2: Validate the plan artifact**

Run:

```sh
git diff --check
rg -n "physical|fixture|restore|AppIDSvc|x64|BLOCKED|external" docs/superpowers/plans/2026-09-13-windows-vm-enforcement-poc.md
```

Expected: no whitespace errors and every safety boundary present.

- [ ] **Step 3: Commit and merge the plan**

Commit subject:

```text
Plan native AppLocker proof before production integration
```

Include Lore trailers for the x64 evaluation choice, UTM emulation limitation, ARM evaluation rejection, and tests not yet run. Push `docs/windows-vm-lab`, open a PR, wait for required CI, then merge without bypassing branch protection.

---

### Task 2: Download and verify official Windows x64 evaluation media

**Host artifacts:**

- Create outside Git: `/Users/choi/Downloads/COMS-PC-Guard-VM/<official-enterprise-eval>.iso`
- Create outside Git: `/Users/choi/Downloads/COMS-PC-Guard-VM/Verify-Download-Win11-Enterprise.pdf`
- Create outside Git: `/Users/choi/Downloads/COMS-PC-Guard-VM/SHA256SUMS.verified.txt`

- [ ] **Step 1: Recheck host resource and UTM gates**

Run:

```sh
/bin/df -h /Users/choi/Downloads
/usr/bin/defaults read /Applications/UTM.app/Contents/Info CFBundleShortVersionString
sysctl -n hw.memsize hw.ncpu
```

Expected: at least 100 GiB free before download, UTM `4.5.4`, and sufficient host RAM/CPU for an 8 GiB guest.

- [ ] **Step 2: Download only from Microsoft Evaluation Center**

Use the official Evaluation Center flow:

```text
https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise
```

Choose Windows 11 Enterprise x64. Do not supply invented personal data. If the direct official download is blocked behind unavailable identity data, record `BLOCKED_MICROSOFT_DOWNLOAD` and try only another official Microsoft download endpoint; do not fall back to a mirror.

- [ ] **Step 3: Download the official hash document and verify**

Hash document:

```text
https://aka.ms/Win11-Hash-PDF
```

Run:

```sh
shasum -a 256 '/Users/choi/Downloads/COMS-PC-Guard-VM/<official-enterprise-eval>.iso'
```

Expected: exact match with the filename/locale/architecture row in Microsoft's document. Write only the filename, observed SHA-256, expected SHA-256, source URLs, retrieval time, and `MATCH` to `SHA256SUMS.verified.txt`.

---

### Task 3: Create the isolated UTM x64 Windows VM

**UTM artifacts:**

- Create: `COMS-PC-Guard-x64-Lab`
- Create stopped clone: `COMS-PC-Guard-x64-Lab--00-clean-install`
- Create stopped clone: `COMS-PC-Guard-x64-Lab--01-tooling`
- Create stopped clone: `COMS-PC-Guard-x64-Lab--02-pre-enforcement`

- [ ] **Step 1: Create through the UTM Windows wizard**

Use `Emulate` -> `Windows`, select the verified x64 ISO, enable `Install Windows 10 or higher` and `Install drivers and SPICE tools`, then set 2 CPU cores, 8192 MiB RAM, and 81920 MiB maximum disk. Skip shared directories.

Expected after save: UEFI/Secure Boot/TPM 2.0 are enabled by the Windows wizard. Confirm in UTM settings before first boot. Do not edit the VM bundle.

- [ ] **Step 2: Install Windows and finish OOBE**

Install the Enterprise Evaluation edition. Complete OOBE with a temporary local setup administrator. Install UTM/SPICE guest tools, apply Windows Update until no required security/cumulative update remains, reboot, and verify activation/evaluation status.

- [ ] **Step 3: Record baseline without secrets**

Inside an elevated PowerShell session, capture:

```powershell
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture
Get-Tpm
Confirm-SecureBootUEFI
Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model
Get-AppLockerPolicy -Local -Xml
Get-AppLockerPolicy -Effective -Xml
Get-Service AppIDSvc | Select-Object Status, StartType
```

Also query the LocalSystem MDM WMI bridge for AppLocker CSP instances and run `CiTool -lp -json`. Expected: Windows 11 x64, build 26100 or newer, TPM present, Secure Boot enabled, QEMU/virtual machine manufacturer-model, empty local/effective AppLocker policy, no AppLocker CSP/MDM instances, and no enforced WDAC/App Control policy. AppIDSvc's initial state is recorded but is not yet changed. Keep full output outside Git.

- [ ] **Step 4: Create the clean-install checkpoint**

Shut Windows down cleanly. Clone with UTM/`utmctl clone` and name the clone `COMS-PC-Guard-x64-Lab--00-clean-install`. Keep the clone stopped.

---

### Task 4: Add fail-closed Windows PoC contracts and unit tests

**Files:**

- Create: `tools/Guard.WindowsPoc/Guard.WindowsPoc.csproj`
- Create: `tools/Guard.WindowsPoc/Program.cs`
- Create: `tools/Guard.WindowsPoc/PocExitCode.cs`
- Create: `tools/Guard.WindowsPoc/Configuration/WindowsPocOptions.cs`
- Create: `tools/Guard.WindowsPoc/Safety/VmAttestation.cs`
- Create: `tools/Guard.WindowsPoc/Safety/PolicyMutationGuard.cs`
- Create: `tools/Guard.WindowsPoc/Inventory/ExternalPolicyInventory.cs`
- Create: `tools/Guard.WindowsPoc/Native/IWindowsCommandRunner.cs`
- Create: `tools/Guard.WindowsPoc/Native/PowerShellCommandRunner.cs`
- Create: `tools/Guard.WindowsPoc/Native/IAppLockerNativeGateway.cs`
- Create: `tools/Guard.WindowsPoc/Native/AppLockerNativeGateway.cs`
- Create: `tools/Guard.WindowsPoc/Evidence/PocEvidenceWriter.cs`
- Create: `tests/Guard.WindowsPoc.Tests/Guard.WindowsPoc.Tests.csproj`
- Create: `tests/Guard.WindowsPoc.Tests/Safety/VmAttestationTests.cs`
- Create: `tests/Guard.WindowsPoc.Tests/Safety/PolicyMutationGuardTests.cs`
- Create: `tests/Guard.WindowsPoc.Tests/Inventory/ExternalPolicyInventoryTests.cs`
- Create: `tests/Guard.WindowsPoc.Tests/Native/AppLockerNativeGatewayTests.cs`
- Modify: `ComsPcGuard.sln`
- Modify: `Directory.Packages.props`
- Create: `tools/Guard.WindowsPoc/packages.lock.json`
- Create: `tests/Guard.WindowsPoc.Tests/packages.lock.json`

**Interfaces:**

- `VmAttestation.Evaluate(WindowsPocOptions, WindowsPlatformEvidence) -> VmAttestationResult`
- `PolicyMutationGuard.Evaluate(VmAttestationResult, AppLockerNativeSnapshot, bool elevated) -> PolicyMutationDecision`
- `IAppLockerNativeGateway.CaptureAsync()`, `ApplyAsync(xml)`, `ObserveAsync()`, and `RestoreAsync(snapshot)`
- `PocEvidenceWriter` writes redacted JSON Lines with hashes and result codes; it never serializes passwords or full SIDs.

- [ ] **Step 1: Write RED safety tests**

Required cases:

```text
Non-Windows platform rejects.
Windows physical manufacturer/model rejects.
QEMU evidence without the exact VM marker and nonce rejects.
Missing --allow-write rejects mutation but permits read-only inventory.
Non-elevated process rejects mutation.
Unsupported build or non-x64 guest rejects.
Stale inventory rejects.
External/unknown local, effective Group Policy, CSP/MDM, or WDAC/App Control policy rejects; unavailable evidence remains Unknown.
Missing/restoration-ineligible snapshot rejects.
Fixture root outside C:\ComsPcGuardPoc\Fixtures rejects.
Rule IDs not present in the compiler preview reject.
Same-ID altered condition, widened version, edited SID/action, different XML hash, or swapped fixture rejects.
Owner/Administrators/Everyone Deny rejects.
Commands are fixed argv arrays; XML and paths are never concatenated into a shell command.
Evidence redacts full SIDs, usernames, passwords, and raw XML.
```

- [ ] **Step 2: Run RED**

Run only the new tests with the repository-local SDK. Preserve the missing-type/compiler failures.

- [ ] **Step 3: Implement the minimum contracts**

Use immutable records and injected interfaces. `PowerShellCommandRunner` invokes `powershell.exe` with `-NoProfile -NonInteractive -ExecutionPolicy Bypass -File <fixed-script-path>` and passes XML through a locked temporary file under `C:\ProgramData\ComsPcGuardPoc`, never through interpolated command text.

`AppLockerNativeGateway` must be Windows-only, cancellation-aware, timeout-bounded, and unable to mutate unless the guard decision is `Allowed`. `CleanupAsync` must be callable from `finally` with an independent timeout even after an apply/observe failure.

- [ ] **Step 4: Run GREEN and the portable matrix**

Run locked restore, new focused tests, full default/TZ tests, format verification, Release build, and `git diff --check`.

- [ ] **Step 5: Commit Task 4**

Commit subject:

```text
Refuse native policy writes outside the authorized VM
```

Record that no native policy was applied by this task.

---

### Task 5: Implement fixture-only AppLocker capture, apply, observe, and rollback

**Files:**

- Create: `scripts/windows/Get-ComsPocInventory.ps1`
- Create: `scripts/windows/Set-ComsPocPolicy.ps1`
- Create: `scripts/windows/Remove-ComsPocPolicy.ps1`
- Create: `scripts/windows/Resume-ComsPocRecovery.ps1`
- Create: `scripts/windows/Test-ComsPocFixture.ps1`
- Create: `tools/Guard.WindowsPoc.Fixture/Guard.WindowsPoc.Fixture.csproj`
- Create: `tools/Guard.WindowsPoc.Fixture/Program.cs`
- Create: `tools/Guard.WindowsPoc.ControlFixture/Guard.WindowsPoc.ControlFixture.csproj`
- Create: `tools/Guard.WindowsPoc.ControlFixture/Program.cs`
- Create: `tools/Guard.WindowsPoc/Native/AppLockerPolicySnapshot.cs`
- Create: `tools/Guard.WindowsPoc/Recovery/PocTransactionJournal.cs`
- Create: `tools/Guard.WindowsPoc/Recovery/CrossProcessPolicyGate.cs`
- Create: `tools/Guard.WindowsPoc/Execution/WindowsPocRunner.cs`
- Create: `tools/Guard.WindowsPoc/Fixtures/HarmlessFixture.cs`
- Create: `tests/Guard.WindowsPoc.Tests/Execution/WindowsPocRunnerTests.cs`
- Create: `tests/Guard.WindowsPoc.Tests/Evidence/PocEvidenceWriterTests.cs`

**Native flow:**

1. Capture empty local/effective AppLocker XML, LocalSystem CSP/MDM WMI evidence, `CiTool` WDAC evidence, and the Automatic/running AppIDSvc baseline.
2. Reject any external/unknown rule, collection, CSP/MDM instance, or enforced WDAC policy.
3. Build two uniquely named harmless console fixtures with distinct product/file metadata, sign both with a VM-only organizational code-signing certificate, trust that certificate only inside the disposable VM, verify Authenticode, and extract Publisher metadata with `Get-AppLockerFileInformation`. One fixture is the deny target; the same-publisher control fixture must remain allowed.
4. Build the existing `AppLockerCompileRequest` with exact Owner and Member SIDs and a Publisher identity derived from the verified target fixture. Bind the complete preview, content hashes, Publisher tuple, and XML hash into the mutation authorization.
5. Re-read local/effective/CSP/MDM/WDAC inventory and AppIDSvc immediately before apply or transition.
6. Persist `Prepared` with the pre-state, complete expected post-state, ownership evidence, and recovery lease; flush `WritePending` before invoking `Set-AppLockerPolicy`; then acknowledge `Mutated` only after a successful write and re-read effective policy. Recovery from `WritePending` compares actual OS state with both sides and is idempotent.
7. Have each actual interactive Owner/Member session launch its probe. The fixture reports its own token SID and writes a unique run marker only after process start. Correlate events by run ID, time window, path, token SID hash, and rule ID.
8. In `finally` or watchdog recovery, inspect every `Prepared`/`WritePending`/`Mutated` journal idempotently. Write nothing only at `InitialBaseline`; restore `InitialBaseline` from every recognized nonempty transition `Before` or `After` state, and request stopped-clone recovery without another live write on drift.
9. On the no-drift path, re-read local/effective/CSP/MDM/WDAC policy and assert original hashes plus zero COMS-owned residual rules. On a drift injection, assert that the gateway issued no cleanup write and that host-side stopped-clone recovery returned the lab to the pre-enforcement checkpoint; keep live coexistence `BLOCKED`.

- [ ] **Step 1: Write RED orchestration tests with a scripted gateway**

Cover success, apply failure before mutation, crash immediately after native write but before acknowledgement, failed second transition before its OS write, crash before a second-transition write, observation mismatch, fixture execution failure, cancellation, process death/recovery resume, repeated recovery invocation, cleanup failure, AppIDSvc-not-ready refusal, external-policy drift before apply, after apply, and immediately before cleanup, plus evidence-write failure. Terminal cleanup writes nothing only at the empty initial baseline; it restores the initial baseline from any recognized nonempty `Before` or `After` state. Recovery may run repeatedly and must converge idempotently. Cleanup failure or drift must dominate the final result and request host-side clone recovery.

- [ ] **Step 2: Run RED**

Run `WindowsPocRunnerTests`; preserve missing runner/native-script contract failures.

- [ ] **Step 3: Implement PowerShell scripts and runner**

Scripts use `[CmdletBinding(SupportsShouldProcess)]`, strict mode, terminating errors, literal paths, bounded input sizes, and structured JSON output. Initial `Set-AppLockerPolicy` is allowed only for a verified empty local policy; transitions require an exact prior expected state; both read only test-owned XML paths. Cleanup receives the journal plus a fresh policy snapshot and restores immutable `InitialBaseline` only when the fresh hash/content exactly equals a recognized COMS transition state. Drift produces no live policy write. All mutation/recovery commands are invoked through the C# entrypoint so the same global named mutex covers controller and watchdog operations.

- [ ] **Step 4: Run GREEN and full matrix**

Run the focused and full portable gates. On macOS, native integration tests must report `NOT_RUN_WINDOWS_ONLY`, not `PASS`, while all guard/orchestration unit tests pass.

- [ ] **Step 5: Commit Task 5**

Commit subject:

```text
Restore AppLocker state after every harmless fixture probe
```

---

### Task 6: Provision guest tooling and lab identities

**Guest artifacts:**

- `C:\ComsPcGuardPoc\Source`
- `C:\ComsPcGuardPoc\Fixtures`
- `C:\ComsPcGuardPoc\Evidence`
- `C:\ProgramData\ComsPcGuardPoc\vm-attestation.json`
- `C:\ProgramData\ComsPcGuardPoc\transaction.json`
- Local admin Owner account: `ComsGuardOwner`
- Standard accounts: `ComsGuardMemberA`, `ComsGuardMemberB`

- [ ] **Step 1: Install exact .NET SDK and transfer source**

Install .NET SDK `10.0.401` from Microsoft's official distribution, verify `dotnet --info`, and transfer the exact merged commit without persisting a GitHub PAT in the guest. Prefer a host-created source archive of the clean Git tree after guest tools are installed.

- [ ] **Step 2: Create the VM attestation marker**

Write a random nonce and expected UTM VM name plus a hash of stable QEMU identity evidence to the ACL-protected marker. Grant read access to the PoC tool and Owner; deny standard users write access. Store the expected nonce outside Git on the host.

- [ ] **Step 3: Create Owner and Member accounts**

Create `ComsGuardOwner` as the single designated app Owner and local administrator. Create `ComsGuardMemberA` and `ComsGuardMemberB` as standard users. Capture their SIDs into raw evidence without committing full SID values. Confirm neither Member is in Administrators.

- [ ] **Step 4: Establish the checkpointed AppIDSvc baseline and recovery task**

Run Microsoft's documented elevated command `sc.exe config appidsvc start=auto`, start AppIDSvc, and verify Automatic/running. Register a persistent SYSTEM watchdog that invokes the C# `recover` entrypoint at startup and every minute; that entrypoint and the controller share the DACL-protected global policy mutex. It handles valid `WritePending`, `Mutated`, and `RebootVerificationPending` journals idempotently, respects an unexpired verification lease, and uses a bounded independent cleanup timeout. It stays installed for later runs but performs no action without an active journal. Do not attempt to return AppIDSvc to Manual.

- [ ] **Step 5: Build and run read-only gates**

Run locked restore, format, Release build, the full test suite, and `Guard.WindowsPoc inventory` without `--allow-write`.

Expected: all portable/unit tests pass; inventory succeeds; mutation is refused; full SIDs/raw XML remain only in the guest evidence folder.

- [ ] **Step 6: Create tooling and pre-enforcement checkpoints**

Shut down and clone `--01-tooling`. Restart, build and sign the dedicated target/control fixtures with the VM-only certificate, verify their distinct Publisher/Product/Binary tuples, prove both launch successfully from each intended interactive account, then shut down and clone `--02-pre-enforcement`. Keep both clones stopped.

---

### Task 7: Execute the x64 AppLocker acceptance matrix

**Raw evidence directory:**

- `/Users/choi/Desktop/project/coms-pc-guard-vm-evidence/<UTC-run-id>/`

- [ ] **Step 1: Audit-only probe**

Before policy, require successful target/control launch markers from Owner, Member A, and Member B. Apply the exact compiler output in `AuditOnly`, run the target fixture as Member A and Member B, and verify both executions succeed while fresh AppLocker audit events identify the run ID, intended rule, path, and hashed token SID. Run as Owner and verify it succeeds without a matching Member Deny. Reject stale events outside the bounded run window.

- [ ] **Step 2: Enabled restriction probe**

Apply `Enabled`, run the target fixture as Member A and Member B, and verify Windows blocks both before the start marker is written. Run as Owner and verify it remains allowed. Rename and copy the signed target fixture within the fixture root and verify Publisher identity behavior remains consistent. Run the same-certificate control fixture for both Members and verify it stays allowed, proving the rule did not widen to the entire test publisher.

- [ ] **Step 3: Member-scoped temporary allowance**

Remove only Member A's COMS-owned Deny from the desired compiler output. Verify Member A succeeds, Member B remains blocked, and Owner remains allowed. Revoke the grant and verify Member A is blocked again.

- [ ] **Step 4: Restart and reboot persistence**

With a known enabled policy, persist `RebootVerificationPending` with a bounded ten-minute lease and reboot the guest. The startup watchdog must acquire the global gate, observe the unexpired lease without cleaning, and release the gate. Resume the exact run, verify effective policy and Member blocking persist, then clean the exact recognized state and mark `Cleaned`. Separately terminate the controller after mutation, stop renewing its short lease, and verify the minute watchdog cleans after expiry. Test crash immediately after the native write while the journal is still `WritePending`; recovery must recognize the expected applied state and clean it. Race a controller lease renewal against watchdog cleanup and start two watchdog invocations; the mutex must serialize them, timeouts must perform no write, and the result must converge to one `Cleaned` baseline. Confirm Automatic/running AppIDSvc remains at its checkpointed baseline and zero COMS-owned residual rules remain.

- [ ] **Step 5: Failure and drift-refusal probes**

Run guard-level scenarios for stale inventory, unavailable CSP/WDAC inventory, AppIDSvc not ready, fake VM marker, non-elevated Owner process, Member attempting `--allow-write`, malformed XML, mismatched rule ID/content, and injected external-policy drift. Initial apply must refuse nonempty policy; transitions must refuse anything except the exact previous expected COMS state. Drift after mutation must cause no further live write and request clone recovery. Do not create a real organization-managed policy solely to satisfy this test; use a stopped-clone disposable run or injected gateway snapshot where the OS boundary is not required.

- [ ] **Step 6: Session coverage**

Run the fixture from actual interactive sessions for Owner, Member A, and Member B. Exercise sign-out and fast-user-switching once. Record unsupported or prohibitively slow sleep/hibernate paths as `NOT_RUN` with reason; do not infer `PASS`.

- [ ] **Step 7: Final rollback proof**

Capture local/effective/CSP/MDM/WDAC evidence, AppIDSvc state, and COMS rule search after the test runner exits. Expected on the no-drift path: original local/effective hashes restored, Automatic/running AppIDSvc baseline preserved, and zero COMS-owned rules remain. Expected on the drift test: no live cleanup write after drift, a hard failure recorded, and stopped-clone recovery returns the VM to the pre-enforcement checkpoint; external-policy coexistence remains `BLOCKED`.

---

### Task 8: Publish evidence without overstating the product

**Files:**

- Modify: `ARCHITECTURE.md`
- Modify: `DECISIONS.md`
- Modify: `ROADMAP.md`
- Modify: `STATUS.md`
- Modify: `TEST_REPORT.md`
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `SOURCES.md`
- Modify: `docs/superpowers/plans/2026-09-13-windows-vm-enforcement-poc.md`

- [ ] **Step 1: Run the complete portable and native evidence gates**

Record exact SDK, commit, Windows edition/build/architecture, UTM version/backend, test totals, AppLocker modes, account-role assertions, pre/post policy hashes, AppIDSvc pre/post state, and raw evidence directory hash manifest.

- [ ] **Step 2: Update the requirement map honestly**

Mark only the proven Publisher-EXE native subset behaviors as `PASS_WINDOWS_X64_EMULATED_VM`. Keep the overall Phase B/P0 gate open: unsigned hash and packaged-app identity, grant expiry, running-process handling, sleep/hibernate if unrun, production service, IPC/ACL, real registered-game cleanup, UI, MSI, performance, external organization-policy integration, and physical hardware acceptance remain `BLOCKED` or `NOT_RUN`.

- [ ] **Step 3: Independent review**

Require a security/spec review of the native diff and the evidence summary. Critical or important findings block merge. Confirm no secret, full SID, raw XML, ISO, VM bundle, or raw evidence entered Git.

- [ ] **Step 4: Commit, PR, CI, and merge**

Use exact-file staging and Lore commits. Push the feature branch, open a PR, wait for `portable` and `windows-compile`, address findings, and merge only after required checks pass. Do not tag a production release; this closes only the Publisher-EXE native subset, not the overall AppLocker/Phase B gate.

## Stop conditions

- Success: the official ISO hash matches, the x64 guest is checkpointed, native guard/unit tests pass, audit/enforce/member-scope/reboot/crash-recovery probes complete, exact-state cleanup proves zero residual COMS rules on no-drift runs, drift causes no additional live write, evidence is reviewed, and the PR merges as a Publisher-EXE subset result.
- Safe block: official media/hash cannot be obtained; UTM cannot present TPM/Secure Boot; free disk falls below the floor; the guest is not x64/build 26100+; external AppLocker/GPO/CSP/WDAC policy is detected; or rollback cannot be proven. Preserve evidence and revert from `--02-pre-enforcement`; never weaken guards.
- Out of scope for this plan: production service/IPC/ACL/UI/installer implementation and v1.0 release claims.
