# COMS PC Guard Repository Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a reproducible .NET 10 repository, required governance documents, and CI foundation without implementing product behavior or invoking WiX.

**Architecture:** Bootstrap only the OS-independent `Guard.Core` and its test project so the first build is portable and honest. Record all Windows-only work as blocked, keep package versions centrally pinned, and make CI distinguish portable validation from later Windows acceptance.

**Tech Stack:** .NET SDK 10.0.401, `net10.0`, MSTest.Sdk 4.4.0, GitHub Actions `ubuntu-24.04` and `windows-2025`.

**Spec:** `PLAN.md`

## Global Constraints

- Work only inside `/Users/choi/Desktop/project/coms-pc-guard` and the approved Private repository `choijunhuk/coms-pc-guard`.
- Do not install, download, or invoke WiX until `BLOCKED_WIX_LICENSE` is cleared by a recorded OSMF eligibility check.
- Do not change any Windows service, account, ACL, AppLocker, WDAC, GPO, MDM, or operating-PC state.
- Pin .NET SDK `10.0.401` with `rollForward: disable` and `allowPrerelease: false`.
- Use `net10.0` for portable Core code. Windows projects are introduced only in the plan that implements them.
- Use central package management and restore lock files; no floating versions.
- Treat warnings as errors, enable nullable reference types, implicit usings, deterministic builds, and .NET analyzers.
- Commit messages use intent-first Conventional Commit subjects plus useful Lore trailers.
- Evidence labels are `PASS`, `FAIL`, `BLOCKED`, or `NOT_RUN`; a macOS or hosted-runner build is not Windows enforcement evidence.
- No product behavior in this bootstrap task; configuration and substantive project documents only.

---

### Task 1: Bootstrap the portable solution, governance documents, and CI

**Files:**

- Create: `.gitignore`
- Create: `.editorconfig`
- Create: `global.json`
- Create: `Directory.Build.props`
- Create: `Directory.Packages.props`
- Create: `NuGet.Config`
- Create: `ComsPcGuard.sln`
- Create: `src/Guard.Core/Guard.Core.csproj`
- Create: `tests/Guard.Core.Tests/Guard.Core.Tests.csproj`
- Create: `.github/workflows/ci.yml`
- Create: `README.md`
- Create: `RESEARCH.md`
- Create: `ARCHITECTURE.md`
- Create: `ROADMAP.md`
- Create: `SECURITY.md`
- Create: `DECISIONS.md`
- Create: `CHANGE_REQUESTS.md`
- Create: `STATUS.md`
- Create: `TEST_REPORT.md`
- Create: `OPERATIONS.md`
- Create: `SOURCES.md`
- Create: `CHANGELOG.md`

**Interfaces:**

- Consumes: approved boundaries and versions from `PLAN.md`.
- Produces: `ComsPcGuard.sln` containing `Guard.Core` and `Guard.Core.Tests`; later plans add source projects without changing the bootstrap contracts.

- [ ] **Step 1: Protect local/tool/build state before generating anything**

Create `.gitignore` with at least these exact classes of entries:

```gitignore
.dotnet/
.worktrees/
.superpowers/
.vs/
.idea/
.vscode/
.DS_Store
bin/
obj/
TestResults/
artifacts/
*.user
*.suo
*.nupkg
*.snupkg
```

Create `.editorconfig` with `root = true`, UTF-8, LF, final newline, four spaces for C#, two spaces for YAML/JSON, and analyzer severities that keep compiler/analyzer output clean without suppressing security findings.

- [ ] **Step 2: Pin the SDK and package graph**

Create `global.json`; keep the test SDK version centralized in `msbuild-sdks` rather than repeating it in a project file:

```json
{
  "sdk": {
    "version": "10.0.401",
    "rollForward": "disable",
    "allowPrerelease": false
  },
  "msbuild-sdks": {
    "MSTest.Sdk": "4.4.0"
  }
}
```

Create `Directory.Build.props` with these public build properties:

```xml
<Project>
  <PropertyGroup>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <AnalysisLevel>latest-recommended</AnalysisLevel>
    <EnableNETAnalyzers>true</EnableNETAnalyzers>
    <Deterministic>true</Deterministic>
    <ContinuousIntegrationBuild Condition="'$(CI)' == 'true'">true</ContinuousIntegrationBuild>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup>
</Project>
```

Create `Directory.Packages.props` with central package management enabled and no floating package versions. Create `NuGet.Config` with `<clear />` followed by nuget.org as the sole package source; do not add credentials or redundant source mapping for a single source.

- [ ] **Step 3: Create the minimal portable solution**

Use the pinned SDK to generate an explicit classic solution file, a class library, and an MSTest project:

```bash
dotnet new sln --format sln -n ComsPcGuard
dotnet new classlib -n Guard.Core -o src/Guard.Core -f net10.0
dotnet new mstest -n Guard.Core.Tests -o tests/Guard.Core.Tests -f net10.0 --no-restore
dotnet sln ComsPcGuard.sln add src/Guard.Core/Guard.Core.csproj tests/Guard.Core.Tests/Guard.Core.Tests.csproj
dotnet add tests/Guard.Core.Tests/Guard.Core.Tests.csproj reference src/Guard.Core/Guard.Core.csproj
```

Remove generated `Class1.cs` and sample test files. The production project contains no placeholder class. Configure `Guard.Core.Tests.csproj` as `<Project Sdk="MSTest.Sdk">`; its exact version comes from `global.json` and is not duplicated locally.

- [ ] **Step 4: Write substantive project documents**

Each document must state current evidence rather than empty headings:

- `README.md`: product purpose, truthful current status, repository map, local SDK/bootstrap commands, and Windows-validation warning.
- `RESEARCH.md`: 2026-09-12 environment findings, AppLocker/WiX/.NET/GitHub runner conclusions, and verified-vs-unknown separation.
- `ARCHITECTURE.md`: component boundaries from PLAN §6, Desired/Applied/Health split, and the policy reconciliation flow.
- `ROADMAP.md`: Phase A-F sequence and B-before-E enforcement gate.
- `SECURITY.md`: Owner SID boundary, standard-user threat model, admin/SYSTEM/offline limits, forbidden mechanisms, and reporting guidance without publishing secrets.
- `DECISIONS.md`: record DR-001 stack, DR-002 AppLocker defense-in-depth, DR-003 LocalSystem narrow boundary, DR-004 Private GitHub/merge commits, DR-005 package trust modes.
- `CHANGE_REQUESTS.md`: exact CR template from the master prompt and state that no CR is open.
- `STATUS.md`: Phase A approved; repository bootstrap in progress; `BLOCKED_WINDOWS_VM` and `BLOCKED_WIX_LICENSE`; next action is Core policy plan.
- `TEST_REPORT.md`: environment inventory and commands actually run in this task; Windows items `BLOCKED`, product tests `NOT_RUN` until Task verification.
- `OPERATIONS.md`: development-only restore/build/test commands and explicit statement that installation/recovery procedures are unavailable until Windows phases.
- `SOURCES.md`: official URLs and 2026-09-12 check date from PLAN §18, including .NET release metadata and WiX v7.
- `CHANGELOG.md`: Keep a Changelog structure with an `[Unreleased]` bootstrap entry; no release claim.

- [ ] **Step 5: Add CI that preserves evidence boundaries**

Create `.github/workflows/ci.yml` triggered by pull requests and pushes to `main` with two jobs:

```yaml
portable:
  runs-on: ubuntu-24.04
  steps:
    - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    - uses: actions/setup-dotnet@26b0ec14cb23fa6904739307f278c14f94c95bf1 # v5
      with:
        dotnet-version: 10.0.401
        cache: true
    - run: dotnet restore ComsPcGuard.sln --locked-mode
    - run: dotnet format ComsPcGuard.sln --verify-no-changes --no-restore
    - run: dotnet build ComsPcGuard.sln -c Release --no-restore
    - run: dotnet test ComsPcGuard.sln -c Release --no-build --no-restore --logger "console;verbosity=normal"
```

Mirror the same restore/format/build/test commands in a `windows-compile` job on `windows-2025`. Do not invoke AppLocker, services, installers, or WiX. Keep the immutable first-party action SHAs above and their readable major versions in comments.

- [ ] **Step 6: Install the local SDK without polluting the repository**

Use Microsoft's official `dotnet-install.sh` from a temporary directory to install SDK `10.0.401` into the ignored `.dotnet/` directory. Do not change the user's global SDK installation or shell profile.

Verify:

```bash
./.dotnet/dotnet --version
```

Expected exact output:

```text
10.0.401
```

- [ ] **Step 7: Restore and generate lock files**

Run:

```bash
./.dotnet/dotnet restore ComsPcGuard.sln
./.dotnet/dotnet restore ComsPcGuard.sln --locked-mode
```

Expected: both commands exit 0; the second command makes no dependency changes. Commit every generated `packages.lock.json` and no package cache/build output.

- [ ] **Step 8: Verify the bootstrap**

Run exactly:

```bash
./.dotnet/dotnet format ComsPcGuard.sln --verify-no-changes --no-restore
./.dotnet/dotnet build ComsPcGuard.sln -c Release --no-restore
./.dotnet/dotnet test ComsPcGuard.sln -c Release --no-build --no-restore --logger "console;verbosity=normal"
git diff --check
git status --short
```

Expected: format/build/test exit 0 with no warnings; `git diff --check` exits 0; status contains only the intended bootstrap and plan files. A zero-test result is acceptable only because no product behavior exists in this task and must be recorded as `NOT_RUN_PRODUCT_BEHAVIOR` rather than PASS.

- [ ] **Step 9: Commit the independently reviewable bootstrap**

Stage only the listed files and commit with an intent-first subject:

```bash
git add .gitignore .editorconfig global.json Directory.Build.props Directory.Packages.props NuGet.Config ComsPcGuard.sln src tests .github README.md RESEARCH.md ARCHITECTURE.md ROADMAP.md SECURITY.md DECISIONS.md CHANGE_REQUESTS.md STATUS.md TEST_REPORT.md OPERATIONS.md SOURCES.md CHANGELOG.md docs/superpowers/plans/2026-09-12-repository-bootstrap.md
git commit -m "Make the guard project reproducible before feature work"
```

The actual commit must include applicable Lore trailers for constraints, tests, and Windows/WiX gaps.
