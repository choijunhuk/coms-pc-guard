# COMS PC Guard v3 최초 승인 계획

## 0. 문서 상태와 승인 기록

| 항목 | 값 |
|---|---|
| 계획 버전 | `0.1-approved` |
| 작성일 | 2026-09-12 (Asia/Seoul) |
| 상태 | `APPROVED` |
| 기준 명세 | `/Users/choi/Downloads/COMS_PC_Guard_v3_GitHub_Autonomous_Master_Prompt.md` |
| 로컬 작업 폴더 | `/Users/choi/Desktop/project/coms-pc-guard` |
| 제안 GitHub 저장소 | `choijunhuk/coms-pc-guard` (Private) |
| 승인자 | 최준혁(실제 사용자 응답으로만 확정) |
| 승인 메시지 | `이제 전부다 ㄱㄱ 비수익 용도야 당연하게도` |
| 승인 시각 | 2026-09-12 18:38:03 KST (+0900) |

이 파일은 사용자의 실제 승인 메시지와 날짜를 연결한 최초 승인 계획이다. 승인된 범위 안에서 Phase B~F를 단계별 재승인 없이 진행한다.

승인 전 조사 단계에서는 읽기 전용 환경·저장소 조사와 이 계획 초안 작성만 수행했다. 그 시점에는 Git 저장소 생성, GitHub 저장소 생성, 의존성 설치, 빌드, Windows 서비스·계정·ACL·AppLocker 정책 변경을 수행하지 않았다. 승인 후 실행 이력은 GitHub와 `STATUS.md`에 기록한다.

## 1. 조사 결과와 현재 제약

### 1.1 저장소와 GitHub

- `/Users/choi/Desktop/project` 아래에 기존 `coms-pc-guard` Git 저장소, 솔루션, 소스 또는 관련 구현은 없었다.
- GitHub의 `choijunhuk/coms-pc-guard`도 존재하지 않았다.
- GitHub CLI는 macOS 키체인을 통해 `choijunhuk` 계정으로 인증되어 있으며 `repo`와 `workflow` 범위가 확인되었다. 토큰 값은 조회하거나 기록하지 않았다.
- 기존 COMS 웹·앱 저장소는 별도 제품이며 이 프로젝트에 병합하거나 그 working tree를 변경하지 않는다.

### 1.2 로컬 개발 환경

- 현재 호스트: macOS 26.6 arm64.
- Git 2.54.0, PowerShell 7.4.6이 설치되어 있다.
- .NET SDK는 9.0.201만 설치되어 있고 .NET 10 SDK는 없다.
- WiX CLI와 Windows PowerShell, AppLocker, Windows Service Control Manager는 이 호스트에서 사용할 수 없다.
- 따라서 macOS에서 실행한 Core 테스트는 Windows 서비스·AppLocker·ACL·MSI 검증을 증명하지 않는다.

### 1.3 Windows 환경

- 과거에 관찰된 SSH 별칭 `gpu`/호스트 `choi`는 현재 포트 22 연결이 타임아웃이다.
- Windows 에디션·빌드·아키텍처, Owner SID, .NET 10, AppIDSvc, AppLocker/WDAC/GPO/MDM 정책 상태는 모두 `UNKNOWN`이다.
- 승인된 격리 Windows VM은 현재 지정되지 않았다.
- 결론: Windows 정책·서비스·ACL·재부팅·설치 검증은 `BLOCKED_WINDOWS_VM`이다. 접근 가능한 개인 PC가 생겨도 별도 확인 없이 격리 테스트 VM으로 간주하지 않는다.

## 2. 제품 목표와 완료 정의

동아리방의 지원 중인 Windows 11 x64 공용 PC에서 등록된 게임·런처의 실행을 한국 시간 기준 일정에 따라 제한하고 자동 해제한다. 표준 사용자의 무단 정책 변경을 어렵게 하면서 정상 개발·학습 도구와 외부 조직 정책을 보존한다.

완료는 UI나 테스트 코드의 존재가 아니라 다음 증거가 모두 연결된 상태다.

1. 승인된 P0/P1 요구사항과 구현 파일·테스트·실행 결과의 추적표.
2. 재현 가능한 restore/build/test/package 명령과 고정된 의존성.
3. 승인된 Windows 환경에서의 서비스·AppLocker·ACL·다중 세션·재부팅·설치/제거 실증.
4. Owner와 Member 실제 토큰을 구분한 권한 테스트.
5. MSI 산출물 경로·버전·해시·서명 여부.
6. 미검증·미지원·잔여 위험의 명시.
7. 기능 브랜치, 커밋, PR, CI, merge, tag/release가 구현 단계와 대응되는 GitHub 기록.

Windows 실증이 끝나지 않으면 상태는 `CODE_COMPLETE_WINDOWS_VALIDATION_BLOCKED`이며 운영 완료나 v1.0.0으로 표시하지 않는다.

## 3. 승인 범위

### 3.1 P0 — 첫 실사용 버전 필수

| ID | 요구사항 | 완료 증거 |
|---|---|---|
| P0-01 | 등록 게임·런처의 시간표 기반 제한과 자동 해제 | 경계 시각·재시작·절전 복귀 테스트와 실제 유효 정책 재조회 |
| P0-02 | 로그인과 독립적인 자동 시작 서비스 | SCM 자동 시작·복구·로그아웃/재부팅 테스트 |
| P0-03 | 표준 사용자 변조 방지 | 파일·DB·서비스 설정·관리 파이프 ACL 거부 테스트 |
| P0-04 | OS 정책 연동과 실행 중 대상 정리 | 무해 EXE의 실행 전 차단 및 정확한 프로세스 종료 실증 |
| P0-05 | 단일 Owner 인증, Admin, 읽기 전용 Notifier | 실제 SID·상승 토큰·Member 거부·세션별 UI 테스트 |
| P0-06 | 앱별/전체/Member별 임시 허용과 긴급 제한 | 두 Member의 기존 로그인 세션, 우선순위·만료·취소·재부팅·외부 Deny 충돌 테스트 |
| P0-07 | 미리보기, 감사 전용, 외부 정책 충돌 검사 | 변경 전 영향 보고와 non-mutating audit 테스트 |
| P0-08 | 마지막 정상 정책, 실제 적용 검증, 복구 CLI, 안전 제거 | 중간 실패·전원 중단 모사·소유 규칙만 복원/제거 |
| P0-09 | 진단과 최소 감사 로그 | 30일/100 MiB 회전, 민감정보·CSV 수식 주입 테스트 |
| P0-10 | 실제 MSI와 반복 가능한 빌드·테스트 | 고정 버전 Windows 빌드, 설치/수리/업그레이드/제거 보고서 |

### 3.2 P1 — 같은 승인 계획에 포함하는 운영 편의

| ID | 요구사항 | 완료 증거 |
|---|---|---|
| P1-01 | 설치 앱·실행 파일 후보 발견과 Owner 확인 등록 | 후보와 실제 승인 규칙 분리 테스트 |
| P1-02 | 앱 업데이트 후 식별·규칙 재검사 | 서명/해시 캐시 무효화 및 불확실 후보 보류 |
| P1-03 | 요일별 다중 구간, 자정 횡단, 날짜/시험기간 예외 | 결정 테이블 경계값 테스트 |
| P1-04 | 정책 JSON 백업/import 미리보기와 CSV 로그 export | 스키마·크기·경로·수식 주입 검증 |
| P1-05 | 로컬 오탐/임시 허용 요청함 | 자동 승인 금지, 중복·속도 제한 테스트 |
| P1-06 | 한국어 상태 안내와 다중 세션 알림 억제 | 빠른 사용자 전환·Notifier 종료/재시작 테스트 |
| P1-07 | 라이트/다크 테마와 키보드 접근성 | 포커스 순서·고대비·키보드 전용 점검 |

P1은 문서상 승인 범위에 포함한다. P0만 충족한 빌드는 중간 prerelease일 수 있지만 프로젝트 최종 완료는 승인된 P0/P1 전체를 요구한다.

### 3.3 P2 — 이번 버전에서 제외

- 중앙 서버, 원격 관리 웹, 모바일 앱, 클라우드 계정, SaaS, 외부 AI API.
- 텔레메트리·개인정보 자동 전송, 자동 업데이트 다운로드/설치.
- 브라우저·클라우드·VM·임의 인터프리터 위 게임의 완전 차단.
- 커널 드라이버, 안티치트 우회/연동, DLL 주입, 프로세스 은폐.
- WDAC/App Control for Business 강제 배포와 서명 잠금 정책.
- 공유 관리자 PIN, 자체 비밀번호, 공통 마스터 해제 암호.
- P2용 빈 서버, 미완성 버튼, 확장용 추상화는 만들지 않는다.

## 4. 위협 모델과 보호 한계

### 4.1 보호 대상

- 표준 Member가 설정·DB·서비스·설치 파일을 변조하는 행위.
- 권한 없는 관리 IPC, caller가 주장하는 `isAdmin`/PID/경로 위조, 재전송·폭주·잘못된 입력.
- 등록 EXE의 이름 변경·경로 복사, 업데이트 후 식별 정보 변화.
- 서명 문자열·파일 속성·Publisher 하나만 신뢰해 같은 공급자의 개발 도구를 오차단하는 행위.
- 서비스 재시작·로그아웃·절전·벽시계 변경으로 임시 허용을 연장하는 행위.
- 제품이 관리하는 규칙과 외부 AppLocker/GPO/MDM 정책의 충돌·드리프트.
- 정책 적용 도중 장애, DB 손상, 디스크 부족, 제거 중단 후 잔여 규칙.

### 4.2 명시적 한계

- 다른 로컬 관리자, SYSTEM, 커널 취약점, 외부 부팅, 펌웨어/UEFI 변경, OS 재설치, 오프라인 디스크 수정은 완전 방어하지 않는다.
- 등록하지 않은 게임, 브라우저/원격/가상 환경 게임, Java/Python/Node 등 허용된 학습 런타임의 모든 사용을 판별하지 않는다.
- AppLocker는 방어 심화 기능이며 절대적인 Windows 보안 경계로 표현하지 않는다.
- 조직이 관리하는 외부 Deny는 이 제품의 임시 허용으로 우회하지 않는다.
- 안티치트·보호 프로세스 접근 거부는 제한된 재시도 후 `DEGRADED`로 표시하며 우회하지 않는다.
- 코드 서명이 SmartScreen 무경고를 보장하지 않는다.

## 5. 확정 제안 기술 스택과 의존성

승인 시 아래 버전을 초기 lock으로 사용한다. patch/feature-band 업데이트는 공식 지원·라이선스·회귀 테스트를 확인한 별도 dependency PR로만 수행한다. major 변경은 Change Request가 필요하다.

| 항목 | 제안 버전/설정 | 라이선스·비용 판단 |
|---|---|---|
| 대상 OS | Windows 11 24H2 x64, build 26100 이상, 최신 보안 업데이트 | Windows 라이선스/VM 비용은 기존 보유 환경 사용을 전제; 새 비용은 별도 승인 |
| .NET SDK | `10.0.401`, `global.json`에서 `rollForward: disable`, `allowPrerelease: false` | MIT, 무료; 10.0.12 LTS 런타임, 2028-11-14 지원 종료 |
| Target Framework | `net10.0-windows10.0.26100.0` | .NET/WPF MIT, 무료 |
| UI | WPF, 별도 MVVM 프레임워크 없음 | .NET 일부, MIT |
| Service | Worker Service + `Microsoft.Extensions.Hosting.WindowsServices` `10.0.12` | MIT, 무료 |
| 로그 | `Microsoft.Extensions.Logging.EventLog` `10.0.12` + 제품 DB 집계 | MIT, 무료; 외부 로그 SaaS 없음 |
| DB | `Microsoft.Data.Sqlite` `10.0.12`; transitive graph lock | MIT; SQLite public domain, 무료 |
| 테스트 | `MSTest.Sdk` `4.4.0` | MIT, 무료 |
| Installer | `WixToolset.Sdk` `7.0.0` | 소스 MS-RL; release binary는 OSMF EULA 적용. 첫 download/install/invocation 전에 Owner의 비수익 사용 진술과 당시 EULA로 무상 적격성을 기록한다. 적격성을 확정할 수 없거나 비용 의무가 있으면 `BLOCKED_WIX_LICENSE`로 두고 승인 요청 |
| CI | GitHub Actions `ubuntu-24.04`, `windows-2025` 고정 label | Private 저장소 포함 무료 분량 안에서는 예상 $0; 유료 runner/minutes 필요 시 사전 승인 |
| 코드 서명 | 초기는 unsigned development package로 명시 | 인증서/Artifact Signing은 자동 구매하지 않음; 비용 발생 시 사전 승인 |

의존성 최소화 원칙:

- WPF/MVVM, IPC protocol, scheduling, hashing, JSON, cryptography는 먼저 .NET 기본 라이브러리를 사용한다.
- Serilog, ORM, command framework, DI 확장, 자동 업데이트 라이브러리를 기본 추가하지 않는다.
- NuGet central package management와 lock file을 사용하고 CI에서 locked restore를 수행한다.
- WiX license gate가 열리기 전에는 다른 .NET 작업만 진행하고 WiX binary를 내려받거나 실행하지 않는다.

## 6. 아키텍처와 신뢰 경계

### 6.1 컴포넌트

- `Guard.Core`: 순수 정책 모델, 우선순위, 시간표, 결정, 다음 전환. OS·DB 의존 없음.
- `Guard.Service`: Windows Service이자 유일한 정책/DB 작성자. 조정 상태 머신과 감사 기록 보유.
- `Guard.Infrastructure.Windows`: AppLocker, 토큰/SID, ACL, 프로세스, SCM, 이벤트 로그 어댑터. 특권 코드를 이 경계에 집중.
- `Guard.Admin`: Owner 관리 UI. 파일/DB를 직접 쓰지 않고 서비스 관리 파이프만 사용.
- `Guard.Notifier`: 일반 사용자 세션별 읽기 UI. 상태 파이프와 예외 요청만 사용.
- `Guard.Cli`: 진단·관리 명령. 서비스와 같은 인증 경계를 사용.
- `Guard.Recovery`: 서비스가 없어도 제품 소유 변경만 복구하는 좁은 elevated 도구. CLI 독립 모드로 통합 가능.
- `Guard.Contracts`: 버전 고정 IPC DTO, 오류 코드, 크기 제한.
- `Tests`, `Installer`, `Docs`.

### 6.2 Owner와 Member

- 역할은 `Owner`와 `Member` 둘뿐이다.
- Owner는 설치 시 실제 상승 토큰에서 선택·확인한 한 개의 Windows SID로 고정한다. 표시 이름이나 Administrators 그룹 전체를 Owner로 보지 않는다.
- Owner SID의 복구 권한 기록은 SQLite와 분리된 ACL 보호 메타데이터에 보관해 DB 장애 시에도 검증한다.
- Owner 교체는 일반 설정이 아니라 별도 복구 절차이며 기존 Owner 또는 문서화된 Windows 복구 권한이 필요하다.
- Member는 명시적으로 등록된 표준 사용자 SID를 대상으로 한다. `Everyone` Deny를 만들지 않는다. 새/미확인 계정은 자동으로 보호됐다고 표시하지 않고 진단·등록 대상으로 올린다.
- Admin UI는 상시 상승 실행하지 않는다. 관리 작업 시 서비스가 실제 caller SID와 상승 상태를 매 요청 재검증한다.

### 6.3 서비스 권한

- 초기 설치 서비스 계정은 `LocalSystem`으로 승인 요청한다. 이유는 로컬 AppLocker 정책 작성, 모든 사용자 세션의 적용 상태 관찰, 대상 프로세스 처리 때문이다.
- LocalSystem 영역은 `Guard.Infrastructure.Windows`와 명시된 coordinator 명령으로 제한한다.
- arbitrary command, PowerShell 문자열, 임의 EXE 실행, 임의 파일 쓰기 API는 만들지 않는다.
- Phase B에서 더 낮은 전용 service identity가 동일한 완료 기준을 만족한다는 증거가 나오면 권한 모델 변경이므로 Change Request로 전환한다.

### 6.4 IPC

- 읽기 중심 상태 파이프와 Owner 관리 파이프를 분리한다.
- 명시적 DACL, local-only, logon SID/session scope, 실제 client token 검사, server process/service identity 검증을 적용한다.
- protocol version, request ID, 고정 command enum, schema/length/count 제한, timeout/cancellation, rate limit, idempotency key를 둔다.
- `FILE_GENERIC_WRITE`처럼 파이프 인스턴스 생성 권한까지 넓히는 ACL을 사용하지 않는다.

## 7. 정책 결정과 실제 적용 상태

Core의 결정은 다음을 포함한다.

- `Decision`
- `ReasonCode`
- `MatchedRuleIds`
- `NextTransition`
- `PolicyVersion`

저장은 다음 세 축을 분리한다.

1. `DesiredDecision`: 현재 시간·사용자·앱 규칙이 원하는 결과.
2. `AppliedObservation`: OS에서 재조회한 실제 유효 정책, revision/hash, 대상 SID/앱, 관찰 시각.
3. `Health`: 초기화·적용·충돌·오류·검증 신선도.

표시 상태 `ALLOWED`, `RESTRICTED`, `TEMPORARY_ALLOW`, `AUDIT_ONLY`, `INITIALIZING`, `APPLYING`, `DEGRADED`, `ERROR`는 세 축의 결정적 매핑 결과다. 시계상 제한 시간이라는 이유나 명령 exit code가 0이라는 이유만으로 `RESTRICTED`를 표시하지 않는다.

## 8. 기본 정책과 수치

승인 시 아래를 기본값으로 확정한다.

- 정책 시간대: Windows ID `Korea Standard Time`.
- 주간 일정: 월~일 매일 09:00 이상 18:00 미만 제한.
- 공휴일: 자동 API 없이 수동 날짜 예외.
- 날짜 예외: 해당 날짜의 주간 규칙을 대체.
- 우선순위: Owner 유지보수/복구 → 긴급 제한 → 유효 임시 허용 → 날짜 예외 → 주간 일정 → 미등록 앱 허용.
- `오늘 종료까지`: 한국 시간의 다음 자정까지.
- 겹치는 임시 허용: 각 grant의 scope/만료/취소를 독립 보존하며 명시된 합집합만 허용.
- 새 실행의 의도적 유예: 없음. Core 결정과 적용 시도는 09:00:00에 시작한다. 실제 OS 활성화 지연은 측정하며 5초 기준을 충족해야 하고, 재조회 전에는 `APPLYING` 또는 실패 시 `DEGRADED`로 표시한다.
- 실행 중 게임: 정상 종료 요청 후 15초 대기, 동일 PID의 생성 시각·이미지 identity를 재검증한 대상만 강제 종료.
- 런처/updater: 등록 시 종료 분류를 별도로 승인하며 관련 없는 자식 프로세스나 공용 런타임을 종료하지 않음.
- 로그 보관: 30일 및 총 100 MiB 중 먼저 도달한 기준으로 회전.
- 진단 bundle: Owner가 직접 저장, 자동 외부 전송 없음.

임시 허용은 실행 중에는 monotonic elapsed time과 absolute expiry를 함께 관리한다. 재시작 후 시각 신뢰가 의심되면 grant를 연장하지 않고 무효화해 Owner에게 표시한다. 제품이 OS 시간·시간대·NTP를 변경하지 않는다.

### 8.1 잠정 성능 완료 기준

Windows PoC 전이므로 아래는 보수적인 승인 기준이다. Phase B 실측으로 충족 불가능한 근거가 확인되면 몰래 완화하지 않고 Change Request를 제출한다.

- 서비스 idle CPU 평균 `< 1%` (10분, 승인 VM의 안정 상태).
- 서비스 working set 안정 상태 `<= 100 MiB`.
- Core 단일 정책 결정 p95 `<= 5 ms` (10,000회, release build).
- local status IPC p95 `<= 100 ms`; 정책 적용 자체의 시간은 별도 측정.
- 서비스 시작/복구 후 첫 실제 상태 관찰 `<= 15 s`.
- 스케줄 전환 후 새 실행 차단의 재검증 `<= 5 s`.
- 09:00 실행 중 대상은 정상 종료 유예 포함 `<= 20 s` 안에 종료 성공 또는 정확한 `DEGRADED` 결과 기록.

## 9. AppLocker 안전 적용과 복구

### 9.1 Phase B 선행 검증

UI 구현 전에 승인된 격리 Windows VM과 무해한 테스트 EXE로 다음을 통과해야 한다.

1. audit와 enforce 전환 및 실제 유효 정책 재조회.
2. Member SID의 실행 차단과 Owner 복구 경로.
3. 서명 앱은 검증된 Publisher AND Product AND Binary identity AND 승인 Version 범위로 컴파일하고, Publisher-only 규칙을 거부하며 같은 Publisher의 개발 도구를 허용.
4. 미서명 앱은 승인된 해시 집합으로 식별하고 이름 변경·경로 복사를 판별하며, 업데이트 시 서명/해시 cache를 무효화. Packaged app은 검증된 별도 identity 경로 사용.
5. 이미 로그인한 Member A만 임시 허용하고 Member B는 계속 제한. 앱별/전체 grant의 만료·취소도 검증하며 runtime group/token refresh에 의존하지 않음.
6. 제품 소유 Deny 재구성에 의한 임시 허용과 외부 Deny 보존.
7. 기존 실행 프로세스의 정상/강제 종료 정확성.
8. 서비스 재시작·재부팅·절전 복귀·사용자 전환 후 일치.
9. 외부 AppLocker/GPO/MDM/WDAC 정책 충돌과 보존.
10. 제품 규칙 제거 후 외부 정책과 개발/복구 도구가 보존됨.

Member별 허용을 실제 로그인 세션에서 구현할 수 없으면 기능을 생략하거나 전체 허용으로 낮추지 않고 Change Request를 제출한다.

### 9.2 공존 규칙

- 먼저 local/effective AppLocker, GPO/MDM/WDAC, AppIDSvc를 읽고 분석한다.
- 제품 관리 baseline과 rule ID, collection mode, policy revision을 소유 기록으로 추적한다.
- 외부 정책이 있는 collection을 전체 snapshot으로 덮어쓰거나 되돌리지 않는다.
- 기존 외부 allowlist에 광범위한 Allow를 추가해 보안을 약화하지 않는다. 광범위 product baseline은 외부 규칙이 없는 것으로 검증된 제품 관리 collection에서만 구성한다.
- 안전 공존을 증명할 수 없으면 `CONFLICT/BLOCKED`로 두고 진단·미리보기만 제공한다.
- AppLocker collection은 allowlist 의미를 가지므로 제품 Deny만 추가하면 나머지가 안전하다고 가정하지 않는다.
- 임시 허용은 겹치는 Allow를 추가하지 않고 해당 제품 소유 Deny를 제거/재컴파일한 뒤 effective policy를 재조회한다. 외부 Deny는 그대로 적용된다.
- 사후 프로세스 종료는 실행 전 차단의 fallback 성공으로 표시하지 않고, 실행 중 대상 정리 용도로만 사용한다.

### 9.3 적용 상태 머신

`Validate → SaveLastGoodEvidence → JournalPrepared → ApplyOwnedDelta → ReadEffectiveState → CommitObservation`

- 각 단계는 policy version과 idempotency key를 기록한다.
- 재시작 시 journal, DB, 실제 OS 상태를 대조해 이어서 확정하거나 제품 소유 delta만 복구한다.
- 정상 정책이 없으면 무차별 차단을 만들지 않고 잔여 OS 상태를 검사한 뒤 `ERROR`로 표시한다.
- 적용 실패 시 마지막 정상 상태를 보존한다. 그 상태가 18:00 이후에도 제한을 유지할 수 있으므로 무조건 fail-open이라고 약속하지 않는다.
- 복구와 제거는 제품 소유 rule/서비스/시작 항목만 다룬다. 제거 실패는 성공이 아니다.

## 10. 장애 정책

| 장애 | 동작 |
|---|---|
| 새 DB/정책 검증 실패 | last-good 유지, 새 버전 거부, 오류 표시 |
| OS 적용/재조회 실패 | Desired/Applied 차이와 실제 잔여 상태 표시, 성공 확정 금지 |
| 유효한 last-good 없음 | 광범위 규칙 생성 금지, `ERROR`, 복구 안내 |
| 서비스 비정상 종료 | SCM 제한 재시작, journal reconciliation, 반복 장애 loop 제한 |
| 로그 실패/디스크 부족 | 정책 engine 유지, 집계/회전으로 공간 회수, 경고 |
| 외부 정책 충돌 | 외부 정책 보존, 자동 우회/초기화 금지, 정확한 충돌 보고 |
| 개발/복구 도구 차단 위험 | enforce 확정 금지, 제품 소유 변경 복구 |
| Owner 메타데이터 손상/자격 상실 | 공통 master 암호 금지, 문서화된 Windows 복구 한계 표시 |

## 11. 단계와 종료 게이트

### Phase A — 조사·계획·최초 승인

- 이 문서와 조사 증거를 검토한다.
- 종료 조건: 사용자의 실제 계획 승인, 저장소/경로/가시성/권한/기본값/VM 범위 기록.

### Phase B — Windows 차단 엔진 PoC

- 승인된 격리 VM에서 AppLocker, 임시 허용, 실행 중 프로세스, 복구, 공존을 무해 EXE로 검증한다.
- 종료 조건: §9.1의 10개 시나리오 PASS와 원복 snapshot. VM 없이는 `BLOCKED`.

### Phase C — Core·저장·서비스 조정

- 결정 엔진, persistence, app identity, Desired/Applied reconciliation과 crash recovery를 test-first로 구현한다.
- 종료 조건: 경계/우선순위/시간/DB/상태 머신 자동 테스트 PASS. OS 독립 작업은 VM 대기 중에도 진행 가능.

### Phase D — Owner·IPC·ACL·Recovery

- 실제 caller token, SID/elevation, pipe DACL, service/file/DB ACL, offline recovery를 구현·공격 테스트한다.
- 종료 조건: Owner/Member 실제 Windows 토큰, malformed/replay/flood, name squatting, standard-user tamper 테스트 PASS. VM 없이는 실제 경계 검증 `BLOCKED`.

### Phase E — Admin·Notifier·운영 기능

- Phase B의 enforcement 계약이 검증된 뒤 한국어 UI와 P1 flow를 구현한다.
- 종료 조건: truthful status, multi-session, keyboard/theme, request/import/export tests PASS.

### Phase F — MSI·수명주기·릴리스

- clean install/reinstall/repair/upgrade/uninstall, 중간 중단, 잔여 rule 검사를 수행한다.
- package trust mode는 `DevelopmentUnsigned`와 `SignedRelease`로 분리한다. 전자는 승인된 격리 VM에서만 명시적으로 허용하고 운영 배포에 사용하지 않는다. 후자는 구성된 Authenticode chain·publisher·timestamp 검증을 통과해야 한다.
- 종료 조건: 실제 MSI, 해시/서명 상태, 변조/잘못된 서명 package 거부, mutable한 동봉 checksum만으로 신뢰하지 않는 negative test, regression/security/performance 보고, 운영·복구 문서. Windows 검증 없이 완료 불가.

## 12. 테스트와 증거 정책

- 모든 요구사항은 `PASS`, `FAIL`, `BLOCKED`, `NOT_RUN` 중 하나로 기록한다.
- 테스트 코드 존재와 실제 실행 통과를 구분한다.
- 실패 assertion을 약화하거나 테스트를 삭제해 통과시키지 않는다.
- Core는 08:59:59/09:00:00/17:59:59/18:00:00, 자정 횡단, 날짜 예외, DST 비적용 시간대, 우선순위, restart/clock rollback을 test-first로 고정한다.
- Windows 통합 테스트는 무해한 전용 fixture EXE와 VM snapshot을 사용한다. 실제 게임/안티치트/운영 PC를 임의 종료하지 않는다.
- GitHub-hosted Windows runner는 관리자/UAC-disabled 환경이므로 compile/unit/package smoke에만 사용한다. 표준 사용자, 실제 AppLocker 공존, multi-session, 운영 설치의 PASS 근거로 쓰지 않는다.
- 최종 `TEST_REPORT.md`에는 환경, 명령, exit code, 결과, 산출물, 미검증 항목을 기록한다.

## 13. GitHub 개발 기록 계획

### 13.1 승인 후 bootstrap

1. 현재 로컬 폴더에서 `main`을 초기화하고 승인된 `PLAN.md`만 첫 기록으로 남긴다.
2. 인증된 개인 계정 `choijunhuk` 아래 `coms-pc-guard` Private 저장소를 만들고 remote `origin`을 연결한다.
3. 승인 계획 commit을 remote `main`에 push하고 upstream 및 GitHub default branch가 `main`인지 재조회한다.
4. `chore/repository-bootstrap` 브랜치에서 solution, `.gitignore`, central package versions/lock, CI, 필수 문서 뼈대를 구현한다.
5. PR과 CI 검토 후 merge commit으로 `main`에 통합한다.

Product source license는 최초 Private 개발 중 `UNLICENSED / all rights reserved`로 둔다. 공개 또는 제3자 배포 라이선스 선택은 별도 승인 대상이며 dependency notices는 유지한다.

### 13.2 일상 workflow

- short-lived `feat/`, `fix/`, `security/`, `test/`, `docs/`, `chore/`, `refactor/` branch.
- Conventional Commit subject와 workspace Lore trailer를 함께 사용한다.
- 의미 있는 단위마다 test → diff/secret 검토 → commit → push → PR.
- PR은 요구사항/PLAN/Decision, 설계 trade-off, 명령과 실제 결과, 권한 영향, BLOCKED/NOT_RUN을 포함한다.
- 적용 가능한 필수 check가 통과한 PR만 merge commit으로 통합한다.
- merge 후 main smoke, STATUS 갱신, 원격 branch 정리.
- 실패/수정 이력을 reset/force-push로 지우지 않는다.

### 13.3 CI와 보호

- `ubuntu-24.04`: locked restore, format/analyzers, Core build/test.
- `windows-2025`: Windows compile, WPF/Service build, unit test, unsigned MSI package smoke.
- 실제 policy/service/ACL/install lifecycle은 승인 VM의 별도 report와 연결한다.
- bootstrap CI가 안정된 뒤 main ruleset에서 PR과 필수 checks를 요구하고 force push/deletion을 금지한다. 단일 Owner의 승인된 자동 merge 흐름은 유지한다.

### 13.4 릴리스

- 검증된 main commit만 tag한다.
- `alpha`: Core/PoC, `beta`: Service/UI/Installer 시험 후보, `v1.0.0`: P0/P1 및 Windows 운영 검증 완료.
- prerelease는 승인 범위에서 자동 생성할 수 있다.
- public stable release, GitHub Pages, package registry 공개는 별도 승인 전 금지한다.
- unsigned package는 release note와 UI/문서에서 명시한다.

## 14. 자율 실행 권한과 별도 승인 경계

### 14.1 이 계획 승인으로 허용

- `/Users/choi/Desktop/project/coms-pc-guard` 안의 파일 생성·수정·리팩터링·테스트·패키징.
- §5의 의존성 설치와 lock, 승인 범위 내 patch update PR. 단 WiX는 `BLOCKED_WIX_LICENSE` gate를 먼저 해제해야 한다.
- `choijunhuk/coms-pc-guard` Private 저장소 생성과 이 저장소 안의 branch/commit/push/PR/merge/branch cleanup/issue/prerelease.
- 회귀 테스트, 버그 수정, 성능 개선, 내부 구조 개선.
- 명시적으로 승인된 격리 Windows VM에서 무해 fixture를 사용하는 Phase B/D/F 테스트.

### 14.2 이 계획을 승인해도 금지

- 실제 동아리방/개인 운영 PC의 서비스·계정·ACL·AppLocker/WDAC/GPO/MDM 변경 또는 실제 게임 종료.
- 아직 지정되지 않은 Windows 장비를 격리 테스트 VM으로 간주하는 행위.
- public/private 전환, repository transfer, collaborator/bot 권한 추가, 기본 branch 변경, protection 약화, history rewrite/force push.
- 외부 서버/포트/원격 관리/telemetry/개인정보 수집.
- 인증서·유료 서비스·유료 runner 구매.
- public stable release, 외부 배포, package registry 공개.
- 필수 기능/보장/권한/오류/복구/완료 기준 변경.

금지 범위가 필요해지면 `CHANGE_REQUESTS.md`에 CR 형식으로 근거·영향·대안·복구·보류/계속 가능 작업을 기록하고 관련 작업만 멈춘다.

## 15. 모델·토큰 사용 전략

사용자가 허용한 상한은 `gpt-6-astra` reasoning `medium`이다. 검증 범위는 줄이지 않고 다음처럼 작업 난도에 따라 라우팅한다.

- Luna low: 파일/심볼 탐색, 로그 요약, 독립적인 단순 현황 조사.
- Terra medium: 일반 구현, 단위 테스트, 작은 리팩터링.
- Sol medium: 구현 계획, 교차 컴포넌트 검토, 테스트 설계.
- Astra medium: Owner/IPC/AppLocker/복구/installer 같은 고위험 설계 및 최종 보안 검토에만 사용.
- 독립 작업만 병렬화하고 동일 파일을 여러 agent가 수정하지 않는다.
- agent에게 전체 대화 대신 필요한 파일·계약·출력 형식만 전달한다.
- 반복 탐색 결과는 STATUS/DECISIONS/TEST_REPORT에 짧게 축적해 같은 문서를 매번 다시 읽지 않는다.
- 빠른 모델의 결론도 공식 문서·실행 결과·상위 검토로 확인하며 테스트/보안 gate는 모델 비용 때문에 생략하지 않는다.

## 16. 미검증 가정과 승인 후 첫 실행 순서

### 16.1 현재 미검증

- 대상 Windows 11 PC가 build 26100+이며 최신 AppLocker 요구사항을 충족하는지.
- AppIDSvc 상태와 기존 local/GPO/MDM/WDAC 정책.
- LocalSystem 서비스가 필요한 모든 기능을 충족하고 부팅/복구 시 안전한지.
- Member별 임시 허용이 기존 로그인 토큰과 외부 정책 아래에서 즉시 반영되는지.
- WiX OSMF의 이 프로젝트 실제 비용 분류와 코드 서명 비용/가용성. Owner가 비수익 사용임을 확인하고 EULA 적격성을 검토하기 전 WiX 사용은 차단됨.
- §8.1의 지연·자원 기준을 승인 VM에서 충족하는지.

### 16.2 승인 후 자동 실행 순서

1. 승인 기록 반영, local Git/main과 Private GitHub 저장소 생성.
2. `chore/repository-bootstrap` PR: solution, pinned SDK/packages, analyzers, CI, required docs.
3. 승인된 Windows VM이 없으면 GitHub issue로 B/D/F 환경 gate를 `BLOCKED` 기록하고 Core/시뮬레이션 harness를 진행.
4. `feat/core-policy` PR: 정책 결정·시간·우선순위·temporary grant test-first 구현.
5. VM이 지정되면 `test/windows-enforcement-poc`에서 Phase B를 먼저 완료. 운영 PC는 사용하지 않음.
6. B PASS 후 Phase C~F를 의존성 순서로 수행하며 각 PR에서 테스트/보안 검토.
7. 완료 증거와 잔여 위험을 `STATUS.md`, `TEST_REPORT.md`, `SECURITY.md`, release note에 일치시킴.

## 17. 승인 시 함께 확정되는 항목

이 계획 `0.1-approved`로 다음을 한 번에 확정했다.

- P0/P1 포함, P2 제외.
- 작업 폴더 `/Users/choi/Desktop/project/coms-pc-guard`.
- GitHub `choijunhuk/coms-pc-guard`, Private, `main`, `origin`, merge commit.
- Windows 11 24H2 x64 build 26100+와 .NET 10/WPF/Windows Service/SQLite/Named Pipe/WiX 7 스택.
- 단일 Owner SID, 명시적 Member SID, LocalSystem service, 외부 정책 보존.
- 매일 09:00~18:00 한국 시간, 15초 정상 종료 유예, 로그 30일/100 MiB, §8.1 성능 기준.
- 승인된 Windows VM이 현재 없으므로 실제 Windows 검증은 지정 전까지 BLOCKED.
- 이 프로젝트가 수익을 발생시키지 않는다는 Owner 진술. 당시 OSMF EULA 검토로 무상 적격성이 확인되지 않으면 WiX 사용은 별도 승인 전 BLOCKED.
- 운영 PC 변경, 유료 구매, 공개 배포는 이 승인에 포함되지 않음.
- 최대 Astra medium의 난도별 모델 라우팅과 검증 불변 원칙.

## 18. 공식 근거와 확인일

확인일: 2026-09-12. 버전·가격·runner image·Windows servicing 상태는 구현/릴리스 시 재검증한다.

- .NET support policy: https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core
- .NET 10 release metadata: https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/10.0/releases.json
- .NET `global.json`: https://learn.microsoft.com/en-us/dotnet/core/tools/global-json
- AppLocker requirements: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/requirements-to-use-applocker
- AppLocker overview/limitations: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview
- AppLocker allow/deny: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-applocker-allow-and-deny-actions-on-rules
- Application Identity service: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/configure-the-application-identity-service
- Windows service/session isolation: https://learn.microsoft.com/en-us/windows/win32/services/service-changes-for-windows-vista
- Named Pipe security: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- SmartScreen reputation: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation
- WiX v7.0.0 release: https://github.com/wixtoolset/wix/releases/tag/v7.0.0
- WiX lifecycle/license/OSMF: https://docs.firegiant.com/wix/
- GitHub-hosted runners: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
