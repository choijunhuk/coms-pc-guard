# 실측 우선 MVP 계획 (2026-10-26)

이 문서는 `docs/superpowers/plans/2026-09-13-windows-vm-enforcement-poc.md`를 대체한다. 승인 범위인 `PLAN.md`는 바꾸지 않는다.

## 왜 다시 계획하나

- `main`은 정책 엔진, SQLite 조정기, 앱 식별, AppLocker XML 컴파일러까지 완료됐다(테스트 265개). 하지만 실제로 실행을 막는 코드는 없다.
- `feat/windows-enforcement-poc` 브랜치(9/13~9/15, 커밋 52개, 약 1만 줄)는 VM 증명용 안전장치(VM 증명, Owner 토큰 검증, 인증서, ACL, SYSTEM 감시 작업)를 먼저 쌓다가, AppLocker 정책을 **한 번도 적용하지 못한 채** 감시 작업 직렬화 문제에서 멈췄다.
- 교훈: 가장 불확실한 것("멤버별 차단과 임시 허용이 실제 Windows에서 되는가")을 마지막으로 미뤘다.

이 브랜치는 지우지 않고 참고용으로 둔다. 새 작업은 `main`에서 시작한다.

## 원칙

1. **가장 불확실한 것부터 실측한다.** 실제 AppLocker 동작을 확인하기 전에는 제품 안전장치를 늘리지 않는다.
2. **일회용 VM 안에서는 스냅샷이 안전장치다.** VM 실험 코드에 증명·잠금 장치를 넣지 않고, 실험 전 스냅샷을 찍고 문제가 생기면 되돌린다. 실험은 오직 VM에서만 하고, 실제 PC(호스트)의 AppLocker·서비스·계정은 건드리지 않는다.
3. **제품 코드의 안전장치는 실제 동아리 PC에 필요한 만큼만 둔다.** `PLAN.md`의 P0/P1 범위와 보호 한계는 그대로 두고, 진행 순서와 검증 방식만 가볍게 한다.

## 1단계 — VM 실측 (Phase B 핵심)

환경: VirtualBox 7.2.16의 `COMS-PC-Guard-x64-Lab`(Windows 11 Enterprise 평가판 25H2 build 26200, D: 드라이브). 계정: Owner(관리자), MemberA·MemberB(일반 사용자). 실험 전 스냅샷: `pre-lean-spike-2026-10-26`.

대상 앱: 무해한 서명 앱 `charmap.exe`(문자표)를 "게임" 대신 쓴다. 대조군은 같은 게시자·같은 제품의 `winver.exe`다.

정책은 레포의 `AppLockerPreviewCompiler`와 `AppLockerPolicyXmlWriter`가 만든 XML을 그대로 적용한다. 수작업 XML은 쓰지 않는다.

| ID | 시나리오 | 기대 결과 |
|---|---|---|
| S1 | 기준 상태 조사 | 로컬·유효 AppLocker 규칙 0개, AppIDSvc 상태 기록 |
| S2 | MemberA 제한, MemberB 허용 정책 적용(Enabled) | MemberA의 charmap 차단, MemberB·Owner 허용, MemberA의 winver 허용 |
| S3 | charmap을 다른 이름·경로로 복사해서 실행 | MemberA에게 계속 차단 |
| S4 | MemberA 임시 허용으로 재컴파일·적용 | 이미 로그인해 있던 MemberA 세션에서 5초 안에 실행 가능 |
| S5 | 다시 제한으로 적용 | 같은 세션에서 5초 안에 다시 차단 |
| S6 | AuditOnly 모드 | MemberA 실행은 허용되고 감사 이벤트(8003)가 기록됨 |
| S7 | 재부팅 | 정책 유지, AppIDSvc 자동 시작, MemberA 차단 유지 |
| S8 | 정리(빈 정책 적용) | 모든 계정 허용, 남은 규칙 0개 |

증거: 원본 로그는 레포 밖 `D:\COMS-PC-Guard-VM\Evidence\lean-spike\`에 저장하고, 레포에는 요약(시나리오별 PASS/FAIL, 측정 시간, 정책 해시)만 기록한다. SID 원문과 비밀번호는 레포에 넣지 않는다.

## 2단계 — 최소 동작 제품

1단계가 통과한 뒤 진행한다.

- `Guard.Windows` (`net10.0-windows`): AppLocker 적용·조회 어댑터(`IEnforcementAdapter` 구현). Windows PowerShell 5.1의 `Set-AppLockerPolicy`/`Get-AppLockerPolicy`를 고정 인자로만 호출하고, 임의 명령 문자열은 만들지 않는다. 실행 중인 대상 프로세스 정리도 여기에 둔다.
- `Guard.Host`: Windows 서비스(LocalSystem). 정책 파일을 읽고, 다음 전환 시각마다 결정 → 컴파일 → 적용 → 재조회 → 기록(기존 `PolicyReconciler` 사용).
- `Guard.Cli`: Owner용 명령(상태, 멤버/앱 등록, 임시 허용, 긴급 제한, 감사/차단 전환, 정리). UI(WPF)는 그 다음이다.
- 설치: 처음에는 PowerShell 설치·제거 스크립트로 한다. MSI(WiX)는 issue #3(EULA) 해결 뒤에 한다.
- 동아리방 적용: 처음 1주는 AuditOnly로 운영해 기록만 보고, 문제가 없으면 Enabled로 바꾼다. 실제 PC 적용은 동아리의 동의를 받은 뒤에 한다.

## 미루는 것

외부 GPO/MDM/WDAC 공존 실증, 앱 자동 발견(P1-01), 요청함(P1-05), 테마(P1-07), MSI, 코드 서명은 2단계가 실제 PC에서 돈 뒤에 다시 판단한다.
