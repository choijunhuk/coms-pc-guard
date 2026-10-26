# 실측 결과: AppLocker 차단과 제품 경로 (2026-10-26)

계획: `docs/plans/2026-10-26-lean-native-mvp.md`. 원본 증거(로그, JSON, 스크린샷)는 레포 밖 `D:\COMS-PC-Guard-VM\Evidence\lean-spike\`에 있다. SID는 `SID-1001`(MemberA), `SID-1002`(MemberB)처럼 줄여 쓴다.

## 환경

- 호스트: Windows 11 Home build 26200, VirtualBox 7.2.16(Hyper-V/NEM 위). 호스트의 AppLocker·서비스·계정은 바꾸지 않았다(읽기 전용 `guard identify`/`guard status`만 실행).
- 게스트: `COMS-PC-Guard-x64-Lab`, Windows 11 Enterprise Evaluation 25H2 build 26200, 4 GB / 3 vCPU. 평가판 라이선스 만료까지 약 47일(2026-12 중순).
- 계정: Owner(관리자), MemberA·MemberB(일반 사용자). 자동화는 내장 Administrator를 VirtualBox 게스트 제어로 사용(UAC 승인 1회).
- "게임" 대역: `hostname.exe`(Microsoft 서명). 대조군: `whoami.exe`(같은 게시자·제품, 다른 파일명).
- 모든 정책 XML은 레포의 컴파일러(`guard preview`, 이후 `guard apply`/서비스)가 만들었다. 손으로 쓴 XML은 없다.

## 시나리오 결과

| ID | 내용 | 결과 |
|---|---|---|
| S1 | 기준 상태 | PASS: 로컬·유효 규칙 0개, AppIDSvc Auto/Running, MDM 없음, 시스템 CI 정책만 존재 |
| S2 | MemberA 제한, MemberB 임시 허용 | PASS: MemberA `hostname` 차단(Win32 1260), MemberA `whoami` 허용, MemberB·Owner 허용 |
| S3 | 이름·경로를 바꾼 복사본 | PASS: `games\totally-not-a-game.exe`도 MemberA에게 차단 |
| S4 | 로그인해 있는 세션에서 임시 허용 | PASS: 정책 교체 후 **2.59초**에 허용, 이후 흔들림 0회 |
| S5 | 같은 세션에서 다시 제한 | PASS: **1.96초**에 차단, 164회 시도 중 오류 0회 |
| S6 | AuditOnly | PASS: **2.82초** 만에 이벤트 8004(차단)→8003(차단 예정 감사)로 전환, 실행 허용. 이벤트에 규칙 이름·ID 포함 |
| S7 | 재부팅 | PASS(서비스 설치 상태): 서비스 자동 시작, 정책(리비전 5) 유지, MemberA 차단·MemberB 허용 |
| S8 | 제거 | 처음 FAIL → 수정 후 PASS. 아래 "빈 정책" 참고 |

## 제품 경로 결과

| ID | 내용 | 결과 |
|---|---|---|
| P1 | `guard status`(게스트) | 상태·결정·"apply 필요" 판정 정확 |
| P2 | `guard apply` | 첫 시도는 아래 버그 2개로 실패해 미완료 시도가 남음 → 수정 후 **복구 로직이 그 시도를 마무리**하고 리비전 1 확인. MemberA 차단, `whoami`·MemberB 허용 |
| P3 | 설치 스크립트 | 서비스 LocalSystem·Auto, 데이터 폴더 ACL은 SYSTEM·Administrators만, `state.db` 생성, 마지막 정상 리비전 1 |
| P4 | 서비스 실행 중 정책 파일 교체(임시 허용) | 파일 교체 후 **16.9초 / 11.7초**(두 번 측정)에 MemberA 허용 |
| P9 | 재설치 → 제거(수정본) | 설치 후 차단, 제거 직후 MemberA 허용, 서비스·설치 폴더 제거, 로컬 규칙 0개 |

## 실측으로 알게 된 것

1. **정책 교체는 2~3초 안에 이미 실행 중인 세션에도 반영된다.** AppLocker는 프로세스를 만들 때마다 토큰의 사용자 SID로 판단한다. 그래서 멤버별 임시 허용은 "우리 Deny 규칙 제거"만으로 충분하다.
2. **`Get-AppLockerPolicy -Effective`는 실제 차단보다 늦게 바뀐다.** 적용 확인은 로컬 정책을 읽어서 한다.
3. **로컬 정책을 "빈 정책"으로 바꾸면 차단이 풀리지 않는다.** 2분 대기와 `gpupdate /force` 후에도 마지막 비어 있지 않은 규칙이 계속 적용됐다. "기준 규칙만 있는 전부 허용 정책"으로 먼저 바꾸면 3.1초 만에 풀리고, 그 뒤에 비워도 안전하다. `guard clear`와 제거 스크립트를 이 두 단계로 고쳤다(DR-010).
4. **제품명 문자열은 파일마다 다르다.** `charmap.exe`의 제품명에는 깨진 문자(`MICROSOFTÂ®`, U+00C2 U+00AE)가 실제로 들어 있다. 식별 정보는 반드시 `guard identify`로 파일에서 읽는다.
5. **강제 전원 차단 직전에 쓴 `policy.json`은 0x00으로 채워져 깨질 수 있다.** 서비스는 읽기 실패를 기록하고 마지막 정상 리비전을 유지했다(풀어 주지 않음). 정책 파일 쓰기는 임시 파일 → 디스크 기록 → 이름 바꾸기로 해야 한다.
6. **적용 1회에 PowerShell을 4번 띄운다.** 이 느린 중첩 VM에서는 한 번에 3~4초라 파일 변경 반영이 12~17초 걸렸다. PLAN §8.1의 "전환 후 5초 이내 재검증"은 실제 PC에서 측정해야 하고, 호출을 줄이는 최적화가 필요하다.

## 고친 버그

- `dotnet format`이 IDE0072("switch 채우기") 자동 수정으로 기본 분기 앞에 `throw new NotImplementedException()` 분기를 몰래 넣었다. `guard apply`가 VM에서 예외로 끝났다. 해당 줄을 지우고 `.editorconfig`에서 IDE0010/IDE0072를 껐다. 회귀 테스트를 추가했다.
- `Import-Module AppLocker`만으로는 정책 형식 어셈블리가 로드되지 않아 `AppLockerPolicy::FromXml`이 실패했다. 실측에서 검증된 `Set-AppLockerPolicy -XmlPolicy`와 임시 파일(무작위 이름, `CreateNew`, 즉시 삭제)로 바꿨다.
- 이벤트 로그 공급자가 기본 Warning이라 "적용함" 기록이 남지 않았다. Information까지 남기도록 고쳤다.
- win-x64 게시가 레포의 lock 파일을 바꿔 locked restore를 깨뜨렸다. 게시를 임시 소스 복사본에서 하도록 바꿨다.

## 실험실 운영에서 겪은 문제

- 9월 VM의 Owner 비밀번호가 만료(42일)되어 화면에서 한 번 변경했다. 실험 계정은 만료되지 않게 바꿨다.
- 라이브 스냅샷(메모리 8 GB)이 호스트 메모리 부족으로 멈춰 VM을 강제 종료했다. 이후 VM을 4 GB / 3 vCPU로 줄이고 스냅샷은 꺼진 상태에서만 찍는다.
- 첫 재부팅에서 대기 중이던 Windows 업데이트가 70분 넘게 끝나지 않아 스냅샷으로 되돌렸다. 실험 VM에서만 자동 업데이트를 껐다(`Disable-LabWindowsUpdate.ps1`).
- 게스트 제어 서비스가 가끔 응답을 멈춰 VM을 다시 시작했다. 원인은 확인하지 못했다(제품 서비스의 재시작 반복은 없었다).

## 아직 검증하지 않은 것

- 실제 하드웨어에서의 성능 기준(PLAN §8.1)과 시간표 경계(09:00/18:00)에서의 전환 지연.
- 제한 시작 시 이미 실행 중인 게임 프로세스 종료(P0-04 후반).
- 외부 GPO/MDM/WDAC 정책과의 공존 실증, 여러 대화형 세션, 절전 복귀.
- Owner 인증·IPC·Notifier UI, MSI 설치 파일.
