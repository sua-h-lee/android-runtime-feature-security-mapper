# Android Runtime Feature Security Mapper

승인된 Android 테스트 환경에서 앱 기능을 저위험으로 탐색하고, 사용자 행동부터
앱 내부 상태, 네트워크 프로토콜, 응답과 UI 반영까지의 런타임 증거를 수집해 기능
인벤토리와 보안 검토 우선순위를 만드는 연구용 도구다.

현재 대상 앱은 KakaoTalk 테스트 환경이지만, 구조는 다른 Android 앱에도 적용할 수
있도록 UI 탐색, 런타임 계측, 판단, 정책, 분석을 분리했다.

> 이 저장소는 정상 동작과 보안 검토 대상을 식별하기 위한 자동화다. 출력된
> 우선순위나 미확인 사항은 취약점 판정이 아니다. 반드시 권한이 있는 테스트 계정과
> 환경에서만 사용한다.

## 현재 구현

```text
UIAutomator/ADB
  → GLM-5.1 저위험 UI 행동 선택
  → 정책 엔진의 실행 허용/차단
  → Frida 행동 단위 런타임 증거 수집
  → Codex 정상 동작·보안 관찰 분석
  → 누적 기능 인벤토리 병합
```

- GLM은 다음 UI 행동만 선택하며 정상 동작 분석에는 사용하지 않는다.
- 위험 정책은 삭제, 차단, 전송, 통화, 결제 등 외부 효과가 있는 후보를 기본 차단한다.
- Frida는 UI, Activity/Fragment, LiveData/StateFlow, HTTP, LOCO, Push 등을 행동과
  연관 지어 수집한다.
- Codex는 저장된 증거를 바탕으로 정상 흐름, 보안 자산, 신뢰 경계, 미확인 사항과
  후속 검사를 정리하고 기존 기능 인벤토리와 병합한다.
- Codex 입력에는 스크린샷과 raw payload를 포함하지 않는다.

세부 실행 방법은 [automation/README.md](automation/README.md)를 참고한다.

## 빠른 실행

필수 조건:

- Android SDK의 `adb`
- Python 가상환경과 Frida Python 패키지
- 연결된 Android 에뮬레이터
- 로컬에 로그인된 Codex CLI
- GLM 계획기를 사용할 경우 Z.AI API 키

```bash
read -s "GLM_API_KEY?Z.AI API Key: "
export GLM_API_KEY
echo

./venv/bin/python -m automation doctor --glm

./venv/bin/python -m automation explore \
  --glm \
  --goal "기능을 탐색하고 정상 동작과 보안 관찰 우선순위를 분류해줘" \
  --max-steps 5
```

저장된 실행을 나중에 Codex로 분석하려면:

```bash
./venv/bin/python -m automation analyze
```

## 공개 저장소에 포함하지 않는 데이터

다음 항목은 인증 헤더, 사용자·기기 식별자, 메시지, 화면 데이터 또는 제3자 앱
바이너리를 포함할 수 있어 `.gitignore`로 제외한다.

- `runs/`, `logs/`, `inventory/`의 원본 런타임 결과
- APK, DEX, 디컴파일 결과
- Frida 서버 바이너리
- API 키와 로컬 환경 파일

공유 가능한 현황은 원본 증거 대신 비식별화된
[중간 보고서](reports/PROGRESS_REPORT_2026-08-25.md)에서 확인할 수 있다.

## 검증 상태

- 자동화 단위 테스트 16개 통과
- GLM-5.1 기반 UI 계획 동작 확인
- 5단계 저위험 탐색 완료
- Codex 행동 분석과 누적 기능 인벤토리 병합 완료
- 현재까지 확인된 기능 5개, 확인된 취약점 0개
