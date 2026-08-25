# 카카오톡 런타임 자동 탐색기

`automation`은 다음 다섯 부분을 묶는다.

- UIAutomator/ADB: 현재 화면 구조, 스크린샷, 클릭과 스크롤
- Frida 관리자: 앱 spawn, `READY` 대기, 행동별 summary reset/저장
- GLM 판단기: 다음 저위험 UI 행동만 선택
- Codex 분석기: 저장된 정상 동작 분석과 기능 인벤토리 통합
- 위험 정책: 삭제·차단·전송·통화·결제 같은 외부 효과를 기본 차단

GLM 설정이 없으면 리소스 ID와 접근성 텍스트를 이용한 결정적 휴리스틱으로
동작한다. 정책 판단은 GLM보다 우선하며 GLM은 차단을 우회할 수 없다.

## 1. 사전 점검

프로젝트 루트에서 실행한다.

```bash
./venv/bin/python -m automation doctor
```

ADB, Frida Python 패키지, 대상 스크립트, 정책 파일, Codex CLI 설치와 ChatGPT
로그인이 모두 정상이면 마지막 `ok`가 `true`다. `--glm`을 붙이면 GLM도 실제
짧은 요청으로 확인한다.

## 2. 저위험 자동 탐색

처음에는 작은 budget으로 확인한다.

```bash
./venv/bin/python -m automation explore --max-steps 5
```

기본 `max_auto_risk`는 `safe`다. 상태를 바꾸는 동작은 실행되지 않고 해당
run의 `blocked-actions.json`에 `NOT_EXECUTED_REQUIRES_APPROVAL`로 저장된다.

결과는 `runs/YYYYMMDD-HHMMSS-auto-explore/`에 저장된다. 실행된 각 동작은
별도 `step-NNN-*` 디렉터리를 가진다.

```text
step-001-*/
  before.xml / before.png / before.json
  decision.json
  policy.json
  trace.log
  common.json
  after.xml / after.png / after.json
  observation.json
  metadata.json
  analysis.json  # 탐색 종료 후 Codex가 생성
```

Frida는 탐색 시작 시 한 번 spawn된다. 각 UI 동작 직전에
`reset_common_summary(label)`을 호출하므로 `common.json`은 다른 동작과 섞이지
않는다. 탐색 종료 시 앱을 force-stop한 뒤 Codex가 여러 step을 묶어 분석한다.

Codex 분석 결과는 두 수준으로 저장된다.

```text
runs/<run>/step-*/analysis.json       # 행동 하나의 정상 동작/보안 관찰
runs/<run>/feature-inventory.json     # 해당 run까지 통합된 인벤토리 사본
inventory/feature-inventory.json      # 여러 run을 누적 통합한 전역 인벤토리
```

## 3. GLM 사용

이 클라이언트는 OpenAI-compatible `POST /chat/completions` 형식의 endpoint를
사용한다. 기본 설정은 Z.AI 일반 API(`https://api.z.ai/api/paas/v4`)와 텍스트
모델 `glm-5.1`이다. Z.AI에서 발급한 일반 API 키만 환경변수로 넣으면 된다.

```bash
export GLM_API_KEY='...'

./venv/bin/python -m automation explore --glm --max-steps 10
```

다른 OpenAI-compatible GLM 서비스나 모델을 사용할 때만 기본값을 덮어쓴다.

```bash
export GLM_BASE_URL='https://YOUR-GLM-ENDPOINT/v1'
export GLM_MODEL='YOUR-GLM-MODEL'
```

`doctor --glm`은 짧은 실제 API 요청으로 키·endpoint·모델·사용 가능 잔액까지
확인한다. 이 확인에는 소량의 API 사용량이 발생한다. `--glm`을 명시했는데
설정이나 실제 호출에 실패하면 휴리스틱으로 조용히 대체하지 않고 오류로 종료한다.
GLM은 `GLM deciding next action...` 단계에서 UI 행동 하나만 고른다. 정상 동작과
보안 우선순위 분석에는 GLM을 호출하지 않는다.

`--glm`을 사용하면 접근성 트리에 노출된 UI 텍스트가 Z.AI endpoint로 전송될 수
있다. 반드시 테스트 계정과 테스트 데이터를 사용한다.

이 구성은 `glm-5.1`만 사용하므로 스크린샷 입력을 지원하지 않는다. `--vision`을
주면 API 호출 전에 오류로 중단된다. GLM에는 UIAutomator가 추출한 UI 텍스트와
control 정보만 전달된다.

## 4. Codex 정상 동작 분석과 인벤토리 통합

Codex 분석은 로컬에 로그인된 Codex CLI를 비대화형으로 호출한다. 별도 OpenAI API
키를 설정하지 않는다. 실행은 `--ephemeral`, `--sandbox read-only`, JSON Schema
제약으로 이루어지며 Codex는 파일을 수정하지 않고 프로그램이 검증된 JSON만 저장한다.

기본적으로 탐색 직후 자동 실행된다.

```text
[AUTO] Codex analyzing 2 step(s), batch 1...
[AUTO] Codex batch 1 analysis received
```

Codex는 다음을 수행한다.

- 각 step의 정상 UI 흐름, 상태 변화, 프로토콜과 외부 목적지 정리
- 관찰과 추론 분리
- 보안 우선순위, 미확인 사항, 후속 검사 제안
- 기존 기능과 동일한 관찰은 같은 `feature_id`로 병합
- 새 기능만 `F_UPPER_SNAKE_CASE` ID로 추가
- 기존 run의 evidence와 기능 항목 보존

탐색과 분석을 분리하려면:

```bash
./venv/bin/python -m automation explore --glm --max-steps 10 --no-codex-analysis
./venv/bin/python -m automation analyze
```

`analyze`는 가장 최근 run을 사용한다. 특정 run 또는 재분석도 가능하다.

```bash
./venv/bin/python -m automation analyze runs/20260825-173313-auto-explore
./venv/bin/python -m automation analyze runs/20260825-173313-auto-explore --force
```

Codex에는 원본 `common.json`을 통째로 보내지 않는다. evidence reference fan-out,
중복 상태 변화와 UI control을 압축한 `codex-input-NNN.json`을 생성해 전달한다.
스크린샷과 raw payload는 Codex 분석 입력에 포함하지 않는다.

## 5. 테스트 입력 fixture

오케스트레이터는 GLM이 임의의 입력 값을 만들도록 허용하지 않는다. 입력은
`config.json`의 selector와 환경변수로 등록해야 한다.

```bash
export KAKAO_TEST_MESSAGE='자동화 테스트 메시지'
```

fixture가 없는 입력창과 password 입력창은 자동 입력하지 않는다. 메시지를 실제로
보내는 버튼은 별도의 `external_effect` 정책에 의해 계속 차단된다.

## 6. 위험 행동 승인

차단 목록을 검토한 뒤 승인된 테스트 계정에서만 risk ceiling을 올린다.

```bash
./venv/bin/python -m automation explore \
  --max-auto-risk state_change \
  --max-steps 5
```

등급 순서는 다음과 같다.

```text
safe < unknown < state_change < external_effect < critical
```

`external_effect`는 메시지 전송·통화·공유처럼 다른 사용자나 서비스에 영향을 줄
수 있다. `critical`은 결제·송금·계정 삭제 후보이므로 무인 실행을 권장하지 않는다.

## 한계

- UIAutomator에 노출되지 않는 WebView, Canvas, 일부 Compose control은 후보에서 빠질 수 있다.
- 자동 탐색은 정상 화면 전환을 수집한다. 서버 권한 검증 여부는 별도의 표적 테스트가 필요하다.
- background push, 재연결, 외부 앱 왕복은 일반 crawl과 분리된 시나리오가 필요하다.
- Codex 분석도 추론이며 evidence reference가 있는 Frida 관찰과 구분해서 해석해야 한다.
- 인벤토리는 관찰된 정상 흐름을 통합한다. 패킷 변조·재전송이나 서버 권한 검증은 별도의 승인된 표적 테스트가 필요하다.
