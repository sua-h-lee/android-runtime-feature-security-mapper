# 범용 기능 흐름 추적기

[`frida_feature_trace.js`](./frida_feature_trace.js)는 특정 채팅 기능에 한정하지 않고 다음 경계를 공통 추적한다.

`사용자 행동 → Activity/Fragment → LiveData 상태 → 네트워크 요청 → 응답/Push → 후속 상태`

## 실행

```bash
frida -U -f com.kakao.talk -l frida_feature_trace.js
```

attach 방식:

```bash
frida -U -n com.kakao.talk -l frida_feature_trace.js
```

시작할 때 각 모듈의 `HOOK_OK` 또는 `HOOK_FAIL`과 마지막 `READY`가 출력된다. 일부 선택 모듈이 현재 프로세스에 없어서 실패해도 다른 모듈은 계속 동작한다.

호스트 자동화에서는 다음 RPC를 사용할 수 있다.

```text
get_common_summary()          현재 구간의 summary 반환
emit_common_summary()         현재 summary 반환 및 [COMMON] 출력
reset_common_summary(label)   앱 상태는 바꾸지 않고 새 summary 구간 시작
mark_user_action(kind,target) UIAutomator/Compose 행동을 USER_ACTION으로 표시
```

`reset_common_summary`는 한 Frida 세션에서 여러 UI 동작을 자동 수행할 때 각 동작의
근거가 섞이지 않도록 한다. Python 오케스트레이터 사용법은
[`automation/README.md`](./automation/README.md)에 있다.

## 기본 추적 범위

- UI: 클릭, 길게 누르기, 키보드 editor action
- 화면: Activity와 Fragment 생명주기
- 상태: AndroidX LiveData와 Kotlin StateFlow 변경
- LOCO: 모든 request, 동기·비동기 response, 모든 push
- HTTP: Retrofit을 포함한 OkHttp request/response/failure
- 직접 HTTP: `URL.openConnection`부터 `HttpURLConnection` 요청·응답 header와 응답 코드
- 실시간: OkHttp WebSocket 연결·송수신·종료·실패
- FCM: 메시지 metadata/data, 복호화된 content, token 갱신
- Protocol Buffers: 선택 모듈이며 기본 비활성화

Retrofit은 최종적으로 OkHttp를 사용하므로 `HTTP_*` 단계에서 관찰된다. JSON/Kotlin Serialization은 모든 객체를 전역 후킹하면 로그와 실행 부하가 매우 커지므로, 직렬화 결과가 실제 네트워크 경계에 도달했는지를 HTTP/LOCO/WebSocket payload 크기와 호출 스택으로 확인하는 방식을 기본으로 한다.

## 기능별 필터

처음에는 전체 흐름을 한 번 관찰한 뒤 `CONFIG.filters`를 좁히는 것이 좋다.

```javascript
filters: {
  locoMethods: ['WRITE', 'MSG', 'GETMSGS'],
  httpHostContains: ['kakao.com']
}
```

빈 배열은 필터를 적용하지 않는다는 뜻이다.

## 모듈 설정

불필요하거나 로그가 많은 모듈은 `CONFIG.modules`에서 끌 수 있다.

```javascript
modules: {
  ui: true,
  lifecycle: true,
  observableState: false,
  loco: true,
  okhttp: true,
  webSocket: false,
  httpUrlConnection: true,
  fcm: true,
  protobuf: false
}
```

`observableState`와 `protobuf`는 호출량이 많을 수 있다. 성능 영향이 보이면 먼저 끈다.

## 개인정보와 인증정보

공유하거나 일반 관찰에 사용할 때의 안전한 권장값은 `rawPayload: false`다. 이
상태에서는 다음 값이 마스킹된다.

- 메시지와 첨부 내용
- token, cookie, session, authorization 계열 값
- 사용자·채팅·메시지 식별자
- FCM token과 message content
- URL query 값

현재 작업 파일의 기본값은 외부 LLM 전달을 고려해 `rawPayload: false`다. 표적 검증을
위해 이 값을 `true`로 바꾼 실행의 원문 로그는 별도의 민감정보 자산으로 취급해야 한다.

`rawPayload: true`를 명시적으로 설정하면 LOCO body, URL query, WebSocket text,
LiveData/StateFlow 값뿐 아니라 OkHttp/HttpURLConnection 요청·응답 header, FCM token,
FCM data와 복호화된 content도 원문으로 기록한다. `Authorization`, `Cookie`,
`Set-Cookie` 및 유사한 사용자 정의 token header가 포함될 수 있으므로 이 로그를
채팅이나 이슈 트래커에 그대로 첨부하지 않는다.

전체 원문 모드가 필요하지 않다면 `rawPayload: false`를 유지하고
`filters.rawLocoKeys: ['msg']`처럼 검증에 필요한 LOCO 키만 선택적으로 연다.
HTTP request/response body는 one-shot 또는 streaming body를 소비해 앱 동작을 바꿀 수
있으므로 현재 범용 추적기에서 자동으로 읽지 않는다. HTTP token 관찰 범위는 URL,
요청·응답 header 및 앱 상태/직렬화 계층이다.

26.7.1 APK/JADX와의 정적 대조 결과 및 실제로 확인된 한계는
[`APK_SCRIPT_AUDIT_26.7.1.md`](./APK_SCRIPT_AUDIT_26.7.1.md)에 정리되어 있다.

## 로그 읽는 순서

1. `USER_ACTION`에서 기능 시작점을 찾는다.
2. 같은 시간대의 Activity/Fragment 및 `LIVEDATA_*`/`STATEFLOW_SET`을 확인한다.
3. `LOCO_*`, `HTTP_*`, `WEBSOCKET_*` 또는 `URL_CONNECTION_*` 요청을 찾는다.
   OkHttp에서는 interceptor가 추가한 최종 token/header를 `HTTP_WIRE_REQUEST`에서 확인한다.
4. 동일한 `trace`의 응답, 실패 또는 push를 연결한다.
5. 응답 뒤의 화면 및 LiveData 상태 변화를 비교한다.

네트워크 단계의 `stack`은 Repository, UseCase, ViewModel 또는 Presenter 후보를 찾기 위한 역추적 지점이다.

## 기존 1대1 채팅 스크립트

`frida_write_trace.js`는 `WRITE/MSG` 및 `ChatSendingLogRequest`에 맞춘 좁은 프리셋으로 그대로 유지한다. 전체 기능 탐색은 `frida_feature_trace.js`, 1대1 메시지 전송을 깊게 재검증할 때는 기존 프리셋을 사용한다.
