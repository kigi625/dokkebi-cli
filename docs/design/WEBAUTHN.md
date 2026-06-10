# WebAuthn (Passkey) 요청 서명 — 설계 및 연동 가이드

**상태**: v5.5 (opt-in, `dok init` 에서 활성화) — 런타임 SDK 구현은 후속 PR
**관련 문서**: [SECURITY.md](../../SECURITY.md) · [AUTHORIZATION.md](./AUTHORIZATION.md)

---

## 0. 왜 WebAuthn 인가

현재 도깨비는 **요청 단위 HMAC 서명**(세션 대칭키 기반) 으로 재전송·변조를 막습니다. 그러나 대칭키는 **브라우저 메모리 안에 있는 순간 탈취 가능**(XSS, 악성 확장, OS 레벨 공격). 한번 새어나가면 세션이 살아있는 동안 공격자가 정당한 사용자로 위장할 수 있습니다.

WebAuthn (= Passkey 표준) 은 다음을 제공합니다:

| 속성 | 대칭 HMAC (현재) | WebAuthn (새 레이어) |
|---|---|---|
| 키 위치 | 브라우저 메모리 | **OS/TPM/Secure Enclave** (브라우저·JS 접근 불가) |
| 키 추출 | XSS·디버거로 가능 | 물리적 공격 외엔 불가 |
| 부인 방지 | 세션 탈취 시 무력 | **가능** — 디바이스-사용자 결합 서명 |
| UX 비용 | 없음 | 민감 연산 시 지문/Face/PIN 1회 |

즉, **기본 HMAC 레이어를 대체하지 않고 그 위에 덧붙이는**, 고가치 연산 한정 "한 번 더 확인" 장치입니다.

---

## 1. 스코프 — 이 레이어가 막는 것

| 위협 | 막아줌? | 설명 |
|---|---|---|
| 세션키 탈취 후 오래된 쓰기 재생 | ✅ | 요청 서명이 디바이스 개인키와 결합되어야 함 |
| XSS 로 `document.cookie` 전체 긁어감 | ✅ | 쿠키/IndexedDB 에 WebAuthn 개인키는 **존재하지 않음** |
| 악성 확장이 JS 실행 컨텍스트 장악 | 부분 | UV(사용자 확인) 프롬프트 우회 불가 — 공격자가 **매번** 프롬프트 통과시켜야 함 |
| 피싱 사이트에서 동일 패스키 재사용 | ✅ | `rpId` 로 origin 바인딩 — 다른 도메인에선 브라우저가 서명을 거부 |
| 서버 DB 통째 탈취 → replay | ✅ | 공개키만 저장되어 있음. 서명 생성 불가 |

### 막지 못하는 것

- 디바이스 자체가 물리적으로 악성 (루팅·탈옥 후 키 추출) → 상위 OS 문제
- 사용자가 패스키를 등록하지 않은 상태 → 이 레이어가 비활성
- `userVerification: 'discouraged'` 로 설정한 경우 UV 자체를 건너뜀 → 권장 X

---

## 2. 사용자 관점 흐름

### 2-A) 신규 회원가입 흐름

```
유저 [ 비밀번호로 가입 ]
       ↓
dokkebi 백엔드 — 사용자 row 생성 (users.id = <생성된 uuid>)
       ↓
프론트 [ await dokkebi.webauthn.register({ userId, userName }) ]
       ↓
브라우저 — "이 사이트에 패스키를 저장하시겠습니까?" 프롬프트 → 지문/Face/PIN
       ↓
dokkebi → _dokkebi_webauthn_credentials 에 공개키 저장
       ↓
이후 모든 쓰기 연산에 서명 요구 (설정된 requireForOps 기준)
```

### 2-B) 로그인 흐름

```
유저 [ 비밀번호로 로그인 성공 ]
       ↓
프론트 [ await dokkebi.webauthn.authenticate({ userId }) ]
       ↓
브라우저 — "패스키로 인증하시겠습니까?" → 지문/Face/PIN
       ↓
dokkebi — chall/sig 검증 → 이 세션을 "webauthn-verified" 로 승격
       ↓
이후 쓰기 연산 자동 보호
```

### 2-C) 패스키 없는 사용자

기존 사용자가 업그레이드 전이면 WebAuthn 이 enabled 여도 **가입/로그인을 막지 않습니다**. 단:
- `requireForOps` 에 매칭되는 연산은 "패스키 등록 필요" 안내와 함께 거부.
- `dok build` 로그에 얼마나 많은 사용자가 아직 등록 안 했는지 통계 표시 (추후 기능).

---

## 3. 서버 측 데이터 모델

```sql
CREATE TABLE IF NOT EXISTS _dokkebi_webauthn_credentials (
  credential_id TEXT PRIMARY KEY,       -- 패스키 ID (base64url)
  user_id       TEXT NOT NULL,          -- 사용자 FK (애플리케이션 users 테이블)
  public_key    TEXT NOT NULL,          -- COSE 공개키 (base64url)
  counter       INTEGER NOT NULL DEFAULT 0,  -- 서명 카운터 (디바이스 복제 탐지)
  transports    TEXT,                   -- ["internal","usb","ble",...] JSON
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON _dokkebi_webauthn_credentials(user_id);

CREATE TABLE IF NOT EXISTS _dokkebi_webauthn_challenges (
  challenge     TEXT PRIMARY KEY,       -- 1회용 chall (base64url)
  user_id       TEXT,                   -- register 는 일시 null 허용
  purpose       TEXT NOT NULL,          -- 'register' | 'authenticate'
  expires_at    INTEGER NOT NULL
);
```

> 이 스키마는 `dokkebi-cli` 가 WebAuthn enabled 시 자동 마이그레이션으로 주입합니다. 프로젝트의 사용자 테이블(`users.id`) 과 `_dokkebi_webauthn_credentials.user_id` 는 **이름만 FK 관계** 이며 물리 FK 는 두지 않습니다 (여러 사용자 스키마 지원).

---

## 4. 서버 엔드포인트 (v5.5+ 자동 주입 예정)

| 경로 | 역할 | 사용 시점 |
|---|---|---|
| `POST /api/_dokkebi/webauthn/register/options` | 등록용 챌린지 생성 | `register()` 호출 초반 |
| `POST /api/_dokkebi/webauthn/register/verify` | 등록 서명 검증 + DB 저장 | `register()` 호출 후반 |
| `POST /api/_dokkebi/webauthn/authenticate/options` | 인증용 챌린지 생성 | `authenticate()` 호출 초반 |
| `POST /api/_dokkebi/webauthn/authenticate/verify` | 인증 서명 검증 + 세션 승격 | `authenticate()` 호출 후반 |

모든 서명 검증은 Cloudflare Worker 의 `crypto.subtle.verify` (ES256 기본, EdDSA 선택) 로 처리합니다.

---

## 5. 클라이언트 SDK (예정 API)

```ts
// 회원가입 직후 1회
await dokkebi.webauthn.register({
  userId:   string,        // 앱의 users.id
  userName: string,        // 표시용 이름 (이메일/닉네임)
  displayName?: string,    // 선택: 장치 선택 UI 표시용
});

// 로그인 성공 직후
await dokkebi.webauthn.authenticate({
  userId: string,
});

// 런타임 상태 조회
dokkebi.webauthn.isRegistered(userId)  // → boolean
dokkebi.webauthn.isVerified()          // 현재 세션이 WebAuthn-verified 인지
dokkebi.webauthn.unregister(credentialId) // 특정 패스키 삭제
```

호출이 실패하면 `{ ok: false, code: 'WEBAUTHN_*', error: ... }` 형태로 반환합니다 — 대칭 HMAC 과 동일한 에러 포맷.

---

## 6. Config 스키마

```js
// dokkebi.config.js
export default {
  security: {
    webauthn: {
      enabled: true,
      rpName: 'Notofly',                 // 기본: package.json name
      rpId:   undefined,                 // 기본: 현재 origin host (권장)
      userVerification: 'preferred',     // 'required' | 'preferred' | 'discouraged'
      attestation:      'none',          // 'none' (권장) | 'indirect' | 'direct'
      timeoutMs:        60_000,
      requireForOps:    ['INSERT:*','UPDATE:*','DELETE:*'],
      // requireForOps 미지정 시: 인증된 사용자의 모든 쓰기에 서명 요구
    },
  },
};
```

### requireForOps 매칭 규칙

Authorization Policy 와 동일한 `OP:table` 문법:
- `'DELETE:posts'` — posts 테이블 DELETE 만
- `'UPDATE:*'` — 모든 테이블 UPDATE
- `'INSERT:orders'` — orders INSERT 만

매칭되지 않는 연산은 WebAuthn 서명 요구 없이 기존 HMAC 만으로 처리. **SELECT 는 기본 요구 X** — 사용자 UX 를 해치지 않는 전략.

---

## 7. 연동 배선 예시

### 7-A) React + 이메일 회원가입

```tsx
async function handleSignup(e) {
  e.preventDefault();
  const { ok, userId } = await auth.signup({ email, password });
  if (!ok) return alert('가입 실패');

  // 비밀번호 가입은 성공. 이제 패스키 등록 프롬프트.
  try {
    await dokkebi.webauthn.register({ userId, userName: email });
    toast.success('패스키 등록 완료 — 다음 로그인부터 더 안전합니다.');
  } catch (err) {
    // 사용자가 패스키 프롬프트를 거부해도 가입은 유지.
    console.warn('WebAuthn 등록 건너뜀:', err.message);
  }
}
```

### 7-B) 로그인

```tsx
async function handleLogin(e) {
  e.preventDefault();
  const { ok, userId } = await auth.login({ email, password });
  if (!ok) return alert('로그인 실패');

  try {
    await dokkebi.webauthn.authenticate({ userId });
  } catch (err) {
    if (err.code === 'WEBAUTHN_NO_CREDENTIAL') {
      // 이 사용자는 아직 패스키 등록 안 함 — 새로 등록 유도 (UI 에서)
      return showPasskeySuggestion(userId, email);
    }
    // UV 거부 등은 그대로 두면 이후 쓰기 연산에서 거부됨.
  }
}
```

### 7-C) notofly 스타일 — JWT 없고 `creator_token` 기반

```tsx
// "가입/로그인" 개념이 없는 사이트라도
// 최초 식별 시점에 register/authenticate 를 묶어 호출 가능.
const creatorToken = getOrCreateCreatorToken();   // localStorage
if (!(await dokkebi.webauthn.isRegistered(creatorToken))) {
  await dokkebi.webauthn.register({
    userId: creatorToken,
    userName: '익명 작성자 ' + creatorToken.slice(0, 6),
  });
} else {
  await dokkebi.webauthn.authenticate({ userId: creatorToken });
}
```

이렇게 하면 "로그인이 없는 사이트" 에서도 디바이스-사용자 결합 서명을 확보할 수 있습니다.

---

## 8. 결정 기록

| # | 결정 | 이유 |
|---|---|---|
| 1 | opt-in 기본값 | 회원가입/로그인 흐름 수정이 필수 → 기본 ON 은 기존 프로젝트를 깨뜨림 |
| 2 | `dok init` 에서만 활성 제안 | 중도 도입은 사용자 수동 config 편집으로 처리 (가이드 링크 제공) |
| 3 | `attestation: 'none'` 기본 | 대부분의 SaaS 는 디바이스 증명이 불필요. privacy 상 우월 |
| 4 | `requireForOps` 기본 null | 기본은 "인증된 모든 쓰기" — 너무 공격적일 경우 사용자가 좁힘 |
| 5 | HMAC 레이어와 공존 | 대체 X, 덧붙이기 O. WebAuthn 미등록 사용자도 기본 경로 가능 |
| 6 | 서버 검증은 Worker 내장 WebCrypto 만 사용 | 외부 라이브러리 의존성 추가 없음 |

---

## 9. 로드맵

- **v5.5** — config schema, `dok init` 프롬프트, `dok build` 배너, 이 문서 (현재)
- **v5.6** — 서버 엔드포인트 4개 + `_dokkebi_webauthn_*` 테이블 auto-migration
- **v5.7** — 클라이언트 `dokkebi.webauthn.*` SDK + React/Vue 예제
- **v5.8** — `requireForOps` 런타임 강제 + 보안 대시보드 통계

---

## 10. FAQ

**Q. 패스키 손실 시?**
→ 비밀번호 기반 복구 경로는 반드시 유지. WebAuthn 은 **보조 레이어** 이지 단일 실패점이 아닙니다.

**Q. 여러 기기에서 쓰고 싶은데?**
→ 한 사용자가 여러 credential_id 를 등록 가능. `register()` 를 각 기기에서 한 번씩 호출.

**Q. Cloudflare Worker 에서 서명 검증이 되나?**
→ WebCrypto API (`crypto.subtle.verify`) 가 ES256·EdDSA 를 지원 — 별도 lib 불필요.

**Q. Safari 에서도 되나?**
→ Safari 16+, Chrome 108+, Firefox 122+ 에서 Passkey 동기화 포함 완전 지원.

**Q. 기존에 HMAC 만 쓰던 사이트에 영향은?**
→ `webauthn.enabled: false` (기본) 면 코드·런타임 모두 아무 변화 없음.
