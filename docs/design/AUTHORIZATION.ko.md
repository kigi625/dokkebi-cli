# Authorization Policy (Stage 4)

> **대상 문제**: 브라우저(WASM) 안의 `if (user.role === 'admin')` 체크는 신뢰할 수 없다.
> 공격자는 번들을 패치하거나 디버거로 메모리를 조작해 "관리자" 가 될 수 있다.
> 서버(DB 프록시) 레이어에서 **JWT 서명 + role 클레임** 을 검증해 "누구나 관리자" 문제를 차단한다.

## TL;DR

```js
// dokkebi.config.js
export default {
  authorization: {
    // mode:
    //   'warn'   (기본) — 규칙이 정의된 연산만 검증, 미정의 연산은 통과 + 빌드 로그 경고
    //   'strict'        — 미정의 연산은 모두 거부 (fail-closed)
    mode: 'warn',

    // 환경변수 이름. Cloudflare Pages Secret 으로 설정
    //   wrangler pages secret put DOKKEBI_JWT_SECRET --project=xxx
    jwtSecretEnv: 'DOKKEBI_JWT_SECRET',

    // JWT payload 에서 role 을 꺼낼 필드 (기본: 'role')
    claim: 'role',

    // 선택: 발급자/청중 검증
    issuer: 'my-app',
    audience: 'web',
    clockSkewSec: 30,

    // 규칙: "OP:table" → 스펙
    rules: {
      'SELECT:posts':  { public: true },
      'INSERT:posts':  { auth: true },
      'UPDATE:posts':  { roles: ['admin', 'author'] },
      'DELETE:posts':  { roles: ['admin'] },
      'DELETE:users':  { deny: true },         // 명시적 차단
      '*':             { auth: true },          // 디폴트: 로그인 필수
    },
  },
};
```

프로덕션 체크리스트:
- [ ] Cloudflare Pages 에 `DOKKEBI_JWT_SECRET` secret 설정
- [ ] `'*'` 디폴트 규칙 정의 (또는 `mode: 'strict'`)
- [ ] JWT 발급 엔드포인트 직접 구현 (`functions/api/auth/login.ts`)
- [ ] 클라이언트에서 `Authorization: Bearer <jwt>` 헤더 또는 `_jwt` payload 필드로 전송

---

## 1. 왜 필요한가

dokkebi 의 기존 보안 스택:

| 레이어 | 역할 | 커버리지 |
|---|---|---|
| 공통 SQL 검증 | stacked query, 위험 토큰 차단 | 전방위 |
| SQL Allowlist (Stage 0) | 테이블 x 연산 단위 허가 | 전방위 |
| Query Registry (Stage 3) | SQL shape 단위 허가 | 전방위 |
| Tenant Policy (Stage 1/2) | **row-level 격리** (유저 A 는 유저 B 데이터 안 보임) | opt-in |
| **Authorization (Stage 4)** ← 신규 | **연산-레벨 권한** ("DELETE 는 admin 만") | opt-in |

Tenant Policy 는 "같은 tenant 내 격리" 를 처리하지만, **"이 tenant 안에서 누가 DELETE 를 할 수 있는가"** 는 다룬 적이 없었다. 이게 이번에 추가되는 것.

## 2. 아키텍처

```
Client (Browser WASM)
  │
  │  headers:
  │    Authorization: Bearer <jwt>   ← 표준
  │    (또는 payload._jwt)           ← 암호화 채널 내부 (네트워크 탭에서 JWT 조차 안 보임)
  ▼
POST /api/_dokkebi/db
  │
  ├─ 세션/서명/복호화                             (기존)
  ├─ SQL 검증 + Allowlist                         (기존)
  ├─ Query Registry                               (기존)
  ├─ Tenant Policy verify/inject                  (기존, opt-in)
  │     → SQL 에 user_id = ? 주입
  ├─ [NEW] Authorization                          (신규, opt-in)
  │     1. 최종 SQL 에서 (op, table) 추출
  │     2. rules 에서 매칭되는 규칙 찾기
  │     3. 필요 시 Authorization 헤더/payload._jwt 추출
  │     4. HS256 서명 검증 + exp/nbf/iss/aud 체크
  │     5. role 클레임 매칭
  │     6. 실패 → 401/403
  └─ D1.prepare().bind()
```

주의:
- **Tenant Policy 이후에 Authorization** 이 돈다 → Tenant Policy 가 주입한 최종 SQL 기준으로 op/table 이 판단됨
- 한 번의 요청은 한 개의 SQL 문장이므로 가장 상위 op/table 로 충분 (stacked query 는 이미 1단계에서 차단됨)
- 규칙 매칭 실패 시에만 JWT 검증 건너뜀 (불필요한 비용 절감)

## 3. 규칙 문법

키 형식:

```
"OP:table"     // 가장 구체적 — 예: "DELETE:posts"
"OP:*"         // 연산 와일드카드 — 예: "DELETE:*"  (모든 테이블의 DELETE)
"*:table"      // 테이블 와일드카드 — 예: "*:users" (users 에 대한 모든 연산)
"*"            // 디폴트 — 매칭되지 않는 모든 요청
```

유효한 OP: `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `*`

우선순위:
1. OP 특정 + 테이블 특정 (최우선)
2. OP 특정 + 테이블 `*`, 또는 OP `*` + 테이블 특정 (동순위)
3. 디폴트 `*`

같은 우선순위에서는 config 선언 순서 무관 (매치하는 것 중 하나가 선택됨 — 동순위 규칙은 의도 충돌이므로 피하세요).

값 스펙:

| 스펙 | 의미 |
|---|---|
| `{ public: true }` | 인증 불필요. JWT 없어도 허용. |
| `{ auth: true }` | 유효한 JWT 필수. role 체크 없음. |
| `{ roles: ['a', 'b'] }` | 유효한 JWT + `payload.role` 이 `a` 또는 `b` 여야 함. `auth: true` 암시적 포함. |
| `{ deny: true }` | 무조건 거부. role 과 무관하게 차단. |

## 4. JWT 요구사항

- **알고리즘**: HS256 만 지원
- **필수 클레임**: `exp` (권장). `role` (혹은 `claim` 에 지정된 필드)
- **선택 클레임**: `nbf`, `iss`, `aud`
- **secret**: `DOKKEBI_JWT_SECRET` Pages 환경변수 (최소 32 bytes 랜덤 권장)

> **⚠ 보안(C-1): 브라우저에서 JWT 를 서명하지 마라.** `DOKKEBI_JWT_SECRET` 는 대칭(HS256) 키 — **워커 전용 시크릿**이며 더 이상 핸드셰이크로 클라이언트에 전달되지 않는다. 브라우저 WASM 백엔드는 이 값을 읽을 수 없다(`__dokkebi_env__("JWT_SECRET")` → 빈 문자열). 토큰은 신뢰된 서버 경로에서만 발급해야 한다. 두 가지 방법:
>
> 1. **내장 워커측 로그인(권장)** — `dokkebi.config.js` 의 `auth.login` 설정. 프록시가 DB 로 자격증명을 검증하고 JWT 를 직접 서명한다. 클라이언트는 `window.__DOKKEBI_LOGIN__({ identifier, password })` 로 호출. §4.1 참고.
> 2. **직접 만든 Pages Function**(`functions/api/auth/login.ts`)에서 `env.DOKKEBI_JWT_SECRET` 로 서명 — 아래 예제.

### 4.1 내장 워커측 로그인 (`auth.login`)

```js
// dokkebi.config.js
export default {
  auth: {
    login: {
      enabled: true,
      query: 'SELECT id, role, password_hash FROM users WHERE email = ?1', // 바인딩 1개(?1)=식별자
      passwordColumn: 'password_hash',
      hash: 'pbkdf2',                 // 'pbkdf2'(기본) | 'plain'(개발용)
      claims: { user_id: 'id', role: 'role' },  // JWT 클레임 ← DB 컬럼
      issuer: 'my-app', audience: 'web', expiresInSec: 3600,
      bindTenant: true,              // 클레임을 세션 tenant_json 에도 기록
    },
  },
};
```

`hash: 'pbkdf2'` 저장 형식: `pbkdf2$<iterations>$<saltB64url>$<hashB64url>` (PBKDF2-SHA256). 비밀번호 비교는 상수시간. 예약(`_` 접두) 클레임명은 무시된다. `DOKKEBI_JWT_SECRET` 는 Pages 시크릿으로 설정(워커측에서만 사용).

```js
const { ok, value } = await window.__DOKKEBI_LOGIN__({ identifier: email, password });
if (ok) { /* value.token = 서명된 JWT, value.claims = 매핑된 클레임 */ }
```

### 발급 예제 (사용자가 직접 구현)

```ts
// functions/api/auth/login.ts
import type { PagesFunction } from '@cloudflare/workers-types';

interface Env { DOKKEBI_JWT_SECRET: string; DB: D1Database; }

export const onRequest: PagesFunction<Env> = async ({ request, env }) => {
  const { email, password } = await request.json();

  // 1. DB 에서 사용자 조회 + 패스워드 검증 (bcrypt 등)
  const row = await env.DB.prepare(
    `SELECT id, role, password_hash FROM users WHERE email = ?`
  ).bind(email).first();
  if (!row || !(await verifyPassword(password, row.password_hash as string))) {
    return new Response('Invalid credentials', { status: 401 });
  }

  // 2. JWT 발급
  const token = await signJwtHs256({
    sub: row.id,
    role: row.role,
    iss: 'my-app',
    aud: 'web',
    exp: Math.floor(Date.now() / 1000) + 3600,
  }, env.DOKKEBI_JWT_SECRET);

  return new Response(JSON.stringify({ token }), {
    headers: { 'Content-Type': 'application/json' },
  });
};

async function signJwtHs256(payload: any, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const enc = (o: any) => btoa(JSON.stringify(o))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const data = `${enc(header)}.${enc(payload)}`;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${data}.${sigB64}`;
}
```

### 클라이언트 전송 방법

**방법 1 — 표준 Authorization 헤더 (권장)**

```js
// 앱의 fetch wrapper 에서
fetch('/api/_dokkebi/db', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${jwt}`,  // ← dokkebi 프록시가 자동 추출
  },
  body: /* 암호화된 payload */,
});
```

**방법 2 — payload._jwt (네트워크 탭에 JWT 숨김)**

암호화 payload 안에 `_jwt` 필드를 포함시키면, 네트워크 탭/DevTools 의 요청 헤더에서 JWT 가 관찰되지 않음. dokkebi 의 AES-GCM 채널 안에 JWT 가 들어가므로 추가 방어 깊이.

```js
// WASM 내부 (dokkebi-runtime)
db.query(sql, params, { jwt: getSessionJwt() });
// ↓ 내부적으로 payload 에 _jwt 포함 → AES-GCM 암호화 → 전송
```

> 구현 팁: dokkebi-runtime 의 `db.query()` 에 `{ jwt }` 옵션을 추가하면 자동으로 payload 에 포함시킬 수 있습니다. 기본 템플릿에는 포함되지 않으니 사용자 정의 wrapper 로 구현하세요.

## 5. 응답 코드

| HTTP | code | 발생 조건 |
|---|---|---|
| 401 | `AUTH_REQUIRED` | 규칙이 `auth` 또는 `roles` 요구, JWT 가 없거나 무효 |
| 403 | `ROLE_MISSING` | JWT 유효하지만 `claim` 필드가 payload 에 없음 |
| 403 | `ROLE_FORBIDDEN` | role 은 있지만 허용 리스트에 없음 |
| 403 | `RULE_DENY` | `deny: true` 규칙에 매칭 |
| 403 | `NO_RULE` | strict 모드에서 매칭 규칙 없음 |
| 403 | `SPEC_INVALID` | 규칙 스펙 형식 오류 (설정 문제) |

응답 body:

```json
{ "ok": false, "error": "필요한 role: [admin], 현재: user", "code": "ROLE_FORBIDDEN" }
```

모든 거부 이벤트는 `_dokkebi_security` 테이블에 `type='authz_denied'` 로 기록됨.

## 6. Tenant Policy 와의 관계

두 정책은 **상호 보완적**입니다:

| 예시 시나리오 | Tenant Policy 역할 | Authorization 역할 |
|---|---|---|
| 유저 A 가 유저 B 의 게시글을 보면 안 됨 | `SELECT posts WHERE user_id = ?` 주입 | (불필요) |
| 관리자가 아니면 게시글 삭제 불가 | (불필요 — tenant 와 무관) | `DELETE:posts` → `roles: ['admin']` |
| 유저는 자기 글만 삭제, 관리자는 아무나 삭제 가능 | `DELETE posts WHERE user_id = ?` 주입 | `DELETE:posts` → `{ auth: true }` (본인이 자기 데이터 지우는 건 tenant 격리로 충분) |

**안전 패턴**: 두 레이어를 함께 켜면 "관리자만 삭제" + "관리자 아니면 자기 tenant 만" 양쪽을 모두 방어.

## 7. 구현 한계

- **HS256 만 지원**: RS256/ES256 같은 비대칭 서명은 현재 미지원. 외부 ID 프로바이더(Auth0 등) 와 연동하려면 Pages Function 에서 JWT 를 한 번 자체 발급으로 재포장 필요.
- **row-level 인가 불가**: "본인 글만 수정" 같은 규칙은 SQL 의 `user_id = ?` 조건에 의존해야 하며 Tenant Policy 의 역할.
- **SELECT 에 대한 필드 수준 제한 없음**: "관리자만 password_hash 컬럼 조회 가능" 같은 column-level 제어는 미지원. 필요하면 뷰나 쿼리 분할로 해결.
- **워커 인라인 코드 사이즈**: v8 템플릿은 약 350줄 증가. Cloudflare Workers 의 1MB 스크립트 한도 내에서는 무시 가능.

## 8. 마이그레이션 가이드

### 새 프로젝트

1. `dok create` 로 새 프로젝트 생성 (v8 템플릿 자동 포함)
2. `dokkebi.config.js` 에 `authorization` 섹션 추가
3. `DOKKEBI_JWT_SECRET` env 설정
4. 로그인 엔드포인트 구현

### 기존 프로젝트 (v7 이하)

```bash
# 1. 워커 템플릿 업데이트
dok update

# 2. 마이그레이션 확인 후 Y
# 3. config 에 authorization 섹션 추가
# 4. dok build
# 5. dok deploy
```

기존 프로젝트는 `authorization` 섹션이 없으면 **off** 상태로 동작 → 기존 동작과 동일. 활성화 전까지 영향 없음.

## 9. 관련 문서

- [SECURITY.md](../../SECURITY.md) — 전체 보안 아키텍처
- [TENANT_POLICY.md](./TENANT_POLICY.md) — Row-level 격리
- [QUERY_REGISTRY.md](./QUERY_REGISTRY.md) — SQL shape 통제
