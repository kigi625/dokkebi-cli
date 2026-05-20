# 도깨비 프레임워크 — AI/Agent 바이브코딩 가이드

> **이 문서는 AI 코딩 에이전트(Cursor, Claude Code, Copilot 등)가 도깨비 프레임워크
> 기반 프로젝트를 작업할 때 반드시 참고해야 하는 핵심 운영 매뉴얼입니다.**
> 이 문서를 읽지 않으면 보안 취약점을 만들거나 빌드 오류를 유발할 수 있습니다.

---

## 0. 가장 먼저 알아야 할 것 (TL;DR)

### 도깨비 프레임워크의 정체

```
"Serverless Client Backend Framework"
브라우저 안의 QuickJS WASM 에서 백엔드 코드가 실행되고,
서버는 신뢰 검증 + DB 프록시 역할만 한다.
```

| 영역 | 실행 위치 | 역할 |
|---|---|---|
| 프론트엔드 | 브라우저 | UI |
| **백엔드 비즈니스 로직** | **브라우저 내 QuickJS WASM** | 컨트롤러, 비즈니스 규칙 |
| 신뢰 경계 (미들웨어) | Cloudflare Pages Functions 또는 `dok serve` | 인증/인가, 쿼리 검증 |
| DB 프록시 | 위와 같음 | D1 / Supabase / Appwrite 호출 |
| 데이터베이스 | Cloudflare D1 / Supabase / Appwrite | 실제 데이터 저장 |

### 두 가지 배포 모드

```js
// dokkebi.config.js
proxyMode: 'serverless',  // Cloudflare Pages Functions 에 미들웨어 배포 (기본)
proxyMode: 'server',      // 자체 Node.js 서버 (dok serve)
```

### 절대 잊지 말 것

> **클라이언트 WASM 의 비즈니스 로직은 신뢰할 수 없다.**
> 메모리 해킹/리버싱으로 어떤 변조든 가능하다.
> **실질적인 보안은 서버 사이드 미들웨어** (`worker/api/_dokkebi/db.ts`)
> 가 담당한다. 모든 권한/테넌트 검증은 거기서 강제된다.

---

## 1. 프로젝트 구조

도깨비 프로젝트는 `dok create` 로 생성되며, 다음 구조를 갖는다:

```
my-app/
├── dokkebi.config.js     ← 프레임워크 설정 (보안, DB, 배포)
├── .env                  ← 자격증명 (gitignore 필수)
├── package.json
├── wrangler.toml         ← Cloudflare Pages 설정 (serverless 모드)
│
├── backend/              ← 브라우저 내 QuickJS WASM 에서 실행
│   ├── controllers/      ← 라우트 핸들러 (router.METHOD)
│   │   └── index.ts      ← 진입점
│   └── models/           ← 테이블 DSL 정의 (dokkebi-dsl)
│       └── index.ts
│
├── frontend/             ← 일반 SPA (Vue/React/Vanilla)
│   └── src/
│
├── worker/               ← serverless 모드 — Pages Functions 소스 (TS)
│   ├── _middleware.ts
│   └── api/
│       └── _dokkebi/     ← 프레임워크 자동 생성. 직접 수정 금지.
│           ├── handshake.ts
│           ├── db.ts
│           └── log.ts
│
├── functions/            ← worker/ → esbuild 컴파일 결과 (자동)
│
└── dist/                 ← 빌드 산출물 (자동)
    └── dokkebi/          ← WASM 번들, allowlist, registry 등
```

**중요**:

- `worker/api/_dokkebi/*.ts` 파일은 `dok build` 가 자동 생성한다. **직접 수정 금지**.
- `functions/` 폴더는 `worker/` 의 컴파일 결과로 자동 생성된다.
- 사용자 정의 API 라우트는 `worker/api/` 의 `_dokkebi` 가 아닌 다른 경로에 추가하거나,
  주로 `backend/controllers/` 의 `router.METHOD` 핸들러로 작성한다.

---

## 2. 백엔드 작성법 (가장 중요)

도깨비 백엔드는 **`backend/controllers/` 와 `backend/models/`** 두 디렉토리로 구성된다.

### 2.1 모델 정의 (`backend/models/`)

`dokkebi-dsl` 의 `table()` / `col()` / `t.xxx()` 로 테이블을 선언한다.

```typescript
// backend/models/index.ts
import { table, col, t } from 'dokkebi-dsl';

// 일반 테이블 — convention 추론에 의존 (user_id 자동 감지)
export const posts = table('posts', {
  id:        col('id',          t.uuid().primaryKey().default('random')),
  userId:    col('user_id',     t.text().notNull()),
  title:     col('title',       t.text().notNull()),
  content:   col('content',     t.text()),
  createdAt: col('created_at',  t.timestamp().default('now')),
});

// 보안이 critical 한 테이블 — DSL 옵션으로 권한/테넌트 명시
export const premiumContents = table('premium_contents', {
  id:      col('id',      t.uuid().primaryKey()),
  content: col('content', t.text()),
  userId:  col('user_id', t.text()),
}, {
  // 테넌트 격리: SQL 에 user_id 조건 자동 주입 (Tenant Policy)
  tenant: 'user_id',
  // 또는 상세: tenant: { column: 'user_id', claim: 'user_id', mode: 'enforce' }

  // 권한 규칙: dok build 가 Authorization Policy 로 자동 변환
  access: {
    read:  { roles: ['premium', 'admin'] },  // SELECT
    write: { roles: ['admin'] },             // INSERT, UPDATE
    delete: { deny: true },                  // DELETE 차단
  },
});

// 공개 데이터
export const blog = table('blog', {
  id:    col('id',    t.uuid().primaryKey()),
  title: col('title', t.text()),
}, {
  access: {
    read:  { public: true },   // 누구나 읽기 가능
    write: { roles: ['admin'] },
  },
});
```

#### `t.xxx()` 타입 빌더

```typescript
t.text()      // TEXT
t.integer()   // INTEGER
t.real()      // REAL
t.boolean()   // INTEGER (0/1)
t.uuid()      // TEXT — primaryKey().default('random') 와 함께 사용
t.timestamp() // TEXT — default('now') 로 CURRENT_TIMESTAMP
t.json()      // TEXT (JSON 직렬화)
t.enum(['a','b','c']) // CHECK 제약
t.serial()    // 자동 증가 PK

// 메서드 체이닝
.notNull()
.primaryKey()
.unique()
.default('random' | 'now' | 값)
.references('table', 'column')
```

#### `table()` 의 세 번째 인자 (보안 옵션)

```typescript
table(name, columns, {
  tenant: 'col_name'                     // 간단형
    | { column, claim?, mode?: 'enforce' | 'none' }  // 상세형
    | false,                             // 명시적 공개 테이블

  access: {
    read?:   { public:true | auth:true | roles:[...] | deny:true },
    write?:  { ... },                    // INSERT + UPDATE
    delete?: { ... },
    create?: { ... },                    // CREATE TABLE
    all?:    { ... },                    // 위에 없는 op 의 폴백
  },
})
```

### 2.2 컨트롤러 작성 (`backend/controllers/`)

`router` + `db` 를 `dokkebi:runtime` 에서 import 한다.

```typescript
// backend/controllers/posts.controller.ts
import { router, db } from 'dokkebi:runtime';
import { posts } from '../models/index.js';
import { eq, and, gt } from 'dokkebi-dsl';

// GET /api/posts
router.get('/api/posts', async (req) => {
  const { rows } = await db
    .select(posts)
    .where(eq(posts.userId, req.session.userId))
    .orderBy(posts.createdAt, 'desc')
    .limit(20)
    .exec();
  return { ok: true, posts: rows };
});

// POST /api/posts
router.post('/api/posts', async (req) => {
  const body = req.json;
  await db
    .insert(posts, {
      userId: req.session.userId,
      title:  body.title,
      content: body.content,
    })
    .exec();
  return { ok: true };
});
```

#### `router` API

```typescript
router.get(path, handler)
router.post(path, handler)
router.put(path, handler)
router.patch(path, handler)
router.delete(path, handler)
```

`handler(req)` 는 다음 객체를 받는다:

```typescript
req: {
  url: string,
  method: string,
  json: any,           // POST/PUT body (JSON 자동 파싱)
  query: object,       // ?a=1&b=2
  params: object,      // /api/users/:id 의 :id
  headers: object,
  session: object,     // 세션 클레임 (테넌트 ID 등)
}
```

handler 는 객체를 반환하면 자동으로 JSON 응답이 된다.

#### `db` DSL

```typescript
// SELECT
const { rows } = await db
  .select(table)                                    // 전체 컬럼
  .select(table, ['id', 'name'])                    // 특정 컬럼만
  .where(eq(table.col, value))                      // 단일 조건
  .where(and(eq(...), gt(...)))                     // 복합
  .orderBy(table.col, 'asc' | 'desc')
  .limit(N)
  .offset(N)
  .exec();

// INSERT
await db.insert(table, { col1: v1, col2: v2 }).exec();

// UPDATE
await db
  .update(table, { col: newValue })
  .where(eq(table.id, id))
  .exec();

// DELETE
await db
  .delete(table)
  .where(eq(table.id, id))
  .exec();

// 표현식 (where 절용)
eq(col, v), neq(col, v), gt(col, v), gte, lt, lte
like(col, pattern), isNull(col), isNotNull(col)
inList(col, [v1, v2])
and(...exprs), or(...exprs), not(expr)
```

### 2.3 컨트롤러에서 권한 표현이 필요한 경우 (JSDoc 어노테이션)

DSL 모델에 `access` 옵션을 둘 수 없거나 (서드파티 모델 등), **컨트롤러 단에서**
권한을 명시하고 싶을 때 사용한다. **`dok build` 가 정적 추출**해 Authorization
Policy 로 변환한다.

```typescript
/**
 * 유료 컨텐츠 라우트.
 *
 * @dokkebi-policy table:premium_contents access:read  roles:['premium','admin']
 * @dokkebi-policy table:premium_contents access:write roles:['admin']
 * @dokkebi-policy table:public_blog      access:read  public:true
 * @dokkebi-tenant table:notes column:user_id
 */
router.get('/api/premium/contents', async (req) => {
  // ...
});
```

#### 어노테이션 문법

```
@dokkebi-policy  table:NAME  access:VERB  [SPEC]

VERB:  read | write | delete | create | all
SPEC:  public:true | auth:true | roles:['r1','r2'] | deny:true

@dokkebi-tenant  table:NAME  column:COL  [claim:CLAIM]  [mode:enforce|none]
```

#### 우선순위 (낮음 → 높음)

1. Convention 추론 (테이블 이름/컬럼 휴리스틱)
2. DSL `table(...)` 옵션 (모델 정의)
3. **JSDoc `@dokkebi-policy` / `@dokkebi-tenant`** (컨트롤러 명시)
4. **`dokkebi.config.js`** 의 `policy` / `authorization` 명시값 (최우선)

---

## 3. 보안 설정 (가장 중요)

### 3.1 `dokkebi.config.js` 의 핵심 설정

```js
// dokkebi.config.js
export default {
  proxyMode: 'serverless',        // 'serverless' | 'server'

  database: {
    type: 'd1',                   // 'd1' | 'supabase' | 'appwrite'
    accountId: process.env.D1_ACCOUNT_ID,
    databaseId: process.env.D1_DATABASE_ID,
    apiToken:   process.env.D1_API_TOKEN,
  },

  backend:  { entry: './backend/controllers/index.ts' },
  frontend: { outDir: './dist' },

  // ═══════════════════════════════════════════════════════════
  // 보안 — 가장 중요한 섹션
  // ═══════════════════════════════════════════════════════════
  security: {
    // 한 줄 보안 프리셋. 'basic' | 'standard' | 'strict' 중 선택.
    //   'basic'    — 추가 강제 없음. 기존 호환 모드.
    //   'standard' — Tenant Policy verify, Authorization warn, 자동 추론.
    //                → 일반 앱에 권장 (기본값으로 사용 권장)
    //   'strict'   — Tenant Policy inject, Authorization strict,
    //                queryRegistry strict. → 유료/금융/admin 앱.
    level: 'strict',

    strictCsp: false,
    activeDefense: { enabled: true, mode: 'enforce' },
  },

  // 아래는 security.level 로 자동 설정되지만, 수동으로 override 가능.
  // 명시값은 항상 프리셋보다 우선.

  // queryRegistry: { strict: true },        // strict 만 허용된 SQL shape 실행
  // policy: {
  //   enabled: true,
  //   mode: 'inject',                        // 'verify' | 'inject' | 'off'
  //   tables: {
  //     posts: { tenantColumn: 'user_id', sessionClaim: 'user_id' },
  //   },
  // },
  // authorization: {
  //   enabled: true,
  //   mode: 'strict',                        // 'warn' | 'strict'
  //   jwtSecretEnv: 'JWT_SECRET',
  //   claim: 'role',
  //   rules: {
  //     'SELECT:premium_contents': { roles: ['premium', 'admin'] },
  //     '*': { auth: true },                 // 디폴트
  //   },
  // },

  deploy: {
    cloudflarePages: { domain: 'app.example.com' },
  },
};
```

### 3.2 보안 레벨 선택 기준

| 앱 종류 | 권장 레벨 | 비고 |
|---|---|---|
| 개인용 도구 / 데모 | `'basic'` 또는 `'standard'` | 보안 위협 노출 적음 |
| 일반 SaaS / 다중 사용자 | `'standard'` | 권장 기본값 |
| **유료 결제 / 멤버십** | **`'strict'`** | **반드시 strict** |
| 금융 / 의료 / 관리자 | `'strict'` | 반드시 strict |
| Admin 전용 페이지 | `'strict'` | 반드시 strict |

### 3.3 서버에서 자동 적용되는 검증 흐름

`dok build` → 배포 후, 모든 DB 요청이 **반드시 다음 관문을 통과**한다 (서버 사이드,
클라이언트가 변조 불가):

```
클라이언트 (브라우저 WASM)
        │ 암호화된 SQL 전송
        ▼
[Cloudflare Pages Functions / dok serve]
  ① Envelope size cap        (Phase 1)
  ② Per-session token bucket (Phase 2)
  ③ Nonce 중복 검사
  ④ Timestamp 검증
  ⑤ HMAC 서명 검증
  ⑥ AES-256-GCM 복호화
  ⑦ SQL Allowlist             ← 항상 ON
  ⑧ Query Registry strict    ← level: 'strict' 시 ON
  ⑨ Tenant Policy inject     ← level: 'strict' 시 ON
  ⑩ Authorization Policy     ← level: 'strict' 시 ON
  ⑪ ADL Blacklist/Risk
        │ 모든 검증 통과 시
        ▼
     D1 / Supabase / Appwrite 실행
```

---

## 4. 자주 하는 작업 패턴

### 4.1 새 라우트 추가

1. **모델 확인** — 사용할 테이블이 `backend/models/index.ts` 에 있는가?
   없으면 `table()` 로 정의. 권한 critical 하면 `access` 옵션 함께 명시.
2. **컨트롤러 작성** — `backend/controllers/` 에 `router.METHOD()` 추가.
3. **권한 명시** (필요 시) — 컨트롤러에 `@dokkebi-policy` JSDoc 추가.
4. `dok dev` 또는 `dok build` 실행.

### 4.2 새 테이블 추가 (마이그레이션)

```typescript
// backend/models/index.ts 에 정의 추가
export const articles = table('articles', { ... });
```

```sql
-- backend/db/migrations/004_articles.sql
CREATE TABLE IF NOT EXISTS articles (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  ...
);
```

`dok build` 시 D1 자격증명이 있으면 자동 적용. 수동 적용은:

```bash
dok build --skip-migration   # 빌드만
# 또는 wrangler d1 execute dokkebi-db --file=...
```

### 4.3 환경변수 사용

```typescript
// backend/controllers/foo.controller.ts
const apiKey = process.env.STRIPE_SECRET_KEY;  // 빌드 타임에 치환됨
```

이름에 `SECRET / KEY / TOKEN / PASSWORD / PRIVATE / CREDENTIAL` 이 포함된 변수는
**자동으로 Opaque Handle 보호** (번들에 평문 미포함, 핸드셰이크로 암호화 전달).

### 4.4 인증 (로그인/세션)

도깨비는 **세션 발급 자체는 사용자 구현**이다 (JWT 발급기는 직접 만들어야 함).
세션 클레임을 도깨비가 인식하려면:

```typescript
// 로그인 핸들러 (예시)
router.post('/api/auth/login', async (req) => {
  const user = await verifyPassword(req.json);
  const token = signJwt({
    user_id: user.id,         // ← Tenant Policy 가 이 클레임을 사용
    role: user.role,          // ← Authorization Policy 가 이 클레임을 사용
    exp: Math.floor(Date.now()/1000) + 86400,
  });
  return { ok: true, token };
});
```

JWT 서명 비밀은 `JWT_SECRET` 환경변수로 관리. `dokkebi.config.js` 의
`authorization.jwtSecretEnv` 로 이름 변경 가능.

---

## 5. 명령어 (CLI)

```bash
dok create [name]               # 새 프로젝트 생성 (대화형)
dok dev                         # 개발 서버 (HMR)
dok build                       # 프로덕션 빌드
dok serve                       # server 모드 백엔드 실행
dok deploy                      # Cloudflare Pages 배포 (또는 R2/S3)
dok deploy --frontend-only      # 프론트만
dok deploy --backend-only       # 백엔드만
dok update                      # 의존성 + 자체 업데이트
```

---

## 6. AI 작업 시 절대 하지 말아야 할 것 (Anti-patterns)

### ❌ 클라이언트 권한 체크에 의존

```typescript
// 잘못됨 — 메모리 해킹으로 우회 가능
if (user.plan !== 'premium') {
  throw new Error('유료 회원만 이용 가능');
}
```

```typescript
// 올바름 — 서버에서 강제. 모델/JSDoc 으로 선언.
// (DSL access 옵션 또는 @dokkebi-policy 사용)
```

### ✅ 고비용/유료 기능은 Signed Unlock Token 사용

브라우저 WASM 의 분기문은 패치될 수 있으므로, AI 생성·유료 기능·관리자 export 같은 기능은
서버가 발급한 짧은 수명 capability 를 요구하도록 작성한다.

우선 `dokkebi.config.js` 의 route guard 로 자동 적용한다.

```js
security: {
  capabilities: {
    enabled: true,
    features: {
      'image.generate': {
        roles: ['premium', 'admin'],
        ttlMs: 10000,
        routes: ['POST /api/ai/image'],
      },
    },
  },
}
```

또는 컨트롤러 JSDoc 으로 선언한다.

```typescript
/**
 * @dokkebi-capability feature:image.generate route:"POST /api/ai/image" roles:['premium','admin'] ttl:10000
 */
router.post('/api/ai/image', async (ctx) => {
  // 자동 guard 통과 후 ctx.capability 사용 가능
});
```

state binding 이 더 필요하면 수동 API 를 추가로 사용한다.

```typescript
import { capability } from 'dokkebi:runtime';

const unlock = await capability.unlock('image.generate', {
  state: { projectId, promptHash },
  jwt: authToken,
});
if (!unlock.ok) throw new Error(unlock.error);

// token/proof 를 단순 true/false 대신 실행 파라미터나 서버 요청 재료에 묶어 사용
```

설정은 `dokkebi.config.js` 의 `security.capabilities` 에서 선언한다. `DOKKEBI_CAPABILITY_SECRET`
은 Worker-only secret 이며, `.env` 또는 Cloudflare Pages Secret 에 32자 이상 랜덤 값으로 둔다.
이 기능은 권한 플래그 패치 방어용이고, DB 권한의 최종 방어선은 여전히 Authorization Policy / Tenant Policy 이다.

선행 단계 통과를 강제해야 하는 기능은 `requires.prev` 로 capability chain 을 만든다.

```js
features: {
  'auth.verified':  { public: true,  ttlMs: 60000 },
  'image.generate': { roles: ['premium','admin'], requires: { prev: ['auth.verified'] } },
}
```

```ts
const a = await capability.unlock('auth.verified');
const b = await capability.unlock('image.generate', {
  prev: [{ feature: 'auth.verified', token: a.capability.token }],
});
```

### ✅ 변조 가능성이 큰 번들에는 Bundle Attestation 사용

`security.attestation.enabled = true` 로 켜고, 보호하려는 capability 에 `requires: { attest: true }` 를 추가한다. Worker 가 매 세션마다 무작위 청크 인덱스를 challenge 로 보내고, 클라이언트는 메모리에 보관된 암호화 번들 바이트로 SHA-256 응답을 생성한다. 변조된 번들은 매니페스트와 어긋나 차단된다. 사용자 코드는 그대로 두고, 클라이언트 SDK 가 `CAPABILITY_ATTEST_REQUIRED` 응답을 받으면 한 번 자동으로 attest 하고 재시도한다.

```js
security: {
  attestation: { enabled: true, sampleSize: 4, ttlMs: 5 * 60_000 },
  capabilities: {
    enabled: true,
    features: {
      'image.generate': { roles: ['premium','admin'], requires: { attest: true } },
    },
  },
}
```

### ✅ 관제 어드민은 비밀번호와 IP 제한을 같이 사용

`/_dokkebi/_panel` 을 운영에 노출하는 프로젝트는 `.env` 또는 Cloudflare Pages Secret 에 긴 `DOKKEBI_ADMIN_PASSWORD` 를 둔다. IP 제한이 필요하면 `dokkebi.config.js` 에서 `security.panelIpGuard: true` 를 켠 뒤 `DOKKEBI_PANEL_ALLOWED_IPS` 로 접속 IP 를 제한한다.

```js
security: {
  panelIpGuard: true,
}
```

```env
DOKKEBI_ADMIN_PASSWORD=your_secure_password
DOKKEBI_PANEL_ALLOWED_IPS=203.0.113.10,198.51.100.0/24
```

`security.panelIpGuard` 기본값은 `false` 이며, 꺼져 있으면 env 값이 있어도 차단하지 않는다. 켜져 있는데 `DOKKEBI_PANEL_ALLOWED_IPS` 가 없으면 `dok build` 가 경고한다. 템플릿의 `_panel` 코드를 직접 수정하지 말고 config/env 로 제어한다.

### ❌ `worker/api/_dokkebi/*` 직접 수정

이 파일들은 `dok build` 가 자동 생성한다. 수정해도 다음 빌드에서 덮어써진다.
정책 변경은 `dokkebi.config.js` 또는 모델/컨트롤러 어노테이션으로.

### ❌ `process.env.SECRET_*` 평문 노출

도깨비는 자동으로 Opaque Handle 처리한다. 단, **클라이언트 코드 (`frontend/`) 에서는
사용 금지**. `frontend/` 는 일반 브라우저 환경이므로 `import.meta.env.VITE_*` 만 사용.

### ❌ `dist/` 또는 `functions/` 에 직접 작성

자동 생성 디렉토리. 항상 `dok build` 로 재생성된다.

### ❌ tenant 컬럼 빠뜨리기

다중 사용자 앱에서 `posts.userId` 같은 tenant 컬럼이 빠지면 사용자 격리가
불가능하다. `policyInference` 가 경고를 출력하므로 빌드 로그를 반드시 확인.

### ❌ SQL 직접 조립 (문자열 결합)

```typescript
// 잘못됨 — Allowlist 거부 + SQL 인젝션
await db.exec(`SELECT * FROM posts WHERE id = '${userInput}'`);
```

```typescript
// 올바름 — DSL 사용
await db.select(posts).where(eq(posts.id, userInput)).exec();
```

---

## 7. 디버깅 / 트러블슈팅

### "tenant 컬럼을 추론하지 못했습니다" 경고

```bash
[tenant] 'X' 테이블에서 tenant 컬럼을 추론하지 못했습니다.
```

해결:
1. 모델에 `user_id` / `owner_id` 등 표준 컬럼 추가, 또는
2. `table('X', {...}, { tenant: 'col_name' })` 명시, 또는
3. 공개 테이블이면 `table('X', {...}, { tenant: false })` 명시

### "queryId not in registry" 에러

`security.level: 'strict'` + `queryRegistry.strict: true` 일 때,
빌드 시 등록되지 않은 SQL shape 가 런타임에 호출됨.

해결:
1. `dok build` 재실행 (빌드 시 모든 SQL 자동 수집).
2. 동적 SQL 이라면 `// @dokkebi-query: SELECT ... FROM ...` 주석으로 등록.
3. 임시 해결: `queryRegistry: { strict: false }`.

### "AUTH_REQUIRED" / "ROLE_FORBIDDEN" (403)

서버의 Authorization Policy 가 요청을 거부함.

해결:
1. 클라이언트가 `Authorization: Bearer <jwt>` 헤더를 보내고 있는가?
2. JWT 의 `role` 클레임이 정책 규칙과 일치하는가?
3. `dokkebi.config.js` 의 `authorization.rules` 또는 모델/JSDoc 어노테이션 확인.

### "TENANT_MISSING" (403)

세션에 tenant 클레임이 없거나, 정책에서 요구하는 컬럼 조건이 SQL 에 없음.

해결:
1. 로그인 시 JWT 에 올바른 클레임 (`user_id` 등) 을 넣고 있는가?
2. 클라이언트에서 `ctx.setSessionTenant({ user_id: '...' })` 호출했는가?
3. `mode: 'inject'` 로 자동 주입할 수 있는지 확인.

---

## 8. 파일별 빠른 참조

| 파일 | 역할 |
|---|---|
| `dokkebi.config.js` | 모든 설정 (DB, 보안, 배포) |
| `.env` | 자격증명 (gitignore!) |
| `backend/models/index.ts` | 테이블 DSL 정의 (+ 보안 옵션) |
| `backend/controllers/*.ts` | 라우트 핸들러 (+ JSDoc 어노테이션) |
| `backend/db/migrations/*.sql` | DB 마이그레이션 |
| `frontend/` | UI (Vue/React/Vanilla) |
| `wrangler.toml` | Cloudflare Pages 설정 |
| `worker/api/_dokkebi/*.ts` | **자동 생성. 수정 금지.** |
| `dist/`, `functions/`, `dist/dokkebi/` | **자동 생성. 수정 금지.** |

---

## 9. 핵심 보안 원칙 요약

> 1. **클라이언트는 신뢰하지 않는다.** WASM/메모리 해킹은 항상 가능하다.
> 2. **서버 미들웨어가 진실의 소스다.** 모든 권한/테넌트 검증은 서버에서.
> 3. **선언적 보안 (DSL access / JSDoc) 을 우선한다.** 코드와 정책이 분리되지 않음.
> 4. **`security.level: 'strict'` 를 적극 활용한다.** 한 줄로 모든 방어선 활성화.
> 5. **빌드 로그를 반드시 확인한다.** 추론 결과/경고가 모두 출력된다.

---

## 10. SEO — 자동 SEO 파이프라인

도깨비는 CSR + WASM 백엔드 구조라 SSR 이 불가능하지만, **빌드 타임 prerender + 런타임 Edge SEO Renderer** 두 단계로 검색엔진/소셜 크롤러에 page-specific 메타를 제공한다. 사용자가 추가로 작성할 코드는 없다 — 모두 `dokkebi.config.js` + 라우터/모델 자동 스캔.

### 10.1 동작 흐름

```
빌드 타임 (dok build)
  ① 라우트 스캔 (frontend/src/**) — title/description 추론
  ② 정적 라우트 → dist/<path>/index.html prerender (메타 + JSON-LD 주입)
  ③ 동적 라우트 → seo.dynamic 의 SQL 또는 D1 enumerate → 정적 HTML 펼침
  ④ sitemap.xml + robots.txt 생성
  ⑤ functions/_dokkebi-seo/[[path]].js (Edge Renderer) + functions/_middleware.js (봇 분기) emit

런타임 (Cloudflare Pages)
  봇 UA 요청 ── _middleware.js 가 UA 검사
                │ 봇이면
                ▼
              /_dokkebi-seo/<path> forward
                │
                ▼
              KV 캐시(SEO_CACHE) hit → 즉시 응답
                │ miss 면
                ▼
              D1 lookup (단건) → 베이스 HTML 에 메타 주입 → KV 24h 저장
              일반 UA 는 그대로 SPA index.html 정적 응답
```

응답 헤더 `x-dokkebi-seo: HIT|MISS|PASS|NO-DB|DB-ERR|NOT-FOUND` 으로 디버깅.

### 10.2 `dokkebi.config.js` 의 `seo` 블록

```js
seo: {
  baseUrl: 'https://example.com',         // sitemap 절대 URL 베이스
  defaults: {
    siteName: 'My App',
    locale: 'ko',
    description: '사이트 기본 설명 (description 추론 실패 시 폴백)',
    image: '/og-default.png',             // og:image 폴백
    twitterCard: 'summary_large_image',
  },

  // 정적 라우트 — title/description 명시. 라우터 자동 스캔이 못 찾으면 여기서 보강.
  routes: {
    '/':              { title: '홈', description: '...', image: '/og/home.png' },
    '/about':         { title: '소개', description: '...' },
    '/pricing':       { title: '가격', description: '...' },
  },

  // 동적 라우트 — 빌드 타임에 D1 에서 SQL 실행해서 정적 HTML 로 펼침.
  // 또한 런타임 Edge SEO Renderer 가 동일 SQL 로 단건 lookup.
  dynamic: [
    {
      path: '/:lang/:username/post/:slug',  // 라우터 패턴
      query: `
        SELECT
          p.locale     AS lang,
          u.username   AS username,
          p.slug       AS slug,
          p.title      AS title,
          p.excerpt    AS description,
          p.updated_at AS updated_at
        FROM posts p
        JOIN users u ON u.id = p.user_id
        WHERE p.published = 1
          AND u.username IS NOT NULL
          AND p.slug IS NOT NULL
      `,
      // 컬럼 매핑은 SELECT alias 와 라우트 :param 이름이 같으면 자동.
      // 명시할 경우:
      // columns: { titleCol: 'title', descCol: 'description', imageCol: null, timeCol: 'updated_at' },
    },
  ],

  // edgeRenderer 는 dynamic 가 1개 이상이면 자동 활성. 끄려면:
  // edgeRenderer: { enabled: false },
  // edgeRenderer: { enabled: true, cacheTtlSeconds: 86400 }, // KV 캐시 TTL
},
```

### 10.3 정적 prerender — 라우트 메타 추출 우선순위

```
1) 페이지 컴포넌트 상단 JSDoc  /** @dokkebi-seo title: ... description: ... image: ... */
2) seo.routes['/path']         (config 명시 — 권장)
3) <Helmet> / next/head 등 라이브러리 사용 패턴
4) 컴포넌트 export default 함수명 → 자연어 추론 (저신뢰)
```

빌드 후 `dist/.dokkebi/seo-report.md` 에서 추출 결과/신뢰도 확인. 신뢰도 낮은 라우트는 `seo.routes` 에 명시.

### 10.4 동적 라우트 — `seo.dynamic` 작성 규칙

- **`path`**: 라우터 패턴. `:param` 형식. 여러 `:` 가능.
- **`query`**: SELECT SQL. 결과 컬럼 alias 가 라우트 `:param` 이름과 일치하면 자동 매핑.
  - 필수 컬럼: 적어도 `:` 마지막 segment 의 alias (위 예시는 `slug`).
  - 권장 컬럼: `title`, `description`, `updated_at` (lastmod 용), 선택적 `image`.
- 빌드 타임에 D1 자격증명 (`.env: D1_API_TOKEN`) 있어야 enumerate 동작.
- 자격증명 없거나 D1 미사용 (`database.type !== 'd1'`) 이면 SEO 동적 라우트 skip.

### 10.5 Cloudflare Pages 바인딩

`wrangler.toml` 에 다음 binding 권장:

```toml
[[d1_databases]]
binding = "DB"                    # 필수. Edge Renderer 가 D1 lookup 에 사용.
database_name = "..."
database_id = "..."

[[kv_namespaces]]
binding = "SEO_CACHE"             # 선택. 24h 캐시. 없으면 매 요청 D1 hit (성능만 영향).
id = "..."                        # `wrangler kv:namespace create SEO_CACHE` 로 생성.
```

KV binding 없어도 동작. `x-dokkebi-seo: MISS` 가 매 호출마다 떠도 결과는 정상.

### 10.6 보안 — Tenant Policy 와 SEO 의 관계

Edge SEO Renderer 는 봇 응답이라 **로그인 세션이 없다**. Tenant Policy 가 `strict` / `enforce` 면 `TENANT_MISSING` 으로 차단된다.

**해결**: 공개 SEO 가 필요한 테이블은 `optional` 모드.

```js
policy: {
  enabled: true,
  mode: 'verify',
  tables: {
    posts:       { tenantColumn: 'user_id', mode: 'optional' },  // 로그인 시만 격리, 봇은 통과
    users:       { mode: 'optional' },
    blog_profiles: { mode: 'optional' },
  },
}
```

`mode: 'optional'` — JWT 클레임 있으면 격리 SQL 자동 주입, 없으면 그대로 통과.

### 10.7 봇 UA 검출 범위

자동 분기되는 봇 (확장 가능):
`googlebot, bingbot, slurp, duckduckbot, yandexbot, baiduspider, sogou, applebot, naver/yeti, daum/kakao, twitterbot, facebookexternalhit, linkedinbot, slackbot, discordbot, telegrambot, whatsapp, gptbot, chatgpt-user, claudebot, perplexitybot, amazonbot, bytespider, *bot, *spider, *crawler` 등.

일반 사용자(브라우저)는 그대로 SPA 응답 → CSR 정상 진행.

### 10.8 봇 응답 디버깅

```bash
# 정상 동작 확인 — x-dokkebi-seo: MISS 헤더 + page-specific 메타
curl -I -A "Googlebot/2.1" https://example.com/posts/hello-world

# 함수 자체 진단 — /_dokkebi-seo/<path> 직접 호출
curl -i https://example.com/_dokkebi-seo/posts/hello-world
# 응답에 x-dokkebi-seo 헤더 없으면 함수가 라우팅 안 됨 → functions/_dokkebi-seo/[[path]].js 존재 확인.

# 두번째 호출에 MISS → HIT 안 바뀌면 KV(SEO_CACHE) binding 없음.
```

상태 코드 의미:
| 헤더 값 | 뜻 |
|---|---|
| `HIT` | KV 캐시 적중 (24h) |
| `MISS` | D1 lookup 성공, 캐시 저장 |
| `PASS` | 라우트 매칭 안 됨, SPA 그대로 응답 |
| `NO-DB` | `env.DB` binding 없음 |
| `DB-ERR` | SQL 실행 실패 (Tenant Policy 차단 등) |
| `NOT-FOUND` | 매칭은 됐지만 D1 row 없음 |

### 10.9 Anti-patterns

❌ **`functions/_dokkebi-seo/[[path]].js` 직접 수정** — 자동 생성, 빌드마다 덮어써짐. 동작 변경은 `seo.dynamic` config 또는 라우트 메타로.

❌ **Tenant strict + 공개 페이지** — 봇 응답 항상 차단됨. `optional` 모드로.

❌ **민감 컬럼을 `seo.dynamic.query` 에 SELECT** — Edge Renderer 응답 HTML 에 노출됨. 공개 안전 컬럼만 select.

❌ **너무 많은 `:param`** — 4 segment 초과 동적 라우트는 sitemap 폭증 / 색인 거부 가능. 카테고리 페이지로 묶는 게 좋다.

---

## 11. 트랜잭션 / WebSocket / Durable Objects 등 고급

### Durable Objects (실시간 협업)

`do-worker/` 디렉토리에 별도 정의 → 별도 Worker 로 배포:

```bash
cd do-worker && wrangler deploy   # 1단계: DO 호스팅 워커
cd .. && dok deploy                # 2단계: Pages + DO binding
```

`wrangler.toml` 에 `script_name = "..."` 으로 binding 만 한다.

### WebSocket

WebSocket 핸드셰이크는 미들웨어를 우회 (`isWebSocketUpgrade` 체크).
`worker/api/some-route/ws.ts` 에서 JWT 검증 후 DO 로 위임하는 패턴 표준.

### 마이그레이션 자동 적용

`.env` 에 `D1_API_TOKEN` 설정 시 `dok build` 가 자동으로 `db/migrations/*.sql`
적용. 수동 실행은 `wrangler d1 execute <name> --file=...`.

---

## 12. D1 샤딩 & 읽기 스케일 (Phase A + B 합류 완료)

> **AI 가 가장 자주 틀리는 영역.** 이 섹션의 규칙을 그대로 따르면 안전하고,
> 응용/창작하면 데이터 격리·트랜잭션 무결성을 거의 확실히 깬다.

### 12.1 의사결정 — 무엇을 켤까

| 상황 | 선택 |
|---|---|
| ~수천 동접, read-heavy | **단일 D1 그대로** (아무것도 안 켬) |
| ~1만 동접, 글로벌 사용자 | `database.sessions: true` **한 줄만 추가** |
| 수만~10만 동접, 쓰기 한계 도달 | `database.type: 'd1-sharded'` + `shards[]` + `strategy` |
| 단일 인기 키 집중 (라이브 채팅방, 인기 글) | **샤딩 아님 — Durable Object** 사용 |

### 12.2 Step 1 — Read replica (1줄, 30초)

```js
// dokkebi.config.js
database: {
  type: 'd1',
  // ... 기존 설정 그대로
  sessions: true,            // ← 한 줄만 추가
},
```

- 모든 `SELECT` 가 가까운 D1 replica 로 자동 분기 (지연 ↓, 동시성 ↑).
- 응답에 `Set-Cookie: __d1b=...; HttpOnly; SameSite=Lax` 자동 첨부 → 같은 사용자의
  "쓰고 바로 읽기" 일관성 자동 보장.
- **컨트롤러 코드 변경 없음.** AI 는 절대 직접 `withSession()` 호출을 추가하지 마라.
  도깨비가 빌드 타임에 자동 주입한다.

### 12.3 Step 2 — 샤드 키 결정 (가장 중요한 단계)

샤드 키는 **한 트랜잭션이 한 샤드 안에서 끝나는 컬럼** 이어야 한다.
다음 4개 모두 ✓ 가 아니면 샤딩하지 마라.

- [ ] 대부분의 쿼리가 `WHERE {key} = ?` 형태인가?
- [ ] 한 트랜잭션이 같은 키 값 안에서만 동작하는가? (cross-key 트랜잭션 X)
- [ ] 정책엔진의 `policy.tables[*].sessionClaim` 과 같은 컬럼인가? (빌드 시 자동 검증)
- [ ] 한 키에 트래픽이 80%+ 집중되지 않는가? (집중되면 샤딩 X, Durable Object O)

### 12.4 Step 3 — 설정 + 프로비저닝

기본 생성된 `dokkebi.config.js` 에 `// type: 'd1-sharded'` 형태의 주석 블록이
이미 들어있다. 주석을 풀고 채운 뒤:

```bash
dok db:provision   # 모든 샤드 D1 자동 생성 + wrangler.toml [[d1_databases]] 자동 갱신
dok migrate        # 모든 샤드 + global 에 스키마 fan-out
```

`dok db:provision` 은 idempotent — 같은 이름의 D1 이 있으면 reuse, 이미 채워진 항목은 skip.
안전하게 여러 번 실행 가능.

### 12.5 Step 4 — 컨트롤러 패턴 (정확히 이대로)

**올바른 패턴**:

```typescript
import type { Context } from 'dokkebi:runtime';

// READ — 같은 user_id 는 항상 같은 샤드
export const listOrders = async (ctx: Context) => {
  const { user_id } = ctx.session;
  const db = ctx.shardFor({ user_id });               // ✅ 결정적 라우팅
  return db.query('SELECT * FROM orders WHERE user_id = ?', [user_id]);
};

// WRITE — 같은 핸들로 쓰기. primary 자동 선택.
export const placeOrder = async (ctx: Context) => {
  const { user_id } = ctx.session;
  const { product_id, qty, total } = await ctx.body();
  const db = ctx.shardFor({ user_id });
  await db.exec(
    'INSERT INTO orders(user_id, product_id, qty, total_price) VALUES (?,?,?,?)',
    [user_id, product_id, qty, total],
  );
  return { ok: true };
};

// FAN-OUT — 관제·집계 전용. 결과 합산은 사용자 코드 책임.
export const adminTotal = async (ctx: Context) => {
  const rows = await ctx.fanout((db) => db.query('SELECT COUNT(*) AS n FROM orders'));
  return { total: rows.reduce((s, r) => s + (r[0]?.n ?? 0), 0) };
};

// GLOBAL — 공용 룩업 테이블 (products, coupons, …)
export const getProduct = async (ctx: Context) => {
  const g = ctx.global();
  return g.query('SELECT * FROM products WHERE id = ?', [Number(ctx.params.id)]);
};
```

### 12.6 절대 하지 말 것 (AI 안티패턴)

- ❌ **다른 사용자 데이터를 한 핸들로 읽기 금지**
  ```typescript
  const db = ctx.shardFor({ user_id: A });
  db.query('SELECT * FROM orders WHERE user_id = ?', [B]);   // 정책엔진 차단됨
  ```
- ❌ **암시적 cross-shard 금지**: `for (const s of shards) { ... }` 같은 수동 순회 금지.
  반드시 `ctx.fanout()` 으로 명시.
- ❌ **cross-shard 트랜잭션 금지**: D1 은 cross-DB 트랜잭션 없음. 다중 키 작업은 saga 패턴.
- ❌ **`ctx.db.withSession()` / `env.DB` 직접 호출 금지**: 빌드 타임에 자동 주입됨.
  AI 가 추가하면 이중 주입으로 쿠키가 깨진다.
- ❌ **샤드 수를 자유롭게 변경 금지**: 같은 키가 다른 샤드로 갈 수 있다. 변경은 Phase C
  (`dok db:reshard`) 워크플로로만.

### 12.7 동적 SQL 라우팅 힌트

prefix 가 `SELECT` 가 아닌 동적 합성 SQL 은 read 인지 도깨비가 알 수 없다.
선두에 한 줄 힌트:

```typescript
const sql = '/*!read*/ '  + buildSelectSql(filters);  // replica 우선
const ups = '/*!write*/ ' + buildUpsertSql(...);      // primary 강제
```

### 12.8 빌드/배포 시 자동 검증

| 검사 | 발생 시점 | 결과 |
|---|---|---|
| `strategy.key` 누락 | `dok build` | 에러 (빌드 차단) |
| `strategy.key` ≠ `policy.tables[*].sessionClaim` | `dok build` | 워닝 (`policy.strict:true` 면 에러) |
| 샤딩 모드인데 `sessions: false` | `dok build` | 워닝 |
| `wrangler.toml` 에 샤드 binding 누락 | `dok deploy` preflight | 에러 (배포 차단) |
| `--preflight strict` 실행 시 워닝 누적 | `dok deploy` | 모두 에러로 차단 |

### 12.9 단일 → 샤딩 마이그레이션 체크리스트

1. `database.type` 을 `'d1-sharded'` 로 변경, `shards`/`strategy` 작성.
2. `dok db:provision` → 출력된 `databaseId` 를 `.env` 또는 config 에 채움.
3. `dok migrate` → 모든 샤드 + global 에 스키마 적용.
4. 컨트롤러를 `ctx.shardFor({ [strategy.key]: value })` 로 일괄 변환.
5. 정책엔진 `sessionClaim` 이 `strategy.key` 와 같은지 재확인.
6. (Phase C) 기존 데이터 분배는 `dok db:reshard backfill` (미구현 — 수동 SQL fanout 필요).

> 자세한 설계는 `dokkebi-cli/docs/design/SHARDING.md`, 사용자용 가이드는
> dokkebi-site `/#/sharding` 페이지 참고.

---

## 부록 A — 자주 쓰는 코드 스니펫

### A.1 사용자 본인 데이터만 조회 (Tenant 자동 적용)

```typescript
// 모델
export const notes = table('notes', {
  id:     col('id',      t.uuid().primaryKey()),
  userId: col('user_id', t.text()),
  text:   col('text',    t.text()),
}, { tenant: 'user_id' });

// 컨트롤러 — Tenant Policy inject 모드면 SQL 에 user_id 자동 주입
router.get('/api/notes', async (req) => {
  const { rows } = await db.select(notes).exec();
  // → 실제 실행: SELECT * FROM notes WHERE user_id = '<JWT.user_id>'
  return { ok: true, notes: rows };
});
```

### A.2 admin 전용 라우트

```typescript
// 모델
export const adminLogs = table('admin_logs', {
  id: col('id', t.uuid().primaryKey()),
  message: col('message', t.text()),
}, {
  access: {
    all: { roles: ['admin'] },
  },
});
```

### A.3 유료/무료 분기 (역할 기반)

```typescript
// 모델
export const premiumFeatures = table('premium_features', {
  id:      col('id',      t.uuid().primaryKey()),
  userId:  col('user_id', t.text()),
  feature: col('feature', t.text()),
}, {
  tenant: 'user_id',
  access: {
    read:  { roles: ['premium', 'admin'] },
    write: { roles: ['admin'] },
  },
});

// 결제 완료 시 JWT 의 role 을 'premium' 으로 갱신 → 자동으로 접근 허용
```

### A.4 공개 + 인증 혼합 (블로그)

```typescript
export const blogPosts = table('blog_posts', {
  id:    col('id',    t.uuid().primaryKey()),
  title: col('title', t.text()),
  body:  col('body',  t.text()),
}, {
  access: {
    read:  { public: true },        // 누구나 읽기
    write: { roles: ['author', 'admin'] },
    delete: { roles: ['admin'] },
  },
});
```

---

**문서 끝.**

도깨비 프레임워크의 핵심은 "**클라이언트에서 백엔드를 실행하지만, 신뢰는 서버가 결정한다**" 입니다. 이 원칙만 지키면 안전합니다.
