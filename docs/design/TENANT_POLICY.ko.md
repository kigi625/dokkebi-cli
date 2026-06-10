# 프레임워크 레벨 Tenant Policy (의사 RLS) — 설계 + 구현 문서

- **버전**: 1.0 (구현 완료 — Stage 1 & 2)
- **상태**: v5.1 (verify) + v5.2 (inject) 릴리스
- **범위**: 단계 1 (정책 메타데이터 + 검증 모드) + 단계 2 (자동 주입 모드)
- **비고**: 단계 3(Query Registry) 은 별도 문서([`QUERY_REGISTRY.md`](./QUERY_REGISTRY.md))에서 다룹니다.

---

## 0. 구현 요약 (v5.1 + v5.2)

```
dokkebi.config.js → normalizePolicyConfig() → allowlist v2 스키마
                                           ↓
                     worker/api/_dokkebi/db.ts  (v6 템플릿)
                       ├─ _policyMeta (빌드 타임 임베드)
                       ├─ verifyTenantPolicy()   (Stage 1)
                       ├─ injectTenantPolicy()   (Stage 2)
                       └─ _setTenant 분기        (세션 클레임 갱신)

클라이언트 흐름:
  로그인 성공 → ctx.setSessionTenant({user_id, ...}) → 암호화 채널 →
    Pages Function 이 _dokkebi_sessions.tenant_json 갱신
  이후 모든 db 요청: 세션 조회시 tenant_json 파싱 → verify/inject
```

### 사용 예시

**1) 단일 사용자 앱** (기본값, 설정 불필요):
```js
// dokkebi.config.js
export default {
  // policy 섹션 생략 → 정책 엔진 비활성, 기존 v4 동작
};
```

**2) 멀티테넌트 SaaS — verify 모드** (개발자 실수를 차단):
```js
export default {
  policy: {
    enabled: true,
    mode: 'verify',              // 'verify' | 'inject' | 'off'
    sessionClaim: 'user_id',
    strict: true,
    tables: {
      orders:   { tenantColumn: 'user_id',  mode: 'enforce' },
      posts:    { tenantColumn: 'author_id', mode: 'enforce' },
      products: { mode: 'none' },     // 공개 테이블
    }
  }
};
```

**3) 자동 주입 모드** (개발자가 빠뜨려도 서버가 채워줌):
```js
export default {
  policy: {
    enabled: true,
    mode: 'inject',              // verify 실패시 자동 주입
    sessionClaim: 'user_id',
    tables: { orders: { tenantColumn: 'user_id', mode: 'enforce' } }
  }
};
```

### 세션 테넌트 설정 (로그인 후)

백엔드 컨트롤러에서 로그인 검증 성공 후 호출:
```typescript
// backend/controllers/auth.ts
export async function login(ctx, email, password) {
  const user = await db.query(users).where(u => u.email.eq(email)).first();
  if (!user || !verifyPassword(password, user.password_hash)) throw new Error('INVALID');

  // 현재 세션에 테넌트 클레임 바인딩 — 이후 모든 db 요청에 자동 적용
  await ctx.setSessionTenant({ user_id: user.id });

  return { id: user.id, email: user.email };
}
```

내부 동작: `ctx.setSessionTenant(obj)` 는 `POST /api/_dokkebi/db` 에 `{_setTenant: obj}` payload 를 전송 → 서버가 `UPDATE _dokkebi_sessions SET tenant_json = ? WHERE session_id = ?` 실행. `obj === null` 이면 로그아웃(클리어).

### 테이블별 `sessionClaim` (v5.4+) — JWT 없이 해시 ID 만으로 tenant 격리

Tenant Policy 는 **로그인 / JWT 와 무관**합니다. 세션의 `tenant_json` 은 자유 형태 JSON 이므로, 사용자 식별에 쓰는 **어떤 값**이든 (해시 토큰, 디바이스 ID, 익명 쿠키 등) tenant 로 삼을 수 있습니다.

대표 예 — **notofly 처럼 테이블마다 다른 해시 토큰**을 쓰는 프로젝트:

```js
// dokkebi.config.js (autogen — dok policy:scaffold 가 생성)
policy: {
  enabled: true,
  mode: 'verify',
  sessionClaim: 'creator_token',   // 전역 기본 (fallback)
  tables: {
    notos:              { tenantColumn: 'creator_token',      sessionClaim: 'creator_token' },
    messages:           { tenantColumn: 'sender_token',       sessionClaim: 'sender_token' },
    users:              { tenantColumn: 'id',                 sessionClaim: 'user_id' },
    noto_collaborators: { tenantColumn: 'collaborator_token', sessionClaim: 'collaborator_token' },
    push_subscriptions: { tenantColumn: 'token',              sessionClaim: 'token' },
    message_replies:    { tenantColumn: 'author_token',       sessionClaim: 'author_token' },
  },
}
```

프런트엔드 — 한 번의 `setSessionTenant` 호출로 **여러 종류의 해시 ID** 를 동시에 세션에 바인딩:

```typescript
// App 초기화 (예: React useEffect, 로그인/회원가입 필요 없음)
await ctx.setSessionTenant({
  creator_token:      localStorage.getItem('creator_token')      || undefined,
  sender_token:       localStorage.getItem('sender_token')       || undefined,
  collaborator_token: localStorage.getItem('collaborator_token') || undefined,
  user_id:            authState?.userId                           || undefined,
});
```

엔진의 클레임 해석 순서 (테이블 단위로 각각 평가):

1. `tables[X].sessionClaim` — 테이블에서 명시한 세션 키 (가장 명확)
2. `policy.sessionClaim` — 전역 기본 (하위 호환)
3. `tenantColumn` 이름 그대로 — 관례 fallback (컬럼명 = 세션 키)

예를 들어 `SELECT * FROM notos WHERE creator_token = ?` 쿼리는 `notos.sessionClaim = 'creator_token'` 을 보고 세션의 `creator_token` 값과 대조합니다. `users.id` 처럼 **컬럼명과 세션 키가 다른 관례 케이스**만 `sessionClaim: 'user_id'` 를 명시해 주면 끝. 나머지는 `dok policy:scaffold` 가 컬럼명을 그대로 세션 키로 자동 배치합니다.

> **요점**: "로그인 한 유저" 가 아니라 "식별되는 어떤 값" 이면 됩니다. 익명 사용자·해시 ID·디바이스 토큰 전부 OK.

### 정책 위반 응답

```json
{
  "ok": false,
  "error": "WHERE 절에 orders.user_id = ? 조건이 없습니다.",
  "code": "NO_TENANT_FILTER",
  "table": "orders"
}
```

HTTP 403 + `_dokkebi_security` 에 `tenant_policy_violation` 이벤트 기록.

### 에러 코드 표

| code | 의미 | 처리 |
|---|---|---|
| `TENANT_MISSING` | 세션에 해당 claim 없음 | `ctx.setSessionTenant()` 호출 필요 |
| `NO_WHERE` | WHERE 절 누락 | WHERE 추가 (또는 `mode: 'inject'`) |
| `NO_TENANT_FILTER` | 테넌트 컬럼 조건 누락 | `WHERE user_id = ?` 추가 |
| `TENANT_MISMATCH` | 전송된 값이 세션과 불일치 | 공격 시도 추정 (403) |
| `LOOSE_OR` | WHERE 최상단 OR | AND 체인으로 재작성 |
| `INSERT_NO_COLUMNS` | INSERT 에 컬럼 리스트 없음 | `INSERT INTO t (c1, c2) VALUES (...)` 형식 사용 |
| `INSERT_MISSING_TENANT_COL` | INSERT 컬럼에 테넌트 없음 | `tenant_col` 추가 |
| `UNSUPPORTED_INSERT_SUBQUERY` | INSERT ... SELECT 미지원 | 분해하거나 `optional` 모드로 |
| `INJECT_FAILED` | 주입 중 파싱 실패 | SQL 구조 단순화 |

### 알려진 제약 (v1.0)

- **INSERT … SELECT** 서브쿼리는 strict 모드에서 거부 (파서 단순성). 필요시 `mode: 'optional'` 로 완화.
- **CTE (WITH)** 내부 각 SELECT 에 대해 verify 는 최종 연산 기준으로만 작동 — 내부 SELECT 에 대한 완전 재귀 검사는 미지원.
- **INSERT 단일 VALUES 튜플** 만 inject 지원. 복수 튜플은 verify 만.
- **동적 테이블명** (변수 치환) 은 파싱 실패 → strict=true 에서 거부.
- **관리자 bypass**: `tenantContext._isAdmin === true` 일 때만. **⚠ 보안(C-2 수정):** 클라이언트는 더 이상 `ctx.setSessionTenant()` 로 `_isAdmin`(및 `_` 접두 예약 키)을 설정할 수 없다 — 프록시가 예약 키를 거부한다(`TENANT_RESERVED_KEY`). 관리자 승격은 서버 신뢰 경로(워커측 `_login` 역할 클레임 + Authorization Policy)로만 부여해야 하며, 클라이언트가 보낸 테넌트 값으로는 불가능하다.

---

## 0.0 단계 간 의존성 · 기본값 정책 (프레임워크 철학)

도깨비는 단일 사용자 앱부터 멀티테넌트 SaaS 까지 **다양한 유스케이스** 를 지원하는 프레임워크입니다. 따라서 각 단계는 **독립적으로 opt-in / opt-out** 가능하도록 설계되며, 아래 표를 기준으로 기본값이 정해집니다.

| 단계           | 보호 대상                          | 기본값              | 활성화 방법                                                               | 의존성                  |
| -------------- | ---------------------------------- | ------------------- | ------------------------------------------------------------------------- | ----------------------- |
| **Allowlist**  | 테이블/연산 레벨 SQL 허가          | **ON (v4 부터)**    | 항상 활성 (방어 깊이)                                                     | 없음                    |
| **Stage 3 (Query Registry)** | SQL shape 레벨 허가  | **ON (v5 기본)**    | `queryRegistry.enabled: false` 로 opt-out                                  | 없음 (독립)             |
| **Stage 1 (Tenant Verify)**  | 테넌트 컬럼 누락 감지 | **OFF**             | `policy.enabled: true, policy.mode: 'enforce-verify'`                      | Stage 3 권장 (필수 아님) |
| **Stage 2 (Tenant Inject)**  | 테넌트 조건 자동 주입 | **OFF**             | `policy.mode: 'enforce-inject'`                                            | Stage 1 전제             |

### 구현 및 릴리스 순서 (권장)

```
v5.0 — Stage 3 (Query Registry) 단독 릴리스  [약 1.5 ~ 2주]
  └─ 모든 앱이 자동 혜택 (단일 사용자 앱도 SQL shape 고정 혜택)

v5.1 — Stage 1 (Tenant Verify) opt-in 추가   [+1주]
  └─ 멀티테넌트 앱이 점진적 롤아웃 (경고만, 차단 X)

v5.2 — Stage 2 (Tenant Inject) opt-in 추가   [+1주]
  └─ 멀티테넌트 앱 테넌트 조건 자동 주입
```

### 유스케이스별 활성화 예시

**단일 사업자 앱 (예: 개인 블로그, 단일 상점):**
```js
// dokkebi.config.js (기본값과 동일, 설정 불필요)
export default {
  // Stage 3 자동 ON
  // Stage 1, 2 OFF
};
```

**멀티테넌트 SaaS (예: 여러 판매자가 쓰는 쇼핑몰):**
```js
export default {
  queryRegistry: { enabled: true, raw: 'deny' },
  policy: {
    enabled: true,
    mode: 'enforce-inject',        // 자동 주입
    sessionClaim: 'user_id',
    tables: {
      orders:   { tenantColumn: 'user_id' },
      products: { tenantColumn: 'seller_id' }
    }
  }
};
```

> **핵심**: 프레임워크는 가능성을 제공하고, 개발자가 유스케이스에 맞춰 선택합니다. 기본값은 "대다수에게 안전하면서 가벼운" 설정입니다.

---

## 0. TL;DR

D1 은 RLS(Row-Level Security) 를 제공하지 않습니다. 하지만 도깨비는 **모든 SQL 이 Cloudflare Pages Function 이라는 단일 게이트를 반드시 통과**하므로, 이 게이트에 정책 레이어를 하나 더 추가해 애플리케이션이 잘못 작성되어도 **테넌트 격리(예: `user_id` 기반 행 수준 격리)를 구조적으로 강제**할 수 있습니다.

본 문서는 기존 SQL Allowlist(`sql-allowlist.json` v1) 을 확장해:
- **v2 스키마**에 테이블별 tenant 정책 메타데이터를 추가하고
- **런타임 정책 엔진**을 Pages Function(`worker/api/_dokkebi/db.ts`) 에 주입해
- **검증 모드(단계 1)** → **자동 주입 모드(단계 2)** 로 점진적 롤아웃하는 방법을 정의합니다.

---

## 1. 배경 / 문제 정의

### 1.1 현재 상태 (v1 Allowlist)

```json
{
  "version": 1,
  "tables": [
    { "name": "orders", "ops": ["SELECT", "INSERT", "UPDATE"] }
  ],
  "rawAllowed": false
}
```

- 테이블/연산 레벨의 허가만 검사
- 공격자가 합법적으로 핸드셰이크를 완료한 뒤 `SELECT * FROM orders` 를 보내면 **전체 사용자의 주문이 노출**
- 개발자가 컨트롤러에 `WHERE user_id = ?` 를 실수로 빼먹으면 앱 전체 데이터가 유출

### 1.2 D1 의 제약

- Cloudflare D1 은 PostgreSQL 의 RLS 같은 DB 레벨 정책을 지원하지 않음
- 따라서 "모든 SQL 을 반드시 거쳐야 하는 경로"에서 정책을 강제할 수밖에 없음 → 도깨비의 경우 Pages Function `/api/_dokkebi/db` 가 그 단일 경로

### 1.3 목표

| 목표 | 레벨 |
|---|---|
| 컨트롤러 실수로 발생하는 tenant 누출 방지 | Must |
| 악의적 클라이언트가 다른 tenant 의 데이터를 조회하지 못함 | Must |
| 기존 프로젝트 하위호환 유지 (v1 그대로 동작) | Must |
| 설정 선언이 직관적 (모델/DSL 에 자연스럽게 녹음) | Should |
| 런타임 성능 오버헤드 최소 (단순 SQL: +0.1ms 이하) | Should |
| 모든 쿼리 자동 주입 (개발자가 신경 안 써도 됨) | Could (단계 2) |

### 1.4 비목표 (Out of Scope)

- 모든 악의적 쿼리를 차단 (SQL 인젝션은 기존 allowlist + DSL 파라미터 바인딩으로 방어)
- DB 레벨 암호화, 행 단위 권한 관리(역할 기반)
- Query Registry (단계 3, 별도 문서)
- 여러 tenant 축의 다차원 정책 (1.0 에선 `user_id` / `owner_id` 같은 단일 축만)

---

## 2. 용어 정의

| 용어 | 의미 |
|---|---|
| **Tenant** | 데이터 격리 단위. 보통 사용자(`user_id`) 나 조직(`org_id`). 현 설계는 단일 축 기준. |
| **Tenant Column** | 해당 테이블에서 tenant 를 가리키는 컬럼명. 예: `orders.user_id` |
| **Session Claim** | 클라이언트 세션이 가진 tenant 식별자. 예: 로그인한 사용자의 `id` 또는 `sub` |
| **Policy** | 테이블에 대한 tenant 요구사항. `enforce` / `optional` / `none` |
| **검증 모드 (enforce-verify)** | WHERE 절을 파싱해 올바른 tenant 필터가 있는지 확인만 하고, 없으면 거부 |
| **자동 주입 모드 (enforce-inject)** | WHERE 절을 재작성해 tenant 필터를 서버에서 강제 추가 |

---

## 3. 아키텍처 개요

```
┌────────────────────────────────────────────────────────────────┐
│  빌드 타임 (dok build)                                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ backend/models/*.ts                                      │  │
│  │   user('users').ownedBy('id')                            │  │
│  │   order('orders').ownedBy('user_id')                     │  │
│  │   product('products').public()                           │  │
│  └──────────────────────────────────────────────────────────┘  │
│             │ 메타 추출 + sqlAllowlist.js                       │
│             ▼                                                   │
│  dist/dokkebi/sql-allowlist.json  (v2 스키마)                   │
│             │ 임베드                                             │
│             ▼                                                   │
│  worker/api/_dokkebi/db.ts  (Pages Function)                    │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│  런타임 (요청마다)                                              │
│  ┌──────────────┐    ┌────────────────┐    ┌─────────────────┐ │
│  │ 기존 6단계   │───▶│ Tenant Policy  │───▶│ executeD1Query  │ │
│  │ 파이프라인   │    │ Engine (7단계)  │    │                 │ │
│  └──────────────┘    └────────────────┘    └─────────────────┘ │
│                             │                                   │
│                             ├─ verify: WHERE 검증              │
│                             └─ inject: SQL 재작성               │
└────────────────────────────────────────────────────────────────┘
```

---

## 4. 단계 1 — 정책 메타데이터 + 검증 모드

### 4.1 선언 방식 (3가지 공존)

우선순위: **명시 정책 파일 > 모델 DSL 어노테이션 > 휴리스틱 추론**

#### (a) `backend/policy.ts` (명시 선언, 권장)

```typescript
// backend/policy.ts
import type { DokkebiPolicy } from 'dokkebi:runtime';

export const policy: DokkebiPolicy = {
  tenant: {
    source: 'session',          // 'session' | 'jwt-claim'
    claim: 'user_id',           // session.user_id 를 기본 tenant 로 사용
  },
  tables: {
    users:    { tenantColumn: 'id',       mode: 'enforce' },
    orders:   { tenantColumn: 'user_id',  mode: 'enforce' },
    products: { mode: 'none' },           // 공개 테이블
    posts:    { tenantColumn: 'author_id', mode: 'optional' }, // 부분 공개
  },
  // 기본 동작: 명시 안 된 테이블은 'none' (하위호환) 또는 'deny' (엄격)
  default: 'none',
};
```

#### (b) 모델 DSL 어노테이션 (DX 우선)

```typescript
// backend/models/order.model.ts
import { table } from 'dokkebi-dsl';

export const orders = table('orders')
  .ownedBy('user_id');     // ← 이 한 줄로 tenant 정책 자동 선언
```

#### (c) 휴리스틱 (마지막 폴백, **기본 비활성화**)

- 테이블에 `user_id` / `owner_id` / `tenant_id` / `author_id` 컬럼이 있으면 자동으로 `optional` 모드 등록
- 리스크: 오탐 가능 → 기본은 OFF, `dokkebi.config.js` 에서 `policy.inferFromColumns: true` 로만 활성화

### 4.2 v2 Allowlist 스키마

```json
{
  "version": 2,
  "tenant": {
    "source": "session",
    "claim": "user_id"
  },
  "tables": [
    {
      "name": "orders",
      "ops": ["SELECT", "INSERT", "UPDATE"],
      "policy": {
        "mode": "enforce",
        "tenantColumn": "user_id"
      }
    },
    {
      "name": "products",
      "ops": ["SELECT"],
      "policy": { "mode": "none" }
    }
  ],
  "rawAllowed": false,
  "defaultMode": "none",
  "generatedAt": "2026-04-20T00:00:00.000Z"
}
```

하위호환:
- `policy` 필드가 없는 테이블 → `defaultMode` 적용 (기본 `"none"`)
- v1 파일은 그대로 로드하되 모든 테이블이 `"none"` 모드로 간주 → **기존 프로젝트는 변경 없이 동작**

### 4.3 세션 컨텍스트

Pages Function 은 이미 세션을 D1 에 저장합니다 (`_dokkebi_sessions`). 여기에 선택 필드를 추가:

```sql
ALTER TABLE _dokkebi_sessions ADD COLUMN tenant_json TEXT;
-- {"user_id": "abc-123", "org_id": "acme"} 같은 JSON 직렬화
```

- 로그인 컨트롤러에서 `ctx.session.set('user_id', user.id)` 같은 API 호출 시 자동 갱신
- Pages Function 은 세션 조회 시 `tenant_json` 도 파싱해서 런타임 컨텍스트에 포함

### 4.4 검증 모드 알고리즘 (enforce-verify)

입력:
- `sql` (파싱 후 정규화), `params`, `tenantContext = { user_id: 'abc-123' }`

알고리즘:
```
for each table T referenced by sql:
  policy = allowlist.policy(T)
  if policy.mode == 'none':         continue
  if policy.mode == 'optional':     continue
  if policy.mode == 'enforce':
    tenantCol = policy.tenantColumn
    sessionClaim = tenant.claim              # e.g. 'user_id'
    expectedValue = tenantContext[sessionClaim]

    # SELECT/UPDATE/DELETE: WHERE 절에 `T.tenantCol = ?` 필수
    # INSERT: VALUES 에서 해당 컬럼 값이 = expectedValue 이어야 함

    if not hasTenantPredicate(sql, T, tenantCol, expectedValue):
      reject 403, reason = "tenant policy violation: $T requires $tenantCol = session.$sessionClaim"
```

#### 4.4.1 SELECT / UPDATE / DELETE

예) `SELECT * FROM orders WHERE user_id = ? AND status = 'paid'`

- WHERE 트리에서 `orders.user_id = ?` 조건을 찾아야 함
- `?` 의 위치에 해당하는 `params[i]` 가 `tenantContext.user_id` 와 일치해야 함
- `OR` 로 느슨해진 경우 거부 (예: `WHERE user_id = ? OR admin = 1`)
- `AND` 트리의 어딘가에 존재하면 OK

#### 4.4.2 INSERT

예) `INSERT INTO orders (user_id, total) VALUES (?, ?)`

- 컬럼 리스트에 `user_id` 가 있고, 대응하는 `params[0]` 가 `tenantContext.user_id` 와 일치해야 함
- 컬럼 리스트가 없는 `INSERT INTO orders VALUES (...)` 는 거부 (컬럼 순서 의존 방지)

#### 4.4.3 JOIN

예) `SELECT o.*, p.name FROM orders o JOIN products p ON p.id = o.product_id WHERE o.user_id = ?`

- 참조된 각 테이블마다 위 규칙 적용
- `products.mode == 'none'` 이면 pass, `orders` 는 `user_id` 검사

#### 4.4.4 Subquery / CTE

- CTE: WITH 절 내 SELECT 는 각각 독립 검사
- Subquery: 최상위 WHERE 와 동일 규칙으로 재귀 검사

### 4.5 파서 선택

- **1차 구현**: 기존 `sqlAllowlist.js` 의 정규식 기반 + 작은 전용 토크나이저 확장 (Cloudflare Workers 의 코드 크기 제약 고려)
- **정확도 한계**: 복잡한 서브쿼리는 오탐 가능 → `policy.strict: false` 에선 경고, `strict: true` 에선 거부
- **2차 업그레이드 옵션**: WASM-컴파일된 경량 SQL 파서 (`node-sql-parser` 의 Workers 호환 서브셋) — 초기 구현 안정화 후 검토

### 4.6 실패 시 응답

```json
{
  "error": "tenant 정책 위반: orders.user_id 조건이 세션 user_id 와 일치하지 않습니다.",
  "code": "TENANT_POLICY_VIOLATION",
  "table": "orders",
  "expectedClaim": "user_id"
}
```

- HTTP 403
- `_dokkebi_security` 에 `tenant_violation` 이벤트 기록

### 4.7 환경변수 / 모드

| 변수 | 기본값 | 의미 |
|---|---|---|
| `DOKKEBI_POLICY_MODE` | `verify` (v2 프로젝트), `off` (v1 프로젝트) | `off` / `verify` / `inject` / `deny-all` |
| `DOKKEBI_POLICY_STRICT` | `true` | 파싱 실패 시 거부할지(`true`) 통과할지(`false`) |

### 4.8 최소 변경 범위 (단계 1)

- `src/core/sqlAllowlist.js` — v2 스키마 지원, `extractAllowlist()` 에서 정책 추출
- `src/core/policyExtractor.js` (신규) — `backend/policy.ts` 파싱 / 모델 DSL 어노테이션 수집
- `src/core/projectGenerator.js` — Pages Function 템플릿에 tenant 검증 섹션 삽입 (v4 → v5)
- `src/commands/build.js` — v2 allowlist 임베드
- `src/commands/serve.js`, `src/commands/dev.js` — 동일 검증 로직 호출
- `docs/design/TENANT_POLICY.md` — 본 문서

---

## 5. 단계 2 — 자동 주입 모드 (enforce-inject)

### 5.1 개념

단계 1이 "개발자가 빠뜨렸으면 차단" 이라면, 단계 2는 "개발자가 빠뜨려도 서버가 채워준다".

장점:
- 개발자가 매번 `WHERE user_id = ctx.user.id` 를 쓰지 않아도 됨
- 누락에 의한 누출을 **전면 차단**

단점:
- SQL 재작성 = 복잡도 ↑, 파서 정확도에 강하게 의존
- 이미 tenant 조건이 있는 쿼리는 중복 주입 방지 필요

### 5.2 주입 규칙

| 연산 | 재작성 |
|---|---|
| SELECT | `SELECT ... FROM T` → `SELECT ... FROM T WHERE T.<tenantCol> = ?` (기존 WHERE 가 있으면 `AND` 로 병합) |
| UPDATE | `UPDATE T SET ... WHERE ...` → `UPDATE T SET ... WHERE (...) AND T.<tenantCol> = ?` |
| DELETE | `DELETE FROM T WHERE ...` → `DELETE FROM T WHERE (...) AND T.<tenantCol> = ?` |
| INSERT | 컬럼 리스트에 `<tenantCol>` 없으면 추가 + params 끝에 `tenantContext.<claim>` append |
| JOIN | 각 테이블마다 독립 주입, 테이블 별칭 사용 |

### 5.3 파라미터 처리

- 재작성된 SQL 은 `?` 파라미터가 N+k 개로 늘어남 (k = 주입된 tenant 수)
- `params` 배열에 `tenantContext[claim]` 을 **튜플 끝**에 append
- D1 은 positional parameter 이므로 순서 유지가 중요 → 파서가 AST 에서 `?` 인덱스를 정확히 추적해야 함

### 5.4 중복 주입 방지

이미 `WHERE T.tenant_col = ?` 이 있는 쿼리는 재주입하지 않음 (값이 일치하는 경우) / 불일치하면 거부.

### 5.5 옵트인 / 단계적 롤아웃

- 프로젝트 생성 시 기본값: **단계 1(verify) 모드**
- 단계 2 활성화는 명시적 선택: `dokkebi.config.js` 의 `security.policyMode: 'inject'`
- 또는 테이블 단위: `{ "mode": "inject" }`

### 5.6 테스트 전략

- 단위 테스트: 100+ SQL 샘플 (SELECT / JOIN / UNION / CTE / subquery / INSERT 변형)
- 퍼지 테스트: 난수 SQL 생성기로 주입 전/후 비교
- 프로퍼티 테스트: "주입 후 SQL = 주입 전 SQL + tenant 조건" 이 논리적으로 성립하는지

---

## 6. 파일별 변경 맵

| 파일 | 단계 1 | 단계 2 |
|---|---|---|
| `src/core/sqlAllowlist.js` | v2 스키마 파싱, 정책 정보 포함 | 주입 엔진 호출부 추가 |
| `src/core/policyExtractor.js` (신규) | backend/policy.ts + 모델 DSL 어노테이션 추출 | 변화 없음 |
| `src/core/policyEngine.js` (신규) | `verifyTenantPolicy(sql, params, ctx, allowlist)` | `injectTenantPolicy(sql, params, ctx, allowlist)` |
| `src/core/projectGenerator.js` | Pages Function 템플릿에 policy 검증 삽입 (v4 → v5) | inject 모드 코드 추가 |
| `src/commands/build.js` | v2 allowlist 임베드 | 동일 |
| `src/commands/serve.js` / `dev.js` | `policyEngine.verifyTenantPolicy()` 호출 | `injectTenantPolicy()` 분기 |
| `src/runtime/session.js` (신규 또는 기존 확장) | 세션 `tenant_json` API | 동일 |
| `backend/policy.ts` (템플릿) | 예제 정책 파일 | 동일 |
| `dokkebi-dsl` | `.ownedBy(col)` API 추가 | 동일 |
| `SECURITY.md` | v2 + verify 모드 문서화 | inject 모드 섹션 |
| `frontend/src/pages/Security.tsx` (dokkebi-site) | 섹션 추가 | 업데이트 |

---

## 7. 마이그레이션 / 호환성

### 7.1 v1 → v2

- `dok build` 가 자동으로 v2 allowlist 를 생성
- `backend/policy.ts` 가 없으면 모든 테이블은 `mode: "none"` 으로 채워짐 → 기존 앱 그대로 동작
- 운영자가 점진적으로 테이블별 정책을 선언 → 각 테이블이 `enforce` 로 전환

### 7.2 v4 → v5 Pages Function

- `@dokkebi-version: 4` (allowlist 임베드) → `@dokkebi-version: 5` (정책 엔진 탑재)
- `dok update --force && dok build` 1회면 업그레이드 완료
- 기존 v4 프로젝트는 v5 템플릿에서도 `mode: "off"` 로 동작 (정책 선언 없음)

### 7.3 명령 추가

```bash
# 정책 상태 진단: 현재 allowlist 가 어떤 모드로 로드되는지 출력
dok policy status

# 정책 선언 점검: policy.ts 와 실제 모델/테이블 간 미스매치 검출
dok policy lint

# 샘플 쿼리로 검증 모드 드라이런
dok policy check "SELECT * FROM orders WHERE id = ?"
```

---

## 8. 테스트 계획

### 8.1 단위

- `policyEngine.verifyTenantPolicy()`
  - 정상 쿼리 통과
  - WHERE 누락 거부
  - OR 로 느슨해진 조건 거부
  - 다른 tenant 값 거부
  - JOIN 에서 일부 테이블만 정책 있는 경우
  - CTE / subquery
  - INSERT 컬럼 리스트 누락 거부

### 8.2 통합

- `dok build` → v2 allowlist 생성 확인
- Pages Function 템플릿 v5 생성 확인
- 실제 요청 플로우: 합법 → 통과, 위반 → 403 + 이벤트 기록

### 8.3 회귀

- v1 allowlist 프로젝트는 여전히 동작
- v4 Pages Function 과의 동시 배포 (점진 롤아웃 시나리오)

### 8.4 성능

- 단순 SELECT 오버헤드 측정 (+0.1ms 목표)
- JOIN 3테이블 쿼리 오버헤드 (+0.3ms 목표)
- 파서 실패율 < 1% (퍼지 코퍼스 기준)

---

## 9. 로드맵

| 스프린트 | 내용 | 예상 기간 |
|---|---|---|
| **S1** | v2 allowlist 스키마 + 파서 + 검증 모드 (단계 1) | 2-3일 |
| S1.1 | `backend/policy.ts` 로더 + 모델 DSL `.ownedBy()` | 1일 |
| S1.2 | 런타임 `policyEngine.verifyTenantPolicy()` + Pages Function 템플릿 v5 | 1-2일 |
| S1.3 | 테스트 커버리지 + 문서 + CLI (`dok policy status/lint/check`) | 1일 |
| S1.4 | dokkebi-site 문서 반영 + SECURITY.md 업데이트 | 0.5일 |
| **S2** | 자동 주입 모드 (단계 2) | 3-5일 |
| S2.1 | `injectTenantPolicy()` + AST 기반 재작성 | 2-3일 |
| S2.2 | 중복 주입 방지 / 파라미터 인덱스 관리 | 1일 |
| S2.3 | 퍼지/프로퍼티 테스트 | 1일 |
| (옵션) S3 | Query Registry 설계 + 구현 — 별도 문서 | 1-2주 |

---

## 10. FAQ / 알려진 한계

### Q1. 동적 테이블명을 쓰는 쿼리는?

- 파싱 실패 → `strict=true` 면 거부. 동적 테이블은 애초에 `dokkebi-dsl` 에서 권장하지 않음.

### Q2. `SELECT COUNT(*) FROM orders` 같이 집계만 하는 쿼리?

- `enforce` 모드에선 여전히 tenant 조건 필수 → `WHERE user_id = ?` 필요
- 전체 통계가 필요한 관리자 UI 는 별도 공개 테이블 또는 `mode: "none"` 로 등록된 뷰 사용

### Q3. 복수 tenant (예: user + org) 는?

- 1.0 은 단일 축. 2.0 에서 `policy.tenants: [...]` 와 `policy.tenantColumns: { user_id, org_id }` 로 확장 예정

### Q4. 관리자(admin)는 어떻게 우회?

- 관리자 세션은 `tenant_json.isAdmin = true` 로 표시 + Pages Function 이 관리자 세션에 한해 정책 bypass
- 단, **관리자 API 경로는 별도 엔드포인트로 분리** 권장 (공격 표면 최소화)

### Q5. 공격자가 tenant 값을 조작하면?

- `params` 에 들어가는 tenant 값은 **클라이언트가 아닌 서버 세션에서만 가져옴**
- 클라이언트가 `user_id = 'other'` 로 바꿔 보내도 서버가 `session.user_id` 로 재비교해 거부

### Q6. 기존 RAW SQL 기반 앱과의 호환?

- `allowlist.rawAllowed: true` + `policyMode: "off"` 로 현재 동작 유지
- 점진 마이그레이션: DSL 도입 → 정책 선언 → 테이블별 `enforce` 전환

---

## 11. 부록 A — index.html 부트스트랩 노출 분석 (별첨 이슈)

### 11.1 현상

빌드 산출물의 `index.html` 에 ECDH 핸드셰이크·OPFS 캐시·WASM 로더 부트스트랩 JS 가 평문으로 삽입되어 있음.

### 11.2 위험도 평가

| 항목 | 노출되는가? | 실제 영향 |
|---|---|---|
| DB 자격증명 / API 토큰 | ❌ | Opaque Handle 패턴으로 Cloudflare 환경변수에만 존재 |
| 세션 마스터 키 | ❌ | 런타임 ECDH 로 생성, 서버/클라 각각 독립 계산 |
| 백엔드 비즈니스 로직 | ❌ | WASM(QuickJS) 내부, JS 로 평문 노출 안 됨 |
| ECDH 엔드포인트 경로 | ⚠️ | `/api/_dokkebi/handshake` 는 어차피 HTTP 트래픽으로 관찰 가능 |
| 암호화 알고리즘 | ⚠️ | AES-256-GCM / HMAC-SHA256 — 공개 표준, Kerckhoffs 원칙상 노출되어도 OK |
| 빌드 버전 / 빌드 해시 | ⚠️ | `window.__DOKKEBI_BUILD_VER__` — 공격 표면 맵핑에 쓸 수 있는 minor info |
| OPFS 경로 / DB 파일명 | ⚠️ | 클라이언트 측 캐시 — 공격자 자기 브라우저에서만 의미 |

**결론: Kerckhoffs 원칙에 따라 "알고리즘 공개는 문제가 아님". 실제 비밀(키, 토큰, 로직)은 노출되지 않음 → 심각한 보안 문제는 아님.**

### 11.3 그래도 하드닝 가치가 있는 항목 (우선순위 순)

1. **빌드 해시/버전 노출 최소화**
   - `window.__DOKKEBI_BUILD_VER__` 를 전역 `window` 에 두지 말고 클로저 내부에 격리
   - 또는 해시 대신 의미없는 난수 빌드 ID

2. **console.log 배너/디버그 로그 프로덕션 비활성화**
   - 현재 `console.log('%c 🔮 DOKKEBI ...')` 는 개발자 어필용 브랜딩이지만 공격자에겐 실마리
   - `dokkebi.config.js` 에 `verboseBootstrap: false` 옵션 도입, 배포 시 배너/로그 제거

3. **외부 리소스 SRI (Subresource Integrity)**
   - 현재 부트스트랩 자체는 인라인이라 OK
   - 추후 `bundle.js`, `dokkebi-qjs.js` 를 `<script src>` 로 분리할 경우 SRI 필수

4. **CSP 더 타이트하게**
   - `script-src 'self' 'sha256-<인라인 스크립트 해시>'` 로 이 인라인 부트스트랩만 허용
   - 현재 `'unsafe-inline'` 이 있다면 제거 (부트스트랩 해시 빌드 타임 계산)

5. **WASM 쪽으로 더 민감 로직 이관** (③ 답변 참고)
   - 키 파생(HKDF)/HMAC 계산을 QuickJS 내부로 이동
   - JS glue 는 `fetch` + 바이트 전달만 하는 얇은 shell 로 축소
   - 단, Web Crypto API 경계는 브라우저 제약상 완전히 없앨 수 없음

6. **부트스트랩 자체 minify + 변수명 난독화**
   - ①에서 `minify: true` 가 이미 적용됨 — 번들은 압축되지만, `index.html` 에 박히는 부트스트랩은 별도 경로
   - `injectBootstrapAll()` 에서 minify 옵션을 추가해 배포 빌드 시 압축

### 11.4 우선순위 권고

- **즉시 적용 가치 높음 (낮은 비용, 확실한 이득)**: 1, 2, 6
- **중기**: 3, 4 (사용자 프로젝트별 CSP 정책 필요)
- **장기 / 큰 변경**: 5 (QuickJS 내부 암호 구현 — 성능 트레이드오프 필요)

필요하시면 이 부록의 1·2·6 항목도 Tenant Policy 와 별개로 빠르게 적용해드릴 수 있습니다.

---

## 12. 변경 이력

- **2026-04-20 (v0.1)**: 초안 작성 — 사용자 요청에 따른 단계 1 + 단계 2 설계. index.html 부트스트랩 노출 분석 부록 추가.
