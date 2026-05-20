# Query Registry (Stage 3) — 설계 문서

> 관련 문서: [`TENANT_POLICY.md`](./TENANT_POLICY.md) (Stage 1, 2)
>
> 이 문서는 도깨비 프레임워크의 **Stage 3 — Query Registry (사전 등록 쿼리)** 설계를 정의합니다.
> Stage 1(Tenant Verify)·Stage 2(Tenant Inject)에 이어지는 마지막 단계이며, 이 단계가 완료되면
> 클라이언트는 **SQL 문자열 자체를 서버로 전송할 수 없고**, 빌드 타임에 등록된 `queryId` 만 사용 가능합니다.

---

## 0.0 단계 간 의존성 · 기본값 정책 (프레임워크 철학)

도깨비는 단일 사용자 앱부터 멀티테넌트 SaaS 까지 **다양한 유스케이스** 를 지원하는 프레임워크입니다. 따라서 각 단계는 **독립적으로 opt-in / opt-out** 가능하도록 설계됩니다.

| 단계           | 보호 대상                          | 기본값              | 활성화 방법                                                               | 의존성                  |
| -------------- | ---------------------------------- | ------------------- | ------------------------------------------------------------------------- | ----------------------- |
| Allowlist      | 테이블/연산 레벨 SQL 허가          | ON (v4 부터)        | 항상 활성 (방어 깊이)                                                     | 없음                    |
| **Stage 3 (본 문서)** | SQL shape 레벨 허가          | **ON (v5 기본)**    | `queryRegistry.enabled: false` 로 opt-out                                  | 없음 (독립)             |
| Stage 1        | 테넌트 컬럼 누락 감지              | OFF                 | `policy.enabled: true, policy.mode: 'enforce-verify'`                      | Stage 3 권장             |
| Stage 2        | 테넌트 조건 자동 주입              | OFF                 | `policy.mode: 'enforce-inject'`                                            | Stage 1 전제             |

### 런타임 모드 (`DOKKEBI_QUERY_MODE` Pages 환경변수)

| 모드        | queryId 매치 | queryId 미등록           | queryId 없이 sql 전송 | 권장 사용                |
| ----------- | ------------ | ------------------------ | --------------------- | ------------------------ |
| **`auto`**  | 매치 SQL 실행 | `_debugSql`/`sql` 로 폴백 | 허용                  | **기본값** (신규/기존 앱 모두 안전) |
| **`strict`** | 매치 SQL 실행 | 403 거부                | 레지스트리 있으면 거부 | 완전 보호 (학습 완료 후 opt-in)  |
| **`learn`**  | 매치 SQL 실행 | `_debugSql` 로 폴백 + 로그 | 허용                  | dev 모드 전용                  |
| **`legacy`** | 매치 SQL 실행 | `sql` 필드로 폴백        | 허용                  | v4 호환 과도기                 |

> **핵심**: 어느 모드든 SQL Allowlist + 공통 방어(dangerous token, multi-statement 차단 등) 는 **항상 실행** 되어 방어 깊이를 유지합니다. Query Registry 는 그 위에 얹히는 **추가** 보호 레이어입니다.

**opt-in strict 활성화 방법:**

1. `dokkebi.config.js`
```js
export default {
  queryRegistry: { enabled: true, strict: true },
};
```

2. 배포 플래그
```bash
dok deploy --strict-registry
```

3. Cloudflare Pages 대시보드에서 환경변수 직접 설정
```
DOKKEBI_QUERY_MODE=strict
```

### 구현 및 릴리스 순서 (권장)

```
v5.0 — Stage 3 (Query Registry) 단독 릴리스  [약 1.5 ~ 2주]
  └─ 모든 앱이 자동 혜택 (단일 사용자 앱도 SQL shape 고정 혜택)

v5.1 — Stage 1 (Tenant Verify) opt-in 추가   [+1주]
v5.2 — Stage 2 (Tenant Inject) opt-in 추가   [+1주]
```

**결정 근거**: Stage 3 는 테넌트 유무와 무관하게 모든 앱에 즉시 이득을 주고, Stage 1·2 의 메타데이터를 레지스트리 엔트리에 얹을 수 있어 자연스러운 확장 기반이 됩니다. 자세한 근거는 [TENANT_POLICY.md §0.0](./TENANT_POLICY.md#00-단계-간-의존성--기본값-정책-프레임워크-철학) 참조.

---

## TL;DR

- 현재 도깨비는 WASM 게스트 내부의 DSL 이 SQL 문자열을 만들어 `_execSql(sql, params)` 로 호출한다.
  이 SQL 은 암호화되어 전송되지만, **서버 입장에서는 "클라이언트가 보낸 문자열"** 이므로 SQL allowlist 로 후처리 검증해야 한다.
- Query Registry 는 이 흐름을 뒤집는다: **빌드 타임에 모든 허용 SQL 을 수집해 `queryId → SQL` 레지스트리를 만들고,
  런타임에는 `queryId + params` 만 전송**한다. 서버는 레지스트리에서 SQL 을 찾아 실행하므로
  "클라이언트가 보낸 SQL 문자열" 자체가 존재하지 않는다.
- 결과적으로 **SQL Injection / Allowlist 우회 / 동적 쿼리 조작 공격 면이 사실상 소멸**한다.
- 도깨비 DSL 구조상 삽입 지점이 `QueryBuilder._compile()` 단 하나라 구현 난이도는 중간 수준이다.
- 기간 예상: **1.5 ~ 2 주 (S3.1 ~ S3.5)**.

### 수집 경로 (v5 기준 — `dok build` / `dok deploy` 자동)

| 경로                                        | 시점          | 대상                                                                  | 비고                              |
| ------------------------------------------- | ------------- | --------------------------------------------------------------------- | --------------------------------- |
| **(a) 정적 스캔** (`queryScanner.js`)       | 빌드 타임     | `backend/**`, `src/backend/**`, `functions/**` 의 SQL 문자열 리터럴   | **자동** — 기본 ON                |
| (b) 주석 선언 (`// @dokkebi-query: ...`)    | 빌드 타임     | `backend/**/*.{ts,js}` 주석                                           | 동적 SQL 수동 등록용              |
| (c) 런타임 학습                             | `dok dev` 실행 | `.dokkebi/query-registry.learned.json`                                | dev 에서 실행된 쿼리만            |

**(a) 정적 스캔 상세**:
- `.prepare('...')`, `.prepare("...")`, `.prepare(\`...\`)`, 자유 string literal 의 첫 토큰이
  `SELECT / INSERT / UPDATE / DELETE / WITH / REPLACE / CREATE TABLE / CREATE INDEX` 인 경우 자동 수집
- 템플릿 리터럴의 `${...}` interpolation 은 `?` 로 수렴 후 canonical 화 — DSL/SQL tag 템플릿 대부분 커버
- 주석(`//`, `/* */`) 내 SQL 은 제외
- 비활성화: `dokkebi.config.js` 의 `queryRegistry.scan: false`
- 스캔 루트 커스터마이즈: `queryRegistry.scanRoots: ['server', 'api']`

---

## 1. 배경

### 1.1 현재 요청 흐름 (v4 기준)

```
[WASM 게스트]
  backend/controllers/users.controller.ts
    db.select(users).where(eq(col('id'), userId)).exec()
         │
         ▼
  QueryBuilder._compile() → { sql: 'SELECT * FROM "users" WHERE "id" = ?', params: [42] }
         │
         ▼
  runtime._execSql(sql, params)  ← ❶ SQL 문자열이 여기서 생성됨
         │
         ▼ (host 호출)
[WASM 호스트 브릿지]
  암호화 패키징 → POST /api/_dokkebi/db  ← ❷ SQL 문자열이 네트워크로 나감
         │
         ▼
[Pages Function]
  복호화 → validateSqlAllowlist(sql) → D1.prepare(sql).bind(params)  ← ❸ 서버가 SQL 문자열을 해석
```

### 1.2 무엇이 문제인가

| 계층 | 현재 방어                                      | 여전히 남는 리스크                                                            |
| ---- | ---------------------------------------------- | -------------------------------------------------------------------------- |
| ❶    | DSL 사용 시 자동 prepared (`?` placeholder)    | WASM 내부 바이너리가 분석되면 원 SQL 구조가 드러남                          |
| ❷    | ECDH + HKDF + AES-GCM + HMAC                   | 세션만 확보되면 **임의 SQL** 을 합법적으로 암호화해서 서버로 보낼 수 있음   |
| ❸    | SQL Allowlist 검증 (v2 임베드)                 | allowlist 가 `SELECT * FROM users` 를 허용하면 공격자도 그 범위 내에서 임의 쿼리 작성 가능 (예: `SELECT password_hash FROM users`) |

**핵심 문제**: allowlist 는 "어떤 테이블/어떤 연산" 수준의 허용이지, "어떤 **쿼리 모양**" 의 허용이 아니다.
공격자는 allowlist 허용 범위 안에서 컬럼을 바꾸거나 `WHERE` 를 제거하거나 `ORDER BY` 를 추가해 정보를 추출할 수 있다.

### 1.3 Query Registry 가 해결하는 것

- SELECT 컬럼 목록 변경 차단 (`password_hash`, `salt` 등 민감 컬럼 노출 방지)
- WHERE 제거·변형 차단 (`SELECT * FROM orders WHERE user_id = ?` 만 허용되고 `WHERE user_id IS NOT NULL` 불가)
- 조건 순서·논리 조작 차단 (`WHERE a = ? OR 1=1` 등)
- 개발자가 명시적으로 작성하지 않은 쿼리 전체 차단

---

## 2. 목표 / 비목표

### 목표
1. 클라이언트는 **네트워크로 SQL 문자열을 보내지 않는다**. `{ queryId, params }` 만 전송한다.
2. 서버는 `queryId` 를 **빌드 타임 레지스트리** 로만 조회한다. 런타임 등록 불가 (`deploy` 환경).
3. Stage 1, 2 의 Tenant Policy 는 레지스트리 매칭 후 서버측에서 SQL 에 주입된다.
4. 기존 DSL API (`db.select(users).where(...)`) 는 **소스 레벨 변경 없이** 작동한다.
5. `dev` 모드에서는 레지스트리 자동 수집 + warn, `deploy` 에서는 strict fail-closed.

### 비목표
- Raw SQL 을 직접 작성하는 경우의 완전한 지원 (후술 — 제한적 폴백 제공).
- 전혀 다른 쿼리 인터페이스 (GraphQL 등) 로의 대체.
- 런타임 최적화 (prepared statement 캐싱) — Cloudflare D1 이 이미 처리.

---

## 3. 용어

| 용어              | 정의                                                                 |
| ----------------- | -------------------------------------------------------------------- |
| Query Shape       | 파라미터를 제외한 SQL 문자열 (placeholder `?` 만 남은 정규화된 형태) |
| Query ID          | Query Shape 의 SHA-256 prefix (예: `q_a3f9b2c1`)                     |
| Registry          | `{ queryId → { sql, meta } }` 맵. 빌드 결과물                        |
| Registry Entry    | 레지스트리의 단일 항목 — 원본 SQL, 출처 파일, 정책 메타 포함         |
| Dry-Run 수집      | 빌드 타임에 controllers 를 QuickJS 샌드박스에서 실행해 shape 추출    |
| AST 추출          | TypeScript compiler API 로 DSL 체인을 정적으로 파싱                  |
| Shape Canonicalization | 공백·대소문자·quote 정규화로 같은 쿼리의 해시 일치 보장         |

---

## 4. 두 가지 구현 접근 — 비교 및 선택

Query Registry 를 실제로 채우는 방법은 크게 두 가지다. **두 접근은 배타적이 아니며 혼용한다.**

### 4.A) **런타임 해싱 + 빌드 타임 Dry-Run 수집** (권장, 우선 구현)

```
[빌드 타임]
  dok build
    ├─ bundleBackend()                  ← 기존
    ├─ 샌드박스 실행:
    │    runtime._execSql = (sql, params) => registry.add(canonicalize(sql))
    │    ↓
    │    controllers/* 의 핸들러들을 "probe input" 으로 호출
    │    (각 핸들러에 대해 샘플 req/ctx 를 넣어 실행)
    └─ query-registry.json 생성 → Pages Function 에 임베드
[런타임]
  WASM 내부 DSL._compile() → { sql, params }
    ├─ queryId = sha256(canonicalize(sql)).slice(0,16)
    └─ _execQuery({ queryId, params })   ← SQL 문자열 전송 안 함
[Pages Function]
  queryId 로 레지스트리 lookup → 등록된 SQL + tenant policy inject → D1.prepare().bind(params).run()
  (레지스트리에 없으면 즉시 403)
```

**장점**
- AST 파싱 불필요 — DSL 이 이미 SQL 을 만드는 로직을 그대로 활용
- 조건부 분기로 생기는 모든 shape 자동 수집 (핸들러 dry-run 커버리지만 충분하면)
- 기존 DSL 코드 수정 최소 (`_compile()` 반환부에 해시 추가 한 줄)

**단점**
- 핸들러가 실제 DB 결과에 의존하는 로직 (예: "조회 결과가 비면 다른 쿼리 실행") 은 dry-run 으로 전부 커버되지 않음 → dev 모드 자동 학습으로 보완 필요
- 부수 효과 (외부 API 호출 등) 가 있는 핸들러는 샌드박스에서 stub 처리 필요

### 4.B) **빌드 타임 정적 AST 추출 + 컴파일 치환**

```
[빌드 타임]
  esbuild 플러그인 또는 ts-morph 로 controllers AST 스캔
    ├─ db.select(users).where(...).exec() 체인 발견
    ├─ 빌드 타임에 해당 체인을 _compile() 실행 → SQL 생성
    └─ 소스코드 변환: db.select(...)...exec() → db.__executeById('q_a3f9b2c1', params)
```

**장점**
- 런타임에 DSL → SQL 변환 자체가 사라짐 → 클라이언트 번들 크기 감소
- SQL 생성 로직이 클라이언트에 없으므로 **WASM 리버싱 시에도 쿼리 구조가 드러나지 않음**
- 가장 강력한 방어

**단점**
- 구현 복잡도 매우 높음 (TypeScript AST, 타입 추론, 동적 분기)
- `db[tableName].select().where(...)` 같은 동적 테이블명은 정적 분석 불가
- 조건부 체인이 많으면 컴파일 시 폭발적으로 모든 조합 생성해야 함

### 결정 — **하이브리드, 4.A 우선**

| Phase   | 접근 | 비고 |
| ------- | ---- | ---- |
| Stage 3.1 | 4.A (런타임 해싱 + dry-run) | 1 주 내 도입 가능, 커버리지 95% 수준 목표 |
| Stage 3.2 | 4.A + dev 자동 학습 | 런타임에 빠진 shape 자동 등록 (dev 모드만) |
| Stage 3.3 | 4.B 선택적 | DSL 이 "단순 체인" 으로 확정 가능한 경우만 AST 치환 적용 (WASM 크기 최적화 용) |

이 문서는 **Stage 3.1 + 3.2** 를 상세히 기술하고, 3.3 은 개요만 제시한다.

---

## 5. 아키텍처

### 5.1 레지스트리 파일 스키마 (v1)

**파일**: `dist/dokkebi/query-registry.json` (빌드 산출물)

```json
{
  "version": 1,
  "generatedAt": "2026-04-20T00:00:00Z",
  "buildHash": "6e5e992ac715",
  "queries": {
    "q_a3f9b2c1d4e5f678": {
      "sql": "SELECT \"id\", \"email\" FROM \"users\" WHERE \"id\" = ?",
      "paramCount": 1,
      "paramTypes": ["number"],
      "tables": ["users"],
      "op": "SELECT",
      "tenantPolicy": "enforce-verify",
      "tenantColumn": "user_id",
      "sources": [
        { "file": "backend/controllers/user.controller.ts", "symbol": "getUser" }
      ]
    },
    "q_8c1e0f2a6b9d3e40": {
      "sql": "INSERT INTO \"orders\" (\"user_id\", \"item\", \"qty\") VALUES (?, ?, ?)",
      "paramCount": 3,
      "paramTypes": ["number", "string", "number"],
      "tables": ["orders"],
      "op": "INSERT",
      "tenantPolicy": "enforce-inject",
      "tenantColumn": "user_id",
      "sources": [
        { "file": "backend/controllers/order.controller.ts", "symbol": "createOrder" }
      ]
    }
  }
}
```

### 5.2 Shape Canonicalization 규칙

레지스트리 매칭의 일관성을 위해 SQL 을 canonical form 으로 변환한 뒤 해싱한다.

1. 문자열 리터럴·숫자 리터럴 → `?` (이미 DSL 에서 처리)
2. 연속 공백 → 단일 공백
3. 앞뒤 공백 제거
4. 식별자 `"column"` 대소문자는 **보존** (D1/SQLite 는 double-quote 내부 대소문자 구분)
5. 키워드 (`SELECT`, `FROM`, `WHERE`, ...) 는 **UPPERCASE** 로 정규화
6. 주석 제거 (`--`, `/* */`)

```js
function canonicalizeSql(sql) {
  let s = stripStringsAndComments(sql);  // 기존 sqlAllowlist 유틸 재사용
  s = s.replace(/\s+/g, ' ').trim();
  s = s.replace(/\b(select|from|where|insert|into|values|update|set|delete|order\s+by|limit|offset|returning)\b/gi,
                (m) => m.toUpperCase().replace(/\s+/g, ' '));
  return s;
}

function computeQueryId(sql) {
  const canonical = canonicalizeSql(sql);
  const hash = crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return 'q_' + bytesToHex(hash).slice(0, 16);
}
```

### 5.3 빌드 타임 (Stage 3.1)

새 모듈: `src/core/queryRegistry.js`

```
src/core/queryRegistry.js
  ├── collectQueriesByDryRun(projectDir, opts)   // 핵심: probe 실행
  ├── collectQueriesByStatic(projectDir, opts)   // 3.3 용 placeholder
  ├── canonicalizeSql(sql)
  ├── computeQueryId(sql)
  ├── writeRegistry(registry, outPath)
  └── mergeWithTenantPolicy(registry, policyMeta) // Stage 2 통합
```

**Dry-run 수집 플로우** (`collectQueriesByDryRun`):

1. `bundleBackend()` 결과 JS 를 QuickJS (Node 의 `quickjs-emscripten` 또는 기존 빌드 파이프라인) 에 로드
2. 런타임 stub 주입:
   ```js
   const registry = new Map();
   const runtime = {
     _execSql: async (sql, params) => {
       const id = computeQueryId(sql);
       registry.set(id, { sql: canonicalizeSql(sql), ... });
       return { ok: true, value: { rows: [] } };       // 빈 결과 반환
     },
     // fetch, crypto, now, jwt 등은 본격 stub
   };
   ```
3. controllers 에서 export 된 핸들러를 probe 입력으로 호출:
   - `req.params`, `req.query`, `req.body` 에 **shape-generating** 스텁 값 (빈 string, 0, {}) 주입
   - 분기 coverage 를 위해 probe 여러번 호출 (특히 `if (x) { A } else { B }` 형태)
4. 수집된 shape 을 `writeRegistry()` 로 기록

**한계와 보완**:
- "결과에 따라 다른 쿼리" — dry-run 은 첫 호출만 커버. 이 경우:
  - 개발자는 `backend/queries.ts` (신규) 에 명시적으로 쿼리를 선언해 레지스트리에 강제 포함 가능
  - `dev` 모드에서 실제 사용 시 등장하는 shape 을 자동 학습 (3.2)

**CLI 통합 (build.js)**:

```js
// dokkebi-cli/src/commands/build.js (추가)
import { collectQueriesByDryRun, writeRegistry } from '../core/queryRegistry.js';

// ... bundleBackend + buildQuickJSBundle 완료 후
if (config.queryRegistry !== false) {
  const registry = await collectQueriesByDryRun(projectDir, { bundlePath });
  await writeRegistry(registry, path.join(outDir, 'dokkebi', 'query-registry.json'));

  // Pages Function 템플릿에 임베드 (allowlist 와 동일 패턴)
  regenerateServerlessDb({ registry, allowlist });
}
```

### 5.4 런타임 — 클라이언트 DSL 변경 (Stage 3.1)

**파일**: `packages/dokkebi-dsl/src/index.js`

`QueryBuilder.exec()` 와 `createDb().raw()` 를 수정:

```js
// BEFORE
async exec() {
  const { sql, params } = this._compile();
  const result = await this._runtime._execSql(sql, params);
  // ...
}

// AFTER
async exec() {
  const { sql, params } = this._compile();
  if (this._runtime._execQuery) {                       // 새 경로: Query Registry 모드
    const queryId = await computeQueryIdSync(sql);
    const result = await this._runtime._execQuery({ queryId, params, _debugSql: sql });
    // _debugSql 은 dev 모드에서만 서버가 경고/자동 학습에 사용
    // ...
  } else {                                              // 폴백: 기존 _execSql
    const result = await this._runtime._execSql(sql, params);
    // ...
  }
}
```

- `_execQuery` 는 호스트 브릿지 (Pages Function 경로) 에서 구현
- `_execSql` 은 **로컬 DB 모드 (sql.js)** 전용으로 유지 — 로컬 모드는 레지스트리 없이 동작
- `computeQueryIdSync` 는 WebCrypto `subtle.digest` 동기 래퍼 (WASM 내부 async OK)

### 5.5 런타임 — Pages Function 변경 (Stage 3.1)

**파일**: `worker/api/_dokkebi/db.ts` (projectGenerator.js 템플릿)

현재 흐름:
```
verifyHmac → decryptAesGcm → JSON.parse(plaintext) → { sql, params } → allowlist.validate(sql) → D1.prepare(sql).bind(params)
```

신규 흐름 (v5):
```
verifyHmac → decryptAesGcm → JSON.parse(plaintext) → { queryId, params, _debugSql? }
  ├─ if (env.DOKKEBI_QUERY_MODE === 'strict')
  │    entry = REGISTRY[queryId]
  │    if (!entry) return 403 "queryId not registered"
  │    sql = entry.sql
  │
  └─ else if (env.DOKKEBI_QUERY_MODE === 'learn')   // dev 전용
       entry = REGISTRY[queryId]
       if (!entry) {
         // _debugSql 을 재캐노니컬라이즈 → 해시 매칭 확인
         // 일치하면 자동 등록 + 경고
         // 불일치면 403
       }
       sql = entry?.sql ?? _debugSql
  ↓
  tenantPolicy.verify(sql, session) || tenantPolicy.inject(sql, session)    // Stage 1, 2
  ↓
  allowlist.validate(sql)            // 방어 깊이 — 여전히 유지
  ↓
  D1.prepare(sql).bind(...params).run()
```

**임베드 크기**: 레지스트리는 쿼리 수 × 평균 200B. 1000 개 쿼리 = 약 200KB. Pages Function 크기 제한 (1MB) 내에서 충분.

### 5.6 Dev 모드 자동 학습 (Stage 3.2)

`dok dev` 실행 시:
- `DOKKEBI_QUERY_MODE=learn` 자동 설정
- 레지스트리에 없는 shape 이 들어오면:
  - 콘솔에 warn 출력: `[query-registry] 등록되지 않은 쿼리 발견 → 자동 등록`
  - 메모리 레지스트리에 추가하고 계속 진행
  - `.dokkebi-cache/query-registry.learned.json` 에 기록
- 개발자가 `dok build` 를 다시 돌리면 학습된 쿼리까지 합쳐 최종 레지스트리 생성

배포 시 (`dok deploy`):
- `DOKKEBI_QUERY_MODE=strict` 강제 설정
- 학습 파일은 무시 — 오직 빌드 산출물만 유효

---

## 6. Stage 1 · 2 와의 통합

| 단계 조합 | 런타임 흐름 요약 |
| --------- | --------------- |
| v4 (현재) | client SQL → allowlist → D1 |
| Stage 1   | client SQL → allowlist → tenant verify → D1 |
| Stage 2   | client SQL → allowlist → tenant inject → D1 |
| **Stage 3** | client queryId → **registry lookup** → tenant inject → allowlist (depth) → D1 |

Stage 3 에서 allowlist 는 여전히 유지된다 — **방어 깊이 (defense in depth)** 원칙.
레지스트리 lookup 이 우선 차단 역할을 하지만, 레지스트리 생성 파이프라인에 버그가 있어도
allowlist 가 2차 방어선으로 남는다.

Tenant Policy 메타는 레지스트리 엔트리에 `tenantPolicy` 필드로 포함되어
Stage 2 의 inject 로직이 **쿼리별로 선택적** 으로 적용될 수 있다.

---

## 7. Raw SQL 처리

`createDb(runtime).raw(sql, params)` 는 DSL 을 우회하는 탈출구이다.
Stage 3 에서는 다음 중 하나:

| 모드              | 동작                                                                       |
| ----------------- | -------------------------------------------------------------------------- |
| `raw: 'deny'`     | `raw()` 호출 자체를 빌드 타임에 에러 (기본값, deploy 권장)                  |
| `raw: 'register'` | `raw()` 호출도 dry-run 시 레지스트리에 포함 시도 (shape 가 결정적이면)       |
| `raw: 'legacy'`   | `_execSql` 경로로 전송 (기존 allowlist-only 방어) — dev 편의용              |

`dokkebi.config.js`:

```js
export default {
  queryRegistry: {
    enabled: true,
    raw: 'deny',          // 'deny' | 'register' | 'legacy'
    coverageThreshold: 0.8
  }
};
```

---

## 8. 파일별 변경 요약

| 파일                                                     | 변경 내용                                                                             |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `packages/dokkebi-dsl/src/index.js`                      | `exec()` / `raw()` 에 `_execQuery` 경로 추가, `computeQueryIdSync` 헬퍼                 |
| `src/core/queryRegistry.js` (신규)                       | dry-run 수집, 캐노니컬라이즈, 해싱, 레지스트리 직렬화                                   |
| `src/commands/build.js`                                  | 빌드 파이프라인에 `collectQueriesByDryRun` 단계 추가, 임베드 호출                       |
| `src/commands/dev.js`                                    | `DOKKEBI_QUERY_MODE=learn` 강제, 학습 파일 기록                                         |
| `src/commands/deploy.js`                                 | `DOKKEBI_QUERY_MODE=strict` 강제, 배포 전 레지스트리 존재 검증                          |
| `src/core/projectGenerator.js`                           | `worker/api/_dokkebi/db.ts` 템플릿을 v5 로 갱신 — 레지스트리 lookup 경로, 임베드 패턴    |
| `src/commands/update.js`                                 | v4→v5 업그레이드 경로, `db.ts requiresRebuild: true`, 사용자 안내                       |
| `src/core/sqlAllowlist.js`                               | 변경 없음 (방어 깊이 유지)                                                              |
| `dokkebi-site/frontend/src/pages/Security.tsx`           | Query Registry 섹션 추가 — 공격 매트릭스에 "미등록 쿼리" 행 추가                        |
| `dokkebi-site/frontend/src/pages/CliCommands.tsx`        | `dok build` 에 query-registry 생성 단계 문서화, v5 업그레이드 안내                      |

---

## 9. CLI 명령 (신규 / 확장)

```bash
# 레지스트리 현황 보기
dok query status

# 출력 예:
# Query Registry v1
#   총 쿼리: 47
#   ├── SELECT: 28
#   ├── INSERT: 9
#   ├── UPDATE: 7
#   └── DELETE: 3
#   테넌트 정책 매핑: 44 / 47
#   출처 파일: 12

# 특정 쿼리 상세
dok query show q_a3f9b2c1d4e5f678

# 레지스트리 재생성 (dry-run)
dok query rebuild

# 학습된 쿼리 병합
dok query merge-learned
```

---

## 10. 테스트 계획

### 단위 테스트
- `canonicalizeSql`: 공백/대소문자/주석 변형 → 동일 해시 (10 케이스)
- `computeQueryId`: 결정적 해시, 충돌 검증 (SHA-256 prefix 16자리 충돌 확률 ~ 2⁻⁶⁴ 무시)
- `collectQueriesByDryRun`: 샘플 controller 에서 예상 쿼리 수 수집
- `exec()` vs `_execQuery` 라우팅 분기

### 통합 테스트 (`test/integration/query-registry/`)
- 등록된 shape → 정상 실행
- 미등록 shape (클라이언트 조작) → 403
- canonicalize 동치 쿼리 (공백 추가) → 정상 (동일 queryId)
- dev learn 모드에서 새 shape 자동 등록 확인
- strict 모드에서 새 shape 거부 확인
- Stage 2 (tenant inject) 와 결합 — 레지스트리 SQL 에 tenant 조건이 주입되는지

### 회귀 테스트
- 기존 `dokkebi-snow` 샘플 앱 — v4 기준 모든 쿼리가 레지스트리에 자동 수집되는지 커버리지 80% 이상

### 퍼포먼스
- 레지스트리 lookup: Map 기준 O(1), 1000 엔트리에서 <0.1ms 예상
- 해시 계산 (subtle.digest): 브라우저 기준 SHA-256 16 바이트 약 <0.5ms
- 빌드 시간 증가: dry-run 단계 약 +2-5초 (controller 수에 따라)

---

## 11. 로드맵

### S3.1 — 기본 Query Registry (1 주)
- [ ] `queryRegistry.js` 구현 (canonicalize, hash, dry-run)
- [ ] DSL `_execQuery` 경로
- [ ] Pages Function v5 템플릿
- [ ] `build.js` / `deploy.js` 통합
- [ ] 기본 테스트

### S3.2 — Dev 자동 학습 (2-3 일)
- [ ] `dev.js` learn 모드
- [ ] `.dokkebi-cache/query-registry.learned.json`
- [ ] `dok query merge-learned`

### S3.3 — 명시적 선언 & Raw 모드 (2 일)
- [ ] `backend/queries.ts` 읽기 (선언적 쿼리 등록)
- [ ] `raw: 'deny' | 'register' | 'legacy'` 모드 구현
- [ ] `dokkebi.config.js` 검증

### S3.4 — CLI & 관찰성 (1-2 일)
- [ ] `dok query status / show / rebuild`
- [ ] 빌드 로그에 커버리지 출력

### S3.5 — 문서 & 사이트 갱신 (1 일)
- [ ] `SECURITY.md` 갱신
- [ ] `dokkebi-site` Security.tsx / CliCommands.tsx
- [ ] 업그레이드 가이드 (v4 → v5)

총합 **약 1.5 ~ 2 주**.

---

## 12. 마이그레이션

### 신규 프로젝트 (`dok create`)
- 기본 활성화 — `queryRegistry: { enabled: true, raw: 'deny' }`
- `dok build` 시 자동 수집

### 기존 v4 프로젝트 (`dok update`)
- `WORKER_FILES` 에 `query-registry.json` 추가, `db.ts` version 5 로 승격
- `update.js` 완료 안내:
  ```
  [!] v5 업그레이드가 적용되었습니다.
      반드시 `dok build` 를 실행해 쿼리 레지스트리를 생성하세요.
      미생성 상태로는 모든 DB 호출이 403 으로 거부됩니다 (strict 모드).
  ```
- 하위 호환: `queryRegistry.enabled: false` 를 `dokkebi.config.js` 에 명시하면 v4 동작 유지

---

## 13. FAQ / 알려진 한계

### Q1. `if (admin) SELECT ... else SELECT ...` 같은 분기는?
양쪽 shape 모두 등록되어야 한다. Dry-run 이 분기를 모두 타지 못하면 dev 학습 모드에서 자동 등록된다.
정적 분석 친화적 코드 스타일을 `dok lint` 로 가이드할 수 있다.

### Q2. WASM 내부의 SQL 문자열은 여전히 노출되지 않나?
노출된다 (WASM 리버싱 시). 하지만:
- **공격자가 그 SQL 을 서버로 보내는 것은 여전히 불가능** — `queryId` 만 허용되므로
- SQL 문자열 노출은 "쿼리가 어떤 걸 조회하는지 알 수 있음" 수준이며, 이는 OpenAPI 스펙을 공개한 것과 동등
- Stage 3.3 (AST 치환) 으로 추가 은닉 가능

### Q3. `JOIN` 이나 subquery 가 포함된 복잡한 쿼리는?
DSL 에서 생성된 SQL 이 결정적이면 정상 지원. 현재 DSL 은 JOIN 을 지원하지 않으므로 해당 없음.
향후 DSL 이 JOIN 을 추가하면 같은 canonicalize 로직으로 처리 가능.

### Q4. 쿼리가 매우 많아지면 레지스트리 크기 문제?
1000 쿼리 × 평균 200B ≈ 200KB. Cloudflare Pages Function 1MB 제한 내에서 2000+ 쿼리까지 OK.
극한 상황에서는 레지스트리를 별도 KV 스토어에 저장하고 lookup 할 수 있다 (S3.3+).

### Q5. 파라미터 타입 강제는?
레지스트리 엔트리에 `paramTypes` 를 포함하므로 서버에서 타입 체크 가능. 잘못된 타입 → 400.
dev 모드에서 DSL 레벨에서도 런타임 체크 경고.

### Q6. Raw SQL 이 꼭 필요한 legacy 쿼리는?
`raw: 'legacy'` 모드로 기존 allowlist 경로 유지 가능. 단, 사이트 문서에 "raw 쿼리는 Query Registry 방어 범위 밖" 명시.

### Q7. 프론트엔드에서 직접 `fetch('/api/_dokkebi/db', ...)` 우회는?
불가능 — 세션 핸드셰이크 + HMAC + AES-GCM 경로를 거쳐야 한다. 그 경로를 거치면 DSL 을 통해야 하고,
DSL 은 queryId 만 전송한다.

### Q8. 실제 보안 효과 수준은?
- **SQL Injection**: 완전 차단 (allowlist 보다 강함)
- **권한 없는 컬럼 조회**: 차단 (레지스트리에 등록된 SELECT 컬럼만 가능)
- **조건 조작**: 차단 (WHERE shape 고정)
- **배치 공격 / 탐색**: 차단 (등록 안 된 shape 전부 403)
- **Stage 2 와 결합 시 테넌트 침범**: 자동 차단

---

## 14. 부록 — Stage 3 단독 도입 vs Stage 1/2 선행

| 조합                     | 방어력 | 개발 비용 | 권장 여부 |
| ------------------------ | ------ | --------- | --------- |
| Stage 1 만               | 중     | 중        | △         |
| Stage 2 만               | 중+    | 중+       | △         |
| **Stage 3 만**           | 높음   | 중        | ○ (테넌트 요구 없으면 이것만으로 충분) |
| Stage 1+2+3              | 최고   | 높음      | ◎ (다중 테넌트 + 고보안 요구) |

**결론**: 도깨비 사용 사례 대부분에서 **Stage 3 단독만 도입해도 실효 보안이 크게 상승**한다.
테넌트 격리 요구가 있는 프로젝트에서 Stage 2 를 추가하는 것이 효율적이다.

---

## 15. 참조
- [TENANT_POLICY.md](./TENANT_POLICY.md) — Stage 1, 2
- [SECURITY.md](../../SECURITY.md) — 전체 보안 모델
- [Cloudflare D1 Prepared Statements](https://developers.cloudflare.com/d1/best-practices/prepared-statements/)
- OWASP Top 10 — A03:2021 Injection
