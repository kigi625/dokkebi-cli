# Phase B — Runtime Sharding & Read Replica Wiring

본 문서는 [SHARDING.md](./SHARDING.md) 의 **Phase B 구현 계획**입니다.
Phase A(설정 스키마, `dok db:provision`, `dok migrate` fan-out, 문서)는 이미 머지됨.
Phase B 는 **컨트롤러 코드에서 사용할 런타임 API** 와 **D1 Sessions 자동 적용**을 합칩니다.

> 본 문서의 목표: 다음 PR 작업을 시작할 때 **새 컨텍스트에서도 곧바로 코드 작업이 가능한 수준**의
> 위치·인터페이스·검증 항목을 남기는 것. 구현은 포함하지 않습니다.

---

## 0. Scope

### 합치는 것

1. **`ctx.shardFor({ key })`** — 결정적 라우팅으로 단일 샤드 핸들 반환
2. **`ctx.global()`** — 글로벌 DB 핸들 (있을 때만)
3. **`ctx.fanout(fn, opts?)`** — 모든 샤드에 동일 작업 실행 (관제·집계 명시 API)
4. **`withSession()` 자동 적용** — `read: 'replica' | 'primary'` 라우트 메타로 분기, bookmark 쿠키 왕복
5. **라우트 메타 확장** — `read`, `shardKey`, `noShard` 옵션
6. **빌드 검증** — 샤드 키 == 정책엔진 sessionClaim 정합성, cross-shard 쿼리 정적 탐지
7. **빌드/배포 영향 흡수** — `env.DB` 단일 가정 제거, wrangler.toml 다중 바인딩, deploy preflight

### 합치지 않는 것 (Phase C 이상)

- 자동 cutover, dual-write 코드 자동 주입, backfill 도구 (`dok db:reshard`)
- Hot key DO 라우팅 자동 전환
- Cross-shard 트랜잭션 (saga API) — 별도 PR 권장

---

## 1. 런타임 API 계약 (확정)

### 1.1 `ctx.shardFor({ key })` → `D1Like`

```ts
type ShardKey = Record<string, string | number | bigint>;

interface D1Like {
  prepare(sql: string): D1PreparedStatement;
  batch(stmts: D1PreparedStatement[]): Promise<D1Result[]>;
  query<T = unknown>(sql: string, params?: unknown[]): Promise<T[]>;
  exec(sql: string): Promise<void>;
  /** 본 핸들이 묶인 샤드의 메타 (관제·로그·테스트용) */
  readonly shard: { id: string; binding: string; index: number };
}

interface DokkebiCtx {
  shardFor(key: ShardKey): D1Like;
  global(): D1Like | null;
  fanout<R>(fn: (db: D1Like) => Promise<R>, opts?: { concurrency?: number }): Promise<R[]>;
  /** 단일 D1 모드: env.DB 와 동일. 샤딩 모드: shardFor 권장 — 사용 시 워닝 로그 */
  db(): D1Like;
}
```

#### 의도적 제약

- `shardFor({ key })` 의 `key` 객체는 **`strategy.key` 컬럼명** 정확히 하나 키만 포함해야 함.
  - 예: `strategy.key === 'user_id'` 인데 `shardFor({ tenant_id })` 호출 시 **빌드 타임 에러**.
  - 동적 호출(빌드 타임에 키 이름 추론 불가)은 허용하되 **런타임 워닝**.
- `shardFor()` 가 반환한 `db` 는 **그 한 샤드** 만 접근. 정책엔진이 SQL 분석으로 다른 샤드 키 값에 대한 쿼리 시도를 차단(이미 존재하는 inject/verify 경로 재사용).
- `fanout(fn)` 은 **명시적**으로만 다중-샤드. 암시 cross-shard 쿼리는 정적 분석 + 런타임 모두 거부.

### 1.2 `withSession()` 자동 적용

라우트 핸들러 메타에 `read` 추가:

```ts
export const getOrders = defineRoute({
  method: 'GET',
  path: '/api/orders',
  read: 'replica',           // 'replica' (기본 GET) | 'primary' | 'auto'
  handler: async (ctx) => {
    const db = ctx.shardFor({ user_id: ctx.session.user_id });
    return db.query('SELECT * FROM orders WHERE user_id = ?', [ctx.session.user_id]);
  },
});
```

#### 동작

| `read` 값 | 핸들 동작 |
|---|---|
| `'replica'` (기본 GET) | `db.withSession('first-unconstrained')`, 응답 시 `__d1b` 쿠키 = `db.getBookmark()` |
| `'primary'` (기본 POST/PUT/DELETE) | `db.withSession('first-primary')` |
| `'auto'` | 요청에 `__d1b` 쿠키가 있으면 그 bookmark, 없으면 method 기본값 |

쿠키 사양:
- 이름: `__d1b`
- `HttpOnly`, `SameSite=Lax`, 도메인 = 사이트 도메인
- 값: D1 bookmark 문자열 (불투명 토큰. URL-safe base64-ish)
- 갱신: 쓰기 라우트 응답 시 항상, 읽기는 변경 시에만
- 삭제: 로그아웃 시 응답 헤더에 만료 처리

---

## 2. 빌드 / 배포 영향 (수정 필요 위치)

### 2.1 `core/projectGenerator.js` (~ L568 부근)

현재:
```ts
export interface Env {
  DB: D1Database;
  // ...
}
```

변경:
```ts
// 단일 D1: { DB }
// 샤딩:    { DB_S0, DB_S1, ..., DB_GLOBAL?, ... }
export interface Env {
  // 빌드 타임에 dokkebi.config.js 의 binding 들로 generate
  [key: string]: unknown;
}
```

→ 템플릿이 **`shardConfig.normalizeDatabaseConfig` 결과**를 받아
   각 binding 을 `D1Database` 타입으로 typed Env 선언으로 emit.

### 2.2 `core/payloadWireRuntime.js` — `env.DB` 직접 접근 제거

영향 받는 호출(약 30+ 곳, deploy.js · projectGenerator.js 양쪽):

- `env.DB.prepare(...)` / `env.DB.batch(...)` → `_internalDb(env)` 헬퍼 경유
- 보안 테이블(`_dokkebi_ephemeral_keys`, `_dokkebi_sessions`, `_dokkebi_nonces`, `_dokkebi_blacklist`, `_dokkebi_risk_score`, `_dokkebi_adl_*`) 는 **항상 global DB**(있으면) **혹은 첫 샤드**에 둠 — 정책 결정 지점.
- ADL 분석(`_runActiveDefenseAnalysis`)도 동일.

새 헬퍼 (런타임 코드 안):
```ts
function _internalDb(env: Env, kind: 'security' | 'session' | 'adl'): D1Database {
  // 빌드 타임 주입된 _DOKKEBI_INTERNAL_BINDING 사용
  // 단일: env.DB
  // 샤딩 + global 있음: env[__DOKKEBI_GLOBAL_BINDING__]
  // 샤딩 + global 없음: env[__DOKKEBI_SHARDS__[0]]   ← 명시 워닝
  return env[__DOKKEBI_INTERNAL_BINDING__] as D1Database;
}
```

→ `__DOKKEBI_INTERNAL_BINDING__` 는 빌드 타임 string-replace 로 주입.

### 2.3 `commands/deploy.js` preflight

추가 검사:
1. `database.type === 'd1-sharded'` 인 경우, **모든 `shards[].databaseId` 와 `global.databaseId`** (있다면) 가 채워졌는가?
2. `wrangler.toml` 에 모든 `binding` 이 등록되어 있는가? 누락 시 `dok db:provision` 안내.
3. 정책엔진 활성화된 경우, `policy.tables[*].sessionClaim` 이 **`strategy.key` 와 다른 컬럼**이면 워닝(또는 strict 모드면 에러).

기존 함수 위치: `runDeploy` 진입부의 환경/설정 검증 블록.

### 2.4 `core/policyEngine.js` — sessionClaim 정합성

빌드 단계에서 다음 검사 추가:
- 각 테이블의 `sessionClaim` 이 `strategy.key` 와 동일하면 OK.
- 다르면 워닝: `policy.tables.<t>.sessionClaim='<x>' 이지만 strategy.key='<y>' — 샤드 격리와 정책 격리가 어긋납니다.`
- `strict` 모드에서는 에러로 승격.

### 2.5 라우트 메타 (`build.js` / 라우터 emit)

라우트 정의 스캐너가 `read`/`shardKey`/`noShard` 메타를 인식해야 함. 현재 라우터는 `routes[]` 배열 형태이므로 emit 단계에서 핸들러 wrapping:

```ts
// 빌드 후 (개념적)
router.handle('/api/orders', wrapWithSession({ mode: 'replica' }, handler));
```

`wrapWithSession` 은 런타임 헬퍼(신규 모듈 `core/runtimeShardHelpers.js` 가칭).

---

## 3. 신규 / 수정 파일 (작업 단위 분해)

| 파일 | 종류 | 책임 |
|---|---|---|
| `src/core/runtimeShardHelpers.js` | 신규 | `wrapWithSession`, `bookmarkCookie`, fnv1a (런타임용 SubtleCrypto-free 버전) |
| `src/core/projectGenerator.js` | 수정 | `Env` 타입 emit, `__DOKKEBI_INTERNAL_BINDING__` 주입 |
| `src/core/payloadWireRuntime.js` | 수정 | `env.DB` → `_internalDb(env, kind)` |
| `src/core/bundleBoot.js` | 수정 | `ctx.shardFor` / `ctx.global` / `ctx.fanout` 주입 |
| `src/core/policyEngine.js` | 수정 | sessionClaim 정합성 검증 |
| `src/core/policyAnnotations.js` | 수정 | 샤드 키 추론 |
| `src/commands/build.js` | 수정 | 라우트 메타 read/shardKey 처리, 정합성 검증 표면화 |
| `src/commands/deploy.js` | 수정 | preflight 확장 |
| `src/core/queryScanner.js` | 수정 | cross-shard 정적 분석 (shard key 컬럼이 WHERE 에 없으면 워닝) |
| `templates/*` | 수정 | `wrangler.toml` 템플릿 다중 D1 binding 패턴 |
| `docs/design/SHARDING.md` | 수정 | Phase A → B 합류 시점에 “Phase B 구현됨” 갱신 |

신규 외부 동작 변경 없음(단일 D1 사용자에게는 무영향 보장이 **수용 기준**).

---

## 4. 마이그레이션 전략 (단일 D1 → 샤딩)

런타임 변경이 들어가면 **기존 단일 D1 프로젝트도 코드 형태 변경 없이 호환**되어야 합니다.

| 사용자 코드 | 단일 D1 (`type:'d1'`) | 샤딩 (`type:'d1-sharded'`) |
|---|---|---|
| `env.DB.prepare(...)` | 동작 (호환) | **빌드 워닝**: `ctx.shardFor()` 로 변경 권장. 동작은 함(첫 샤드로 라우팅) — strict 에서 에러 |
| `ctx.db().prepare(...)` | `env.DB` | 첫 샤드 (워닝) |
| `ctx.shardFor({ user_id }).prepare(...)` | `env.DB` 로 매핑 (단일 모드에서는 동일) | 정상 라우팅 |
| `ctx.global().prepare(...)` | `null` 반환 | 글로벌 DB |

→ **기존 사용자 코드는 안 깨진다**. 새 코드만 `shardFor()` 사용을 권장.

---

## 5. 테스트 항목 (수용 기준)

### 5.1 단위
- `runtimeShardHelpers.fnv1a` — Phase A 의 `shardConfig.hashString('fnv1a')` 와 100 케이스 같은 값.
- `wrapWithSession({mode:'replica'})` — `withSession` 호출 + 응답 쿠키 셋업.
- `_internalDb(env, kind)` — 단일/샤딩+global/샤딩 only 3 모드 모두.

### 5.2 통합 (vitest + wrangler local)
- 단일 D1 프로젝트(`dokkebi-site` 형태)가 코드 변경 없이 빌드·배포·런타임 OK.
- 샤딩 프로젝트(테스트 픽스처): 4 샤드 + global, fnv1a 라우팅이 SQL 실행 결과와 일치.
- `read:'replica'` 라우트가 **bookmark 쿠키** 를 정확히 왕복.

### 5.3 정적 분석
- `policy.tables[t].sessionClaim !== strategy.key` 일 때 빌드 워닝.
- 컨트롤러가 `shardFor({ x })` 호출인데 `strategy.key !== 'x'` 면 빌드 에러.

### 5.4 회귀
- `dokkebi-site`, `dokkebi-animate` 빌드가 깨지지 않는다.

---

## 6. 위험 요소 & 의사결정 필요 지점

본 PR 시작 전 명시 합의가 필요한 지점:

1. **내부 테이블의 위치**
   - 후보 A: 글로벌 DB 가 있으면 글로벌, 없으면 첫 샤드
   - 후보 B: **항상 별도 internal binding** (`DB_INTERNAL`)
   - 권장: A. 단순함이 운영적 이득 큼. global 미사용 사용자에게는 첫 샤드에 모이는 점을 문서화.

2. **bookmark 쿠키 범위**
   - 후보 A: 사이트 전역 1개 쿠키
   - 후보 B: 샤드별 쿠키 (`__d1b_s0`, …)
   - 권장: A. D1 bookmark 는 DB 별로 별개 토큰이지만, **last-bookmark 1 개**만 넘겨도 D1 이 합리적으로 처리. 쿠키 폭발 방지 우선.

3. **`ctx.db()` 호출 의미** (단일 → 샤딩 호환 레이어)
   - 단일 모드: `env.DB`.
   - 샤딩 모드: 첫 샤드 + 워닝. 운영 모드(prod)에서 워닝 누적 시 옵션으로 strict 에러로 승격.

4. **`fanout` 동시성 한계**
   - 기본 `concurrency: shards.length` (전부 동시).
   - SQL 한도 / Workers CPU 한도 고려해 상한 4–8 권장.

5. **빌드 시 라우트 데코레이터 스캐닝**
   - 현 라우터는 `routes[]` 배열 — 정적 분석 가능.
   - 동적 등록(`router.add(path, handler)`) 패턴은 메타 부착 위치 별도 검토.

---

## 7. 추정 작업량

대략적인 분해 (PR 단위로 쪼개는 것이 안전):

| PR | 내용 | 추정 |
|---|---|---|
| B-1 | `runtimeShardHelpers.js` + `_internalDb` 도입 (단일 D1 동작 보존) | 1 일 |
| B-2 | `ctx.shardFor` / `global` / `fanout` (런타임 API), `dokkebi.config` 단일 호환 매핑 | 1 일 |
| B-3 | `read` 라우트 메타 + `withSession` 자동 적용 + bookmark 쿠키 | 0.5 일 |
| B-4 | 정합성 검증 (policy sessionClaim ↔ strategy.key, queryScanner 워닝) | 0.5 일 |
| B-5 | `deploy.js` preflight, `wrangler.toml` 템플릿, 회귀 테스트 | 0.5 일 |

총 ~3.5 일. 단, **`payloadWireRuntime.js` 의 `env.DB` 30+ 호출 일괄 변환**은 코드 검토량이 크므로 보수적으로 +1 일.

---

## 8. 본 PR 시작 시 체크리스트

다음 PR 작업자에게:

1. [ ] [SHARDING.md](./SHARDING.md) 의 “Phase B 합류 시” 항목 업데이트 위치 확인
2. [ ] `dokkebi-site/Sharding.tsx` 의 “Phase B (예정)” 문구 제거 / 갱신
3. [ ] `core/shardConfig.js` 의 `hashString('sha1'/'sha256')` 구현 보강 (필요 시)
4. [ ] `dokkebi-site` 와 `dokkebi-animate` 둘 다 단일 D1 모드로 회귀 테스트
5. [ ] 본 문서 §6 의 5개 의사결정 항목을 PR 설명에 명시 합의

---

## 부록 — Phase A 에서 이미 확정된 인터페이스 (변경 금지)

- `database.type ∈ {'d1', 'd1-sharded'}`
- `database.shards[].{ id, binding, databaseId?, databaseName? }`
- `database.strategy.{ kind:'hash', key, hash:'fnv1a'|'sha1'|'sha256', virtualBuckets? }`
- `database.global.{ id, binding, databaseId?, databaseName? }`
- `database.sessions: true | { enabled, mode:'first-unconstrained'|'first-primary' }`
- `dok db:provision` / `dok migrate [--shard <id>]`

Phase B 는 위 스키마를 **소비**할 뿐 변경하지 않습니다.
