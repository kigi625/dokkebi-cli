# Sharding & Read Scaling — Design (Phase A + B 합류 완료)

본 문서는 도깨비 프레임워크가 D1 기반 백엔드에서 **읽기 오토스케일(Sessions / read replica)** 과
**결정적 샤딩(deterministic sharding)** 을 어떻게 지원할지의 **현재 단계(A)** 와
**이후 단계(B/C)** 를 정리합니다.

> 결론 요약
>
> - **읽기 스케일**: D1 read replica 는 Cloudflare 가 자동으로 띄움. 우리는 `withSession()` 으로 사용 여부를 결정. → **항상 ON 권장.**
> - **쓰기 스케일**: 샤드 키와 샤드 수는 **사용자가 선언**(domain 결정). 라우팅·프로비저닝·마이그레이션은 **CLI/런타임이 자동**.
> - **자동 오토샤딩(런타임에 DB 추가/리샤딩)** 은 Cloudflare 플랫폼 제약과 분산 DB 이론상 안전하게 자동화하기 어려워 **반자동(도구 + 사람 승인)** 으로 갑니다.

---

## 0. 설계 원칙

| 항목 | 누가 결정 | 누가 실행 |
|---|---|---|
| 샤드 키 (`user_id` / `tenant_id` / …) | **사용자** | — |
| 샤드 수 / 초기 분포 | **사용자** | — |
| 샤드 라우팅 | (선언만) | **프레임워크** (deterministic hash) |
| 샤드 D1 생성·바인딩 | (선언만) | **CLI** (`dok db:provision`) |
| 다중 샤드 마이그레이션 | (선언만) | **CLI** (`dok migrate` fan-out) |
| Cross-shard 트랜잭션 경계 | **사용자** | (saga API, 추후) |
| 리샤딩 (cutover 등) | **사용자가 승인** | **CLI** 단계별 자동 (추후 Phase C) |

---

## 1. `dokkebi.config.js` 스키마 (Phase A 구현됨)

### 단일 D1 (기본, 기존 동작)

```js
database: {
  type: 'd1',
  accountId:  process.env.D1_ACCOUNT_ID,
  databaseId: process.env.D1_DATABASE_ID,
  apiToken:   process.env.D1_API_TOKEN,
  binding:    'DB',                 // 선택, 기본 'DB'
  sessions:   true,                  // 선택. read replica 사용
}
```

### 샤딩 (`d1-sharded`)

```js
database: {
  type: 'd1-sharded',
  // 샤드 풀 — 모든 샤드는 같은 스키마를 가집니다
  shards: [
    { id: 's0', binding: 'DB_S0', databaseId: '...' },
    { id: 's1', binding: 'DB_S1', databaseId: '...' },
    { id: 's2', binding: 'DB_S2', databaseId: '...' },
    { id: 's3', binding: 'DB_S3', databaseId: '...' },
  ],
  // 결정적 라우팅
  strategy: {
    kind: 'hash',          // 현재 'hash' 만 지원
    key:  'user_id',       // 샤드 키 컬럼 (정책엔진 sessionClaim 과 같은 것을 권장)
    hash: 'fnv1a',         // 'fnv1a' (기본) | 'sha1' | 'sha256'
    virtualBuckets: 256,   // 선택. resharding 대비 (consistent-hash 권장)
  },
  // 글로벌(공통 메타) DB — 선택
  global: { id: 'global', binding: 'DB_GLOBAL', databaseId: '...' },
  sessions: true,
}
```

### 검증 규칙 (`normalizeDatabaseConfig`)

- `shards.length >= 2`
- `id`/`binding` 비어있지 않고 중복 없음
- `strategy.kind === 'hash'`, `strategy.key` 존재
- `virtualBuckets` 는 `shards.length ~ 4096` 범위
- 검증 실패 시 `dok db:provision` / `dok migrate` 가 즉시 종료

### 라우팅 알고리즘

```
bucket = hash(strategy.key 값) % virtualBuckets
index  = bucket % shards.length
shard  = shards[index]
```

`fnv1a` 기본: 빠르고, 결정적이고, CLI/런타임 동일 결과. 분포는 32-bit fnv1a 수준이면 일반 ID 분포에서 충분.

---

## 2. CLI — Phase A 구현됨

### `dok db:provision [src]`

`d1-sharded` 설정의 모든 샤드와 (있으면) global DB 를 한 번에 생성·바인딩.

동작:
1. `dokkebi.config.js` 로드 + `normalizeDatabaseConfig` 검증.
2. `.env` 의 `D1_ACCOUNT_ID` / `D1_API_TOKEN` 로 Cloudflare API 호출.
3. 기존 D1 목록과 매칭:
   - `databaseId` 가 이미 채워져 있으면 **skip**
   - 같은 이름의 D1 이 이미 있으면 **reuse** (uuid 회수)
   - 없으면 **create** (`<package.name>-<shardId>`)
4. `wrangler.toml` 에 `[[d1_databases]]` 블록 idempotent 추가/갱신.
5. `dokkebi.config.js` 의 각 shard 에 들어갈 `databaseId` 를 사용자에게 출력 (자동 패치는 안 함 — 안전).

옵션:
- `--dry-run` — 계획만 출력
- `-y, --yes` — 대화 없이 실행

### `dok migrate [src] [--shard <id>]`

샤딩 모드에서 자동으로 fan-out:
- 모든 샤드 + global DB 에 동일 마이그레이션을 적용
- `--shard s0` 또는 `--shard global` 로 단일 타깃 마이그레이션 가능
- 각 샤드별 결과(applied / skipped / 실패)를 한 번에 리포트
- `databaseId` 가 채워지지 않은 항목은 안전하게 skip

> 단일 D1 (`type: 'd1'`) 은 기존 동작 그대로.

---

## 3. 런타임 — Phase B (구현 완료)

> **상태**: B-1 ~ B-5 모두 합류. 단일 D1 (`type: 'd1'`) 사용자에게는 동작 변화 없음 (opt-in).

### 구현된 항목

| ID | 내용 | 위치 |
|---|---|---|
| B-1 | `_internalDb(env)` / `_userDbForSql(env, sql)` 도입, `env.DB` 직접 접근 일반화 | `templates/worker/db.ts.tpl`, `core/projectGenerator.js` |
| B-2 | `ctx.shardFor({key})` / `ctx.global()` / `ctx.fanout(fn)` / `ctx.db` 런타임 API | `packages/dokkebi-runtime/src/index.js`, `templates/project/dokkebi.d.ts.tpl` |
| B-3 | `withSession(__d1b)` 자동 적용 + `__d1b` httpOnly 쿠키 왕복 | `templates/worker/db.ts.tpl` (`_withMaybeSession`, `_appendBookmarkCookie`) |
| B-4 | `strategy.key` ↔ `policy.tables[*].sessionClaim` 정합성 검증, `/*!read*/` SQL 힌트 | `core/shardConfig.js#verifyShardConsistency`, `templates/worker/db.ts.tpl` |
| B-5 | `dok deploy` preflight (샤드 binding 누락 검사 + sessions 안내) | `commands/deploy.js#runPreflight` |

런타임 API 사용 예:

```ts
// 컨트롤러 안에서
const db = ctx.shardFor({ user_id });          // 결정적 라우팅
await db.query('SELECT ... WHERE user_id = ?', [user_id]);

const meta = ctx.global();                       // (있다면) global DB 핸들

// 다중 샤드 명시 호출 — 암시적 cross-shard 는 금지
const totals = await ctx.fanout((db) => db.query('SELECT COUNT(*) AS n FROM orders'));
//   → 각 샤드 결과 배열, 집계는 사용자가
```

### 계약

- `ctx.shardFor({ key })` 는 빌드 타임에 추론 가능한 호출이면 **인라인 라우팅 코드** 로 치환. 그렇지 않으면 런타임 fnv1a 라우팅.
- `ctx.shardFor()` 가 반환한 `db` 는 **그 한 샤드** 만 접근. 다른 샤드 키로 쿼리 시도 시 정책엔진이 차단.
- `withSession(bookmark)` 자동 적용:
  - `read: 'replica'` 메타가 붙은 라우트 → replica 우선
  - `write` 라우트 / `read: 'primary'` → primary
  - bookmark 는 응답 쿠키 `__d1b` (httpOnly, SameSite=Lax) 로 왕복
- 샤드 키 == 정책엔진 `sessionClaim` 정합성 검증 (빌드 시 워닝)

### Sessions API (D1 Read Replica) 활성화

`dokkebi.config.js`:

```js
database: {
  type: 'd1',                  // 또는 'd1-sharded'
  // ...
  sessions: true,              // 또는 { enabled: true, mode: 'first-unconstrained' }
},
```

- 모드: `'first-unconstrained'` (기본, 지연 허용) | `'first-primary'` (정합성 우선)
- 응답에 `Set-Cookie: __d1b=...; HttpOnly; SameSite=Lax` 자동 첨부
- 쓰기 또는 `/*!write*/` 힌트가 붙은 SQL 은 자동으로 primary 라우팅

### 명시적 read/write 메타

동적으로 합성되는 SQL 은 prefix 만 보고 read 여부를 판별하기 어렵다. SQL 선두에 주석 힌트로 강제 지정 가능:

```ts
const sql = '/*!read*/ ' + buildSelectSql(filters);  // replica 우선
const sql = '/*!write*/ ' + buildUpsertSql(...);     // primary 강제
```

### 정합성 검증 (build / deploy 시 자동)

- 샤딩 모드인데 `strategy.key` 가 비어있으면 **에러**
- `policy.tables[*].sessionClaim` 이 `strategy.key` 와 다르면 워닝(`policy.strict: true` 면 에러)
- `wrangler.toml` 에 모든 샤드 binding 이 선언되어 있는지 `dok deploy` preflight 가 검사

> 단일 D1 사용자는 위 모든 동작이 no-op 이며 기존 동작 유지.

---

## 4. 리샤딩 — Phase C (미래)

`dok db:reshard` 단계별 명령:

| 단계 | 명령 | 자동/수동 |
|---|---|---|
| Plan | `dok db:reshard plan --to <N>` | 자동 분석, **사용자 승인** |
| Dual-write | `dok db:reshard start` | 자동 코드 생성·배포 |
| Backfill | `dok db:reshard backfill` | 자동 (재시도·체크섬) |
| Cutover | `dok db:reshard cutover` | **사용자 승인** 후 자동 |
| Rollback | `dok db:reshard rollback` | 즉시 (안전) |
| Finalize | `dok db:reshard finalize` | 구 위치 정리 |

**자동 cutover 는 의도적으로 만들지 않습니다.** 데이터 사고 방지.

---

## 5. 무엇이 자동/반자동/수동인가 — 정리

| 작업 | 자동 | 수동 |
|---|---|---|
| Replica 사용 (Sessions API) | **전부 자동** | 켤지 말지 |
| 샤드 라우팅 | **전부 자동** (선언 후) | 샤드 키·수 선언 |
| 샤드 D1 생성·바인딩 | DB 생성, wrangler.toml 갱신 | 명령 실행, 개수 결정 |
| 다중 샤드 마이그레이션 | fan-out, 이력 추적 | 명령 실행 |
| 리샤딩 실행 | dual-write·backfill·검증·롤백 | **plan 검토, cutover 승인** |
| Hot key 대응 (Durable Object) | 감지·권장·코드 템플릿 | 적용·배포 |
| Cross-shard 트랜잭션 | (saga API) | **비즈 로직 작성** |

---

## 6. 왜 “자동 오토샤딩” 을 의도적으로 안 만드는가

1. **D1 control plane 제약**: 새 D1 은 wrangler 바인딩에 등재돼야 코드가 접근 가능 → 런타임에서 “DB 자동 생성·즉시 라우팅” 은 사실상 재배포 없이 불가.
2. **분산 트랜잭션 부재**: D1 은 cross-DB 트랜잭션을 제공하지 않음 → 자동 분할이 비즈 트랜잭션을 깨뜨림.
3. **Hot key 는 샤딩으로 안 풀림**: 단일 키 집중은 샤드를 늘려도 그 키는 한 샤드 → DO/큐가 정답.
4. **자동 결정의 비가역성**: 잘못된 샤드 키 자동 선택은 며칠~몇 주짜리 부채로 누적.

대신 **사람이 “하자” 고 하면 도깨비가 “안전하게” 한다** 가 본 설계의 일관된 원칙입니다.

---

## 7. 마이그레이션 가이드 (단일 → 샤딩)

1. `database.type` 을 `'d1-sharded'` 로 변경, `shards`/`strategy` 작성.
2. `dok db:provision` 으로 D1 생성, `databaseId` 를 `dokkebi.config.js` 에 채움.
3. `dok migrate` 로 모든 샤드에 스키마 적용.
4. `ctx.shardFor({ [strategy.key]: value })` 로 컨트롤러 코드 변환.
5. (Phase C 이후) 기존 단일 DB 데이터를 `dok db:reshard backfill` 로 분배.

Phase A + B 합류 완료. 1~4 단계가 가능합니다. 5 단계(온라인 리샤딩)는 Phase C 에서.
