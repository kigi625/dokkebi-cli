# Policy Inference — 관례 기반 정책 자동 추론 + `dok policy:scaffold`

- **버전**: 1.0 (v5.3 이후 합류)
- **상태**: 설계 + 구현 완료
- **관련 문서**:
  - [`TENANT_POLICY.md`](./TENANT_POLICY.md) — row-level 격리 정책
  - [`AUTHORIZATION.md`](./AUTHORIZATION.md) — 연산 레벨 인가 정책
  - [`QUERY_REGISTRY.md`](./QUERY_REGISTRY.md) — SQL 허용목록/레지스트리

---

## 0. 배경 — "보안이 개발을 막는" 문제

v5.2 까지의 Tenant Policy 와 v5.3 의 Authorization Policy 는 둘 다
**opt-in / fail-closed** 로 설계되었다. 이는 보안 관점에서 올바른 선택이지만,
현업에서는 다음과 같은 마찰이 실제로 관찰됐다:

- 테이블마다 `tenantColumn` 을 수동으로 적어야 한다 → 모델 수정 시마다 config 도 같이 수정.
- 운영 단위 규칙 (`SELECT:posts`, `DELETE:users` 등) 을 손으로 쓰다 보면 쉽게 빠뜨린다.
- 사용자가 빠뜨린 항목은 `strict` 모드에서 전부 차단 → 작업이 막힌다.
- 결국 대부분 `enabled: false` 로 돌려놓고 정책을 사용하지 않게 된다.

> "보안 기능이 켜져 있지 않으면 아무 효과가 없다."
> 이 문서는 **켜는 비용을 0 에 가깝게** 만들어서, 보안을 "기본 경로" 로 끌고 오는 걸 목표로 한다.

보안 수준은 낮추지 않는다. 차단 규칙은 여전히 서버 측(`worker/api/_dokkebi/db.ts`)에서만
평가되며, 추론은 "사용자가 직접 써야 했던 규칙을 대신 제안 / 채워 넣어주는" 레이어일 뿐이다.

---

## 1. 설계 목표

| 목표 | 달성 수단 |
|---|---|
| 기본 설정 없이도 올바른 기본값 | 관례 기반 추론 (컬럼명 / 테이블명 휴리스틱) |
| 사용자 명시값은 절대 침해하지 않음 | 레이어드 병합 — user 값이 추론값을 이긴다 |
| 기존 프로젝트를 깨지 않음 | 기본은 **제안만**, `autoApply: true` 또는 `policy:scaffold` 실행시에만 반영 |
| 추론 결과를 명시적으로 확인 가능 | `dok policy:scaffold --dry-run` / `dok build` 로그 |
| "왜 이 규칙이 만들어졌나" 를 설명 가능 | 모든 추론 규칙에 `_inferred: true` 마킹 + 로그에 출처 표시 |

---

## 2. 전체 파이프라인

```
 models/schema.ts          controllers/**/*.ts
   │ (table DSL)              │ (SQL literals)
   ▼                          ▼
 extractTableDefinitions   queryScanner.scanProjectQueries
   (policyInference.js)       (queryScanner.js)
   │                          │ returns { registry, opTableStats }
   │                          ▼
   │                     opTableStats: Map<"OP:table", count>
   ▼                          │
 per-table inference          │
   · tenantColumn             │
   · mode (enforce/none)      │
                              │
         ┌────────────────────┘
         ▼
 inferPolicyFromProject(rootDir, opTableStats)
    → { tables, rules, tenantCoverage[], warnings[] }
         │
         ▼
 mergeInferredIntoConfig(userConfig, inferred)
    → { merged, policyAdds, authzAdds,
        policyAutoSuggestions, authzAutoSuggestions }
         │
         ├─ dok build     → 로그에만 노출 (기본 동작을 바꾸지 않는다)
         └─ dok policy:scaffold → dokkebi.config.js 에 AUTOGEN 블록으로 영속화
```

---

## 3. 관례 (Conventions) — 정확한 규칙 명세

### 3.1 Tenant Column 감지

`inferTenantColumn(tableDef)` 가 다음 **4 단계** 를 순서대로 검사한다.
첫 번째 매칭되는 규칙이 채택된다.

#### 단계 1 — Self-tenant 관례 (users 테이블)

테이블 이름이 `SELF_TENANT_TABLES` 에 포함되고 `id` 컬럼이 있으면 → `id` 사용.

```
SELF_TENANT_TABLES = { 'users' }
```

#### 단계 2 — 정확 매칭 후보 (`TENANT_COLUMN_CANDIDATES`)

```
user_id / owner_id / author_id / tenant_id / workspace_id / account_id /
org_id / organization_id / created_by / creator_id /
creator_token / sender_token / author_token / owner_token /
subscriber_token / collaborator_token / member_token / participant_token
```

#### 단계 3 — 테이블 접미사 + 단일 `token` 컬럼

테이블 이름이 아래 접미사로 끝나고 `token` 컬럼이 있으면 → `token` 이 tenant.

```
TOKEN_OWNED_TABLE_SUFFIXES = [
  '_subscriptions', '_subscribers', '_sessions', '_tokens',
  '_devices', '_registrations', '_endpoints',
]
```

예: `push_subscriptions.token`, `user_sessions.token`.

단계 3 이 단계 4 보다 먼저 수행되는 이유: 구독/세션 테이블에는 `app_push_token`
같은 보조 토큰이 함께 존재할 수 있는데, 설계상 주 식별자는 단일 `token` 이기 때문.

#### 단계 4 — `*_token` 일반 패턴

컬럼 중 `*_token` 으로 끝나는 것 중 "**tenant 가 아닌**" prefix 를 제외한 첫 매칭.

```
NON_TENANT_TOKEN_PREFIXES = {
  'password', 'reset', 'refresh', 'access', 'id', 'csrf', 'api',
  'webhook', 'verification', 'invite', 'activation', 'magic',
  'session', 'bearer', 'confirmation', 'oauth', 'jwt',
}
```

제외 대상이 아닌 `*_token` (예: `editor_token`, `admin_token`) 은 자동으로
tenant 로 인식. 이 단계 덕분에 관례에 없는 새 토큰 타입도 커버된다.

**매칭 실패 시**:
- `isSharedTable()` 검사로 넘어가 "공유 테이블" 인지 판단 (§3.2).
- 공유도 아니면 `null` → **tenant 미감지**, 경고 로그.

**제외 대상 (추론 전체에서)**:
- `_dokkebi_*` prefix (프레임워크 내부 테이블)
- `sqlite_master`, `sqlite_sequence`, `sqlite_stat1`, `sqlite_stat4`, `sqlite_temp_master`
  (SQLite 엔진 내장 메타 테이블)

### 3.2 Shared (공유/참조) 테이블 자동 분류

tenant 컬럼을 찾지 못했을 때 `isSharedTable()` 이 다음 조건을 검사한다:

1. **관례 이름 매칭**: 테이블 이름이 `SHARED_TABLE_NAMES` 에 있음
   ```
   templates, categories, tags, labels, settings, metadata, configs,
   configurations, countries, languages, currencies, timezones,
   feature_flags, plans, prices, translations
   ```
2. **순수 참조 테이블 휴리스틱**: `*_id` FK 도 없고 `*_token` / `token` 도 없음
   (예: `colors`, `statuses` 같은 enum 류 테이블).

둘 중 하나라도 해당하면 `mode: 'none'`, `shared: true` 로 분류되며
**경고 로그를 발생시키지 않는다**. 사용자가 "왜 차단 안 되지?" 라고 의심할 필요 없이,
설계상 공유 테이블임이 명확히 드러난다.

### 3.2 Mode 추론

| 조건 | 추론 mode |
|---|---|
| tenantColumn 감지됨 + 테이블이 명백히 per-user 데이터 (posts, notos, comments, messages ...) | `enforce` |
| tenantColumn 감지됨 + 테이블이 `users` 류 | `enforce` (self-tenant) |
| tenantColumn 미감지 | `none` (추론 안 함, 경고 로그) |
| 시스템/공유 테이블 (templates, categories 등 — 관례 + `*_shared`) | `none` |

> 모델 파일이 하나도 없거나 `table()` 호출이 감지되지 않으면 추론 자체가 스킵된다 (= 0 개 제안).

### 3.3 예시 — 실제 관례 적용 결과

notofly 모델에서 자동 감지되는 결과:

| 테이블 | 감지 결과 | 적용 규칙 |
|---|---|---|
| `notos` | `creator_token` | 단계 2 (정확 매칭) |
| `messages` | `sender_token` | 단계 2 (정확 매칭) |
| `users` | `id` | 단계 1 (self-tenant) |
| `noto_collaborators` | `collaborator_token` | 단계 2 (정확 매칭) |
| `push_subscriptions` | `token` | 단계 3 (접미사 `_subscriptions` + `token`) |
| `message_replies` | `author_token` | 단계 2 (정확 매칭) |
| `templates` | `shared: true` | §3.2 (관례 이름) |

→ **7 개 전부 자동 처리. 경고 0 개. 수동 설정 불필요.**

### 3.4 Authorization Rule 추론 (`defaultAuthzSpec(op, table)`)

```
SELECT:*  → { public: true }
INSERT:*  → { auth: true }
UPDATE:*  → { auth: true }
DELETE:*  → { auth: true }

// 민감 테이블 상향 (SENSITIVE_TABLES)
DELETE:{users, roles, payments, ...}  → { roles: ['admin'] }
UPDATE:{users, roles, payments, ...}  → { roles: ['admin'] }

// 시스템 테이블 / SQLite 메타
_dokkebi_* / sqlite_*                 → 규칙 미생성 (SQL Allowlist 전담)
```

**핵심 원칙**:
- **fallback 은 `*: { public: true }`** — 규칙이 없는 연산이 전부 차단돼 작업이 막히는 걸 방지.
- 사용자가 원하면 `authorization.rules['*'] = { auth: true }` 로 언제든 전환 가능.
- 운영 단계별 정확한 강도는 사용자가 "그 규칙 위에" 덮어써서 조정한다
  (예: `SELECT:payments` 만 `roles: ['admin']` 로).

---

## 4. 레이어드 병합 모델

```
┌─────────────────────────────────────┐  최우선 (덮어쓸 수 없음)
│ 4. 사용자의 dokkebi.config.js       │
│    (policy.tables, authorization.rules)│
└─────────────────────────────────────┘
┌─────────────────────────────────────┐
│ 3. AUTOGEN 블록 (__dokkebi_autogen_*)│
│    `dok policy:scaffold` 로 생성    │
└─────────────────────────────────────┘
┌─────────────────────────────────────┐
│ 2. dok build 시 실시간 추론 (in-memory)│
│    autoApply: true 일 때만 반영     │
└─────────────────────────────────────┘
┌─────────────────────────────────────┐  최하위
│ 1. 프레임워크 디폴트                │
│    (allowlist v2 스키마 기본값)     │
└─────────────────────────────────────┘
```

### 4.1 `mergeInferredIntoConfig` 의 정확한 동작

```js
function mergeInferredIntoConfig(userConfig, inferred) {
  const merged = deepClone(userConfig);

  // Tenant Policy — user 값 보존, 추론 값은 빈 자리만 채움
  if (userConfig.policy?.enabled !== false
   && inferred.tables && Object.keys(inferred.tables).length > 0) {
    const policyAuto = userConfig.policy?.autoApply === true;
    for (const [tbl, inf] of Object.entries(inferred.tables)) {
      if (merged.policy?.tables?.[tbl]) continue;       // 사용자 명시 → skip
      if (policyAuto) {
        merged.policy = merged.policy || {};
        merged.policy.tables = merged.policy.tables || {};
        merged.policy.tables[tbl] = inf;                // 즉시 병합
        policyAdds.push(tbl);
      } else {
        policyAutoSuggestions.push(tbl);                // 제안만
      }
    }
  }

  // Authorization Rules — 동일 로직
  if (userConfig.authorization?.enabled !== false) {
    const authzAuto = userConfig.authorization?.autoApply === true;
    for (const [key, spec] of Object.entries(inferred.rules || {})) {
      if (merged.authorization?.rules?.[key]) continue; // 사용자 명시 → skip
      if (authzAuto) {
        merged.authorization.rules[key] = stripInferredFlag(spec);
        authzAdds.push(key);
      } else {
        authzAutoSuggestions.push(key);
      }
    }
    // '*' 디폴트가 사용자 config 에도 AUTOGEN 에도 없을 때만 public 으로 보강
    if (authzAuto && !merged.authorization.rules['*']) {
      merged.authorization.rules['*'] = { public: true };
    }
  }

  return { merged, policyAdds, authzAdds, policyAutoSuggestions, authzAutoSuggestions };
}
```

### 4.2 왜 기본은 "제안만" 인가

기존 notofly 같은 **이미 운영 중인 프로젝트**에서 `dok build` 한 번만 했는데
갑자기 `SELECT:posts` 가 public 이 되고 `DELETE:users` 가 admin 전용이 되면,
의도치 않은 행동 변화가 production 으로 흘러갈 수 있다.

따라서:
- **기본은 무해**: `dok build` 는 로그로 제안만 노출한다 (런타임 동작 동일).
- **사용자가 명시적으로 opt-in**: `dok policy:scaffold` 실행 또는
  `policy.autoApply: true` / `authorization.autoApply: true` 추가시 반영된다.

---

## 5. `dok policy:scaffold` 명령

### 5.1 동작 개요

```
$ dok policy:scaffold [--dry-run]
```

1. `dokkebi.config.js` 를 읽고 ESM 로 평가한다.
2. `scanProjectQueries(rootDir)` 로 `opTableStats` 를 수집한다.
3. `inferPolicyFromProject(rootDir, opTableStats)` 호출.
4. **안전 기본값** 으로 AUTOGEN 객체 구성:
   - `__dokkebi_autogen_policy`: `enabled: false`, `mode: 'verify'`, `strict: false`
   - `__dokkebi_autogen_authz`: `enabled: false`, `mode: 'warn'`
   - **테이블별 `sessionClaim`** (v5.4+) 을 모든 enforce 테이블에 명시:
     - `users.id` → `sessionClaim: 'user_id'` (self-tenant 관례)
     - 그 외 → `sessionClaim: <tenantColumn>` (예: `creator_token` 컬럼은 세션의 `creator_token` 키로 매핑)
     → JWT 없이 해시 토큰만 쓰는 프로젝트(notofly 등)도 바로 작동. 프론트는
     `ctx.setSessionTenant({ creator_token: '<해시>', sender_token: '<해시>', ... })` 한 줄로 끝.
   - `policy.sessionClaim` (전역) 은 "가장 흔한 컬럼" 을 기본 fallback 값으로 선택
5. 결과를 다음 블록으로 렌더링한다:

```js
// ╭─ DOKKEBI AUTOGEN:POLICY START ─────────────────────────────
// │ 생성 시각: 2026-04-22T07:02:48.945Z
// │ `dok policy:scaffold` 로 재생성됩니다.
// │ 감지: tenant=2, rules=10, scannedModels=1
// ╰──────────────────────────────────────────────────────────────
const __dokkebi_autogen_policy = { /* ... */ };
const __dokkebi_autogen_authz  = { /* ... */ };
// ╰─ DOKKEBI AUTOGEN:POLICY END ─────────────────────────────
```

5. 파일 상단에 블록을 삽입 (이미 있으면 교체).
6. `export default` 객체에 `policy: { ...__dokkebi_autogen_policy, ... }` /
   `authorization: { ...__dokkebi_autogen_authz, ... }` 를 자동 주입
   (동일한 키가 이미 있으면 건드리지 않음 → 사용자 커스텀 보존).
7. 원본은 `dokkebi.config.js.bak` 로 백업.

### 5.2 안전 장치

- `--dry-run`: 파일을 수정하지 않고 바뀔 내용만 출력.
- AUTOGEN 블록은 마커 (`// ╭─ DOKKEBI AUTOGEN:POLICY START/END`) 사이에만 존재.
  마커 밖의 사용자 코드는 절대 수정하지 않는다.
- 재실행시 기존 AUTOGEN 블록만 정확히 교체 → diff 가 깔끔하게 유지된다.
- 사용자가 export default 안의 `policy.tables.X` 를 직접 손으로 덮어써도 그대로 살아남는다
  (스프레드 순서: `{ ...__dokkebi_autogen_policy, /* 여기에 수동 오버라이드 */ }`).

---

## 6. 코드 배치 요약

| 파일 | 역할 | 상태 |
|---|---|---|
| `src/core/policyInference.js` | 핵심 추론 로직 + 병합 | 신규 |
| `src/core/queryScanner.js` | SQL 정적 스캔 (op/table 통계 추가) | 수정 |
| `src/core/queryRegistry.js` | `buildRegistry` 가 `opTableStats` 반환 | 수정 |
| `src/commands/build.js` | 추론 결과를 로그에 노출 (`[4b2]` 단계) | 수정 |
| `src/commands/policyScaffold.js` | `dok policy:scaffold` 구현 | 신규 |
| `src/cli.js` | `policy:scaffold` 커맨드 등록 | 수정 |
| `tests/policyInference.test.mjs` | 단위 테스트 18 개 | 신규 |

---

## 7. 모델 파서 세부 — `extractTableDefinitions`

model DSL 예시:

```ts
// backend/models/schema.ts
export const notos = table('notos', {
  id: text('id').primaryKey(),
  creator_token: text('creator_token').notNull(),
  title: text('title'),
  // ...
});
```

`extractTableDefinitions(source)` 는 다음을 수행한다:

1. `_tokenizeForScan(source)` 로 `sanitized` (주석 공백화) + `stringRanges` (문자열 리터럴 범위) 를 얻는다.
2. `/\btable\s*\(/g` 로 `table(` 호출 후보를 스캔한다.
3. 각 매치가 `stringRanges` 안에 있으면 skip (문자열 안의 `table(` 은 무시).
4. 여는 괄호부터 균형 잡힌 닫는 괄호까지 잘라낸다 (scope-aware).
5. 첫 번째 인자 = 테이블 이름 (문자열 리터럴), 두 번째 인자 = 컬럼 객체.
6. 컬럼 객체에서 키만 뽑아 `{ name, columns[] }` 로 반환.

**견고한 이유**:
- 주석 내부 `table(` 은 무시 → false positive 차단.
- 문자열 리터럴 내부 `table(` 도 무시 (원래 `_stripCommentsOutsideStrings` 가 문자열 본문을 지웠지만,
  남아 있는 따옴표가 다음 regex 를 혼동시켜 bug 를 유발 → 현재는 범위 기반으로 교체).
- 중첩 괄호 / arrow 함수가 있어도 괄호 카운팅으로 올바른 구간 추출.

---

## 8. 실제 적용 흐름 — notofly 사례

### 8.1 `dok build` 로그 (autoApply 없음 — 기본 상태)

```
[dokkebi] [4b2] Policy 자동 추론...
[dokkebi]   모델 파일 1개 스캔 → tenant 감지 2개 / 미감지 5개
[dokkebi]     · 감지: notos, users
[dokkebi]   ⚠ [tenant] 'templates' 에서 tenant 컬럼을 추론하지 못했습니다. ...
[dokkebi]   💡 policy.tables 제안: 2개 (notos, users)
[dokkebi]      → 적용하려면: 'dok policy:scaffold' 또는 policy.autoApply: true 추가
[dokkebi]   💡 authorization.rules 제안: 10개 (SELECT=public, INSERT/UPDATE/DELETE=auth, users/roles/payments 삭제=admin)
[dokkebi]      → 적용하려면: 'dok policy:scaffold' 또는 authorization.autoApply: true 추가
```

이 시점의 `worker/api/_dokkebi/db.ts` 에는 **사용자가 명시한 규칙만** 임베드된다.
즉, 실제 보안 경계는 이전과 완전히 동일하다.

### 8.2 `dok policy:scaffold` 실행 후

- `dokkebi.config.js` 상단에 AUTOGEN 블록 생성.
- `export default` 에 `policy: { ...__dokkebi_autogen_policy, ...overrides }` 주입.
- 다음 `dok build` 부터는 이 정책이 실제로 활성화된다.
- 사용자는 그대로 두거나, `tables.notos.tenantColumn` 을 명시적으로 덮어써서 조정 가능.

### 8.3 사용자의 수동 수정 시나리오

```js
// dokkebi.config.js
policy: {
  ...__dokkebi_autogen_policy,
  tables: {
    ...__dokkebi_autogen_policy.tables,
    // 수동 오버라이드: notofly 는 creator_token 이지만 예외적으로 owner_token 사용
    notos: { tenantColumn: 'owner_token', mode: 'enforce' },
  },
},
```

이 경우 `notos` 는 사용자 값을 사용하고, `users` 는 AUTOGEN 값을 사용한다.
다음 `dok policy:scaffold` 재실행 시에도 사용자 수정은 보존된다 (AUTOGEN 블록 밖에 있으므로).

---

## 9. 테스트 커버리지

`tests/policyInference.test.mjs` (18 케이스):

- `extractTableDefinitions`
  - 기본 테이블 정의 추출
  - 주석 안의 `table()` 무시
  - 문자열 리터럴 안의 `table()` 무시
  - 중첩 괄호 / arrow 함수 / 스프레드 처리
- `inferTenantColumn`
  - `user_id` / `owner_id` / `creator_token` / `sender_token` 우선순위
  - `users` 테이블 self-tenant (`id`) 처리
  - 매칭 없음 → `null`
  - `_dokkebi_*` / `sqlite_*` 제외
- `defaultAuthzSpec`
  - SELECT → public, INSERT/UPDATE/DELETE → auth
  - 민감 테이블 (users, roles, payments) 상향
  - 시스템 테이블 → `null`
- `inferPolicyFromProject`
  - 모델 + `opTableStats` 조합
  - tenant 미감지 테이블 경고
- `mergeInferredIntoConfig`
  - `autoApply` 없을 때 제안만
  - `policy.autoApply: true` → 병합 + 사용자 값 보존
  - `authorization.autoApply: true` → 규칙 병합 + `*` 디폴트
  - `enabled: false` 이면 추론 스킵

모든 테스트는 `node --test tests/policyInference.test.mjs` 로 실행.

---

## 10. 제약과 향후 과제

### 10.1 현재 제약

- **모델 DSL 한정**: `table(...)` 패턴만 인식. Drizzle ORM / Prisma 등 다른 스키마 형태는 미지원.
- **단일 파일 / 전역 스캔**: `backend/models/` 하위 전체를 훑지만 import graph 는 따지지 않는다.
- **FK 기반 cascaded tenant 미지원**: `messages.noto_id → notos.creator_token` 같이 간접 격리는 수동 설정 필요.
- **authz 세분화 제한**: 기본은 `public` / `auth` / `admin` 3 단계. 조직/팀 롤은 사용자가 명시해야 함.

### 10.2 향후 고려 대상

- **P2. 어노테이션 기반 오버라이드**:
  ```ts
  /** @dokkebi tenant=user_id authz=SELECT:public,DELETE:admin */
  export const posts = table('posts', { ... });
  ```
- **P3. FK 그래프 추론**: 부모 테이블의 tenant 를 FK 경로로 승계.
- **P4. 런타임 관찰 기반 보강**: `learn` 모드에서 실제 호출된 (op, table) 쌍을
  자동으로 `rules` 에 추가.
- **P5. 비-D1 DB 지원 확장**: Postgres RLS 로 실제 DB 레벨 강제 적용 (현재는 프레임워크 레벨).

---

## 11. 보안 관점 — 추론이 보안을 약화시키지 않는 이유

1. **추론 결과는 항상 서버에서 평가된다**.
   빌드 타임에 `worker/api/_dokkebi/db.ts` 로 임베드되며, 클라이언트는 이 규칙을 볼 수 없다.
2. **추론 규칙은 보수적이다**.
   - 민감 테이블 (users, roles, payments) 의 파괴적 연산은 `admin` 만 허용.
   - 규칙 공백 (`*`) 의 기본값이 `public` 인 것은 "기존 동작 보존" 을 위한 현실적 선택이며,
     사용자가 `mode: 'strict'` + `'*': { deny: true }` 로 언제든 fail-closed 로 전환 가능.
3. **사용자 명시값이 항상 이긴다**.
   추론이 더 느슨한 규칙을 제안하더라도 사용자가 이미 `DELETE:users: { deny: true }` 로 막아뒀다면
   그것이 유지된다.
4. **autoApply 가 켜져 있지 않은 한 `dok build` 는 런타임 동작을 바꾸지 않는다**.
   즉, 기존 프로젝트가 의도치 않게 뚫리거나 막히지 않는다.

보안 경계는 v5.3 과 동일하며, 이 시스템은 **보안을 "기본 선택" 으로 만들기 위한 UX 레이어**다.

---

## 12. 변경 이력

- 2026-04-20 — 초안 (v1.0): P1 (convention + scaffold) 범위로 구현.
  - `mergeInferredIntoConfig` 가 기본 "제안만" 반환하도록 설계.
  - SQLite 내장 메타 테이블 (`sqlite_master` 등) 을 추론 대상에서 제외.
  - `extractTableDefinitions` 의 문자열 리터럴 false-positive 버그 수정
    (`_stripCommentsOutsideStrings` → `_tokenizeForScan` + `stringRanges`).
- 2026-04-23 — v1.3 (테이블별 sessionClaim / 비-JWT tenant 지원):
  - `policyEngine` 의 claim 해석이 **테이블 단위**로 독립 평가되도록 변경.
    우선순위: `tables[X].sessionClaim` → `policy.sessionClaim` → `tenantColumn` 이름 fallback.
  - `policyInference._inferSessionClaim` 추가 — `users.id` 는 `'user_id'`,
    그 외는 `tenantColumn` 을 그대로 세션 키로 매핑.
  - scaffold 가 모든 enforce 테이블에 `sessionClaim` 을 명시 출력.
  - 효과: JWT 나 로그인 세션 없이 해시 토큰(creator_token, sender_token, device_token 등)만
    쓰는 프로젝트에서도 `ctx.setSessionTenant({ <token_name>: value, ... })` 한 번이면 전체 정책 작동.
  - notofly: `notos/messages/users/noto_collaborators/push_subscriptions/message_replies`
    모두 자기 컬럼 기반 세션 키로 자동 매핑 확인.
  - AUTOGEN 블록 주석을 "비-JWT 해시 tenant" 시나리오까지 커버하도록 확장.
- 2026-04-20 — v1.2 (안전 기본값): scaffold 가 기존 프로젝트 런타임을 깨지 않도록 수정.
  - AUTOGEN policy: `enabled: false`, `mode: 'verify'`, `strict: false` 로 생성.
  - AUTOGEN authorization: `enabled: false` 로 생성.
  - `sessionClaim` 은 "가장 흔한 tenantColumn" 을 휴리스틱으로 선택 (`_pickCommonClaim`).
  - 블록 상단에 단계별 활성화 가이드 주석 (setSessionTenant 호출, JWT 시크릿 설정 등).
  - 배경: notofly 처럼 세션 기반 tenant 를 쓰지 않는 기존 프로젝트에서 scaffold 직후
    `TENANT_MISSING` 에러로 모든 쿼리가 차단되던 문제를 해결.
  - 보안 관점: 사용자가 의식적으로 `enabled: true` 로 전환하는 "opt-in of opt-in" 로
    바뀌었지만, 여전히 추론 결과는 모두 유지되고 scaffold 실행 시점에 "준비 사항" 이
    명확히 주석으로 제시된다.
- 2026-04-20 — v1.1 (관례 확장): notofly 실제 케이스로 검증된 추가 관례 반영.
  - `TENANT_COLUMN_CANDIDATES` 확장: `sender_token` / `author_token` /
    `subscriber_token` / `collaborator_token` / `member_token` 등 토큰 계열 추가.
  - 단계 3 신설 — 테이블 접미사 (`*_subscriptions`, `*_sessions`, …) + 단일 `token`
    컬럼이면 `token` 을 tenant 로. `push_subscriptions.token` 자동 감지.
  - 단계 4 신설 — `*_token` 일반 패턴. `NON_TENANT_TOKEN_PREFIXES` 로 인증 토큰류 제외.
  - `isSharedTable()` + `SHARED_TABLE_NAMES` 도입. `templates` / `categories` 등
    공유 참조 테이블은 경고 없이 자동 분류 (§3.2).
  - `inferPolicyFromProject` 반환값에 `sharedTables[]` 추가.
  - notofly 실 테스트 결과: 7 개 테이블 전부 자동 감지, 경고 0 개.
