# Query Registry (Stage 3) — Design Document

> Related: [`TENANT_POLICY.md`](./TENANT_POLICY.md) (Stage 1, 2)
>
> This document defines **Stage 3 — Query Registry (pre-registered queries)** for the Dokkebi framework.
> It follows Stage 1 (Tenant Verify) and Stage 2 (Tenant Inject). When this stage is complete,
> clients **cannot send SQL strings to the server**; only build-time-registered `queryId` values are allowed.

---

## 0.0 Inter-Stage Dependencies · Default Policy (Framework Philosophy)

Dokkebi supports **many use cases**, from single-user apps to multi-tenant SaaS. Each stage is designed to be **independently opt-in / opt-out**.

| Stage           | What it protects                         | Default              | How to enable                                                               | Dependencies            |
| --------------- | ---------------------------------------- | -------------------- | --------------------------------------------------------------------------- | ----------------------- |
| Allowlist       | Table/operation-level SQL permission     | ON (from v4)         | Always on (defense in depth)                                                | None                    |
| **Stage 3 (this doc)** | SQL shape-level permission          | **ON (v5 default)**  | Opt out with `queryRegistry.enabled: false`                                 | None (independent)      |
| Stage 1         | Missing tenant column detection          | OFF                  | `policy.enabled: true, policy.mode: 'enforce-verify'`                       | Stage 3 recommended     |
| Stage 2         | Automatic tenant condition injection     | OFF                  | `policy.mode: 'enforce-inject'`                                             | Requires Stage 1        |

### Runtime mode (`DOKKEBI_QUERY_MODE` Pages env var)

| Mode        | queryId match | Unregistered queryId           | Send sql without queryId | Recommended use                |
| ----------- | ------------- | ------------------------------ | ------------------------ | ------------------------------ |
| **`auto`**  | Run matched SQL | Fallback via `_debugSql`/`sql` | Allowed                  | **Default** (safe for new and existing apps) |
| **`strict`** | Run matched SQL | 403 reject                     | Reject if registry exists | Full protection (opt-in after learning) |
| **`learn`**  | Run matched SQL | Fallback via `_debugSql` + log | Allowed                  | Dev mode only                  |
| **`legacy`** | Run matched SQL | Fallback via `sql` field       | Allowed                  | v4 compatibility transition  |

> **Core**: In every mode, SQL Allowlist + common defenses (dangerous token, multi-statement block, etc.) **always run** for defense in depth. Query Registry is an **additional** layer on top.

**How to opt in to strict:**

1. `dokkebi.config.js`
```js
export default {
  queryRegistry: { enabled: true, strict: true },
};
```

2. Deploy flag
```bash
dok deploy --strict-registry
```

3. Set env var directly in Cloudflare Pages dashboard
```
DOKKEBI_QUERY_MODE=strict
```

### Implementation and release order (recommended)

```
v5.0 — Stage 3 (Query Registry) standalone release  [~1.5–2 weeks]
  └─ All apps benefit automatically (single-user apps also get fixed SQL shapes)

v5.1 — Stage 1 (Tenant Verify) opt-in add           [+1 week]
v5.2 — Stage 2 (Tenant Inject) opt-in add           [+1 week]
```

**Rationale**: Stage 3 helps every app immediately regardless of tenancy, and Stage 1·2 metadata can attach to registry entries for a natural extension base. See [TENANT_POLICY.md §0.0](./TENANT_POLICY.md#00-inter-stage-dependencies--default-policy-framework-philosophy) for details.

---

## TL;DR

- Today Dokkebi builds SQL strings inside the WASM guest DSL and calls `_execSql(sql, params)`.
  That SQL is encrypted in transit, but **from the server’s view it is still “a string from the client”**, so post-hoc SQL allowlist validation is required.
- Query Registry inverts this flow: **collect all allowed SQL at build time into a `queryId → SQL` registry,
  and at runtime send only `queryId + params`**. The server looks up SQL from the registry, so
  **there is no “client-sent SQL string”**.
- As a result, **SQL injection / allowlist bypass / dynamic query manipulation attack surface is effectively eliminated**.
- Dokkebi DSL has a single insertion point at `QueryBuilder._compile()`, so implementation difficulty is moderate.
- Estimated timeline: **1.5–2 weeks (S3.1–S3.5)**.

### Collection paths (v5 — automatic via `dok build` / `dok deploy`)

| Path                                        | When          | Target                                                                  | Notes                              |
| ------------------------------------------- | ------------- | ----------------------------------------------------------------------- | ---------------------------------- |
| **(a) Static scan** (`queryScanner.js`)     | Build time    | SQL string literals in `backend/**`, `src/backend/**`, `functions/**`   | **Automatic** — ON by default      |
| (b) Comment declaration (`// @dokkebi-query: ...`) | Build time | Comments in `backend/**/*.{ts,js}`                                      | Manual registration for dynamic SQL |
| (c) Runtime learning                        | `dok dev` run | `.dokkebi/query-registry.learned.json`                                | Queries executed in dev only       |

**(a) Static scan details**:
- Collect when first token of `.prepare('...')`, `.prepare("...")`, `.prepare(\`...\`)`, or free string literal is
  `SELECT / INSERT / UPDATE / DELETE / WITH / REPLACE / CREATE TABLE / CREATE INDEX`
- `${...}` interpolation in template literals converges to `?` then canonicalize — covers most DSL/SQL tag templates
- SQL inside comments (`//`, `/* */`) is excluded
- Disable: `queryRegistry.scan: false` in `dokkebi.config.js`
- Customize scan roots: `queryRegistry.scanRoots: ['server', 'api']`

---

## 1. Background

### 1.1 Current request flow (v4)

```
[WASM guest]
  backend/controllers/users.controller.ts
    db.select(users).where(eq(col('id'), userId)).exec()
         │
         ▼
  QueryBuilder._compile() → { sql: 'SELECT * FROM "users" WHERE "id" = ?', params: [42] }
         │
         ▼
  runtime._execSql(sql, params)  ← ❶ SQL string created here
         │
         ▼ (host call)
[WASM host bridge]
  Encrypt package → POST /api/_dokkebi/db  ← ❷ SQL string leaves the network
         │
         ▼
[Pages Function]
  Decrypt → validateSqlAllowlist(sql) → D1.prepare(sql).bind(params)  ← ❸ Server interprets SQL string
```

### 1.2 What is the problem?

| Layer | Current defense                                      | Remaining risk                                                            |
| ----- | ---------------------------------------------------- | ------------------------------------------------------------------------- |
| ❶    | Auto prepared (`?` placeholder) when using DSL         | WASM binary analysis can expose raw SQL structure                         |
| ❷    | ECDH + HKDF + AES-GCM + HMAC                         | Once session is established, **arbitrary SQL** can be encrypted and sent legally |
| ❸    | SQL Allowlist validation (v2 embed)                  | If allowlist permits `SELECT * FROM users`, attacker can craft arbitrary queries in that scope (e.g. `SELECT password_hash FROM users`) |

**Core issue**: Allowlist permits “which tables / which operations”, not “which **query shape**”.
An attacker can change columns, drop `WHERE`, or add `ORDER BY` within the allowlist to extract information.

### 1.3 What Query Registry solves

- Blocks changing SELECT column lists (prevents exposing `password_hash`, `salt`, etc.)
- Blocks removing or altering WHERE (`SELECT * FROM orders WHERE user_id = ?` only; not `WHERE user_id IS NOT NULL`)
- Blocks condition order / logic manipulation (`WHERE a = ? OR 1=1`, etc.)
- Blocks all queries the developer did not explicitly author

---

## 2. Goals / Non-goals

### Goals
1. Clients **do not send SQL strings over the network**. Only `{ queryId, params }`.
2. Server resolves `queryId` **only from the build-time registry**. No runtime registration (`deploy` env).
3. Stage 1, 2 Tenant Policy is injected server-side after registry match.
4. Existing DSL API (`db.select(users).where(...)`) works **with no source-level changes**.
5. `dev` mode: auto-collect registry + warn; `deploy`: strict fail-closed.

### Non-goals
- Full support for hand-written raw SQL (limited fallback described later).
- Replacing with a different query interface (GraphQL, etc.).
- Runtime optimization (prepared statement caching) — Cloudflare D1 already handles this.

---

## 3. Terminology

| Term              | Definition                                                                 |
| ----------------- | -------------------------------------------------------------------------- |
| Query Shape       | SQL string excluding parameters (normalized form with only `?` placeholders) |
| Query ID          | SHA-256 prefix of Query Shape (e.g. `q_a3f9b2c1`)                          |
| Registry          | `{ queryId → { sql, meta } }` map. Build artifact                        |
| Registry Entry    | Single registry item — original SQL, source file, policy meta              |
| Dry-Run collection | Run controllers in QuickJS sandbox at build time to extract shapes        |
| AST extraction    | Statically parse DSL chains via TypeScript compiler API                    |
| Shape Canonicalization | Normalize whitespace, case, quotes so identical queries hash the same |

---

## 4. Two implementation approaches — comparison and choice

There are two main ways to populate Query Registry. **They are not mutually exclusive; use both.**

### 4.A) **Runtime hashing + build-time dry-run collection** (recommended, implement first)

```
[Build time]
  dok build
    ├─ bundleBackend()                  ← existing
    ├─ Sandbox run:
    │    runtime._execSql = (sql, params) => registry.add(canonicalize(sql))
    │    ↓
    │    Call controllers/* handlers with "probe input"
    │    (sample req/ctx per handler)
    └─ Generate query-registry.json → embed in Pages Function
[Runtime]
  WASM internal DSL._compile() → { sql, params }
    ├─ queryId = sha256(canonicalize(sql)).slice(0,16)
    └─ _execQuery({ queryId, params })   ← no SQL string sent
[Pages Function]
  Registry lookup by queryId → registered SQL + tenant policy inject → D1.prepare().bind(params).run()
  (if not in registry → 403 immediately)
```

**Pros**
- No AST parsing — reuse DSL SQL generation as-is
- Auto-collect all shapes from conditional branches (if dry-run coverage is sufficient)
- Minimal DSL changes (one line: hash in `_compile()` return path)

**Cons**
- Handlers that depend on real DB results (e.g. “if empty, run another query”) may not be fully covered by dry-run → dev auto-learning supplements
- Handlers with side effects (external API calls) need stubs in sandbox

### 4.B) **Build-time static AST extraction + compile-time substitution**

```
[Build time]
  esbuild plugin or ts-morph scans controllers AST
    ├─ Find db.select(users).where(...).exec() chains
    ├─ Run _compile() at build time → generate SQL
    └─ Transform source: db.select(...)...exec() → db.__executeById('q_a3f9b2c1', params)
```

**Pros**
- No DSL → SQL conversion at runtime → smaller client bundle
- No SQL generation logic in client → **query structure hidden even on WASM reverse engineering**
- Strongest defense

**Cons**
- Very high implementation complexity (TypeScript AST, type inference, dynamic branches)
- Dynamic table names like `db[tableName].select().where(...)` are not statically analyzable
- Many conditional chains → combinatorial explosion at compile time

### Decision — **hybrid, 4.A first**

| Phase   | Approach | Notes |
| ------- | -------- | ----- |
| Stage 3.1 | 4.A (runtime hash + dry-run) | ~1 week; target ~95% coverage |
| Stage 3.2 | 4.A + dev auto-learning | Auto-register missing shapes at runtime (dev only) |
| Stage 3.3 | 4.B optional | AST substitution only when DSL is a “simple chain” (WASM size optimization) |

This document details **Stage 3.1 + 3.2**; 3.3 is overview only.

---

## 5. Architecture

### 5.1 Registry file schema (v1)

**File**: `dist/dokkebi/query-registry.json` (build output)

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

### 5.2 Shape Canonicalization rules

SQL is converted to canonical form before hashing for consistent registry matching.

1. String literals · numeric literals → `?` (already handled by DSL)
2. Consecutive whitespace → single space
3. Trim leading/trailing whitespace
4. Preserve identifier `"column"` case (D1/SQLite is case-sensitive inside double quotes)
5. Keywords (`SELECT`, `FROM`, `WHERE`, ...) → **UPPERCASE**
6. Strip comments (`--`, `/* */`)

```js
function canonicalizeSql(sql) {
  let s = stripStringsAndComments(sql);  // reuse existing sqlAllowlist util
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

### 5.3 Build time (Stage 3.1)

New module: `src/core/queryRegistry.js`

```
src/core/queryRegistry.js
  ├── collectQueriesByDryRun(projectDir, opts)   // core: probe execution
  ├── collectQueriesByStatic(projectDir, opts)   // 3.3 placeholder
  ├── canonicalizeSql(sql)
  ├── computeQueryId(sql)
  ├── writeRegistry(registry, outPath)
  └── mergeWithTenantPolicy(registry, policyMeta) // Stage 2 integration
```

**Dry-run collection flow** (`collectQueriesByDryRun`):

1. Load `bundleBackend()` output JS into QuickJS (Node `quickjs-emscripten` or existing build pipeline)
2. Inject runtime stubs:
   ```js
   const registry = new Map();
   const runtime = {
     _execSql: async (sql, params) => {
       const id = computeQueryId(sql);
       registry.set(id, { sql: canonicalizeSql(sql), ... });
       return { ok: true, value: { rows: [] } };       // empty result
     },
     // fetch, crypto, now, jwt etc. are full stubs
   };
   ```
3. Call exported handlers from controllers with probe input:
   - Inject **shape-generating** stub values into `req.params`, `req.query`, `req.body` (empty string, 0, {})
   - Multiple probe calls for branch coverage (especially `if (x) { A } else { B }`)
4. Record collected shapes via `writeRegistry()`

**Limits and supplements**:
- “Different query based on result” — dry-run only covers first call. In that case:
  - Developer can declare queries explicitly in `backend/queries.ts` (new) to force inclusion
  - `dev` mode auto-learns shapes that appear on real use (3.2)

**CLI integration (build.js)**:

```js
// dokkebi-cli/src/commands/build.js (addition)
import { collectQueriesByDryRun, writeRegistry } from '../core/queryRegistry.js';

// ... after bundleBackend + buildQuickJSBundle
if (config.queryRegistry !== false) {
  const registry = await collectQueriesByDryRun(projectDir, { bundlePath });
  await writeRegistry(registry, path.join(outDir, 'dokkebi', 'query-registry.json'));

  // Embed in Pages Function template (same pattern as allowlist)
  regenerateServerlessDb({ registry, allowlist });
}
```

### 5.4 Runtime — client DSL changes (Stage 3.1)

**File**: `packages/dokkebi-dsl/src/index.js`

Modify `QueryBuilder.exec()` and `createDb().raw()`:

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
  if (this._runtime._execQuery) {                       // new path: Query Registry mode
    const queryId = await computeQueryIdSync(sql);
    const result = await this._runtime._execQuery({ queryId, params, _debugSql: sql });
    // _debugSql used by server in dev only for warn/auto-learn
    // ...
  } else {                                              // fallback: legacy _execSql
    const result = await this._runtime._execSql(sql, params);
    // ...
  }
}
```

- `_execQuery` implemented in host bridge (Pages Function path)
- `_execSql` kept for **local DB mode (sql.js)** — local mode runs without registry
- `computeQueryIdSync` is WebCrypto `subtle.digest` sync wrapper (async OK inside WASM)

### 5.5 Runtime — Pages Function changes (Stage 3.1)

**File**: `worker/api/_dokkebi/db.ts` (`projectGenerator.js` template)

Current flow:
```
verifyHmac → decryptAesGcm → JSON.parse(plaintext) → { sql, params } → allowlist.validate(sql) → D1.prepare(sql).bind(params)
```

New flow (v5):
```
verifyHmac → decryptAesGcm → JSON.parse(plaintext) → { queryId, params, _debugSql? }
  ├─ if (env.DOKKEBI_QUERY_MODE === 'strict')
  │    entry = REGISTRY[queryId]
  │    if (!entry) return 403 "queryId not registered"
  │    sql = entry.sql
  │
  └─ else if (env.DOKKEBI_QUERY_MODE === 'learn')   // dev only
       entry = REGISTRY[queryId]
       if (!entry) {
         // re-canonicalize _debugSql → verify hash match
         // if match → auto-register + warn
         // if mismatch → 403
       }
       sql = entry?.sql ?? _debugSql
  ↓
  tenantPolicy.verify(sql, session) || tenantPolicy.inject(sql, session)    // Stage 1, 2
  ↓
  allowlist.validate(sql)            // defense in depth — still kept
  ↓
  D1.prepare(sql).bind(...params).run()
```

**Embed size**: registry ≈ query count × ~200B. 1000 queries ≈ 200KB. Fits Pages Function 1MB limit.

### 5.6 Dev mode auto-learning (Stage 3.2)

When running `dok dev`:
- `DOKKEBI_QUERY_MODE=learn` set automatically
- If an unregistered shape arrives:
  - Console warn: `[query-registry] unregistered query found → auto-registering`
  - Add to in-memory registry and continue
  - Record in `.dokkebi-cache/query-registry.learned.json`
- On `dok build`, merge learned queries into final registry

On deploy (`dok deploy`):
- Force `DOKKEBI_QUERY_MODE=strict`
- Ignore learn file — only build artifacts are valid

---

## 6. Integration with Stage 1 · 2

| Stage combo | Runtime flow summary |
| ----------- | -------------------- |
| v4 (current) | client SQL → allowlist → D1 |
| Stage 1   | client SQL → allowlist → tenant verify → D1 |
| Stage 2   | client SQL → allowlist → tenant inject → D1 |
| **Stage 3** | client queryId → **registry lookup** → tenant inject → allowlist (depth) → D1 |

Allowlist remains in Stage 3 — **defense in depth**.
Registry lookup is the primary gate; if the registry pipeline has a bug, allowlist is the second line.

Tenant Policy meta is on registry entries via `tenantPolicy` so Stage 2 inject can apply **per query**.

---

## 7. Raw SQL handling

`createDb(runtime).raw(sql, params)` bypasses the DSL. In Stage 3, one of:

| Mode              | Behavior                                                                   |
| ----------------- | -------------------------------------------------------------------------- |
| `raw: 'deny'`     | Error at build time on `raw()` call (default, recommended for deploy)      |
| `raw: 'register'` | Include `raw()` in registry on dry-run when shape is deterministic         |
| `raw: 'legacy'`   | Send via `_execSql` (allowlist-only defense) — dev convenience             |

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

## 8. Per-file change summary

| File                                                     | Changes                                                                             |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `packages/dokkebi-dsl/src/index.js`                      | Add `_execQuery` path to `exec()` / `raw()`, `computeQueryIdSync` helper             |
| `src/core/queryRegistry.js` (new)                        | dry-run collection, canonicalize, hash, registry serialization                      |
| `src/commands/build.js`                                  | Add `collectQueriesByDryRun` to build pipeline, embed call                          |
| `src/commands/dev.js`                                    | Force `DOKKEBI_QUERY_MODE=learn`, write learn file                                  |
| `src/commands/deploy.js`                                 | Force `DOKKEBI_QUERY_MODE=strict`, verify registry exists before deploy             |
| `src/core/projectGenerator.js`                           | Update `worker/api/_dokkebi/db.ts` template to v5 — registry lookup, embed pattern  |
| `src/commands/update.js`                                 | v4→v5 upgrade path, `db.ts requiresRebuild: true`, user notice                      |
| `src/core/sqlAllowlist.js`                               | No change (keep defense in depth)                                                   |
| `dokkebi-site/frontend/src/pages/Security.tsx`           | Add Query Registry section — “unregistered query” row in attack matrix              |
| `dokkebi-site/frontend/src/pages/CliCommands.tsx`        | Document query-registry step in `dok build`, v5 upgrade guide                       |

---

## 9. CLI commands (new / extended)

```bash
# View registry status
dok query status

# Example output:
# Query Registry v1
#   Total queries: 47
#   ├── SELECT: 28
#   ├── INSERT: 9
#   ├── UPDATE: 7
#   └── DELETE: 3
#   Tenant policy mapped: 44 / 47
#   Source files: 12

# Query detail
dok query show q_a3f9b2c1d4e5f678

# Rebuild registry (dry-run)
dok query rebuild

# Merge learned queries
dok query merge-learned
```

---

## 10. Test plan

### Unit tests
- `canonicalizeSql`: whitespace/case/comment variants → same hash (10 cases)
- `computeQueryId`: deterministic hash, collision check (SHA-256 16-char prefix collision ~2⁻⁶⁴ negligible)
- `collectQueriesByDryRun`: expected query count from sample controller
- `exec()` vs `_execQuery` routing branch

### Integration tests (`test/integration/query-registry/`)
- Registered shape → runs OK
- Unregistered shape (client tampering) → 403
- Canonicalize-equivalent query (extra whitespace) → OK (same queryId)
- Dev learn mode auto-registers new shape
- Strict mode rejects new shape
- Stage 2 (tenant inject) — tenant condition injected into registry SQL

### Regression tests
- Existing `dokkebi-snow` sample — all v4 queries auto-collected in registry with ≥80% coverage

### Performance
- Registry lookup: O(1) Map, <0.1ms for 1000 entries expected
- Hash (`subtle.digest`): SHA-256 16 bytes ~<0.5ms in browser
- Build time: dry-run adds ~2–5s (depends on controller count)

---

## 11. Roadmap

### S3.1 — Basic Query Registry (1 week)
- [ ] Implement `queryRegistry.js` (canonicalize, hash, dry-run)
- [ ] DSL `_execQuery` path
- [ ] Pages Function v5 template
- [ ] `build.js` / `deploy.js` integration
- [ ] Basic tests

### S3.2 — Dev auto-learning (2–3 days)
- [ ] `dev.js` learn mode
- [ ] `.dokkebi-cache/query-registry.learned.json`
- [ ] `dok query merge-learned`

### S3.3 — Explicit declaration & raw modes (2 days)
- [ ] Read `backend/queries.ts` (declarative query registration)
- [ ] `raw: 'deny' | 'register' | 'legacy'` modes
- [ ] `dokkebi.config.js` validation

### S3.4 — CLI & observability (1–2 days)
- [ ] `dok query status / show / rebuild`
- [ ] Coverage in build log

### S3.5 — Docs & site update (1 day)
- [ ] Update `SECURITY.md`
- [ ] `dokkebi-site` Security.tsx / CliCommands.tsx
- [ ] Upgrade guide (v4 → v5)

Total **~1.5–2 weeks**.

---

## 12. Migration

### New project (`dok create`)
- Enabled by default — `queryRegistry: { enabled: true, raw: 'deny' }`
- Auto-collect on `dok build`

### Existing v4 project (`dok update`)
- Add `query-registry.json` to `WORKER_FILES`, promote `db.ts` to version 5
- `update.js` completion notice:
  ```
  [!] v5 upgrade applied.
      You must run `dok build` to generate the query registry.
      Without it, all DB calls return 403 (strict mode).
  ```
- Back compat: set `queryRegistry.enabled: false` in `dokkebi.config.js` to keep v4 behavior

---

## 13. FAQ / Known limitations

### Q1. Branches like `if (admin) SELECT ... else SELECT ...`?
Both shapes must be registered. If dry-run misses a branch, dev learn mode auto-registers.
`dok lint` can guide static-analysis-friendly style.

### Q2. Is SQL still exposed inside WASM?
Yes (on WASM reverse engineering). But:
- **Attacker still cannot send that SQL to the server** — only `queryId` is accepted
- SQL exposure is “knows what the query fetches” level, comparable to publishing OpenAPI
- Stage 3.3 (AST substitution) can add further hiding

### Q3. Complex queries with `JOIN` or subqueries?
Supported if DSL-generated SQL is deterministic. Current DSL has no JOIN — N/A for now.
When DSL adds JOIN, same canonicalize logic applies.

### Q4. Registry size with many queries?
1000 queries × ~200B ≈ 200KB. OK up to 2000+ queries within Cloudflare Pages Function 1MB limit.
Extreme case: store registry in separate KV and lookup (S3.3+).

### Q5. Parameter type enforcement?
Registry entries include `paramTypes`; server can type-check. Wrong type → 400.
Dev mode can warn at DSL runtime too.

### Q6. Legacy queries that need raw SQL?
`raw: 'legacy'` keeps allowlist-only path. Document on site: “raw queries are outside Query Registry defense”.

### Q7. Frontend bypass via `fetch('/api/_dokkebi/db', ...)`?
Not possible — must go through session handshake + HMAC + AES-GCM. That path requires DSL, which sends only queryId.

### Q8. Actual security effect?
- **SQL Injection**: fully blocked (stronger than allowlist alone)
- **Unauthorized column access**: blocked (only registered SELECT columns)
- **Condition manipulation**: blocked (fixed WHERE shape)
- **Batch / probing attacks**: blocked (unregistered shapes → 403)
- **Tenant breach with Stage 2**: auto-blocked

---

## 14. Appendix — Stage 3 alone vs Stage 1/2 first

| Combination              | Defense | Dev cost | Recommended |
| ------------------------ | ------- | -------- | ----------- |
| Stage 1 only             | Medium  | Medium   | △           |
| Stage 2 only             | Medium+ | Medium+  | △           |
| **Stage 3 only**         | High    | Medium   | ○ (enough without tenancy) |
| Stage 1+2+3              | Highest | High     | ◎ (multi-tenant + high security) |

**Conclusion**: For most Dokkebi use cases, **Stage 3 alone materially improves security**.
Add Stage 2 when tenant isolation is required.

---

## 15. References
- [TENANT_POLICY.md](./TENANT_POLICY.md) — Stage 1, 2
- [SECURITY.md](../../SECURITY.md) — Full security model
- [Cloudflare D1 Prepared Statements](https://developers.cloudflare.com/d1/best-practices/prepared-statements/)
- OWASP Top 10 — A03:2021 Injection
