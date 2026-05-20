# dokkebi-cli Security Documentation

> Last updated: 2026-04-20
> This document records **currently implemented defense layers and remaining limitations**.
> For version-by-version change history, see CHANGELOG.
>
> For a guide on **"which attack does each user-toggleable option block?"**,
> see [`docs/SECURITY_OPTIONS.md`](docs/SECURITY_OPTIONS.md).

---

## 0. Summary (TL;DR)

Dokkebi is an experimental architecture designed to establish one thing:

> **"Backend business logic is packaged in an obfuscated + AES-256-GCM protected bundle, runs in the browser's local QuickJS WASM VM, and the DB is only reachable through an encrypted proxy. DB credentials are never exposed to the browser."**

For that goal, it works strongly. However, **"user permission/authorization decisions"** must be made outside the browser (proxy layer or the DB itself) by design—§6 is the core of this document.

**As of now:**
- 🟢 Well defended: transport encryption, SQL injection, timing attacks, path traversal, body DoS, rate limits, nonce replay, session key leakage
- 🟡 Available as opt-in: row-level isolation (Tenant Policy), operation-level authorization (Authorization Policy)
- 🔴 Structural limits: XSS cascade damage, browser-direct API plugin key exposure, distributed DDoS, intellectual property protection

---

## 1. Architecture & trust boundaries

```
  ┌──────────────────────┐                     ┌────────────────────────┐
  │ Browser (Untrusted)  │                     │ dok serve / CF Worker  │
  │                      │                     │   (Trusted Proxy)      │
  │  ┌────────────────┐  │   AES-256-GCM       │                        │
  │  │ QuickJS WASM VM│  │    + HMAC-SHA256    │ 4-layer SQL pipeline   │
  │  │  backend.bundle│──┼──── + Nonce+TS ────▶│                        │
  │  │  (biz logic)   │  │                     │                        │
  │  └────────────────┘  │                     │ (opt) JWT+role auth    │
  │  env secrets: Opaque │                     │                        │
  │  Handle (host closure)                     └───────────┬────────────┘
  └──────────────────────┘                                 │
                                                           ▼
                                                    ┌──────────────┐
                                                    │ D1/Supabase/ │
                                                    │  Appwrite    │
                                                    └──────────────┘
```

| Layer | Trust level |
|---|---|
| Browser JS / WASM bundle | ❌ Untrusted. Assume attacker has full control. |
| Proxy (dok serve / Pages Function) | ✅ Trusted |
| DB | ✅ Trusted |

Key conclusion: the proxy **will** accept requests from **any cryptographically valid client**. Whether it is a "legitimate user of my app" must be decided **additionally** by the proxy (§6).

---

## 2. Defense layers — current implementation

### 2.1 Transport / network

| ID | Goal | Implementation | Limitations |
|---|---|---|---|
| A-1 | Eavesdropping/tampering | **ECDH(P-256) + HKDF-SHA256 → AES-256-GCM** bidirectional encryption | No server public-key verification outside TLS—if TLS is broken, the session belongs to the attacker |
| A-2 | Request integrity | **HMAC-SHA256** signature verification | Applied to entire request |
| A-3 | Replay | **Nonce (one-time) + ±5s TS skew window** — in-memory map + D1 `_dokkebi_nonces` dual check for cross-isolate replay blocking, cache only after HMAC passes | nonce cache 35s TTL (both tunable via `security.replay`) |
| A-4 | Forward Secrecy | ECDH Ephemeral — new keypair per handshake | Weakened if server keeps long-lived session JWK |

### 2.2 Session

| Implementation | Details |
|---|---|
| Session ID | `crypto.randomUUID()` (128-bit) |
| Session keys | enc/sig keys separated via HKDF (`dokkebi-enc` / `dokkebi-sig`) |
| Storage | D1 `_dokkebi_sessions` + isolate in-memory cache |
| TTL | 10 min (server) / 8 hours (serverless cache) |
| Session bomb defense | `MAX_SESSIONS=500` + FIFO + 20 handshakes/min per IP |

### 2.3 SQL security — 4-layer pipeline + 2 options

```
Request → [Common defense] → [Allowlist] → [Query Registry] → [Tenant Policy] → [Authorization] → DB
          always           always         always             opt-in             opt-in
```

| Layer | Role | Coverage |
|---|---|---|
| **Common defense** | Blocks multiple statements (`;`), comments (`-- /**/`), >50KB, dangerous tokens (`ATTACH`, `PRAGMA`, `LOAD_EXTENSION`, `INTO OUTFILE`, `xp_*`, `SLEEP`, `PG_SLEEP`, `BENCHMARK`, `WAITFOR`, `INFORMATION_SCHEMA`) | always |
| **SQL Allowlist** | Table × operation (SELECT/INSERT/UPDATE/DELETE) permit. All FROM/JOIN/INTO/UPDATE references checked. `CREATE TABLE` only for `_dokkebi_*` | always |
| **Query Registry** | SQL **shape** permit — blocks structural tampering (column changes, WHERE removal, `OR 1=1`, etc.). Collected via static scanner + comment declarations + dev learning | always (auto/strict modes) |
| **Tenant Policy** | Row-level isolation — validates or auto-injects `WHERE user_id = ?`. Detects top-level `OR`, missing WHERE, aliased columns | opt-in |
| **Authorization** | Operation-level permissions — e.g. "DELETE posts only for role=admin" — JWT signature + role match | opt-in |

Parameter binding is handled by D1/Supabase/Appwrite SDK via `prepare().bind()`. The proxy never interpolates raw SQL as strings.

### 2.4 Crypto implementation

| Implementation | Details |
|---|---|
| HMAC compare | `timingSafeEqual` + dummy compare on length mismatch for **constant-time** behavior |
| Admin PW compare | Constant-time compare after padding |
| Nonce | `crypto.randomUUID()` per request |
| Plaintext cleanup | `plain.fill(0)` immediately after decrypt (best-effort) |
| Curve | P-256 (prime256v1) |
| env secrets | Wrapped with AES-GCM at build time, stored in OPFS. Decrypt only in Host closure |

### 2.5 DoS / resource exhaustion

| Category | Limit |
|---|---|
| Handshake | 20/min per IP |
| DB query | 300/min per IP + valid session |
| Log | 600/min per IP + 64KB body |
| Body size | handshake 8KB / db 128KB / log 64KB / admin 2KB — `Content-Length` pre-check + abort during streaming |
| Sessions | max 500 + FIFO |
| Nonce cache | TTL 35s + cleanup every 60s |

### 2.6 Information disclosure

| Implementation | Details |
|---|---|
| DB credentials | Opaque Handle — proxy side only. Not in browser |
| Query content | AES-GCM encrypted channel — plaintext not observable in DevTools |
| Path traversal | `safeStaticJoin()` — blocks `../`, `%2e%2e`, null bytes + distRoot re-validation |
| Sensitive file serving | Blocks paths like `.dokkebi/env-secrets.json`, `.dev.vars` |
| Error messages | `sanitizeDbError()` — masks Bearer/Authorization |

### 2.7 Bundle integrity / build

| Implementation | Details |
|---|---|
| `backend.bundle.enc` | Build-time SHA-256 + runtime `crypto.subtle.digest` verification |
| QuickJS WASM | Local npm packages (`@jitl/quickjs-*`) — no external CDN dependency |
| Build tools | Structured Node API–centric processing. External commands only where needed (deploy/install) via array args |

### 2.8 Admin panel

| Implementation | Details |
|---|---|
| PW compare | Constant-time |
| Brute force | 5 failures per IP → 5 min lock |
| Token | HMAC signed + expiry |
| Body | 2KB cap |

### 2.9 Plugins

| Plugin | Status | Notes |
|---|---|---|
| `plugin-fetch` | ✅ Built-in | Domain whitelist, http/https scheme enforced, standalone TLD rejected |
| `plugin-bundle` | ✅ Built-in | Code bundler |
| `plugin-ai` | ❌ **Removed from CLI built-in** (v5.3) | Moved to `examples/plugins/plugin-ai.js`. Production enable fails build unless `acknowledgeKeyExposure` is set. See §5 |

---

## 3. Opt-in security features

### 3.1 Tenant Policy — Row-level isolation

**Purpose**: "User A must not see User B's data"

```js
// dokkebi.config.js
policy: {
  enabled: true,
  mode: 'inject',        // 'verify' (validate only) | 'inject' (auto-inject)
  claim: 'user_id',      // field from session tenant_json
  strict: true,
  tables: {
    posts: { tenantColumn: 'user_id', mode: 'enforce' },
    orders: { tenantColumn: 'user_id', mode: 'enforce' },
  },
},
```

Flow:
1. Client calls `ctx.setSessionTenant({ user_id: 'u1' })` (after login)
2. Proxy stores in session `tenant_json`
3. All subsequent SELECT/UPDATE/DELETE are verified (verify) or auto-injected (inject) with `WHERE user_id = ?`
4. INSERT validates `user_id` column matches session tenant

Details: [docs/design/TENANT_POLICY.md](docs/design/TENANT_POLICY.md)

### 3.2 Authorization Policy — Operation-level authorization (new in v5.3)

**Purpose**: "DELETE posts must be allowed only for role=admin"

```js
authorization: {
  mode: 'warn',  // 'warn' (default) | 'strict'
  jwtSecretEnv: 'DOKKEBI_JWT_SECRET',
  claim: 'role',
  rules: {
    'SELECT:posts':  { public: true },
    'INSERT:posts':  { auth: true },
    'UPDATE:posts':  { roles: ['admin', 'author'] },
    'DELETE:posts':  { roles: ['admin'] },
    'DELETE:users':  { deny: true },
    '*':             { auth: true },
  },
},
```

Flow:
1. Client sends JWT via `Authorization: Bearer <jwt>` header or encrypted payload `_jwt` field
2. Proxy verifies HS256 signature + `exp/nbf/iss/aud`
3. Match rules by final SQL (op, table) → role check
4. Failure returns 401 (AUTH_REQUIRED) or 403 (ROLE_FORBIDDEN, etc.)

**The layer that practically solves the "authorization boundary" problem in §6.** JWT issuance must be implemented separately by the user (login endpoint).

Details: [docs/design/AUTHORIZATION.md](docs/design/AUTHORIZATION.md)

### 3.3 WebAuthn (Passkey) request signing — opt-in (v5.5+, **runtime not implemented**)

> ⚠️ **Current status**: `dok init` option and `webauthn` section in `dokkebi.config.js`, plus client SDK entry points (`dokkebi.webauthn.register/authenticate`) are defined, but **worker-side assertion verification / `requireForOps` gate is not implemented yet** (follow-up PR — see `docs/design/WEBAUTHN.md` "runtime SDK implementation is a follow-up PR"). Setting `enabled: true` does not enforce anything server-side today. Read this section as **design intent**.

When enabled via `dok init`, sensitive operations can require an additional signature from a **private key in OS/TPM/Secure Enclave** that cannot be extracted from browser memory. Even if session keys are stolen via XSS, the attacker cannot pass fingerprint/Face/PIN prompts every time.

```js
// dokkebi.config.js
security: {
  webauthn: {
    enabled: true,
    requireForOps: ['INSERT:*', 'UPDATE:*', 'DELETE:*'], // UV required for writes only
  },
}
```

You must wire **`dokkebi.webauthn.register({ userId, userName })` right after signup** and **`dokkebi.webauthn.authenticate({ userId })` right after login** for protection to actually apply. `dok build` prints a wiring reminder banner every build.

Design and integration guide: [docs/design/WEBAUTHN.md](docs/design/WEBAUTHN.md)

### 3.4 Operations admin IP allowlist

`/_dokkebi/_panel` supports IP-based access restriction in production in addition to password auth and login rate limits. Off by default; enable explicitly in `dokkebi.config.js`.

```js
// dokkebi.config.js
security: {
  panelIpGuard: true,
}
```

```env
DOKKEBI_ADMIN_PASSWORD=your_secure_password
DOKKEBI_PANEL_ALLOWED_IPS=203.0.113.10,198.51.100.0/24
```

Behavior:
1. Worker prefers `CF-Connecting-IP`; otherwise first value of `X-Forwarded-For`
2. When `security.panelIpGuard` is `false`, `DOKKEBI_PANEL_ALLOWED_IPS` is ignored even if set
3. When `security.panelIpGuard` is `true` but `DOKKEBI_PANEL_ALLOWED_IPS` is empty, `dok build` warns
4. When set, panel HTML, login, and API access allowed only for comma-separated exact IPs or IPv4 CIDR matches
5. Blocked requests return 403; serverless panel with D1 logs `panel_ip_block` to `_dokkebi_security`

Same config applies to `dok dev`, `dok serve`, and Cloudflare Pages Functions panel. `DOKKEBI_ADMIN_ALLOWED_IPS` is read for legacy compatibility; new projects should use `DOKKEBI_PANEL_ALLOWED_IPS`.

### 3.5 Signed Unlock Token — Cryptographic Checkpoint (opt-in)

**Purpose**: Raise the cost of attacks that patch browser WASM `if (user.plan === 'premium')` branches to force paid/high-cost features.

```js
// dokkebi.config.js
security: {
  capabilities: {
    enabled: true,
    secretEnv: 'DOKKEBI_CAPABILITY_SECRET',
    defaultTtlMs: 15000,
    features: {
      'image.generate': {
        roles: ['premium', 'admin'],
        ttlMs: 10000,
        routes: ['POST /api/ai/image'],
      },
      'admin.export': {
        roles: ['admin'],
        ttlMs: 5000,
        routes: ['POST /api/admin/export'],
      },
    },
  },
}
```

Or declare build-time auto-application via controller JSDoc:

```ts
/**
 * @dokkebi-capability feature:image.generate route:"POST /api/ai/image" roles:['premium','admin'] ttl:10000
 */
router.post('/api/ai/image', async (ctx) => {
  // ctx.capability available after guard passes
});
```

Flow:
1. `dok build` collects `security.capabilities.features[*].routes` and `@dokkebi-capability`
2. Dokkebi runtime router auto-inserts capability guard before matching routes
3. On request, guard calls `capability.unlock(feature, { state, jwt })`
4. Requests use existing `/api/_dokkebi/db` encrypted channel—must pass ECDH, AES-GCM, HMAC, nonce, timestamp, ADL defenses
5. Worker checks feature policy and JWT role
6. Worker-only `DOKKEBI_CAPABILITY_SECRET` signs `feature + sessionId + controllersHash + stateHash + nonce + exp`
7. After guard passes, handler uses `ctx.capability` `token/proof` as execution material, not a simple permit flag

Important limitations:
- Does not replace Authorization Policy. DB write/delete permissions must still be enforced via Worker Authorization Policy or DB RLS.
- `if (verify(token)) runFeature()` is vulnerable to verify-function patching. Bind `proof` or values derived from the token into decrypt keys/params/server request inputs for real effect.
- Not DRM that fully blocks dumps by already-authorized users on their own devices.

#### 3.5.1 Capability Chain — prerequisite tokens (`requires.prev`)

Force submission of valid tokens from other features before issuing a specific one. Use to block step skipping like "payment → image generation".

```js
security: {
  capabilities: {
    enabled: true,
    features: {
      'auth.verified':  { public: true,  ttlMs: 60000 },
      'image.generate': {
        roles: ['premium','admin'],
        ttlMs: 10000,
        requires: { prev: ['auth.verified'] },
      },
    },
  },
}
```

Client sends prerequisite tokens together:

```ts
const a = await dokkebi.capability.unlock('auth.verified');
const b = await dokkebi.capability.unlock('image.generate', {
  prev: [{ feature: 'auth.verified', token: a.capability.token }],
});
```

Worker verifies HMAC signature, expiry, `sid` match, and feature match for each prerequisite token. Any break returns `CAPABILITY_PREV_MISSING` / `CAPABILITY_PREV_INVALID`.

### 3.6 Bundle Attestation — random chunk hash verification (opt-in)

**Purpose**: Each session, the server randomly challenges the client to prove encrypted bundle bytes in memory match the build output. Patched/forged bundles fail the challenge.

```js
// dokkebi.config.js
security: {
  attestation: {
    enabled: true,
    sampleSize: 4,         // chunks per challenge (1–16, default 4)
    ttlMs: 5 * 60_000,     // validity after pass (30s – 30min, default 5 min)
  },
  capabilities: {
    enabled: true,
    features: {
      'image.generate': {
        roles: ['premium','admin'],
        requires: { attest: true },   // issue only after attest passes
      },
    },
  },
}
```

Flow:

1. `dok build` splits encrypted bundle bytes into 16KB chunks and generates SHA-256 manifest (`backend-bundle.chunks.json`). Manifest is embedded in Worker code, not exposed to client.
2. When client requests capability with `requires.attest`, Worker returns `CAPABILITY_ATTEST_REQUIRED`.
3. Client automatically receives `_attest` challenge (`{ nonce, indices }`).
4. Client slices in-memory encrypted bundle bytes and responds with SHA-256 hash per index.
5. Worker compares to manifest; on match marks session attest-passed (`_attestPassMap`) and client auto-retries capability issuance.

Logs (`_dokkebi_security`):

| event | Meaning |
|---|---|
| `attest_passed` | Challenge response matches manifest |
| `attest_failed` | nonce expired / length mismatch / hash mismatch |
| `capability_denied: CAPABILITY_ATTEST_REQUIRED` | `requires.attest=true` but session has not passed attest |

Limitations:

- Client legitimately holds bundle bytes, so attestation strongly guarantees "tampered bundles cannot pass" but does not block "legitimate user modifying behavior afterward." Use with Capability/Authorization Policy.
- Chunk manifest is in build output. `dist/`/`worker/` are not externally exposed in normal deploy flow; do not publish manifest files to separate public static hosting.

### 3.7 Replay defense — ON by default, values tunable only (v5.4+)

All `/api/_dokkebi/db` requests are **automatically** protected by Nonce (one-time) + Timestamp skew window. Cannot be disabled via config; only parameters are adjustable.

```js
// dokkebi.config.js
export default {
  security: {
    replay: {
      timestampWindowMs: 5000,   // default 5s. For mobile/satellite with large skew, 8–15s recommended.
      nonceTtlMs: 35000,         // default 35s. Must be >= window + 5s.
    },
  },
};
```

- **Allowed range**: `timestampWindowMs ∈ [1s, 30s]`, `nonceTtlMs ∈ [window+5s, 5min]`
- **Out-of-range values** are clamped to safe range at `dok build` with warning.
- **Client clock auto-correction**: When server returns `TIMESTAMP_SKEW` with `server_ts`, client learns offset and retries once. All responses' `Date` header also observed for EWMA gradual correction. → **Features work even when device clock is wrong.**

**`code`** field added to error responses for clearer debugging:

| code | Meaning | Client auto-recovery |
|---|---|---|
| `TIMESTAMP_SKEW` | Client clock differs from server by more than `timestampWindowMs` | ✅ offset correction + 1 retry |
| `REPLAY_DETECTED` | Same nonce already seen | ✅ new nonce + 1 retry |
| `SIGNATURE_INVALID` | HMAC mismatch (session key mismatch / tampering) | ✅ re-handshake |
| `SESSION_INVALID` | Session expired or missing | ✅ re-handshake |
| `REQUEST_MALFORMED` | Required field missing | ❌ code bug |

---

## 4. Remaining concerns

### 4.1 🟡 Tenant Policy only, no Authorization — role-based permissions undefended

Tenant Policy handles "isolation within the same tenant" only. **Role-based permissions** like "only admins can delete" are not handled. The two layers are **complementary**; enabling both is recommended.

### 4.2 🟡 Query Registry `auto` mode defense limits

In default `auto` mode, unregistered queryIds still execute via `_debugSql` fallback → SQL shape protection is effectively off.

For full protection:
```js
queryRegistry: { strict: true }
```
Safe only after sufficient learning in dev or collection via static scanner.

### 4.3 🔴 XSS cascade damage

On XSS, attacker can:
- Send **arbitrary queries within allowlist/registry** via WASM to proxy
- Reproduce OPFS env secrets in same origin → OPFS encryption does not defend against XSS
- Steal Authorization JWT from localStorage etc. and call proxy

Mitigation: solve **outside dokkebi** — CSP, Trusted Types, sink removal.

### 4.4 🔴 Distributed DDoS

Application layer provides IP-based rate limits only. **Cloudflare WAF / Bot Management at the edge is required**.

### 4.5 🟡 Initial trust of ECDH server public key

Server public key on first handshake rides on TLS — no verification outside TLS. If TLS is broken, MITM is possible (common assumption for all web apps).

### 4.6 🟡 WASM bundle reverse engineering

Shipping backend business logic to the browser is **by design**. Minify only, no obfuscation. Not suitable for dokkebi if commercial IP protection is required.

### 4.7 🟡 Default CORS settings

Default template starts with `Access-Control-Allow-Origin: *` — restrict to actual frontend origin before deploy (especially when mixed with cookie-based other services).

### 4.8 🟡 Observability

`_dokkebi_security` table logs events but no alerting/SIEM integration. Operators must wire dashboard/alerting separately.

### 4.9 🟡 HS256 only (Authorization)

No asymmetric signatures (RS256/ES256) — for external IdP (Auth0, Cognito, etc.), re-wrap JWT as self-issued in Pages Function.

---

## 5. `plugin-ai` — risks of browser-direct API calls

`plugin-ai` was **removed** from CLI built-in in v5.3.

### Why it was removed

Calling Anthropic API directly from the browser means:
1. `x-api-key` header is **visible in plaintext in Network tab** (by design)
2. Key theft possible on XSS
3. Effectively public key when used on public SaaS

### Remaining file

Moved to `examples/plugins/plugin-ai.js`. Usable only via one of:

**Method 1 — recommended: server proxy**

```
Browser (dokkebi WASM)
    │
    ▼
Pages Function /api/ai/complete   ← ANTHROPIC_API_KEY only here
    │   (auth / billing / prompt policy)
    ▼
Anthropic API
```

**Method 2 — personal/internal only: copy to project**

```bash
cp examples/plugins/plugin-ai.js <my-project>/plugins/plugin-ai.js
```

Explicit in `dokkebi.config.js` + `acknowledgeKeyExposure: true` required for production deploy:

```js
plugins: {
  ai: {
    enabled: true,
    acknowledgeKeyExposure: true,  // explicit acknowledgment of key exposure risk
  },
},
```

`NODE_ENV=production` without flag → **build fails**.

---

## 6. Authorization boundary

### 6.1 Problem

```js
// Inside browser WASM:
if (user.role === 'admin') {
  await db.delete(users, { id: targetId });
}
```

Attacker can modify WASM bundle to remove `role === 'admin'` check. **Authorization decisions made in the browser are not trustworthy.** Proxy verifies "is this SQL in allowlist" but not "is this user really admin".

### 6.2 Solution — v5.3 Authorization Policy

Authorization Policy in §3.2 directly solves this:

- Proxy verifies JWT signature + role match
- Even with WASM tampering, operations requiring roles cannot run without valid JWT with role
- JWT is **server**-issued at user login (from actual role in DB)

Thus:
- **Without Authorization**: §6.1 problem remains — "anyone can be admin"
- **With Authorization**: security of JWT issuance server becomes the foundation

### 6.3 Tenant Policy + Authorization combination patterns

| Requirement | Tenant Policy | Authorization |
|---|---|---|
| Edit own posts only | ✅ inject `UPDATE posts WHERE user_id = ?` | `UPDATE:posts` → `{ auth: true }` |
| Admin deletes anyone | (admin bypass) | `DELETE:posts` → `{ roles: ['admin'] }` |
| Public feed read | (off) | `SELECT:posts` → `{ public: true }` |
| Signup (no auth) | (off — cannot create user_id) | `INSERT:users` → `{ public: true }` + separate rate limit |

**Recommended**: enable both layers for multi-user apps.

### 6.4 Alternatives when not using Authorization

| Option | Description |
|---|---|
| **DB-level RLS** (Supabase/Postgres) | Passthrough Supabase JWT via proxy. DB enforces `auth.uid()` limits |
| **Separate authorization edge function** | `/api/authorized-query` verifies JWT + business permissions then relays to dok proxy |
| **Read-only deploy** | Exclude write operations from Allowlist entirely |

---

## 6.5 Zero-downtime deploy

Each `dok build` rotates:

- `__DOKKEBI_BC_KEY__` — AES-256-GCM key for encrypted bundle (`backend.bundle.enc`)
- `bundleHash` — SHA-256 hash embedded in `index.html` (16-byte trim)

Because this rotation is asynchronous with static asset deploy (edge cache) ↔ Worker Secret registration (all-edge propagation), handshake failures can occur in two scenarios:

1. **Scenario A** — User refreshes with old HTML while static assets updated to new bundle, Worker Secret still propagating. → tries decrypt new bundle with old key → `OperationError`.
2. **Scenario B** — User got new HTML but some edges still serve old bundle. → tries decrypt old bundle with new key → same failure.

Dokkebi removes this race with triple defense (all automatic, no user config):

### ① Hash-pinned immutable bundle filename
- Outputs `backend.bundle.<hash12>.enc` alongside `backend.bundle.enc`.
- HTML bootstrap fetches hash-pinned filename first (falls back to non-hashed name).
- Cloudflare `_headers` applies `/dokkebi/backend.bundle.*.enc → public, immutable, max-age=1y`.
- **Effect**: old HTML always gets old bundle, new HTML gets new bundle permanently. Blocks Scenario B.

### ② `__DOKKEBI_BC_KEY_MAP__` (keep last N build keys)
- Build time accumulates `__DOKKEBI_BC_KEY_MAP__: { "<hash12>": "<keyHex>", ... }` JSON in `.dokkebi/env-secrets.json`.
- Keeps latest 5 builds only (FIFO GC).
- `dok deploy` registers this JSON as single Worker Secret.
- Handshake client includes `bh: <bundleHash 12 chars>` in POST body.
- Handshake worker responds with matching key via `pickClientHandshakeSecrets(env, requestedBh)`.
- **Effect**: old HTML users get old key, new HTML users get new key. Blocks Scenario A.

### ③ Deploy order + propagation sleep
- `dok deploy` order: Worker Secret register → `DOKKEBI_SECRET_PROPAGATION_MS` (default 15000ms) sleep → static asset push.
- Tune sleep via `DOKKEBI_SECRET_PROPAGATION_MS` (e.g. `DOKKEBI_SECRET_PROPAGATION_MS=30000 dok deploy`).
- **Effect**: when static assets appear on edge, Worker already has new key. Default 15s is conservative (CF Pages secret propagation measured 4–30s).

### ④ prop_pending — silent propagation wait response
- Handshake worker first checks if client `bh` maps in `__DOKKEBI_BC_KEY_MAP__`, then whether direct key is for current bundle via `__DOKKEBI_BC_HASH__`.
- If direct key is also not for current bundle, **does not fall back to wrong key** — returns `200 + { pending: true, code: "prop_pending", retryAfterMs: 5000 }`. No HTTP 503, so no red network errors in browser console.
- Client handles internally with backoff retry up to ~5 minutes. Users see loading only; execution resumes automatically when update propagates.
- **Effect**: blocks wrong key at handshake while absorbing delay without looking like outage.

### Security impact
- All four mechanisms **do not affect cryptographic security** — bundle still AES-256-GCM encrypted, keys only delivered via ECDH channel.
- Old bundles decodable until old keys GC'd; if old bundle has unpatched code, **expires automatically after N+1 deploys** (one more deploy for urgent patches).
- Exposed info: first 12 chars of `bundleHash` (already public via `?v=` query/attestation manifest).

### Operations notes
- Zero-downtime deploy requires **dokkebi-cli itself** v6.x+ and at least one `dok deploy` registering `__DOKKEBI_BC_KEY_MAP__`.
- Right after first deploy, map has only one key—old HTML cache may need one reload (subsequent deploys are zero-downtime).
- Client reload guard is 60s expiry; if propagation delay exceeds 60s continuously, auto refresh retries once more.

---

## 7. Production deployment checklist

**🔴 Required**
- [ ] HTTPS enforced (Cloudflare Pages automatic)
- [ ] **At least one authorization layer** — Authorization Policy or DB RLS or separate edge function
- [ ] XSS defense layer (CSP, Trusted Types)
- [ ] Restrict CORS `Access-Control-Allow-Origin` to actual frontend origin
- [ ] Cloudflare WAF / Bot Management at edge
- [ ] Register `DOKKEBI_SERVER_JWK`, `DOKKEBI_SESSION_SECRET` as Pages secrets
- [ ] If Authorization enabled, register `DOKKEBI_JWT_SECRET` (32+ bytes random)

**🟡 Strongly recommended**
- [ ] `queryRegistry.strict: true` (after learning complete)
- [ ] Multi-user apps: `policy.mode: 'inject'` + `ctx.setSessionTenant()`
- [ ] Replace `plugin-ai` with server proxy (do not use direct)
- [ ] Confirm `.dokkebi-secrets.json`, `.dev.vars`, `.dokkebi/env-secrets.json` in gitignore
- [ ] Admin PW 20+ chars high entropy
- [ ] Forward `_dokkebi_security` events to external monitoring (Logpush, Datadog, etc.)

**🟢 Reference**
- [ ] Confirm `sql-allowlist.json` included in `dist/dokkebi/`
- [ ] Query Registry non-empty (check build log)
- [ ] If Tenant Policy enabled, `_dokkebi_sessions.tenant_json` column migration complete

---

## 8. One-line summary

**"Excellent as an SQL attack blocking framework, but authorization must be solved separately via Authorization Policy or external layers (RLS/JWT)."**

---

## 8.5 Security options integration verification table (post build + deploy)

> **Scope**: Excludes `dok dev`. Based on **deployed worker** (Cloudflare Pages Function, `worker/api/_dokkebi/*.ts`).
> **Method**: Static analysis of **actual runtime code** embedded at build time from `src/core/projectGenerator.js` `workerHandshake()`, `workerDb()`, `workerRootMiddleware()`, `workerAdmin()`, `workerAdminApi()`.
> Opt-in items verified assuming user enabled option and filled secrets/config.

### At a glance

- ✅ **27 working normally** (always ON 17 + opt-in 7 + deploy helpers 3)
- ⚠️ **1 partial / not implemented**: WebAuthn server verification (as stated in §3.3)
- `prop_pending` response works normally in v6.x runtime (matches §6.5 ④ in this document)

### Analysis table

| # | Name | Layer | Role | Behavior (deployed worker) | Blocks (attack) | Status |
|---|------|-------|------|---------------------------|-----------------|--------|
| 1 | **ECDH(P-256) + HKDF-SHA256 → AES-256-GCM** | Network/transport | Bidirectional E2E encrypted channel | Handshake: `crypto.subtle.generateKey({ECDH, P-256})` ephemeral keypair → `deriveBits` → HKDF splits `dokkebi-enc`/`dokkebi-sig` → AES-256-GCM encrypts all requests/responses | Eavesdropping, MITM plaintext, DevTools plaintext observation | ✅ OK |
| 2 | **HMAC-SHA256 request signing** | Network/transport | Tamper prevention | All `/api/_dokkebi/db` requests verified with sigKey HMAC before processing. `SIGNATURE_INVALID` defined | Request tampering, message integrity threats | ✅ OK |
| 3 | **Replay defense (Nonce + ±5s TS)** | Network/transport | Replay blocking | `workerDb` nonce/timestamp → in-memory + `_dokkebi_nonces` D1 cross-isolate duplicate check. `REPLAY_DETECTED` / `TIMESTAMP_SKEW`. Tunable `replay.timestampWindowMs` (1-30s clamp), `nonceTtlMs` (window+5s ~ 5min clamp) | Captured request replay, rapid burst | ✅ OK |
| 4 | **Forward Secrecy (Ephemeral ECDH)** | Network/transport | Past traffic protected if session key leaks | New keypair per handshake, `_dokkebi_ephemeral_keys` deleted after 60s TTL | Long-term session key theft → decrypt past traffic | ✅ OK |
| 5 | **Session management (FIFO + token bucket)** | Network/session | DoS defense | `_dokkebi_sessions` D1 + per-session `bucketTokens`/`bucketRefillAt`. Session bomb/request burst defense | Session bomb, single-session burst | ✅ OK |
| 6 | **Envelope body size limit (512KB)** | Network/DoS | Body DoS defense | `MAX_ENVELOPE_BYTES = 512*1024` + `Content-Length` pre-check → 413 | Huge payload DoS, memory exhaustion | ✅ OK |
| 7 | **SQL Allowlist (table×op)** | Backend/DB | 4-layer stage 1 — allowed table·op only | `dist/dokkebi/sql-allowlist.json` extracted at build → inlined in `workerDb`. SELECT/INSERT/UPDATE/DELETE + `CREATE TABLE _dokkebi_*` only | Arbitrary table SELECT/UPDATE/DELETE, system table tampering | ✅ OK |
| 8 | **Query Registry (SQL shape)** | Backend/DB | 4-layer stage 2 — SQL structure tampering blocked | Shape register/match. Blocks `OR 1=1`, missing WHERE, column changes. **Default `auto`** (_debugSql fallback = effectively off), `queryRegistry.strict: true` blocks unregistered | SQL structure tampering, `OR 1=1`, WHERE removal | ✅ OK (weak in auto — §4.2) |
| 9 | **Common SQL defense** | Backend/DB | 4-layer stage 0 | `hasMultipleStatements` (`;`), `stripStringsAndComments` (`--`/`/* */`), dangerous tokens (`ATTACH`, `DETACH`, `PRAGMA`, `LOAD_EXTENSION`, `INTO OUTFILE`, `INTO DUMPFILE`, `INFORMATION_SCHEMA`, `PG_SLEEP`, `SLEEP(`, `BENCHMARK(`, `WAITFOR`, `XP_`, `SP_EXECUTESQL`) | SQL injection (stacked queries, comment bypass), DB privilege escalation, time-based blind injection | ✅ OK |
| 10 | **MTD — Payload Field Rotation** | Network/MTD | Rotate envelope key names per build (static signature defense) | `dok build` SHA-256 maps 8 keys to `_f<hash20>` from `buildId`. `wire-runtime.json` + `_payloadWire.ts` embedded worker+client. `denormalizePayload()` recognizes active+previous mappings → **zero-downtime compatible**. `DOKKEBI_HARDENING_ROTATE=off` disables (default ON) | Static key signature bots (`queryId=`/`_debugSql=`), capture-replay bots, static payload scanners, cross-build payload diff analysis | ✅ OK |
| 11 | **PoW — lightweight Proof of Work (14-bit SHA-256)** | Network/bot cost | Raise automation cost + protect capability·attest challenges | Required only for `_capabilityUnlock` or `_attest.request === true` (`powPayloadRequired`). Client mines SHA-256 leading zero ≥14bit on `<sid>:<minuteSlot>:<counter>` → worker `verifyAndStripPowDb()`, `±1 minuteSlot` window, counter ≤ 20M. `DOKKEBI_HARDENING_POW=off` disables (default ON) | Capability brute issue, free attestation challenge flood, zero-cost token issue, bots without extra cost on base channel | ✅ OK |
| 12 | **Tenant Policy (Row-level)** | Backend/DB | 4-layer stage 3 (opt-in) — multi-tenant isolation | `_pe_inject` / `verifyTenant` / `_pe_hasTopLevelOr` embedded. `mode: 'verify'` reject only, `'inject'` auto-inject. `tenant_json` column stores session tenant. top-level `OR`, aliased col validation | A→B data SELECT/UPDATE/DELETE, missing WHERE, OR 1=1 bypass | ✅ OK |
| 13 | **Authorization Policy (JWT/role)** | Backend/auth | 4-layer stage 4 (opt-in) — op-level permissions | HS256 JWT sign·exp verify, `(op, table)` → `roles.some(r => userRoles.includes(r))`, wildcard `'*'`, `mode: 'warn'`/`'strict'` | Regular user calling admin ops (`UPDATE users`, `DELETE *`), forged/expired JWT reuse | ✅ OK (HS256 only — §4.9) |
| 14 | **Capabilities (Signed Unlock Token)** | Backend/auth | (opt-in) permission branch bypass / cost route protection | `_cap_sign`/`_cap_verify` HMAC, `DOKKEBI_CAPABILITY_SECRET`, auto router guard from `routes`/`@dokkebi-capability` JSDoc at build | WASM patch bypass, direct costly routes (OpenAI etc.), stolen token other session (sid verify) | ✅ OK |
| 15 | **Capability Chain (`requires.prev`)** | Backend/auth | (opt-in) business step bypass blocked | `prevTokens` HMAC·exp·sid·feature verify. `CAPABILITY_PREV_MISSING`/`CAPABILITY_PREV_INVALID` | Skip auth→payment→step3, step tampering | ✅ OK |
| 16 | **Bundle Attestation (chunk SHA-256)** | Backend/bundle integrity | (opt-in, auto with capabilities) tampered bundle blocked | `dok build` `backend-bundle.chunks.json` (16KB chunk SHA-256) → worker embedded (not client). `_attest` challenge → client slices in-memory bundle. Fail: `attest_failed` / `CAPABILITY_ATTEST_REQUIRED`. `requires: { attest: true }` gates capability | Client bundle patch (permission bypass·free capability) | ✅ OK |
| 17 | **Active Defense Layer (ADL)** | Backend/bot·automation | (opt-in) risk-score blocking | `_adlRisk` calc (`ADL_RISK_BLOCK` threshold). `mode: 'monitor'` log only / `'enforce'` block. `sampleRate`, `riskBlockThreshold`, `trigger: 'lazy'/'cron'`, Workers AI options | Automation scraping, 403/auth failure bursts, price fuzzing | ✅ OK |
| 18 | **Panel IP Guard (CIDR)** | Network/ops | (opt-in) block external IPs from ops panel | `workerAdmin`/`workerAdminApi` `panelIpAllowed` + CIDR. `CF-Connecting-IP` first → `X-Forwarded-For` fallback. 403 + `panel_ip_block` (`_dokkebi_security`) | Panel PW brute force, external IP ops API, unauthorized log/event access·delete | ✅ OK |
| 19 | **Admin panel security (PW + lock + token)** | Backend/ops | always ON | `timingSafeEqual` constant-time PW, 5 failures → 5 min lock, HMAC token + expiry, 2KB body cap, 600/min log limit | Panel PW brute force, timing attack, token forgery, ops DoS | ✅ OK |
| 20 | **Strict CSP (hash-pinned)** | Network/XSS deep defense | (opt-in) | `deploy.js _writeSecurityHeaders` → `dist/_headers`. Inline `<script>/<style>` SHA-256 hashed into `script-src 'self' 'sha256-…'`, removes `unsafe-inline`. Full CSP directives | XSS follow-up external script injection, eval, data exfil (assets/keys) | ✅ OK |
| 21 | **OPFS env secrets (Opaque Handle)** | Backend/secrets | always ON | Build-time AES-GCM wrap → OPFS. Decrypt only in host closure. `.dokkebi/env-secrets.json` static serve blocked | DevTools env var exposure, client code dump | ✅ OK (XSS same-origin replay possible — §4.3) |
| 22 | **Bundle integrity SHA-256** | Build/bundle | always ON | `dok build` SHA-256 → `backend.bundle.<hash12>.enc` immutable filename + runtime `crypto.subtle.digest` verify | Bundle swap/tamper, MITM bundle swap | ✅ OK |
| 23 | **Zero-downtime — BC_KEY_MAP** | Build/deploy | always ON (v6.x+) | `__DOKKEBI_BC_KEY_MAP__` (last 5 build keys FIFO) Worker Secret. Client sends `bh=<hash12>` → `pickClientHandshakeSecrets()` matching key | Cache·propagation race handshake failure (scenarios A·B) | ✅ OK |
| 24 | **Zero-downtime — `prop_pending` absorption** | Build/deploy | always ON | `_pickBcKeyForBundle()` no match + direct key not current → `status: 'pending'`. Handshake: no wrong-key fallback, `200 + { pending: true, code: 'prop_pending', retryAfterMs: 5000 }` → client SDK backoff | Red console errors during Worker Secret propagation after deploy, wrong-key decrypt infinite retry | ✅ OK |
| 25 | **Zero-downtime — propagation sleep** | Build/deploy | always ON | `dok deploy`: Secret register → `DOKKEBI_SECRET_PROPAGATION_MS` (default 15s) sleep → static push | New static ↔ old Worker Secret race | ✅ OK |
| 26 | **CORS policy validation** | Network | always ON (preflight warning) | `dok deploy` preflight warns if `security.cors.allowedOrigins` unset or includes `*`. Operator must narrow to real frontend origin (§4.7) | (If not narrowed, other origins can call) | ✅ Works (warning + operator action) |
| 27 | **plugin-fetch domain whitelist** | Backend/external | always ON | http/https enforced, standalone TLD rejected, per-project whitelist | SSRF, arbitrary external fetch | ✅ OK |
| 28 | **plugin-ai build block** | Build | always ON | `NODE_ENV=production` without `acknowledgeKeyExposure` → build fails (`pluginLoader.js`) | API key browser exposure (structural risk) | ✅ OK |
| 29 | **Build-time Advisor** | Build/human error | (opt-out) | Scans OpenAI/Stripe/LemonSqueezy URLs, `points.deduct(`, `wallet.charge(`, secret env direct use routes → warns if capability undeclared | Missing capability declaration (indirect defense) | ✅ OK |
| 30 | **Bytecode Mode (QuickJS)** | Backend/IP protection | (opt-in) | `dok build --bytecode` precompiles backend to QuickJS bytecode — client memory has bytecode not JS source (`_bcMode`). `bytecodeEncrypted: true` adds AES-GCM wrap | WASM memory dump JS source reversing, business logic extraction (partial §4.6 mitigation — not full DRM) | ✅ OK |
| 31 | **Encrypted Text Mode** | Backend/IP protection | (opt-in) | `encryptedTextMode: true` (`_etMode`) — additional AES-GCM on bundle text. `_cacheFile = 'backend.bundle.enc'` keeps OPFS cache encrypted | Disk/cache dump plaintext bundle | ✅ OK |
| 32 | **Pre-gate (per-session token bucket)** | Network/DoS | always ON | `workerDb` rate limit via `bucketTokens`/`bucketRefillAt` **before** envelope verify·decrypt. Blocks before costly AES-GCM/ECDH | Single session exhausting worker via ECDH/AES-GCM cost, well-formed burst (Phase 2-⑤) | ✅ OK |
| 33 | **Monotonic Request Counter** | Network/session | always ON | Per-session request seq verify (Phase 1-①). Reject if client seq not monotonic. Counter issued from `opaqueHandle` | Captured request replay / order tampering / nonce reuse with reversed order | ✅ OK |
| 34 | **Bundle Boot KEK (HKDF + AES-GCM wrap)** | Build/bundle boot | always ON | `bundleBoot.js` — `DOKKEBI_BUNDLE_BOOT_SECRET` nonce HMAC → HKDF-SHA256(salt=nonce, info=`dokkebi-bc-wrap-v1\|<h12>`) → AES-256 KEK → wrap BC_KEY 32 bytes AES-GCM inline in HTML `__DOKKEBI_BOOT__`. Worker middleware reproduces same via Web Crypto | BC_KEY plaintext in captured HTML static, h12 binding blocks reuse of other build boot payload | ✅ OK |
| 35 | **Console Call Stripping** | Build/info disclosure | always ON | `replaceConsoleCallsWithVoid()` — production bundle replaces specified `console.METHOD(...)` with `void 0`. Ignores parens inside strings/comments/regex. `buildWasm.js` auto-applies | Debug info·internal state·SQL/secrets leaking to production console | ✅ OK |
| 36 | **Build Artifact Purge** | Build/info disclosure | always ON | `purgeBuildArtifactsFromDist()` — overwrites 8 sensitive JSON in `dist/dokkebi/` with `{}` (`env-secrets.json`, `secrets.json`, `query-registry.json`, `sql-allowlist.json`, `wire-runtime.json`, `backend-bundle.chunks.json`, `backend-bundle.sha256`, legacy `env-secrets.js`). All meta inlined in worker—client does not fetch. CF Pages `_redirects` force(`!`) no 404 support → emptying is only trusted method | Static fallback exposing SQL allowlist·query shape·attestation manifest·env secret — recon of allowed tables·columns·bundle structure | ✅ OK |
| 37 | **JWT extra validation (alg whitelist + iss/aud/nbf + clockSkew)** | Backend/auth | always ON (when Authorization enabled) | `authorizationPolicy.js` — `header.typ === 'JWT' && header.alg === 'HS256'` whitelist, `exp` + 30s clockSkew, `nbf`, optional `iss`/`aud`. Blocks None alg / alg confusion | JWT alg=`none` bypass, RS256→HS256 key confusion, expired/early token, wrong issuer reuse | ✅ OK |
| 38 | **Plaintext Zeroize (best-effort)** | Backend/memory | always ON | `opaqueHandle` `_secPlain.fill(0)`, `_bcKeyBytes.fill(0)`, `_bytecodeData.fill(0)`, `sharedBits.fill(0)` etc. immediately after decrypt·sign·KEK use | Memory dump / heap snapshot retaining expired plaintext keys·bytecode·session secrets | ✅ OK (best-effort — JS GC may clone copies) |
| 39 | **Additional security headers** (`_headers`) | Network/browser policy | always ON (on deploy) | `dist/_headers`: `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera/microphone/display-capture=(self), geolocation/payment=()`, `index.html/sw.js: no-cache,no-store`, `/dokkebi/*.json: X-Robots-Tag: noindex` | MIME sniffing, legacy reflected XSS, clickjacking, referrer leak, unauthorized permission requests, stale SW cache, search engine indexing sensitive JSON | ✅ OK |
| 40 | **WebAuthn (Passkey) request signing** | Network/sensitive-action auth | (opt-in) — **runtime not implemented** | Config (`security.webauthn`) and client SDK exist but **worker assertion verify / `requireForOps` gate not implemented** (`docs/design/WEBAUTHN.md`: "runtime SDK is follow-up PR"). `enabled: true` has no server enforcement | (When implemented) password/session theft → payment·admin export. **Use Authorization Policy + Capabilities instead for now** | ⚠️ Not implemented (§3.3) |

### Zero-downtime scenario ④ implementation note (v6.x verified)

`worker/api/_dokkebi/handshake.ts` `_pickBcKeyForBundle()` returns four branches:

| status | Condition | Handler behavior |
|---|---|---|
| `matched` (with key) | `bh` matches `__DOKKEBI_BC_KEY_MAP__` or direct key hash | Normal handshake + BC key response |
| `fallback` (with key) | `bh` not sent (legacy client) + direct key exists | Respond with direct key |
| `pending` (no key) | `bh` no match + direct key not for current bundle / key unregistered | **`200 + { pending: true, code: 'prop_pending', retryAfterMs: 5000 }`** — no wrong-key fallback. Client SDK backoff retry. |

This matches §6.5 ④ behavior—absorbs Worker Secret propagation delay after new deploy without red console errors.

---

## 9. Reporting

Report security issues via private channel (contact in README), not public GitHub issues.

---

## Related documents

- [docs/design/TENANT_POLICY.md](docs/design/TENANT_POLICY.md) — Row-level isolation
- [docs/design/AUTHORIZATION.md](docs/design/AUTHORIZATION.md) — Operation-level authorization
- [docs/design/QUERY_REGISTRY.md](docs/design/QUERY_REGISTRY.md) — SQL shape control
