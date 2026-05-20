# Authorization Policy (Stage 4)

> **Problem addressed**: `if (user.role === 'admin')` checks inside the browser (WASM) are not trustworthy.
> Attackers can patch the bundle or manipulate memory in a debugger to become "admin".
> The server (DB proxy) layer verifies **JWT signature + role claims** to block the "everyone is admin" problem.

## TL;DR

```js
// dokkebi.config.js
export default {
  authorization: {
    // mode:
    //   'warn'   (default) — only validates ops with defined rules; undefined ops pass + build log warning
    //   'strict'        — rejects all undefined ops (fail-closed)
    mode: 'warn',

    // Env var name. Set as Cloudflare Pages Secret
    //   wrangler pages secret put DOKKEBI_JWT_SECRET --project=xxx
    jwtSecretEnv: 'DOKKEBI_JWT_SECRET',

    // JWT payload field for role (default: 'role')
    claim: 'role',

    // Optional: issuer/audience validation
    issuer: 'my-app',
    audience: 'web',
    clockSkewSec: 30,

    // Rules: "OP:table" → spec
    rules: {
      'SELECT:posts':  { public: true },
      'INSERT:posts':  { auth: true },
      'UPDATE:posts':  { roles: ['admin', 'author'] },
      'DELETE:posts':  { roles: ['admin'] },
      'DELETE:users':  { deny: true },         // explicit deny
      '*':             { auth: true },          // default: login required
    },
  },
};
```

Production checklist:
- [ ] Set `DOKKEBI_JWT_SECRET` secret on Cloudflare Pages
- [ ] Define `'*'` default rule (or use `mode: 'strict'`)
- [ ] Implement JWT issuance endpoint yourself (`functions/api/auth/login.ts`)
- [ ] Client sends via `Authorization: Bearer <jwt>` header or `_jwt` payload field

---

## 1. Why it's needed

Dokkebi's existing security stack:

| Layer | Role | Coverage |
|---|---|---|
| Common SQL validation | Block stacked queries, dangerous tokens | Broad |
| SQL Allowlist (Stage 0) | Table × operation permit | Broad |
| Query Registry (Stage 3) | SQL shape permit | Broad |
| Tenant Policy (Stage 1/2) | **Row-level isolation** (user A cannot see user B's data) | opt-in |
| **Authorization (Stage 4)** ← new | **Operation-level permissions** ("only admin can DELETE") | opt-in |

Tenant Policy handles "isolation within the same tenant" but never addressed **"who within that tenant can DELETE"**. This addition covers that.

## 2. Architecture

```
Client (Browser WASM)
  │
  │  headers:
  │    Authorization: Bearer <jwt>   ← standard
  │    (or payload._jwt)           ← inside encrypted channel (JWT not visible in Network tab)
  ▼
POST /api/_dokkebi/db
  │
  ├─ Session/signature/decrypt                             (existing)
  ├─ SQL validation + Allowlist                         (existing)
  ├─ Query Registry                               (existing)
  ├─ Tenant Policy verify/inject                  (existing, opt-in)
  │     → inject user_id = ? into SQL
  ├─ [NEW] Authorization                          (new, opt-in)
  │     1. Extract (op, table) from final SQL
  │     2. Find matching rule in rules
  │     3. Extract Authorization header/payload._jwt if needed
  │     4. HS256 signature verify + exp/nbf/iss/aud check
  │     5. Match role claim
  │     6. Failure → 401/403
  └─ D1.prepare().bind()
```

Notes:
- **Authorization runs after Tenant Policy** → op/table judged on final SQL after Tenant Policy injection
- One request = one SQL statement; top-level op/table is sufficient (stacked queries blocked at step 1)
- JWT verification skipped only when no rule matches (cost savings)

## 3. Rule syntax

Key format:

```
"OP:table"     // most specific — e.g. "DELETE:posts"
"OP:*"         // op wildcard — e.g. "DELETE:*"  (DELETE on all tables)
"*:table"      // table wildcard — e.g. "*:users" (all ops on users)
"*"            // default — all unmatched requests
```

Valid OP: `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `*`

Priority:
1. Specific OP + specific table (highest)
2. Specific OP + table `*`, or OP `*` + specific table (same rank)
3. Default `*`

At same priority, config order does not matter (one match is chosen — avoid conflicting rules at same rank).

Value specs:

| Spec | Meaning |
|---|---|
| `{ public: true }` | No auth required. Allowed without JWT. |
| `{ auth: true }` | Valid JWT required. No role check. |
| `{ roles: ['a', 'b'] }` | Valid JWT + `payload.role` must be `a` or `b`. Implies `auth: true`. |
| `{ deny: true }` | Always deny. Blocked regardless of role. |

## 4. JWT requirements

- **Algorithm**: HS256 only
- **Required claims**: `exp` (recommended). `role` (or field specified in `claim`)
- **Optional claims**: `nbf`, `iss`, `aud`
- **secret**: `DOKKEBI_JWT_SECRET` Pages env var (32+ random bytes recommended)

### Issuance example (you implement)

```ts
// functions/api/auth/login.ts
import type { PagesFunction } from '@cloudflare/workers-types';

interface Env { DOKKEBI_JWT_SECRET: string; DB: D1Database; }

export const onRequest: PagesFunction<Env> = async ({ request, env }) => {
  const { email, password } = await request.json();

  // 1. Lookup user in DB + verify password (bcrypt, etc.)
  const row = await env.DB.prepare(
    `SELECT id, role, password_hash FROM users WHERE email = ?`
  ).bind(email).first();
  if (!row || !(await verifyPassword(password, row.password_hash as string))) {
    return new Response('Invalid credentials', { status: 401 });
  }

  // 2. Issue JWT
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

### Client transmission methods

**Method 1 — standard Authorization header (recommended)**

```js
// In app fetch wrapper
fetch('/api/_dokkebi/db', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${jwt}`,  // ← dokkebi proxy auto-extracts
  },
  body: /* encrypted payload */,
});
```

**Method 2 — payload._jwt (hide JWT from Network tab)**

Include `_jwt` in encrypted payload so JWT is not visible in request headers in Network tab/DevTools. JWT rides inside Dokkebi's AES-GCM channel for extra depth.

```js
// Inside WASM (dokkebi-runtime)
db.query(sql, params, { jwt: getSessionJwt() });
// ↓ internally adds _jwt to payload → AES-GCM encrypt → send
```

> Tip: Adding `{ jwt }` option to dokkebi-runtime `db.query()` can auto-include in payload. Default template does not include it—implement via custom wrapper.

## 5. Response codes

| HTTP | code | Condition |
|---|---|---|
| 401 | `AUTH_REQUIRED` | Rule requires `auth` or `roles`, JWT missing or invalid |
| 403 | `ROLE_MISSING` | JWT valid but `claim` field missing from payload |
| 403 | `ROLE_FORBIDDEN` | Role present but not in allowed list |
| 403 | `RULE_DENY` | Matched `deny: true` rule |
| 403 | `NO_RULE` | No matching rule in strict mode |
| 403 | `SPEC_INVALID` | Invalid rule spec format (config error) |

Response body:

```json
{ "ok": false, "error": "Required role: [admin], current: user", "code": "ROLE_FORBIDDEN" }
```

All denials logged to `_dokkebi_security` as `type='authz_denied'`.

## 6. Relationship with Tenant Policy

The two policies are **complementary**:

| Example scenario | Tenant Policy role | Authorization role |
|---|---|---|
| User A must not see User B's posts | Inject `SELECT posts WHERE user_id = ?` | (not needed) |
| Non-admin must not delete posts | (not needed — unrelated to tenant) | `DELETE:posts` → `roles: ['admin']` |
| User deletes own posts only; admin deletes anyone | Inject `DELETE posts WHERE user_id = ?` | `DELETE:posts` → `{ auth: true }` (own data covered by tenant isolation) |

**Safe pattern**: enable both layers for "admin-only delete" + "non-admin only own tenant".

## 7. Implementation limits

- **HS256 only**: RS256/ES256 not supported. For external IdP (Auth0, etc.), re-wrap JWT as self-issued in Pages Function.
- **No row-level authorization**: rules like "edit own posts only" depend on SQL `user_id = ?` — Tenant Policy's job.
- **No field-level SELECT limits**: "only admin can read password_hash column" not supported. Use views or split queries.
- **Worker inline code size**: v8 template adds ~350 lines. Negligible within Cloudflare Workers 1MB script limit.

## 8. Migration guide

### New project

1. Create with `dok create` (v8 template included automatically)
2. Add `authorization` section to `dokkebi.config.js`
3. Set `DOKKEBI_JWT_SECRET` env
4. Implement login endpoint

### Existing project (v7 and below)

```bash
# 1. Update worker template
dok update

# 2. Confirm migration then Y
# 3. Add authorization section to config
# 4. dok build
# 5. dok deploy
```

Without `authorization` section, behavior is **off** → same as before. No impact until enabled.

## 9. Related documents

- [SECURITY.md](../../SECURITY.md) — Full security architecture
- [TENANT_POLICY.md](./TENANT_POLICY.md) — Row-level isolation
- [QUERY_REGISTRY.md](./QUERY_REGISTRY.md) — SQL shape control
