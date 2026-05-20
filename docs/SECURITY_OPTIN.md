# Dokkebi Security Options — Opt-in Quick Reference

Short summary of options users toggle in `dokkebi.config.js`. For behavior and limits, see `docs/SECURITY_OPTIONS.md` and `SECURITY.md`.

**Quick check**: At project root, run `dok security` (TTY) to view per-item threats and required settings, toggle ON/OFF, and save. `dok security --status` prints once only.

> **Always ON (no user config)**: ECDH handshake, AES-256-GCM, HMAC, replay defense (nonce + timestamp), bundle integrity SHA-256, SQL Allowlist, Query Registry, build meta traceability.

---

## At a glance

| Option | Attack blocked when enabled | Default |
|---|---|---|
| `capabilities` | Permission branch bypass, direct costly route calls | off |
| `capabilities.features[*].requires.prev` | Business step bypass | (when declared) |
| `attestation` | Tampered bundle bypass | auto ON when capabilities ON |
| `panelIpGuard` | Ops panel brute force / external exposure | off |
| `replay` (tuning only) | Captured request replay | always ON, values tunable |
| `activeDefense` | Automated scraping / burst attacks | off |
| `advisor` | Missing capability declaration (human error) | on |
| `policy` (Tenant) | Other tenant data exposure | off (`tenantPolicy` is alias for `policy`) |
| `authorization` | SQL ignoring role, JWT forgery | off |
| `webauthn` | Sensitive actions after session theft | off |
| `strictCsp` | Post-XSS follow-up attacks | off |

---

## 1. `capabilities` — Signed Unlock Token

**Blocks**: Backend permission branch bypass like `if (user.role === 'admin')` / direct calls to costly routes (OpenAI, payment).

```js
security: {
  capabilities: {
    enabled: true,
    secretEnv: 'DOKKEBI_CAPABILITY_SECRET',
    features: {
      'image.generate': { roles: ['premium','admin'], routes: ['POST /api/ai/image'] },
      'admin.export':   { roles: ['admin'],           routes: ['POST /api/admin/export'] },
    },
  },
}
```
```env
DOKKEBI_CAPABILITY_SECRET=<32+ char random>
```

> Declaring `routes` or `@dokkebi-capability` JSDoc auto-inserts router guard at build.

---

## 2. `capabilities.features[*].requires.prev` — Capability Chain

**Blocks**: Skipping steps 1–2 and calling step 3 only in flows like "auth → payment → execute".

```js
features: {
  'auth.verified':   { public: true, ttlMs: 60_000 },
  'payment.charged': { roles: ['user'], requires: { prev: ['auth.verified'] } },
  'image.generate':  { roles: ['premium','admin'], requires: { prev: ['payment.charged'] } },
}
```

Call stays `await capability.unlock('image.generate')` — client auto-caches and attaches prev tokens.

---

## 3. `attestation` — Bundle Attestation

**Blocks**: Client bundle patch that bypasses all permission branches.

```js
security: {
  attestation: { enabled: true },   // auto ON when capabilities on; set false to disable
  capabilities: {
    enabled: true,
    features: {
      'image.generate': {
        roles: ['premium','admin'],
        requires: { attest: true },  // issue token only after attest passes
      },
    },
  },
}
```

> On first call, client auto-attests and retries. No user code change.

---

## 4. `panelIpGuard` — Operations admin IP restriction

**Blocks**: `/_dokkebi/_panel` password brute force / direct ops API from external IPs.

```js
security: { panelIpGuard: true }
```
```env
DOKKEBI_ADMIN_PASSWORD=<long password>
DOKKEBI_PANEL_ALLOWED_IPS=203.0.113.10,198.51.100.0/24
```

---

## 5. `replay` — Replay defense tuning

**Blocks**: Replaying captured valid requests / rapid burst fire.

> Always ON; cannot disable, only tune values.

```js
security: {
  replay: {
    timestampWindowMs: 5_000,   // 1s ~ 30s. Use 8–15s on mobile.
    nonceTtlMs: 35_000,         // window + 5s ~ 5min.
  },
}
```

---

## 6. `activeDefense` — ADL

**Blocks**: Automated scraping, burst 403/auth failures, price fuzzing.

```js
security: {
  activeDefense: {
    enabled: true,
    mode: 'monitor',            // start monitor → observe ~1 week → promote to enforce
    sampleRate: 0.01,
    riskBlockThreshold: 0.85,
  },
}
```

---

## 7. `advisor` — Build-time security advisor

**Blocks mistakes**: Forgetting capability on external-cost routes.

ON by default. `dok build` warns (does not auto-add) when external API / sensitive secret / `points.deduct(` routes lack capability.

To disable:
```js
security: { advisor: { disable: true } }
```

---

## 8. `policy` — Row-level isolation (Tenant Policy)

**Blocks**: User A SELECT/UPDATE/DELETE on User B's data via SQL bypass.

```js
policy: {
  enabled: true,
  mode: 'inject',              // 'verify' (validate only) | 'inject' (auto-inject)
  claim: 'sub',
  strict: true,
  tables: {
    animation_projects: { tenantColumn: 'user_id' },
    user_assets:        { tenantColumn: 'user_id' },
  },
}
```

> Top-level `tenantPolicy` merges same as `policy` (legacy compat). Prefer `policy` for new config.

> Almost required for multi-tenant SaaS. Use with `authorization`.

---

## 9. `authorization` — Operation-level authorization (JWT)

**Blocks**: Regular users calling admin ops (`UPDATE users`, `DELETE FROM …`) / JWT forgery.

```js
authorization: {
  enabled: true,
  mode: 'strict',              // 'warn' (log only) | 'strict' (reject)
  claim: 'role',
  rules: [
    { op: 'UPDATE', table: 'users', roles: ['admin'] },
    { op: 'DELETE', table: '*',     roles: ['admin'] },
    { op: '*',      table: '*',     roles: ['user','admin'] },
  ],
}
```
```env
DOKKEBI_JWT_SECRET=<32+ chars>
```

---

## 10. `webauthn` — Extra auth for sensitive actions

**Blocks**: Payment / admin export etc. without device passkey even after password/session theft.

```js
webauthn: {
  enabled: true,
  rpName: 'MyApp',
  rpId: 'myapp.com',
  userVerification: 'required',
  requireForOps: ['DELETE', 'UPDATE_users'],
}
```

> Requires passkey registration in user signup flow. Limit to truly sensitive ops.

---

## 11. `strictCsp` — Strict CSP

**Blocks**: Post-XSS external script injection / eval follow-up attacks.

```js
security: { strictCsp: true }
```

> Some third-party scripts (ad SDKs, etc.) may need extra domains.

---

## Recommended default (good starting point)

```js
// dokkebi.config.js
export default {
  security: {
    capabilities: {
      enabled: true,
      features: {
        // Declare only external-cost / admin routes
        'image.generate': { roles: ['premium','admin'], routes: ['POST /api/ai/image'] },
        'admin.export':   { roles: ['admin'],           routes: ['POST /api/admin/export'] },
      },
    },
    panelIpGuard: true,
  },

  // For multi-tenant SaaS also:
  // policy: { enabled: true, mode: 'inject', tables: { ... } },
  // authorization: { enabled: true, mode: 'strict', rules: [...] },
};
```
```env
DOKKEBI_CAPABILITY_SECRET=<32+ chars>
DOKKEBI_ADMIN_PASSWORD=<long password>
DOKKEBI_PANEL_ALLOWED_IPS=203.0.113.10,198.51.100.0/24
DOKKEBI_JWT_SECRET=<32+ chars>     # when using authorization
```

> More detail: `docs/SECURITY_OPTIONS.md` (full attack mapping table), `SECURITY.md` (architecture).
