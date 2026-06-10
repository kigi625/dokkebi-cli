# Dokkebi Security Options Guide — "Which attack does each option block?"

This document covers **user-toggleable options** in the `security` section of `dokkebi.config.js`. For each option:

1. **Attack case blocked** — scenario possible *without* the option.
2. **What it does** — one-line behavior summary.
3. **How to apply** — `dokkebi.config.js` / `.env` examples.
4. **Operations notes** — tradeoffs, common mistakes, recommended defaults.

> Always-on baseline security (ECDH/AES-GCM/HMAC/session, replay defense, partial Active Defense Layer, bundle integrity verification) cannot be disabled by users and is omitted here. See `SECURITY.md` for architecture.

---

## Quick recommended default

For a new project, enabling the following blocks 80%+ of threats:

```js
// dokkebi.config.js
export default {
  security: {
    capabilities: {
      enabled: true,
      // Declare only external-cost / payment / admin routes
      features: {
        'image.generate': { roles: ['premium','admin'], routes: ['POST /api/ai/image'] },
        'admin.export':   { roles: ['admin'],           routes: ['POST /api/admin/export'] },
      },
    },
    // attestation auto ON when capabilities enabled (explicit false to disable)

    panelIpGuard: true, // recommended ON if exposing ops panel in production
  },

  // For multi-tenant SaaS also use:
  // policy: { enabled: true, mode: 'inject', tables: { ... } },
  // authorization: { enabled: true, mode: 'strict', rules: [...] },
};
```

`.env` (or Cloudflare Pages Secret):

```env
DOKKEBI_CAPABILITY_SECRET=<32+ char random string>
DOKKEBI_PANEL_ALLOWED_IPS=203.0.113.10,198.51.100.0/24
DOKKEBI_ADMIN_PASSWORD=<long password>
DOKKEBI_JWT_SECRET=<32+ chars>           # when using authorization
```

---

## 1. `security.capabilities` — Signed Unlock Token

### Attacks blocked
- **A1.** User **jumps permission branches** in their browser backend code like `if (user.role === 'admin')` to force paid/admin features.
- **A2.** Calls external costly routes (e.g. OpenAI image generation) **before** point deduction — free usage.
- **A3.** Steals another user's token and uses it in their own session.

### What it does
Declare protected actions as "features"; Worker issues **HMAC-signed short-lived tokens** per feature. Handlers should use the token as *material*, not simple branch flags.

### How to apply
```js
security: {
  capabilities: {
    enabled: true,
    secretEnv: 'DOKKEBI_CAPABILITY_SECRET',
    defaultTtlMs: 15_000,
    features: {
      'image.generate': {
        roles: ['premium', 'admin'],
        ttlMs: 10_000,
        routes: ['POST /api/ai/image'],
      },
      'admin.export': {
        roles: ['admin'],
        ttlMs: 5_000,
        routes: ['POST /api/admin/export'],
      },
    },
  },
}
```

Or controller JSDoc:
```ts
/**
 * @dokkebi-capability feature:image.generate route:"POST /api/ai/image" roles:['premium','admin'] ttl:10000
 */
router.post('/api/ai/image', async (ctx) => {
  // use ctx.capability.token / proof
});
```

### Operations notes
- With `routes` or `@dokkebi-capability`, **build auto-inserts router guard**. Users need not call `unlock()` in handlers.
- **`if (cap.ok) doExpensive()` as a simple flag weakens protection.** Bind `ctx.capability.token/proof` or `stateHash` into external call inputs/signing material.
- `DOKKEBI_CAPABILITY_SECRET`: 32+ random chars, **Worker-only** (never sent to browser).
- `dok build` warns if costly routes lack capability (see §7).

Details: `SECURITY.md` §3.5.

---

## 2. `security.capabilities.features[*].requires.prev` — Capability Chain

### Attacks blocked
- **A4.** Business flow is "step 1 auth → step 2 payment → step 3 execute" but caller skips 1–2 and hits 3 directly.
- **A5.** Sends only policy-legal SQL while **reordering steps** to bypass payment for free.

### What it does
Before issuing one capability, caller must submit **valid tokens from other capabilities** in the same session. Worker verifies HMAC signature/expiry/`sid`/feature match for each.

### How to apply
```js
features: {
  'auth.verified':  { public: true, ttlMs: 60_000 },
  'payment.charged':{ roles: ['user'], ttlMs: 30_000, requires: { prev: ['auth.verified'] } },
  'image.generate': {
    roles: ['premium','admin'],
    requires: { prev: ['auth.verified', 'payment.charged'] },
  },
}
```

Usage:
```ts
// Auto: Dokkebi fills prev tokens via cache/recursive unlock.
const r = await capability.unlock('image.generate');

// Manual (only when needed):
const a = await capability.unlock('auth.verified');
const r = await capability.unlock('image.generate', {
  prev: [{ feature: 'auth.verified', token: a.capability.token }],
});
```

### Operations notes
- **Automation**: Client caches prev tokens and auto-unlocks missing prev. No user code change.
- **No cycles**: `A → B → A` cycles ignored at build; worker returns PREV_MISSING.
- **State-bound calls not cached**: `unlock(feature, { state, ... })` gets fresh token each time (intended).

---

## 3. `security.attestation` — Bundle Attestation

### Attacks blocked
- **A6.** User **patches bundle** in browser (permission branches all pass) and sends only legal SQL.
- **A7.** Issues capability tokens with tampered bundle for external costly calls.

### What it does
At build, encrypted bundle split into 16KB chunks → SHA-256 manifest (`backend-bundle.chunks.json`). Each session Worker challenges random chunk indices; client responds from in-memory bundle bytes. Any mismatch → `attest_failed`.

### How to apply
```js
security: {
  attestation: {
    // When omitted, auto ON if capabilities.enabled === true
    enabled: true,
    sampleSize: 4,         // 1–16, default 4
    ttlMs: 5 * 60_000,     // 30s–30min, default 5 min
  },
  capabilities: {
    enabled: true,
    features: {
      'image.generate': {
        roles: ['premium','admin'],
        requires: { attest: true },   // issue token only after attest passes
      },
    },
  },
}
```

Explicit disable:
```js
security: { attestation: { enabled: false } }
```

### Operations notes
- **Auto ON**: enabling capabilities enables attestation unless `enabled: false`.
- Manifest is **always** generated each build (works without rebuild on enable).
- Auto retry: first call with `requires.attest: true` gets `CAPABILITY_ATTEST_REQUIRED` → client attests and retries once (no user code change).
- Manifest embedded in worker only — **not exposed to client**.

Details: `SECURITY.md` §3.6.

---

## 4. `security.panelIpGuard` + `DOKKEBI_PANEL_ALLOWED_IPS` — Ops admin IP restriction

### Attacks blocked
- **A8.** Brute-force ops panel (`/_dokkebi/_panel`) password or login from arbitrary IP with leaked password.
- **A9.** Direct ops API calls to read/delete logs, events, request history.

### What it does
Only IPs / IPv4 CIDR in `DOKKEBI_PANEL_ALLOWED_IPS` may access panel. Blocked attempts logged as `panel_ip_block`.

### How to apply
```js
security: { panelIpGuard: true }
```
```env
DOKKEBI_ADMIN_PASSWORD=<long password>
DOKKEBI_PANEL_ALLOWED_IPS=203.0.113.10,198.51.100.0/24
```

### Operations notes
- **Default `false`**. Enable before production deploy.
- Empty `DOKKEBI_PANEL_ALLOWED_IPS` when enabled → `dok build` warns.
- Legacy name `DOKKEBI_ADMIN_ALLOWED_IPS` also recognized.
- `dok update` adds `panelIpGuard: false` default and `.env.example` entry to existing projects.

Details: `SECURITY.md` §3.4.

---

## 5. `security.replay` — Replay defense tuning

### Attacks blocked
- **A10.** **Replay** of captured valid requests.
- **A11.** Rapid burst of identical requests from automation.

### What it does
**Always ON** on all `/api/_dokkebi/db` requests: `nonce` (one-time) + `timestamp` skew window. **Cannot disable; values only tunable.**

### How to apply
```js
security: {
  replay: {
    timestampWindowMs: 5_000,   // auto-clamped 1s ~ 30s
    nonceTtlMs: 35_000,         // auto-clamped window + 5s ~ 5min
  },
}
```

### Operations notes
- Mobile/satellite with large clock skew: raise `timestampWindowMs` to 8–15s.
- Client auto-learns clock offset; 5s is usually enough.

---

## 6. `security.activeDefense` — Active Defense Layer (ADL)

### Attacks blocked
- **A12.** Automation sending many well-formed requests in short time (brute force, scraping, price fuzzing).
- **A13.** One IP/session accumulating risky behavior (burst 403s, auth failures).

### What it does
Samples some `/api/_dokkebi/db` requests, computes **risk score**, blocks above threshold (`enforce`) or logs only (`monitor`). Works in lazy mode without cron.

### How to apply
```js
security: {
  activeDefense: {
    enabled: true,
    mode: 'monitor',            // 'monitor' | 'enforce'
    trigger: 'lazy',            // 'lazy' (default) | 'cron'
    sampleRate: 0.01,           // 1% sample
    intervalMs: 5 * 60_000,
    riskBlockThreshold: 0.85,   // block cutoff in enforce mode
    useWorkersAI: false,
  },
}
```

### Operations notes
- **Start with `mode: 'monitor'`**. Observe ~1 week for false positives, then promote to `enforce`.
- If legitimate calls blocked in `enforce`, raise `riskBlockThreshold` to 0.9–0.95 or temporarily use `monitor`.

---

## 7. `security.advisor` — Build-time security advisor

### Attacks blocked (indirect)
- **A14.** Human mistake: building external-cost/payment routes **without capability** → protection gap.

### What it does
`dok build` lightly scans backend controllers for:
- External payment/AI API calls (`api.openai.com`, `api.lemonsqueezy.com`, `api.stripe.com`, ...)
- Direct sensitive secret use (`process.env.OPENAI_API_KEY`, `__dokkebi_env__('OPENAI_API_KEY')`, etc.)
- Explicit cost actions (`points.deduct(`, `wallet.charge(`, etc.)

**Warns only** if route not covered by `security.capabilities.features` or `@dokkebi-capability` (does not auto-add).

### How to apply
ON by default. To disable:
```js
security: { advisor: { disable: true } }
```

### Operations notes
- False positives possible (e.g. strings inside library code only).
- Recommended: keep ON and declare capabilities for routes that truly need protection.

---

## 8. `policy` — Row-level isolation (Tenant Policy, required for multi-tenant SaaS)

### Attacks blocked
- **A15.** User A bypasses intended client code to SELECT/UPDATE/DELETE User B's data.
- **A16.** SQL injection or missing WHERE exposes other tenant rows.

### What it does
Worker checks every SQL for declared **tenant column** (e.g. `user_id = ?`) in WHERE; rejects (`verify`) or auto-injects (`inject`).

### How to apply
```js
policy: {
  enabled: true,
  mode: 'inject',                  // 'verify' | 'inject'
  claim: 'sub',                    // session tenant_json or JWT claim
  strict: true,
  tables: {
    animation_projects: { tenantColumn: 'user_id' },
    user_assets:        { tenantColumn: 'user_id' },
    // omit shared tables to exclude from policy
  },
}
```

> Top-level `tenantPolicy` is an **alias** merged same as `policy`. New projects: use `policy` only.

### Operations notes
- **Enable together with** `authorization` (op-level). They complement each other.
- `mode: 'verify'` rejects non-compliant SQL only. `inject` also auto-injects. New projects: prefer `inject`.
- Details: `docs/design/TENANT_POLICY.md`.

---

## 9. `authorization` — Operation-level authorization (JWT role)

### Attacks blocked
- **A17.** Regular user calls admin-only ops (`UPDATE users SET role=...`, `DELETE FROM …`).
- **A18.** JWT forgery or reuse of expired token.

### What it does
Verifies JWT signature/expiry and checks role policy per SQL (op, table) combination.

### How to apply
```js
authorization: {
  enabled: true,
  mode: 'strict',                       // 'warn' | 'strict'
  claim: 'role',
  rules: [
    { op: 'UPDATE', table: 'users',  roles: ['admin'] },
    { op: 'DELETE', table: '*',      roles: ['admin'] },
    { op: '*',      table: '*',      roles: ['user', 'admin'] }, // wildcard default
  ],
}
```
```env
DOKKEBI_JWT_SECRET=<32+ chars>
```

### Operations notes
- `mode: 'warn'` → log only on violation. `mode: 'strict'` → reject.
- Without `{ op:'*', table:'*' }` wildcard at end in strict mode, undefined ops are all rejected.

---

## 10. `webauthn` — Extra auth for sensitive actions (optional)

### Attacks blocked
- **A19.** After password/session theft, **payment/admin export** cannot proceed without device key (Passkey).

### What it does
Requires one-time WebAuthn passkey before specified ops; only requests with valid signature pass.

### How to apply
```js
webauthn: {
  enabled: true,
  rpName: 'Notofly',
  rpId: 'notofly.app',
  userVerification: 'required',
  requireForOps: ['DELETE', 'UPDATE_users'],
}
```

### Operations notes
- User registration flow must include passkey enrollment.
- Do not require on every call — limit to *truly sensitive* ops.

---

## 11. `strictCsp` — Strict Content Security Policy

### Attacks blocked
- **A20.** Even with XSS, blocks follow-up via external script injection/eval (data exfil, key theft).

### What it does
On deploy, auto-applies hash-pinned CSP headers like `script-src 'self' <hash>`.

### How to apply
```js
security: { strictCsp: true }
```

### Operations notes
- Some environments (e.g. iPad Safari) need `unsafe-eval` for WebAssembly instantiation; Dokkebi deploy template handles this.
- Third-party scripts (ad SDKs) may need extra domains.

---

## 12. `cspExtraHosts` — Per-app CSP allowlist (external images / APIs / iframes)

### Attacks blocked
- Complement to #11 strictCsp. When CSP is so strict that legitimate external resources (avatar CDN, payment widget, …) get blocked, this is the per-app escape hatch — **without weakening the baseline CSP**.

### What it does
Appends extra hosts to the CSP that `dok deploy` writes into `dist/_headers` and that `dok dev` / `dok serve` set on every response. The baseline directives are kept; only the listed directives are extended.

| Key | CSP directive | Applied by |
|---|---|---|
| `imgSrc` | `img-src` | deploy / serve / dev |
| `connectSrc` | `connect-src` | deploy |
| `frameSrc` | `frame-src` | deploy |

### How to apply
```js
// dokkebi.config.js
security: {
  level: 'standard',
  cspExtraHosts: {
    imgSrc:     ['https://api.dicebear.com'],
    connectSrc: ['https://api.openai.com'],
    frameSrc:   ['https://embed.partner.com'],
  },
},
```

→ After `dok deploy`, `dist/_headers` CSP becomes:

```
img-src 'self' data: blob: https://api.dicebear.com; ...
```

### Operations notes
- `dok build` does **not** write `_headers`. CSP changes require **re-running `dok deploy`**.
- Use full origins (`https://...`); wildcards (`https://*.example.com`) are supported.
- `connect-src` defaults already allow `https:`, so most external APIs work without extras — only add when blocked.
- Safety net: a `scripts/patch-headers.mjs` postbuild step keeps `_headers` patched even on older CLI caches.

---

## Option ↔ attack mapping — one table

| Attack scenario | 1 capabilities | 2 prev | 3 attest | 4 panelIp | 5 replay | 6 ADL | 8 tenant | 9 authz | 10 webauthn | 11 CSP | 12 cspHosts |
|---|---|---|---|---|---|---|---|---|---|---|
| A1 Permission branch bypass | ✅ | | | | | | | (supplement) | | |
| A2 Direct costly route call | ✅ | | | | | | | | | |
| A3 Stolen token on own session | ✅(sid verify) | | | | | | | | | |
| A4-A5 Step bypass | | ✅ | | | | | | | | |
| A6-A7 Bundle tampering | | | ✅ | | | | | | | |
| A8-A9 Ops brute force | | | | ✅ | | (supplement) | | | | |
| A10-A11 Replay/burst | | | | | ✅ | (supplement) | | | | |
| A12-A13 Automated scraping | | | | | | ✅ | | | | |
| A14 Human error (missing capability) | (advisor §7) | | | | | | | | | |
| A15-A16 Other tenant exposure | | | | | | | ✅ | (supplement) | | |
| A17-A18 Admin op bypass / JWT forgery | | | | | | | (supplement) | ✅ | | |
| A19 Sensitive action after session theft | | | | | | | | | ✅ | |
| A20 Post-XSS attacks | | | | | | | | | | ✅ |

✅ = direct block, (supplement) = partial/indirect.

---

## FAQ

**Q. If I enable everything, what do I worry about less?**
A. 1+2+3 (capabilities + chain + attestation) are mostly automated with little user code change. 8+9 (policy + authorization) need SQL policy declarations. 10 (webauthn) needs registration UX. 11 (strictCsp) is mostly automatic.

**Q. Must every route have capability?**
A. No. Only **external cost / payment / admin / step-dependent routes**. General CRUD is enough with policy + authorization.

**Q. Capabilities enabled but `CAPABILITY_AUTH_REQUIRED` on call?**
A. Feature has `roles` but request lacks JWT or empty role claim. Client should send `unlock(feature, { jwt: token })` or `Authorization: Bearer`.

**Q. `attestation` enabled; `CAPABILITY_ATTEST_REQUIRED` once after deploy?**
A. Normal. First capability call in new session auto-attests and retries. Looks like single call to client.

**Q. Legitimate calls blocked by ADL?**
A. Drop to `mode: 'monitor'` for ~1 week, then raise `riskBlockThreshold` to 0.9–0.95 and return to `enforce`.

---

## References

- Architecture / internals: `SECURITY.md`
- Multi-tenant policy: `docs/design/TENANT_POLICY.md`
- Authorization policy: `docs/design/AUTHORIZATION.md`
- AI agent guide: `AGENTS.md`
