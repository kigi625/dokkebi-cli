# dokkebi-cli

![Dokkebi logo](./icon-512.png)

[Learn more](https://dokkebi.net)

[Contact](https://notofly.com?page=noto&id=54a144f4-2ac1-41a4-b13d-0269fc265b4f)

# A client-side serverless framework where the backend runs in the browser

Dokkebi is an innovative framework that compiles backend TypeScript into **QuickJS** WASM and runs it directly in the browser. APIs work without a server, and database communication is handled securely through an E2E-encrypted proxy.

# "Zero-cost MVP operations"

Building and deploying a service consumes too many resources—from architecture design to infrastructure setup. AI has dramatically accelerated development, but the barrier of server management and maintenance costs remains.

Dokkebi starts from a firm philosophy: *use the user's resources wherever possible to deliver a smooth service at no cost.* Whether you have 10 or 100 services, we bring operating costs for unpredictable MVP-stage products to **exactly zero**.

# Core features and benefits

**Zero Cost:** Eliminate infrastructure management and server maintenance costs entirely

**One-Click Deploy:** Deploy and roll back frontend and backend together in one click (Cloudflare environment)

**No Server, No Ops:** No need to manage traditional server infrastructure—load balancers, port forwarding, Linux hardening, and the like.

# Two operating modes

Dokkebi supports two modes tailored to your project's needs.

**Serverless Mode:** Uses Cloudflare Functions to validate the Dokkebi environment and runs as a pure client-side backend.

**Server Mode:** Use when E2E encryption, payment verification, or business-logic protection is required, or when you want to avoid cloud vendor lock-in.

# A security architecture that reframes the problem

*"No server means nothing to hack."*

Shipping backend source to the client (browser) may sound reckless at first. Dokkebi does not try to make hacking impossible; instead, it shifts the security paradigm by exponentially increasing the time and cost of attacks until they are no longer worthwhile.

**Heavy obfuscation and encryption:** Backend logic is compiled to WASM with aggressive encryption and obfuscation.

**Whitelist query validation:** Unapproved or abnormal queries are blocked at the proxy layer and never reach the database.

**Active Defense:** Detects anomalous client behavior and blocks access immediately.

```
Browser
├── Vue / React frontend
└── QuickJS WASM backend (runs in-browser)
       │
       │  ECDH P-256 + HKDF + AES-256-GCM + HMAC-SHA256
       ▼
  DB proxy (/api/_dokkebi/db)
  ┌─────────────────────────────────────────┐
  │ 🖥  Server mode    dok serve → Node.js   │
  │ ☁  Serverless      Cloudflare Pages Fn   │
  └─────────────────────────────────────────┘
       │
       ▼
  DB (Cloudflare D1 / Supabase / Appwrite)
```

---

## Quick start

```bash
npm install -g dokkebi-cli

dok create my-app      # Interactive project scaffolding
cd my-app
dok dev                # Auto build + hot-reload dev server
open http://localhost:5173
```

---

## Key features

### True serverless

- Backend runs in the browser as **QuickJS WASM**—no separate server process
- Familiar Express-style API (`dokkebi:runtime`) for routes, middleware, and DB access
- Built-in type-safe query builder (`dokkebi-dsl`)

### Multi-layer security applied automatically

Multiple security layers are applied automatically during build and deploy—no extra configuration required.


| Category | Security | Description |
| -------- | -------- | ----------- |
| Transport encryption | ECDH P-256 + AES-256-GCM + HMAC-SHA256 | Forward secrecy, bidirectional encryption, request signing |
| Replay protection | Nonce + Timestamp (±30s) + timingSafeEqual | Blocks replay and timing attacks |
| SQL defense | SQL Allowlist + Query Registry + db.raw() blocked | Build-time allowlist, query hash registration, arbitrary SQL blocked |
| Secret protection | Env Opaque Handle | Sensitive vars never embedded in plaintext in the bundle |
| Code protection | Dual-protected bundle | JS obfuscation → AES-256-GCM encryption |
| Data isolation | Tenant Policy (pseudo-RLS) | Per-table session tenant conditions enforced automatically |
| Access control | Authorization Policy | JWT role-based operation and table-level permission checks |
| Session protection | OPFS session encryption (PBKDF2 + AES-GCM) | Defends against browser session theft |
| Active defense | Active Defense Layer (opt-in) | Real-time blocking of anomalous behavior via behavioral analysis |
| Execution permit | Signed Unlock Token (opt-in) | Worker-signed capability before paid or high-cost features run |
| Auth hardening | WebAuthn Passkey (opt-in) | Stronger defense against phishing and replay |
| Deploy safety | Preflight checks + build signing | Pre-deploy security config review, supply-chain traceability |
| Header protection | CSP · X-Frame-Options auto-applied | Blocks XSS, clickjacking, MIME sniffing |


### Defense by attack scenario


| Attack scenario | Defense stack | Defense flow |
| --------------- | ------------- | ------------ |
| 🔑 Secret theft | Env Opaque Handle | Build-time auto-transform → runtime Host closure isolation |
| 🌐 Network eavesdropping / tampering | E2E encryption | ECDH key exchange → AES-GCM + HMAC bidirectional encryption |
| 🛡 Code reversing | Dual-protected bundle | JS obfuscation → AES-256-GCM encryption |
| 💉 SQL injection | Triple SQL defense | Allowlist → Query Registry → dangerous syntax validation |
| 👤 Cross-user data access | Tenant Policy (pseudo-RLS) | Session binding → auto-injected WHERE / deny |
| 🍪 Session theft | OPFS session encryption | PBKDF2 100K + AES-GCM + origin salt |
| 🔓 Feature permission bypass | Signed Unlock Token | Short-lived execution permit signed with Worker-only secret |


### Parallel SELECT (DB read speed)

The browser bootstrap (`/api/_dokkebi/db` client injected by `dokkebi-cli`) uses a serial queue for DB calls to preserve **replay protection and nonce ordering**. However, **read-only queries whose string starts with `SELECT`** bypass this queue and can **send network requests concurrently**, reducing round-trip wait when multiple independent reads overlap.

- **Stays serial (queued):** `INSERT` / `UPDATE` / `DELETE`, SQL starting with `WITH` (CTEs, `WITH … INSERT`, etc.), tenant setup, capability channels—paths that need counter and ordering guarantees.
- **Runtime helper:** `parallelReads([...])` in `dokkebi:runtime` bundles multiple read `Promise`s with `Promise.all` within the same request; use it with the bootstrap behavior above to make **parallel SELECT** intent explicit in code.

### Developer experience

- **`dok dev`** — one command for build + server + hot reload
- **`dok deploy`** — one command for build + deploy + domain wiring + security headers
- **`dok policy:scaffold`** — auto-generate security policies from model/controller analysis
- **Operations admin** (`/_dokkebi/_panel`) — real-time requests, errors, and security event dashboard
- **Automatic error collection** — WASM errors + browser uncaught exceptions logged automatically
- **12-language CLI** — Korean, English, 日本語, 中文, Deutsch, and more
- **Upgrade existing projects** — `dok update` safely upgrades without touching user code

---

## CLI commands


| Command | Description |
| ------- | ----------- |
| `dok create [name]` | Interactive project creation (Vue/React + D1/Supabase/Appwrite) |
| `dok dev [src]` | Dev server (auto build + hot reload, default port 5173) |
| `dok build [src]` | QuickJS WASM build + frontend integration |
| `dok serve [src]` | Production Node.js server (default port 5174) |
| `dok deploy [src]` | Cloudflare Pages deploy (R2/S3 frontend + domain automation) |
| `dok migrate [src]` | Apply SQL migrations |
| `dok update [src]` | Apply latest version to existing project (preserves user code) |
| `dok security [src]` | Security opt-in **interactive** (`--status` for text-only) |
| `dok policy:scaffold [src]` | Auto-generate Tenant/Authorization Policy from model analysis |
| `dok lang [code]` | Change CLI language (12 languages supported) |


> See `dok <command> --help` for detailed options per command.

---

## Backend code example

```typescript
// backend/controllers/users.controller.ts
import { router, db, use, cors, jwtAuth } from 'dokkebi:runtime';
import { users } from '../models/index.js';

use(cors({ origin: '*' }));
use(jwtAuth(process.env.JWT_SECRET, ['/api/auth/login']));

router.get('/api/users', async (ctx) => {
  const result = await db.select(users).exec();
  return ctx.json(result.rows);
});

router.post('/api/users', async (ctx) => {
  const { name, email } = ctx.body;
  await db.insert(users).values({ id: crypto.randomUUID(), name, email }).exec();
  return ctx.json({ ok: true }, 201);
});
```

```typescript
// backend/models/index.ts
import { defineTable, text } from 'dokkebi-dsl';

export const users = defineTable('users', {
  id:         text('id').primaryKey(),
  name:       text('name').notNull(),
  email:      text('email').notNull().unique(),
  created_at: text('created_at').default('CURRENT_TIMESTAMP'),
});
```

---

## Deployment modes


| | Development (`dok dev`) | Server (`dok serve`) | Serverless (`dok deploy`) |
| - | ----------------------- | -------------------- | ------------------------- |
| Runtime | Node.js (local) | Node.js (server) | Cloudflare Pages Edge |
| Hot reload | ✓ | — | — |
| DB proxy | Node.js | Node.js | Pages Function |
| Default port | 5173 | 5174 | — |


---

## Supported databases


| DB | proxyMode | Notes |
| -- | --------- | ----- |
| Cloudflare D1 | server / serverless | Recommended (serverless-native) |
| Supabase | server | REST API |
| Appwrite | server | REST API |


---

## Security options — start with what each attack is blocked by

The `security` section in `dokkebi.config.js` has several user-toggleable options. One document summarizes **which attack each option blocks** and **how it is applied**.

- **Current project:** `dok security` — in a terminal (TTY), move with **arrows + Enter**, toggle ON/OFF and levels, see per-item threat summary and required `.env`/config. Saves patch `dokkebi.config.js` automatically (failed lines get snippet guidance) + `.bak`.
- **Text only:** `dok security --status` (CI / non-TTY). **Force TUI:** `dok security --interactive`.
- ➡ **[docs/SECURITY_OPTIN.md](docs/SECURITY_OPTIN.md)** — opt-in quick reference (option ↔ attack ↔ config, one line each).
- ➡ **[docs/SECURITY_OPTIONS.md](docs/SECURITY_OPTIONS.md)** — per-option attack cases / examples / ops notes, including option ↔ attack mapping table.

Recommended default: enable only `capabilities.enabled: true` and `attestation` turns on automatically; client prev-token attachment and recursive unlock are handled automatically. `dok build` warns if cost-bearing routes lack capability declarations.

## Production checklist (external attacker perspective)

We do not assume malicious dependencies or a compromised build machine. This checklist covers what to verify in production assuming **only access to the deployed URL—static bundles (JSON·JS·WASM) and public APIs**.

### Query / SQL boundary

- **Cloudflare Pages Secret** has `DOKKEBI_QUERY_MODE=strict` (or equivalent fail-closed operation). **Do not use `auto` / `learn` in production.**
- `dist/dokkebi/query-registry.json` is non-empty, and empty-registry deploy is blocked via **`dok deploy --strict-registry`** or **`queryRegistry.strict: true`** in `dokkebi.config.js`.
- Prefer **`rawAllowed: false`** in `sql-allowlist.json` and avoid **`db.raw()`**.
- Allowed tables and operations are minimal (no unnecessary **`SELECT *`**, wide JOINs, or subquery sprawl).

### Tenant / authorization (server trust boundary)

- **Do not authorize from `bindSession()` or tenant meta sent by the client alone.** Restrict real data access via **D1 schema/app-level enforcement** or **separate trusted server verification / RLS** (where the platform supports it).
- **`policy` (Tenant)** in `dokkebi.config.js` is enabled, and **`policy.strict`** is not disabled in production.
- **`authorization`** rules are defined; operate close to **`strict`** when needed (default `warn` alone may be insufficient).

### Minimize exposed surface

- If you do not need **`/_dokkebi/_panel`**, put it behind routing/IP restrictions or a private network. If you use it, set a long **`DOKKEBI_ADMIN_PASSWORD`** and restrict IPs with **`DOKKEBI_PANEL_ALLOWED_IPS`** when possible.
- Be aware that **`/api/_dokkebi/log`** can pollute storage or pressure quotas; use rate limits and monitoring if needed.
- **`dok serve`** is for local/internal networks only. **Do not expose `0.0.0.0` binding to the internet.**

### Build / deploy quality

- Do not disable **`--preflight`** on **`dok deploy`**; use **`--preflight-strict`** to fail deploy on warnings when needed.
- Optionally reviewed **`security.strictCsp: true`** (trade off with browser/CDN compatibility).
- Reduce **frontend XSS** (with CSP allowing `unsafe-inline` / `unsafe-eval`, XSS can lead to compromise of in-browser execution context).

### Assume reconnaissance is possible

- Treat **`/dokkebi/sql-allowlist.json`**, **`query-registry.json`**, etc. as **potentially public** and confirm design ensures their contents alone cannot reach other users' data.

---

## Plugins

Extend the WASM backend safely. Enable in `plugins` in `dokkebi.config.js`.


| Plugin | Capability | Security |
| ------ | ---------- | -------- |
| **fetch** | External HTTP from WASM | Domain whitelist + concurrent request limit + timeout |
| **bundle** | In-browser esbuild-wasm bundling | OPFS sandbox + CDN external |


---

## Operations admin IP restriction

`/_dokkebi/_panel` can be restricted with an IP allowlist by setting `security.panelIpGuard: true` in `dokkebi.config.js` and `DOKKEBI_PANEL_ALLOWED_IPS` in `.env` or Cloudflare Pages Secrets. Default is `false`.

```js
// dokkebi.config.js
export default {
  security: {
    panelIpGuard: true,
  },
};
```

```env
DOKKEBI_ADMIN_PASSWORD=your_secure_password
DOKKEBI_PANEL_ALLOWED_IPS=203.0.113.10,198.51.100.0/24
```

When `security.panelIpGuard` is `false`, `DOKKEBI_PANEL_ALLOWED_IPS` is ignored. When `true` but env is empty, `dok build` prints a warning. Comma-separated IPs or IPv4 CIDR are supported; `dok dev`, `dok serve`, and Cloudflare Pages Functions panel share the same config.

Existing projects get `panelIpGuard: false` default and `.env.example` `DOKKEBI_PANEL_ALLOWED_IPS` entry reinforced on `dok update`.

## Signed Unlock Token

Paid features, high-cost AI calls, admin export, and similar should not rely on browser-only `if (isPremium)`—require a Worker-signed execution permit instead.

```js
// dokkebi.config.js
export default {
  security: {
    capabilities: {
      enabled: true,
      secretEnv: 'DOKKEBI_CAPABILITY_SECRET',
      features: {
        'image.generate': {
          roles: ['premium', 'admin'],
          ttlMs: 10000,
          routes: ['POST /api/ai/image'],
        },
      },
    },
  },
};
```

With `routes` set, `dok build` auto-inserts a guard before the matching Dokkebi runtime route. Users need not call `capability.unlock()` in handlers manually; passing requests get `ctx.capability` populated.

You can also declare near controllers via JSDoc:

```ts
/**
 * @dokkebi-capability feature:image.generate route:"POST /api/ai/image" roles:['premium','admin'] ttl:10000
 */
router.post('/api/ai/image', async (ctx) => {
  // Bind ctx.capability.token/proof into execution params or server request material
});
```

For finer manual state binding, call the API directly:

```ts
import { capability } from 'dokkebi:runtime';

const unlock = await capability.unlock('image.generate', {
  state: { projectId, promptHash },
  jwt: userToken,
});
if (!unlock.ok) throw new Error(unlock.error);

// token/proof must be used as execution material, not as a simple flag
```

Set `DOKKEBI_CAPABILITY_SECRET` in `.env` or Cloudflare Pages Secrets to a random value of at least 32 bytes. This raises the cost of permission-flag/branch-patch attacks but is not DRM that fully blocks local dumps by already-authorized users.

### Capability Chain

You can require a valid token from another capability before issuing a specific one.

```js
features: {
  'auth.verified':  { public: true,  ttlMs: 60000 },
  'image.generate': {
    roles: ['premium','admin'],
    ttlMs: 10000,
    requires: { prev: ['auth.verified'] },
  },
}
```

```ts
const a = await capability.unlock('auth.verified');
const b = await capability.unlock('image.generate', {
  prev: [{ feature: 'auth.verified', token: a.capability.token }],
});
```

The Worker verifies HMAC signatures, expiry, `sid` match, and feature match for all prerequisite tokens.

## Bundle Attestation

At build time, encrypted bundle bytes are split into 16KB chunks and a SHA-256 manifest is generated. Each session, the Worker sends random chunk indices as a challenge and compares the client response to the manifest. Tampered bundles cannot pass the challenge.

```js
// dokkebi.config.js
security: {
  attestation: {
    enabled: true,
    sampleSize: 4,         // 1–16, default 4
    ttlMs: 5 * 60_000,     // 30s–30min, default 5 min
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

When the server returns `CAPABILITY_ATTEST_REQUIRED` for a capability with `requires.attest: true`, the client automatically runs the `_attest` challenge and retries once. No user code changes required.

See `SECURITY.md` §3.6 for details and limitations.

---

## Requirements

- **Node.js 20+** — required by Cloudflare Wrangler. `dok deploy` calls `wrangler pages deploy` internally, so deploy fails on Node 18. Build/local dev may work on 18, but **20 LTS or newer** is recommended.

## Installation

```bash
# Global install
npm install -g dokkebi-cli

# Or local install
npm install dokkebi-cli
npx dok --help
```

## Change language

```bash
dok lang
```

## License

ELv2
