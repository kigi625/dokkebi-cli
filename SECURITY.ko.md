# dokkebi-cli 보안 문서

> 최종 갱신: 2026-04-20
> 이 문서는 **현재 구현된 방어 계층과 지금도 남아있는 한계** 를 기록합니다.
> 버전별 변경 이력은 CHANGELOG 를 참조하세요.
>
> 사용자가 직접 켜고 끄는 옵션별 **"이 옵션은 어떤 공격을 막는가"** 가이드는
> [`docs/SECURITY_OPTIONS.md`](docs/SECURITY_OPTIONS.md) 를 참고하세요.

---

## 0. 요약 (TL;DR)

dokkebi 는 다음 한 가지를 성립시키려고 설계된 실험적 아키텍처입니다:

> **"백엔드 비즈 로직은 난독화 + AES-256-GCM 보호 번들로 패키징되어 브라우저의 로컬 QuickJS WASM VM에서 실행되고, DB 는 암호화 프록시를 거쳐만 접근된다. DB 자격증명은 브라우저에 절대 노출되지 않는다."**

이 목적에 한해서는 강력하게 작동합니다. 다만 **"사용자 권한/인가 결정"** 은 설계적으로 브라우저 바깥(프록시 레이어 또는 DB 자체)에서 해야 하며, 이 문서의 §6 이 핵심입니다.

**지금 시점 기준:**
- 🟢 잘 방어됨: 전송 암호화, SQL 인젝션, 타이밍 공격, 경로 traversal, body DoS, rate limit, nonce 재전송, 세션 키 유출
- 🟡 opt-in 으로 가능: row-level 격리(Tenant Policy), 연산-레벨 인가(Authorization Policy)
- 🔴 구조적 한계: XSS 시 연쇄 피해, 브라우저 직접 API 호출 플러그인의 키 노출, 분산 DDoS, 지적재산 보호

---

## 1. 아키텍처 & 신뢰 경계

```
  ┌──────────────────────┐                     ┌────────────────────────┐
  │ 브라우저 (Untrusted) │                     │ dok serve / CF Worker  │
  │                      │                     │   (Trusted Proxy)      │
  │  ┌────────────────┐  │   AES-256-GCM       │                        │
  │  │ QuickJS WASM VM│  │    + HMAC-SHA256    │ 4-레이어 SQL 파이프라인│
  │  │  backend.bundle│──┼──── + Nonce+TS ────▶│                        │
  │  │  (비즈 로직)    │  │                     │                        │
  │  └────────────────┘  │                     │ (옵션) JWT+role 인가  │
  │  env 비밀: Opaque    │                     │                        │
  │  Handle (host 클로저)│                     └───────────┬────────────┘
  └──────────────────────┘                                 │
                                                           ▼
                                                    ┌──────────────┐
                                                    │ D1/Supabase/ │
                                                    │  Appwrite    │
                                                    └──────────────┘
```

| 계층 | 신뢰 수준 |
|---|---|
| 브라우저 JS / WASM 번들 | ❌ Untrusted. 공격자가 완전 제어 가능하다고 가정. |
| 프록시 (dok serve / Pages Function) | ✅ Trusted |
| DB | ✅ Trusted |

핵심 귀결: **암호학적으로 유효한 어떤 클라이언트** 가 왔을 때 프록시는 요청을 받게 됩니다. "내 앱의 합법적 사용자" 인지는 프록시가 **추가로** 판정해야 합니다 (§6).

---

## 2. 방어 계층 — 현재 구현 상태

### 2.1 전송 / 네트워크

| ID | 목표 | 구현 | 한계 |
|---|---|---|---|
| A-1 | 도청/변조 | **ECDH(P-256) + HKDF-SHA256 → AES-256-GCM** 양방향 암호화 | TLS 밖에서의 서버 공개키 검증 없음 — TLS 무력화 시 세션 자체가 공격자 것 |
| A-2 | 요청 무결성 | **HMAC-SHA256** 서명 검증 | 전체 요청에 적용 |
| A-3 | 재전송 | **Nonce(1회성) + ±5s TS skew 윈도우** — 인메모리 map + D1 `_dokkebi_nonces` 이중 체크로 크로스-아이솔레이트 replay 차단, HMAC 검증 통과 후에만 캐시 | nonce 캐시 35s TTL (둘 다 `security.replay` 로 조정 가능) |
| A-4 | Forward Secrecy | ECDH Ephemeral — 핸드셰이크마다 새 키쌍 | 서버 긴-세션 JWK 유지 시 약화 가능 |

### 2.2 세션

| 구현 | 내용 |
|---|---|
| 세션 ID | `crypto.randomUUID()` (128-bit) |
| 세션키 | enc/sig 키 HKDF 분리 (`dokkebi-enc` / `dokkebi-sig`) |
| 저장 | D1 `_dokkebi_sessions` + 아이솔레이트 인메모리 캐시 |
| TTL | 10분(서버) / 8시간(서버리스 캐시) |
| 세션 폭탄 방어 | `MAX_SESSIONS=500` + FIFO + IP당 핸드셰이크 20/분 |

### 2.3 SQL 보안 — 4-레이어 파이프라인 + 옵션 2개

```
요청 → [공통 방어] → [Allowlist] → [Query Registry] → [Tenant Policy] → [Authorization] → DB
        상시        상시          상시             opt-in             opt-in
```

| 레이어 | 역할 | 커버리지 |
|---|---|---|
| **공통 방어** | 다중 문장(`;`), 주석(`-- /**/`), 50KB 초과, 위험 토큰(`ATTACH`, `PRAGMA`, `LOAD_EXTENSION`, `INTO OUTFILE`, `xp_*`, `SLEEP`, `PG_SLEEP`, `BENCHMARK`, `WAITFOR`, `INFORMATION_SCHEMA`) 차단 | 상시 |
| **SQL Allowlist** | 테이블 × 연산(SELECT/INSERT/UPDATE/DELETE) 단위 허가. 모든 FROM/JOIN/INTO/UPDATE 참조 검사. `CREATE TABLE` 은 `_dokkebi_*` 만 | 상시 |
| **Query Registry** | SQL **shape** 단위 허가 — 컬럼 변경, WHERE 제거, `OR 1=1` 등 구조 변조 차단. 정적 스캐너 + 주석 선언 + dev 학습으로 수집 | 상시 (auto/strict 모드) |
| **Tenant Policy** | Row-level 격리 — `WHERE user_id = ?` 검증(verify) 또는 자동 주입(inject). top-level `OR`, 누락 WHERE, aliased column 감지 | opt-in |
| **Authorization** | 연산-레벨 권한 — "DELETE posts 는 role=admin 만" — JWT 서명 검증 + role 매칭 | opt-in |

파라미터 바인딩은 D1/Supabase/Appwrite SDK 가 `prepare().bind()` 로 처리. 프록시는 raw SQL 을 절대 문자열 보간하지 않음.

### 2.4 암호 구현

| 구현 | 내용 |
|---|---|
| HMAC 비교 | `timingSafeEqual` + 길이 불일치 시 더미 비교로 **상수-시간** 유지 |
| 관리자 PW 비교 | 패딩 후 상수-시간 비교 |
| Nonce | 요청당 `crypto.randomUUID()` |
| 평문 잔존 | 복호화 직후 `plain.fill(0)` (best-effort) |
| 커브 | P-256 (prime256v1) |
| env secret | 빌드타임에 AES-GCM 으로 감싸 OPFS 저장. Host 클로저에만 복호화 |

### 2.5 DoS / 자원 고갈

| 범주 | 상한 |
|---|---|
| 핸드셰이크 | IP당 20/분 |
| DB 쿼리 | IP당 300/분 + 유효 세션 |
| 로그 | IP당 600/분 + 64KB body |
| Body 크기 | handshake 8KB / db 128KB / log 64KB / admin 2KB — `Content-Length` 선체크 + 스트리밍 중 중단 |
| 세션 | 최대 500 + FIFO |
| Nonce 캐시 | TTL 35s + 60s 주기 정리 |

### 2.6 정보 노출

| 구현 | 내용 |
|---|---|
| DB 자격증명 | Opaque Handle — 프록시 측에만. 브라우저에 없음 |
| 쿼리 내용 | AES-GCM 암호화 채널 — DevTools 에서 평문 관찰 불가 |
| Path traversal | `safeStaticJoin()` — `../`, `%2e%2e`, 널바이트 차단 + distRoot 재검증 |
| 민감 파일 서빙 | `.dokkebi/env-secrets.json`, `.dev.vars` 등 경로 차단 |
| 에러 메시지 | `sanitizeDbError()` — Bearer/Authorization 마스킹 |

### 2.7 번들 무결성 / 빌드

| 구현 | 내용 |
|---|---|
| `backend.bundle.enc` | 빌드타임 SHA-256 + 런타임 `crypto.subtle.digest` 검증 |
| QuickJS WASM | 로컬 npm 패키지 (`@jitl/quickjs-*`) — 외부 CDN 의존 없음 |
| 빌드 도구 | 구조화된 Node API 중심 처리. 외부 명령은 배포/설치 등 필요한 경우에만 배열 인자로 호출 |

### 2.8 관리자 패널

| 구현 | 내용 |
|---|---|
| PW 비교 | 상수-시간 |
| 브루트포스 | IP당 5회 실패 → 5분 락 |
| 토큰 | HMAC 서명 + 만료 |
| Body | 2KB 상한 |

### 2.9 플러그인

| 플러그인 | 상태 | 비고 |
|---|---|---|
| `plugin-fetch` | ✅ 빌트인 | 도메인 화이트리스트, http/https 스킴 강제, TLD 단독 거부 |
| `plugin-bundle` | ✅ 빌트인 | 코드 번들러 |
| `plugin-ai` | ❌ **CLI 빌트인에서 제거됨** (v5.3) | `examples/plugins/plugin-ai.js` 로 이동. 프로덕션에서 활성 시 빌드 실패 (acknowledgeKeyExposure 명시 없으면). §5 참조 |

---

## 3. opt-in 보안 기능

### 3.1 Tenant Policy — Row-level 격리

**용도**: "유저 A 가 유저 B 의 데이터를 볼 수 없어야 함"

```js
// dokkebi.config.js
policy: {
  enabled: true,
  mode: 'inject',        // 'verify' (검증만) | 'inject' (자동 주입)
  claim: 'user_id',      // 세션 tenant_json 에서 꺼낼 필드
  strict: true,
  tables: {
    posts: { tenantColumn: 'user_id', mode: 'enforce' },
    orders: { tenantColumn: 'user_id', mode: 'enforce' },
  },
},
```

동작:
1. 클라이언트가 `ctx.setSessionTenant({ user_id: 'u1' })` 호출 (로그인 후)
2. 프록시가 세션의 `tenant_json` 에 저장
3. 이후 모든 SELECT/UPDATE/DELETE 는 `WHERE user_id = ?` 가 있는지 검증(verify) 또는 자동 주입(inject)
4. INSERT 는 `user_id` 컬럼 값이 세션 테넌트와 일치하는지 검증

자세한 내용: [docs/design/TENANT_POLICY.md](docs/design/TENANT_POLICY.md)

### 3.2 Authorization Policy — 연산-레벨 인가 (v5.3 신규)

**용도**: "DELETE posts 는 role=admin 만 가능해야 함"

```js
authorization: {
  mode: 'warn',  // 'warn' (기본) | 'strict'
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

동작:
1. 클라이언트가 `Authorization: Bearer <jwt>` 헤더 또는 암호화 payload 의 `_jwt` 필드로 JWT 전송
2. 프록시가 HS256 서명 + `exp/nbf/iss/aud` 검증
3. 최종 SQL 의 (op, table) 로 규칙 매칭 → role 검증
4. 실패 시 401 (AUTH_REQUIRED) 또는 403 (ROLE_FORBIDDEN 등)

**§6 의 "인가 경계" 문제를 실질적으로 해결하는 레이어**. JWT 발급은 사용자가 별도로 구현 (로그인 엔드포인트).

자세한 내용: [docs/design/AUTHORIZATION.md](docs/design/AUTHORIZATION.md)

### 3.3 WebAuthn (Passkey) 요청 서명 — opt-in (v5.5+, **런타임 미구현**)

> ⚠️ **현재 상태**: `dok init` 옵션과 `dokkebi.config.js` 의 `webauthn` 섹션, 클라이언트 SDK 진입점(`dokkebi.webauthn.register/authenticate`) 까지는 정의돼 있으나, **워커 측 assertion 검증 / `requireForOps` 게이트는 아직 구현되지 않았습니다** (후속 PR — `docs/design/WEBAUTHN.md` 의 "런타임 SDK 구현은 후속 PR" 명시 참조). 즉 현재는 `enabled: true` 로 설정해도 서버 측에서 강제되지 않습니다. 본 절은 **설계 의도** 로 읽어주세요.

`dok init` 에서 활성화를 선택한 프로젝트만 동작. 브라우저 메모리에서 추출할 수 없는 **OS/TPM/Secure Enclave 기반 개인키** 로 민감 연산 요청에 추가 서명을 요구합니다. 세션키가 XSS 로 탈취돼도 공격자는 **매번** 지문/Face/PIN 프롬프트를 통과시킬 수 없으므로 방어가 무너지지 않습니다.

```js
// dokkebi.config.js
security: {
  webauthn: {
    enabled: true,
    requireForOps: ['INSERT:*', 'UPDATE:*', 'DELETE:*'], // 쓰기에만 UV 요구
  },
}
```

반드시 **회원가입 직후** `dokkebi.webauthn.register({ userId, userName })` 와 **로그인 직후** `dokkebi.webauthn.authenticate({ userId })` 를 배선해야 실제 보호가 켜집니다. `dok build` 가 매 빌드마다 배선 안내 배너를 출력합니다.

상세 설계·연동 가이드: [docs/design/WEBAUTHN.md](docs/design/WEBAUTHN.md)

### 3.4 관제 어드민 IP allowlist

`/_dokkebi/_panel` 은 비밀번호 인증과 로그인 rate limit 에 더해, 운영 환경에서 IP 기반 접근 제한을 걸 수 있습니다. 기본값은 꺼짐이며 `dokkebi.config.js` 에서 명시적으로 켭니다.

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

동작:
1. Worker 는 `CF-Connecting-IP` 를 우선 사용하고, 없으면 `X-Forwarded-For` 첫 번째 값을 사용
2. `security.panelIpGuard` 가 `false` 이면 `DOKKEBI_PANEL_ALLOWED_IPS` 값이 있어도 차단하지 않음
3. `security.panelIpGuard` 가 `true` 인데 `DOKKEBI_PANEL_ALLOWED_IPS` 가 비어 있으면 `dok build` 가 경고 출력
4. 값이 있으면 쉼표로 분리된 정확한 IP 또는 IPv4 CIDR 과 일치할 때만 패널 HTML, 로그인, API 접근 허용
5. 차단된 요청은 403 을 반환하고, D1 이 연결된 서버리스 패널에서는 `_dokkebi_security` 에 `panel_ip_block` 이벤트를 남김

이 설정은 `dok dev`, `dok serve`, Cloudflare Pages Functions 패널에 동일하게 적용됩니다. 예전 명칭 호환을 위해 `DOKKEBI_ADMIN_ALLOWED_IPS` 도 읽지만, 새 프로젝트에서는 `DOKKEBI_PANEL_ALLOWED_IPS` 를 권장합니다.

### 3.5 Signed Unlock Token — Cryptographic Checkpoint (opt-in)

**용도**: "브라우저 WASM 의 `if (user.plan === 'premium')` 분기를 패치해 유료/고비용 기능을 강제로 실행하는 공격"의 비용을 올립니다.

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

또는 컨트롤러 JSDoc 으로 빌드 타임 자동 적용을 선언할 수 있습니다.

```ts
/**
 * @dokkebi-capability feature:image.generate route:"POST /api/ai/image" roles:['premium','admin'] ttl:10000
 */
router.post('/api/ai/image', async (ctx) => {
  // guard 통과 후 ctx.capability 사용 가능
});
```

동작:
1. `dok build` 가 `security.capabilities.features[*].routes` 와 `@dokkebi-capability` 를 수집
2. Dokkebi runtime 라우터가 일치하는 route 앞에 capability guard 를 자동 삽입
3. 요청 시 guard 가 `capability.unlock(feature, { state, jwt })` 를 호출
4. 요청은 기존 `/api/_dokkebi/db` 암호화 채널을 사용하므로 ECDH, AES-GCM, HMAC, nonce, timestamp, ADL 방어를 그대로 통과해야 함
5. Worker 가 feature 정책과 JWT role 을 확인
6. Worker-only `DOKKEBI_CAPABILITY_SECRET` 으로 `feature + sessionId + controllersHash + stateHash + nonce + exp` 를 서명
7. guard 통과 후 핸들러는 `ctx.capability` 의 `token/proof` 를 단순 허가 플래그가 아니라 기능 실행 재료로 사용

중요한 한계:
- 이 기능은 Authorization Policy 를 대체하지 않습니다. DB 쓰기/삭제 권한은 여전히 Worker 의 Authorization Policy 또는 DB RLS 로 강제해야 합니다.
- `if (verify(token)) runFeature()` 형태로 쓰면 검증 함수 패치에 취약합니다. 토큰의 `proof` 또는 토큰에서 파생한 값을 복호화 키/파라미터/서버 요청 입력에 묶어야 효과가 큽니다.
- 권한 있는 사용자가 자기 기기에서 이미 받은 코드/토큰/결과를 덤프하는 것까지 완전히 막는 DRM 은 아닙니다.

#### 3.5.1 Capability Chain — 선행 토큰 요구 (`requires.prev`)

특정 feature 가 발급되기 전에 다른 feature 의 유효한 토큰을 함께 제출하도록 강제합니다. "결제 → 이미지 생성" 처럼 단계 우회를 막을 때 사용합니다.

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

클라이언트는 선행 토큰을 함께 보냅니다.

```ts
const a = await dokkebi.capability.unlock('auth.verified');
const b = await dokkebi.capability.unlock('image.generate', {
  prev: [{ feature: 'auth.verified', token: a.capability.token }],
});
```

Worker 는 각 선행 토큰의 HMAC 서명, 만료, `sid` 일치, feature 일치를 모두 검증합니다. 어디 한 곳이라도 끊기면 `CAPABILITY_PREV_MISSING` / `CAPABILITY_PREV_INVALID` 로 거절됩니다.

### 3.6 Bundle Attestation — 청크 무작위 해시 검증 (opt-in)

**목적**: 클라이언트가 들고 있는 암호화 번들 바이트가 실제로 "이 빌드에서 산출된 원본 번들" 임을 서버가 매 세션마다 무작위 챌린지로 확인합니다. 번들이 패치/위조됐다면 챌린지 응답이 매니페스트와 어긋나 차단됩니다.

```js
// dokkebi.config.js
security: {
  attestation: {
    enabled: true,
    sampleSize: 4,         // 한 챌린지에서 검사할 청크 수 (1–16, 기본 4)
    ttlMs: 5 * 60_000,     // 통과 후 유효 시간 (30s – 30min, 기본 5분)
  },
  capabilities: {
    enabled: true,
    features: {
      'image.generate': {
        roles: ['premium','admin'],
        requires: { attest: true },   // attest 통과 세션만 토큰 발급
      },
    },
  },
}
```

동작:

1. `dok build` 가 암호화 번들 바이트를 16KB 청크로 나눠 SHA-256 매니페스트(`backend-bundle.chunks.json`) 를 생성합니다. 매니페스트는 Worker 코드에 임베드되며, 클라이언트로는 노출되지 않습니다.
2. 클라이언트가 `requires.attest` 가 있는 capability 를 요청하면 Worker 가 `CAPABILITY_ATTEST_REQUIRED` 를 반환합니다.
3. 클라이언트는 자동으로 `_attest` 챌린지를 받습니다. (`{ nonce, indices }`)
4. 클라이언트가 메모리에 보관 중인 암호화 번들 바이트를 슬라이싱해 각 인덱스의 SHA-256 해시를 응답합니다.
5. Worker 가 매니페스트와 비교해 일치하면 세션을 attest 통과 상태로 표시(`_attestPassMap`)하고, 클라이언트는 capability 발급을 자동 재시도합니다.

로그 (`_dokkebi_security`):

| event | 의미 |
|---|---|
| `attest_passed` | 챌린지 응답이 매니페스트와 일치 |
| `attest_failed` | nonce 만료/길이 불일치/해시 불일치 |
| `capability_denied: CAPABILITY_ATTEST_REQUIRED` | `requires.attest=true` 인데 attest 미통과 세션이 capability 요청 |

한계:

- 클라이언트는 합법적으로 번들 바이트를 가지고 있으므로 attestation 은 "변조된 번들로는 통과할 수 없다" 는 보장은 강하지만, "정상 번들을 가진 사용자가 이후 행위를 변형하는 것" 까지 막지는 못합니다. Capability/Authorization Policy 와 함께 사용하세요.
- 청크 매니페스트는 빌드 산출물에 포함됩니다. `dist/`/`worker/` 는 정상 배포 흐름에서 외부 노출되지 않으므로 그대로 두면 되지만, 별도 정적 호스팅에 매니페스트 파일 자체를 공개로 올리지는 마세요.

### 3.7 Replay 방어 — 기본 ON, 값만 튜닝 (v5.4+)

모든 `/api/_dokkebi/db` 요청은 **자동으로** Nonce(1회성) + Timestamp skew 윈도우로 재전송이 차단됩니다. 설정으로 끌 수는 없고, 파라미터만 조정합니다.

```js
// dokkebi.config.js
export default {
  security: {
    replay: {
      timestampWindowMs: 5000,   // 기본 5초. 모바일/위성망 환경에서 오차 크면 8~15s 권장.
      nonceTtlMs: 35000,         // 기본 35초. window + 5s 이상이어야 함.
    },
  },
};
```

- **허용 범위**: `timestampWindowMs ∈ [1s, 30s]`, `nonceTtlMs ∈ [window+5s, 5min]`
- **범위 외 값**은 `dok build` 시 자동으로 안전 범위로 clamp + 경고 출력.
- **클라이언트 시계 자동 보정**: 서버가 `TIMESTAMP_SKEW` 응답에 `server_ts` 를 담아 돌려주면, 클라가 offset 을 학습하여 1회 재시도. 모든 응답의 `Date` 헤더도 관찰해 EWMA 로 점진 보정. → **디바이스 시계가 틀어져도 기능은 정상 동작**.

에러 응답에 **`code`** 필드가 추가되어 디버깅이 명확해졌습니다:

| code | 의미 | 클라 자동 복구 |
|---|---|---|
| `TIMESTAMP_SKEW` | 클라 시계가 서버와 `timestampWindowMs` 이상 차이남 | ✅ offset 보정 후 1회 재시도 |
| `REPLAY_DETECTED` | 동일 nonce 가 이미 관측됨 | ✅ 새 nonce 로 1회 재시도 |
| `SIGNATURE_INVALID` | HMAC 불일치 (세션 키 불일치 / 변조) | ✅ 재핸드셰이크 |
| `SESSION_INVALID` | 세션 만료 또는 존재 X | ✅ 재핸드셰이크 |
| `REQUEST_MALFORMED` | 필수 필드 누락 | ❌ 코드 버그 |

---

## 4. 현재도 남아있는 우려 사항

### 4.1 🟡 Tenant Policy 만 켜고 Authorization 없으면 — role 기반 권한 미방어

Tenant Policy 는 "같은 tenant 내 격리" 만 처리. "관리자만 삭제" 같은 **역할 기반 권한** 은 처리하지 않음. 두 레이어는 **보완적** 이며 둘 다 활성화하는 것이 권장.

### 4.2 🟡 Query Registry `auto` 모드의 방어 한계

기본 `auto` 모드에서는 미등록 queryId 가 와도 `_debugSql` 폴백으로 실행됨 → SQL shape 보호가 사실상 비활성.

완전 보호가 필요하면:
```js
queryRegistry: { strict: true }
```
단, dev 에서 충분히 학습시켰거나 정적 스캐너로 수집된 후에만 안전.

### 4.3 🔴 XSS 연쇄 피해

XSS 발생 시 공격자는:
- WASM 을 통해 프록시로 **allowlist/registry 범위 내 임의 쿼리** 전송 가능
- OPFS 의 env secret 을 같은 origin 에서 재현 가능 → OPFS 암호화는 XSS 방어 아님
- Authorization JWT 토큰을 localStorage 등에서 훔쳐 프록시 호출 가능

대응: **dokkebi 바깥**에서 해결 — CSP, Trusted Types, sink 제거.

### 4.4 🔴 분산 DDoS

애플리케이션 레벨은 IP 기반 rate limit 만 제공. **Cloudflare WAF / Bot Management 앞단 필수**.

### 4.5 🟡 ECDH 서버 공개키의 초기 신뢰

첫 핸드셰이크의 서버 공개키는 TLS 위에 실려 옴 — TLS 밖에서 검증 없음. TLS 무력화 시 MITM 가능 (모든 웹 앱의 공통 가정).

### 4.6 🟡 WASM 번들 역공학

백엔드 비즈 로직이 브라우저로 배포되는 것은 **설계상 필연**. minify 만, 난독화 없음. 상용 지적재산 보호가 필요하면 dokkebi 부적합.

### 4.7 🟡 CORS 기본 설정

기본 템플릿은 `Access-Control-Allow-Origin: *` 로 시작 — 배포 전 실제 프론트 오리진으로 제한 필수 (특히 쿠키 기반 다른 서비스와 혼용될 때).

### 4.8 🟡 관찰 가능성

`_dokkebi_security` 테이블에 이벤트 로깅은 있지만 알림/SIEM 통합은 없음. 운영자는 대시보드/알림을 별도로 연동해야 함.

### 4.9 🟡 HS256 만 지원 (Authorization)

RS256/ES256 같은 비대칭 서명 미지원 — 외부 IdP(Auth0, Cognito 등) 연동 시 Pages Function 에서 JWT 를 자체 발급으로 재포장 필요.

---

## 5. `plugin-ai` — 브라우저 직접 API 호출의 위험

v5.3 에서 `plugin-ai` 는 CLI 빌트인에서 **제거**되었습니다.

### 왜 제거되었나

브라우저에서 Anthropic API 를 직접 호출하면:
1. `x-api-key` 헤더가 **네트워크 탭에서 평문 관찰 가능** (설계적 필연)
2. XSS 시 키 탈취 가능
3. 공개 SaaS 에서 사용 시 키가 사실상 공개됨

### 남은 파일

`examples/plugins/plugin-ai.js` 로 이동됨. 다음 방법 중 하나로만 사용 가능:

**방법 1 — 권장: 서버 프록시**

```
브라우저 (dokkebi WASM)
    │
    ▼
Pages Function /api/ai/complete   ← ANTHROPIC_API_KEY 는 여기에만
    │   (인증 / 요금 / 프롬프트 정책)
    ▼
Anthropic API
```

**방법 2 — 개인/내부 용도에 한함: 프로젝트 로컬 복사**

```bash
cp examples/plugins/plugin-ai.js <내프로젝트>/plugins/plugin-ai.js
```

`dokkebi.config.js` 에 명시 + 프로덕션 배포 시 `acknowledgeKeyExposure: true` 추가 필요:

```js
plugins: {
  ai: {
    enabled: true,
    acknowledgeKeyExposure: true,  // 키 노출 위험 인지 명시
  },
},
```

`NODE_ENV=production` + 플래그 없음 → **빌드 실패**.

---

## 6. 인가 경계 (Authorization Boundary)

### 6.1 문제

```js
// 브라우저 WASM 안에서:
if (user.role === 'admin') {
  await db.delete(users, { id: targetId });
}
```

공격자는 WASM 번들을 수정해 `role === 'admin'` 체크를 제거할 수 있습니다. **브라우저에서 내린 인가 결정은 신뢰할 수 없습니다.** 프록시는 "이 SQL 이 allowlist 에 있는지" 는 검증하지만 "사용자가 정말 admin 인지" 는 모릅니다.

### 6.2 해결 — v5.3 Authorization Policy

위 §3.2 의 Authorization Policy 가 이 문제를 직접 해결합니다:

- JWT 서명 + role 매칭을 **프록시가** 검증
- WASM 번들을 조작해도 유효한 role 이 담긴 JWT 없이는 규칙이 요구하는 연산 수행 불가
- JWT 는 사용자의 로그인 시점에 **서버** 가 자체 발급 (DB 의 실제 role 값으로)

즉:
- **Authorization 을 활성화하지 않으면**: § 6.1 문제 그대로 노출 — "누구나 admin" 가능
- **Authorization 을 활성화하면**: JWT 발급 서버의 보안이 전체 보안의 근간이 됨

### 6.3 Tenant Policy + Authorization 조합 패턴

| 요구사항 | Tenant Policy | Authorization |
|---|---|---|
| 본인 글만 수정 | ✅ `UPDATE posts WHERE user_id = ?` 주입 | `UPDATE:posts` → `{ auth: true }` |
| 관리자는 아무나 삭제 | (관리자 바이패스) | `DELETE:posts` → `{ roles: ['admin'] }` |
| 공개 피드 조회 | (off) | `SELECT:posts` → `{ public: true }` |
| 가입 (인증 없이) | (off — user_id 생성 불가) | `INSERT:users` → `{ public: true }` + 별도 rate limit |

**권장**: 다중 사용자 앱은 두 레이어 모두 활성화.

### 6.4 Authorization 을 쓰지 않을 때의 대안

| 옵션 | 설명 |
|---|---|
| **DB-레벨 RLS** (Supabase/Postgres) | Supabase JWT 를 프록시 경유로 passthrough. DB 가 `auth.uid()` 기반 제한 |
| **별도 인가 엣지 함수** | `/api/authorized-query` 가 JWT + 비즈 권한 검증 후 dok 프록시로 중계 |
| **읽기 전용 배포** | 쓰기 연산 자체를 Allowlist 에서 제외 |

---

## 6.5 무중단 배포 (Zero-Downtime Deploy)

`dok build` 마다 다음 두 값이 회전합니다:

- `__DOKKEBI_BC_KEY__` — 암호화 번들(`backend.bundle.enc`) 의 AES-256-GCM 키
- `bundleHash` — `index.html` 에 박히는 SHA-256 해시 (16 바이트 trim)

이 회전이 정적 자산 배포(엣지 캐시) ↔ Worker Secret 등록(전 엣지 전파) 와 비동기적으로 일어나기 때문에, 다음 두 시나리오에서 핸드셰이크 실패가 발생할 수 있습니다:

1. **시나리오 A** — 사용자가 옛 HTML 을 들고 새로고침했는데 정적은 새 번들로 갱신, Worker Secret 은 아직 전파 중. → 옛 키로 새 번들을 복호화 시도 → `OperationError`.
2. **시나리오 B** — 새 HTML 을 받았는데 엣지 일부에서 옛 번들을 응답. → 새 키로 옛 번들 복호화 시도 → 동일 실패.

dokkebi 는 다음 3중 방어로 이 race 를 제거합니다 (모두 자동, 사용자 설정 불필요):

### ① 해시 박힌 immutable 번들 파일명
- `backend.bundle.enc` 와 함께 `backend.bundle.<hash12>.enc` 도 같이 출력합니다.
- HTML 부트스트랩은 해시 박힌 파일명을 우선 fetch (실패 시 비-해시명 폴백).
- Cloudflare `_headers` 에 `/dokkebi/backend.bundle.*.enc → public, immutable, max-age=1y` 적용.
- **효과**: 옛 HTML 은 옛 번들을, 새 HTML 은 새 번들을 영구히 정확하게 받음. 시나리오 B 차단.

### ② `__DOKKEBI_BC_KEY_MAP__` (최근 N개 빌드 키 보존)
- 빌드 타임에 `.dokkebi/env-secrets.json` 에 `__DOKKEBI_BC_KEY_MAP__: { "<hash12>": "<keyHex>", ... }` JSON 을 누적.
- 최신 5개 빌드만 유지 (FIFO GC).
- `dok deploy` 가 이 JSON 을 단일 Worker Secret 으로 등록.
- 핸드셰이크 클라이언트는 POST body 에 `bh: <bundleHash 12자>` 를 동봉.
- 핸드셰이크 워커는 `pickClientHandshakeSecrets(env, requestedBh)` 로 매칭 키를 응답.
- **효과**: 옛 HTML 사용자에게는 옛 키로, 새 HTML 사용자에게는 새 키로 응답. 시나리오 A 차단.

### ③ 배포 순서 + 전파 슬립
- `dok deploy` 는 `Worker Secret 등록 → DOKKEBI_SECRET_PROPAGATION_MS (기본 15000ms) 슬립 → 정적 자산 푸시` 순서로 실행.
- 환경변수 `DOKKEBI_SECRET_PROPAGATION_MS` 로 슬립 시간 조정 가능 (예: `DOKKEBI_SECRET_PROPAGATION_MS=30000 dok deploy`).
- **효과**: 정적 자산이 엣지에 보이는 순간 Worker 도 이미 새 키를 들고 있도록 하는 안전 마진. CF Pages secret 전파는 실측 4~30초 분포라 기본값을 15초로 보수적으로 설정.

### ④ prop_pending — 조용한 전파 대기 응답
- 핸드셰이크 워커는 클라이언트가 보낸 `bh` 가 `__DOKKEBI_BC_KEY_MAP__` 에 매핑돼 있지 않으면 먼저 `__DOKKEBI_BC_HASH__` 로 direct 키가 현재 번들용인지 확인합니다.
- direct 키도 현재 번들용이 아니면 **잘못된 키로 폴백하지 않고** `200 + { pending: true, code: "prop_pending", retryAfterMs: 5000 }` 로 응답합니다. HTTP 503 을 사용하지 않아 브라우저 콘솔의 빨간 네트워크 에러가 노출되지 않습니다.
- 클라이언트는 이 응답을 내부 상태로만 처리하고, 최대 약 5분 동안 백오프 재시도합니다. 일반 사용자는 로딩 상태만 보며, 업데이트가 반영되면 자동으로 이어서 실행됩니다.
- **효과**: 핸드셰이크 단계에서부터 잘못된 키 전달을 차단하되, 사용자에게는 장애처럼 보이지 않게 흡수합니다.

### 보안 영향
- 위 4 메커니즘 모두 **암호학적 보안에 영향 없음** — 번들은 여전히 AES-256-GCM 으로 암호화돼 있고, 키는 ECDH 채널을 통해서만 전달됩니다.
- 옛 키를 GC 하기 전까지는 옛 번들이 디코딩 가능하지만, 옛 번들 자체에 보안 패치 미적용 코드가 있다고 가정하면 **N+1 회 deploy 후 자동으로 만료** 됩니다 (긴급 패치 시 deploy 한 번 더 하면 됨).
- 노출되는 정보: `bundleHash` 앞 12자 (이미 `?v=` 쿼리/attestation 매니페스트로 공개 정보).

### 운영 노트
- 무중단 배포가 작동하려면 **dokkebi-cli 본체** 가 v6.x+ 이고, 한 번은 `dok deploy` 로 `__DOKKEBI_BC_KEY_MAP__` 가 등록되어야 합니다.
- 첫 deploy 직후에는 map 에 키가 1개뿐이라 옛 HTML 캐시가 있다면 한 번 reload 가 필요할 수 있습니다 (이후 deploy 부터 무중단).
- 클라이언트 reload 가드는 60초 만료식이라, 60초 이상 전파 지연이 계속되면 자동으로 한 번 더 새로고침 시도합니다.

---

## 7. 프로덕션 배포 체크리스트

**🔴 반드시**
- [ ] HTTPS 강제 (Cloudflare Pages 자동)
- [ ] **인가 레이어 하나는 반드시** — Authorization Policy 활성 or DB RLS or 별도 엣지 함수 중 택 1
- [ ] XSS 방어 레이어 (CSP, Trusted Types)
- [ ] CORS `Access-Control-Allow-Origin` 를 실제 프론트 오리진으로 제한
- [ ] Cloudflare WAF / Bot Management 앞단 배치
- [ ] `DOKKEBI_SERVER_JWK`, `DOKKEBI_SESSION_SECRET` Pages secret 등록
- [ ] Authorization 활성 시 `DOKKEBI_JWT_SECRET` 등록 (32+ bytes 랜덤)

**🟡 강력 권장**
- [ ] `queryRegistry.strict: true` (학습 완료 후)
- [ ] 다중 사용자 앱이면 `policy.mode: 'inject'` + `ctx.setSessionTenant()`
- [ ] `plugin-ai` 는 서버 프록시로 교체 (직접 사용 금지)
- [ ] `.dokkebi-secrets.json`, `.dev.vars`, `.dokkebi/env-secrets.json` gitignore 확인
- [ ] 관리자 PW 20자+ 고엔트로피
- [ ] `_dokkebi_security` 이벤트를 외부 모니터링 (Logpush, Datadog 등) 으로 forward

**🟢 참고**
- [ ] `sql-allowlist.json` 이 `dist/dokkebi/` 에 포함됐는지 확인
- [ ] Query Registry 가 비어있지 않은지 (빌드 로그로 확인)
- [ ] Tenant Policy 활성 시 `_dokkebi_sessions.tenant_json` 컬럼 마이그레이션 완료

---

## 8. 한 줄 요약

**"SQL 공격 차단 프레임워크로는 우수하지만, 인가(authorization) 는 반드시 Authorization Policy 또는 외부 레이어(RLS/JWT)로 따로 해결해야 한다."**

---

## 8.5 보안 옵션 통합 검증 표 (build + deploy 후 동작)

> **검증 범위**: `dok dev` 제외. **배포된 워커**(Cloudflare Pages Function, `worker/api/_dokkebi/*.ts`) 기준.
> **검증 방법**: `src/core/projectGenerator.js` 의 `workerHandshake()`, `workerDb()`, `workerRootMiddleware()`, `workerAdmin()`, `workerAdminApi()` 가 빌드 시 임베드하는 **실제 런타임 코드**를 정적 분석.
> 옵트인 항목은 사용자가 옵션을 켜고 시크릿/설정을 채웠다는 전제로 검증.

### 한눈에 요약

- ✅ **27개 정상 동작** (항상 ON 17개 + 옵트인 7개 + 배포 보조 3개)
- ⚠️ **1개 부분 동작 / 미구현**: WebAuthn 서버 검증 (§3.3 명시)
- `prop_pending` 응답은 v6.x 런타임에서 정상 동작 (이 문서 §6.5 ④ 와 일치)

### 분석 표

| # | 명칭 | 구분 (레이어) | 역할 | 동작 (deployed worker 기준) | 차단 요소 (대응 공격) | 동작 상태 |
|---|------|---|---|---|---|---|
| 1 | **ECDH(P-256) + HKDF-SHA256 → AES-256-GCM** | 네트워크/전송 | 양방향 종단 암호화 채널 | 핸드셰이크에서 `crypto.subtle.generateKey({ECDH, P-256})` 으로 ephemeral 키쌍 생성 → `deriveBits` → HKDF로 `dokkebi-enc`/`dokkebi-sig` 두 키 분리 → AES-256-GCM으로 모든 요청·응답 암호화 | 도청, MITM 평문 노출, DevTools 평문 관찰 | ✅ 정상 |
| 2 | **HMAC-SHA256 요청 서명** | 네트워크/전송 | 변조 방지 | 모든 `/api/_dokkebi/db` 요청은 sigKey 로 HMAC 서명 검증 후 처리. `SIGNATURE_INVALID` 응답 코드 정의됨 | 요청 변조, 메시지 무결성 위협 | ✅ 정상 |
| 3 | **Replay 방어 (Nonce + ±5s TS)** | 네트워크/전송 | 재전송 차단 | `workerDb` 가 nonce/timestamp 검증 → 인메모리 + `_dokkebi_nonces` D1 cross-isolate 중복 체크. `REPLAY_DETECTED` / `TIMESTAMP_SKEW` 코드. `replay.timestampWindowMs`(1-30s clamp), `nonceTtlMs`(window+5s ~ 5min clamp) 튜닝 가능 | 캡처 요청 재전송, 빠른 다발 발사 | ✅ 정상 |
| 4 | **Forward Secrecy (Ephemeral ECDH)** | 네트워크/전송 | 세션키 노출 시에도 과거 트래픽 보호 | 매 핸드셰이크마다 새 키쌍, `_dokkebi_ephemeral_keys` 60s TTL 후 삭제 | 장기 세션키 탈취 후 과거 트래픽 복호화 | ✅ 정상 |
| 5 | **세션 관리 (FIFO + 토큰 버킷)** | 네트워크/세션 | DoS 방어 | `_dokkebi_sessions` D1 + per-session `bucketTokens`/`bucketRefillAt`. 세션 폭탄/요청 폭주 방어 | 세션 폭탄, 단일 세션 다발 공격 | ✅ 정상 |
| 6 | **Envelope Body 크기 제한 (512KB)** | 네트워크/DoS | body DoS 방어 | `MAX_ENVELOPE_BYTES = 512*1024` + `Content-Length` 선체크 → 413 | 거대 페이로드 DoS, 메모리 고갈 | ✅ 정상 |
| 7 | **SQL Allowlist (테이블×op)** | 백엔드 로직/DB | 4-레이어 1단계 — 허용된 테이블·op만 통과 | `dist/dokkebi/sql-allowlist.json` 빌드시 추출 → `workerDb` 에 인라인 임베드. SELECT/INSERT/UPDATE/DELETE 단위 + `CREATE TABLE _dokkebi_*` 만 허용 | 임의 테이블 SELECT/UPDATE/DELETE, 시스템 테이블 변조 | ✅ 정상 |
| 8 | **Query Registry (SQL shape)** | 백엔드 로직/DB | 4-레이어 2단계 — SQL 구조 변조 차단 | shape 등록·매칭. `OR 1=1`, WHERE 누락, 컬럼 변경 차단. **기본 `auto`** (등록 안된 건 _debugSql 폴백 = 사실상 비활성), `queryRegistry.strict: true` 시 미등록 차단 | SQL 구조 변조, `OR 1=1`, WHERE 제거 | ✅ 정상 (auto 시 방어 약화 — §4.2 참조) |
| 9 | **공통 SQL 방어** | 백엔드 로직/DB | 4-레이어 0단계 | `hasMultipleStatements` (다중 문장 `;`), `stripStringsAndComments` (주석 `--`/`/* */`), 위험토큰 차단 (`ATTACH`, `DETACH`, `PRAGMA`, `LOAD_EXTENSION`, `INTO OUTFILE`, `INTO DUMPFILE`, `INFORMATION_SCHEMA`, `PG_SLEEP`, `SLEEP(`, `BENCHMARK(`, `WAITFOR`, `XP_`, `SP_EXECUTESQL`) | SQL injection (스택 쿼리, 주석 우회), DB 권한 확장, 시간 기반 blind injection | ✅ 정상 |
| 10 | **MTD — Payload Field Rotation** | 네트워크/MTD (Moving Target Defense) | 봉투 내부 키명을 빌드별로 회전 (정적 시그니처 방어) | `dok build` 가 `buildId` 기반 SHA-256 으로 `queryId/params/_debugSql/_setTenant/_attest/_capabilityUnlock/sql/_jwt` 8개 키를 `_f<hash20>` 으로 매핑(`PAYLOAD_FIELD_ROTATE_CANONICAL`). `wire-runtime.json` + `_payloadWire.ts` 로 워커·클라 동시 임베드. `denormalizePayload()` 가 active+previous(이전 빌드 호환) 두 매핑 모두 인식 → **무중단 배포 호환**. `DOKKEBI_HARDENING_ROTATE=off` 로 비활성 가능 (기본 ON) | 자동화 도구의 정적 키 시그니처 매칭(`queryId=`/`_debugSql=`), 캡처-재구성 봇, 정적 페이로드 스캐너, 빌드 간 페이로드 다이프 분석 | ✅ 정상 |
| 11 | **PoW — 경량 Proof of Work (14-bit SHA-256)** | 네트워크/봇 비용 부과 | 자동화 봇의 단가 상승 + capability·attest 챌린지 보호 | `_capabilityUnlock` 또는 `_attest.request === true` 페이로드에만 요구 (`powPayloadRequired`). 클라가 `<sid>:<minuteSlot>:<counter>` SHA-256 leading zero ≥14bit 채굴 → 워커가 `verifyAndStripPowDb()` 로 검증, `±1 minuteSlot` 윈도우, counter ≤ 20M, slot 만료 거부. 빌드 시 `_payloadWire.ts` 에 임베드. `DOKKEBI_HARDENING_POW=off` 로 비활성 (기본 ON) | 자동화 봇의 capability 무차별 발급 시도, 무료 attestation 챌린지 폭주, 토큰 발급 단가 0 공격, 기본 채널 위 추가 비용 부과 안된 봇 | ✅ 정상 |
| 12 | **Tenant Policy (Row-level)** | 백엔드 로직/DB | 4-레이어 3단계 (opt-in) — 멀티테넌트 격리 | `_pe_inject` / `verifyTenant` / `_pe_hasTopLevelOr` 임베드. `mode: 'verify'` 거절만, `'inject'` 자동 주입. `tenant_json` 컬럼에 세션 테넌트 저장. top-level `OR`, aliased col 검증 | A→B 데이터 SELECT/UPDATE/DELETE, WHERE 누락, OR 1=1 우회 | ✅ 정상 |
| 13 | **Authorization Policy (JWT/role)** | 백엔드 로직/인가 | 4-레이어 4단계 (opt-in) — op-level 권한 | HS256 JWT 서명·exp 검증, `(op, table)` → `roles.some(r => userRoles.includes(r))` 매칭, wildcard `'*'` 지원, `mode: 'warn'`/`'strict'` | 일반 사용자가 admin op (`UPDATE users`, `DELETE *`) 호출, JWT 위조/만료 토큰 재사용 | ✅ 정상 (HS256 한정 — §4.9) |
| 14 | **Capabilities (Signed Unlock Token)** | 백엔드 로직/인가 | (opt-in) 권한 분기점프 / 비용 라우트 보호 | `_cap_sign`/`_cap_verify` HMAC, `DOKKEBI_CAPABILITY_SECRET` 사용, `routes`/`@dokkebi-capability` JSDoc 빌드 시 자동 라우터 guard 삽입 | WASM 패치로 권한 분기 우회, 외부 비용 라우트(OpenAI 등) 직접 호출, 토큰 탈취 후 다른 세션 사용 (sid 검증) | ✅ 정상 |
| 15 | **Capability Chain (`requires.prev`)** | 백엔드 로직/인가 | (opt-in) 비즈 단계 우회 차단 | `prevTokens` HMAC·exp·sid·feature 일치 검증. `CAPABILITY_PREV_MISSING`/`CAPABILITY_PREV_INVALID` 코드 | 1단계 인증·2단계 결제 건너뛰고 3단계 직접 호출, 단계 비틀기 | ✅ 정상 |
| 16 | **Bundle Attestation (chunk SHA-256)** | 백엔드 로직/번들 무결성 | (opt-in, capabilities 켜면 자동) 변조된 번들 차단 | `dok build` 가 `backend-bundle.chunks.json` (16KB chunk SHA-256 매니페스트) 생성 → 워커 코드에 임베드 (클라이언트 비노출). `_attest` challenge → 클라가 메모리 번들 슬라이싱 응답. 실패시 `attest_failed` / `CAPABILITY_ATTEST_REQUIRED`. `requires: { attest: true }` 시 capability 발급 게이트 | 클라이언트 번들 패치(권한 분기 우회·자유 capability 발급) | ✅ 정상 |
| 17 | **Active Defense Layer (ADL)** | 백엔드 로직/봇·자동화 | (opt-in) 위험 점수 기반 차단 | `_adlRisk` 계산 (`ADL_RISK_BLOCK` threshold). `mode: 'monitor'` 로그만 / `'enforce'` 차단. `sampleRate`, `riskBlockThreshold`, `trigger: 'lazy'/'cron'`, Workers AI 옵션 | 자동화 스크래핑, 403/인증 실패 다발, 가격 fuzzing | ✅ 정상 |
| 18 | **Panel IP Guard (CIDR)** | 네트워크/관제 | (opt-in) 관제 패널 외부 IP 차단 | `workerAdmin`/`workerAdminApi` 에 `panelIpAllowed` + CIDR 매칭. `CF-Connecting-IP` 우선 → `X-Forwarded-For` fallback. 차단 시 403 + `panel_ip_block` 이벤트 (`_dokkebi_security`) | 패널 비밀번호 무차별 대입, 외부 IP 관제 API 호출, 로그/이벤트 무단 조회·삭제 | ✅ 정상 |
| 19 | **관리자 패널 보안 (PW + 락 + 토큰)** | 백엔드 로직/관제 | 항상 ON | `timingSafeEqual` 상수-시간 PW 비교, 5회 실패 → 5분 락, HMAC 서명 + 만료 토큰, 2KB body 상한, 600/min 로그 한도 | 패널 PW 브루트포스, 타이밍 공격, 토큰 위조, 관제 DoS | ✅ 정상 |
| 20 | **Strict CSP (hash-pinned)** | 네트워크/XSS 심층방어 | (opt-in) | `deploy.js _writeSecurityHeaders` → `dist/_headers`. 인라인 `<script>/<style>` 콘텐츠를 SHA-256 해싱해 `script-src 'self' 'sha256-…'` 자동 부여, `unsafe-inline` 제거. CSP 전 directive 명시 | XSS 후속 외부 스크립트 주입, eval, 데이터 유출 (자료/키 탈취) | ✅ 정상 |
| 21 | **OPFS 환경시크릿 (Opaque Handle)** | 백엔드 로직/시크릿 | 항상 ON | 빌드 타임 AES-GCM 으로 env-secret 감싸 OPFS 저장. host 클로저에만 복호화. `.dokkebi/env-secrets.json` 정적 서빙 차단 | 브라우저 콘솔/DevTools 환경변수 노출, 클라이언트 코드 dump | ✅ 정상 (XSS 시 같은 origin 재현 가능 — §4.3) |
| 22 | **번들 무결성 SHA-256** | 빌드/번들 | 항상 ON | `dok build` 가 `backend.bundle.enc` SHA-256 → `backend.bundle.<hash12>.enc` immutable 파일명 + 런타임 `crypto.subtle.digest` 검증 | 번들 교체/변조, MITM 번들 swap | ✅ 정상 |
| 23 | **무중단 배포 — BC_KEY_MAP** | 빌드/배포 | 항상 ON (v6.x+) | `__DOKKEBI_BC_KEY_MAP__` (최근 5개 빌드 키 FIFO) Worker Secret 등록. 클라가 `bh=<hash12>` 동봉 → `pickClientHandshakeSecrets()` 가 매칭 키로 응답 | 캐시·전파 race로 인한 핸드셰이크 실패 (시나리오 A·B) | ✅ 정상 |
| 24 | **무중단 배포 — `prop_pending` 흡수** | 빌드/배포 | 항상 ON | `_pickBcKeyForBundle()` 가 `bh` 미매칭 + direct 키도 현재 번들용 아님 시 `status: 'pending'` 반환. 핸드셰이크 핸들러는 잘못된 키로 폴백하지 않고 `200 + { pending: true, code: 'prop_pending', retryAfterMs: 5000 }` 응답 → 클라 SDK 자동 백오프 재시도 | 새 deploy 직후 ~수십초의 Worker Secret 전파 지연 시 사용자에게 빨간 콘솔 에러로 노출되는 문제, 잘못된 키로 복호화 실패 후 무한 재시도 | ✅ 정상 |
| 25 | **무중단 배포 — 전파 슬립** | 빌드/배포 | 항상 ON | `dok deploy` 순서: Secret 등록 → `DOKKEBI_SECRET_PROPAGATION_MS` (기본 15s) sleep → 정적자산 push | 새 정적 자산 ↔ 옛 Worker Secret race | ✅ 정상 |
| 26 | **CORS 정책 검증** | 네트워크 | 항상 ON (preflight 경고) | `dok deploy` preflight 가 `security.cors.allowedOrigins` 미설정/`*` 포함 시 경고. 운영자가 실제 프론트 오리진으로 좁혀야 함 (§4.7) | (좁히지 않으면 다른 출처에서 호출 가능) | ✅ 동작 (경고 + 운영자 조치 필요) |
| 27 | **plugin-fetch 도메인 화이트리스트** | 백엔드 로직/외부 호출 | 항상 ON | http/https 강제, TLD 단독 거부, 프로젝트별 화이트리스트 | SSRF, 임의 외부 fetch | ✅ 정상 |
| 28 | **plugin-ai 빌드 차단** | 빌드 | 항상 ON | `NODE_ENV=production` + `acknowledgeKeyExposure` 미명시 → 빌드 실패 (`pluginLoader.js`) | API 키 브라우저 노출 (구조적 위험) | ✅ 정상 |
| 29 | **Build-time Advisor** | 빌드/사람 실수 | (opt-out) | OpenAI/Stripe/LemonSqueezy URL, `points.deduct(`, `wallet.charge(`, secret env 직접 사용 라우트 스캔 → capability 미선언 시 경고 | capability 선언 누락 인적 실수 (간접 방어) | ✅ 정상 |
| 30 | **Bytecode Mode (QuickJS)** | 백엔드 로직/지적재산 보호 | (opt-in) | `dok build --bytecode` 시 백엔드 번들을 QuickJS bytecode 로 사전 컴파일 → 클라 메모리에는 JS 소스가 아닌 bytecode 만 존재 (`_bcMode`). `bytecodeEncrypted: true` 시 추가 AES-GCM 래핑 | WASM 메모리 dump 후 JS 소스 직접 리버싱, 비즈 로직 그대로 추출 (§4.6 의 한계를 부분 보완 — 완전 DRM 은 아님) | ✅ 정상 |
| 31 | **Encrypted Text Mode** | 백엔드 로직/지적재산 보호 | (opt-in) | `encryptedTextMode: true` (`_etMode`) — 번들 텍스트 자체 추가 AES-GCM 래핑. `_cacheFile = 'backend.bundle.enc'` 로 OPFS 캐시도 암호화 유지 | 디스크/캐시 dump 후 평문 번들 추출 | ✅ 정상 |
| 32 | **Pre-gate (per-session token bucket)** | 네트워크/DoS | 항상 ON | `workerDb` 의 envelope 검증·복호화 **이전** 단계에서 `bucketTokens`/`bucketRefillAt` 으로 세션당 처리율 제한. CPU 비용 큰 AES-GCM/ECDH 도달 전에 차단 | 한 세션이 ECDH/AES-GCM 비용으로 워커 자원 고갈, 정상 모양 다발 요청 (Phase 2-⑤) | ✅ 정상 |
| 33 | **Monotonic Request Counter** | 네트워크/세션 | 항상 ON | 세션 내 요청 순서 카운터 검증 (Phase 1-①). 클라가 보낸 seq 가 단조 증가하지 않으면 거부. `opaqueHandle` 에서 클라 측 카운터 발급 | 캡처 요청 재구성 / 순서 비틀기 / nonce 재사용은 통과해도 순서 역전 공격 차단 | ✅ 정상 |
| 34 | **Bundle Boot KEK (HKDF + AES-GCM 래핑)** | 빌드/번들 부트 | 항상 ON | `bundleBoot.js` — `DOKKEBI_BUNDLE_BOOT_SECRET` 로 nonce HMAC → HKDF-SHA256(salt=nonce, info=`dokkebi-bc-wrap-v1\|<h12>`) → AES-256 KEK → BC_KEY 32바이트 AES-GCM 래핑해 HTML 의 `__DOKKEBI_BOOT__` 에 inline. 워커 미들웨어가 Web Crypto 로 동일 알고리즘 재현해 언래핑 | HTML 정적 캡처에서 BC_KEY 평문 노출, h12 binding 으로 다른 빌드의 부트 페이로드 재사용 차단 | ✅ 정상 |
| 35 | **Console Call Stripping** | 빌드/정보 노출 | 항상 ON | `replaceConsoleCallsWithVoid()` — 프로덕션 번들에서 지정 `console.METHOD(...)` 호출을 `void 0` 치환. 문자열/주석/정규식 리터럴 안의 괄호는 무시. `buildWasm.js` 가 자동 적용 | 프로덕션 콘솔에 흘러나가는 디버그 정보·내부 상태·SQL/시크릿 누출 | ✅ 정상 |
| 36 | **Build Artifact Purge** | 빌드/정보 노출 | 항상 ON | `purgeBuildArtifactsFromDist()` — `dist/dokkebi/` 의 민감 JSON 8종 (`env-secrets.json`, `secrets.json`, `query-registry.json`, `sql-allowlist.json`, `wire-runtime.json`, `backend-bundle.chunks.json`, `backend-bundle.sha256`, legacy `env-secrets.js`) 을 `{}` 로 덮어쓰기. 메타는 모두 워커에 인라인 임베드되어 클라가 fetch 안 함. Cloudflare Pages `_redirects` 의 force(`!`) 가 404 미지원 → 비우기가 유일 신뢰 방법 | 정적 자산 fallback 으로 외부 노출 (SQL allowlist·query shape·attestation 매니페스트·env secret) — 허용 테이블·컬럼·번들 내부 구조 정찰 차단 | ✅ 정상 |
| 37 | **JWT 추가 검증 (alg whitelist + iss/aud/nbf + clockSkew)** | 백엔드 로직/인가 | 항상 ON (Authorization 활성 시) | `authorizationPolicy.js` — `header.typ === 'JWT' && header.alg === 'HS256'` 화이트리스트, `exp` + 30s clockSkew, `nbf` 검사, `iss`/`aud` 옵션 매칭. None alg / alg confusion 차단 | JWT alg=`none` 우회, RS256→HS256 키 혼동 공격, 만료/이른 토큰 사용, 다른 발급자 토큰 재사용 | ✅ 정상 |
| 38 | **Plaintext Zeroize (best-effort)** | 백엔드 로직/메모리 | 항상 ON | `opaqueHandle` 에서 `_secPlain.fill(0)`, `_bcKeyBytes.fill(0)`, `_bytecodeData.fill(0)`, `sharedBits.fill(0)` 등 복호화·서명·KEK 사용 직후 평문 버퍼 즉시 0 채움 | 메모리 dump / heap 스냅샷에서 만료된 평문 키·바이트코드·세션 비밀 잔존 | ✅ 정상 (best-effort — JS GC 가 사본 복제하면 한계) |
| 39 | **추가 보안 헤더** (`_headers`) | 네트워크/브라우저 정책 | 항상 ON (deploy 시) | `dist/_headers` 에 `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera/microphone/display-capture=(self), geolocation/payment=()`, `index.html/sw.js: no-cache,no-store`, `/dokkebi/*.json: X-Robots-Tag: noindex` | MIME sniffing, 레거시 reflected XSS, clickjacking, referrer 누출, 무권한 권한 요청, SW 캐시 stale, 검색엔진 민감 JSON 인덱싱 | ✅ 정상 |
| 40 | **WebAuthn (Passkey) 요청 서명** | 네트워크/민감행위 인가 | (opt-in) — **런타임 미구현** | 설정 정의(`security.webauthn`) 와 클라 SDK 진입점은 존재하나, **워커 측 assertion 검증 / `requireForOps` 게이트 미구현** (`docs/design/WEBAUTHN.md`: "런타임 SDK 구현은 후속 PR"). `enabled: true` 로 켜도 서버 측 강제 없음 | (구현 시) 비밀번호/세션 탈취 후 결제·관리자 export 등 민감 행위. **현재는 Authorization Policy + Capabilities 로 대체 권장** | ⚠️ 미구현 (§3.3 명시) |

### 무중단 배포 시나리오 ④ 구현 노트 (v6.x 검증)

`worker/api/_dokkebi/handshake.ts` 의 `_pickBcKeyForBundle()` 는 다음 4 분기를 반환합니다.

| status | 조건 | 핸들러 동작 |
|---|---|---|
| `matched` (with key) | `bh` 가 `__DOKKEBI_BC_KEY_MAP__` 또는 direct 키 해시와 일치 | 정상 핸드셰이크 + BC 키 응답 |
| `fallback` (with key) | `bh` 미제공(구버전 클라) + direct 키 존재 | direct 키로 응답 |
| `pending` (no key) | `bh` 매칭 실패 + direct 키도 현재 번들용 아님 / 키 자체가 미등록 | **`200 + { pending: true, code: 'prop_pending', retryAfterMs: 5000 }`** — 잘못된 키로 폴백하지 않음. 클라 SDK 가 백오프 재시도. |

이 분기는 § 6.5 ④ 의 동작과 일치하며, 새 deploy 직후 Worker Secret 전파 지연 동안 사용자에게 빨간 콘솔 에러가 노출되지 않게 흡수합니다.

---

## 9. 보고

보안 이슈는 공개 GitHub 이슈가 아닌 개별 채널(README 의 연락처)로 알려주세요.

---

## 관련 문서

- [docs/design/TENANT_POLICY.md](docs/design/TENANT_POLICY.md) — Row-level 격리
- [docs/design/AUTHORIZATION.md](docs/design/AUTHORIZATION.md) — 연산-레벨 인가
- [docs/design/QUERY_REGISTRY.md](docs/design/QUERY_REGISTRY.md) — SQL shape 통제
