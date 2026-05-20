# Dokkebi 보안 옵션 가이드 — "이 옵션은 어떤 공격을 막나"

이 문서는 `dokkebi.config.js` 의 `security` 섹션에서 **사용자가 직접 켜고 끄는 옵션**들을 다룹니다. 각 옵션마다 다음 네 가지를 함께 적었습니다.

1. **막는 공격(Attack Case)** — 그 옵션이 *없을 때* 가능한 시나리오.
2. **그 옵션이 정확히 무엇을 하는가** — 동작 원리 한 줄 요약.
3. **적용 방법** — `dokkebi.config.js` / `.env` 예시.
4. **운영 메모** — 트레이드오프, 흔한 실수, 디폴트 권장값.

> 항상 ON 인 기본 보안(ECDH/AES-GCM/HMAC/세션, Replay 방어, Active Defense Layer 일부, Bundle 무결성 검증)은 사용자가 끌 수 없으므로 이 문서에는 포함하지 않았습니다. 자세한 아키텍처는 `SECURITY.md` 를 참고하세요.

---

## 빠른 권장 디폴트

처음 프로젝트를 만들 때는 다음만 켜도 80% 이상의 위협이 차단됩니다.

```js
// dokkebi.config.js
export default {
  security: {
    capabilities: {
      enabled: true,
      // 외부 비용 호출 / 결제 / 관리자 행위 라우트만 선언
      features: {
        'image.generate': { roles: ['premium','admin'], routes: ['POST /api/ai/image'] },
        'admin.export':   { roles: ['admin'],           routes: ['POST /api/admin/export'] },
      },
    },
    // attestation 은 capabilities 가 켜지면 자동 ON (명시 false 로 끌 수 있음)

    panelIpGuard: true, // 관제 패널을 운영에 노출한다면 ON 권장
  },

  // 멀티 테넌트 SaaS 라면 다음을 같이 사용:
  // policy: { enabled: true, mode: 'inject', tables: { ... } },
  // authorization: { enabled: true, mode: 'strict', rules: [...] },
};
```

`.env` (또는 Cloudflare Pages Secret):

```env
DOKKEBI_CAPABILITY_SECRET=<32자 이상 랜덤 문자열>
DOKKEBI_PANEL_ALLOWED_IPS=203.0.113.10,198.51.100.0/24
DOKKEBI_ADMIN_PASSWORD=<긴 비밀번호>
DOKKEBI_JWT_SECRET=<32자 이상>           # authorization 사용 시
```

---

## 1. `security.capabilities` — Signed Unlock Token

### 막는 공격
- **A1.** 사용자가 자기 브라우저의 백엔드 코드에서 `if (user.role === 'admin')` 같은 **권한 분기를 점프**해 결제/유료/관리자 기능을 강제 실행.
- **A2.** 외부 비용 라우트(예: OpenAI 이미지 생성)를 **포인트 차감 *전*에** 직접 호출해 무료로 이용.
- **A3.** 다른 사용자의 토큰을 훔쳐 자기 세션에 그대로 사용.

### 무엇을 하는가
보호하려는 행위를 "feature" 로 선언하고, Worker 가 그 feature 별로 **HMAC 서명된 짧은 수명 토큰**을 발급합니다. 핸들러는 분기문이 아니라 *토큰을 재료로* 동작하도록 작성합니다.

### 적용 방법
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

또는 컨트롤러 위 JSDoc:
```ts
/**
 * @dokkebi-capability feature:image.generate route:"POST /api/ai/image" roles:['premium','admin'] ttl:10000
 */
router.post('/api/ai/image', async (ctx) => {
  // ctx.capability.token / proof 사용
});
```

### 운영 메모
- `routes` 또는 `@dokkebi-capability` 가 있으면 **빌드가 라우터에 guard 를 자동 삽입**합니다. 사용자는 핸들러에 `unlock()` 을 직접 적지 않아도 됩니다.
- **`if (cap.ok) doExpensive()` 처럼 단순 플래그로 쓰면 의미가 줄어듭니다.** `ctx.capability.token/proof` 또는 `stateHash` 를 외부 호출 입력/서명 재료로 묶으세요.
- `DOKKEBI_CAPABILITY_SECRET` 은 32자 이상 랜덤 값, **Worker-only 시크릿**으로 보관 (브라우저로 절대 내려가지 않음).
- 빌드 중 비용 라우트가 capability 미선언이면 `dok build` 가 경고합니다 (§7 참고).

자세한 동작은 `SECURITY.md` §3.5.

---

## 2. `security.capabilities.features[*].requires.prev` — Capability Chain

### 막는 공격
- **A4.** 비즈니스 흐름이 "1단계 인증 → 2단계 결제 → 3단계 실행" 인데, 1·2 를 건너뛰고 3 만 직접 호출.
- **A5.** 정책상 합법인 SQL 만 쏘면서 **순서를 비틀어** 실제로는 무료로 단계 우회.

### 무엇을 하는가
한 capability 가 발급되기 전에, 같은 세션에서 발급된 **다른 capability 의 유효 토큰**을 함께 제출해야 합니다. Worker 가 각 토큰의 HMAC 서명/만료/`sid`/feature 일치를 모두 검증합니다.

### 적용 방법
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

호출:
```ts
// 자동: 도깨비가 캐시/재귀 unlock 으로 prev 토큰을 알아서 채웁니다.
const r = await capability.unlock('image.generate');

// 수동(필요할 때만):
const a = await capability.unlock('auth.verified');
const r = await capability.unlock('image.generate', {
  prev: [{ feature: 'auth.verified', token: a.capability.token }],
});
```

### 운영 메모
- **자동화**: 이번 버전부터 클라이언트가 prev 토큰을 메모리에 캐시하고, 빠진 prev 가 있으면 자동으로 먼저 unlock 합니다. 사용자 코드 변경 없음.
- **사이클 금지**: `A → B → A` 같은 순환은 빌드 시 무시되고 워커가 PREV_MISSING 으로 거절합니다.
- **state 묶이는 호출은 캐시 안 함**: `unlock(feature, { state, ... })` 처럼 입력 binding 이 있는 호출은 매번 새 토큰을 받습니다(의도된 동작).

---

## 3. `security.attestation` — Bundle Attestation

### 막는 공격
- **A6.** 사용자가 자기 브라우저에서 **번들을 패치**(권한 분기를 모두 통과되게 변조) 해 정상 SQL 만 쏘는 우회.
- **A7.** 변조된 번들을 들고 capability 토큰을 발급받아 외부 비용 호출.

### 무엇을 하는가
빌드 시 암호화 번들을 16KB chunk 로 나눠 SHA-256 매니페스트(`backend-bundle.chunks.json`)를 만듭니다. 매 세션에서 Worker 가 무작위 chunk 인덱스를 challenge 로 보내고, 클라이언트는 메모리에 보관 중인 번들 바이트로 응답합니다. 한 chunk 라도 매니페스트와 어긋나면 `attest_failed`.

### 적용 방법
```js
security: {
  attestation: {
    // 명시 안 하면 capabilities.enabled === true 일 때 자동 ON
    enabled: true,
    sampleSize: 4,         // 1–16, 기본 4
    ttlMs: 5 * 60_000,     // 30s–30min, 기본 5분
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

명시적으로 끄려면:
```js
security: { attestation: { enabled: false } }
```

### 운영 메모
- **자동 ON**: capabilities 를 켜면 attestation 도 자동 ON. 사용자가 `enabled: false` 로 명시할 때만 off.
- 매니페스트 자체는 **빌드마다 항상** 만들어집니다 (켜는 순간 재빌드 없이도 동작 가능).
- 자동 재시도: feature 에 `requires.attest: true` 가 걸리고 첫 호출이 `CAPABILITY_ATTEST_REQUIRED` 면, 클라가 자동으로 attest 후 한 번 재시도합니다 (사용자 코드 변경 없음).
- 매니페스트는 워커 코드에만 임베드되고 **클라이언트로는 노출되지 않습니다.**

자세한 동작은 `SECURITY.md` §3.6.

---

## 4. `security.panelIpGuard` + `DOKKEBI_PANEL_ALLOWED_IPS` — 관제 어드민 IP 제한

### 막는 공격
- **A8.** 관제 패널 (`/_dokkebi/_panel`) 의 비밀번호를 무작위 대입하거나, 유출된 비밀번호로 임의 IP에서 로그인 시도.
- **A9.** 관제 API를 직접 호출해 로그/이벤트/요청 내역을 조회하거나 삭제.

### 무엇을 하는가
`DOKKEBI_PANEL_ALLOWED_IPS` 에 등록된 IP / IPv4 CIDR 만 패널에 접근하게 합니다. 차단된 시도는 `panel_ip_block` 이벤트로 로깅됩니다.

### 적용 방법
```js
security: { panelIpGuard: true }
```
```env
DOKKEBI_ADMIN_PASSWORD=<긴 비밀번호>
DOKKEBI_PANEL_ALLOWED_IPS=203.0.113.10,198.51.100.0/24
```

### 운영 메모
- **기본값은 `false`**. 운영 배포 전에 켜는 걸 권장.
- 켜져 있는데 `DOKKEBI_PANEL_ALLOWED_IPS` 가 비어 있으면 `dok build` 가 경고를 띄웁니다.
- 호환: 예전 이름 `DOKKEBI_ADMIN_ALLOWED_IPS` 도 인식.
- `dok update` 가 기존 프로젝트의 `dokkebi.config.js` 에 `panelIpGuard: false` 기본값과 `.env.example` 항목을 보강합니다.

자세한 동작은 `SECURITY.md` §3.4.

---

## 5. `security.replay` — Replay 방어 튜닝

### 막는 공격
- **A10.** 캡처한 정상 요청을 그대로 다시 쏘는 **Replay 공격**.
- **A11.** 동일 요청을 빠르게 다발 발사하는 자동화 공격.

### 무엇을 하는가
모든 `/api/_dokkebi/db` 요청에 **항상 ON** 으로 `nonce` (1회성) + `timestamp` skew window 검사가 적용됩니다. **끌 수는 없고 값만 조정** 합니다.

### 적용 방법
```js
security: {
  replay: {
    timestampWindowMs: 5_000,   // 1s ~ 30s 사이로 자동 clamp
    nonceTtlMs: 35_000,         // window + 5s ~ 5min 사이로 clamp
  },
}
```

### 운영 메모
- 모바일/위성망 등 시계 오차가 큰 환경에서는 `timestampWindowMs` 를 8~15초로 늘리세요.
- 클라이언트가 자동으로 시계 오차를 학습/보정하므로 평소엔 5초로 충분합니다.

---

## 6. `security.activeDefense` — Active Defense Layer (ADL)

### 막는 공격
- **A12.** 자동화 도구로 단시간에 다량의 정상 모양 요청을 보내는 행위 (브루트포스, 스크래핑, 가격 fuzzing 등).
- **A13.** 한 IP/세션이 위험 행위(403 다발, 인증 실패 다발)를 누적 발생시키는 패턴.

### 무엇을 하는가
`/api/_dokkebi/db` 요청 일부를 샘플링해 **위험 점수**를 계산하고, 임계 이상이면 차단(`enforce`)하거나 로그만 남깁니다(`monitor`). Cron 없이 lazy 모드로도 동작.

### 적용 방법
```js
security: {
  activeDefense: {
    enabled: true,
    mode: 'monitor',            // 'monitor' | 'enforce'
    trigger: 'lazy',            // 'lazy' (기본) | 'cron'
    sampleRate: 0.01,           // 1% 샘플
    intervalMs: 5 * 60_000,
    riskBlockThreshold: 0.85,   // enforce 모드에서 차단 컷오프
    useWorkersAI: false,
  },
}
```

### 운영 메모
- **첫 도입은 `mode: 'monitor'` 로**. 한 주 정도 로그를 보면서 false positive 가 없는지 확인하고 `enforce` 로 승격하세요.
- `enforce` 에서 정상 호출이 차단되면 `riskBlockThreshold` 를 0.9~0.95 로 올리거나 `mode: 'monitor'` 로 임시 회피.

---

## 7. `security.advisor` — 빌드 시 보안 어드바이저

### 막는 공격(간접)
- **A14.** 외부 비용/금전 라우트를 만들고 **capability 선언을 잊어서** 보호 공백이 생기는 인적 실수.

### 무엇을 하는가
`dok build` 가 백엔드 컨트롤러를 가볍게 스캔해 다음 신호가 있는 라우트를 찾아냅니다.
- 외부 결제/AI API 호출 (`api.openai.com`, `api.lemonsqueezy.com`, `api.stripe.com`, ...)
- 민감 secret 직접 사용 (`process.env.OPENAI_API_KEY`, `__dokkebi_env__('OPENAI_API_KEY')` 등)
- 명시적 비용 행위 (`points.deduct(`, `wallet.charge(` 등)

해당 라우트가 `security.capabilities.features` 또는 `@dokkebi-capability` 로 커버되지 않으면 **경고만** 출력합니다 (자동 추가 X).

### 적용 방법
기본 ON. 끄려면:
```js
security: { advisor: { disable: true } }
```

### 운영 메모
- false positive 가 있을 수 있습니다. 라이브러리 코드 안의 문자열만으로 트리거되는 경우가 그 예.
- 권장: 끄지 말고 경고를 보면서 진짜로 보호가 필요한 라우트부터 capability 를 선언.

---

## 8. `policy` — Row-level 격리 (Tenant Policy, 멀티 테넌트 SaaS 필수)

### 막는 공격
- **A15.** 사용자 A 가 의도된 클라이언트 코드를 우회해 사용자 B 의 데이터를 SELECT/UPDATE/DELETE.
- **A16.** SQL 인젝션이나 잘못된 WHERE 누락으로 다른 테넌트 row 가 노출.

### 무엇을 하는가
워커가 모든 SQL 에 대해 **선언된 테넌트 컬럼**(예: `user_id = ?`)이 WHERE 에 묶였는지 검사하고, 없으면 거절(`verify`) 또는 자동 주입(`inject`)합니다.

### 적용 방법
```js
policy: {
  enabled: true,
  mode: 'inject',                  // 'verify' | 'inject'
  claim: 'sub',                    // 세션 tenant_json 또는 JWT 클레임
  strict: true,
  tables: {
    animation_projects: { tenantColumn: 'user_id' },
    user_assets:        { tenantColumn: 'user_id' },
    // 공용 테이블은 등록하지 않으면 정책에서 제외
  },
}
```

> 최상위 `tenantPolicy` 는 `policy` 와 동일하게 병합되는 **별칭**입니다. 새 프로젝트는 `policy` 만 사용하세요.

### 운영 메모
- **반드시 함께 켤 것**: `authorization` (op 단위 인가). 둘은 보완 관계입니다.
- `mode: 'verify'` 는 정책 미준수 SQL 을 거절만 합니다. `inject` 는 자동 주입까지. 새 프로젝트는 `inject` 권장.
- 자세한 설명: `docs/design/TENANT_POLICY.md`.

---

## 9. `authorization` — 연산-레벨 인가 (JWT role)

### 막는 공격
- **A17.** 일반 사용자가 admin 전용 op (`UPDATE users SET role=...`, `DELETE FROM …`) 을 호출.
- **A18.** JWT 자체를 위조하거나 만료된 토큰 재사용.

### 무엇을 하는가
요청에 들어온 JWT 의 서명/만료를 검증하고, 매 SQL의 (op, table) 조합에 대한 role 정책을 검사합니다.

### 적용 방법
```js
authorization: {
  enabled: true,
  mode: 'strict',                       // 'warn' | 'strict'
  claim: 'role',
  rules: [
    { op: 'UPDATE', table: 'users',  roles: ['admin'] },
    { op: 'DELETE', table: '*',      roles: ['admin'] },
    { op: '*',      table: '*',      roles: ['user', 'admin'] }, // wildcard 기본
  ],
}
```
```env
DOKKEBI_JWT_SECRET=<32자 이상>
```

### 운영 메모
- `mode: 'warn'` → 위반 시 로그만. `mode: 'strict'` → 위반 시 거절.
- `rules` 끝에 `{ op:'*', table:'*' }` 와일드카드를 두지 않고 strict 면 미정의 op 는 모두 거절됩니다.

---

## 10. `webauthn` — 민감 행위 추가 인증 (선택)

### 막는 공격
- **A19.** 비밀번호/세션을 탈취당했더라도, **결제/관리자 export 같은 민감 행위 직전에 디바이스 키 (Passkey)** 가 없으면 진행 불가.

### 무엇을 하는가
지정된 op 직전에 WebAuthn passkey 를 1회 요구하고, 그 서명이 동봉된 요청만 통과시킵니다.

### 적용 방법
```js
webauthn: {
  enabled: true,
  rpName: 'Notofly',
  rpId: 'notofly.app',
  userVerification: 'required',
  requireForOps: ['DELETE', 'UPDATE_users'],
}
```

### 운영 메모
- 사용자 등록 흐름에 패스키 등록 단계가 있어야 합니다.
- 매 호출마다 요구하지 말고 *진짜로 민감한 op* 에만 한정.

---

## 11. `strictCsp` — 엄격한 콘텐츠 보안 정책

### 막는 공격
- **A20.** XSS 취약점이 있어도 외부 스크립트 주입/eval 을 통한 추가 공격 (자료 유출, 키 탈취) 차단.

### 무엇을 하는가
배포 시 `script-src 'self' <hash>` 형태의 hash-pinned CSP 헤더를 자동 부여합니다.

### 적용 방법
```js
security: { strictCsp: true }
```

### 운영 메모
- iPad Safari 등 일부 환경의 WebAssembly 인스턴스화에 `unsafe-eval` 이 필요합니다. 도깨비 배포 템플릿이 이미 적절히 설정합니다.
- 외부 광고 SDK 등 third-party 스크립트가 있으면 도메인을 추가해야 합니다.

---

## 옵션과 공격의 매핑 — 한 표로 보기

| 공격 시나리오 | 1 capabilities | 2 prev | 3 attest | 4 panelIp | 5 replay | 6 ADL | 8 tenant | 9 authz | 10 webauthn | 11 CSP |
|---|---|---|---|---|---|---|---|---|---|---|
| A1 권한 분기 점프 | ✅ | | | | | | | (보완) | | |
| A2 비용 라우트 직접 호출 | ✅ | | | | | | | | | |
| A3 토큰 탈취 후 자기 세션 사용 | ✅(sid 검증) | | | | | | | | | |
| A4-A5 단계 우회 | | ✅ | | | | | | | | |
| A6-A7 번들 변조 | | | ✅ | | | | | | | |
| A8-A9 관제 무차별 대입 | | | | ✅ | | (보완) | | | | |
| A10-A11 Replay/다발 | | | | | ✅ | (보완) | | | | |
| A12-A13 자동화 스크래핑 | | | | | | ✅ | | | | |
| A14 인적 실수 (capability 누락) | (advisor §7) | | | | | | | | | |
| A15-A16 다른 테넌트 노출 | | | | | | | ✅ | (보완) | | |
| A17-A18 admin op 우회 / JWT 위조 | | | | | | | (보완) | ✅ | | |
| A19 세션 탈취 후 민감 행위 | | | | | | | | | ✅ | |
| A20 XSS 후속 공격 | | | | | | | | | | ✅ |

✅ = 직접 차단, (보완) = 부분적/간접적 차단.

---

## 자주 묻는 질문

**Q. 모두 다 켜면 뭘 더 적게 신경 써도 되나요?**
A. 1+2+3 (capabilities + chain + attestation) 은 자동화가 되어 사용자 코드 변경이 거의 없습니다. 8+9 (policy + authorization) 는 SQL 정책 선언이 필요하고, 10 (webauthn) 은 사용자 등록 UX가 필요합니다. 11 (strictCsp) 는 거의 자동.

**Q. 모든 라우트에 capability 를 걸어야 하나요?**
A. 아닙니다. **외부 비용/결제/관리자/단계 의존 라우트** 에만 거는 게 맞습니다. 일반 CRUD 는 policy + authorization 으로 충분합니다.

**Q. capability 를 켰는데 호출 시 `CAPABILITY_AUTH_REQUIRED` 가 납니다.**
A. `roles` 가 들어간 feature 인데 요청에 JWT 가 없거나 role 클레임이 비어 있습니다. 클라이언트가 `unlock(feature, { jwt: token })` 으로 JWT 를 함께 보내거나, `Authorization: Bearer` 헤더로 보내야 합니다.

**Q. `attestation` 을 켰는데 deploy 후 `CAPABILITY_ATTEST_REQUIRED` 가 한 번 보입니다.**
A. 정상입니다. 새 세션의 첫 capability 호출에서 자동 attest 한 번을 수행하고 즉시 재시도합니다. 클라이언트 사용자 측에서는 단일 호출처럼 보입니다.

**Q. 정상 호출이 ADL 에 차단됐습니다.**
A. `mode: 'monitor'` 로 내려서 한 주 관찰하고, 패턴이 확인되면 `riskBlockThreshold` 를 0.9~0.95 로 올린 뒤 다시 `enforce` 로 올리세요.

---

## 참고

- 아키텍처/내부 동작: `SECURITY.md`
- 멀티 테넌트 정책: `docs/design/TENANT_POLICY.md`
- 인가 정책: `docs/design/AUTHORIZATION.md`
- AI 에이전트 작성 가이드: `AGENTS.md`
