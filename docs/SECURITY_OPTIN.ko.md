# Dokkebi 보안 옵션 — 옵트인 빠른 참조

`dokkebi.config.js` 에서 사용자가 직접 켜는 옵션만 짧게 정리했습니다. 자세한 동작/한계는 `docs/SECURITY_OPTIONS.md` 와 `SECURITY.md` 를 참고하세요.

**빠른 확인**: 프로젝트 루트에서 `dok security`(TTY)로 항목별 위협·필요 설정을 보며 ON/OFF 편집·저장. `dok security --status` 는 한 번만 출력합니다.

> **항상 ON (사용자 설정 불필요)**: ECDH 핸드셰이크, AES-256-GCM, HMAC, Replay 방어(nonce + timestamp), Bundle 무결성 SHA-256, SQL Allowlist, Query Registry, 빌드 메타 트레이서빌리티.

---

## 한 눈에 보기

| 옵션 | 켜면 막는 공격 | 기본값 |
|---|---|---|
| `capabilities` | 권한 분기 점프, 비용 라우트 직접 호출 | off |
| `capabilities.features[*].requires.prev` | 비즈니스 단계 우회 | (선언 시 적용) |
| `attestation` | 변조된 번들로 우회 | capabilities ON 시 자동 ON |
| `panelIpGuard` | 관제 패널 무차별 대입/외부 노출 | off |
| `replay` (튜닝만) | 캡처 요청 재전송 | always ON, 값만 조정 |
| `activeDefense` | 자동화 스크래핑/다발 공격 | off |
| `advisor` | capability 선언 누락 인적 실수 | on |
| `policy` (Tenant) | 다른 테넌트 데이터 노출 | off (`tenantPolicy` 는 `policy` 별칭) |
| `authorization` | role 무시 SQL, JWT 위조 | off |
| `webauthn` | 세션 탈취 후 민감 행위 | off |
| `strictCsp` | XSS 후속 공격 | off |
| `cspExtraHosts` | 베이스라인 CSP 유지하며 외부 이미지·API·iframe 호스트 화이트리스트 | `{}` |

---

## 1. `capabilities` — Signed Unlock Token

**막는 공격**: 백엔드 `if (user.role === 'admin')` 같은 권한 분기 점프 / 외부 비용(OpenAI, 결제) 라우트 직접 호출.

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
DOKKEBI_CAPABILITY_SECRET=<32자 이상 랜덤>
```

> `routes` 또는 `@dokkebi-capability` JSDoc 만 선언하면 빌드가 라우터에 guard 를 자동 삽입합니다.

---

## 2. `capabilities.features[*].requires.prev` — Capability Chain

**막는 공격**: "1단계 인증 → 2단계 결제 → 3단계 실행" 흐름에서 1·2 를 건너뛰고 3 만 직접 호출.

```js
features: {
  'auth.verified':   { public: true, ttlMs: 60_000 },
  'payment.charged': { roles: ['user'], requires: { prev: ['auth.verified'] } },
  'image.generate':  { roles: ['premium','admin'], requires: { prev: ['payment.charged'] } },
}
```

호출은 그대로 `await capability.unlock('image.generate')` — prev 토큰은 클라이언트가 자동 캐시·동봉합니다.

---

## 3. `attestation` — Bundle Attestation

**막는 공격**: 클라이언트 번들을 패치해 권한 분기를 모두 통과시키는 변조 우회.

```js
security: {
  attestation: { enabled: true },   // capabilities 켜면 자동 ON, 끄려면 false
  capabilities: {
    enabled: true,
    features: {
      'image.generate': {
        roles: ['premium','admin'],
        requires: { attest: true },  // attest 통과 세션만 토큰 발급
      },
    },
  },
}
```

> 첫 호출 시 클라이언트가 자동으로 attest 후 재시도합니다. 사용자 코드 변경 없음.

---

## 4. `panelIpGuard` — 관제 어드민 IP 제한

**막는 공격**: `/_dokkebi/_panel` 비밀번호 무차별 대입 / 외부 IP 에서 직접 관제 API 호출.

```js
security: { panelIpGuard: true }
```
```env
DOKKEBI_ADMIN_PASSWORD=<긴 비밀번호>
DOKKEBI_PANEL_ALLOWED_IPS=203.0.113.10,198.51.100.0/24
```

---

## 5. `replay` — Replay 방어 튜닝

**막는 공격**: 캡처한 정상 요청을 그대로 다시 쏘는 재전송 / 빠른 다발 발사.

> 항상 ON 이라 끌 수 없고, 값만 조정합니다.

```js
security: {
  replay: {
    timestampWindowMs: 5_000,   // 1s ~ 30s. 모바일 환경이면 8~15s.
    nonceTtlMs: 35_000,         // window + 5s ~ 5min.
  },
}
```

---

## 6. `activeDefense` — ADL

**막는 공격**: 자동화 스크래핑, 403/인증 실패 다발, 가격 fuzzing.

```js
security: {
  activeDefense: {
    enabled: true,
    mode: 'monitor',            // 첫 도입은 monitor → 한 주 관찰 후 enforce 승격
    sampleRate: 0.01,
    riskBlockThreshold: 0.85,
  },
}
```

---

## 7. `advisor` — 빌드 시 보안 어드바이저

**막는 실수**: 외부 비용 라우트를 만들고 capability 선언을 잊는 인적 실수.

기본 ON. `dok build` 가 외부 API 호출 / 민감 secret 사용 / `points.deduct(` 류 라우트가 capability 미선언이면 경고만 출력 (자동 추가 X).

끄려면:
```js
security: { advisor: { disable: true } }
```

---

## 8. `policy` — Row-level 격리 (Tenant Policy)

**막는 공격**: 사용자 A 가 SQL 우회로 사용자 B 의 데이터 SELECT/UPDATE/DELETE.

```js
policy: {
  enabled: true,
  mode: 'inject',              // 'verify' (검증만) | 'inject' (자동 주입)
  claim: 'sub',
  strict: true,
  tables: {
    animation_projects: { tenantColumn: 'user_id' },
    user_assets:        { tenantColumn: 'user_id' },
  },
}
```

> 최상위 `tenantPolicy` 는 `policy` 와 동일하게 병합됩니다(문서·구버전 호환). 새 설정은 `policy` 만 쓰는 것을 권장합니다.

> 멀티 테넌트 SaaS 라면 거의 필수. `authorization` 과 함께 사용 권장.

---

## 9. `authorization` — 연산-레벨 인가 (JWT)

**막는 공격**: 일반 사용자가 admin 전용 op (`UPDATE users`, `DELETE FROM …`) 호출 / JWT 위조.

```js
authorization: {
  enabled: true,
  mode: 'strict',              // 'warn' (로그만) | 'strict' (거절)
  claim: 'role',
  rules: [
    { op: 'UPDATE', table: 'users', roles: ['admin'] },
    { op: 'DELETE', table: '*',     roles: ['admin'] },
    { op: '*',      table: '*',     roles: ['user','admin'] },
  ],
}
```
```env
DOKKEBI_JWT_SECRET=<32자 이상>
```

---

## 10. `webauthn` — 민감 행위 추가 인증

**막는 공격**: 비밀번호/세션을 탈취당했어도 결제·관리자 export 같은 민감 행위 직전에 디바이스 패스키 없이는 진행 불가.

```js
webauthn: {
  enabled: true,
  rpName: 'MyApp',
  rpId: 'myapp.com',
  userVerification: 'required',
  requireForOps: ['DELETE', 'UPDATE_users'],
}
```

> 사용자 등록 흐름에 패스키 등록 단계가 필요합니다. 진짜 민감한 op 에만 한정 사용.

---

## 11. `strictCsp` — 엄격한 CSP

**막는 공격**: XSS 취약점이 있어도 외부 스크립트 주입/eval 로 이어지는 후속 공격.

```js
security: { strictCsp: true }
```

> 일부 third-party 스크립트(외부 광고 SDK 등)는 도메인 추가가 필요할 수 있습니다.

---

## 12. `cspExtraHosts` — 앱별 CSP 화이트리스트 (외부 이미지·API·iframe)

**용도**: 베이스라인 CSP 를 유지한 채, 정당한 외부 리소스(예: Dicebear 아바타 CDN, 결제 위젯)만 화이트리스트에 추가.

```js
security: {
  cspExtraHosts: {
    imgSrc:     ['https://api.dicebear.com'],
    connectSrc: ['https://api.openai.com'],
    frameSrc:   ['https://embed.partner.com'],
  },
}
```

- `imgSrc` → `img-src` (deploy / serve / dev 모두 반영)
- `connectSrc` → `connect-src` (deploy)
- `frameSrc` → `frame-src` (deploy)
- `dok build` 는 `_headers` 를 만들지 않습니다 — CSP 변경은 **`dok deploy` 재실행** 필요.
- 풀 origin (`https://...`) 또는 와일드카드 (`https://*.example.com`) 지원.

---

## 권장 디폴트 (시작은 이 정도)

```js
// dokkebi.config.js
export default {
  security: {
    capabilities: {
      enabled: true,
      features: {
        // 외부 비용/관리자 라우트만 선언
        'image.generate': { roles: ['premium','admin'], routes: ['POST /api/ai/image'] },
        'admin.export':   { roles: ['admin'],           routes: ['POST /api/admin/export'] },
      },
    },
    panelIpGuard: true,
  },

  // 멀티 테넌트 SaaS 면 함께:
  // policy: { enabled: true, mode: 'inject', tables: { ... } },
  // authorization: { enabled: true, mode: 'strict', rules: [...] },
};
```
```env
DOKKEBI_CAPABILITY_SECRET=<32자 이상>
DOKKEBI_ADMIN_PASSWORD=<긴 비밀번호>
DOKKEBI_PANEL_ALLOWED_IPS=203.0.113.10,198.51.100.0/24
DOKKEBI_JWT_SECRET=<32자 이상>     # authorization 사용 시
```

> 더 자세히: `docs/SECURITY_OPTIONS.md` (공격 케이스 풀 매핑 표 포함), `SECURITY.md` (아키텍처).
