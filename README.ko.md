# dokkebi-cli

![Dokkebi logo](https://github.com/kigi625/dokkebi-cli/blob/main/icon-512.png?raw=true)

[자세한 내용 확인하기](https://dokkebi.net)

[Contact](https://notofly.com?page=noto&id=54a144f4-2ac1-41a4-b13d-0269fc265b4f)

# 브라우저 안에서 백엔드가 실행되는 클라이언트사이드 서버리스 프레임워크

도깨비는 백엔드 TypeScript 코드를 **QuickJS** WASM으로 빌드하여 브라우저에서 직접 실행하는 혁신적인 프레임워크입니다. 서버가 없어도 API가 동작하며, DB 통신은 E2E 암호화된 프록시를 통해 안전하게 처리됩니다.

# "MVP 운영 비용 0원의 혁신"

서비스를 하나 만들고 배포하는 데는 아키텍처 설계부터 인프라 구축까지 너무 많은 리소스가 소모됩니다. AI의 발전으로 개발 속도는 비약적으로 빨라졌지만, 서버 관리와 유지 비용의 장벽은 여전히 남아있습니다.

도깨비는 "가능한 사용자의 리소스를 활용하여 쾌적한 서비스를 비용 없이 만들자"는 확고한 철학에서 출발했습니다. 10개든 100개든, 성공을 예측할 수 없는 MVP(최소 기능 제품) 단계의 서비스 운영 비용을 완벽하게 0원으로 만들어 드립니다.

# 핵심 기능 및 장점

Zero Cost: 인프라 관리 및 서버 유지 비용 완벽 제거

One-Click Deploy: 프론트엔드와 백엔드를 원클릭으로 동시 배포 및 롤백 (Cloudflare 환경)

No Server, No Ops: 로드밸런서, 포트 포워딩, 리눅스 보안 등 기존 서버 인프라 관리가 불필요합니다.

# 두 가지 운영 모드

도깨비는 프로젝트의 요구사항에 맞춰 두 가지 모드를 지원합니다.

서버리스 모드 (Serverless Mode): Cloudflare Functions를 활용하여 도깨비 환경의 신뢰성을 검증하고 순수한 클라이언트 사이드 백엔드로 동작합니다.

서버 모드 (Server Mode): 종단간(E2E) 암호화 처리, 결제 검증, 비즈니스 로직 보호가 필수적이거나 특정 클라우드의 종속성(Lock-in)을 피하고 싶을 때 사용합니다.

# 발상을 전환한 보안 아키텍처
"서버가 없으니, 해킹할 서버도 없습니다."

백엔드 소스가 클라이언트(브라우저)에 다운로드된다는 것은 언뜻 미친 짓처럼 보일 수 있습니다. 하지만 도깨비는 해킹을 원천 차단하는 대신, 해킹에 드는 시간과 비용을 기하급수적으로 높여 공격의 가치를 없애는 방식으로 보안 패러다임을 전환했습니다.

초강력 난독화 및 암호화: 백엔드 로직은 WASM으로 컴파일되며, 과도할 정도의 암호화 및 난독화 기법이 적용됩니다.
화이트리스트 쿼리 검증: 승인되지 않은 비정상적인 쿼리는 프록시 단계에서 원천 차단되어 DB에 도달하지 못합니다.
능동 방어 시스템 (Active Defense): 클라이언트 측의 이상 동작을 감지하고 해당 접근을 즉시 차단합니다.

```
브라우저
├── Vue / React 프론트엔드
└── QuickJS WASM 백엔드 (브라우저 내 실행)
       │
       │  ECDH P-256 + HKDF + AES-256-GCM + HMAC-SHA256
       ▼
  DB 프록시 (/api/_dokkebi/db)
  ┌─────────────────────────────────────────┐
  │ 🖥  서버 모드    dok serve → Node.js     │
  │ ☁  서버리스    Cloudflare Pages Function │
  └─────────────────────────────────────────┘
       │
       ▼
  DB (Cloudflare D1 / Supabase / Appwrite)
```

---

## 빠른 시작

```bash
npm install -g dokkebi-cli

dok create my-app      # 인터랙티브 프로젝트 생성
cd my-app
dok dev                # 자동 빌드 + 핫 리로드 개발 서버
open http://localhost:5173
```

---

## 주요 특징

### 진정한 서버리스

- 백엔드가 **QuickJS WASM**으로 브라우저에서 직접 실행 — 별도 서버 프로세스 불필요
- Express 스타일의 친숙한 API (`dokkebi:runtime`)로 라우트·미들웨어·DB 접근
- Type-safe 쿼리 빌더 (`dokkebi-dsl`) 내장

### 다층 보안 레이어 자동 적용

개발자가 별도 설정 없이도 빌드·배포 과정에서 다중 보안이 자동으로 적용됩니다.


| 분류     | 주요 보안                                        | 설명                                     |
| ------ | -------------------------------------------- | -------------------------------------- |
| 통신 암호화 | ECDH P-256 + AES-256-GCM + HMAC-SHA256       | Forward Secrecy, 양방향 암호화, 요청 서명        |
| 재전송 방어 | Nonce + Timestamp (±30s) + timingSafeEqual   | 재전송 공격·타이밍 공격 차단                       |
| SQL 방어 | SQL Allowlist + Query Registry + db.raw() 차단 | 빌드 타임 허용목록·쿼리 해시 등록·임의 SQL 차단          |
| 시크릿 보호 | Env Opaque Handle                            | 민감 변수가 번들에 평문으로 포함되지 않음                |
| 코드 보호  | 2중 보호 번들                                     | JS 난독화 → AES-256-GCM 암호화               |
| 데이터 격리 | Tenant Policy (pseudo-RLS)                   | 테이블별 세션 테넌트 조건 자동 강제                   |
| 접근 제어  | Authorization Policy                         | JWT role 기반 연산·테이블 단위 권한 검증            |
| 세션 보호  | OPFS 세션 암호화 (PBKDF2 + AES-GCM)               | 브라우저 세션 탈취 방어                          |
| 능동 방어  | Active Defense Layer (opt-in)                | 행동 분석 기반 이상 행위 실시간 차단                  |
| 실행 허가  | Signed Unlock Token (opt-in)                 | 유료·고비용 기능 실행 전 Worker 서명 capability 발급 |
| 인증 강화  | WebAuthn Passkey (opt-in)                    | 피싱·재전송 강화 방어                           |
| 배포 안전  | Preflight 점검 + 빌드 서명                         | 배포 전 보안 구성 검사, 공급망 트레이서빌리티             |
| 헤더 보호  | CSP · X-Frame-Options 등 자동 적용                | XSS·클릭재킹·MIME 스니핑 차단                   |


### 주요 공격 시나리오별 방어


| 공격 시나리오         | 방어 체계                      | 방어 흐름                                 |
| --------------- | -------------------------- | ------------------------------------- |
| 🔑 시크릿 탈취       | Env Opaque Handle          | 빌드 타임 자동 변환 → 런타임 Host 클로저 격리         |
| 🌐 네트워크 도청 / 변조 | E2E 암호화                    | ECDH 키 교환 → AES-GCM + HMAC 양방향 암호화    |
| 🛡 코드 리버싱       | 2중 보호 번들                   | JS 난독화 → AES-256-GCM 암호화              |
| 💉 SQL 인젝션      | 3중 SQL 방어                  | Allowlist → Query Registry → 위험 구문 검증 |
| 👤 타 사용자 데이터 접근 | Tenant Policy (pseudo-RLS) | 세션 바인딩 → WHERE 조건 자동 주입 / 거부          |
| 🍪 세션 탈취        | OPFS 세션 암호화                | PBKDF2 100K + AES-GCM + origin salt   |
| 🔓 기능 권한 우회     | Signed Unlock Token        | Worker-only secret 으로 짧은 수명 실행 허가증 발급 |


### 병렬 SELECT (DB 읽기 속도)

브라우저 부트스트랩(`dokkebi-cli`가 주입하는 `/api/_dokkebi/db` 클라이언트)에서 **재전송 방지·nonce 순서**를 위해 DB 호출을 한 줄로 세우는 직렬 큐가 있습니다. 다만 **문자열이 `SELECT`로 시작하는 읽기 전용 쿼리**는 이 큐를 타지 않고 **네트워크 요청을 동시에** 보낼 수 있어, 서로 독립된 여러 조회가 겹칠 때 왕복 대기가 줄어듭니다.

- **직렬(큐) 유지**: `INSERT` / `UPDATE` / `DELETE`, `WITH`로 시작하는 SQL(CTE·`WITH … INSERT` 등), 테넌트 설정·capability 등 부가 채널 — 카운터·순서 보장이 필요한 경로.
- **런타임 헬퍼**: `dokkebi:runtime`의 `parallelReads([...])`는 같은 요청 안에서 여러 읽기 `Promise`를 `Promise.all`로 묶는 용도이며, 위 부트스트랩 동작과 맞물려 **SELECT 병렬 전송** 의도를 코드에 드러낼 때 쓸 수 있습니다.

### 개발 편의

- `**dok dev`** 한 번이면 빌드+서버+핫 리로드 전부 자동
- `**dok deploy**` 한 번이면 빌드+배포+도메인 연결+보안 헤더 생성까지 완료
- `**dok policy:scaffold**` 모델·컨트롤러 분석으로 보안 정책 자동 생성
- **관제 어드민** (`/_dokkebi/_panel`) — 실시간 요청·에러·보안 이벤트 대시보드
- **에러 자동 수집** — WASM 오류 + 브라우저 uncaught exception 자동 기록
- **12개 언어 CLI** — 한국어, English, 日本語, 中文, Deutsch 등
- **기존 프로젝트 업데이트** — `dok update`로 사용자 코드 손대지 않고 안전 업그레이드

---

## CLI 커맨드


| 커맨드                         | 설명                                               |
| --------------------------- | ------------------------------------------------ |
| `dok create [name]`         | 인터랙티브 프로젝트 생성 (Vue/React + D1/Supabase/Appwrite) |
| `dok dev [src]`             | 개발 서버 (자동 빌드 + 핫 리로드, 기본 포트 5173)                |
| `dok build [src]`           | QuickJS WASM 빌드 + 프론트엔드 통합                       |
| `dok serve [src]`           | 프로덕션 Node.js 서버 (기본 포트 5174)                     |
| `dok deploy [src]`          | Cloudflare Pages 배포 (R2/S3 프론트엔드 + 도메인 자동화)      |
| `dok migrate [src]`         | SQL 마이그레이션 적용                                    |
| `dok update [src]`          | 기존 프로젝트에 최신 버전 적용 (사용자 코드 보존)                    |
| `dok security [src]`        | 보안 옵트인 **인터랙티브** (`--status` 텍스트만)               |
| `dok policy:scaffold [src]` | 모델 분석 기반 Tenant/Authorization Policy 자동 생성       |
| `dok lang [code]`           | CLI 언어 변경 (12개 언어 지원)                            |


> 각 커맨드의 상세 옵션은 `dok <command> --help`로 확인할 수 있습니다.

---

## 백엔드 코드 예시

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

## 배포 모드


|        | 개발 (`dok dev`) | 서버 (`dok serve`) | 서버리스 (`dok deploy`)   |
| ------ | -------------- | ---------------- | --------------------- |
| 실행 환경  | Node.js (로컬)   | Node.js (서버)     | Cloudflare Pages Edge |
| 핫 리로드  | O              | —                | —                     |
| DB 프록시 | Node.js        | Node.js          | Pages Function        |
| 기본 포트  | 5173           | 5174             | —                     |


---

## 지원 DB


| DB            | proxyMode           | 비고             |
| ------------- | ------------------- | -------------- |
| Cloudflare D1 | server / serverless | 권장 (서버리스 네이티브) |
| Supabase      | server              | REST API       |
| Appwrite      | server              | REST API       |


---

## 보안 옵션 — 어떤 공격을 막는지부터 보세요

`dokkebi.config.js` 의 `security` 섹션에는 사용자가 직접 켜고 끄는 옵션이 여러 개 있습니다. 각 옵션이 **어떤 공격을 막는지** + **어떻게 적용하는지**를 한 문서에서 정리했습니다.

- **현재 프로젝트**: `dok security` — 터미널(TTY)에서 **화살표·Enter**로 항목 이동, ON/OFF·레벨 변경, 항목별 위협 요약·필요 `.env`/설정 안내. 저장 시 `dokkebi.config.js` 자동 패치(실패 줄은 스니펫 안내) + `.bak`.
- **텍스트만**: `dok security --status` (CI / 비TTY). **TUI 강제**: `dok security --interactive`.
- ➡ `**[docs/SECURITY_OPTIN.md](docs/SECURITY_OPTIN.md)`** — 옵트인 옵션 빠른 참조 (옵션 ↔ 공격 ↔ 설정 한 줄씩).
- ➡ `**[docs/SECURITY_OPTIONS.md](docs/SECURITY_OPTIONS.md)**` — 옵션별 공격 케이스 / 적용 예시 / 운영 메모, 옵션 ↔ 공격 매핑 표 포함.

권장 디폴트: `capabilities.enabled: true` 만 켜면 `attestation` 도 자동 ON 이고, 클라이언트의 prev 토큰 동봉/재귀 unlock 도 자동 처리됩니다. `dok build` 가 비용 발생 라우트가 capability 미선언이면 경고를 띄워줍니다.

## 외부 공격 관점 프로덕션 체크리스트

악성 의존성·조작된 빌드 PC는 가정하지 않습니다. **이미 배포된 URL만으로 접근 가능한 정적 번들(JSON·JS·WASM)과 공개 API**를 전제로, 운영에서 점검할 항목입니다.

### 쿼리·SQL 경계

- **Cloudflare Pages Secret** 에 `DOKKEBI_QUERY_MODE=strict` (또는 동등한 fail-closed 운영)을 두었다. `**auto` / `learn` 을 프로덕션에서 사용하지 않는다.**
- `dist/dokkebi/query-registry.json` 이 비어 있지 않으며, `**dok deploy --strict-registry`** 또는 `dokkebi.config.js` 의 `**queryRegistry.strict: true**` 로 빈 레지스트리 배포를 막았다.
- 가능하면 `**sql-allowlist.json` 에서 `rawAllowed: false**` 를 유지하고, `**db.raw()**` 사용을 피했다.
- 허용 테이블·연산이 최소이다(불필요한 `**SELECT ***`, 넓은 JOIN·서브쿼리 남발 없음).

### 테넌트·인가(서버 신뢰 경계)

- `**bindSession()`·클라이언트가 보내는 테넌트 메타만으로 인가하지 않는다.** 실데이터 접근 제한은 **D1 스키마/앱 레벨 강제** 또는 **별도 신뢰 서버 검증·RLS**(해당 플랫폼 가능 시)에 둔다.
- `**dokkebi.config.js` 의 `policy`(Tenant)** 가 켜져 있고, 프로덕션에서는 `**policy.strict`** 를 끄지 않았다.
- `**authorization**` 규칙이 정의되어 있으며, 필요 시 `**strict**` 에 가깝게 운영한다(기본 `warn` 만으로는 부족할 수 있음).

### 노출 표면 최소화

- `**/_dokkebi/_panel**` 을 꼭 쓰지 않으면 라우팅/IP 제한 또는 비공개 네트워크 뒤에 둔다. 쓰면 `**DOKKEBI_ADMIN_PASSWORD**` 를 충분히 길게 두고, 가능하면 `**DOKKEBI_PANEL_ALLOWED_IPS**` 로 접속 IP 를 제한한다.
- `**/api/_dokkebi/log**` 에 의한 저장소 오염·쿼터 압박 가능성을 인지하고, 필요 시 레이트 리밋·모니터링으로 대응한다.
- `**dok serve**` 는 로컬/내부망 한정이다. `**0.0.0.0` 바인딩을 인터넷에 노출하지 않는다.**

### 빌드·배포 품질

- `**dok deploy`** 시 `**--preflight**` 를 끄지 않으며, 필요 시 `**--preflight-strict**` 로 경고 존재 시 배포 실패하게 한다.
- 선택적으로 `**security.strictCsp: true**` 를 검토했다(브라우저·CDN 호환성과 트레이드오프).
- 외부 이미지·API·iframe 화이트리스트는 `**security.cspExtraHosts**` 로 **앱별 화이트리스트만** 열어준다(예: `imgSrc: ['https://api.dicebear.com']`). 베이스라인 CSP 는 그대로 유지된다 — 자세한 내용은 [`docs/SECURITY_OPTIONS.md`](docs/SECURITY_OPTIONS.md) 12번.
- **프론트 XSS** 를 줄인다(`unsafe-inline` / `unsafe-eval` 이 허용된 CSP에서는 XSS 가 곧 브라우저 내 실행 맥락 침해로 이어질 수 있다).

### 사전 정찰이 가능함을 인지

- `**/dokkebi/sql-allowlist.json`**, `**query-registry.json**` 등은 **공개될 수 있다**고 가정하고, 그 안의 정보만으로 다른 사용자 데이터에 닿지 않도록 설계했는지 확인한다.

---

## 플러그인

WASM 백엔드에 기능을 안전하게 확장합니다. `dokkebi.config.js`의 `plugins`에서 활성화합니다.


| 플러그인       | 기능                      | 보안                           |
| ---------- | ----------------------- | ---------------------------- |
| **fetch**  | WASM에서 외부 HTTP 요청       | 도메인 화이트리스트 + 동시 요청 제한 + 타임아웃 |
| **bundle** | 브라우저 내 esbuild-wasm 번들링 | OPFS 샌드박스 + CDN external     |


---

## 관제 어드민 IP 제한

`/_dokkebi/_panel` 은 `dokkebi.config.js` 에서 `security.panelIpGuard: true` 를 켠 뒤 `.env` 또는 Cloudflare Pages Secret 에 `DOKKEBI_PANEL_ALLOWED_IPS` 를 두면 IP allowlist 방식으로 접근을 제한합니다. 기본값은 `false` 입니다.

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

`security.panelIpGuard` 가 `false` 이면 `DOKKEBI_PANEL_ALLOWED_IPS` 값이 있어도 차단하지 않습니다. `true` 인데 env 값이 비어 있으면 `dok build` 가 경고를 출력합니다. 쉼표로 여러 IP 또는 IPv4 CIDR 을 지정할 수 있고, `dok dev`, `dok serve`, Cloudflare Pages Functions 패널 모두 같은 설정을 사용합니다.

기존 프로젝트는 `dok update` 실행 시 `dokkebi.config.js` 에 `panelIpGuard: false` 기본값과 `.env.example` 의 `DOKKEBI_PANEL_ALLOWED_IPS` 항목이 보강됩니다.

## Signed Unlock Token

유료 기능, 고비용 AI 호출, 관리자 export 같은 기능은 브라우저의 `if (isPremium)` 만으로 보호하지 말고 Worker 가 서명한 실행 허가증을 요구할 수 있습니다.

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

위처럼 `routes` 를 지정하면 `dok build` 가 해당 Dokkebi runtime route 앞에 guard 를 자동 삽입합니다. 사용자는 핸들러에 `capability.unlock()` 을 직접 넣지 않아도 되며, 통과한 요청에는 `ctx.capability` 가 채워집니다.

컨트롤러 근처에 JSDoc 으로도 선언할 수 있습니다.

```ts
/**
 * @dokkebi-capability feature:image.generate route:"POST /api/ai/image" roles:['premium','admin'] ttl:10000
 */
router.post('/api/ai/image', async (ctx) => {
  // ctx.capability.token/proof 를 실행 파라미터나 서버 요청 재료에 묶어 사용
});
```

수동으로 더 세밀한 state binding 이 필요하면 기존 API 를 직접 호출할 수 있습니다.

```ts
import { capability } from 'dokkebi:runtime';

const unlock = await capability.unlock('image.generate', {
  state: { projectId, promptHash },
  jwt: userToken,
});
if (!unlock.ok) throw new Error(unlock.error);

// token/proof 는 단순 플래그가 아니라 기능 실행 재료로 사용해야 합니다.
```

`DOKKEBI_CAPABILITY_SECRET` 은 `.env` 또는 Cloudflare Pages Secret 에 32바이트 이상 랜덤 값으로 설정하세요. 이 기능은 권한 플래그/분기문 패치 공격 비용을 올리지만, 이미 권한 있는 사용자의 로컬 덤프까지 완전히 막는 DRM 은 아닙니다.

### Capability Chain

특정 기능이 발급되기 전에 다른 capability 의 유효한 토큰을 함께 제출하도록 강제할 수 있습니다.

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

Worker 는 모든 선행 토큰의 HMAC 서명, 만료, `sid` 일치, feature 일치를 검증합니다.

## Bundle Attestation

빌드 시 암호화 번들 바이트를 16KB 청크로 나눠 SHA-256 매니페스트를 생성하고, Worker 가 매 세션마다 무작위 청크 인덱스를 challenge 로 보내 클라이언트 응답을 매니페스트와 비교합니다. 변조된 번들로는 챌린지를 통과할 수 없습니다.

```js
// dokkebi.config.js
security: {
  attestation: {
    enabled: true,
    sampleSize: 4,         // 1–16, 기본 4
    ttlMs: 5 * 60_000,     // 30s–30min, 기본 5분
  },
  capabilities: {
    enabled: true,
    features: {
      'image.generate': {
        roles: ['premium','admin'],
        requires: { attest: true },   // attest 통과 세션만 발급
      },
    },
  },
}
```

`requires.attest: true` 가 붙은 capability 요청에서 서버가 `CAPABILITY_ATTEST_REQUIRED` 를 돌려주면 클라이언트가 자동으로 `_attest` 챌린지를 수행한 뒤 한 번 재시도합니다. 사용자 코드 변경은 필요 없습니다.

자세한 설명과 한계는 `SECURITY.md` 의 §3.6 을 참고하세요.

---

## 요구사항

- **Node.js 20+** — Cloudflare Wrangler 요구사항. `dok deploy` 가 내부적으로 `wrangler pages deploy` 를 호출하므로 18 에서는 배포 단계가 실패합니다. 빌드/로컬 개발은 18 에서도 동작하지만 권장 버전은 20 LTS 이상입니다.

## 설치

```bash
# 전역 설치
npm install -g dokkebi-cli

# 또는 로컬 설치
npm install dokkebi-cli
npx dok --help
```

# 언어 변경
```bash
dok lang
```

## 라이선스
ELv2
