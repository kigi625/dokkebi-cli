/**
 * 프로젝트 파일 생성기
 *
 * dokkebi create 커맨드가 선택한 (frontend × database) 조합에 따라
 * 완전한 프로젝트 구조를 생성합니다.
 *
 * 지원 조합:
 *   frontend: react | vue
 *   database: d1 | supabase | appwrite
 */

import fs from 'fs/promises';
import path from 'path';
import url from 'url';
import { emitPayloadWireTs, disabledWireRuntimeJson } from './payloadWireRuntime.js';
import { renderTemplate } from './templateLoader.js';
import { dokkebiClientTsSource } from '../../packages/dokkebi-vite-plugin/src/index.js';

const __projectGeneratorFile = url.fileURLToPath(import.meta.url);
const CLI_PACKAGE_ROOT = path.resolve(path.dirname(__projectGeneratorFile), '..', '..');

async function readCliPackageDocSafe(relPath) {
    try {
        return await fs.readFile(path.join(CLI_PACKAGE_ROOT, relPath), 'utf-8');
    } catch {
        return '';
    }
}

/**
 * @param {object} opts
 * @param {string} opts.name        - 프로젝트 이름
 * @param {string} opts.targetDir   - 생성 대상 디렉토리
 * @param {'react'|'vue'} opts.frontend
 * @param {'d1'|'supabase'|'appwrite'} opts.database
 * @param {boolean} opts.withAuth   - Auth 보일러플레이트 포함 여부
 * @param {'server'|'serverless'} opts.proxyMode - 프록시 모드
 * @param {boolean} [opts.withWebAuthn=false] - WebAuthn (Passkey) 요청 서명 활성 (v5.5+)
 */
export async function generateProject({ name, targetDir, frontend, database, withAuth, proxyMode = 'server', withWebAuthn = false }) {
    await fs.mkdir(targetDir, { recursive: true });

    const files = buildFileTree({ name, frontend, database, withAuth, proxyMode, withWebAuthn });

    const [agentsMd, securityMd] = await Promise.all([
        readCliPackageDocSafe('AGENTS.md'),
        readCliPackageDocSafe('SECURITY.md'),
    ]);
    if (agentsMd) files['AGENTS.md'] = agentsMd;
    if (securityMd) files['SECURITY.md'] = securityMd;

    for (const [relativePath, content] of Object.entries(files)) {
        const fullPath = path.join(targetDir, relativePath);
        await fs.mkdir(path.dirname(fullPath), { recursive: true });
        await fs.writeFile(fullPath, content, 'utf-8');
    }
}

// ─────────────────────────────────────────────────────────────
// 파일 트리 빌더 — 모든 조합 파일 생성
// ─────────────────────────────────────────────────────────────

function buildFileTree({ name, frontend, database, withAuth, proxyMode = 'server', withWebAuthn = false }) {
    const files = {};

    // ── 루트 파일 ──────────────────────────────────────────

    files['package.json'] = packageJson(name, frontend, database, proxyMode);
    files['dokkebi.config.js'] = dokkebiConfig(database, proxyMode, { withWebAuthn });
    files['.gitignore'] = gitignore(proxyMode);
    files['.env.example'] = envExample(database, proxyMode);
    files['README.md'] = readme(name, frontend, database, proxyMode);
    files['tsconfig.json'] = tsconfig();

    // ── 백엔드 타입 선언 (dokkebi:runtime / dokkebi:dsl 모듈) ──
    files['backend/types/dokkebi.d.ts'] = dokkebiTypeDeclarations();

    // ── 백엔드 공통 ────────────────────────────────────────

    files['backend/wit/dokkebi.wit'] = witFile();
    files['backend/models/index.ts'] = modelsIndex();
    files['backend/controllers/index.ts'] = controllersIndex(database, withAuth);
    files['backend/controllers/product.controller.ts'] = productController();
    files['backend/controllers/order.controller.ts'] = orderController();
    files['backend/controllers/auth.controller.ts'] = authController(database);
    files['backend/middleware/index.ts'] = middlewareIndex(withAuth);

    // ── DB 어댑터 (DB별 설정) ──────────────────────────────

    files['backend/db/index.ts'] = dbAdapter(database);
    files['backend/db/migrations/001_initial.sql'] = initialMigration(database);

    // ── 서버리스 모드 — Cloudflare Pages Functions ─────────

    if (proxyMode === 'serverless') {
        files['worker/api/_dokkebi/handshake.ts'] = workerHandshake();
        files['worker/api/_dokkebi/_payloadWire.ts'] = emitPayloadWireTs(disabledWireRuntimeJson());
        files['worker/api/_dokkebi/db.ts'] = workerDb(database);
        files['worker/api/_dokkebi/log.ts'] = workerLog();
        files['worker/api/_dokkebi/_panel.ts'] = workerAdmin(name);
        files['worker/api/_dokkebi/_panel/[[path]].ts'] = workerAdminApi(name);
        files['worker/api/webhooks/lemonsqueezy.ts'] = workerLemonSqueezyWebhookTemplate();
        files['worker/_middleware.ts'] = workerRootMiddleware(database);
        files['worker/api/_middleware.ts'] = workerMiddleware();
        files['worker/tsconfig.json'] = workerTsconfig();
        files['wrangler.toml'] = wranglerToml(name, database);
    }

    // ── 프론트엔드 ─────────────────────────────────────────

    if (frontend === 'react') {
        files['frontend/package.json'] = frontendPackageJson(name, 'react');
        files['frontend/vite.config.ts'] = viteConfigReact();
        files['frontend/tsconfig.json'] = frontendTsconfig('react');
        files['frontend/index.html'] = indexHtml(name, 'react');
        files['frontend/src/main.tsx'] = reactMain();
        files['frontend/src/App.tsx'] = reactApp(database);
        files['frontend/src/composables/useDokkebi.ts'] = useDokkebiHook('react');
        files['frontend/src/lib/dokkebi.ts'] = dokkebiClientTsSource();
    } else {
        files['frontend/package.json'] = frontendPackageJson(name, 'vue');
        files['frontend/vite.config.ts'] = viteConfigVue();
        files['frontend/tsconfig.json'] = frontendTsconfig('vue');
        files['frontend/index.html'] = indexHtml(name, 'vue');
        files['frontend/src/main.ts'] = vueMain();
        files['frontend/src/App.vue'] = vueApp(database);
        files['frontend/src/composables/useDokkebi.ts'] = useDokkebiHook('vue');
        files['frontend/src/lib/dokkebi.ts'] = dokkebiClientTsSource();
    }

    return files;
}


// ─────────────────────────────────────────────────────────────
// 루트 파일 템플릿
// ─────────────────────────────────────────────────────────────

function packageJson(name, frontend, database, proxyMode = 'server') {
    const frontendDeps =
        frontend === 'react'
            ? { react: '^18.3.1', 'react-dom': '^18.3.1' }
            : { vue: '^3.4.0' };
    const frontendDevDeps =
        frontend === 'react'
            ? {
                  '@types/react': '^18.3.1',
                  '@types/react-dom': '^18.3.1',
                  '@vitejs/plugin-react': '^4.3.1',
              }
            : { '@vitejs/plugin-vue': '^5.1.2' };

    const scripts = {
        dev: 'dok dev',
        build: 'dok build',
        'type-check': 'tsc --noEmit',
    };

    if (proxyMode === 'serverless') {
        scripts['deploy'] = 'dok deploy';
        scripts['preview'] = 'wrangler pages dev dist/';
    } else {
        scripts['serve'] = 'dok serve --skip-build';
    }

    const devDeps = {
        typescript: '^5.5.3',
        vite: '^5.4.0',
        ...frontendDevDeps,
    };

    if (proxyMode === 'serverless') {
        devDeps['@cloudflare/workers-types'] = '^4.20240725.0';
    }

    return JSON.stringify(
        {
            name,
            version: '0.1.0',
            private: true,
            type: 'module',
            scripts,
            dependencies: {
                ...frontendDeps,
            },
            devDependencies: devDeps,
        },
        null,
        2
    );
}

function dokkebiConfig(database, proxyMode = 'server', opts = {}) {
    const { withWebAuthn = false } = opts;
    const dbConfigs = {
        d1: `  database: {
    type: 'd1',
    // Cloudflare Dashboard에서 확인: https://dash.cloudflare.com
    accountId: process.env.D1_ACCOUNT_ID || '',
    databaseId: process.env.D1_DATABASE_ID || '',
    apiToken: process.env.D1_API_TOKEN || '',
    apiBase: 'https://api.cloudflare.com/client/v4',

    // ── D1 Read Replica (Sessions API) — opt-in ─────────────────
    // 켜면 SELECT 는 가까운 replica 로, 쓰기/직후 read 는 primary 로 자동 분기.
    // 응답에 __d1b 쿠키(httpOnly, SameSite=Lax) 가 자동 첨부되어 같은 사용자의
    // "내 글이 안보여요" 류 일관성 문제를 막아줍니다.
    //   true            — 기본 모드(first-unconstrained, 지연 허용)
    //   { enabled, mode } — 'first-unconstrained' | 'first-primary'
    // sessions: true,

    // ── 샤딩(d1-sharded) — 1만~10만 동접급에서만 필요 ─────────────
    // 단일 D1 의 쓰기 한계가 보일 때 type 을 'd1-sharded' 로 바꾸고 아래 블록을
    // 활성화하세요. 자세한 적용 방법: dokkebi-site /#/sharding
    //   1) dok db:provision  → 각 샤드 D1 자동 생성 + wrangler.toml 자동 갱신
    //   2) dok migrate       → 모든 샤드에 스키마 fan-out
    //   3) 컨트롤러: const db = ctx.shardFor({ user_id }); 로 결정적 라우팅
    //
    // type: 'd1-sharded',
    // shards: [
    //   { id: 's0', binding: 'DB_S0', databaseId: process.env.D1_S0_ID || '' },
    //   { id: 's1', binding: 'DB_S1', databaseId: process.env.D1_S1_ID || '' },
    // ],
    // strategy: {
    //   key: 'user_id',         // policy.tables[*].sessionClaim 과 동일하게 두는 것 권장
    //   hash: 'fnv1a',          // 'fnv1a' | 'sha1' | 'sha256'
    //   virtualBuckets: 256,    // (선택) consistent-hash 풍 리샤딩 대비
    // },
    // global: { id: 'global', binding: 'DB_GLOBAL', databaseId: process.env.D1_GLOBAL_ID || '' },
  },`,
        supabase: `  database: {
    type: 'supabase',
    // Supabase 프로젝트 설정에서 확인: https://app.supabase.com
    supabaseUrl: process.env.SUPABASE_URL || '',
    anonKey: process.env.SUPABASE_ANON_KEY || '',
    serviceKey: process.env.SUPABASE_SERVICE_KEY || '',
  },`,
        appwrite: `  database: {
    type: 'appwrite',
    // Appwrite Console에서 확인: https://cloud.appwrite.io
    endpoint: process.env.APPWRITE_ENDPOINT || 'https://cloud.appwrite.io/v1',
    projectId: process.env.APPWRITE_PROJECT_ID || '',
    apiKey: process.env.APPWRITE_API_KEY || '',
    databaseId: process.env.APPWRITE_DATABASE_ID || '',
  },`,
    };

    return `// dokkebi.config.js — 프레임워크 설정
// 빌드 타임에 dok build 가 이 파일을 읽습니다.
// DB 자격증명은 .env 파일에서 관리하세요 (.env.example 참고).

/** @type {import('dokkebi-cli').DokkebiConfig} */
export default {
  // 프록시 모드: 'server' (dok serve) | 'serverless' (Cloudflare Pages)
  proxyMode: '${proxyMode}',

${dbConfigs[database]}

  backend: {
    entry: './backend/controllers/index.ts',
    outDir: './dist/dokkebi',
  },

  frontend: {
    outDir: './dist',
  },

  logging: {
    /** 원격 로그 수집 최소 레벨 — 생략 시 CLI 기본은 error (Spring root level 과 유사) */
    level: 'error', // 'debug' | 'log' | 'info' | 'warn' | 'error'
  },

  // ── 개발 서버 포트 설정 (선택) ────────────────────────────
  // CLI: dok dev --port 3000 | .env: PORT=3000 | 여기서 설정
  // dev:   { port: 5173 },   // dok dev 기본 포트
  // serve: { port: 5174 },   // dok serve 기본 포트

  // ── 보안 (Replay 방어는 기본 활성 · WebAuthn 은 opt-in) ───
  //
  //   Replay 방어: 항상 ON (보안 필수). 값만 조정 가능합니다.
  //     - timestampWindowMs: 클라↔서버 허용 시계 오차 [1s, 30s] (기본 5s)
  //     - nonceTtlMs:        nonce 보존 수명 [window+5s, 5min] (기본 35s)
  //
  //   WebAuthn (Passkey) 요청 서명: opt-in. 'dok init' 에서 활성화한 경우에만
  //   dokkebi.webauthn.* 가 런타임에 노출됩니다. 연동 가이드:
  //     → docs/design/WEBAUTHN.md  (dokkebi-cli 저장소)
  //
${withWebAuthn ? `  security: {
    // replay: { timestampWindowMs: 5000, nonceTtlMs: 35000 },  // 기본값이면 생략
    // ── Caller Guard (opt-in) ──────────────────────────────────
    // 페이지 frontend 번들에서 온 dokkebi 호출만 허용. DevTools 콘솔 / inline XSS
    // (<img onerror=>) / eval / cross-origin iframe 호출을 차단/감사합니다.
    //   'audit' — 의심 호출 감사 로그만 (sendBeacon → callerCheckAuditUrl)
    //   'block' — 의심 호출 차단 + 감사
    // 'audit' 로 1주 운영 후 false positive 없으면 'block' 으로 승격 권장.
    // callerCheck: 'audit',
    webauthn: {
      enabled: true,
      // rpName:            '\${name}',           // 패스키에 표시될 사이트 이름 (기본: package.json name)
      // rpId:              undefined,           // 기본값: 현재 origin host (권장)
      // userVerification:  'preferred',         // 'required' | 'preferred' | 'discouraged'
      // attestation:       'none',              // 서버가 디바이스 증명 요구 X (권장)
      // timeoutMs:         60000,
      // requireForOps:     ['INSERT:*','UPDATE:*','DELETE:*'], // 쓰기에만 서명 요구 (기본: 인증된 모든 연산)
      //
      // ⚠ 회원가입/로그인에 반드시 배선해야 실제 보호가 활성됩니다:
      //     회원가입 성공 직후:  await dokkebi.webauthn.register({ userId, userName })
      //     로그인 직후:         await dokkebi.webauthn.authenticate({ userId })
      //   호출 안 하면 "enabled: true" 만으로는 아무 보호도 되지 않습니다.
      //   (client SDK 는 v5.5+ 빌드 시 자동 주입됩니다.)
    },
  },` : `  // security: {
  //   replay:   { timestampWindowMs: 5000, nonceTtlMs: 35000 },
  //   webauthn: { enabled: false },  // v5.5+ — Passkey 요청 서명 (필요 시 true 로 전환 + 회원가입/로그인에 배선)
  //   panelIpGuard: false,           // 관제 어드민 IP allowlist. true면 DOKKEBI_PANEL_ALLOWED_IPS 필요
  //
  //   // ── Caller Guard (opt-in) ────────────────────────────────
  //   // 페이지 frontend 번들에서 온 dokkebi 호출만 허용. DevTools 콘솔 / inline XSS
  //   // (<img onerror=>) / eval / cross-origin iframe 호출을 차단/감사합니다.
  //   //   'audit' — 의심 호출 감사 로그만 (sendBeacon)
  //   //   'block' — 의심 호출 차단 + 감사
  //   // callerCheck: 'audit',
  //   // callerCheckAuditUrl: '/_dokkebi/quarantine',  // (선택) 감사 endpoint
  //
  //   // ── Active Defense Layer (Phase 3, opt-in) ────────────────
  //   // 행동 기반 차단(블랙리스트/risk_score). Lazy Cron 모델로 추가 비용/지연 없음.
  //   // monitor 모드 → 1주 운영 후 enforce 전환을 권장합니다.
  //   activeDefense: {
  //     enabled: false,
  //     mode: 'monitor',          // 'monitor' | 'enforce'
  //     trigger: 'lazy',          // 'lazy' (핫패스 ctx.waitUntil) | 'cron' (별도 워커)
  //     interval: '5m',           // 분석 주기 (1m,5m,15m,1h … 또는 ms 숫자)
  //     sampleRate: 0.01,         // 핫패스 트리거 확률 (0~1)
  //     riskBlockThreshold: 0.85, // risk_score ≥ 임계 시 차단
  //     useWorkersAI: false,      // (선택) Workers AI 보조 분석
  //   },
  // },`}

  // ── 배포 설정 (선택) ──────────────────────────────────────
  // deploy: {
  //   // 프론트엔드 배포 방식
  //   // 'cloudflare-pages' (기본) — 백엔드와 함께 CF Pages에 배포
  //   // 'cloudflare-r2'           — Cloudflare R2에 프론트엔드 업로드
  //   // 's3'                      — AWS S3에 프론트엔드 업로드
  //   frontend: 'cloudflare-r2',
  //
  //   r2: {
  //     bucket: 'my-frontend-bucket',
  //     domain: 'www.example.com',  // CF 관리 도메인이면 DNS 자동 설정
  //   },
  //
  //   // cloudflarePages: { domain: 'app.example.com' }, // CF Pages 커스텀 도메인
  //   // s3: { bucket: 'my-bucket', region: 'ap-northeast-2' },
  // },
};
`;
}

function gitignore(proxyMode = 'server') {
    const serverlessExtras = proxyMode === 'serverless'
        ? `functions/\n.dokkebi-secrets.json\n.wrangler/\n`
        : '';
    return `node_modules/
dist/
.env
.env.local
*.local
.DS_Store
*.wasm
${serverlessExtras}`;
}

function envExample(database, proxyMode = 'server') {
    const templates = {
        d1: proxyMode === 'serverless'
            ? `# Cloudflare D1 자격증명
# https://dash.cloudflare.com → Workers & Pages → D1
#
# 📦 로컬 DB 모드: 값을 비워두면 브라우저 IndexedDB/OPFS에
#    sql.js(SQLite WASM)로 데이터를 저장하여 샘플이 즉시 동작합니다.
#    외부 DB 자격증명을 설정하면 자동으로 서버 프록시 모드로 전환됩니다.

D1_ACCOUNT_ID=
D1_DATABASE_ID=
D1_API_TOKEN=

# Cloudflare Pages 배포 설정
D1_DATABASE_NAME=

# ── Cloudflare R2 프론트엔드 배포 (선택) ─────────────────────
# deploy.frontend: 'cloudflare-r2' 설정 시 필요합니다.
# Cloudflare 대시보드 → R2 → Manage R2 API Tokens → Create API Token
# R2_ACCESS_KEY_ID=
# R2_SECRET_ACCESS_KEY=
# R2_BUCKET=

# ── AWS S3 프론트엔드 배포 (선택) ────────────────────────────
# deploy.frontend: 's3' 설정 시 필요합니다.
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=
# AWS_REGION=ap-northeast-2
# AWS_S3_BUCKET=
# AWS_CLOUDFRONT_DISTRIBUTION_ID=

# ── 관제 어드민 (선택) ───────────────────────────────────────
# 설정 시 /_dokkebi/_panel 경로로 관제 대시보드 접속 가능
# DOKKEBI_ADMIN_PASSWORD=
# security.panelIpGuard=true 일 때 사용. 쉼표 구분 IP/CIDR allowlist.
# 예: 203.0.113.10,198.51.100.0/24
# DOKKEBI_PANEL_ALLOWED_IPS=
#
# ── Signed Unlock Token (선택) ───────────────────────────────
# security.capabilities.enabled=true 설정 시 필요
# DOKKEBI_CAPABILITY_SECRET=
#
# ── 결제 웹훅 (Lemon Squeezy, 선택) ──────────────────────────
# worker/api/webhooks/lemonsqueezy.ts 예제에서 사용
# LEMON_SQUEEZY_WEBHOOK_SECRET=
`
            : `# Cloudflare D1 자격증명
# https://dash.cloudflare.com → Workers & Pages → D1
#
# 📦 로컬 DB 모드: 값을 비워두면 브라우저 IndexedDB/OPFS에
#    sql.js(SQLite WASM)로 데이터를 저장하여 샘플이 즉시 동작합니다.
#    외부 DB 자격증명을 설정하면 자동으로 서버 프록시 모드로 전환됩니다.

D1_ACCOUNT_ID=
D1_DATABASE_ID=
D1_API_TOKEN=
`,
        supabase: `# Supabase 자격증명
# https://app.supabase.com → Project Settings → API
#
# 📦 로컬 DB 모드: 값을 비워두면 브라우저 IndexedDB/OPFS에
#    sql.js(SQLite WASM)로 데이터를 저장하여 샘플이 즉시 동작합니다.
#    외부 DB 자격증명을 설정하면 자동으로 서버 프록시 모드로 전환됩니다.

SUPABASE_URL=
SUPABASE_ANON_KEY=
SUPABASE_SERVICE_KEY=

# ── 관제 어드민 (선택) ───────────────────────────────────────
# DOKKEBI_ADMIN_PASSWORD=
# security.panelIpGuard=true 일 때 사용. 쉼표 구분 IP/CIDR allowlist.
# 예: 203.0.113.10,198.51.100.0/24
# DOKKEBI_PANEL_ALLOWED_IPS=
#
# ── Signed Unlock Token (선택) ───────────────────────────────
# security.capabilities.enabled=true 설정 시 필요
# DOKKEBI_CAPABILITY_SECRET=
`,
        appwrite: `# Appwrite 자격증명
# https://cloud.appwrite.io → Project → API Keys
#
# 📦 로컬 DB 모드: 값을 비워두면 브라우저 IndexedDB/OPFS에
#    sql.js(SQLite WASM)로 데이터를 저장하여 샘플이 즉시 동작합니다.
#    외부 DB 자격증명을 설정하면 자동으로 서버 프록시 모드로 전환됩니다.

APPWRITE_ENDPOINT=https://cloud.appwrite.io/v1
APPWRITE_PROJECT_ID=
APPWRITE_API_KEY=
APPWRITE_DATABASE_ID=

# ── 관제 어드민 (선택) ───────────────────────────────────────
# DOKKEBI_ADMIN_PASSWORD=
# security.panelIpGuard=true 일 때 사용. 쉼표 구분 IP/CIDR allowlist.
# 예: 203.0.113.10,198.51.100.0/24
# DOKKEBI_PANEL_ALLOWED_IPS=
#
# ── Signed Unlock Token (선택) ───────────────────────────────
# security.capabilities.enabled=true 설정 시 필요
# DOKKEBI_CAPABILITY_SECRET=
`,
    };
    return templates[database] || '';
}

function dokkebiTypeDeclarations() {
    return renderTemplate('project/dokkebi.d.ts.tpl', []);
}

// ─────────────────────────────────────────────────────────────
// 서버리스 모드 — Cloudflare Pages Functions 템플릿
// ─────────────────────────────────────────────────────────────

// Phase B (B-1): 단일 D1 모드 placeholder. 샤딩 모드 값 주입은 B-2 에서 NormalizedDb 인자로 확장.
// _PHASE_B_PH_INTERNAL : `_internalDb()` 헬퍼만 사용하는 워커 템플릿용 (handshake/log/admin/...)
// _PHASE_B_PH_FULL     : 사용자 SQL 라우팅도 하는 db.ts.tpl 용 (SHARD_BINDINGS 추가).
const _PHASE_B_PH_INTERNAL = [
    { find: '__DOKKEBI_PH_INTERNAL_BINDING__', replace: 'DB' },
];
const _PHASE_B_PH_FULL = [
    ..._PHASE_B_PH_INTERNAL,
    { find: '__DOKKEBI_PH_SHARD_BINDINGS__', replace: '[]' },
];

export function workerHandshake() {
    return renderTemplate('worker/handshake.ts.tpl', [..._PHASE_B_PH_INTERNAL]);
}


/**
 * Pages Function 템플릿 생성 — DB 프록시 (v8)
 *
 * @param {string} database - DB 타입 (현재는 'd1' 만 의미있음)
 * @param {object|null} allowlist - extractAllowlist() 결과 (v1 또는 v2)
 * @param {object|null} registry  - Query Registry (Stage 3)
 * @param {object|null} policy    - normalizePolicyConfig() 결과 (Stage 1/2)
 * @param {object|null} authz     - normalizeAuthorizationConfig() 결과 (Stage 4)
 */
export function workerDb(database, allowlist = null, registry = null, policy = null, authz = null, replayCfg = null, buildMeta = null, adlCfg = null, capabilityCfg = null, sessionsCfg = null) {
    const d1QueryCode = database === 'd1' ? `
async function executeD1Query(env: Env, sql: string, params: unknown[]): Promise<DbResult> {
  const stmt = _userDbForSql(env, sql).prepare(sql);
  const bound = params.length > 0 ? stmt.bind(...params) : stmt;
  const result = await bound.all();
  return {
    rows: (result.results || []).map((r) => JSON.stringify(r)),
    affected: result.meta?.changes ?? 0,
    lastInsertId: result.meta?.last_row_id ?? 0,
  };
}
` : `
async function executeD1Query(env: Env, sql: string, params: unknown[]): Promise<DbResult> {
  throw new Error('서버리스 모드에서는 Cloudflare D1만 지원됩니다.');
}
`;

    // ── SQL Allowlist 임베드 ──────────────────────────────────
    //   빌드 타임에 생성된 sql-allowlist.json 내용을 소스에 직접
    //   박아넣음. D1 왕복 제거 + 배포 원자성 확보.
    //   allowlist === null 인 경우 (dok create 초기 생성) 자리만 마련.
    const allowlistEmbedded = allowlist && Array.isArray(allowlist.tables)
        ? JSON.stringify(allowlist)
        : 'null';

    // ── Query Registry 임베드 (Stage 3) ──────────────────────
    //   빌드 타임에 수집된 queryId → SQL 매핑.
    //   registry === null 인 경우 (dok create 초기 생성) placeholder.
    //   strict 모드에서는 레지스트리 없으면 모든 queryId 쿼리 거부 (fail-closed).
    const registryEmbedded = registry && registry.queries
        ? JSON.stringify(registry)
        : 'null';

    // ── Tenant Policy 임베드 (Stage 1/2, opt-in) ──────────────
    //   policy === null 또는 enabled === false → 'off' 모드로 강제.
    //   'verify' — SQL 이 테넌트 조건을 갖췄는지 검증 (없으면 403)
    //   'inject' — verify 실패시 자동 주입 (v5.2)
    //   문서: docs/design/TENANT_POLICY.md
    const policyEmbedded = policy && policy.enabled
        ? JSON.stringify(policy)
        : 'null';

    // ── Authorization Policy 임베드 (Stage 4, opt-in) ──────────
    //   authz === null 또는 enabled === false → 인가 검사 건너뜀.
    //   규칙이 정의된 연산/테이블에 한해 JWT 서명 검증 + role 체크를 수행합니다.
    //   dokkebi.config.js 의 authorization 섹션 → normalizeAuthorizationConfig()
    //   → 여기 삽입. 문서: docs/design/AUTHORIZATION.md
    const authzEmbedded = authz && authz.enabled
        ? JSON.stringify(authz)
        : 'null';

    // ── Replay 방어 설정 임베드 ────────────────────────────────
    //   security.replay 는 opt-out 불가(보안 필수). 값만 조정 가능:
    //     - timestampWindowMs: 클라↔서버 허용 시계 오차 (기본 5초)
    //     - nonceTtlMs:        nonce 보존 수명 (기본 35초)
    //   normalizeReplayConfig() 에서 안전 범위로 clamp 된 상태로 들어옴.
    const replayEmbedded = JSON.stringify(replayCfg || {
        timestampWindowMs: 5_000,
        nonceTtlMs: 35_000,
        maxEnvelopeBytes: 512 * 1024,
    });

    // Phase 1-③ 빌드 메타데이터 embed — 공급망 tripwire.
    const buildMetaEmbedded = JSON.stringify(buildMeta || {});

    // Phase 3 (Active Defense Layer) embed — Lazy Cron + Blacklist/Risk lookup.
    //   adlCfg === null 또는 enabled === false 인 경우 모든 ADL 코드 경로가 no-op.
    //   하위호환: 기존 빌드 산출물에 영향 없음.
    const adlEmbedded = JSON.stringify(adlCfg && adlCfg.enabled ? adlCfg : { enabled: false });

    // ── Signed Unlock Token capability gates (opt-in) ─────────
    //   security.capabilities.enabled === true 일 때만 feature policy 와
    //   Worker-only HMAC secret 으로 짧은 수명 실행 허가 토큰을 발급한다.
    const capabilityEmbedded = JSON.stringify(capabilityCfg && capabilityCfg.enabled ? capabilityCfg : { enabled: false });

    // Phase B — sharding placeholder (B-1 단계: 단일 D1 폴백만, B-2 에서 샤딩값 주입)
    const internalBinding = 'DB';
    const shardBindings = '[]';

    // Phase B-3 — D1 Sessions opt-in (database.sessions: true | { mode })
    //   sessionsCfg 가 비어있거나 { enabled:false } 면 비활성. 기본 폴백: 비활성.
    const _sess = sessionsCfg && typeof sessionsCfg === 'object'
        ? { enabled: !!sessionsCfg.enabled, mode: sessionsCfg.mode === 'first-primary' ? 'first-primary' : 'first-unconstrained' }
        : { enabled: false, mode: 'first-unconstrained' };
    const sessionsEmbedded = JSON.stringify(_sess);

    return renderTemplate('worker/db.ts.tpl', [
        { find: '/* __DOKKEBI_PH_D1_QUERY__ */', replace: d1QueryCode },
        { find: '__DOKKEBI_PH_REPLAY__',     replace: replayEmbedded },
        { find: '__DOKKEBI_PH_BUILD_META__', replace: buildMetaEmbedded },
        { find: '__DOKKEBI_PH_CAPABILITY__', replace: capabilityEmbedded },
        { find: '__DOKKEBI_PH_ADL__',        replace: adlEmbedded },
        { find: '__DOKKEBI_PH_ALLOWLIST__',  replace: allowlistEmbedded },
        { find: '__DOKKEBI_PH_REGISTRY__',   replace: registryEmbedded },
        { find: '__DOKKEBI_PH_POLICY__',     replace: policyEmbedded },
        { find: '__DOKKEBI_PH_AUTHZ__',      replace: authzEmbedded },
        { find: '__DOKKEBI_PH_INTERNAL_BINDING__', replace: internalBinding },
        { find: '__DOKKEBI_PH_SHARD_BINDINGS__',   replace: shardBindings },
        { find: '__DOKKEBI_PH_SESSIONS__',         replace: sessionsEmbedded },
    ]);
}


export function workerLog() {
    return renderTemplate('worker/log.ts.tpl', [..._PHASE_B_PH_INTERNAL]);
}
export function workerAdmin(projectName = 'dokkebi', securitySummary = null, panelIpGuard = null) {
    const summaryEmbedded = JSON.stringify(securitySummary || {
        coverage: { score: 0, weights: {}, enabled: {} },
        buildMeta: {},
        replay: {},
    });
    const panelIpGuardEnabled = !!(panelIpGuard?.enabled);
    return renderTemplate('worker/admin.ts.tpl', [
        { find: '"__DOKKEBI_PLACEHOLDER_SUMMARY__"', replace: summaryEmbedded },
        { find: '__DOKKEBI_PLACEHOLDER_PROJECT__', replace: String(projectName) },
        ...(panelIpGuardEnabled
            ? [{ find: '_PANEL_IP_GUARD_ENABLED = false', replace: '_PANEL_IP_GUARD_ENABLED = true' }]
            : []),
        ..._PHASE_B_PH_INTERNAL,
    ]);
}


/**
 * 어드민 API 캐치올 핸들러
 * Cloudflare Pages 서브패스 라우팅:
 *   worker/api/_dokkebi/_panel/[[path]].ts → /api/_dokkebi/_panel/*
 *   (auth, api/overview, api/errors, api/security, api/requests)
 */
export function workerAdminApi(projectName = 'dokkebi', securitySummary = null, panelIpGuard = null) {
    const summaryEmbedded = JSON.stringify(securitySummary || {
        coverage: { score: 0, weights: {}, enabled: {} },
        buildMeta: {},
        replay: {},
    });
    const panelIpGuardEnabled = !!(panelIpGuard?.enabled);
    return renderTemplate('worker/admin-api.ts.tpl', [
        { find: '__DOKKEBI_PH_SUMMARY__',     replace: summaryEmbedded },
        { find: '__DOKKEBI_PH_PANEL_GUARD__', replace: panelIpGuardEnabled ? 'true' : 'false' },
        { find: '__DOKKEBI_PH_PROJECT__',     replace: String(projectName) },
        ..._PHASE_B_PH_INTERNAL,
    ]);
}


function workerTsconfig() {
    return JSON.stringify({
        compilerOptions: {
            target: 'ES2022',
            module: 'ESNext',
            moduleResolution: 'bundler',
            strict: true,
            types: ['@cloudflare/workers-types'],
            lib: ['ES2022'],
        },
        include: ['**/*.ts'],
    }, null, 2);
}

function wranglerToml(name, database) {
    const d1Section = database === 'd1' ? `
[[d1_databases]]
binding = "DB"
database_name = "YOUR_D1_DATABASE_NAME"  # .env의 D1_DATABASE_NAME과 동일하게
database_id = "YOUR_D1_DATABASE_ID"      # .env의 D1_DATABASE_ID와 동일하게
` : '';

    return `# wrangler.toml — Cloudflare Pages 배포 설정
# dok deploy 실행 시 자동으로 사용됩니다.

name = "${name}"
compatibility_date = "2024-09-23"
pages_build_output_dir = "dist"
${d1Section}
# Worker Secrets (민감 정보) — dok deploy 가 자동으로 등록합니다:
#   DOKKEBI_SERVER_JWK     — ECDH P-256 서버 개인키 (JWK 형식)
#   DOKKEBI_SESSION_SECRET — 세션 서명키 (32바이트 Hex)
`;
}

function readme(name, frontend, database, proxyMode = 'server') {
    const dbNames = { d1: 'Cloudflare D1', supabase: 'Supabase', appwrite: 'Appwrite' };
    const feNames = { react: 'React (TypeScript)', vue: 'Vue 3 (TypeScript)' };

    const isServerless = proxyMode === 'serverless';
    const proxyLabel = isServerless ? 'Cloudflare Pages Functions (서버리스)' : 'dok serve (Node.js 서버)';

    const startSection = isServerless
        ? '# 5. Cloudflare Pages 배포\nnpm run deploy   # = dok deploy\n\n# 서버리스 로컬 시뮬레이션\nwrangler pages dev dist/\n'
        : '# 5. 빌드 결과 서빙 (DB 프록시 포함)\nnpm run serve    # = dok serve\n';

    const workerSection = isServerless
        ? '├── worker/             ← Cloudflare Pages Functions\n│   └── api/_dokkebi/   ← handshake.ts / db.ts (DB 프록시)\n├── wrangler.toml\n'
        : '';

    const dbSpecificEnv = dbEnvKeyReference(database, isServerless);
    const cloudflareSection = isServerless ? cloudflareGuide(database) : '';
    const webhookSection = isServerless ? lemonSqueezyWebhookGuide() : '';

    return `# ${name}

> dokkebi — Serverless Client Backend Framework (QuickJS WASM)
>
> 자세한 보안 모델은 \`SECURITY.md\`, AI/Agent 작업 규칙은 \`AGENTS.md\` 참조.

## AI / Vibe Coding 시 반드시

- Cursor / Claude Code / Copilot 등으로 작업할 때, 시작 전에 **\`AGENTS.md\`를 먼저 읽고**
  그 안에 적힌 규칙(컨트롤러 분리, 신뢰 경계, dokkebi runtime API 사용 패턴 등)을
  지킨 채 코드를 만들도록 지시할 것.
- 보안 결정(인증/인가/SQL/세션)은 \`SECURITY.md\` 를 근거로 변경. 임의로 약화 금지.
- 새 라우트/모델/마이그레이션 추가 후엔 \`dok build\` 가 통과해야 PR/배포 진행.

## 스택

| 항목 | 값 |
|------|----|
| 프론트엔드 | ${feNames[frontend]} |
| 데이터베이스 | ${dbNames[database]} |
| 백엔드 런타임 | QuickJS WASM (브라우저 내 실행) |
| 프록시 모드 | ${proxyLabel} |

## 빠르게 시작

\`\`\`bash
# 1. 의존성
npm install

# 2. 개발 모드 (DB 자격증명 없으면 로컬 DB 모드 자동)
npm run dev

# 3. 외부 DB 사용 시
cp .env.example .env   # 값 채우고
dok migrate

# 4. 프로덕션 빌드
npm run build

${startSection}\`\`\`

> .env에 DB 자격증명이 비어 있으면 브라우저 내 sql.js(IndexedDB/OPFS)에 데이터를 저장합니다.
> 자격증명을 채우면 자동으로 외부 DB + 프록시 모드로 전환됩니다.

## 프로젝트 구조

\`\`\`
${name}/
├── backend/
│   ├── controllers/    ← Guest-side (QuickJS WASM)
│   ├── models/         ← Host-side (dokkebi-dsl)
│   ├── middleware/
│   ├── db/             ← 어댑터 + 마이그레이션
│   └── wit/            ← WIT 인터페이스
├── frontend/           ← ${feNames[frontend]}
${workerSection}├── dokkebi.config.js   ← 보안/배포/DB 설정
├── .env / .env.example
├── AGENTS.md           ← AI 작업 가이드
├── SECURITY.md         ← 보안 모델·한계
└── package.json
\`\`\`

## dok 커맨드

| 커맨드 | 용도 |
|--------|------|
| \`dok create\` | 새 프로젝트 스캐폴딩 |
| \`dok dev\` | 핫리로드 개발 서버 (WASM + 프록시 동시) |
| \`dok build\` | 컨트롤러 번들 + 부트스트랩 주입 |
| \`dok serve\` | 빌드 결과를 직접 서빙 (server 모드) |
| \`dok deploy\` | Cloudflare Pages + Secrets 자동 배포 (serverless 모드) |
| \`dok migrate\` | DB 마이그레이션 적용 |
| \`dok security\` | 보안 옵션 인터랙티브 점검 |
| \`dok update\` | 프레임워크 파일·런타임 업데이트 |
| \`dok lang\` | CLI 언어 변경 |

## dokkebi.config.js — 주요 키

\`\`\`js
// dokkebi.config.js (발췌)
export default {
  proxyMode: '${proxyMode}',           // 'server' | 'serverless'

  // ── 보안 옵션 (자세한 영향은 SECURITY.md / docs/SECURITY_OPTIONS.md) ──
  security: {
    bytecodeMode: true,             // QuickJS bytecode 로 묶어 노출 최소화
    bytecodeEncrypted: true,        // 번들 AES-256-GCM 암호화 (권장: 운영)
    encryptedTextMode: false,       // text bundle 모드(디버깅용). 운영은 false.
    queryLearn: false,              // SQL allowlist 학습 모드 (개발 단계만)
    panelIpGuard: true,             // /_dokkebi/_panel 관제 IP 화이트리스트
    callerCheck: 'audit',           // 'off' | 'audit' | 'block' — XSS·DevTools 호출 가드
    capabilities: { enabled: false },  // 라우트 단위 capability unlock
    payloadWire: { rotation: { enabled: false }, pow: { enabled: false } },
    authSession: { enabled: true, debounceMs: 2000 },
    logging: { level: 'error' },    // remote 로그 수집 최소 레벨
  },

  // ── DB 설정 (.env 와 함께 동작) ──
  db: { type: '${database}' },

  // ── 배포 ──
  deploy: {
    cloudflare: { project: '${name}' },  // serverless 모드일 때
    frontend: 'cloudflare-pages',        // 'cloudflare-pages' | 'cloudflare-r2' | 's3'
  },
};
\`\`\`

## .env / Secret 키

\`.env\` 의 모든 값은 \`dok deploy\` 가 Cloudflare Pages Secret 으로 자동 동기화합니다.
**브라우저로 직접 노출되지 않습니다** (host 클로저에 보관 + opaque handle).

${dbSpecificEnv}

공통 secret:

- \`DOKKEBI_JWT_SECRET\` — JWT 서명키 (필수, 32B+ 무작위)
- \`DOKKEBI_SESSION_SECRET\` — 세션 시크릿 (자동 생성/순환)
- \`DOKKEBI_CAPABILITY_SECRET\` — \`security.capabilities.enabled\` 시 필요
- \`DOKKEBI_ADMIN_PASSWORD\` — \`/_dokkebi/_panel\` 관제 (선택)
- \`DOKKEBI_PANEL_ALLOWED_IPS\` — 관제 IP/CIDR allowlist
- \`LEMON_SQUEEZY_WEBHOOK_SECRET\` — 결제 웹훅 예제 사용 시

> \`.env\` 는 **반드시 \`.gitignore\` 에 유지** (생성 시 자동 포함).
${cloudflareSection}
## 배포 시 주의사항

1. **시크릿 점검**: \`DOKKEBI_JWT_SECRET\` 등이 진짜 무작위 32바이트 이상인지 확인.
2. **운영 보안 옵션**: \`bytecodeMode\` + \`bytecodeEncrypted\` 켜고 \`encryptedTextMode: false\`,
   \`queryLearn: false\`, \`callerCheck: 'block'\` 이상 권장.
3. **관제 패널**: \`panelIpGuard: true\` + \`DOKKEBI_PANEL_ALLOWED_IPS\` 미설정이면 사실상 무방어.
4. **마이그레이션**: \`dok migrate\` 는 멱등하지만 운영 DB 대상 실행 전 반드시 백업.
5. **DB 자격증명 회전**: 회전 후 \`dok deploy\` 한 번 더 — Secret 전파 ≈15초.
6. **로그 수집 레벨**: \`logging.level\` 을 운영에선 \`error\` 또는 \`warn\` 으로 유지(과도한 수집 방지).
7. **attribution / 라이선스 표시**: 콘솔 배너 및 LICENSE 표시는 제거하지 말 것 (ELv2 조항).
${webhookSection}
## 아키텍처 개요

브라우저가 페이지를 열면:

1. 부트스트랩이 QuickJS WASM VM 로드
2. \`backend/controllers/\` 가 WASM 내부에서 실행
3. DB 요청 → AES-256-GCM + HMAC + Nonce 로 암호화하여 프록시 전송
4. 프록시(${isServerless ? 'Cloudflare Pages Function' : 'dok serve'})가 실제 쿼리 → 암호화 응답
5. 프론트는 \`import { dokkebi } from './lib/dokkebi'\` 로 호출 (\`useDokkebi()\` 훅 제공)

상세 보안 모델·한계는 \`SECURITY.md\` 를 보세요.
`;
}

function dbEnvKeyReference(database, isServerless) {
    if (database === 'd1') {
        return `**Cloudflare D1 (.env)**

- \`D1_ACCOUNT_ID\` — Cloudflare 대시보드 우측 사이드바
- \`D1_DATABASE_ID\` — Workers & Pages → D1 → DB 상세
- \`D1_API_TOKEN\` — My Profile → API Tokens (아래 권한 가이드)
- \`D1_DATABASE_NAME\` — wrangler 바인딩 이름 (${isServerless ? 'wrangler.toml과 일치' : '선택'})`;
    }
    if (database === 'supabase') {
        return `**Supabase (.env)**

- \`SUPABASE_URL\` — Project Settings → API → Project URL
- \`SUPABASE_SERVICE_ROLE_KEY\` — Project Settings → API (서버 전용 secret)
- \`SUPABASE_ANON_KEY\` — 공개 키 (RLS 정책과 함께 사용)`;
    }
    if (database === 'appwrite') {
        return `**Appwrite (.env)**

- \`APPWRITE_ENDPOINT\` — 예: https://cloud.appwrite.io/v1
- \`APPWRITE_PROJECT_ID\`
- \`APPWRITE_API_KEY\` — 필요한 scope만 허용 (databases.read/write 등)
- \`APPWRITE_DATABASE_ID\``;
    }
    return '';
}

function cloudflareGuide(database) {
    const d1Block = database === 'd1' ? `
### Cloudflare D1 만들기

1. **D1 데이터베이스 생성**: \`wrangler d1 create ${'`'}<db-name>${'`'}\`
   또는 대시보드 → Workers & Pages → D1 → Create database.
2. 출력의 \`database_id\` 를 \`.env\` 의 \`D1_DATABASE_ID\` 에 넣기.
3. \`wrangler.toml\` 의 \`[[d1_databases]]\` 블록(이미 생성됨)도 같은 ID/이름으로 채워져 있어야 함.
4. \`dok migrate\` 로 스키마 적용.

### D1_API_TOKEN 권한

My Profile → **API Tokens** → **Create Token** → "Create Custom Token":

| Scope | Permission |
|-------|-----------|
| Account → \`Cloudflare D1\` | **Edit** |
| Account → \`Workers Scripts\` | Edit (선택, 자동 배포 시) |
| Account → \`Workers KV Storage\` | Read (선택) |
| Account Resources | 해당 계정만 |
| Account → \`Pages\` | **Edit** (\`dok deploy\` 사용 시 필수) |
| Account → \`User Details\` | Read |

> Account ID 는 우측 사이드바에 표기. **TTL 은 짧게 설정**하고 회전 권장.
` : '';

    return `
## Cloudflare 가입 후 키 생성 가이드 (serverless 모드)

1. **Cloudflare 계정** 만든 뒤 https://dash.cloudflare.com 접속.
2. (필요 시) **Workers & Pages** 활성화 — 무료 플랜으로도 충분.
${d1Block}
### Cloudflare Pages 프로젝트

- \`dok deploy\` 가 \`wrangler pages deploy\` 를 호출합니다.
- 첫 배포 시 \`wrangler pages project create <name>\` 으로 프로젝트 미리 생성하거나
  대시보드에서 동일 이름의 Pages 프로젝트를 만든 뒤, \`dokkebi.config.js\` 의
  \`deploy.cloudflare.project\` 와 이름을 맞춥니다.

### CI / 별도 머신에서 배포할 때

배포 머신에 다음 환경 변수만 있으면 됩니다.

- \`CLOUDFLARE_API_TOKEN\` — 위 D1_API_TOKEN과 같은 값 또는 별도 토큰(Pages Edit 포함)
- \`CLOUDFLARE_ACCOUNT_ID\`

> 토큰을 GitHub Secrets 등에 저장하고, 코드/로그에 절대 노출하지 말 것.
`;
}

function lemonSqueezyWebhookGuide() {
    return `
## 결제 웹훅 (Lemon Squeezy 예제)

- 파일: \`worker/api/webhooks/lemonsqueezy.ts\`
- 엔드포인트: \`POST /api/webhooks/lemonsqueezy\`
- 검증: \`X-Signature\` HMAC-SHA256, \`event_id\` 멱등 처리.

설정:

1. \`.env\` 에 \`LEMON_SQUEEZY_WEBHOOK_SECRET\` 추가
2. \`dok deploy\` (Secret 자동 등록)
3. Lemon Squeezy 대시보드 → Webhook URL 에 배포 주소 등록
4. 템플릿 TODO 위치에 비즈니스 로직 작성
`;
}

function tsconfig() {
    return JSON.stringify(
        {
            compilerOptions: {
                target: 'ES2020',
                module: 'ESNext',
                moduleResolution: 'bundler',
                strict: true,
                esModuleInterop: true,
                skipLibCheck: true,
                types: ['vite/client'],
                // dokkebi:runtime / dokkebi:dsl 은 esbuild external 처리
                // 타입은 backend/types/dokkebi.d.ts 에서 선언
                paths: {
                    'dokkebi:runtime': ['./backend/types/dokkebi.d.ts'],
                    'dokkebi-dsl': ['./backend/types/dokkebi.d.ts'],
                },
            },
            include: [
                'backend/**/*.ts',
                'frontend/src/**/*.ts',
                'frontend/src/**/*.tsx',
            ],
            exclude: ['node_modules', 'dist'],
        },
        null,
        2
    );
}

function workerLemonSqueezyWebhookTemplate() {
    return renderTemplate('worker/webhooks/lemonsqueezy.ts.tpl', [..._PHASE_B_PH_INTERNAL]);
}

// ─────────────────────────────────────────────────────────────
// 백엔드 파일 템플릿
// ─────────────────────────────────────────────────────────────

function witFile() {
    return renderTemplate('backend/wit-interface.tpl', []);
}

function modelsIndex() {
    return renderTemplate('backend/models-index.ts.tpl', []);
}

function controllersIndex(database, withAuth = true) {
    return `// backend/controllers/index.ts
// 🏮 dokkebi 쇼핑몰 — Guest-side Controller 레이어

import { router, use, cors } from 'dokkebi:runtime';

use(cors({ origin: '*' }));
// logger()는 기본 비활성화 — _middleware.ts(서버 사이드)가 이미 동일 데이터를 기록하므로
// WASM 내부에서 추가로 사용 시 DB 호출 2배 + _dokkebi_requests 중복 집계 발생
// use(logger());

import './product.controller.js';
import './order.controller.js';
import './auth.controller.js';

router.get('/api/health', (ctx) => {
  return ctx.json({
    status: 'ok',
    runtime: 'QuickJS WASM',
    app: 'dokkebi-shop',
    db: '${database}',
    timestamp: new Date().toISOString(),
  });
});

export { router };
`;
}

function productController() {
    return renderTemplate('backend/controllers/product.ts.tpl', []);
}

function orderController() {
    return renderTemplate('backend/controllers/order.ts.tpl', []);
}

function authController(database) {
    return `// backend/controllers/auth.controller.ts
// 인증 컨트롤러 (JWT 기반)

import { router, db, signJwt, verifyJwt } from 'dokkebi:runtime';
import { users } from '../models/index.js';
import { eq } from 'dokkebi-dsl';

const JWT_SECRET = globalThis.__dokkebi_host__?.kv.kvGet('DOKKEBI_JWT_SECRET')
  || globalThis.__dokkebi_host__?.kv.kvGet('JWT_SECRET')
  || 'change-this-in-production';

// POST /api/auth/register — 회원가입
router.post('/api/auth/register', async (ctx) => {
  const { name, email, password } = ctx.body || {};
  if (!name || !email || !password) {
    return ctx.badRequest('name, email, password는 필수입니다.');
  }

  // 이미 존재하는 이메일 확인
  const { rows: existing } = await db
    .select(users, ['id'])
    .where(eq(users.email, email))
    .limit(1)
    .exec();

  if (existing.length > 0) {
    return ctx.json({ error: '이미 사용 중인 이메일입니다.' }, 409);
  }

  // 비밀번호 해시 (host-crypto 사용)
  const host = globalThis.__dokkebi_host__;
  const passBytes = Array.from(new TextEncoder().encode(password));
  const hashBytes = await host.crypto.hashSha256(passBytes);
  const passwordHash = btoa(String.fromCharCode(...hashBytes));

  const { rows } = await db
    .insert(users, { name, email, passwordHash, role: 'user' })
    .returning()
    .exec();

  const token = await signJwt({ userId: rows[0]?.id, email, role: 'user' }, JWT_SECRET);
  return ctx.json({ token, user: { id: rows[0]?.id, name, email } }, 201);
});

// POST /api/auth/login — 로그인
router.post('/api/auth/login', async (ctx) => {
  const { email, password } = ctx.body || {};
  if (!email || !password) return ctx.badRequest('email, password는 필수입니다.');

  const { rows } = await db
    .select(users)
    .where(eq(users.email, email))
    .limit(1)
    .exec();

  if (rows.length === 0) return ctx.unauthorized('이메일 또는 비밀번호가 올바르지 않습니다.');

  const user = rows[0];
  const host = globalThis.__dokkebi_host__;
  const passBytes = Array.from(new TextEncoder().encode(password));
  const hashBytes = await host.crypto.hashSha256(passBytes);
  const passwordHash = btoa(String.fromCharCode(...hashBytes));

  if (user.password_hash !== passwordHash) {
    return ctx.unauthorized('이메일 또는 비밀번호가 올바르지 않습니다.');
  }

  const token = await signJwt(
    { userId: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    86400 // 24시간
  );

  return ctx.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

// GET /api/auth/me — 현재 사용자 정보
router.get('/api/auth/me', async (ctx) => {
  const authHeader = ctx.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) return ctx.unauthorized();

  try {
    const payload = await verifyJwt(authHeader.slice(7), JWT_SECRET);
    const { rows } = await db
      .select(users, ['id', 'name', 'email', 'role'])
      .where(eq(users.id, payload.userId))
      .limit(1)
      .exec();

    if (rows.length === 0) return ctx.notFound('사용자를 찾을 수 없습니다.');
    return ctx.json({ user: rows[0] });
  } catch (e) {
    return ctx.unauthorized(e.message);
  }
});
`;
}

function middlewareIndex(withAuth) {
    return `// backend/middleware/index.ts
// 미들웨어 모음

export { cors, logger, jwtAuth } from 'dokkebi:runtime';
${withAuth ? `
// 커스텀 인증 미들웨어 예시
export function requireAuth(ctx: any) {
  const token = ctx.headers['authorization']?.replace('Bearer ', '');
  if (!token) return ctx.unauthorized('로그인이 필요합니다.');
  return null;
}
` : ''}
`;
}

function dbAdapter(database) {
    return `// backend/db/index.ts
// DB 어댑터 초기화 (dokkebi-dsl 연결)
// 실제 DB 연결은 Host-side에서 처리됩니다.
// 이 파일은 스키마 export만 담당합니다.

export * from '../models/index.js';
`;
}

/**
 * dokkebi 시스템 테이블 DDL 반환 (업데이트 시 신규 테이블 추가용)
 * 각 테이블의 이름과 해당 CREATE TABLE SQL을 맵 형태로 반환
 */
export function systemTableSql() {
    return {
        '_dokkebi_errors': `-- dokkebi 에러 자동 수집 테이블
CREATE TABLE IF NOT EXISTS "_dokkebi_errors" (
  "id"      TEXT NOT NULL PRIMARY KEY,
  "ts"      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "source"  TEXT NOT NULL DEFAULT 'wasm',
  "level"   TEXT NOT NULL DEFAULT 'error',
  "message" TEXT NOT NULL,
  "stack"   TEXT,
  "path"    TEXT,
  "method"  TEXT,
  "context" TEXT
);`,
        '_dokkebi_requests': `-- dokkebi 요청 로그 테이블 (관제 어드민 통계용)
CREATE TABLE IF NOT EXISTS "_dokkebi_requests" (
  "id"          TEXT NOT NULL PRIMARY KEY,
  "ts"          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "method"      TEXT NOT NULL DEFAULT '',
  "path"        TEXT NOT NULL DEFAULT '',
  "status"      INTEGER NOT NULL DEFAULT 0,
  "duration_ms" INTEGER NOT NULL DEFAULT 0,
  "ip"          TEXT NOT NULL DEFAULT ''
);`,
        '_dokkebi_security': `-- dokkebi 보안 이벤트 테이블 (관제 어드민 해킹 탐지용)
CREATE TABLE IF NOT EXISTS "_dokkebi_security" (
  "id"     TEXT NOT NULL PRIMARY KEY,
  "ts"     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "type"   TEXT NOT NULL,
  "ip"     TEXT NOT NULL DEFAULT '',
  "path"   TEXT NOT NULL DEFAULT '',
  "detail" TEXT NOT NULL DEFAULT ''
);`,
        '_dokkebi_blacklist': `-- dokkebi 능동방어(ADL) 블랙리스트 테이블 (Phase 3-A)
-- 핫패스에서 LRU 캐시(60s) → D1 폴백으로 조회. expires_at 으로 자동 만료.
CREATE TABLE IF NOT EXISTS "_dokkebi_blacklist" (
  "key"        TEXT NOT NULL,
  "kind"       TEXT NOT NULL,                       -- 'ip' | 'sid' | 'ipua'
  "reason"     TEXT,
  "score"      REAL DEFAULT 0,
  "expires_at" INTEGER NOT NULL,
  "created_at" INTEGER NOT NULL,
  PRIMARY KEY ("key","kind")
);
CREATE INDEX IF NOT EXISTS "_dokkebi_bl_exp" ON "_dokkebi_blacklist"("expires_at");`,
        '_dokkebi_risk_score': `-- dokkebi 능동방어(ADL) 세션 risk_score 테이블 (Phase 3-A)
-- 0~1 점수. riskBlockThreshold(기본 0.85) 이상이면 enforce 모드에서 즉시 차단.
CREATE TABLE IF NOT EXISTS "_dokkebi_risk_score" (
  "sid"        TEXT NOT NULL PRIMARY KEY,
  "score"      REAL NOT NULL,
  "factors"    TEXT,
  "updated_at" INTEGER NOT NULL
);`,
        '_dokkebi_adl_state': `-- dokkebi 능동방어(ADL) 메타 상태 테이블 (Phase 3-A)
-- key 'last_run' 으로 분석 last_run timestamp 추적 → Lazy Cron 분산락 구현.
CREATE TABLE IF NOT EXISTS "_dokkebi_adl_state" (
  "key"        TEXT NOT NULL PRIMARY KEY,
  "value"      TEXT,
  "updated_at" INTEGER NOT NULL
);`,
        '_dokkebi_adl_suspicion': `-- dokkebi 능동방어(ADL) 의심 목록 — monitor 모드에서 자동 분석만 적재 (미들웨어 차단 안 함)
CREATE TABLE IF NOT EXISTS "_dokkebi_adl_suspicion" (
  "key"        TEXT NOT NULL,
  "kind"       TEXT NOT NULL,
  "reason"     TEXT,
  "score"      REAL DEFAULT 0,
  "expires_at" INTEGER NOT NULL,
  "created_at" INTEGER NOT NULL,
  PRIMARY KEY ("key","kind")
);
CREATE INDEX IF NOT EXISTS "_dokkebi_susp_exp" ON "_dokkebi_adl_suspicion"("expires_at");`,
    };
}

function initialMigration(database) {
    if (database === 'appwrite') {
        return `-- Appwrite는 NoSQL Document DB입니다.
-- Appwrite Console에서 Collection을 수동으로 생성하세요.
-- https://cloud.appwrite.io
--
-- 필요한 Collection:
--   products: id, name, description, price, stock, category, image_url, created_at
--   orders: id, customer_name, customer_email, total_price, status, created_at
--   order_items: id, order_id, product_id, product_name, price, quantity
`;
    }

    return `-- 🏮 dokkebi 쇼핑몰 초기 스키마
-- dok migrate 실행 시 자동 적용됩니다.

CREATE TABLE IF NOT EXISTS "users" (
  "id"            TEXT NOT NULL PRIMARY KEY,
  "name"          TEXT NOT NULL,
  "email"         TEXT NOT NULL UNIQUE,
  "password_hash" TEXT NOT NULL,
  "role"          TEXT NOT NULL DEFAULT 'user',
  "created_at"    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "products" (
  "id"          TEXT NOT NULL PRIMARY KEY,
  "name"        TEXT NOT NULL,
  "description" TEXT NOT NULL DEFAULT '',
  "price"       INTEGER NOT NULL DEFAULT 0,
  "stock"       INTEGER NOT NULL DEFAULT 0,
  "category"    TEXT NOT NULL DEFAULT 'general',
  "image_url"   TEXT NOT NULL DEFAULT '',
  "created_at"  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "orders" (
  "id"             TEXT NOT NULL PRIMARY KEY,
  "customer_name"  TEXT NOT NULL,
  "customer_email" TEXT NOT NULL,
  "total_price"    INTEGER NOT NULL DEFAULT 0,
  "status"         TEXT NOT NULL DEFAULT 'pending'
                   CHECK("status" IN ('pending','paid','shipped','cancelled')),
  "created_at"     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "order_items" (
  "id"           TEXT NOT NULL PRIMARY KEY,
  "order_id"     TEXT NOT NULL,
  "product_id"   TEXT NOT NULL,
  "product_name" TEXT NOT NULL,
  "price"        INTEGER NOT NULL,
  "quantity"     INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY ("order_id")   REFERENCES "orders"("id"),
  FOREIGN KEY ("product_id") REFERENCES "products"("id")
);

-- 샘플 상품 데이터
INSERT OR IGNORE INTO "products" ("id","name","description","price","stock","category","image_url") VALUES
  ('prod-001','샘플 상품 A','첫 번째 샘플 상품입니다.',29000,100,'general','https://placehold.co/400x300/6c5ce7/white?text=Product+A'),
  ('prod-002','샘플 상품 B','두 번째 샘플 상품입니다.',19000,50,'general','https://placehold.co/400x300/00b894/white?text=Product+B'),
  ('prod-003','샘플 상품 C','세 번째 샘플 상품입니다.',9000,200,'general','https://placehold.co/400x300/fd79a8/white?text=Product+C');

-- dokkebi 에러 자동 수집 테이블
-- WASM 백엔드에서 발생한 모든 에러가 자동으로 기록됩니다.
CREATE TABLE IF NOT EXISTS "_dokkebi_errors" (
  "id"      TEXT NOT NULL PRIMARY KEY,
  "ts"      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "source"  TEXT NOT NULL DEFAULT 'wasm',
  "level"   TEXT NOT NULL DEFAULT 'error',
  "message" TEXT NOT NULL,
  "stack"   TEXT,
  "path"    TEXT,
  "method"  TEXT,
  "context" TEXT
);

-- dokkebi 요청 로그 테이블 (관제 어드민 통계용)
CREATE TABLE IF NOT EXISTS "_dokkebi_requests" (
  "id"          TEXT NOT NULL PRIMARY KEY,
  "ts"          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "method"      TEXT NOT NULL DEFAULT '',
  "path"        TEXT NOT NULL DEFAULT '',
  "status"      INTEGER NOT NULL DEFAULT 0,
  "duration_ms" INTEGER NOT NULL DEFAULT 0,
  "ip"          TEXT NOT NULL DEFAULT ''
);

-- dokkebi 보안 이벤트 테이블 (관제 어드민 해킹 탐지용)
CREATE TABLE IF NOT EXISTS "_dokkebi_security" (
  "id"     TEXT NOT NULL PRIMARY KEY,
  "ts"     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "type"   TEXT NOT NULL,
  "ip"     TEXT NOT NULL DEFAULT '',
  "path"   TEXT NOT NULL DEFAULT '',
  "detail" TEXT NOT NULL DEFAULT ''
);
`;
}

// ─────────────────────────────────────────────────────────────
// 프론트엔드 파일 템플릿 (공통)
// ─────────────────────────────────────────────────────────────

function frontendPackageJson(name, framework) {
    const deps =
        framework === 'react'
            ? { react: '^18.3.1', 'react-dom': '^18.3.1' }
            : { vue: '^3.4.0' };
    const devDeps =
        framework === 'react'
            ? {
                  '@types/react': '^18.3.1',
                  '@types/react-dom': '^18.3.1',
                  '@vitejs/plugin-react': '^4.3.1',
                  typescript: '^5.5.3',
                  vite: '^5.4.0',
              }
            : {
                  '@vitejs/plugin-vue': '^5.1.2',
                  typescript: '^5.5.3',
                  vite: '^5.4.0',
              };
    return JSON.stringify(
        {
            name: `${name}-frontend`,
            version: '0.1.0',
            private: true,
            type: 'module',
            scripts: {
                dev: 'vite',
                build: 'vite build',
                preview: 'vite preview',
            },
            dependencies: deps,
            devDependencies: devDeps,
        },
        null,
        2
    );
}

function indexHtml(name, framework = 'react') {
    // React → main.tsx / Vue → main.ts
    const entry = framework === 'react' ? '/src/main.tsx' : '/src/main.ts';
    return `<!DOCTYPE html>
<html lang="ko">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${name}</title>
    <!-- dokkebi 부트스트랩은 빌드 시 자동 주입됩니다 -->
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="${entry}"></script>
  </body>
</html>
`;
}

function viteConfigReact() {
    return renderTemplate('frontend/vite.config.react.ts.tpl', []);
}

function viteConfigVue() {
    return renderTemplate('frontend/vite.config.vue.ts.tpl', []);
}

function frontendTsconfig(framework) {
    return JSON.stringify(
        {
            compilerOptions: {
                target: 'ES2020',
                useDefineForClassFields: true,
                lib: ['ES2020', 'DOM', 'DOM.Iterable'],
                module: 'ESNext',
                skipLibCheck: true,
                moduleResolution: 'bundler',
                allowImportingTsExtensions: true,
                resolveJsonModule: true,
                isolatedModules: true,
                noEmit: true,
                strict: true,
                ...(framework === 'react'
                    ? { jsx: 'react-jsx' }
                    : {}),
            },
            include: ['src'],
        },
        null,
        2
    );
}

function useDokkebiHook(framework) {
    if (framework === 'react') {
        return `// frontend/src/composables/useDokkebi.ts
// React 훅 — dokkebi 클라이언트 래퍼
//
// v6.x+ 부터 dokkebi 클라이언트는 window 에 노출되지 않습니다.
// 같은 디렉토리의 ../lib/dokkebi 에서 import 해서 사용하세요.

import { useState, useEffect, useCallback } from 'react';
import { dokkebi } from '../lib/dokkebi';

interface DokkebiResponse {
  ok: boolean;
  status: number;
  body: string;
  json: any;
  error: string | null;
  headers: [string, string][];
}

export function useDokkebi() {
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    dokkebi.ready().then(() => setReady(true)).catch(setError);
  }, []);

  const request = useCallback(
    async <T = any>(method: string, path: string, body?: any, headers?: Record<string, string>): Promise<T> => {
      const res = await dokkebi.request(method, path, body, headers) as DokkebiResponse;
      const data = res.json ?? (res.body ? JSON.parse(res.body) : null);
      if (res.status >= 400) throw new Error((data && data.error) || res.error || '요청 실패');
      return data as T;
    },
    []
  );

  return {
    ready,
    error,
    get:    <T = any>(path: string)             => request<T>('GET',    path),
    post:   <T = any>(path: string, body?: any) => request<T>('POST',   path, body),
    put:    <T = any>(path: string, body?: any) => request<T>('PUT',    path, body),
    delete: <T = any>(path: string)             => request<T>('DELETE', path),
  };
}
`;
    }

    return `// frontend/src/composables/useDokkebi.ts
// Vue 3 Composable — dokkebi 클라이언트 래퍼
//
// v6.x+ 부터 dokkebi 클라이언트는 window 에 노출되지 않습니다.
// 같은 디렉토리의 ../lib/dokkebi 에서 import 해서 사용하세요.

import { ref, onMounted } from 'vue';
import { dokkebi } from '../lib/dokkebi';

interface DokkebiResponse {
  ok: boolean;
  status: number;
  body: string;
  json: any;
  error: string | null;
  headers: [string, string][];
}

export function useDokkebi() {
  const ready = ref(false);
  const error = ref<Error | null>(null);

  onMounted(() => {
    dokkebi.ready()
      .then(() => { ready.value = true; })
      .catch((e: any) => { error.value = e; });
  });

  async function request<T = any>(method: string, path: string, body?: any, headers?: Record<string, string>): Promise<T> {
    const res = await dokkebi.request(method, path, body, headers) as DokkebiResponse;
    const data = res.json ?? (res.body ? JSON.parse(res.body) : null);
    if (res.status >= 400) throw new Error((data && data.error) || res.error || '요청 실패');
    return data as T;
  }

  return {
    ready,
    error,
    get:    <T = any>(path: string)             => request<T>('GET',    path),
    post:   <T = any>(path: string, body?: any) => request<T>('POST',   path, body),
    put:    <T = any>(path: string, body?: any) => request<T>('PUT',    path, body),
    delete: <T = any>(path: string)             => request<T>('DELETE', path),
  };
}
`;
}

// ─────────────────────────────────────────────────────────────
// React 컴포넌트 템플릿
// ─────────────────────────────────────────────────────────────

function reactMain() {
    return renderTemplate('frontend/react/main.tsx.tpl', []);
}

function reactApp(database) {
    return renderTemplate('frontend/react-app.tsx.tpl', []);
}

function reactLogin() {
    return renderTemplate('frontend/react/Login.tsx.tpl', []);
}

function reactDashboard() {
    return renderTemplate('frontend/react/Dashboard.tsx.tpl', []);
}

// ─────────────────────────────────────────────────────────────
// Vue 컴포넌트 템플릿
// ─────────────────────────────────────────────────────────────

function vueMain() {
    return renderTemplate('frontend/vue/main.ts.tpl', []);
}

function vueApp(database) {
    return renderTemplate('frontend/vue-app.vue.tpl', []);
}

function vueLogin() {
    return renderTemplate('frontend/vue/Login.vue.tpl', []);
}

function vueDashboard() {
    return renderTemplate('frontend/vue/Dashboard.vue.tpl', []);
}

export function workerRootMiddleware(database = 'd1') {
    return `// @dokkebi-version: 2
// worker/_middleware.ts
// Cloudflare Pages 루트 미들웨어 — ADL 블랙리스트 + HTML 에 __DOKKEBI_BOOT__ 주입(옵션)
// DOKKEBI_BUNDLE_BOOT_SECRET + __DOKKEBI_BC_KEY__ 와 __DOKKEBI_BC_HASH__(12) 가 있으면
// text/html 응답에 번들 복호 래핑 재료를 삽입하고 Cache-Control: private, no-store 를 설정합니다.

export interface Env {
  DB?: D1Database;
  DOKKEBI_BUNDLE_BOOT_SECRET?: string;
  __DOKKEBI_BC_KEY__?: string;
  __DOKKEBI_BC_HASH__?: string;
}

const _SKIP = ['/_dokkebi/_panel', '/api/billing/lemon-webhook'];

// ── Phase B — internal DB resolver (build-time injected) ─
const _DOKKEBI_INTERNAL_BINDING: string = '__DOKKEBI_PH_INTERNAL_BINDING__' || 'DB';
function _internalDb(env: Env): D1Database {
  const b = (env as any)[_DOKKEBI_INTERNAL_BINDING];
  return (b as D1Database) || (env.DB as D1Database);
}

// __DOKKEBI_SEO__ — Edge SEO Renderer 봇 분기 (frameworks/dokkebi-cli emitEdgeRenderer.js 와 매칭)
const _DOKKEBI_BOT_UA_RE = /(?:googlebot|bingbot|slurp|duckduckbot|yandex(?:bot)?|baiduspider|sogou|exabot|facebot|facebookexternalhit|twitterbot|linkedinbot|slackbot|discordbot|telegrambot|whatsapp|skypeuripreview|applebot|petalbot|naver|yeti|daum|kakao|kagibot|chatgpt-user|gptbot|claudebot|perplexitybot|amazonbot|bytespider|ia_archiver|crawler|spider|bot)/i;

async function _dokkebiSeoTryHandle(request: Request): Promise<Response | null> {
  if (request.method !== 'GET' && request.method !== 'HEAD') return null;
  const ua = request.headers.get('user-agent') || '';
  if (!_DOKKEBI_BOT_UA_RE.test(ua)) return null;
  const url = new URL(request.url);
  if (url.pathname.startsWith('/_dokkebi-seo')) return null;
  if (url.pathname.startsWith('/api/')) return null;
  if (/\\.[a-z0-9]{1,8}(?:$|\\?)/i.test(url.pathname)) return null;
  try {
    const seoUrl = new URL('/_dokkebi-seo' + url.pathname + url.search, request.url);
    const seoRes = await fetch(seoUrl.toString(), {
      headers: { 'x-dokkebi-seo': '1', 'x-original-ua': ua },
      cf: { cacheTtl: 0 },
    } as any);
    if (seoRes.ok) return seoRes;
  } catch (_e) { /* fallback */ }
  return null;
}

const _blCache = new Map<string, { blocked: boolean; until: number }>();
const _CACHE_TTL = 60_000;
const _CACHE_MAX = 2048;

function _prune() {
  if (_blCache.size <= _CACHE_MAX) return;
  const now = Date.now();
  for (const [k, v] of _blCache) {
    if (v.until <= now) _blCache.delete(k);
    if (_blCache.size <= _CACHE_MAX * 0.8) break;
  }
}

async function _isBlocked(db: D1Database, ip: string): Promise<boolean> {
  if (!ip) return false;
  const now = Date.now();
  const cached = _blCache.get(ip);
  if (cached && cached.until > now) return cached.blocked;

  try {
    const r = await db.prepare(
      \`SELECT key FROM "_dokkebi_blacklist" WHERE kind = 'ip' AND key = ? AND expires_at > ? LIMIT 1\`
    ).bind(ip, now).first<{ key: string }>();
    const blocked = !!r;
    _blCache.set(ip, { blocked, until: now + _CACHE_TTL });
    _prune();
    return blocked;
  } catch {
    return false;
  }
}

function relaxCspForCrossOriginEmbed(csp: string): string {
  const s = csp.trim();
  if (!s) return 'frame-ancestors *';
  let out = s.replace(/\\s*;\\s*frame-ancestors\\s+[^;]+/gi, '');
  out = out.replace(/^\\s*frame-ancestors\\s+[^;]+\\s*(;\\s*|$)/i, '');
  out = out.replace(/;\\s*;/g, ';').replace(/^;\\s*|\\s*;$/g, '').trim();
  return out ? out + '; frame-ancestors *' : 'frame-ancestors *';
}

function _isEmbeddableNotoPage(url: URL): boolean {
  const page = url.searchParams.get('page');
  return page === 'embed' || page === 'noto';
}

function _relaxEmbedFrameAncestors(res: Response, url: URL): Response {
  // SPA embed 공유 (?page=embed, ?page=noto) 는 타 사이트 iframe 에서도 표시되어야 함 — _headers 의
  // X-Frame-Options / CSP frame-ancestors 가 SAMEORIGIN 이면 브라우저가 차단함.
  if (!_isEmbeddableNotoPage(url)) return res;
  const h = new Headers(res.headers);
  h.delete('x-frame-options');
  const csp = h.get('Content-Security-Policy');
  if (csp) {
    h.set('Content-Security-Policy', relaxCspForCrossOriginEmbed(csp));
  } else {
    h.set('Content-Security-Policy', 'frame-ancestors *');
  }
  const cspRo = h.get('Content-Security-Policy-Report-Only');
  if (cspRo) {
    h.set('Content-Security-Policy-Report-Only', relaxCspForCrossOriginEmbed(cspRo));
  }
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: h,
  });
}

function _b64urlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '');
}

function _hexToBytesStrict32(hex: string): Uint8Array | null {
  const h = hex.replace(/\\s/g, '').slice(0, 64);
  if (h.length < 64) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 64; i += 2) {
    const v = parseInt(h.slice(i, i + 2), 16);
    if (Number.isNaN(v)) return null;
    out[i / 2] = v;
  }
  return out;
}

async function _buildBundleBootForHtml(env: Env): Promise<{ v: number; n: string; t: string; w: string } | null> {
  const bootSecret = String((env as any).DOKKEBI_BUNDLE_BOOT_SECRET || '').trim();
  const bcHex = String((env as any).__DOKKEBI_BC_KEY__ || '').replace(/\\s/g, '');
  const bh12 = String((env as any).__DOKKEBI_BC_HASH__ || '').trim().slice(0, 12);
  if (!bootSecret || bh12.length < 12) return null;
  const keyBytes = _hexToBytesStrict32(bcHex);
  if (!keyBytes) return null;
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const hmacKey = await crypto.subtle.importKey('raw', enc.encode(bootSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const token = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, nonce));
  const ikmKey = await crypto.subtle.importKey('raw', token, 'HKDF', false, ['deriveKey']);
  const info = enc.encode('dokkebi-bc-wrap-v1|' + bh12);
  const kek = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: nonce, info },
    ikmKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, keyBytes);
  const w = new Uint8Array(iv.byteLength + encBuf.byteLength);
  w.set(iv, 0);
  w.set(new Uint8Array(encBuf), iv.byteLength);
  return { v: 1, n: _b64urlEncode(nonce), t: _b64urlEncode(token), w: _b64urlEncode(w) };
}

function _injectBootInHtml(html: string, payload: { v: number; n: string; t: string; w: string }): string {
  const json = JSON.stringify(payload).replace(/</g, '\\\\u003c');
  const tag = '<script>window.__DOKKEBI_BOOT__=' + json + ';</script>';
  return /<head[^>]*>/i.test(html) ? html.replace(/<head([^>]*)>/i, '<head$1>' + tag) : tag + html;
}

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env, next } = ctx;
  const url = new URL(request.url);
  const path = url.pathname;

  const _idb = _internalDb(env);
  if (!_idb || request.method === 'OPTIONS' || _SKIP.some(p => path.includes(p))) {
    return _relaxEmbedFrameAncestors(await next(), url);
  }

  // SEO 봇 분기 — 봇 UA 면 Edge SEO Renderer 로 위임 (실패 시 정상 흐름)
  const seoRes = await _dokkebiSeoTryHandle(request);
  if (seoRes) return _relaxEmbedFrameAncestors(seoRes, url);

  const ip = request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')?.split(',')[0].trim()
    || '';

  if (ip && await _isBlocked(_idb, ip)) {
    return new Response(
      '<!DOCTYPE html><html><body style="font-family:system-ui;background:#0d1117;color:#e6edf3;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0"><div style="text-align:center"><h1 style="font-size:48px;margin-bottom:8px">403</h1><p style="color:#8b949e">Access denied by security policy.</p></div></body></html>',
      { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } }
    );
  }

  let res = await next();
  res = _relaxEmbedFrameAncestors(res, url);
  if (request.method === 'GET' && (res.headers.get('content-type') || '').includes('text/html')) {
    const payload = await _buildBundleBootForHtml(env);
    if (payload) {
      const clone = res.clone();
      try {
        const html = await res.text();
        const out = _injectBootInHtml(html, payload);
        const h = new Headers(res.headers);
        h.set('Cache-Control', 'private, no-store, no-cache, must-revalidate');
        h.set('Pragma', 'no-cache');
        h.delete('content-length');
        return new Response(out, { status: res.status, statusText: res.statusText, headers: h });
      } catch {
        return clone;
      }
    }
  }
  return res;
};
`
        .replace(/__DOKKEBI_PH_INTERNAL_BINDING__/g, 'DB')
        .replace(/__DOKKEBI_PH_SHARD_BINDINGS__/g, '[]');
}

export function workerMiddleware() {
    return renderTemplate('worker/middleware.ts.tpl', [..._PHASE_B_PH_INTERNAL]);
}
