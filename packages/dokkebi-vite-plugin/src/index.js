/**
 * dokkebi Vite 플러그인
 *
 * 기능:
 *   1. 'dokkebi:runtime' / 'dokkebi:dsl' 가상 모듈 해석
 *      (프론트엔드 코드에서 백엔드를 직접 import 방지)
 *   2. 개발 모드: 백엔드 JS를 Vite devServer에서 HMR과 함께 번들
 *   3. 프로덕션 빌드: dokkebi.config.ts 기반으로 빌드 파이프라인 통합
 *   4. 빌드 완료 후 Opaque Handle 부트스트랩 자동 주입
 *   5. 백엔드 WASM 번들을 public/ 폴더에 복사
 *
 * 사용 예 (vite.config.ts):
 *   import { dokkebi } from 'dokkebi-vite-plugin';
 *
 *   export default defineConfig({
 *     plugins: [
 *       vue(), // 또는 react()
 *       dokkebi(),
 *     ],
 *   });
 */

import path from 'path';
import fs from 'fs/promises';

const VIRTUAL_RUNTIME_ID = 'dokkebi:runtime';
const VIRTUAL_DSL_ID = 'dokkebi:dsl';
const VIRTUAL_CLIENT_ID = 'dokkebi:client';
const RESOLVED_RUNTIME = '\0' + VIRTUAL_RUNTIME_ID;
const RESOLVED_DSL = '\0' + VIRTUAL_DSL_ID;
const RESOLVED_CLIENT = '\0' + VIRTUAL_CLIENT_ID;

/**
 * dokkebi Vite 플러그인 팩토리
 * @param {object} opts
 * @param {string} [opts.configFile] - dokkebi.config.ts 경로 (기본: './dokkebi.config.ts')
 * @param {boolean} [opts.buildWasm] - 프로덕션 빌드 시 WASM 빌드 실행 여부
 * @returns {import('vite').Plugin}
 */
export function dokkebi(opts = {}) {
    const { configFile = './dokkebi.config.ts', buildWasm: doBuildWasm = true } = opts;

    let viteConfig;
    let dokkebiConfig = null;
    let isDev = false;

    return {
        name: 'dokkebi-vite-plugin',

        // ── 플러그인 초기화 ────────────────────────────────────

        configResolved(resolved) {
            viteConfig = resolved;
            isDev = resolved.command === 'serve';
        },

        async buildStart() {
            // dokkebi.config.ts 로드
            dokkebiConfig = await loadDokkebiConfig(configFile, viteConfig.root);

            if (isDev) {
                console.log('\n[dokkebi] 개발 모드 — QuickJS 인메모리 모드 활성');
                console.log('[dokkebi] DB 타입:', dokkebiConfig?.database?.type || '미설정\n');
            }
        },

        // ── 가상 모듈 해석 ─────────────────────────────────────
        // 프론트엔드에서 'dokkebi:runtime'을 import 시도하면 에러 안내

        resolveId(id) {
            if (id === VIRTUAL_RUNTIME_ID) return RESOLVED_RUNTIME;
            if (id === VIRTUAL_DSL_ID) return RESOLVED_DSL;
            if (id === VIRTUAL_CLIENT_ID) return RESOLVED_CLIENT;
        },

        load(id) {
            if (id === RESOLVED_RUNTIME || id === RESOLVED_DSL) {
                // 프론트엔드에서 직접 import하면 브라우저 API 안내
                return `
// dokkebi 백엔드 API는 프론트엔드에서 직접 import할 수 없습니다.
// 대신 'dokkebi:client' 에서 dokkebi 를 import 하세요.
throw new Error(
  '[dokkebi] "${id}"는 백엔드 전용 모듈입니다.\\n' +
  '프론트엔드에서는 import { dokkebi } from "dokkebi:client" 를 사용하세요.'
);
`;
            }
            if (id === RESOLVED_CLIENT) {
                // 프론트엔드 전용 클라이언트 모듈.
                // 부트스트랩이 발급한 일회성 handoff 토큰을 즉시 소비하고 window 에서 제거.
                // → 페이지 로드 후 실행되는 XSS 코드는 dokkebi 객체에 접근할 수 없음.
                return generateClientVirtualModule();
            }
        },

        // ── HTML 변환 (개발 모드) ──────────────────────────────
        // 개발 모드에서 인메모리 QuickJS 부트스트랩 주입

        transformIndexHtml: {
            order: 'pre',
            handler(html) {
                if (!isDev) return html;

                const devBootstrap = generateDevBootstrap(dokkebiConfig);
                return html.replace(
                    '</head>',
                    `${devBootstrap}\n</head>`
                );
            },
        },

        // ── 프로덕션 빌드 후처리 ───────────────────────────────

        async closeBundle() {
            if (isDev) return;
            if (!dokkebiConfig) return;

            const outDir = viteConfig.build?.outDir || 'dist';
            const absoluteOutDir = path.resolve(viteConfig.root, outDir);

            console.log('\n[dokkebi] 프로덕션 빌드 후처리 시작...');

            try {
                // 1) WASM 빌드 (옵션)
                if (doBuildWasm) {
                    await runDokkebiWasmBuild(dokkebiConfig, viteConfig.root, absoluteOutDir);
                }

                // 2) 부트스트랩 HTML 주입
                await injectBootstrapIntoHtmlFiles(absoluteOutDir, dokkebiConfig);

                console.log('[dokkebi] 빌드 완료!\n');
            } catch (e) {
                console.error('[dokkebi] 빌드 후처리 실패:', e.message);
                // 빌드 실패를 전파하지 않음 — 프론트엔드 빌드는 성공 처리
            }
        },
    };
}

// ─────────────────────────────────────────────────────────────
// dokkebi.config.ts 로더
// ─────────────────────────────────────────────────────────────

async function loadDokkebiConfig(configFile, root) {
    const candidates = [
        path.resolve(root, configFile),
        path.resolve(root, 'dokkebi.config.ts'),
        path.resolve(root, 'dokkebi.config.js'),
        path.resolve(root, 'dokkebi.config.mjs'),
    ];

    for (const candidate of candidates) {
        try {
            await fs.access(candidate);
            // 동적 import (Vite가 트랜스파일 처리함)
            const mod = await import(candidate + '?t=' + Date.now());
            return mod.default || mod;
        } catch {
            /* 파일 없음 */
        }
    }

    console.warn('[dokkebi] dokkebi.config.ts 파일을 찾을 수 없습니다. 기본값을 사용합니다.');
    return {
        database: { type: 'd1' },
        backend: { entry: './backend/controllers/index.ts' },
    };
}

// ─────────────────────────────────────────────────────────────
// 개발 모드 부트스트랩 (인메모리 QuickJS)
// ─────────────────────────────────────────────────────────────

function generateDevBootstrap(config) {
    const dbType = config?.database?.type || 'd1';
    return `
<!-- dokkebi Dev Bootstrap -->
<script type="module">
import { getQuickJS } from 'https://cdn.jsdelivr.net/npm/quickjs-emscripten@0.31.0/dist/quickjs-emscripten-core.mjs';

window.dokkebiReady = (async () => {
  try {
    const QuickJS = await getQuickJS();
    const vm = QuickJS.newContext();
    console.log('[dokkebi:dev] QuickJS VM 초기화 완료 (DB: ${dbType})');

    // dokkebi 클라이언트 객체 (클로저, window 비노출)
    const _dokClient = {
      async request(method, path, body, headers = {}) {
        // 개발 모드: 백엔드 번들을 동적으로 로드
        const res = await fetch('/__dokkebi_backend__', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ method, path, body, headers }),
        });
        return res.json();
      },
      get: (p, h) => _dokClient.request('GET', p, null, h),
      post: (p, b, h) => _dokClient.request('POST', p, b, h),
      put: (p, b, h) => _dokClient.request('PUT', p, b, h),
      delete: (p, h) => _dokClient.request('DELETE', p, null, h),
    };

    // dokkebi:client 가상 모듈을 위한 일회성 handoff
    const _HANDOFF = Symbol.for('dokkebi.client.handoff');
    let _consumed = false;
    Object.defineProperty(window, _HANDOFF, {
      value: function () {
        if (_consumed) throw new Error('[dokkebi:dev] client handoff already consumed');
        _consumed = true;
        return _dokClient;
      },
      configurable: true,
      enumerable: false,
      writable: false,
    });

    return _dokClient;
  } catch (e) {
    console.error('[dokkebi:dev] 초기화 실패:', e);
    throw e;
  }
})();
</script>`;
}

// ─────────────────────────────────────────────────────────────
// 'dokkebi:client' 가상 모듈 코드 생성
// ─────────────────────────────────────────────────────────────
//
// 부트스트랩이 window[Symbol.for('dokkebi.client.handoff')] 에 일회성 함수를 심으면,
// 이 모듈이 첫 호출 시 그 함수를 호출해서 dokkebi 객체를 받아오고 즉시 window 에서 제거합니다.
//
// 결과:
//   - 페이지 위 JS 컨텍스트에는 dokkebi 객체가 노출되지 않음 (frontend 번들 클로저에만 존재)
//   - 페이지 로드 후 실행되는 XSS 코드는 handoff 함수가 이미 사라져서 접근 불가
//   - frontend 코드만 정상 사용 가능
//
// 이 코드는 dokkebi-cli 가 빌드 시 frontend/src/lib/dokkebi.ts 실제 파일로도 emit 합니다.
// (dokkebi-vite-plugin 미등록 환경에서도 작동 가능하도록)
//
export function dokkebiClientSource() {
    return `const _HANDOFF = Symbol.for('dokkebi.client.handoff');

let _client = null;
let _initPromise = null;

function _consumeHandoff() {
  if (typeof window === 'undefined') {
    throw new Error('[dokkebi:client] window 가 없습니다 (SSR 컨텍스트?).');
  }
  const handoff = window[_HANDOFF];
  if (typeof handoff !== 'function') return null;
  const c = handoff();
  try { delete window[_HANDOFF]; } catch (_) { /* noop */ }
  return c;
}

async function _init() {
  if (_client) return _client;
  if (_initPromise) return _initPromise;
  _initPromise = (async () => {
    if (typeof window === 'undefined') {
      throw new Error('[dokkebi:client] window 가 없습니다 (SSR 컨텍스트?).');
    }
    if (window.dokkebiReady && typeof window.dokkebiReady.then === 'function') {
      try { await window.dokkebiReady; } catch (_) { /* 부트스트랩 실패는 아래에서 처리 */ }
    }
    const c = _consumeHandoff();
    if (!c) {
      throw new Error(
        '[dokkebi:client] handoff 가 비어 있습니다. ' +
        '부트스트랩이 주입되지 않았거나 (HTML 에 dokkebi 부트스트랩이 없거나), ' +
        '이미 다른 코드가 handoff 를 소비했습니다.'
      );
    }
    _client = c;
    return c;
  })();
  return _initPromise;
}

const dokkebi = {
  async request() { return (await _init()).request.apply(null, arguments); },
  async get()     { return (await _init()).get.apply(null, arguments); },
  async post()    { return (await _init()).post.apply(null, arguments); },
  async put()     { return (await _init()).put.apply(null, arguments); },
  async delete()  { return (await _init()).delete.apply(null, arguments); },
  capability: {
    async unlock() {
      const c = await _init();
      return c.capability && c.capability.unlock
        ? c.capability.unlock.apply(null, arguments)
        : Promise.reject(new Error('capability API not available'));
    },
  },
  async upload()        { return (await _init()).upload.apply(null, arguments); },
  async download()      { return (await _init()).download.apply(null, arguments); },
  async removeData()    { return (await _init()).removeData.apply(null, arguments); },
  async removeDataDir() { return (await _init()).removeDataDir.apply(null, arguments); },
  get opfsAvailable() { return _client ? _client.opfsAvailable === true : false; },
  /** 초기화 완료를 명시적으로 기다리고 싶을 때 사용. 보통은 호출하지 않아도 됨. */
  async ready() { await _init(); },
};

export { dokkebi };
export default dokkebi;
`;
}

/**
 * vite-plugin 의 'dokkebi:client' 가상 모듈 본문.
 * dokkebi-vite-plugin 을 frontend Vite 에 등록한 경우에만 사용됩니다.
 */
function generateClientVirtualModule() {
    return `// dokkebi:client — 프론트엔드 전용 클라이언트 (가상 모듈, 자동 생성)\n${dokkebiClientSource()}`;
}

/**
 * frontend/src/lib/dokkebi.ts 로 emit 할 TypeScript 소스.
 *
 * dokkebi-vite-plugin 미등록 환경에서도 동작하도록 frontend/src 안에 실제 파일로
 * emit 합니다. 사용자 코드는 \`import { dokkebi } from '<상대경로>/lib/dokkebi'\` 형태로
 * 가져옵니다. (dok create / dok update 가 자동 처리)
 */
export function dokkebiClientTsSource() {
    return [
        "// frontend/src/lib/dokkebi.ts — dokkebi 클라이언트 (자동 생성, 수정하지 마세요)",
        "//",
        "// v6.x+ 부터 `window.dokkebi` 전역 노출이 제거되었습니다 (XSS 표면 축소).",
        "// 부트스트랩이 페이지에 일회성 handoff (Symbol.for('dokkebi.client.handoff')) 를 심고,",
        "// 이 모듈이 첫 호출 시 그 함수를 소비한 뒤 즉시 window 에서 제거합니다.",
        "// → 페이지 로드 후 실행되는 XSS 코드는 dokkebi 객체에 접근할 수 없습니다.",
        "//",
        "// 사용:  import { dokkebi } from './lib/dokkebi';",
        "//        const res = await dokkebi.get('/api/users');",
        "",
        "export interface DokkebiResponse {",
        "  ok: boolean;",
        "  status: number;",
        "  body: string;",
        "  json: any;",
        "  error: string | null;",
        "  headers: [string, string][];",
        "}",
        "",
        "export interface DokkebiClient {",
        "  request(method: string, path: string, body?: any, headers?: Record<string, string>): Promise<DokkebiResponse>;",
        "  request(opts: { method: string; path: string; body?: any; headers?: Record<string, string> }): Promise<DokkebiResponse>;",
        "  get(path: string, headers?: Record<string, string>): Promise<DokkebiResponse>;",
        "  post(path: string, body?: any, headers?: Record<string, string>): Promise<DokkebiResponse>;",
        "  put(path: string, body?: any, headers?: Record<string, string>): Promise<DokkebiResponse>;",
        "  delete(path: string, headers?: Record<string, string>): Promise<DokkebiResponse>;",
        "  capability: {",
        "    unlock(route: string, secret: string): Promise<{ ok: boolean; error?: string }>;",
        "  };",
        "  upload(file: File | Blob, targetPath?: string): Promise<{ opfsRef: string; size: number }>;",
        "  download(opfsRef: string): Promise<string>;",
        "  removeData(opfsRef: string): Promise<void>;",
        "  removeDataDir(dirPath: string): Promise<void>;",
        "  readonly opfsAvailable: boolean;",
        "  ready(): Promise<void>;",
        "}",
        "",
        "declare global {",
        "  interface Window {",
        "    /** 호환성을 위해 유지되는 dokkebi 부트스트랩 준비 Promise. */",
        "    dokkebiReady?: Promise<DokkebiClient>;",
        "  }",
        "}",
        "",
        "const _HANDOFF = Symbol.for('dokkebi.client.handoff');",
        "",
        "let _client: DokkebiClient | null = null;",
        "let _initPromise: Promise<DokkebiClient> | null = null;",
        "",
        "function _consumeHandoff(): DokkebiClient | null {",
        "  if (typeof window === 'undefined') {",
        "    throw new Error('[dokkebi] window 가 없습니다 (SSR 컨텍스트?).');",
        "  }",
        "  const handoff = (window as any)[_HANDOFF];",
        "  if (typeof handoff !== 'function') return null;",
        "  const c = handoff() as DokkebiClient;",
        "  try { delete (window as any)[_HANDOFF]; } catch { /* noop */ }",
        "  return c;",
        "}",
        "",
        "async function _init(): Promise<DokkebiClient> {",
        "  if (_client) return _client;",
        "  if (_initPromise) return _initPromise;",
        "  _initPromise = (async () => {",
        "    if (typeof window === 'undefined') {",
        "      throw new Error('[dokkebi] window 가 없습니다 (SSR 컨텍스트?).');",
        "    }",
        "    if (window.dokkebiReady && typeof (window.dokkebiReady as any).then === 'function') {",
        "      try { await window.dokkebiReady; } catch { /* 부트스트랩 실패는 아래에서 처리 */ }",
        "    }",
        "    const c = _consumeHandoff();",
        "    if (!c) {",
        "      throw new Error(",
        "        '[dokkebi] handoff 가 비어 있습니다. ' +",
        "        '부트스트랩이 주입되지 않았거나 (HTML 에 dokkebi 부트스트랩이 없거나), ' +",
        "        '이미 다른 코드가 handoff 를 소비했습니다.'",
        "      );",
        "    }",
        "    _client = c;",
        "    return c;",
        "  })();",
        "  return _initPromise;",
        "}",
        "",
        "export const dokkebi: DokkebiClient = {",
        "  async request(...args: any[]) { return (await _init()).request.apply(null, args as [any]); },",
        "  async get(...args: any[])     { return (await _init()).get.apply(null, args as [any]); },",
        "  async post(...args: any[])    { return (await _init()).post.apply(null, args as [any]); },",
        "  async put(...args: any[])     { return (await _init()).put.apply(null, args as [any]); },",
        "  async delete(...args: any[])  { return (await _init()).delete.apply(null, args as [any]); },",
        "  capability: {",
        "    async unlock(...args: any[]) {",
        "      const c = await _init();",
        "      return c.capability && c.capability.unlock",
        "        ? c.capability.unlock.apply(null, args as [any, any])",
        "        : Promise.reject(new Error('capability API not available'));",
        "    },",
        "  },",
        "  async upload(...args: any[])        { return (await _init()).upload.apply(null, args as [any]); },",
        "  async download(...args: any[])      { return (await _init()).download.apply(null, args as [any]); },",
        "  async removeData(...args: any[])    { return (await _init()).removeData.apply(null, args as [any]); },",
        "  async removeDataDir(...args: any[]) { return (await _init()).removeDataDir.apply(null, args as [any]); },",
        "  get opfsAvailable() { return _client ? _client.opfsAvailable === true : false; },",
        "  async ready() { await _init(); },",
        "};",
        "",
        "export default dokkebi;",
        "",
    ].join("\n");
}

// ─────────────────────────────────────────────────────────────
// 프로덕션 빌드: WASM 빌드 실행
// ─────────────────────────────────────────────────────────────

async function runDokkebiWasmBuild(dokkebiConfig, root, outDir) {
    const backendEntry =
        dokkebiConfig.backend?.entry ||
        path.resolve(root, 'backend/controllers/index.ts');

    const absoluteEntry = path.resolve(root, backendEntry);
    const wasmOutDir = path.join(outDir, 'dokkebi');

    console.log('[dokkebi] 백엔드 WASM 빌드 시작:', absoluteEntry);

    // CLI 코어 빌드 모듈 동적 로드
    const { buildWasm } = await import('../../../src/core/buildWasm.js').catch(() => {
        // 패키지로 설치된 경우
        return import('dokkebi-cli/core/buildWasm');
    });

    const result = await buildWasm({
        backendEntry: absoluteEntry,
        backendDir: path.resolve(root, 'backend'),
        outDir: wasmOutDir,
        dbType: dokkebiConfig.database?.type || 'd1',
        logCollectLevel: dokkebiConfig?.logging?.level,
        bundleEncrypt: dokkebiConfig?.security?.bundleEncrypt,
    });

    console.log('[dokkebi] WASM 빌드 완료:', result.mode);
    return result;
}

// ─────────────────────────────────────────────────────────────
// 프로덕션 빌드: HTML 부트스트랩 주입
// ─────────────────────────────────────────────────────────────

async function injectBootstrapIntoHtmlFiles(outDir, dokkebiConfig) {
    const { injectBootstrapAll, normalizeAuthSessionForBootstrap } = await import('../../../src/core/opaqueHandle.js').catch(
        () => import('dokkebi-cli/core/opaqueHandle')
    );

    const dbType = dokkebiConfig.database?.type || 'd1';
    const dbConfig = dokkebiConfig.database || {};

    // Caller Guard: dist 의 모든 *.js 파일(번들 청크)을 allowlist 로 수집.
    // 부트스트랩이 이 목록에 있는 source 에서 온 호출만 정당한 frontend 호출로 인정함.
    const callerCheck = dokkebiConfig?.security?.callerCheck || 'off';
    let allowedScripts = [];
    if (callerCheck !== 'off') {
        try {
            allowedScripts = await collectJsAssetPaths(outDir, outDir);
            console.log(`[dokkebi] caller guard 활성 (${callerCheck}) — 허용 청크 ${allowedScripts.length}개`);
        } catch (e) {
            console.warn('[dokkebi] caller guard allowlist 수집 실패:', e.message);
        }
    }

    const count = await injectBootstrapAll(outDir, {
        dbType,
        dbConfig,
        bundleUrl: './dokkebi/backend-bundle.js',
        loaderUrl: './dokkebi/dokkebi-loader.js',
        buildMode: 'cdn-fallback',
        logging: dokkebiConfig?.logging,
        authSession: normalizeAuthSessionForBootstrap(dokkebiConfig?.security?.authSession),
        callerCheck,
        allowedScripts,
        callerCheckAuditUrl: dokkebiConfig?.security?.callerCheckAuditUrl,
    });

    console.log(`[dokkebi] 부트스트랩 주입: ${count}개 HTML 파일`);
}

/**
 * dist 디렉터리에서 *.js 파일들의 web-root 절대 경로를 수집한다.
 * 예: '/assets/index-abc123.js', '/sw.js'
 * `/dokkebi/*` (도깨비 내부 자산) 은 frontend 호출 출처로 인정될 일이 없으므로 제외.
 */
async function collectJsAssetPaths(rootDir, currentDir, basePath = '') {
    const out = [];
    const entries = await fs.readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
        const abs = path.join(currentDir, entry.name);
        const web = basePath + '/' + entry.name;
        if (entry.isDirectory()) {
            // dokkebi 내부 자산은 frontend 출처가 아니므로 스킵
            if (entry.name === 'dokkebi') continue;
            const sub = await collectJsAssetPaths(rootDir, abs, web);
            out.push(...sub);
        } else if (/\.(m|c)?js$/i.test(entry.name)) {
            out.push(web);
        }
    }
    return out;
}

// 기본 내보내기 (ESM + CJS 호환)
export default dokkebi;
