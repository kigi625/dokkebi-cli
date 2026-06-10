/**
 * dokkebi WASM 빌드 파이프라인
 *
 * 파이프라인:
 *   1. esbuild: TypeScript 백엔드 → 단일 ESM 번들 (QuickJS VM 실행용)
 *   2. QuickJS WASM 런타임 준비 (로컬 npm 패키지 — CDN 없음)
 *   3. 부트스트랩 JS 생성: QuickJS Async VM 초기화 + Opaque Handle 연결
 *   4. WIT 바인딩 파일 출력
 *
 * WASM 전략:
 *   - 암호화 번들(기본): Step 2A — 난독화 + AES-256-GCM + 핸드셰이크 BC_KEY (.enc)
 *   - 평문 번들(opt-out): security.bundleEncrypt: false 또는 DOKKEBI_BUNDLE_ENCRYPT=off — backend-bundle.js + SHA만
 */

import path from 'path';
import fs from 'fs/promises';
import { fileURLToPath } from 'url';
import { createHash, randomBytes, createCipheriv } from 'crypto';
import * as esbuild from 'esbuild';
import { consoleMethodsToStripFromBundle, normalizeLogCollectLevel } from './logCollectLevel.js';
import { replaceConsoleCallsWithVoid } from './stripConsoleCalls.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_ROOT = path.resolve(__dirname, '../../');

const RUNTIME_SRC = path.join(CLI_ROOT, 'packages/dokkebi-runtime/src/index.js');
const DSL_SRC     = path.join(CLI_ROOT, 'packages/dokkebi-dsl/src/index.js');

// ─────────────────────────────────────────────────────────────
// Step 1: esbuild — TypeScript 번들링
// ─────────────────────────────────────────────────────────────

/**
 * 백엔드 TypeScript/JS를 QuickJS VM에서 실행 가능한 단일 ESM 번들로 컴파일
 */
// 민감 환경변수 패턴은 더 이상 사용하지 않습니다.
// .env 의 모든 값은 secret 으로 취급되어 Pages Secret 으로만 노출됩니다(번들 인라인 금지).
// 단, NODE_ENV 같이 표준 빌드 토큰만 예외(아래 BUILD_TIME_ENV_KEYS).
const SENSITIVE_ENV_PATTERN = /.*/;
/** 빌드 타임에만 인라인 허용할 화이트리스트 키 (값이 민감하지 않은 표준 키만). */
const BUILD_TIME_ENV_KEYS = new Set(['NODE_ENV']);
// C-1: JWT 서명 시크릿은 더 이상 클라이언트로 전달되지 않는다(워커측 _login 으로 발급).
//   따라서 백엔드 WASM 이 JWT_SECRET 을 직접 읽으면 "Worker 전용 Secret" 경고 대상이 된다.
const CLIENT_HANDSHAKE_SECRET_KEYS = new Set(['__DOKKEBI_BC_KEY__']);

/**
 * 백엔드 번들 AES+난독화(Step 2A) — 항상 강제 ON.
 *
 * 이전에는 `security.bundleEncrypt: false` 또는 `DOKKEBI_BUNDLE_ENCRYPT=off` 로
 * 평문 번들을 만들 수 있었지만, 평문 번들은 핸드셰이크에서 BC_KEY 흐름이 끊기고
 * 부트스트랩이 매 새로고침마다 재핸드셰이크를 도는 원인이 되어 무조건 암호화로 강제한다.
 *
 * 시그니처는 호환을 위해 유지 — 인자는 무시한다.
 * @returns {true}
 */
export function isBundleEncryptEnabled() {
    return true;
}

async function removeLegacyEncBundleArtifacts(outDir) {
    let entries;
    try {
        entries = await fs.readdir(outDir);
    } catch {
        return;
    }
    for (const name of entries) {
        if (name === 'backend.bundle.enc' || /^backend\.bundle\.[a-f0-9]{12}\.enc$/i.test(name)) {
            await fs.unlink(path.join(outDir, name)).catch(() => {});
        }
    }
}

export async function bundleBackendForWasm({
    backendEntry,
    outFile,
    backendDir,
    minify,
    /** @type {string|undefined} 원격 로그 최소 레벨과 동일 기준으로 console.* 제거 */
    logCollectLevel,
}) {
    // 기본값: 프로덕션 빌드(dok build/deploy)는 minify=true.
    // dev 모드(dok dev)는 호출부에서 minify=false 를 명시적으로 전달.
    // 강제 off 가 필요한 경우(디버깅) 환경변수 DOKKEBI_NO_MINIFY=true.
    const effectiveMinify = minify !== undefined
        ? !!minify
        : (String(process.env.DOKKEBI_NO_MINIFY || '').toLowerCase() !== 'true');
    const dokkebiResolvePlugin = {
        name: 'dokkebi-resolve',
        setup(build) {
            build.onResolve({ filter: /^dokkebi:runtime$/ }, () => ({ path: RUNTIME_SRC }));
            build.onResolve({ filter: /^dokkebi-dsl$/ },     () => ({ path: DSL_SRC }));
            build.onResolve({ filter: /^dokkebi:dsl$/ },     () => ({ path: DSL_SRC }));
        },
    };

    // .env 파일에서 환경변수를 읽어 esbuild define으로 주입
    // QuickJS에는 process 전역이 없으므로 빌드 타임에 치환 필수
    //
    // 보안: 민감 변수(SECRET, KEY, TOKEN 등)는 번들에 평문으로 삽입하지 않고
    // __dokkebi_env__("KEY") 호출로 대체합니다. 클라이언트 handshake에는
    // __DOKKEBI_BC_KEY__ 와 (로그인 JWT용) JWT_SECRET / DOKKEBI_JWT_SECRET 만 전달되며,
    // 그 외 민감 키는 Worker-side operation 으로 옮겨야 합니다.
    // envDefine: esbuild define 옵션용 (JSON 리터럴만 허용)
    // envSecretReplace: processEnvPlugin에서 함수 호출로 치환 (esbuild define 불가)
    const envDefine = { 'process.env.NODE_ENV': '"production"' };
    const envSecrets = {};
    const envSecretReplace = {};
    const sensitiveEnvUsages = new Set();
    const projectRoot = backendDir ? path.resolve(backendDir, '..') : path.dirname(backendEntry);
    for (const candidate of [path.join(projectRoot, '.env'), path.join(backendDir || projectRoot, '.env')]) {
        try {
            const envContent = await fs.readFile(candidate, 'utf-8');
            for (const line of envContent.split('\n')) {
                const trimmed = line.trim();
                if (!trimmed || trimmed.startsWith('#')) continue;
                const eqIdx = trimmed.indexOf('=');
                if (eqIdx < 1) continue;
                const key = trimmed.slice(0, eqIdx).trim();
                const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
                if (BUILD_TIME_ENV_KEYS.has(key)) {
                    envDefine[`process.env.${key}`] = JSON.stringify(val);
                } else {
                    // 모든 사용자 정의 환경변수는 Secret 으로 처리.
                    envSecretReplace[`process.env.${key}`] = `__dokkebi_env__("${key}")`;
                    envSecrets[key] = val;
                }
            }
            break;
        } catch {}
    }

    const sensitiveCount = Object.keys(envSecrets).length;
    if (sensitiveCount > 0) {
        console.log(`[dokkebi:wasm] 🔐 민감 변수 ${sensitiveCount}개 감지 (${Object.keys(envSecrets).join(', ')})`);
    }

    // 소스에서 사용된 process.env.XXX 참조를 직접 텍스트 치환
    // 민감 변수 → __dokkebi_env__("KEY") 호스트 함수 호출 (esbuild define은 함수 호출을 지원하지 않음)
    // 비민감 변수 → JSON 리터럴 (envDefine에도 있지만 onLoad 우선)
    const processEnvPlugin = {
        name: 'process-env-fallback',
        setup(build) {
            build.onLoad({ filter: /\.(ts|js|tsx|jsx)$/ }, async (args) => {
                const src = await fs.readFile(args.path, 'utf-8');
                if (!src.includes('process.env.')) return null;
                const replaced = src.replace(/process\.env\.([A-Z_][A-Z0-9_]*)/g, (match, key) => {
                    // 빌드 타임 화이트리스트(NODE_ENV 등) 외 모든 env 참조는 secret 으로 간주.
                    if (!BUILD_TIME_ENV_KEYS.has(key)) sensitiveEnvUsages.add(key);
                    if (envSecretReplace[match]) return envSecretReplace[match];
                    if (envDefine[match]) return envDefine[match];
                    return '""';
                });
                if (replaced === src) return null;
                return { contents: replaced, loader: args.path.endsWith('.ts') || args.path.endsWith('.tsx') ? 'ts' : 'js' };
            });
        },
    };

    // QuickJS evalCode는 ESM 구문(export/import)을 지원하지 않음.
    // IIFE 포맷으로 빌드하여 모든 export를 제거하고 사이드이펙트만 실행.
    await esbuild.build({
        entryPoints: [backendEntry],
        bundle: true,
        platform: 'browser',
        target: ['es2020'],
        format: 'iife',
        outfile: outFile,
        plugins: [dokkebiResolvePlugin, processEnvPlugin],
        define: envDefine,
        sourcemap: false,
        minify: effectiveMinify,
        treeShaking: true,
        metafile: false,
        logLevel: 'error',
    });

    const normalizedLevel = normalizeLogCollectLevel(logCollectLevel);
    const stripMethods = consoleMethodsToStripFromBundle(normalizedLevel);
    // dok dev 는 minify:false → 번들에 console 유지(디버깅). 프로덕션만 최소 레벨 미만 호출 제거.
    if (effectiveMinify && stripMethods.length > 0) {
        let bundled = await fs.readFile(outFile, 'utf-8');
        bundled = replaceConsoleCallsWithVoid(bundled, stripMethods);
        await fs.writeFile(outFile, bundled, 'utf-8');
        console.log(`[dokkebi:wasm] 🧹 console 스트립 (${normalizedLevel} 미만): ${stripMethods.join(', ')}`);
    }

    const stat = await fs.stat(outFile);
    return {
        outFile,
        size: stat.size,
        envSecrets,
        sensitiveEnvUsages: Array.from(sensitiveEnvUsages).filter((key) => !CLIENT_HANDSHAKE_SECRET_KEYS.has(key)),
    };
}

// ─────────────────────────────────────────────────────────────
// Step 2A: 암호화 번들 (기본 경로)
//   JS 소스를 난독화한 뒤 AES-256-GCM으로 암호화합니다.
//   런타임은 로컬 QuickJS WASM VM에서 복호화된 JS를 evalCode로 실행합니다.
// ─────────────────────────────────────────────────────────────

/**
 * JS 소스에 경량 난독화를 적용합니다.
 * QuickJS 호환성을 위해 안전한 옵션만 사용합니다.
 * (controlFlowFlattening, selfDefending, debugProtection 비활성)
 */
async function obfuscateSource(jsSource) {
    try {
        const JavaScriptObfuscator = (await import('javascript-obfuscator')).default;
        const result = JavaScriptObfuscator.obfuscate(jsSource, {
            compact: true,
            controlFlowFlattening: false,
            deadCodeInjection: false,
            stringArray: true,
            stringArrayEncoding: ['base64'],
            stringArrayThreshold: 0.75,
            stringArrayIndexShift: true,
            stringArrayRotate: true,
            stringArrayShuffle: true,
            stringArrayWrappersCount: 2,
            stringArrayWrappersType: 'function',
            renameGlobals: false,
            selfDefending: false,
            debugProtection: false,
            disableConsoleOutput: false,
            identifierNamesGenerator: 'hexadecimal',
            transformObjectKeys: true,
            unicodeEscapeSequence: false,
        });
        return result.getObfuscatedCode();
    } catch (e) {
        console.warn(`[dokkebi:wasm] ⚠ JS 난독화 실패 → 원본 사용: ${e.message}`);
        return jsSource;
    }
}

/**
 * 바이트코드를 AES-256-GCM으로 암호화합니다.
 * 형식: [12 bytes IV][ciphertext + 16 bytes auth tag]
 * 복호화 키는 ECDH 세션을 통해 런타임에 안전하게 전달됩니다.
 */
function encryptBytecode(bytecodeArray) {
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(bytecodeArray), cipher.final()]);
    const tag = cipher.getAuthTag();
    const encrypted = Buffer.concat([iv, enc, tag]);
    return { encrypted, keyHex: key.toString('hex') };
}

/**
 * JS 소스를 난독화 + AES-256-GCM 암호화합니다.
 * 2중 보호: JS 난독화 (변수명 파괴 + 문자열 인코딩) → AES-256-GCM 암호화
 *
 * quickjs-emscripten의 encodeBinaryJSON은 JS_TAG_FUNCTION_BYTECODE를 지원하지 않고
 * (JS_WriteObject 미노출), getArrayBuffer는 WASM 힙 한계로 실패하므로
 * 난독화된 소스를 직접 암호화하는 방식을 사용합니다.
 * 런타임에서는 AES 복호화 → TextDecoder → evalCode로 실행합니다.
 */
export async function compileToBytecodeBundled({ jsBundlePath, outDir }) {
    await fs.mkdir(outDir, { recursive: true });

    let jsSource = await fs.readFile(jsBundlePath, 'utf-8');
    const origSize = Buffer.byteLength(jsSource, 'utf-8');

    // Phase 1: JS 난독화 (변수명 파괴 + 문자열 인코딩)
    console.log('[dokkebi:wasm] Phase 1: JS 소스 난독화...');
    const obfuscated = await obfuscateSource(jsSource);
    const obfSize = Buffer.byteLength(obfuscated, 'utf-8');
    console.log(`[dokkebi:wasm]   난독화 완료: ${(origSize / 1024).toFixed(1)} KB → ${(obfSize / 1024).toFixed(1)} KB`);

    // Phase 2: AES-256-GCM 암호화 (난독화된 소스의 UTF-8 바이트를 직접 암호화)
    console.log('[dokkebi:wasm] Phase 2: AES-256-GCM 암호화...');
    const obfuscatedBytes = Buffer.from(obfuscated, 'utf-8');
    const { encrypted, keyHex } = encryptBytecode(obfuscatedBytes);

    const bundleHash = createHash('sha256').update(encrypted).digest('hex');
    await fs.writeFile(path.join(outDir, 'backend-bundle.sha256'), bundleHash, 'utf-8');

    // 무중단 배포(zero-downtime) 지원:
    //   1) 해시 박힌 정식 파일명 — 빌드마다 다른 URL 이라 새 HTML 사용자가 옛/새 자산을
    //      동시에 안전하게 받을 수 있다. 이 파일은 immutable 캐시 대상.
    //   2) 비-해시 호환 파일명 (backend.bundle.enc) — 동일한 콘텐츠를 한 번 더 써둔다.
    //      구버전 dokkebi 클라이언트가 박혀있는 사이트에서도 깨지지 않도록 유지.
    //      (콘텐츠는 동일하므로 보안 영향 없음, CDN 캐시는 _headers 로 no-store)
    const hash12 = bundleHash.slice(0, 12);
    const encFile = path.join(outDir, 'backend.bundle.enc');
    const encFileHashed = path.join(outDir, `backend.bundle.${hash12}.enc`);
    await fs.writeFile(encFileHashed, encrypted);
    await fs.writeFile(encFile, encrypted);

    // Bundle Attestation 매니페스트 — 암호화된 번들 바이트를 N개 청크로 나눠 각 청크의
    // SHA-256 을 기록한다. 핸드셰이크 이후 서버가 무작위 인덱스를 challenge 로 보내고,
    // 클라이언트가 메모리에 보관 중인 암호화 번들 바이트로 같은 해시를 만들어 응답한다.
    // 번들이 변조되면 응답 해시가 매니페스트와 달라 검증에 실패한다.
    const chunkManifest = _buildChunkManifest(encrypted);
    await fs.writeFile(
        path.join(outDir, 'backend-bundle.chunks.json'),
        JSON.stringify(chunkManifest),
        'utf-8',
    );

    const stat = await fs.stat(encFile);
    console.log(`[dokkebi:wasm] ✅ 2중 보호 완료: ${encFile}`);
    console.log(`[dokkebi:wasm]   JS ${(origSize / 1024).toFixed(1)} KB → 난독화 ${(obfSize / 1024).toFixed(1)} KB → 암호화 ${(stat.size / 1024).toFixed(1)} KB`);
    console.log(`[dokkebi:wasm]   SHA-256: ${bundleHash.slice(0, 16)}...`);
    console.log(`[dokkebi:wasm]   Chunks: ${chunkManifest.count} × ${chunkManifest.chunkSize}B (attestation)`);

    return {
        bytecodeFile: encFile,
        bytecodeFileHashed: encFileHashed,
        bundleAssetName: `backend.bundle.${hash12}.enc`,
        bundleHash,
        chunkManifest,
        size: stat.size,
        bytecodeKey: keyHex,
        encryptedTextMode: true,
    };
}

// 암호화된 번들 바이트를 고정 크기 청크로 나눠 매니페스트를 생성한다.
// chunkSize 는 16KB 기본값이며, 너무 작은 번들은 청크가 1개 이하로 떨어진다.
// salt 는 매니페스트 자체의 무결성을 워커 메모리에서 일관되게 검증하기 위함이다.
function _buildChunkManifest(encrypted) {
    const total = encrypted.length;
    const chunkSize = 16 * 1024;
    const count = Math.max(1, Math.ceil(total / chunkSize));
    const hashes = new Array(count);
    for (let i = 0; i < count; i++) {
        const start = i * chunkSize;
        const end = Math.min(total, start + chunkSize);
        const slice = encrypted.subarray(start, end);
        hashes[i] = createHash('sha256').update(slice).digest('hex');
    }
    const salt = randomBytes(16).toString('hex');
    return {
        version: 1,
        algorithm: 'sha256',
        chunkSize,
        count,
        totalBytes: total,
        salt,
        hashes,
    };
}

// ─────────────────────────────────────────────────────────────
// Step 2B: 로컬 npm 패키지 기반 QuickJS WASM 런타임 번들
//   @jitl/quickjs-wasmfile-release-sync + quickjs-emscripten-core
//   → JS 로더 + 별도 .wasm 파일
//
// asyncify → sync 전환:
//   - newAsyncifiedFunction 미사용: deferred promise 패턴으로 비동기 처리
//   - WASM 크기 50% 감소 (1.0MB → 507KB)
//   - QuickJS WASM 기본 maximum=2GB 메모리 예약 → 커스텀 Memory로 제한
//     (iOS Safari OOM 크래시 근본 해결)
// ─────────────────────────────────────────────────────────────

/**
 * QuickJS sync VM 번들을 로컬 npm 패키지로 빌드합니다.
 * .wasm 파일을 별도로 분리하고 커스텀 메모리 제한을 지원합니다.
 */
export async function buildQuickJSBundle(outDir, { minify } = {}) {
    const effectiveMinify = minify !== undefined
        ? !!minify
        : (String(process.env.DOKKEBI_NO_MINIFY || '').toLowerCase() !== 'true');
    await fs.mkdir(outDir, { recursive: true });

    const wasmfilePkg = path.join(
        CLI_ROOT,
        'node_modules/@jitl/quickjs-wasmfile-release-sync'
    );
    const corePkg = path.join(
        CLI_ROOT,
        'node_modules/quickjs-emscripten-core'
    );

    try {
        await fs.access(wasmfilePkg);
        await fs.access(corePkg);
    } catch {
        throw new Error(
            '[dokkebi:wasm] quickjs 패키지가 없습니다.\n' +
            'dokkebi-cli 디렉토리에서 npm install 을 실행하세요.\n' +
            `필요 패키지: @jitl/quickjs-wasmfile-release-sync, quickjs-emscripten-core`
        );
    }

    // .wasm 파일을 출력 디렉토리에 복사
    const wasmSrc = path.join(wasmfilePkg, 'dist/emscripten-module.wasm');
    const wasmDst = path.join(outDir, 'emscripten-module.wasm');
    await fs.copyFile(wasmSrc, wasmDst);
    const wasmStat = await fs.stat(wasmDst);

    // 임시 진입점 파일 (esbuild 번들링용)
    const tempEntry = path.join(outDir, '_qjs-entry-tmp.mjs');
    const qjsBundleOut = path.join(outDir, 'dokkebi-qjs.js');

    const entryCode = `
// dokkebi QuickJS Sync VM — wasmfile 기반 + 커스텀 메모리 제한 지원
import syncVariant from '@jitl/quickjs-wasmfile-release-sync';
import { newQuickJSWASMModuleFromVariant } from 'quickjs-emscripten-core';

export async function getQuickJS(opts) {
  if (!opts || !opts.wasmMemory) {
    return newQuickJSWASMModuleFromVariant(syncVariant);
  }
  const wrappedVariant = {
    type: syncVariant.type,
    importFFI: syncVariant.importFFI,
    importModuleLoader: async () => {
      const origLoader = await syncVariant.importModuleLoader();
      return function(moduleArgs) {
        return origLoader(Object.assign({}, moduleArgs, { wasmMemory: opts.wasmMemory }));
      };
    },
  };
  return newQuickJSWASMModuleFromVariant(wrappedVariant);
}
`;

    await fs.writeFile(tempEntry, entryCode, 'utf-8');

    try {
        await esbuild.build({
            entryPoints: [tempEntry],
            bundle: true,
            platform: 'browser',
            target: ['es2020'],
            format: 'esm',
            outfile: qjsBundleOut,
            sourcemap: false,
            minify: effectiveMinify,
            logLevel: 'error',
            nodePaths: [path.join(CLI_ROOT, 'node_modules')],
            external: ['node:*', 'path', 'fs', 'crypto', 'os', 'url', 'module', 'child_process'],
            loader: { '.wasm': 'file' },
        });
    } finally {
        await fs.unlink(tempEntry).catch(() => {});
    }

    const stat = await fs.stat(qjsBundleOut);
    console.log(
        `[dokkebi:wasm] ✅ QuickJS Sync VM 번들 완료: ${qjsBundleOut} (${(stat.size / 1024).toFixed(0)} KB)`
    );
    console.log(
        `[dokkebi:wasm] ✅ WASM 파일: ${wasmDst} (${(wasmStat.size / 1024).toFixed(0)} KB)`
    );
    return qjsBundleOut;
}

/**
 * 암호화 번들을 실행할 로컬 QuickJS 런타임 번들 생성
 * CDN 없이 완전 로컬 동작, 별도 .wasm 파일 + JS 로더 사용
 */
export async function buildEncryptedRuntimeBundle({ outDir, bytecodeResult }) {
    await fs.mkdir(outDir, { recursive: true });

    if (!bytecodeResult?.bundleHash) {
        throw new Error('[dokkebi:wasm] encrypted-bundle 런타임 생성에는 bytecodeResult.bundleHash 가 필요합니다.');
    }
    const bundleHash = bytecodeResult.bundleHash;

    // QuickJS 번들 빌드
    const qjsBundlePath = await buildQuickJSBundle(outDir);

    // 로더 JS 생성 (bootstrap에서 사용)
    const loaderOut = path.join(outDir, 'dokkebi-loader.js');
    const loaderContent = generateQuickJsLoader();
    await fs.writeFile(loaderOut, loaderContent, 'utf-8');

    return { loaderOut, qjsBundlePath, bundleHash, bytecodeMode: false, encryptedTextMode: true };
}

/**
 * QuickJS VM 로더 JS 생성
 * 브라우저에서 실행되어 QuickJS Async VM을 초기화하고 백엔드 JS를 실행합니다.
 * /dokkebi/dokkebi-qjs.js (로컬 번들) 에서 getAsyncQuickJS를 가져옵니다.
 */
function generateQuickJsLoader() {
    return `
// ─── dokkebi QuickJS Async VM 로더 (자동 생성됨) ──────────────
// 로컬 npm 번들 기반 — CDN 없음, WASM(asyncify) 내장

import { getAsyncQuickJS } from '/dokkebi/dokkebi-qjs.js';

let _vm = null;
let _handleRequest = null;

export async function initDokkebiBackend({ bundleUrl, hostFunctions }) {
  const QuickJS = await getAsyncQuickJS();
  _vm = await QuickJS.newContext();

  // ── Host 함수 주입 (WIT import 구현) ─────────────────────
  const hostModule = _vm.newObject();

  // host-db: 모든 DB 쿼리를 /api/_dokkebi/db 프록시로 전달
  const hostDb = _vm.newObject();
  // ⚠️ params / statements 는 VM 에서 JS 배열/객체로 넘어오므로
  //    _vm.dump() 로 원시 타입(null/number/boolean)을 보존해 받는다.
  //    (JSON.parse(_vm.getString(...)) 는 array 전달 시 깨진다.)
  _vm.setProp(hostDb, 'dbExecute', _vm.newAsyncifiedFunction('dbExecute',
    async (handleIdH, sqlH, paramsH) => {
      const handleId = _vm.getNumber(handleIdH);
      const sql      = _vm.getString(sqlH);
      const dumped   = _vm.dump(paramsH);
      const params   = Array.isArray(dumped) ? dumped : [];
      const result   = await hostFunctions.db.dbExecute(handleId, sql, params);
      return _vm.newString(JSON.stringify(result));
    }
  ));
  _vm.setProp(hostDb, 'dbTransaction', _vm.newAsyncifiedFunction('dbTransaction',
    async (handleIdH, statementsH) => {
      const handleId   = _vm.getNumber(handleIdH);
      const statements = _vm.dump(statementsH);
      const result     = await hostFunctions.db.dbTransaction(handleId, statements);
      return _vm.newString(JSON.stringify(result));
    }
  ));
  _vm.setProp(hostModule, 'db', hostDb);

  // host-crypto
  const hostCrypto = _vm.newObject();
  _vm.setProp(hostCrypto, 'randomBytes', _vm.newFunction('randomBytes', (lenH) => {
    const len = _vm.getNumber(lenH);
    return _vm.newString(JSON.stringify(hostFunctions.crypto.randomBytes(len)));
  }));
  _vm.setProp(hostCrypto, 'nowMillis', _vm.newFunction('nowMillis', () => {
    return _vm.newString(String(hostFunctions.crypto.nowMillis()));
  }));
  // ── SHA-256 / HMAC 는 브라우저 WebCrypto 에 의존하므로 async 브리지로 노출한다.
  //    dokkebi-runtime 의 WebCrypto polyfill (crypto.subtle.digest / sign 등) 이
  //    이 함수들을 호출해 표준 API 를 구성한다.
  _vm.setProp(hostCrypto, 'hashSha256', _vm.newAsyncifiedFunction('hashSha256',
    async (dataH) => {
      const data = _vm.dump(dataH);
      const result = await hostFunctions.crypto.hashSha256(data);
      return _vm.newString(JSON.stringify(result));
    }
  ));
  _vm.setProp(hostCrypto, 'hmacSign', _vm.newAsyncifiedFunction('hmacSign',
    async (keyH, dataH) => {
      const key  = _vm.dump(keyH);
      const data = _vm.dump(dataH);
      const result = await hostFunctions.crypto.hmacSign(key, data);
      return _vm.newString(JSON.stringify(result));
    }
  ));
  _vm.setProp(hostModule, 'crypto', hostCrypto);

  // host-kv
  const hostKv = _vm.newObject();
  _vm.setProp(hostKv, 'kvGet', _vm.newFunction('kvGet', (keyH) => {
    const key = _vm.getString(keyH);
    const val = hostFunctions.kv.kvGet(key);
    return val !== undefined ? _vm.newString(val) : _vm.undefined;
  }));
  _vm.setProp(hostKv, 'kvSet', _vm.newFunction('kvSet', (keyH, valueH, ttlH) => {
    hostFunctions.kv.kvSet(
      _vm.getString(keyH),
      _vm.getString(valueH),
      ttlH !== _vm.undefined ? _vm.getNumber(ttlH) : undefined
    );
    return _vm.undefined;
  }));
  _vm.setProp(hostModule, 'kv', hostKv);

  _vm.setProp(_vm.global, '__dokkebi_host__', hostModule);

  // ── 백엔드 JS 번들 로드 및 QuickJS VM 내에서 실행 ──────────
  const bundleCode = await fetch(bundleUrl).then(r => r.text());
  const evalResult = _vm.evalCode(bundleCode, 'backend-bundle.js');
  if (evalResult.error) {
    const err = _vm.dump(evalResult.error);
    evalResult.error.dispose();
    throw new Error('[dokkebi] 백엔드 초기화 실패: ' + JSON.stringify(err));
  }
  evalResult.value.dispose();

  _handleRequest = _vm.getProp(_vm.global, '__dokkebi_handle_request__');

  console.log('[dokkebi] ✅ QuickJS Async VM 백엔드 초기화 완료 (로컬 WASM)');
  return { initialized: true };
}

/**
 * 요청 처리 (QuickJS VM 내부에서 실행)
 * @param {object} req - { method, path, query, body, headers }
 * @returns {Promise<{status, body, headers}>}
 */
export async function handleRequest(req) {
  if (!_vm || !_handleRequest) {
    throw new Error('[dokkebi] 백엔드가 초기화되지 않았습니다. initDokkebiBackend()를 먼저 호출하세요.');
  }
  const reqStr = _vm.newString(JSON.stringify(req));
  const resultHandle = await _vm.callFunction(_handleRequest, _vm.undefined, [reqStr]);
  reqStr.dispose();

  if (resultHandle.error) {
    const err = _vm.dump(resultHandle.error);
    resultHandle.error.dispose();
    throw new Error('[dokkebi] 요청 처리 오류: ' + JSON.stringify(err));
  }
  const responseStr = _vm.getString(resultHandle.value);
  resultHandle.value.dispose();
  return JSON.parse(responseStr);
}
`;
}

// ─────────────────────────────────────────────────────────────
// 통합 빌드 함수
// ─────────────────────────────────────────────────────────────

export async function buildWasm(opts) {
    const { backendEntry, backendDir, outDir, dbType = 'd1', logCollectLevel, bundleEncrypt } = opts;

    await fs.mkdir(outDir, { recursive: true });

    const jsBundlePath = path.join(outDir, 'backend-source.js');

    console.log('[dokkebi:wasm] Step 1: TypeScript → ESM 번들...');
    const bundle = await bundleBackendForWasm({
        backendEntry,
        outFile: jsBundlePath,
        backendDir,
        logCollectLevel,
    });
    console.log(`[dokkebi:wasm] 번들 완료: ${bundle.outFile} (${(bundle.size / 1024).toFixed(1)} KB)`);

    const encryptBundle = isBundleEncryptEnabled(bundleEncrypt, typeof process !== 'undefined' && process.env ? process.env : {});
    const plainBundlePath = path.join(outDir, 'backend-bundle.js');

    if (!encryptBundle) {
        // dok dev / bootstrap 평문 경로는 backend-bundle.js 를 fetch 한다. Step 1 과 동기화.
        await fs.copyFile(jsBundlePath, plainBundlePath);
        console.log(`[dokkebi:wasm]   평문 백엔드 동기화: ${path.basename(plainBundlePath)} ← ${path.basename(jsBundlePath)}`);
        console.log('[dokkebi:wasm] Step 2A: 생략 (평문 번들 — security.bundleEncrypt:false 또는 DOKKEBI_BUNDLE_ENCRYPT=off)');
        delete bundle.envSecrets.__DOKKEBI_BC_KEY__;
        delete bundle.envSecrets.__DOKKEBI_BC_KEY_MAP__;
        delete bundle.envSecrets.__DOKKEBI_BC_HASH__;
        const plainBuf = await fs.readFile(plainBundlePath);
        const bundleHash = createHash('sha256').update(plainBuf).digest('hex');
        await fs.writeFile(path.join(outDir, 'backend-bundle.sha256'), bundleHash, 'utf-8');
        const chunkManifest = _buildChunkManifest(plainBuf);
        await fs.writeFile(
            path.join(outDir, 'backend-bundle.chunks.json'),
            JSON.stringify(chunkManifest),
            'utf-8',
        );
        await removeLegacyEncBundleArtifacts(outDir);
        const bytecodeResult = { bundleHash, chunkManifest, bundleAssetName: null };
        const buildResult = await buildEncryptedRuntimeBundle({ outDir, bytecodeResult });
        buildResult.bundleHash = bundleHash;
        buildResult.bundleAssetName = null;
        buildResult.chunkManifest = chunkManifest;
        buildResult.mode = 'plain-bundle';
        buildResult.bytecodeMode = false;
        buildResult.encryptedTextMode = false;
        buildResult.bytecodeEncrypted = false;
        console.log(`[dokkebi:wasm] 평문 번들 SHA-256: ${bundleHash.slice(0, 16)}... (attestation chunks: ${chunkManifest.count})`);
        return {
            ...buildResult,
            jsBundlePath,
            dbType,
            outDir,
            envSecrets: bundle.envSecrets,
            sensitiveEnvUsages: bundle.sensitiveEnvUsages || [],
        };
    }

    // 암호화: 평문 backend-bundle.js 는 작성하지 않는다(배포 정적 경로 비노출). 이전 평문 빌드 잔재만 제거.
    try {
        await fs.unlink(plainBundlePath);
    } catch (e) {
        if (e.code !== 'ENOENT') console.warn('[dokkebi:wasm]   경고: 기존 backend-bundle.js 삭제 실패:', e?.message || e);
    }

    // Step 2A: 2중 보호 번들 (JS 난독화 → AES-256-GCM 암호화)
    console.log('[dokkebi:wasm] Step 2A: 2중 보호 빌드 (난독화 + AES)...');
    const bytecodeResult = await compileToBytecodeBundled({ jsBundlePath, outDir });

    // Step 2B: 로컬 QuickJS WASM 런타임 번들
    const buildResult = await buildEncryptedRuntimeBundle({ outDir, bytecodeResult });
    buildResult.bundleHash = bytecodeResult.bundleHash;
    buildResult.bundleAssetName = bytecodeResult.bundleAssetName || null;
    buildResult.chunkManifest = bytecodeResult.chunkManifest || null;
    buildResult.mode = 'encrypted-bundle';
    buildResult.bytecodeMode = false;
    buildResult.encryptedTextMode = true;
    if (bytecodeResult.bytecodeKey) {
        bundle.envSecrets.__DOKKEBI_BC_KEY__ = bytecodeResult.bytecodeKey;
        buildResult.bytecodeEncrypted = true;
    }
    console.log(`[dokkebi:wasm] 🛡 보안: 2중 보호 활성 (난독화 + AES-256-GCM)`);

    try {
        await fs.unlink(jsBundlePath);
        console.log(`[dokkebi:wasm]   암호화 빌드: ${path.basename(jsBundlePath)} 제거 (배포 산출물에서 제외)`);
    } catch (e) {
        console.warn('[dokkebi:wasm]   경고: backend-source.js 삭제 실패:', e?.message || e);
    }

    return {
        ...buildResult,
        jsBundlePath,
        dbType,
        outDir,
        envSecrets: bundle.envSecrets,
        sensitiveEnvUsages: bundle.sensitiveEnvUsages || [],
    };
}
