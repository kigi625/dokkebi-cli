/**
 * Opaque Handle 보안 레이어 v3 (ECDH + HMAC)
 *
 * 설계 원칙:
 *   - WASM(QuickJS) 게스트는 실제 API 키/토큰을 절대 볼 수 없음
 *   - 게스트는 숫자 핸들(101, 102...)만 알고 있음
 *   - 실제 자격증명은 Host JS 클로저 내부에만 존재
 *
 * 보안 계층 (v3):
 *   ┌─────────────────────────────────────────────────────────┐
 *   │  1. ECDH P-256 Ephemeral Key Exchange (Forward Secrecy) │
 *   │     브라우저 ↔ dok serve: 세션마다 새 키 쌍              │
 *   │  2. HKDF-SHA256: encKey(암호화) + sigKey(서명) 별도 파생 │
 *   │  3. AES-256-GCM: DB 쿼리 암호화                         │
 *   │  4. HMAC-SHA256: nonce + timestamp + enc 서명            │
 *   │     → 재전송/변조 공격 방어                              │
 *   │  5. QuickJS Async VM: 백엔드가 실제 WASM 내에서 실행    │
 *   └─────────────────────────────────────────────────────────┘
 *
 * WASM 실행 구조:
 *   Bootstrap
 *     → /dokkebi/dokkebi-qjs.js (로컬 빌드된 QuickJS Async VM)
 *     → /dokkebi/backend-bundle.js (평문 빌드) 또는 backend.bundle.enc (암호화 빌드)
 *     → __dokkebi_handle_request__(reqJson) → 응답 JSON
 */

import fs from 'fs/promises';
import path from 'path';

import { normalizeLogCollectLevel } from './logCollectLevel.js';
import { getAttributionSealTemplateReplacements } from './attributionSeal.js';
import { renderTemplate } from './templateLoader.js';

// ─────────────────────────────────────────────────────────────
// 부트스트랩 HTML 주입 코드 생성
// ─────────────────────────────────────────────────────────────

/**
 * HTML에 주입할 dokkebi 부트스트랩 스크립트 생성
 *
 * @param {object} config
 * @param {string} config.dbType    - 'd1' | 'supabase' | 'appwrite'
 * @param {object} config.dbConfig  - 빌드 타임 .env 자격증명
 * @param {boolean} [config.localDbMode] - true면 sql.js + OPFS/IndexedDB 로컬 DB 모드
 * @param {string}  [config.migrationSql] - 로컬 DB 초기화용 마이그레이션 SQL
 * @returns {string} HTML에 주입할 <script> 블록
 */
export function generateBootstrapScript(config) {
    const { dbType, bundleHash = '', bundleAssetName = '', localDbMode = false, migrationSql = '', buildVer = '',
            pluginHostCode = '', pluginVmBridge = '',
            queryLearn = false, capabilityGuards = { enabled: false, routes: [] },
            bytecodeMode = false, bytecodeEncrypted = false, encryptedTextMode = false,
            payloadWireClient = null, authSession: authSessionInput = null,
            callerCheck: callerCheckInput = 'off', allowedScripts: allowedScriptsInput = [],
            callerCheckAuditUrl = '' } = config;
    const logCollectMin = normalizeLogCollectLevel(
        config.logging?.level ?? config.logCollectLevel,
    );
    const logMinLiteral = JSON.stringify(logCollectMin);
    const authSessionResolved = (() => {
        if (authSessionInput === false) return { enabled: false };
        const o = authSessionInput && typeof authSessionInput === 'object' ? authSessionInput : {};
        return {
            enabled: o.enabled !== false,
            debounceMs: Math.min(60000, Math.max(400, Number(o.debounceMs) || 2000)),
            clearLocalStorageKeys: Array.isArray(o.clearLocalStorageKeys)
                ? o.clearLocalStorageKeys.map((k) => String(k))
                : Array.isArray(o.localStorageKeys)
                    ? o.localStorageKeys.map((k) => String(k))
                    : [],
        };
    })();
    const authSessionJson = JSON.stringify(authSessionResolved);

    // Caller Guard: page 의 frontend 번들에서 온 호출만 허용 (XSS / DevTools 차단)
    //   'off'   — 검사 안 함 (기본)
    //   'audit' — 의심 호출 로깅만 (sendBeacon → callerCheckAuditUrl), 통과는 허용
    //   'block' — 의심 호출 차단 + 로깅
    const callerCheckMode = ['off', 'audit', 'block'].includes(callerCheckInput) ? callerCheckInput : 'off';
    const allowedScripts = Array.isArray(allowedScriptsInput)
        ? allowedScriptsInput.filter((s) => typeof s === 'string' && s.length > 0).map((s) => (s.startsWith('/') ? s : '/' + s))
        : [];
    const allowedScriptsJson = JSON.stringify(allowedScripts);
    const callerCheckAuditUrlStr = typeof callerCheckAuditUrl === 'string' ? callerCheckAuditUrl : '';
    // 무중단 배포(zero-downtime) — 해시 박힌 파일명을 우선 사용한다.
    // bundleAssetName 이 비어있으면(레거시 빌드) 기본 파일명으로 폴백.
    const _encAssetName = bundleAssetName || 'backend.bundle.enc';
    const escapedMigrationSql = localDbMode ? JSON.stringify(migrationSql) : 'null';
    const capabilityGuardsJson = JSON.stringify(capabilityGuards || { enabled: false, routes: [] });
    const payloadWireJson = JSON.stringify(payloadWireClient || {
        rotation: { enabled: false, activeForward: {} },
        pow: { enabled: false, bits: 14 },
    });

    const attrSeal = getAttributionSealTemplateReplacements();
    return renderTemplate('bootstrap.js.tpl', [
        ...attrSeal,
        { find: '__DOKKEBI_PH_BUILD_VER__',                       replace: String(buildVer || '') },
        { find: '__DOKKEBI_PH_BUNDLE_HASH__',                     replace: String(bundleHash || '') },
        { find: '__DOKKEBI_PH_DB_TYPE__',                         replace: String(dbType) },
        { find: '__DOKKEBI_PH_ENC_ASSET__',                       replace: _encAssetName },
        { find: '"__DOKKEBI_PH_LOG_MIN__"',                       replace: logMinLiteral },
        { find: '"__DOKKEBI_PH_PAYLOAD_WIRE__"',                  replace: payloadWireJson },
        { find: '"__DOKKEBI_PH_AUTH_SESSION__"',                  replace: authSessionJson },
        { find: '"__DOKKEBI_PH_CAPABILITY_GUARDS__"',             replace: capabilityGuardsJson },
        { find: '"__DOKKEBI_PH_MIGRATION_SQL__"',                 replace: escapedMigrationSql },
        { find: '/* __DOKKEBI_PH_PLUGIN_HOST__ */',               replace: pluginHostCode || '' },
        { find: '/* __DOKKEBI_PH_PLUGIN_VM_BRIDGE__ */',          replace: pluginVmBridge || '' },
        // ternary booleans — combined first to avoid partial overlap
        { find: '__DOKKEBI_PH_BOOL_ENCRYPTED_TEXT___OR___DOKKEBI_PH_BOOL_BYTECODE_ENC__', replace: (encryptedTextMode || bytecodeEncrypted) ? 'true' : 'false' },
        { find: '__DOKKEBI_PH_BOOL_QUERY_LEARN__',                replace: queryLearn ? 'true' : 'false' },
        { find: '__DOKKEBI_PH_BOOL_BYTECODE_MODE__',              replace: bytecodeMode ? 'true' : 'false' },
        { find: '__DOKKEBI_PH_BOOL_BYTECODE_ENC__',               replace: bytecodeEncrypted ? 'true' : 'false' },
        { find: '__DOKKEBI_PH_BOOL_ENCRYPTED_TEXT__',             replace: encryptedTextMode ? 'true' : 'false' },
        { find: '__DOKKEBI_PH_BOOL_LOCAL_DB__',                   replace: localDbMode ? 'true' : 'false' },
        { find: '"__DOKKEBI_PH_CALLER_CHECK__"',                  replace: JSON.stringify(callerCheckMode) },
        { find: '"__DOKKEBI_PH_ALLOWED_SCRIPTS__"',               replace: allowedScriptsJson },
        { find: '"__DOKKEBI_PH_CALLER_AUDIT_URL__"',              replace: JSON.stringify(callerCheckAuditUrlStr) },
    ]);
}


/** dok build / vite 플러그인이 공유 — 부트스트랩 JWT 무효 정리 옵션 정규화 */
export function normalizeAuthSessionForBootstrap(raw) {
    if (raw === false) return { enabled: false };
    const o = raw && typeof raw === 'object' ? raw : {};
    return {
        enabled: o.enabled !== false,
        debounceMs: Math.min(60000, Math.max(400, Number(o.debounceMs) || 2000)),
        clearLocalStorageKeys: Array.isArray(o.clearLocalStorageKeys)
            ? o.clearLocalStorageKeys.map((k) => String(k))
            : Array.isArray(o.localStorageKeys)
                ? o.localStorageKeys.map((k) => String(k))
                : [],
    };
}

// ─────────────────────────────────────────────────────────────
// HTML 파일 주입
// ─────────────────────────────────────────────────────────────

/**
 * dokkebi 부트스트랩을 `<head>` 바로 다음에 넣으면 `<meta charset>` 이 대형 스크립트 뒤로 밀려
 * 첫 1024바이트 스니핑 규칙을 깨뜨린다. 일부 브라우저에서 파싱·후속 모듈 스크립트 로드가
 * HTML(text/html)로 잘못 해석되는 증상으로 이어질 수 있어, charset/viewport 를 `<head>` 직후로 모은다.
 */
function normalizeHeadCharsetViewport(html) {
    const headMatch = html.match(/<head[^>]*>/i);
    if (!headMatch) return html;

    const charsetMatches = [...html.matchAll(/<meta\s+charset=["'][^"']*["'][^>]*\/?>/gi)];
    const viewportMatches = [...html.matchAll(
        /<meta\s+[^>]*name\s*=\s*["']viewport["'][^>]*\/?>/gi
    )];
    if (charsetMatches.length === 0) return html;

    const charset0 = charsetMatches[0][0].trim();
    const viewport0 = viewportMatches[0]?.[0]?.trim();

    let out = html;
    for (const m of charsetMatches) out = out.replace(m[0], '');
    for (const m of viewportMatches) out = out.replace(m[0], '');

    const early = viewport0 ? `${charset0}\n${viewport0}\n` : `${charset0}\n`;
    return out.replace(headMatch[0], `${headMatch[0]}\n${early}`);
}

export async function injectBootstrap(htmlPath, config) {
    const html = await fs.readFile(htmlPath, 'utf-8');
    const script = generateBootstrapScript(config);

    let patched;
    // 이미 주입됐어도 빌드마다 재주입 (번들 해시 갱신 반영)
    if (html.includes('dokkebi v3 Bootstrap')) {
        patched = html.replace(
            /<!-- dokkebi v3 Bootstrap[\s\S]*?<\/script>/,
            script
        );
        if (patched === html) return false;
    } else if (
        /<meta\s+[^>]*name\s*=\s*["']viewport["'][^>]*\/?>/i.test(html)
    ) {
        patched = html.replace(
            /<meta\s+[^>]*name\s*=\s*["']viewport["'][^>]*\/?>/i,
            (m) => `${m}\n${script}`
        );
    } else if (/<meta\s+charset=["'][^"']*["'][^>]*\/?>/i.test(html)) {
        patched = html.replace(
            /<meta\s+charset=["'][^"']*["'][^>]*\/?>/i,
            (m) => `${m}\n${script}`
        );
    } else if (/<head[^>]*>/i.test(html)) {
        patched = html.replace(/<head[^>]*>/i, (h) => `${h}\n${script}`);
    } else {
        patched = html.replace('</head>', `${script}\n</head>`);
    }

    patched = normalizeHeadCharsetViewport(patched);
    await fs.writeFile(htmlPath, patched, 'utf-8');
    return true;
}

export async function injectBootstrapAll(distDir, config) {
    let count = 0;
    const entries = await fs.readdir(distDir, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(distDir, entry.name);
        if (entry.isDirectory()) {
            count += await injectBootstrapAll(fullPath, config);
        } else if (entry.name.endsWith('.html')) {
            const injected = await injectBootstrap(fullPath, config);
            if (injected) count++;
        }
    }
    return count;
}
