/**
 * dokkebi Plugin Loader
 *
 * 플러그인 시스템 핵심 모듈.
 * dokkebi.config.js의 plugins 섹션을 읽어 Host/Guest 바인딩 코드를 생성합니다.
 *
 * 플러그인 로드 우선순위:
 *   1. 프로젝트 로컬: {projectRoot}/plugins/plugin-{name}.js
 *   2. npm 패키지:    node_modules/dokkebi-plugin-{name}
 *   3. CLI 빌트인:    dokkebi-cli/src/plugins/plugin-{name}.js
 *      - 현재 빌트인: fetch, bundle
 *      - `ai` 는 v5.3 에서 CLI 빌트인에서 **제거**됨 (API 키 브라우저 노출 우려).
 *        examples/plugins/plugin-ai.js 로 이동됨. 사용자가 프로젝트에
 *        직접 복사하거나 서버 프록시로 대체해야 합니다.
 *
 * 플러그인 인터페이스:
 *   name          — 플러그인 식별자 (fetch, bundle, ...)
 *   permissions   — 필요 권한 목록 (보안 검증용)
 *   hostCode(cfg) — Host JS 코드 (브라우저 부트스트랩에 주입)
 *   vmBridge(cfg) — QuickJS VM ↔ Host 브릿지 코드
 *   guestApi()    — Guest(runtime) 측 export 코드
 *   validate(cfg) — 설정 유효성 검증
 */

import path from 'path';
import fs from 'fs/promises';
import { fileURLToPath } from 'url';
import { loadDokkebiConfigMerged } from './dokkebiConfigLoad.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// CLI 빌트인 플러그인 — core 동작에 필요한 것만 유지.
// `ai` 는 v5.3 에서 제거되었습니다 (브라우저 직접 API 호출 → 키 노출 우려).
// 사용자가 자신의 프로젝트 `plugins/plugin-ai.js` 로 복사하거나
// `examples/safe-ai-proxy/` 처럼 서버 프록시를 사용해야 합니다.
const BUILTIN_PLUGINS = ['fetch', 'bundle'];

// CLI 에서 의도적으로 제거된 플러그인 — 활성화 시도 시 명확한 에러 메시지 출력.
const REMOVED_BUILTIN_PLUGINS = {
    ai: {
        removedIn: 'v5.3',
        reason:
            '브라우저에서 Anthropic API 를 직접 호출하는 구조라 x-api-key 가 ' +
            '네트워크 탭에 관찰 가능. 프로덕션에 배포 시 API 키가 ' +
            '누구에게나 노출되는 결과를 초래합니다.',
        migration:
            '① 서버 프록시 사용(권장): functions/api/ai/complete.ts 같은 Pages Function ' +
            '에서 env.ANTHROPIC_API_KEY 를 보관하고, 클라이언트는 해당 엔드포인트만 호출. ' +
            '② 개인/내부 프로젝트 한정: examples/plugins/plugin-ai.js 를 프로젝트의 ' +
            'plugins/plugin-ai.js 로 복사 (위험을 이해하고 사용).',
    },
};

/**
 * 플러그인 모듈을 우선순위에 따라 로드합니다.
 * 프로젝트 로컬 → npm 패키지 → CLI 빌트인 순서로 탐색.
 *
 * @param {string} name
 * @param {string} sourceRoot
 * @param {{ skipBuiltin?: boolean }} opts - skipBuiltin=true 면 CLI 빌트인
 *   폴백을 건너뜀. REMOVED_BUILTIN_PLUGINS 에서 호출 시 사용.
 */
async function resolvePlugin(name, sourceRoot, opts = {}) {
    for (const ext of ['.js', '.mjs']) {
        const localPath = path.join(sourceRoot, 'plugins', `plugin-${name}${ext}`);
        try {
            await fs.access(localPath);
            const mod = await import(localPath + '?t=' + Date.now());
            return { module: mod, source: 'local' };
        } catch { /* 없음 — 다음 경로 시도 */ }
    }

    try {
        const mod = await import(`dokkebi-plugin-${name}`);
        return { module: mod, source: 'npm' };
    } catch { /* 없음 — 빌트인 폴백 */ }

    if (!opts.skipBuiltin) {
        try {
            const mod = await import(`../plugins/plugin-${name}.js`);
            return { module: mod, source: 'builtin' };
        } catch { /* 없음 */ }
    }

    return null;
}

/**
 * dokkebi.config.js에서 플러그인 설정을 읽고 로딩합니다.
 *
 * 특수 처리:
 *   - REMOVED_BUILTIN_PLUGINS 에 해당하는 플러그인은
 *     · 프로젝트 로컬(`{sourceRoot}/plugins/plugin-{name}.js`) 또는
 *     · npm 패키지(`dokkebi-plugin-{name}`) 가 존재할 때만 로드됩니다.
 *     CLI 빌트인 폴백은 사용되지 않으며, 로컬/npm 도 없으면
 *     NODE_ENV=production 에서는 빌드 실패, dev 에서는 경고.
 */
export async function loadPlugins(sourceRoot) {
    const config = await loadDokkebiConfigMerged(sourceRoot);
    const pluginsConfig = config?.plugins || {};
    const plugins = [];
    const isProduction = String(process.env.NODE_ENV || '').toLowerCase() === 'production';

    // config에 명시된 플러그인 이름 수집 (빌트인 + 커스텀 모두 포함)
    const pluginNames = new Set([
        ...BUILTIN_PLUGINS,
        ...Object.keys(pluginsConfig),
    ]);

    for (const name of pluginNames) {
        const cfg = pluginsConfig[name];
        if (!cfg || cfg.enabled === false) continue;

        const removed = REMOVED_BUILTIN_PLUGINS[name];

        try {
            const resolved = await resolvePlugin(name, sourceRoot, { skipBuiltin: !!removed });

            if (!resolved) {
                if (removed) {
                    const msg =
                        `[dokkebi:plugin] ⚠ '${name}' 플러그인은 dokkebi-cli ${removed.removedIn} 에서 CLI 빌트인에서 제거되었습니다.\n` +
                        `    이유: ${removed.reason}\n` +
                        `    대응: ${removed.migration}`;
                    if (isProduction) {
                        throw new Error(msg + `\n    (NODE_ENV=production 이므로 빌드 실패)`);
                    }
                    console.warn(msg);
                    continue;
                }
                console.warn(`[dokkebi:plugin] ⚠ ${name} 플러그인을 찾을 수 없습니다`);
                continue;
            }

            const plugin = (resolved.module.default || resolved.module)(cfg);

            if (plugin.validate) {
                const err = plugin.validate(cfg);
                if (err) {
                    console.warn(`[dokkebi:plugin] ⚠ ${name}: ${err}`);
                    continue;
                }
            }

            const sourceLabel = { local: '로컬', npm: 'npm', builtin: '빌트인' }[resolved.source];
            plugins.push({ name, config: cfg, ...plugin });
            console.log(`[dokkebi:plugin] ✅ ${name} 플러그인 로드됨 (${sourceLabel})`);

            if (removed) {
                console.warn(
                    `[dokkebi:plugin] ⚠ '${name}' 는 dokkebi-cli ${removed.removedIn} 에서 보안상 빌트인에서 제거되었습니다.\n` +
                    `    ${resolved.source === 'local' ? '프로젝트 로컬 파일' : 'npm 패키지'}에서 로드되었으나 ` +
                    `배포 전 다음을 반드시 검토하세요:\n    ${removed.migration}`
                );
                if (isProduction && !cfg.acknowledgeKeyExposure) {
                    throw new Error(
                        `[dokkebi:plugin] NODE_ENV=production 에서 '${name}' 플러그인은 기본 차단됩니다.\n` +
                        `    ${removed.reason}\n` +
                        `    인지하고도 의도적으로 사용하려면 dokkebi.config.js 에 ` +
                        `plugins.${name}.acknowledgeKeyExposure: true 를 추가하세요.`
                    );
                }
            }
        } catch (e) {
            if (isProduction) throw e;
            console.warn(`[dokkebi:plugin] ⚠ ${name} 플러그인 로드 실패: ${e.message}`);
        }
    }

    return plugins;
}

/**
 * 로딩된 플러그인들의 Host 코드를 합쳐서 부트스트랩에 주입할 코드를 생성합니다.
 * 반환값: { hostImplementations, vmBindings }
 */
export function generatePluginBootstrapCode(plugins, envVars = {}) {
    const hostParts = [];
    const vmParts = [];

    for (const plugin of plugins) {
        if (plugin.hostCode) {
            hostParts.push(`\n  // ── Plugin: ${plugin.name} (Host) ──`);
            hostParts.push(plugin.hostCode({ ...plugin.config, env: envVars }));
        }
        if (plugin.vmBridge) {
            vmParts.push(`\n      // ── Plugin: ${plugin.name} (VM Bridge) ──`);
            vmParts.push(plugin.vmBridge({ ...plugin.config, env: envVars }));
        }
    }

    return {
        hostImplementations: hostParts.join('\n'),
        vmBindings: vmParts.join('\n'),
    };
}

/**
 * 로딩된 플러그인들의 Guest API 코드를 생성합니다.
 * dokkebi-runtime에 합쳐져 esbuild 번들에 포함됩니다.
 */
export function generatePluginGuestCode(plugins) {
    const parts = [];
    for (const plugin of plugins) {
        if (plugin.guestApi) {
            parts.push(`// ── Plugin Guest API: ${plugin.name} ──`);
            parts.push(plugin.guestApi());
        }
    }
    return parts.join('\n');
}

/**
 * 플러그인이 __dokkebi_host__ 에 등록하는 키 목록 반환
 */
export function getPluginHostKeys(plugins) {
    return plugins.map(p => p.name);
}
