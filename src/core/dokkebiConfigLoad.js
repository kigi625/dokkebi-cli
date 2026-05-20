/**
 * dokkebi.config.js 로드 및 사용자 친화적 별칭/프리셋.
 * build / deploy / dok security / 플러그인 로더에서 공유합니다.
 */

import path from 'path';
import fs from 'fs/promises';
import { existsSync } from 'fs';

/**
 * 문서·구버전 호환: `tenantPolicy` → `policy` (policy 키가 우선).
 * `security.adminPanel.ipAllowlist` 사용 시 한 번 경고.
 *
 * @param {object | null | undefined} raw
 * @param {{ quiet?: boolean }} [opts]
 * @returns {Record<string, unknown>}
 */
export function applyDokkebiConfigAliases(raw, opts = {}) {
    const quiet = opts.quiet === true;
    if (!raw || typeof raw !== 'object') return {};

    const out = { ...raw };
    const tp = raw.tenantPolicy;
    if (tp && typeof tp === 'object' && Object.keys(tp).length > 0) {
        if (!quiet) {
            console.warn(
                '[dokkebi] dokkebi.config.js: 최상위 `tenantPolicy` 는 `policy` 의 별칭으로 병합되었습니다. ' +
                '새 프로젝트는 `policy` 만 쓰는 것을 권장합니다.'
            );
        }
        const pol = raw.policy && typeof raw.policy === 'object' ? raw.policy : {};
        out.policy = { ...tp, ...pol };
        delete out.tenantPolicy;
    }

    const sec = raw.security;
    if (sec && typeof sec === 'object') {
        const legacy = sec.adminPanel?.ipAllowlist;
        const legacyOn = legacy === true || legacy?.enabled === true;
        const modern = sec.panelIpGuard === true || sec.panelIpGuard?.enabled === true;
        if (legacyOn && !modern && !quiet) {
            console.warn(
                '[dokkebi] security.adminPanel.ipAllowlist 는 구문법입니다. ' +
                '`security.panelIpGuard: true` 로 통일하는 것을 권장합니다.'
            );
        }
    }

    return out;
}

function parseConfigTs(source) {
    const config = { database: {}, backend: {} };
    const typeMatch = source.match(/type:\s*['"](\w+)['"]/);
    if (typeMatch) config.database.type = typeMatch[1];
    const entryMatch = source.match(/entry:\s*['"]([^'"]+)['"]/);
    if (entryMatch) config.backend.entry = entryMatch[1];
    const proxyModeMatch = source.match(/proxyMode:\s*['"](\w+)['"]/);
    if (proxyModeMatch) config.proxyMode = proxyModeMatch[1];
    const fields = [
        'accountId', 'databaseId', 'apiToken', 'apiBase',
        'supabaseUrl', 'anonKey', 'serviceKey',
        'endpoint', 'projectId', 'apiKey',
    ];
    for (const field of fields) {
        const re = new RegExp(`${field}:\\s*['"](.*?)['"]`);
        const m = source.match(re);
        if (m) config.database[field] = m[1];
    }
    return config;
}

/**
 * dokkebi.config.{js,mjs,ts} 로드 (빌드와 동일한 후보 순서).
 * @param {string} sourceRoot
 */
export async function loadDokkebiConfig(sourceRoot) {
    const candidates = [
        path.join(sourceRoot, 'dokkebi.config.js'),
        path.join(sourceRoot, 'dokkebi.config.mjs'),
        path.join(sourceRoot, 'dokkebi.config.ts'),
    ];

    for (const candidate of candidates) {
        try {
            await fs.access(candidate);
            if (!candidate.endsWith('.ts')) {
                const mod = await import(candidate + '?t=' + Date.now());
                return mod.default || mod;
            }
            return parseConfigTs(await fs.readFile(candidate, 'utf-8'));
        } catch {
            /* 파일 없음 */
        }
    }
    return null;
}

/**
 * 프로젝트 루트에서 dokkebi 설정 파일 경로 (있는 첫 번째).
 * @param {string} sourceRoot
 * @returns {string | null}
 */
export function findDokkebiConfigPath(sourceRoot) {
    const candidates = [
        path.join(sourceRoot, 'dokkebi.config.js'),
        path.join(sourceRoot, 'dokkebi.config.mjs'),
        path.join(sourceRoot, 'dokkebi.config.ts'),
    ];
    for (const p of candidates) {
        if (existsSync(p)) return p;
    }
    return null;
}

/**
 * @param {string} sourceRoot
 * @param {{ quiet?: boolean }} [opts] — 별칭 경고 억제 (예: CI)
 */
export async function loadDokkebiConfigMerged(sourceRoot, opts = {}) {
    const raw = await loadDokkebiConfig(sourceRoot);
    return applyDokkebiConfigAliases(raw || {}, opts);
}

/**
 * 보안 프리셋 — security.level 한 줄로 핵심 방어 레이어를 일괄 활성화.
 *
 * 레벨:
 *   - 'basic'     — 어떤 강제도 추가하지 않음 (legacy 호환).
 *   - 'standard'  — Tenant Policy verify, Authorization warn, queryRegistry on, autoApply.
 *   - 'strict'    — queryRegistry strict, Tenant inject, Authorization strict.
 *
 * 사용자 명시값(예: policy.mode)은 **항상** 스프레드로 프리셋을 덮어쓴다.
 *
 * @param {object | null | undefined} rawConfig
 * @param {{ quiet?: boolean }} [opts] — true면 콘솔 로그 생략 (dok security 등)
 */
export function applySecurityPreset(rawConfig, opts = {}) {
    const quiet = opts.quiet === true;
    const config = { ...(rawConfig || {}) };
    const level = String(config?.security?.level || '').toLowerCase();

    // 미지정 시 동작은 변경하지 않음(기존 프로젝트 호환). 베이스라인은 `security.level` 로 opt-in.
    if (!level) return config;

    if (level === 'basic') {
        if (!quiet) console.log('[dokkebi] 🔓 보안 레벨: basic — 추가 강제 없음 (legacy 호환 모드)');
        return config;
    }

    const out = { ...config };

    if (level === 'standard') {
        if (!quiet) console.log('[dokkebi] 🔒 보안 레벨: standard — Tenant Policy verify + Authorization warn + 자동 추론 적용');
        out.queryRegistry = {
            enabled: true,
            ...(config.queryRegistry || {}),
        };
        out.policy = {
            enabled: true,
            mode: 'verify',
            autoApply: true,
            ...(config.policy || {}),
        };
        out.authorization = {
            enabled: true,
            mode: 'warn',
            autoApply: true,
            ...(config.authorization || {}),
        };
    } else if (level === 'strict') {
        if (!quiet) console.log('[dokkebi] 🔐 보안 레벨: strict — queryRegistry strict + Tenant inject + Authorization strict');
        out.queryRegistry = {
            enabled: true,
            strict: true,
            ...(config.queryRegistry || {}),
        };
        out.policy = {
            enabled: true,
            mode: 'inject',
            strict: true,
            autoApply: true,
            ...(config.policy || {}),
        };
        out.authorization = {
            enabled: true,
            mode: 'strict',
            autoApply: true,
            ...(config.authorization || {}),
        };
    } else {
        if (!quiet) console.warn(`[dokkebi] ⚠ 알 수 없는 security.level "${level}" — 무시됨 (basic | standard | strict 중 하나여야 함)`);
        return config;
    }

    return out;
}
