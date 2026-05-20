/**
 * dokkebi.config.js (JS/MJS) 문자열에 보안 관련 값만 최소 치환.
 * 복잡한 포맷·주석·중첩은 놓칠 수 있으므로 실패 시 manualSnippets 로 안내한다.
 */

import { t } from '../i18n/index.js';

/**
 * @param {object} obj
 * @param {string} dotPath e.g. "security.panelIpGuard"
 */
export function getAtPath(obj, dotPath) {
    const parts = dotPath.split('.').filter(Boolean);
    let cur = obj;
    for (const p of parts) {
        if (cur == null || typeof cur !== 'object') return undefined;
        cur = cur[p];
    }
    return cur;
}

/**
 * @param {object} obj — mutate
 * @param {string} dotPath
 * @param {unknown} value
 */
export function setAtPath(obj, dotPath, value) {
    const parts = dotPath.split('.').filter(Boolean);
    if (parts.length === 0) return;
    let cur = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        const p = parts[i];
        if (cur[p] == null || typeof cur[p] !== 'object') cur[p] = {};
        cur = cur[p];
    }
    cur[parts[parts.length - 1]] = value;
}

/**
 * @param {string} text
 * @param {object} baseline
 * @param {object} draft
 * @returns {{ text: string, manualSnippets: string[], warnings: string[] }}
 */
export function patchDokkebiConfigText(text, baseline, draft) {
    const manualSnippets = [];
    const warnings = [];
    let out = text;

    const tryPatch = (name, fn) => {
        const r = fn(out, baseline, draft);
        if (r.ok) out = r.text;
        else {
            warnings.push(
                t('security.patchSkipped', {
                    name,
                    reason: r.reason || t('security.patchReasonDefault'),
                }),
            );
            if (r.snippet) manualSnippets.push(r.snippet);
        }
    };

    tryPatch('security.level', patchSecurityLevel);
    tryPatch('security.panelIpGuard', patchPanelIpGuard);
    tryPatch('security.strictCsp', patchStrictCsp);
    // security.bundleEncrypt 는 항상 강제 ON — 토글/패치 경로 제거.
    tryPatch('security.activeDefense.enabled', patchActiveDefenseEnabled);
    tryPatch('security.activeDefense.mode', patchActiveDefenseMode);
    tryPatch('security.capabilities.enabled', patchCapabilitiesEnabled);
    tryPatch('security.attestation.enabled', patchAttestationEnabled);
    tryPatch('security.advisor.disable', patchAdvisorDisable);
    tryPatch('security.webauthn.enabled', patchWebauthnEnabled);
    tryPatch('queryRegistry.enabled', patchQueryRegistryEnabled);
    tryPatch('queryRegistry.strict', patchQueryRegistryStrict);
    tryPatch('policy.enabled', patchPolicyEnabled);
    tryPatch('authorization.enabled', patchAuthorizationEnabled);
    tryPatch('policy.mode', patchPolicyMode);
    tryPatch('authorization.mode', patchAuthorizationMode);

    return { text: out, manualSnippets, warnings };
}

function eq(a, b) {
    return a === b || (Number.isNaN(a) && Number.isNaN(b));
}

/** @param {string} s */
function escapeSingleQuotedJs(s) {
    return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

/**
 * Insert a full top-level block immediately before `security: {`. Fallback: after `export default {`.
 * @param {string} text
 * @param {string} blockLine e.g. "  policy: { enabled: true },"
 * @returns {string | null}
 */
function insertBeforeSecurityBlock(text, blockLine) {
    const re = /(\n)(\s*security:\s*\{)/;
    if (re.test(text)) return text.replace(re, `$1${blockLine}$1$2`);
    const re2 = /(\bexport\s+default\s*\{)/;
    if (re2.test(text)) return text.replace(re2, `$1\n${blockLine}`);
    return null;
}

/**
 * @param {string} text
 * @param {string} snippet property lines after "security: {" (comma-terminated entries)
 * @returns {string | null}
 */
function insertInsideSecurityBlock(text, snippet) {
    const re = /(\bsecurity:\s*\{)/;
    if (!re.test(text)) return null;
    return text.replace(re, `$1\n    ${snippet}\n`);
}

/**
 * Insert after a single-line activeDefense object, or after multi-line block's closing `},`.
 * @param {string} text
 * @param {string} snippet
 */
function insertAfterActiveDefenseBlock(text, snippet) {
    const single = /(\bactiveDefense:\s*\{[^}]*\},\s*\n)/;
    if (single.test(text)) return text.replace(single, `$1    ${snippet}\n`);

    const multi = /(\bactiveDefense:\s*\{[\s\S]*?\n\s*\},\s*\n)/m;
    if (multi.test(text)) return text.replace(multi, `$1    ${snippet}\n`);

    return null;
}

function patchSecurityLevel(text, baseline, draft) {
    const b = String(getAtPath(baseline, 'security.level') || '').replace(/['"]/g, '');
    const d = String(getAtPath(draft, 'security.level') || '').replace(/['"]/g, '');
    if (eq(b, d)) return { ok: true, text };

    if (!d) {
        const re = /^\s*level:\s*['"][^'"]*['"],?\s*$/m;
        if (!re.test(text)) {
            return {
                ok: false,
                reason: t('security.patch.levelRemoveNotFound'),
                snippet:
                    '// security.level 을 끄려면 해당 줄을 삭제하세요 (미설정 = 프리셋 없음).\n',
            };
        }
        return { ok: true, text: text.replace(re, '') };
    }

    const re = /(\blevel:\s*)(['"])([^'"]*)\2/;
    if (!re.test(text)) {
        return {
            ok: false,
            reason: t('security.patch.levelKeyNotFound'),
            snippet: `    level: '${d}',   // security 블록 안에 추가\n`,
        };
    }
    return { ok: true, text: text.replace(re, `$1$2${d}$2`) };
}

function patchPanelIpGuard(text, baseline, draft) {
    const b = getAtPath(baseline, 'security.panelIpGuard');
    const d = getAtPath(draft, 'security.panelIpGuard');
    const bv = b === true || b?.enabled === true;
    const dv = d === true || d?.enabled === true;
    if (bv === dv) return { ok: true, text };

    const re = /(\bpanelIpGuard:\s*)(true|false)/;
    if (!re.test(text)) {
        return {
            ok: false,
            reason: t('security.patch.panelIpGuardPattern'),
            snippet:
                '    panelIpGuard: true,  // security 블록 + .env DOKKEBI_PANEL_ALLOWED_IPS\n',
        };
    }
    return { ok: true, text: text.replace(re, `$1${dv}`) };
}

function patchStrictCsp(text, baseline, draft) {
    const b = getAtPath(baseline, 'security.strictCsp') === true;
    const d = getAtPath(draft, 'security.strictCsp') === true;
    if (b === d) return { ok: true, text };

    const re = /(\bstrictCsp:\s*)(true|false)/;
    if (re.test(text)) return { ok: true, text: text.replace(re, `$1${d}`) };

    const ins = /(\bsecurity:\s*\{)/;
    if (!ins.test(text)) {
        return {
            ok: false,
            reason: t('security.patch.securityBlockMissing'),
            snippet: '    strictCsp: true,  // security 객체 안\n',
        };
    }
    return { ok: true, text: text.replace(ins, `$1\n    strictCsp: ${d},`) };
}

function patchActiveDefenseEnabled(text, baseline, draft) {
    const b = getAtPath(baseline, 'security.activeDefense.enabled') === true;
    const d = getAtPath(draft, 'security.activeDefense.enabled') === true;
    if (b === d) return { ok: true, text };

    const re = /(\bactiveDefense:\s*\{[\s\S]*?\n\s*)enabled:\s*(true|false)/m;
    const reSameLine = /(\bactiveDefense:\s*\{\s*)enabled:\s*(true|false)/;
    if (re.test(text)) return { ok: true, text: text.replace(re, `$1enabled: ${d}`) };
    if (reSameLine.test(text)) return { ok: true, text: text.replace(reSameLine, `$1enabled: ${d}`) };

    const mode = escapeSingleQuotedJs(String(getAtPath(draft, 'security.activeDefense.mode') || 'monitor'));
    const trigger = escapeSingleQuotedJs(String(getAtPath(draft, 'security.activeDefense.trigger') || 'lazy'));
    const snippet = `activeDefense: { enabled: ${d}, mode: '${mode}', trigger: '${trigger}' },`;
    const ins = insertInsideSecurityBlock(text, snippet);
    if (ins) return { ok: true, text: ins };

    return {
        ok: false,
        reason: t('security.patch.activeDefenseEnabledPattern'),
        snippet:
            "    activeDefense: { enabled: true, mode: 'monitor', trigger: 'lazy' },\n",
    };
}

function patchActiveDefenseMode(text, baseline, draft) {
    const b = String(getAtPath(baseline, 'security.activeDefense.mode') || '');
    const d = String(getAtPath(draft, 'security.activeDefense.mode') || '');
    if (b === d) return { ok: true, text };

    const dq = escapeSingleQuotedJs(d);
    const re = /(\bactiveDefense:\s*\{[\s\S]*?\n\s*mode:\s*)['"]([^'"]+)['"]/m;
    const reSameLine = /(\bactiveDefense:\s*\{[^}]*mode:\s*)['"]([^'"]+)['"]/;
    if (re.test(text)) return { ok: true, text: text.replace(re, `$1'${dq}'`) };
    if (reSameLine.test(text)) return { ok: true, text: text.replace(reSameLine, `$1'${dq}'`) };

    const en = getAtPath(draft, 'security.activeDefense.enabled') === true;
    const trigger = escapeSingleQuotedJs(String(getAtPath(draft, 'security.activeDefense.trigger') || 'lazy'));
    const snippet = `activeDefense: { enabled: ${en}, mode: '${dq}', trigger: '${trigger}' },`;
    const ins = insertInsideSecurityBlock(text, snippet);
    if (ins) return { ok: true, text: ins };

    return {
        ok: false,
        reason: t('security.patch.activeDefenseModePattern'),
        snippet: "      mode: 'enforce',  // 'monitor' | 'enforce'\n",
    };
}

function patchCapabilitiesEnabled(text, baseline, draft) {
    const b = getAtPath(baseline, 'security.capabilities.enabled') === true;
    const d = getAtPath(draft, 'security.capabilities.enabled') === true;
    if (b === d) return { ok: true, text };

    const re = /(\bcapabilities:\s*\{[\s\S]*?\n\s*)enabled:\s*(true|false)/m;
    const reSameLine = /(\bcapabilities:\s*\{\s*)enabled:\s*(true|false)/;
    if (re.test(text)) return { ok: true, text: text.replace(re, `$1enabled: ${d}`) };
    if (reSameLine.test(text)) return { ok: true, text: text.replace(reSameLine, `$1enabled: ${d}`) };

    const secretEnv = escapeSingleQuotedJs(
        String(getAtPath(draft, 'security.capabilities.secretEnv') || 'DOKKEBI_CAPABILITY_SECRET'),
    );
    const snippet = `capabilities: { enabled: ${d}, secretEnv: '${secretEnv}', features: {} },`;

    let next = insertAfterActiveDefenseBlock(text, snippet);
    if (next) return { ok: true, text: next };

    next = insertInsideSecurityBlock(text, snippet);
    if (next) return { ok: true, text: next };

    return {
        ok: false,
        reason: t('security.patch.capabilitiesEnabledPattern'),
        snippet:
            '    capabilities: { enabled: true, secretEnv: \'DOKKEBI_CAPABILITY_SECRET\', features: { } },\n',
    };
}

function patchAttestationEnabled(text, baseline, draft) {
    const b = getAtPath(baseline, 'security.attestation.enabled');
    const d = getAtPath(draft, 'security.attestation.enabled');
    if (b === d) return { ok: true, text };

    const re = /(\battestation:\s*\{[\s\S]*?\n\s*)enabled:\s*(true|false)/m;
    if (re.test(text)) return { ok: true, text: text.replace(re, `$1enabled: ${d === true}`) };

    if (d === true || d === false) {
        const ins = /(\bsecurity:\s*\{)/;
        if (!ins.test(text)) return { ok: false, reason: t('security.patch.securityBlockMissing'), snippet: '' };
        return {
            ok: true,
            text: text.replace(ins, `$1\n    attestation: { enabled: ${d === true} },`),
        };
    }
    return { ok: true, text };
}

function patchAdvisorDisable(text, baseline, draft) {
    const b = getAtPath(baseline, 'security.advisor.disable') === true;
    const d = getAtPath(draft, 'security.advisor.disable') === true;
    if (b === d) return { ok: true, text };

    const re = /(\badvisor:\s*\{[\s\S]*?\n\s*)disable:\s*(true|false)/m;
    if (re.test(text)) return { ok: true, text: text.replace(re, `$1disable: ${d}`) };

    const ins = /(\bsecurity:\s*\{)/;
    if (!ins.test(text)) return { ok: false, reason: t('security.patch.securityBlockMissing'), snippet: '' };
    return {
        ok: true,
        text: text.replace(ins, `$1\n    advisor: { disable: ${d} },`),
    };
}

function patchWebauthnEnabled(text, baseline, draft) {
    const b = getAtPath(baseline, 'security.webauthn.enabled') === true;
    const d = getAtPath(draft, 'security.webauthn.enabled') === true;
    if (b === d) return { ok: true, text };

    const re = /(\bwebauthn:\s*\{[\s\S]*?\n\s*)enabled:\s*(true|false)/m;
    if (!re.test(text)) {
        return {
            ok: false,
            reason: t('security.patch.webauthnSkip'),
            snippet:
                '    webauthn: { enabled: true },  // docs/design/WEBAUTHN.md — 회원가입/로그인에 register/authenticate 배선 필요\n',
        };
    }
    return { ok: true, text: text.replace(re, `$1enabled: ${d}`) };
}

function patchQueryRegistryEnabled(text, baseline, draft) {
    const b = getAtPath(baseline, 'queryRegistry.enabled');
    const d = getAtPath(draft, 'queryRegistry.enabled');
    if (b === d) return { ok: true, text };

    const re = /(\bqueryRegistry:\s*\{[\s\S]*?\n\s*)enabled:\s*(true|false)/m;
    if (!re.test(text)) {
        return {
            ok: false,
            reason: t('security.patch.queryRegistryBlock'),
            snippet: '  queryRegistry: { enabled: true },\n',
        };
    }
    const val = d === false ? 'false' : 'true';
    return { ok: true, text: text.replace(re, `$1enabled: ${val}`) };
}

function patchQueryRegistryStrict(text, baseline, draft) {
    const b = getAtPath(baseline, 'queryRegistry.strict') === true;
    const d = getAtPath(draft, 'queryRegistry.strict') === true;
    if (b === d) return { ok: true, text };

    const re = /(\bqueryRegistry:\s*\{[\s\S]*?\n\s*)strict:\s*(true|false)/m;
    if (re.test(text)) return { ok: true, text: text.replace(re, `$1strict: ${d}`) };

    const ins = /(\bqueryRegistry:\s*\{)/;
    if (!ins.test(text)) {
        return {
            ok: false,
            reason: t('security.patch.queryRegistryBlock'),
            snippet: '  queryRegistry: { strict: true },\n',
        };
    }
    return { ok: true, text: text.replace(ins, `$1\n    strict: ${d},`) };
}

function patchPolicyEnabled(text, baseline, draft) {
    const b = getAtPath(baseline, 'policy.enabled') === true;
    const d = getAtPath(draft, 'policy.enabled') === true;
    if (b === d) return { ok: true, text };

    const re = /(\bpolicy:\s*\{[\s\S]*?\n\s*)enabled:\s*(true|false)/m;
    const reSameLine = /(\bpolicy:\s*\{\s*)enabled:\s*(true|false)/;
    if (re.test(text)) return { ok: true, text: text.replace(re, `$1enabled: ${d}`) };
    if (reSameLine.test(text)) return { ok: true, text: text.replace(reSameLine, `$1enabled: ${d}`) };

    const mode = escapeSingleQuotedJs(String(getAtPath(draft, 'policy.mode') || 'verify'));
    const blockLine = `  policy: {\n    enabled: ${d},\n    mode: '${mode}',\n    tables: {},\n  },`;
    const ins = insertBeforeSecurityBlock(text, blockLine);
    if (ins) return { ok: true, text: ins };

    return {
        ok: false,
        reason: t('security.patch.policyEnabledPattern'),
        snippet: '  policy: { enabled: true, mode: \'verify\', tables: { } },\n',
    };
}

function patchAuthorizationEnabled(text, baseline, draft) {
    const b = getAtPath(baseline, 'authorization.enabled') === true;
    const d = getAtPath(draft, 'authorization.enabled') === true;
    if (b === d) return { ok: true, text };

    const re = /(\bauthorization:\s*\{[\s\S]*?\n\s*)enabled:\s*(true|false)/m;
    const reSameLine = /(\bauthorization:\s*\{\s*)enabled:\s*(true|false)/;
    if (re.test(text)) return { ok: true, text: text.replace(re, `$1enabled: ${d}`) };
    if (reSameLine.test(text)) return { ok: true, text: text.replace(reSameLine, `$1enabled: ${d}`) };

    const mode = escapeSingleQuotedJs(String(getAtPath(draft, 'authorization.mode') || 'warn'));
    const blockLine = `  authorization: {\n    enabled: ${d},\n    mode: '${mode}',\n    rules: [],\n  },`;
    const ins = insertBeforeSecurityBlock(text, blockLine);
    if (ins) return { ok: true, text: ins };

    return {
        ok: false,
        reason: t('security.patch.authorizationEnabledPattern'),
        snippet:
            "  authorization: { enabled: true, mode: 'warn', rules: [] },\n",
    };
}

function patchPolicyMode(text, baseline, draft) {
    const b = String(getAtPath(baseline, 'policy.mode') || '');
    const d = String(getAtPath(draft, 'policy.mode') || '');
    if (b === d) return { ok: true, text };

    const dq = escapeSingleQuotedJs(d);
    const re = /(\bpolicy:\s*\{[\s\S]*?\n\s*mode:\s*)['"]([^'"]+)['"]/m;
    if (re.test(text)) return { ok: true, text: text.replace(re, `$1'${dq}'`) };

    const en = getAtPath(draft, 'policy.enabled') === true;
    const blockLine = `  policy: {\n    enabled: ${en},\n    mode: '${dq}',\n    tables: {},\n  },`;
    const ins = insertBeforeSecurityBlock(text, blockLine);
    if (ins) return { ok: true, text: ins };

    return { ok: false, reason: t('security.patch.policyModePattern'), snippet: `  policy: { mode: '${d}' },\n` };
}

function patchAuthorizationMode(text, baseline, draft) {
    const b = String(getAtPath(baseline, 'authorization.mode') || '');
    const d = String(getAtPath(draft, 'authorization.mode') || '');
    if (b === d) return { ok: true, text };

    const dq = escapeSingleQuotedJs(d);
    const re = /(\bauthorization:\s*\{[\s\S]*?\n\s*mode:\s*)['"]([^'"]+)['"]/m;
    if (re.test(text)) return { ok: true, text: text.replace(re, `$1'${dq}'`) };

    const en = getAtPath(draft, 'authorization.enabled') === true;
    const blockLine = `  authorization: {\n    enabled: ${en},\n    mode: '${dq}',\n    rules: [],\n  },`;
    const ins = insertBeforeSecurityBlock(text, blockLine);
    if (ins) return { ok: true, text: ins };

    return {
        ok: false,
        reason: t('security.patch.authorizationModePattern'),
        snippet: `  authorization: { mode: '${d}' },\n`,
    };
}
