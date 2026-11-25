/**
 * dok security — 보안 옵트인 (인터랙티브 TUI / --status 일회 출력)
 */

import path from 'path';
import fs from 'fs/promises';
import {
    loadDokkebiConfigMerged,
    applySecurityPreset,
} from '../core/dokkebiConfigLoad.js';
import { deriveCorsOrigins } from '../core/cors.js';
import { patchDokkebiConfigText } from '../core/securityConfigPatch.js';
import { resolveJwtSecret } from '../core/authorizationPolicy.js';
import { normalizePolicyConfig } from '../core/policyEngine.js';
import { normalizeAuthorizationConfig } from '../core/authorizationPolicy.js';
import { runSecurityInteractive } from './securityInteractive.js';
import { collectSecurityAudit, formatSecurityAudit } from '../core/securityAudit.js';
import { isBundleEncryptEnabled } from '../core/buildWasm.js';
import { t } from '../i18n/index.js';

function yn(v) {
    return v ? t('security.stateOn') : t('security.stateOff');
}

function panelOn(sec) {
    if (!sec || typeof sec !== 'object') return false;
    const d = sec.panelIpGuard;
    const legacy = sec.adminPanel?.ipAllowlist;
    return d === true || d?.enabled === true || legacy === true || legacy?.enabled === true;
}

/**
 * @param {string} src
 */
export async function runSecurityStatus(src = '.') {
    const sourceRoot = path.resolve(process.cwd(), src);
    const merged = await loadDokkebiConfigMerged(sourceRoot, { quiet: false });
    if (!merged || typeof merged !== 'object' || Object.keys(merged).length === 0) {
        console.log('\n' + t('common.prefix') + ' ' + t('security.noConfigJs') + '\n');
        process.exitCode = 1;
        return;
    }

    const withPreset = applySecurityPreset(merged, { quiet: true });
    const sec = withPreset.security && typeof withPreset.security === 'object' ? withPreset.security : {};
    const policyMeta = normalizePolicyConfig(withPreset.policy);
    const authzMeta = normalizeAuthorizationConfig(withPreset.authorization);
    const qr = withPreset.queryRegistry && typeof withPreset.queryRegistry === 'object' ? withPreset.queryRegistry : {};
    const cap = sec.capabilities && typeof sec.capabilities === 'object' ? sec.capabilities : {};
    const adl = sec.activeDefense && typeof sec.activeDefense === 'object' ? sec.activeDefense : {};
    const notSet = t('security.notSet');
    const levelRaw = sec.level != null && String(sec.level).trim() !== '' ? String(sec.level).toLowerCase() : '';
    const level = levelRaw || notSet;

    const attRaw = sec.attestation;
    let attestationOn = false;
    if (attRaw?.enabled === true) attestationOn = true;
    else if (attRaw?.enabled === false) attestationOn = false;
    else attestationOn = cap.enabled === true;

    const pfx = t('common.prefix');
    const rule = t('security.status.ruleLine');
    const sep = '━'.repeat(40);
    console.log(`\n${pfx} ${sep}`);
    console.log(`${pfx} ${t('security.status.title')}`);
    console.log(`${pfx} ${t('security.status.projectRoot', { root: sourceRoot })}`);
    console.log(`${pfx} ${sep}\n`);

    console.log(`  ${rule}\n`);

    const levelHint = level === notSet ? t('security.status.levelUnsetHint') : '';
    console.log(t('security.status.rowLevel', { value: level, hint: levelHint }));
    const qrVal =
        qr.enabled === false
            ? t('security.stateOff')
            : `${t('security.stateOn')}${qr.strict ? t('security.status.strictParen') : ''}`;
    console.log(t('security.status.rowQueryRegistry', { value: qrVal }));
    console.log(
        t('security.status.rowPolicy', {
            yn: yn(policyMeta?.enabled && policyMeta.mode !== 'off'),
            mode: policyMeta?.mode || 'off',
        }),
    );
    console.log(
        t('security.status.rowAuthz', {
            yn: yn(authzMeta?.enabled && authzMeta.mode !== 'off'),
            mode: authzMeta?.mode || 'off',
        }),
    );
    console.log(t('security.status.rowCapabilities', { yn: yn(cap.enabled === true) }));
    console.log(t('security.status.rowAttestation', { yn: yn(attestationOn) }));
    console.log(t('security.status.rowPanelIp', { yn: yn(panelOn(sec)) }));
    const adlDetails =
        adl.enabled === true
            ? `${yn(true)}  (${adl.mode || 'monitor'})`
            : yn(adl.enabled === true);
    console.log(t('security.status.rowActiveDefense', { details: adlDetails }));
    console.log(t('security.status.rowWebauthn', { yn: yn(sec.webauthn?.enabled === true) }));
    console.log(t('security.status.rowStrictCsp', { yn: yn(sec.strictCsp === true) }));
    const bundleEncEff = isBundleEncryptEnabled(sec.bundleEncrypt, typeof process !== 'undefined' && process.env ? process.env : {});
    console.log(t('security.status.rowBundleEncrypt', { yn: yn(bundleEncEff) }));
    const advisorLabel =
        sec.advisor?.disable === true ? t('security.status.advisorOff') : t('security.status.advisorOn');
    console.log(t('security.status.rowAdvisor', { label: advisorLabel }) + '\n');

    console.log(`${pfx} ${t('security.status.interactiveHint')}\n`);
    console.log(`  • ${t('security.status.docsHint')}\n`);
}

/**
 * 읽기 전용 보안 감사 (dok security --audit)
 * @param {string} src
 * @param {{ json?: boolean }} [options]
 */
export async function runSecurityAudit(src = '.', options = {}) {
    const sourceRoot = path.resolve(process.cwd(), src);
    const report = await collectSecurityAudit(sourceRoot);
    if (options.json === true) {
        console.log(JSON.stringify(report, null, 2));
    } else {
        console.log(formatSecurityAudit(report));
    }
    // CI 에서 사용할 수 있도록 error 가 있으면 실패 코드.
    if (report.counts.error > 0) process.exitCode = 1;
}

async function _readDotEnv(root) {
    try {
        const text = await fs.readFile(path.join(root, '.env'), 'utf-8');
        const out = {};
        for (const line of text.split(/\r?\n/)) {
            const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/.exec(line);
            if (!m) continue;
            let v = m[2].trim();
            if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
                v = v.slice(1, -1);
            }
            out[m[1]] = v;
        }
        return out;
    } catch {
        return {};
    }
}

async function _findConfigPath(root) {
    for (const name of ['dokkebi.config.js', 'dokkebi.config.mjs']) {
        const p = path.join(root, name);
        try { await fs.access(p); return p; } catch { /* next */ }
    }
    return null;
}

/**
 * 보안 설정 자동 보정 (dok security --fix)
 * - 배포 설정에서 CORS allowedOrigins 유도
 * - --preset production 시 security.preset + level(strict) 설정
 * - 필수 시크릿 누락을 보고 (값은 절대 생성/기록하지 않음)
 *
 * @param {string} sourceRoot
 * @param {{ write?: boolean, preset?: string, json?: boolean }} [options]
 */
export async function runSecurityFix(sourceRoot, options = {}) {
    const root = path.resolve(sourceRoot);
    const raw = await loadDokkebiConfigMerged(root, { quiet: true });
    if (!raw || typeof raw !== 'object' || Object.keys(raw).length === 0) {
        console.error('[dokkebi] dokkebi.config.js 를 찾을 수 없습니다.');
        process.exitCode = 1;
        return;
    }
    const configPath = await _findConfigPath(root);
    if (!configPath) {
        console.error('[dokkebi] dokkebi.config.js / .mjs 를 찾을 수 없습니다.');
        process.exitCode = 1;
        return;
    }

    const sec = raw.security && typeof raw.security === 'object' ? raw.security : {};
    const existingOrigins = Array.isArray(sec.cors?.allowedOrigins)
        ? sec.cors.allowedOrigins.map((v) => String(v || '').trim()).filter(Boolean)
        : [];
    const derivedOrigins = sec.cors?.auto === false
        ? []
        : deriveCorsOrigins(raw, { projectName: path.basename(root) });

    const draft = { ...raw, security: { ...sec } };
    const changes = [];
    if (options.preset) {
        const preset = String(options.preset).toLowerCase();
        if (preset !== 'production') {
            console.warn('[dokkebi] ⚠ 지원하는 preset 은 production 뿐입니다.');
        } else {
            draft.security.preset = 'production';
            draft.security.level = 'strict';
            changes.push("security.preset = 'production' (level: strict)");
        }
    }
    if (existingOrigins.length === 0 && derivedOrigins.length > 0) {
        draft.security.cors = { ...(sec.cors || {}), allowedOrigins: derivedOrigins };
        changes.push(`security.cors.allowedOrigins = [${derivedOrigins.join(', ')}]`);
    }

    const text = await fs.readFile(configPath, 'utf-8');
    const patched = patchDokkebiConfigText(text, raw, draft);

    const env = { ...process.env, ...(await _readDotEnv(root)) };
    // --preset production 은 effective config 에서 authorization 을 켜므로,
    // 필수 시크릿 판정도 프리셋 적용 후 설정을 기준으로 한다.
    const effective = applySecurityPreset({ ...raw, security: { ...sec, ...(draft.security.preset ? { preset: draft.security.preset, level: draft.security.level } : {}) } }, { quiet: true });
    const required = [];
    const authzCfg = effective.authorization;
    const authzEnabled = authzCfg?.enabled === true
        || !!(authzCfg?.rules && Object.keys(authzCfg.rules).length > 0)
        || effective.auth?.login?.enabled === true;
    if (authzEnabled) {
        const jwt = resolveJwtSecret(env, authzCfg);
        required.push({
            name: 'JWT_SECRET (또는 DOKKEBI_JWT_SECRET)',
            required: true,
            present: !!jwt.secret,
            reason: 'Authorization/로그인 JWT 검증',
        });
    }
    const cap = effective.security?.capabilities;
    if (cap?.enabled === true) {
        const name = String(cap.secretEnv || 'DOKKEBI_CAPABILITY_SECRET');
        required.push({
            name,
            required: true,
            present: !!String(env[name] || ''),
            reason: 'Signed Unlock Token 서명',
        });
    }
    required.push({
        name: 'DOKKEBI_ADMIN_PASSWORD',
        required: false,
        present: !!String(env.DOKKEBI_ADMIN_PASSWORD || ''),
        reason: '관제 패널 사용 시 (미설정이면 503)',
    });
    required.push({
        name: 'DOKKEBI_PANEL_ALLOWED_IPS',
        required: false,
        present: !!String(env.DOKKEBI_PANEL_ALLOWED_IPS || ''),
        reason: 'panelIpGuard 사용 시 (선택)',
    });

    const result = {
        configPath,
        derivedOrigins,
        existingOrigins,
        changes,
        manualSnippets: patched.manualSnippets,
        warnings: patched.warnings,
        requiredSecrets: required,
        written: false,
    };

    if (options.write === true) {
        if (patched.text !== text) {
            const backup = configPath + '.bak';
            await fs.writeFile(backup, text, 'utf-8');
            await fs.writeFile(configPath, patched.text, 'utf-8');
            result.written = true;
            result.backupPath = backup;
        }
    }

    if (options.json === true) {
        console.log(JSON.stringify(result, null, 2));
        return;
    }

    console.log('\n[dokkebi] 🔧 보안 설정 자동 보정');
    console.log('  config: ' + configPath);
    if (changes.length === 0) {
        console.log('  변경할 항목이 없습니다.');
    } else {
        for (const c of changes) console.log('  • ' + c);
    }
    if (patched.warnings.length > 0) {
        for (const w of patched.warnings) console.warn('  ⚠ ' + w);
    }
    if (patched.manualSnippets.length > 0) {
        console.log('  수동으로 추가할 코드:');
        for (const snippet of patched.manualSnippets) console.log('    ' + snippet.trim());
    }
    console.log('\n  필수/선택 값:');
    for (const r of required) {
        const mark = r.present ? '✓' : (r.required ? '✗' : '·');
        console.log(`    ${mark} ${r.name} — ${r.reason}`);
    }
    console.log(options.write === true
        ? (result.written ? '\n  ✓ config 파일에 반영했습니다. (백업: ' + result.backupPath + ')' : '\n  변경 사항이 없어 파일을 쓰지 않았습니다.')
        : '\n  (dry-run) 반영하려면 --write 를 추가하세요.');
    console.log('');
}

/**
 * @param {string} src
 * @param {{ status?: boolean, interactive?: boolean, audit?: boolean, json?: boolean }} [options]
 */
export async function runSecurity(src = '.', options = {}) {
    const sourceRoot = path.resolve(process.cwd(), src);
    const forceStatus = options.status === true;
    const forceInteractive = options.interactive === true;
    const tty = process.stdin.isTTY === true;

    if (options.fix === true) {
        await runSecurityFix(sourceRoot, {
            write: options.write === true,
            preset: options.preset,
            json: options.json === true,
        });
        return;
    }

    if (options.audit === true) {
        await runSecurityAudit(sourceRoot, { json: options.json === true });
        return;
    }

    if (forceInteractive) {
        await runSecurityInteractive(sourceRoot);
        return;
    }
    if (forceStatus || !tty) {
        await runSecurityStatus(sourceRoot);
        return;
    }
    await runSecurityInteractive(sourceRoot);
}
