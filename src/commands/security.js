/**
 * dok security — 보안 옵트인 (인터랙티브 TUI / --status 일회 출력)
 */

import path from 'path';
import {
    loadDokkebiConfigMerged,
    applySecurityPreset,
} from '../core/dokkebiConfigLoad.js';
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

/**
 * @param {string} src
 * @param {{ status?: boolean, interactive?: boolean, audit?: boolean, json?: boolean }} [options]
 */
export async function runSecurity(src = '.', options = {}) {
    const sourceRoot = path.resolve(process.cwd(), src);
    const forceStatus = options.status === true;
    const forceInteractive = options.interactive === true;
    const tty = process.stdin.isTTY === true;

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
