/**
 * dok security — 인터랙티브 TUI (inquirer)
 */

import fs from 'fs/promises';
import path from 'path';
import inquirer from 'inquirer';
import {
    loadDokkebiConfigMerged,
    applySecurityPreset,
    findDokkebiConfigPath,
} from '../core/dokkebiConfigLoad.js';
import { normalizePolicyConfig } from '../core/policyEngine.js';
import { normalizeAuthorizationConfig } from '../core/authorizationPolicy.js';
import { patchDokkebiConfigText, getAtPath, setAtPath } from '../core/securityConfigPatch.js';
import { t, hasKey } from '../i18n/index.js';

function deepClone(o) {
    return JSON.parse(JSON.stringify(o));
}

function panelOn(sec) {
    if (!sec || typeof sec !== 'object') return false;
    const d = sec.panelIpGuard;
    const legacy = sec.adminPanel?.ipAllowlist;
    return d === true || d?.enabled === true || legacy === true || legacy?.enabled === true;
}

function attestationEffective(sec, capOn) {
    const att = sec?.attestation;
    if (att?.enabled === true) return true;
    if (att?.enabled === false) return false;
    return capOn;
}

/** @typedef {{ id: string, label: string, group: string, readonly?: boolean }} SecItem */

/** @returns {SecItem[]} */
function buildCatalog() {
    const ids = [
        'baseline',
        'level',
        'queryRegistry',
        'policy',
        'authorization',
        'capabilities',
        'attestation',
        'panelIpGuard',
        'activeDefense',
        'webauthn',
        'strictCsp',
        'advisor',
    ];
    const group = {
        baseline: 'always',
        level: 'preset',
        queryRegistry: 'registry',
        policy: 'tenant',
        authorization: 'authz',
        capabilities: 'cap',
        attestation: 'cap',
        panelIpGuard: 'ops',
        activeDefense: 'ops',
        webauthn: 'auth',
        strictCsp: 'browser',
        advisor: 'dev',
    };
    return ids.map((id) => ({
        id,
        label: t(`security.cat.${id}`),
        group: group[id],
        readonly: id === 'baseline',
    }));
}

function getDescribe(id) {
    const attack = t(`security.desc.${id}.attack`);
    const body = t(`security.desc.${id}.body`);
    const nk = `security.needs.${id}`;
    const needsRaw = hasKey(nk) ? t(nk) : '';
    const needs = needsRaw ? needsRaw.split('|').map((s) => s.trim()).filter(Boolean) : [];
    return { attack, body, needs };
}

function summarizeDraftLine(id, draft) {
    const eff = applySecurityPreset(deepClone(draft), { quiet: true });
    const sec = eff.security || {};
    const qr = eff.queryRegistry || {};
    const pol = normalizePolicyConfig(eff.policy);
    const authz = normalizeAuthorizationConfig(eff.authorization);
    const capOn = sec.capabilities?.enabled === true;
    const on = t('security.stateOn');
    const off = t('security.stateOff');
    const notSet = t('security.notSet');
    const alwaysOn = t('security.stateAlwaysOn');

    switch (id) {
        case 'baseline':
            return alwaysOn;
        case 'level':
            return String(sec.level || notSet);
        case 'queryRegistry':
            return `${qr.enabled === false ? off : on} / strict=${qr.strict === true}`;
        case 'policy':
            return `${pol.enabled && pol.mode !== 'off' ? on : off} mode=${pol.mode}`;
        case 'authorization':
            return `${authz?.enabled && authz.mode !== 'off' ? on : off} mode=${authz?.mode ?? 'off'}`;
        case 'capabilities':
            return capOn ? on : off;
        case 'attestation':
            return attestationEffective(sec, capOn) ? on : off;
        case 'panelIpGuard':
            return panelOn(sec) ? on : off;
        case 'activeDefense':
            return sec.activeDefense?.enabled === true
                ? `${on} (${sec.activeDefense.mode || 'monitor'})`
                : off;
        case 'webauthn':
            return sec.webauthn?.enabled === true ? on : off;
        case 'strictCsp':
            return sec.strictCsp === true ? on : off;
        case 'advisor':
            return sec.advisor?.disable === true ? off : on;
        default:
            return '';
    }
}

async function showDetailAndMaybeEdit(id, draft) {
    const meta = getDescribe(id);
    console.log('\n' + '─'.repeat(56));
    console.log(`【${id}】`);
    console.log(`${t('security.threatBlocked')}:`, meta.attack);
    console.log('\n' + meta.body);
    if (meta.needs.length) {
        console.log(`\n${t('security.whenEnabling')}:`);
        for (const n of meta.needs) console.log(`  • ${n}`);
    }
    console.log('─'.repeat(56) + '\n');

    if (id === 'baseline') {
        await inquirer.prompt([
            {
                type: 'list',
                name: '_',
                message: t('common.ok'),
                choices: [{ name: t('common.ok'), value: 1 }],
            },
        ]);
        return;
    }

    const actions = [{ name: t('security.backToList'), value: 'back' }];

    if (id === 'level') {
        actions.unshift(
            { name: t('security.levelToStandard'), value: 'std' },
            { name: t('security.levelToStrict'), value: 'strict' },
            { name: t('security.levelToBasic'), value: 'basic' },
            { name: t('security.levelClear'), value: 'clear' },
        );
    } else if (id === 'queryRegistry') {
        actions.unshift(
            { name: t('security.qrToggleEnabled'), value: 'qr_en' },
            { name: t('security.qrToggleStrict'), value: 'qr_st' },
        );
    } else if (id === 'policy') {
        actions.unshift(
            { name: t('security.polToggleEnabled'), value: 'pol_en' },
            { name: t('security.polCycleMode'), value: 'pol_mode' },
        );
    } else if (id === 'authorization') {
        actions.unshift(
            { name: t('security.authzToggleEnabled'), value: 'authz_en' },
            { name: t('security.authzCycleMode'), value: 'authz_mode' },
        );
    } else if (id === 'activeDefense') {
        actions.unshift(
            { name: t('security.adlToggleEnabled'), value: 'adl_en' },
            { name: t('security.adlToggleMode'), value: 'adl_mode' },
        );
    } else {
        const pathMap = {
            capabilities: 'security.capabilities.enabled',
            attestation: 'security.attestation.enabled',
            panelIpGuard: 'security.panelIpGuard',
            webauthn: 'security.webauthn.enabled',
            strictCsp: 'security.strictCsp',
            advisor: 'security.advisor.disable',
        };
        const p = pathMap[id];
        if (p) {
            const cur = getAtPath(draft, p);
            const isOn =
                p === 'security.advisor.disable'
                    ? cur !== true
                    : p === 'security.panelIpGuard'
                        ? cur === true || cur?.enabled === true
                        : cur === true;
            actions.unshift({
                name: isOn ? t('security.toggleOff') : t('security.toggleOn'),
                value: `toggle:${p}`,
            });
        }
    }

    const { act } = await inquirer.prompt([
        {
            type: 'list',
            name: 'act',
            message: t('security.pickAction'),
            choices: actions,
            pageSize: 16,
        },
    ]);

    if (act === 'back') return;

    if (act === 'std') {
        setAtPath(draft, 'security.level', 'standard');
    } else if (act === 'strict') {
        setAtPath(draft, 'security.level', 'strict');
    } else if (act === 'basic') {
        setAtPath(draft, 'security.level', 'basic');
    } else if (act === 'clear') {
        if (draft.security && typeof draft.security === 'object') delete draft.security.level;
    } else if (act === 'qr_en') {
        const q = draft.queryRegistry || {};
        const en = q.enabled;
        const next = en !== true;
        setAtPath(draft, 'queryRegistry', { ...q, enabled: next });
    } else if (act === 'qr_st') {
        const cur = getAtPath(draft, 'queryRegistry.strict') === true;
        setAtPath(draft, 'queryRegistry', { ...(draft.queryRegistry || {}), strict: !cur });
    } else if (act === 'pol_en') {
        const cur = getAtPath(draft, 'policy.enabled') === true;
        setAtPath(draft, 'policy', { ...(draft.policy || {}), enabled: !cur });
    } else if (act === 'pol_mode') {
        const m = String(getAtPath(draft, 'policy.mode') || 'verify');
        const next = m === 'verify' ? 'inject' : 'verify';
        setAtPath(draft, 'policy', { ...(draft.policy || {}), mode: next });
    } else if (act === 'authz_en') {
        const cur = getAtPath(draft, 'authorization.enabled') === true;
        setAtPath(draft, 'authorization', { ...(draft.authorization || {}), enabled: !cur });
    } else if (act === 'authz_mode') {
        const m = String(getAtPath(draft, 'authorization.mode') || 'warn');
        const next = m === 'warn' ? 'strict' : 'warn';
        setAtPath(draft, 'authorization', { ...(draft.authorization || {}), mode: next });
    } else if (act === 'adl_en') {
        const cur = getAtPath(draft, 'security.activeDefense.enabled') === true;
        setAtPath(draft, 'security.activeDefense', {
            ...(draft.security?.activeDefense || {}),
            enabled: !cur,
            mode: draft.security?.activeDefense?.mode || 'monitor',
            trigger: draft.security?.activeDefense?.trigger || 'lazy',
        });
    } else if (act === 'adl_mode') {
        const m = String(getAtPath(draft, 'security.activeDefense.mode') || 'monitor');
        const next = m === 'enforce' ? 'monitor' : 'enforce';
        setAtPath(draft, 'security.activeDefense', {
            ...(draft.security?.activeDefense || {}),
            enabled: true,
            mode: next,
        });
    } else if (String(act).startsWith('toggle:')) {
        const p = String(act).slice('toggle:'.length);
        if (p === 'security.panelIpGuard') {
            const on = getAtPath(draft, p) === true || getAtPath(draft, p)?.enabled === true;
            setAtPath(draft, p, !on);
        } else if (p === 'security.advisor.disable') {
            const cur = getAtPath(draft, p) === true;
            setAtPath(draft, 'security.advisor', { ...(draft.security?.advisor || {}), disable: !cur });
        } else if (p === 'security.capabilities.enabled') {
            const cur = getAtPath(draft, p) === true;
            setAtPath(draft, 'security.capabilities', {
                ...(draft.security?.capabilities || {}),
                enabled: !cur,
            });
        } else if (p === 'security.attestation.enabled') {
            const cur = getAtPath(draft, p) === true;
            setAtPath(draft, 'security.attestation', {
                ...(draft.security?.attestation || {}),
                enabled: !cur,
            });
        } else if (p === 'security.webauthn.enabled') {
            const cur = getAtPath(draft, p) === true;
            setAtPath(draft, 'security.webauthn', {
                ...(draft.security?.webauthn || {}),
                enabled: !cur,
            });
        } else {
            const cur = getAtPath(draft, p) === true;
            setAtPath(draft, p, !cur);
        }
    }
}

async function saveToFile(configPath, originalText, baseline, draft) {
    if (configPath.endsWith('.ts')) {
        console.log('\n' + t('security.tsNoAutoSave') + '\n');
        printManualDiffSnippets(baseline, draft);
        return false;
    }

    const { text, manualSnippets, warnings } = patchDokkebiConfigText(originalText, baseline, draft);
    for (const w of warnings) console.warn(w);
    if (manualSnippets.length) {
        console.log('\n' + t('security.patchPartialFailed') + '\n');
        for (const s of manualSnippets) console.log(s);
    }

    if (text === originalText && manualSnippets.length === 0) {
        console.log('\n' + t('security.noAutoChanges') + '\n');
        return false;
    }
    const { ok } = await inquirer.prompt([
        {
            type: 'confirm',
            name: 'ok',
            message: t('security.saveConfirm', { file: path.basename(configPath) }),
            default: false,
        },
    ]);
    if (!ok) {
        console.log(t('common.prefix') + ' ' + t('security.saveCancelled'));
        return false;
    }

    const bak = `${configPath}.bak`;
    await fs.writeFile(bak, originalText, 'utf-8');
    await fs.writeFile(configPath, text, 'utf-8');
    console.log('\n' + t('security.saveDone', { path: configPath, bak }) + '\n');
    return true;
}

function printManualDiffSnippets(baseline, draft) {
    const keys = [
        'security.level',
        'security.panelIpGuard',
        'security.strictCsp',
        'security.activeDefense.enabled',
        'security.activeDefense.mode',
        'security.capabilities.enabled',
        'security.attestation.enabled',
        'security.advisor.disable',
        'security.webauthn.enabled',
        'queryRegistry.enabled',
        'queryRegistry.strict',
        'policy.enabled',
        'policy.mode',
        'authorization.enabled',
        'authorization.mode',
    ];
    for (const k of keys) {
        const a = JSON.stringify(getAtPath(baseline, k));
        const b = JSON.stringify(getAtPath(draft, k));
        if (a !== b) console.log(`  ${k}: ${a} → ${b}`);
    }
}

/**
 * @param {string} sourceRoot
 */
export async function runSecurityInteractive(sourceRoot) {
    const merged = await loadDokkebiConfigMerged(sourceRoot, { quiet: true });
    if (!merged || typeof merged !== 'object' || Object.keys(merged).length === 0) {
        console.log('\n' + t('common.prefix') + ' ' + t('security.noConfigJs') + '\n');
        process.exitCode = 1;
        return;
    }

    const configPath = findDokkebiConfigPath(sourceRoot);
    if (!configPath) {
        console.log('\n' + t('common.prefix') + ' ' + t('security.noConfigPath') + '\n');
        process.exitCode = 1;
        return;
    }

    let originalText = '';
    try {
        originalText = await fs.readFile(configPath, 'utf-8');
    } catch {
        console.error(t('common.prefix'), t('security.readConfigFailed'), configPath);
        process.exitCode = 1;
        return;
    }

    const baseline = deepClone(merged);
    const draft = deepClone(merged);
    const catalog = buildCatalog();

    console.log('\n' + t('common.prefix') + ' ' + t('security.interactiveIntro') + '\n');
    console.log(`${t('security.project')}: ${sourceRoot}`);
    console.log(`${t('security.file')}:    ${configPath}\n`);

    for (;;) {
        const choices = [
            ...catalog.map((c) => ({
                name: `${c.label.padEnd(38)} │ ${summarizeDraftLine(c.id, draft)}`,
                value: c.id,
            })),
            new inquirer.Separator('─'),
            { name: t('security.menuSave'), value: '__save__' },
            { name: t('security.menuDiff'), value: '__diff__' },
            { name: t('security.menuQuit'), value: '__quit__' },
        ];

        const { pick } = await inquirer.prompt([
            {
                type: 'list',
                name: 'pick',
                message: t('security.pickItem'),
                choices,
                pageSize: 20,
            },
        ]);

        if (pick === '__quit__') {
            console.log('\n' + t('common.prefix') + ' ' + t('security.exitUnsaved') + '\n');
            return;
        }
        if (pick === '__diff__') {
            printManualDiffSnippets(baseline, draft);
            continue;
        }
        if (pick === '__save__') {
            await saveToFile(configPath, originalText, baseline, draft);
            return;
        }

        await showDetailAndMaybeEdit(pick, draft);
    }
}
