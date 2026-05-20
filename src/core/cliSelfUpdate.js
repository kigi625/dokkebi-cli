/**
 * dok update — npm registry 기준 CLI 자체 업데이트 후 프로젝트 업데이트 재실행
 *
 * npm publish 전: registry 404 → 안내 후 기존 CLI로 프로젝트 업데이트 계속
 * 로컬 개발(node src/cli.js): 전역 npm 설치 건너뜀
 */

import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';
import fetch from 'node-fetch';
import { t } from '../i18n/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_ROOT = path.resolve(__dirname, '../..');
const REEXEC_ENV = 'DOKKEBI_CLI_UPDATE_REEXEC';
const REGISTRY_TIMEOUT_MS = 12_000;

/** @returns {{ name: string, version: string, installKind: 'global'|'npx'|'dev'|'unknown', canSelfUpdate: boolean }} */
export function getCliMeta() {
    const pkgPath = path.join(CLI_ROOT, 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    const entry = path.resolve(process.argv[1] || path.join(CLI_ROOT, 'src/cli.js'));
    const norm = entry.replace(/\\/g, '/');
    let installKind = 'unknown';
    if (norm.includes('/node_modules/dokkebi-cli/')) installKind = 'global';
    else if (norm.includes('/_npx/')) installKind = 'npx';
    else if (norm.includes('/dokkebi-cli/src/')) installKind = 'dev';
    return {
        name: pkg.name || 'dokkebi-cli',
        version: pkg.version || '0.0.0',
        installKind,
        canSelfUpdate: installKind === 'global' || installKind === 'npx',
    };
}

/** @returns {-1|0|1} */
export function compareSemver(a, b) {
    const pa = String(a).split('-')[0].split('.').map((n) => parseInt(n, 10) || 0);
    const pb = String(b).split('-')[0].split('.').map((n) => parseInt(n, 10) || 0);
    const len = Math.max(pa.length, pb.length);
    for (let i = 0; i < len; i++) {
        const da = pa[i] ?? 0;
        const db = pb[i] ?? 0;
        if (da > db) return 1;
        if (da < db) return -1;
    }
    return 0;
}

/** @returns {Promise<{ version: string }|null>} */
export async function fetchRegistryLatest(packageName) {
    const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`;
    try {
        const res = await fetch(url, {
            headers: { accept: 'application/json' },
            signal: AbortSignal.timeout(REGISTRY_TIMEOUT_MS),
        });
        if (res.status === 404) return null;
        if (!res.ok) return null;
        const data = await res.json();
        if (!data?.version) return null;
        return { version: data.version };
    } catch {
        return null;
    }
}

function runNpmGlobalInstall(packageName, version) {
    const spec = `${packageName}@${version}`;
    const r = spawnSync('npm', ['install', '-g', spec], { stdio: 'inherit' });
    return r.status === 0;
}

function buildUpdateArgv(src, options) {
    const args = ['update'];
    const resolved = src ? path.resolve(src) : process.cwd();
    if (resolved !== process.cwd()) args.push(resolved);
    if (options.dryRun) args.push('--dry-run');
    if (options.force) args.push('--force');
    if (options.skipCliUpdate) args.push('--skip-cli-update');
    return args;
}

function spawnUpdateReexec(src, options, meta) {
    const env = { ...process.env, [REEXEC_ENV]: '1' };
    const args = buildUpdateArgv(src, options);
    const shell = process.platform === 'win32';

    if (meta.installKind === 'npx') {
        const r = spawnSync('npx', ['-y', `${meta.name}@latest`, ...args], {
            stdio: 'inherit',
            env,
            shell,
        });
        return r.status === 0;
    }

    for (const bin of ['dokkebi', 'dok']) {
        const r = spawnSync(bin, args, { stdio: 'inherit', env, shell });
        if (r.status === 0) return true;
        if (r.error?.code === 'ENOENT') continue;
        return false;
    }

    const r = spawnSync('npm', ['exec', '-g', '--package', meta.name, '--', ...args], {
        stdio: 'inherit',
        env,
        shell,
    });
    return r.status === 0;
}

/**
 * CLI가 npm 최신이면 프로젝트 업데이트로 진행.
 * 업데이트·재실행 성공 시 process.exit(0) — 호출부는 더 이상 진행하지 않음.
 *
 * @returns {Promise<boolean>} true = 프로젝트 업데이트 계속
 */
export async function ensureCliUpdatedBeforeProject(src, options, { askConfirm }) {
    if (process.env[REEXEC_ENV] === '1') return true;
    if (options.skipCliUpdate) return true;

    const meta = getCliMeta();
    const latest = await fetchRegistryLatest(meta.name);

    if (!latest) {
        console.log(`${t('update.cliRegistryUnavailable')}\n`);
        return true;
    }

    if (compareSemver(meta.version, latest.version) >= 0) {
        console.log(`${t('update.cliAlreadyLatest', { version: meta.version })}\n`);
        return true;
    }

    console.log(
        `${t('update.cliNewAvailable', { current: meta.version, latest: latest.version })}\n`,
    );

    if (!meta.canSelfUpdate) {
        console.log(`${t('update.cliDevSkip')}\n`);
        return true;
    }

    if (options.dryRun) {
        console.log(`${t('update.cliDryRunWouldInstall', { version: latest.version })}\n`);
        return true;
    }

    if (!options.force) {
        const ok = await askConfirm(t('update.cliConfirm'));
        if (!ok) {
            console.log(`${t('update.cliSkippedContinuing')}\n`);
            return true;
        }
    }

    console.log(`${t('update.cliInstalling', { version: latest.version })}\n`);
    if (!runNpmGlobalInstall(meta.name, latest.version)) {
        console.error(`${t('update.cliInstallFailed')}\n`);
        return true;
    }

    console.log(`${t('update.cliReexec')}\n`);
    if (spawnUpdateReexec(src, options, meta)) {
        process.exit(0);
    }

    console.warn(`${t('update.cliReexecFailed')}\n`);
    return true;
}

export { REEXEC_ENV };
