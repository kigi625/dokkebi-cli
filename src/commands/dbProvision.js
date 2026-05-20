/**
 * `dok db:provision` — d1-sharded 설정의 모든 샤드(+global) D1 DB 생성·바인딩 채우기.
 *
 * 동작:
 *  1) dokkebi.config.js 로드 → normalizeDatabaseConfig.
 *  2) wrangler 가 설치되어 있으면 `wrangler d1 create <name>` 호출 (대화 없이).
 *     설치 안돼있으면 Cloudflare REST API 직접 호출.
 *  3) 각 샤드에 databaseId 주입된 사본 출력 (config 패치는 사용자 승인 후).
 *  4) wrangler.toml 에 d1_databases 블록 자동 추가/갱신.
 *
 * 안전 장치:
 *  - 이미 databaseId 가 있으면 스킵.
 *  - --dry-run 으로 변경 미리보기.
 */

import path from 'path';
import fs from 'fs/promises';
import inquirer from 'inquirer';
import { loadDokkebiConfigMerged, findDokkebiConfigPath } from '../core/dokkebiConfigLoad.js';
import { normalizeDatabaseConfig, summarizeShardConfig } from '../core/shardConfig.js';

const D1_API_BASE = 'https://api.cloudflare.com/client/v4';

function readEnvFile(envPath) {
    return fs.readFile(envPath, 'utf-8').then(
        (raw) => {
            const out = {};
            for (const line of raw.split('\n')) {
                const t = line.trim();
                if (!t || t.startsWith('#')) continue;
                const eq = t.indexOf('=');
                if (eq === -1) continue;
                out[t.slice(0, eq).trim()] = t.slice(eq + 1).trim().replace(/^['"]|['"]$/g, '');
            }
            return out;
        },
        () => ({}),
    );
}

async function cfCreateD1(accountId, apiToken, name) {
    const url = `${D1_API_BASE}/accounts/${encodeURIComponent(accountId)}/d1/database`;
    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiToken}` },
        body: JSON.stringify({ name }),
    });
    const text = await res.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = null; }
    if (!res.ok || !parsed?.success) {
        const msg = parsed?.errors?.[0]?.message || `D1_HTTP_${res.status}`;
        throw new Error(`Cloudflare API: ${msg}`);
    }
    return parsed.result; // { uuid, name, ... }
}

async function cfListD1(accountId, apiToken) {
    const url = `${D1_API_BASE}/accounts/${encodeURIComponent(accountId)}/d1/database?per_page=200`;
    const res = await fetch(url, {
        headers: { Authorization: `Bearer ${apiToken}` },
    });
    const text = await res.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = null; }
    if (!res.ok || !parsed?.success) return [];
    return Array.isArray(parsed.result) ? parsed.result : [];
}

function defaultDbName(projectName, shardId) {
    const safe = String(projectName || 'app').replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase();
    return `${safe}-${shardId}`;
}

/**
 * wrangler.toml 에 [[d1_databases]] 블록을 idempotent 하게 추가/갱신.
 * @param {string} tomlPath
 * @param {Array<{ binding: string, database_name: string, database_id: string }>} entries
 */
async function upsertWranglerD1Blocks(tomlPath, entries) {
    let text = '';
    try { text = await fs.readFile(tomlPath, 'utf-8'); } catch { text = ''; }
    let out = text;
    let changed = false;
    for (const e of entries) {
        const re = new RegExp(
            String.raw`\[\[d1_databases\]\][^[]*?binding\s*=\s*"${e.binding}"[^[]*?(?=\n\[|$)`,
            's',
        );
        const block = [
            '',
            '[[d1_databases]]',
            `binding = "${e.binding}"`,
            `database_name = "${e.database_name}"`,
            `database_id = "${e.database_id}"`,
            '',
        ].join('\n');
        if (re.test(out)) {
            const replaced = out.replace(re, block.trim());
            if (replaced !== out) { out = replaced; changed = true; }
        } else {
            out = (out.endsWith('\n') ? out : out + '\n') + block;
            changed = true;
        }
    }
    if (changed) await fs.writeFile(tomlPath, out, 'utf-8');
    return changed;
}

/**
 * @param {string} sourceRoot
 * @param {{ dryRun?: boolean, yes?: boolean }} opts
 */
export async function runDbProvision(sourceRoot, opts = {}) {
    const root = path.resolve(process.cwd(), sourceRoot || '.');
    const cfg = await loadDokkebiConfigMerged(root, { quiet: true });
    if (!cfg || typeof cfg !== 'object') {
        console.error('[dokkebi] dokkebi.config.js 를 찾을 수 없습니다:', root);
        process.exitCode = 1;
        return;
    }
    const norm = normalizeDatabaseConfig(cfg.database);
    if (!norm.ok) {
        console.error('[dokkebi] database 설정 오류:');
        for (const e of norm.errors) console.error('  -', e);
        process.exitCode = 1;
        return;
    }
    const db = norm.value;
    if (!db.sharded) {
        console.log("[dokkebi] database.type 이 'd1-sharded' 가 아닙니다 — provision 할 항목이 없습니다.");
        console.log('  현재:', summarizeShardConfig(db));
        return;
    }

    const env = { ...(await readEnvFile(path.join(root, '.env'))), ...process.env };
    const accountId = env.D1_ACCOUNT_ID || env.CLOUDFLARE_ACCOUNT_ID || '';
    const apiToken = env.D1_API_TOKEN || env.CLOUDFLARE_API_TOKEN || '';
    if (!accountId || !apiToken) {
        console.error('[dokkebi] D1_ACCOUNT_ID / D1_API_TOKEN (.env) 가 필요합니다.');
        process.exitCode = 1;
        return;
    }

    let pkgName = 'app';
    try {
        const pkg = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf-8'));
        pkgName = pkg.name || pkgName;
    } catch { /* ignore */ }

    const all = [...db.shards];
    if (db.global) all.push(db.global);

    console.log(`[dokkebi] db:provision — ${summarizeShardConfig(db)}`);
    console.log(`  account=${accountId.slice(0, 8)}…  project=${pkgName}\n`);

    const existing = await cfListD1(accountId, apiToken).catch(() => []);
    const byName = new Map(existing.map((d) => [d.name, d]));

    const planned = [];
    for (const e of all) {
        if (e.databaseId) {
            planned.push({ ...e, action: 'skip', databaseId: e.databaseId, databaseName: e.databaseName || defaultDbName(pkgName, e.id) });
            continue;
        }
        const name = e.databaseName || defaultDbName(pkgName, e.id);
        const found = byName.get(name);
        if (found) {
            planned.push({ ...e, action: 'reuse', databaseId: found.uuid || found.id, databaseName: name });
        } else {
            planned.push({ ...e, action: 'create', databaseId: '', databaseName: name });
        }
    }

    console.log('계획:');
    for (const p of planned) {
        console.log(`  [${p.action.padEnd(6)}] ${p.binding.padEnd(14)} ${p.databaseName}${p.databaseId ? `  (${p.databaseId})` : ''}`);
    }
    console.log('');

    if (opts.dryRun) {
        console.log('[dokkebi] --dry-run — 실행하지 않고 종료합니다.');
        return;
    }

    if (!opts.yes) {
        const { ok } = await inquirer.prompt([
            { type: 'confirm', name: 'ok', message: '위 계획대로 진행할까요?', default: false },
        ]);
        if (!ok) {
            console.log('[dokkebi] 취소되었습니다.');
            return;
        }
    }

    for (const p of planned) {
        if (p.action === 'create') {
            try {
                const r = await cfCreateD1(accountId, apiToken, p.databaseName);
                p.databaseId = r.uuid || r.id;
                console.log(`  ✓ created ${p.databaseName} (${p.databaseId})`);
            } catch (e) {
                console.error(`  ✗ create failed ${p.databaseName}: ${e.message}`);
                process.exitCode = 1;
                return;
            }
        } else if (p.action === 'reuse') {
            console.log(`  ↻ reuse ${p.databaseName} (${p.databaseId})`);
        } else {
            console.log(`  · skip ${p.databaseName}`);
        }
    }

    // wrangler.toml 갱신
    const tomlPath = path.join(root, 'wrangler.toml');
    const entries = planned.map((p) => ({
        binding: p.binding,
        database_name: p.databaseName,
        database_id: p.databaseId,
    }));
    const changed = await upsertWranglerD1Blocks(tomlPath, entries);
    console.log(`\n[dokkebi] wrangler.toml ${changed ? '갱신됨' : '변경 없음'}: ${tomlPath}`);

    // dokkebi.config.js 패치 안내 (자동 패치는 미지원 — 사용자가 직접 채우는 것이 안전)
    const cfgPath = findDokkebiConfigPath(root);
    console.log('\n[dokkebi] dokkebi.config.js 의 database.shards / database.global 에 databaseId 를 채워주세요:');
    for (const p of planned) {
        console.log(`  - id: '${p.id || (p === planned[planned.length - 1] && db.global ? db.global.id : '')}', databaseId: '${p.databaseId}'`);
    }
    if (cfgPath) console.log(`  파일: ${cfgPath}`);
    console.log('\n[dokkebi] 다음 단계: dok migrate  (모든 샤드에 마이그레이션 fan-out)');
}
