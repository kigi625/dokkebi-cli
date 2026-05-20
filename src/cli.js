#!/usr/bin/env node

/**
 * dokkebi CLI v2
 *
 * 사용법:
 *   dokkebi create [name]            — 인터랙티브 프로젝트 생성 (Nuxt 스타일)
 *   dokkebi build [src]              — QuickJS WASM 백엔드 빌드
 *   dokkebi serve [src]              — 빌드 결과 정적 서빙
 *   dokkebi dev [src]                — 개발 서버 (HMR)
 *   dokkebi update [src]             — 기존 프로젝트에 최신 버전 업데이트 적용
 *   dokkebi security [src]           — 보안 옵트인 설정 요약 (빌드 없음)
 *   dokkebi lang [code]              — CLI 언어 변경
 */

import { Command } from 'commander';
import { runCreate } from './commands/create.js';
import { runBuild } from './commands/build.js';
import { runServe } from './commands/serve.js';
import { runDeploy } from './commands/deploy.js';
import { runDev } from './commands/dev.js';
import { runUpdate } from './commands/update.js';
import { runPolicyScaffold } from './commands/policyScaffold.js';
import { runLang } from './commands/lang.js';
import { runSecurity } from './commands/security.js';
import { runDbProvision } from './commands/dbProvision.js';
import { t } from './i18n/index.js';

const program = new Command();

program
    .name('dokkebi')
    .description(t('cli.description'))
    .version('1.0.0');

// ── create ──────────────────────────────────────────────────

program
    .command('create [name]')
    .alias('new')
    .description(t('cli.cmd.create'))
    .option('-f, --frontend <framework>', t('cli.opt.frontend'))
    .option('-d, --database <type>', t('cli.opt.database'))
    .option('--no-install', t('cli.opt.noInstall'))
    .action(async (name, options) => {
        try {
            await runCreate({
                name,
                frontend: options.frontend,
                database: options.database,
            });
        } catch (e) {
            console.error(t('cli.errCreate'), e.message);
            process.exitCode = 1;
        }
    });

// ── build ──────────────────────────────────────────────────

program
    .command('build [src]')
    .description(t('cli.cmd.build'))
    .option('-o, --output <dir>', t('cli.opt.output'), 'dist')
    .option('--backend <dir>', t('cli.opt.backendDir'))
    .option('--frontend <dir>', t('cli.opt.frontendDir'))
    .option('--skip-frontend-build', t('cli.opt.skipFrontendBuild'))
    .option('--skip-backend-build', t('cli.opt.skipBackendBuild'))
    .option('--skip-migration', t('cli.opt.skipMigration'))
    .option('--db-type <type>', t('cli.opt.dbTypeOverride'))
    .action(async (src = '.', options) => {
        try {
            await runBuild(src, {
                output: options.output,
                backend: options.backend,
                frontend: options.frontend,
                skipFrontendBuild: options.skipFrontendBuild,
                skipBackendBuild: options.skipBackendBuild,
                skipMigration: options.skipMigration,
                dbType: options.dbType,
            });
        } catch (e) {
            console.error('\n' + t('cli.errBuild'), e.message);
            if (process.env.DEBUG) console.error(e.stack);
            process.exitCode = 1;
        }
    });

// ── serve ──────────────────────────────────────────────────

program
    .command('serve [src]')
    .description(t('cli.cmd.serve'))
    .option('-o, --output <dir>', t('cli.opt.outputBuild'), 'dist')
    .option('-p, --port <port>', t('cli.opt.port'), '5174')
    .option('--skip-build', t('cli.opt.skipBuild'))
    .action(async (src = '.', options) => {
        try {
            await runServe(src, {
                output: options.output,
                port: options.port,
                skipBuild: options.skipBuild,
            });
        } catch (e) {
            console.error(t('cli.errServe'), e.message);
            process.exitCode = 1;
        }
    });

// ── deploy ─────────────────────────────────────────────────

program
    .command('deploy [src]')
    .description(t('cli.cmd.deploy'))
    .option('-o, --output <dir>', t('cli.opt.outputBuild'), 'dist')
    .option('--skip-build', t('cli.opt.skipBuildDeploy'))
    .option('--skip-migration', t('cli.opt.skipMigration'))
    .option('--project-name <name>', t('cli.opt.projectNameOverride'))
    .option('--frontend-only', t('cli.opt.frontendOnly'))
    .option('--backend-only', t('cli.opt.backendOnly'))
    .option('--frontend-target <target>', t('cli.opt.frontendTarget'))
    .option('--strict-registry', t('cli.opt.strictRegistry'))
    .option('--allow-empty-registry', t('cli.opt.allowEmptyRegistry'))
    .option('--no-preflight', t('cli.opt.noPreflight'))
    .option('--preflight-strict', t('cli.opt.preflightStrict'))
    .action(async (src = '.', options) => {
        try {
            await runDeploy(src, {
                output:             options.output,
                skipBuild:          options.skipBuild,
                skipMigration:      options.skipMigration,
                projectName:        options.projectName,
                frontendOnly:       options.frontendOnly,
                backendOnly:        options.backendOnly,
                frontendTarget:     options.frontendTarget,
                strictRegistry:     options.strictRegistry,
                allowEmptyRegistry: options.allowEmptyRegistry,
                preflight:          options.preflight === false ? false : (options.preflightStrict ? 'strict' : true),
                preflightStrict:    options.preflightStrict,
            });
        } catch (e) {
            console.error(t('cli.errDeploy'), e.message);
            if (process.env.DEBUG) console.error(e.stack);
            process.exitCode = 1;
        }
    });

// ── migrate ────────────────────────────────────────────────

program
    .command('migrate [src]')
    .description(t('cli.cmd.migrate'))
    .option('--db-type <type>', t('cli.opt.dbTypeOverride'))
    .option('--shard <id>', '특정 샤드만 마이그레이트 (d1-sharded 전용, 예: s0 또는 global)')
    .action(async (src = '.', options) => {
        try {
            const path = (await import('path')).default;
            const fs   = (await import('fs/promises')).default;

            const sourceRoot = path.resolve(process.cwd(), src);

            const envPath = path.join(sourceRoot, '.env');
            const envVars = {};
            try {
                const raw = await fs.readFile(envPath, 'utf-8');
                for (const line of raw.split('\n')) {
                    const tt = line.trim();
                    if (!tt || tt.startsWith('#')) continue;
                    const eq = tt.indexOf('=');
                    if (eq === -1) continue;
                    envVars[tt.slice(0, eq).trim()] = tt.slice(eq + 1).trim().replace(/^['"]|['"]$/g, '');
                }
            } catch { /* .env 없음 */ }

            const env    = { ...envVars, ...process.env };
            const dbType = options.dbType || env.DOKKEBI_DB_TYPE || 'd1';
            const migrationsDir = path.join(sourceRoot, 'backend', 'db', 'migrations');

            // ── d1-sharded fan-out 경로 ──────────────────────────
            if (dbType === 'd1-sharded' || dbType === 'd1') {
                const { loadDokkebiConfigMerged } = await import('./core/dokkebiConfigLoad.js');
                const { normalizeDatabaseConfig, summarizeShardConfig } = await import('./core/shardConfig.js');
                const cfg = await loadDokkebiConfigMerged(sourceRoot, { quiet: true });
                const norm = normalizeDatabaseConfig(cfg?.database);
                if (norm.ok && norm.value.sharded) {
                    const dbn = norm.value;
                    const accountId = env.D1_ACCOUNT_ID || env.CLOUDFLARE_ACCOUNT_ID || '';
                    const apiToken  = env.D1_API_TOKEN  || env.CLOUDFLARE_API_TOKEN  || '';
                    const apiBase   = env.D1_API_BASE   || 'https://api.cloudflare.com/client/v4';
                    if (!accountId || !apiToken) {
                        console.error('[dokkebi] D1_ACCOUNT_ID / D1_API_TOKEN 가 필요합니다 (.env)');
                        process.exitCode = 1;
                        return;
                    }
                    const targets = [...dbn.shards];
                    if (dbn.global) targets.push(dbn.global);
                    const filtered = options.shard
                        ? targets.filter((t) => t.id === options.shard)
                        : targets;
                    if (filtered.length === 0) {
                        console.error(`[dokkebi] --shard ${options.shard} 매칭 없음 (가용: ${targets.map((t) => t.id).join(', ')})`);
                        process.exitCode = 1;
                        return;
                    }
                    console.log(`\n[dokkebi] migrate (sharded) — ${summarizeShardConfig(dbn)}`);
                    console.log(`  대상 ${filtered.length}개 / 폴더 ${migrationsDir}\n`);

                    const { applyMigrationsToD1 } = await import('./core/d1Integration.js');
                    let totalApplied = 0;
                    const failures = [];
                    for (const tgt of filtered) {
                        if (!tgt.databaseId) {
                            console.warn(`  · skip ${tgt.id} (${tgt.binding}) — databaseId 없음. dok db:provision 후 dokkebi.config.js 에 채워주세요.`);
                            continue;
                        }
                        const cfgOne = { accountId, databaseId: tgt.databaseId, apiToken, apiBase };
                        try {
                            const r = await applyMigrationsToD1(cfgOne, migrationsDir);
                            totalApplied += r.applied;
                            console.log(`  ✓ ${tgt.id.padEnd(8)} (${tgt.binding}) applied=${r.applied} skipped=${r.skippedFiles?.length || 0}`);
                        } catch (err) {
                            failures.push({ id: tgt.id, error: err.message });
                            console.error(`  ✗ ${tgt.id} (${tgt.binding}) 실패: ${err.message}`);
                        }
                    }
                    console.log(`\n[dokkebi] 완료 — 총 ${totalApplied} 문장 적용, 실패 ${failures.length}개`);
                    if (failures.length > 0) process.exitCode = 1;
                    return;
                }
                // 단일 D1 — 기존 동작
            }

            let dbConfig;
            if (dbType === 'd1') {
                dbConfig = {
                    accountId:  env.D1_ACCOUNT_ID  || '',
                    databaseId: env.D1_DATABASE_ID || '',
                    apiToken:   env.D1_API_TOKEN   || '',
                    apiBase:    env.D1_API_BASE     || 'https://api.cloudflare.com/client/v4',
                };
            } else if (dbType === 'supabase') {
                dbConfig = {
                    supabaseUrl: env.SUPABASE_URL         || '',
                    anonKey:     env.SUPABASE_ANON_KEY    || '',
                    serviceKey:  env.SUPABASE_SERVICE_KEY || '',
                };
            } else if (dbType === 'appwrite') {
                dbConfig = {
                    endpoint:   env.APPWRITE_ENDPOINT    || '',
                    projectId:  env.APPWRITE_PROJECT_ID  || '',
                    apiKey:     env.APPWRITE_API_KEY      || '',
                    databaseId: env.APPWRITE_DATABASE_ID || '',
                };
            }

            console.log('\n' + t('migrate.running', { db: dbType }));
            console.log(t('migrate.folder', { dir: migrationsDir }) + '\n');

            const { applyMigrationsToD1 } = await import('./core/d1Integration.js');
            const result = await applyMigrationsToD1(dbConfig, migrationsDir);

            console.log('\n' + t('migrate.complete'));
            if (result.applied === 0 && result.skippedFiles?.length > 0) {
                console.log(
                    t('migrate.allAlreadyApplied', {
                        count: String(result.skippedFiles.length),
                        files: result.skippedFiles.join(', '),
                    }),
                );
            } else {
                console.log(t('migrate.files', { files: result.files?.join(', ') || t('migrate.noFiles') }));
            }
            console.log(t('migrate.applied', { count: result.applied }) + '\n');
        } catch (e) {
            console.error('\n' + t('cli.errMigrate'), e.message);
            process.exitCode = 1;
        }
    });

// ── db:provision ───────────────────────────────────────────

program
    .command('db:provision [src]')
    .description('d1-sharded: 모든 샤드(+global) D1 DB 생성·바인딩 및 wrangler.toml 갱신')
    .option('--dry-run', '계획만 출력하고 종료')
    .option('-y, --yes', '대화 없이 바로 실행')
    .action(async (src = '.', options) => {
        try {
            await runDbProvision(src, { dryRun: options.dryRun, yes: options.yes });
        } catch (e) {
            console.error('\n[dokkebi] db:provision 실패:', e.message);
            if (process.env.DEBUG) console.error(e.stack);
            process.exitCode = 1;
        }
    });

// ── dev ────────────────────────────────────────────────────

program
    .command('dev [src]')
    .description(t('cli.cmd.dev'))
    .option('-p, --port <port>', t('cli.opt.port'), '5173')
    .option('-o, --output <dir>', t('cli.opt.outputBuild'), 'dist')
    .option('--db-type <type>', t('cli.opt.dbTypeOverride'))
    .option('--rebuild', t('cli.opt.rebuild'))
    .action(async (src = '.', options) => {
        try {
            await runDev(src, {
                port:    options.port,
                output:  options.output,
                dbType:  options.dbType,
                rebuild: options.rebuild,
            });
        } catch (e) {
            console.error(t('cli.errDev'), e.message);
            process.exitCode = 1;
        }
    });

// ── update ─────────────────────────────────────────────────

program
    .command('update [src]')
    .description(t('cli.cmd.update'))
    .option('--dry-run', t('cli.opt.dryRun'))
    .option('--force', t('cli.opt.force'))
    .option('--skip-cli-update', t('cli.opt.skipCliUpdate'))
    .action(async (src = '.', options) => {
        try {
            await runUpdate(src, {
                dryRun: options.dryRun,
                force:  options.force,
                skipCliUpdate: options.skipCliUpdate,
            });
        } catch (e) {
            console.error(t('cli.errUpdate'), e.message);
            process.exitCode = 1;
        }
    });

// ── policy:scaffold ────────────────────────────────────────

program
    .command('policy:scaffold [src]')
    .description(t('cli.cmd.policyScaffold'))
    .option('--dry-run', t('cli.opt.dryRunPolicy'))
    .action(async (src = '.', options) => {
        try {
            await runPolicyScaffold(src, { dryRun: options.dryRun });
        } catch (e) {
            console.error(t('cli.errPolicyScaffold'), e.message);
            if (process.env.DEBUG) console.error(e.stack);
            process.exitCode = 1;
        }
    });

// ── security ───────────────────────────────────────────────

program
    .command('security [src]')
    .description(t('cli.cmd.security'))
    .option('--status', t('cli.opt.securityStatus'))
    .option('--interactive', t('cli.opt.securityInteractive'))
    .action(async (src = '.', options) => {
        try {
            await runSecurity(src, {
                status:       options.status === true,
                interactive:  options.interactive === true,
            });
        } catch (e) {
            console.error(t('cli.errSecurity'), e.message);
            if (process.env.DEBUG) console.error(e.stack);
            process.exitCode = 1;
        }
    });

// ── lang ───────────────────────────────────────────────────

program
    .command('lang [code]')
    .description(t('cli.cmd.lang'))
    .option('--list', 'list supported languages')
    .option('--show', 'show current language')
    .action(async (code, options) => {
        try {
            await runLang(code, options);
        } catch (e) {
            console.error(t('cli.errLang'), e.message);
            process.exitCode = 1;
        }
    });

// ── 도움말 ─────────────────────────────────────────────────

async function main() {
    const args = process.argv.slice(2);
    if (args.length === 0) {
        const L = (k) => t('help.lines.' + k);
        console.log(`
  ${t('help.title')}

  ${t('help.usage')}
    ${L('create')}
    ${L('build')}
    ${L('dev')}
    ${L('serve')}
    ${L('deploy')}
    ${L('migrate')}
    dok db:provision [src]      d1-sharded: 모든 샤드(+global) D1 생성·바인딩
    ${L('update')}
    ${L('security')}
    ${L('policy')}
    ${L('lang')}

  ${t('help.examples')}
    ${L('exCreate')}
    ${L('exBuild')}
    ${L('exMigrate')}
    ${L('exDev')}
    ${L('exServe')}
    ${L('exDeploy')}
    ${L('exUpdate')}
    ${L('exSecurity')}
    ${L('exSecurityStatus')}
    ${L('exDryRun')}
    ${L('exForce')}
    ${L('exLang')}

  ${t('help.options')}
    ${L('optDbType')}
    ${L('optSkipBuild')}

  ${t('help.proxyModes')}
    ${L('modeDev')}
    ${L('modeServer')}
    ${L('modeServerless')}

  ${t('help.architecture')}
    ${L('archLine1')}
    ${L('archLine2')}
    ${L('archLine3')}
    ${L('archLine4')}

  ${t('cli.langHint')}
`);
        return;
    }
    await program.parseAsync(process.argv);
}

main();
