/**
 * Worker 템플릿 esbuild 스모크 테스트
 *
 * workerDb() 결과(v8 템플릿)가 실제 Cloudflare Workers 타입을 상정한
 * esbuild ESM 번들링을 통과하는지 확인. 템플릿 문법 오류나 이스케이프
 * 실수는 여기서 잡힙니다.
 *
 * 실행: node tests/workerTemplate.smoke.mjs
 */

import { build } from 'esbuild';
import { workerDb } from '../src/core/projectGenerator.js';
import { emitPayloadWireTs, disabledWireRuntimeJson } from '../src/core/payloadWireRuntime.js';
import { normalizeAuthorizationConfig } from '../src/core/authorizationPolicy.js';
import { normalizePolicyConfig } from '../src/core/policyEngine.js';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';

const SAMPLES = [
    { name: '빈 설정 (인가 off)', allowlist: null, registry: null, policy: null, authz: null },
    {
        name: '허용목록만',
        allowlist: { tables: [{ name: 'posts', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] }], rawAllowed: false },
        registry: null,
        policy: null,
        authz: null,
    },
    {
        name: 'Authorization 기본',
        allowlist: { tables: [{ name: 'posts', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] }], rawAllowed: false },
        registry: null,
        policy: null,
        authz: normalizeAuthorizationConfig({
            rules: {
                'SELECT:posts': { public: true },
                'INSERT:posts': { auth: true },
                'UPDATE:posts': { roles: ['admin', 'author'] },
                'DELETE:posts': { roles: ['admin'] },
                '*': { auth: true },
            },
        }),
    },
    {
        name: 'Tenant Policy + Authorization 동시 활성',
        allowlist: { tables: [{ name: 'posts', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] }], rawAllowed: false },
        registry: null,
        policy: normalizePolicyConfig({
            enabled: true,
            mode: 'verify',
            claim: 'user_id',
            strict: true,
            tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } },
        }),
        authz: normalizeAuthorizationConfig({
            mode: 'strict',
            rules: { 'DELETE:*': { roles: ['admin'] }, '*': { auth: true } },
        }),
    },
    {
        name: 'Authorization strict 모드 - 디폴트 규칙 없음',
        allowlist: { tables: [{ name: 'posts', ops: ['SELECT', 'DELETE'] }], rawAllowed: false },
        registry: null,
        policy: null,
        authz: normalizeAuthorizationConfig({
            mode: 'strict',
            rules: { 'DELETE:posts': { roles: ['admin'] } },
        }),
    },
    {
        name: 'Replay 커스텀 파라미터 (window=10s, nonceTtl=60s)',
        allowlist: null,
        registry: null,
        policy: null,
        authz: null,
        replay: { timestampWindowMs: 10_000, nonceTtlMs: 60_000 },
    },
];

const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'dokkebi-worker-smoke-'));

let failed = 0;
for (const sample of SAMPLES) {
    const source = workerDb('d1', sample.allowlist, sample.registry, sample.policy, sample.authz, sample.replay || null);
    const tsPath = path.join(tmpRoot, sample.name.replace(/[^a-zA-Z0-9]/g, '_') + '.ts');
    await fs.writeFile(tsPath, source, 'utf-8');
    await fs.writeFile(
        path.join(path.dirname(tsPath), '_payloadWire.ts'),
        emitPayloadWireTs(disabledWireRuntimeJson()),
        'utf-8',
    );
    try {
        await build({
            entryPoints: [tsPath],
            bundle: true,
            format: 'esm',
            target: 'es2022',
            platform: 'neutral',
            write: false,
            // D1Database / PagesFunction / Env 는 Cloudflare 런타임 글로벌.
            // esbuild 가 글로벌 심볼에 대해 엄격한 에러를 주지 않도록 external 없이 진행.
        });
        console.log(`[OK] ${sample.name}`);
    } catch (e) {
        failed++;
        console.error(`[FAIL] ${sample.name}`);
        console.error('  ' + (e.message || e));
        if (e.errors) {
            for (const err of e.errors.slice(0, 5)) {
                console.error('  -', err.text, err.location ? `(${err.location.file}:${err.location.line}:${err.location.column})` : '');
            }
        }
    }
}

await fs.rm(tmpRoot, { recursive: true, force: true });

if (failed > 0) {
    console.error(`\n${failed}/${SAMPLES.length} 샘플이 esbuild 빌드에 실패했습니다.`);
    process.exit(1);
}
console.log(`\n${SAMPLES.length}/${SAMPLES.length} 샘플 esbuild 빌드 통과`);
