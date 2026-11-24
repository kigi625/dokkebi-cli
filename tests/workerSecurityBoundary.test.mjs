/**
 * Worker 템플릿 보안 경계 실행 테스트
 *
 *   workerDb() 가 생성한 실제 워커 코드를 esbuild 로 JS 로 변환한 뒤 내부 함수를
 *   export 해서 직접 호출한다. → src/core 의 단위 테스트와 별개로, 템플릿에
 *   인라인된 복사본이 실제로 시스템 테이블·JOIN 을 막는지 확인한다.
 *
 * 실행: node --test tests/workerSecurityBoundary.test.mjs   (esbuild 필요)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { createHmac } from 'node:crypto';

import { workerDb } from '../src/core/projectGenerator.js';
import { emitPayloadWireTs, disabledWireRuntimeJson } from '../src/core/payloadWireRuntime.js';
import { normalizeAuthorizationConfig } from '../src/core/authorizationPolicy.js';
import { normalizePolicyConfig } from '../src/core/policyEngine.js';

const ALLOWLIST = {
    version: 1,
    tables: [
        { name: 'posts', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] },
        { name: 'users', ops: ['SELECT'] },
        // 구버전 빌드 산출물 호환: allowlist 에 시스템 테이블이 남아 있는 상황을 가정
        { name: '_dokkebi_sessions', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE'] },
    ],
    rawAllowed: false,
};

const AUTHZ = normalizeAuthorizationConfig({
    enabled: true,
    mode: 'strict',
    rules: {
        'SELECT:posts': { public: true },
        'SELECT:users': { roles: ['admin'] },
        'INSERT:posts': { auth: true },
        'INSERT:users': { roles: ['admin'] },
        '*': { deny: true },
    },
});

const POLICY = normalizePolicyConfig(
    { enabled: true, mode: 'inject', tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } } },
    { authorizationEnabled: true },
);

async function loadWorkerInternals() {
    const source = workerDb('d1', ALLOWLIST, null, POLICY, AUTHZ, null, null, null, null, null, null, { origins: ['https://app.example.com'] })
        + '\nexport { validateSqlAllowlist, findInternalTableRef, _az_checkSql, verifyTenantPolicy, injectTenantPolicy, _pe_detectOp, _isReadOnlySelectSql, _az_resolveJwtSecret, _az_verifyJwtHs256, _jwtClaimIdentity, _corsHeadersFor };\n';
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'dokkebi-worker-sec-'));
    const tsPath = path.join(dir, 'worker.ts');
    await fs.writeFile(tsPath, source, 'utf-8');
    await fs.writeFile(path.join(dir, '_payloadWire.ts'), emitPayloadWireTs(disabledWireRuntimeJson()), 'utf-8');
    const out = await build({
        entryPoints: [tsPath],
        bundle: true,
        format: 'esm',
        target: 'es2022',
        platform: 'neutral',
        write: false,
    });
    const jsPath = path.join(dir, 'worker.mjs');
    await fs.writeFile(jsPath, out.outputFiles[0].text, 'utf-8');
    const mod = await import(pathToFileURL(jsPath).href);
    return { mod, dir };
}

const JWT_SECRET = 'test-secret-0123456789abcdef0123456789abcdef';

function signJwt(payload, secret = JWT_SECRET) {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const head = b64({ alg: 'HS256', typ: 'JWT' });
    const body = b64({ ...payload, iat: now, exp: now + 60 });
    const sig = createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url');
    return `${head}.${body}.${sig}`;
}

const { mod: worker, dir: workerDir } = await loadWorkerInternals();
test.after(async () => {
    await fs.rm(workerDir, { recursive: true, force: true });
});

test('워커 템플릿: 시스템 테이블 SQL 차단 (allowlist 에 남아 있어도)', async () => {
    for (const sql of [
        'SELECT session_id, enc_key, sig_key FROM _dokkebi_sessions',
        'SELECT * FROM sqlite_master',
        'DELETE FROM _dokkebi_security',
        'SELECT k.priv_jwk FROM main._dokkebi_ephemeral_keys k',
        'CREATE TABLE _dokkebi_shadow (x INT)',
    ]) {
        assert.equal(worker.findInternalTableRef(sql) !== null, true, sql);
        const r = worker.validateSqlAllowlist(sql, { strict: true });
        assert.equal(r.allowed, false, sql);
    }
    assert.equal(worker.validateSqlAllowlist('SELECT * FROM posts', { strict: true }).allowed, true);
});

test('워커 템플릿: Authorization 이 JOIN/INSERT..SELECT 의 보호 테이블을 검사', async () => {
    const req = { headers: new Headers() };
    const env = { DOKKEBI_JWT_SECRET: JWT_SECRET };
    const userJwt = signJwt({ role: 'user', user_id: 'u1' });
    const adminJwt = signJwt({ role: 'admin', user_id: 'a1' });

    const join = 'SELECT * FROM posts JOIN users ON users.id = posts.user_id';
    assert.equal((await worker._az_checkSql(join, req, {}, env)).ok, false);
    assert.equal((await worker._az_checkSql(join, req, { _jwt: userJwt }, env)).ok, false);
    assert.equal((await worker._az_checkSql(join, req, { _jwt: adminJwt }, env)).ok, true);

    const exfil = 'INSERT INTO posts (user_id, title) SELECT user_id, password_hash FROM users';
    const denied = await worker._az_checkSql(exfil, req, { _jwt: userJwt }, env);
    assert.equal(denied.ok, false);
    assert.equal(denied.code, 'ROLE_FORBIDDEN');

    // public 단일 테이블은 JWT 없이 허용
    assert.equal((await worker._az_checkSql('SELECT * FROM posts', req, {}, env)).ok, true);
});

test('워커 템플릿: WITH-DML 을 SELECT 로 오판하지 않음 (C1)', async () => {
    assert.equal(worker._pe_detectOp('WITH X AS (SELECT 1) DELETE FROM POSTS'), 'DELETE');
    assert.equal(worker._pe_detectOp('WITH X AS (SELECT 1) UPDATE POSTS SET A=1'), 'UPDATE');
    const selectOnly = { tables: [{ name: 'posts', ops: ['SELECT'] }] };
    // build 시 allowlist 를 주입했으므로 posts 는 SELECT/INSERT/UPDATE/DELETE 전체 허용.
    // 금지 테이블(users: SELECT only)로 WITH-DML 이 거부되는지 확인.
    for (const sql of [
        'WITH x AS (SELECT 1) DELETE FROM users',
        'WITH x AS (SELECT 1) UPDATE users SET a = 1',
    ]) {
        assert.equal(worker.validateSqlAllowlist(sql, { strict: true }).allowed, false, sql);
    }
    const req = { headers: new Headers() };
    const env = { DOKKEBI_JWT_SECRET: JWT_SECRET };
    const user = signJwt({ role: 'user', user_id: 'u1' });
    const admin = signJwt({ role: 'admin', user_id: 'a1' });
    const sql = 'WITH x AS (SELECT 1) DELETE FROM users';
    assert.equal((await worker._az_checkSql(sql, req, { _jwt: user }, env)).ok, false);
    assert.equal((await worker._az_checkSql(sql, req, { _jwt: admin }, env)).ok, true);
});

test('워커 템플릿: 테넌트 서브쿼리/OR 우회 차단 (C2)', () => {
    const p = {
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } },
    };
    const ctx = { user_id: 'u1' };
    assert.equal(worker.verifyTenantPolicy('SELECT * FROM posts WHERE user_id = ?', ['u1'], ctx, p, { strict: true }).ok, true);
    assert.equal(worker.verifyTenantPolicy('SELECT * FROM posts WHERE (user_id = ? OR 1=1)', ['u1'], ctx, p, { strict: true }).ok, false);
    assert.equal(worker.verifyTenantPolicy('UPDATE posts SET x = (SELECT 1 FROM posts WHERE user_id = ?) WHERE id = ?', ['u1', '5'], ctx, p, { strict: true }).ok, false);
    assert.equal(worker.verifyTenantPolicy('DELETE FROM posts WHERE id = ? AND (SELECT 1 FROM posts WHERE user_id = ?)', ['5', 'u1'], ctx, p, { strict: true }).ok, false);

    const inj = { ...p, mode: 'inject' };
    const r = worker.injectTenantPolicy('UPDATE posts SET x = (SELECT 1 FROM posts WHERE user_id = ?) WHERE id = ?', ['u1', '5'], ctx, inj, { strict: true });
    assert.equal(r.ok, true);
    assert.match(r.sql, /WHERE id = \? AND \(posts\.user_id = \?\)/);
});

test('워커 템플릿: optional 은 클레임이 있을 때만 격리 (C3)', () => {
    const p = {
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: { posts: { tenantColumn: 'user_id', mode: 'optional' } },
    };
    assert.equal(worker.verifyTenantPolicy('SELECT * FROM posts', [], null, p, { strict: true }).ok, true);
    assert.equal(worker.verifyTenantPolicy('SELECT * FROM posts', [], { user_id: 'u1' }, p, { strict: true }).ok, false);
    assert.equal(worker.verifyTenantPolicy('SELECT * FROM posts WHERE user_id = ?', ['u1'], { user_id: 'u1' }, p, { strict: true }).ok, true);

    // 모호한 매핑(site_id ← user_id)은 optional 에서 강제하지 않는다.
    const amb = {
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: { inquiries: { tenantColumn: 'site_id', mode: 'optional' } },
    };
    assert.equal(worker.verifyTenantPolicy('SELECT * FROM inquiries', [], { user_id: 'u1' }, amb, { strict: true }).ok, true);
    assert.equal(worker.verifyTenantPolicy('SELECT * FROM inquiries', [], { site_id: 's1' }, amb, { strict: true }).ok, true);
});

test('워커 템플릿: /*!read*/ 힌트로 쓰기를 읽기로 위장할 수 없음 (H1)', () => {
    assert.equal(worker._isReadOnlySelectSql('SELECT * FROM posts'), true);
    assert.equal(worker._isReadOnlySelectSql('/*!read*/ SELECT * FROM posts'), true);
    assert.equal(worker._isReadOnlySelectSql('/*!write*/ SELECT * FROM posts'), false);
    assert.equal(worker._isReadOnlySelectSql('/*!read*/ DELETE FROM posts'), false);
    assert.equal(worker._isReadOnlySelectSql('/*!read*/ WITH x AS (SELECT 1) DELETE FROM posts'), false);
    assert.equal(worker._isReadOnlySelectSql('-- c\nUPDATE posts SET a = 1'), false);
});

test('워커 템플릿: JWT 시크릿은 하나만 사용 (H3)', async () => {
    const env = { JWT_SECRET: 'legacy-secret', DOKKEBI_JWT_SECRET: 'canonical-secret' };
    assert.equal(worker._az_resolveJwtSecret(env), 'legacy-secret');
    assert.equal(worker._az_resolveJwtSecret({ DOKKEBI_JWT_SECRET: 'canonical-secret' }), 'canonical-secret');

    const okLegacy = await worker._az_verifyJwtHs256(signJwt({ role: 'admin' }, 'legacy-secret'), env);
    const stale = await worker._az_verifyJwtHs256(signJwt({ role: 'admin' }, 'canonical-secret'), env);
    assert.equal(okLegacy.valid, true);
    assert.equal(stale.valid, false);
});

test('워커 템플릿: JWT claim 을 명시하면 그 claim 을 우선 (H4)', () => {
    assert.equal(worker._jwtClaimIdentity({ user_id: 'u1', org_id: 'o1' }, 'org_id'), 'o1');
    assert.equal(worker._jwtClaimIdentity({ user_id: 'u1' }, 'org_id'), 'u1');
    assert.equal(worker._jwtClaimIdentity({}, 'org_id'), null);
});

test('워커 템플릿: CORS allowedOrigins 를 강제 (H4/4번)', () => {
    const req = (origin) => ({ headers: new Headers(origin ? { origin } : {}) });
    const ok = worker._corsHeadersFor(req('https://app.example.com'));
    assert.equal(ok['Access-Control-Allow-Origin'], 'https://app.example.com');
    assert.equal(ok['Vary'], 'Origin');

    const bad = worker._corsHeadersFor(req('https://evil.example.com'));
    assert.equal(bad['Access-Control-Allow-Origin'], undefined);

    const noOrigin = worker._corsHeadersFor(req(''));
    assert.equal(noOrigin['Access-Control-Allow-Origin'], undefined);
});

test('워커 템플릿: 콤마 조인 보호 테이블 우회 차단 (C4)', async () => {
    // users 는 allowlist 에 포함되어 있으므로, 미등록 테이블(secrets)로 확인한다.
    for (const sql of [
        'SELECT * FROM posts, secrets',
        'SELECT * FROM posts p, "secrets" u',
        'SELECT * FROM posts, main.secrets',
        // 대괄호/따옴표 스키마 표기 우회
        'SELECT * FROM posts, [secrets]',
        'SELECT * FROM posts JOIN [secrets] ON 1=1',
        'SELECT * FROM posts, (SELECT * FROM [secrets])',
        'SELECT * FROM "main"."secrets"',
        'SELECT * FROM posts, [main].[secrets]',
        'SELECT * FROM posts, (secrets)',
        'SELECT * FROM (posts) p, secrets s',
        'SELECT * FROM ((secrets))',
        'UPDATE posts SET x = 1 FROM [secrets] WHERE secrets.id = posts.id',
        // JOIN 제약(INDEXED BY / NOT INDEXED / ON / USING) 뒤 콤마로 이어지는 테이블
        'SELECT * FROM posts INDEXED BY idx, secrets',
        'SELECT * FROM posts NOT INDEXED, secrets',
        'SELECT * FROM posts JOIN users ON posts.id = users.id, secrets',
        'SELECT * FROM posts JOIN users USING(id), secrets',
        // UPDATE OR <conflict> 대상 테이블
        'UPDATE OR REPLACE secrets SET x = 1',
        'UPDATE OR IGNORE [secrets] SET x = 1 FROM posts',
    ]) {
        assert.equal(worker.validateSqlAllowlist(sql, { strict: true }).allowed, false, sql);
    }
    assert.equal(worker.validateSqlAllowlist('SELECT * FROM posts, users', { strict: true }).allowed, true);

    const req = { headers: new Headers() };
    const env = { DOKKEBI_JWT_SECRET: JWT_SECRET };
    const user = signJwt({ role: 'user', user_id: 'u1' });
    const admin = signJwt({ role: 'admin', user_id: 'a1' });
    assert.equal((await worker._az_checkSql('SELECT * FROM posts, users', req, { _jwt: user }, env)).ok, false);
    assert.equal((await worker._az_checkSql('SELECT * FROM posts, users', req, { _jwt: admin }, env)).ok, true);

    const p = {
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: {
            posts: { tenantColumn: 'user_id', mode: 'enforce' },
            users: { tenantColumn: 'user_id', mode: 'enforce' },
        },
    };
    const ctx = { user_id: 'u1' };
    assert.equal(worker.verifyTenantPolicy('SELECT * FROM posts, users WHERE user_id = ?', ['u1'], ctx, p, { strict: true }).ok, false);
    assert.equal(worker.verifyTenantPolicy('SELECT * FROM posts, users WHERE posts.user_id = ? AND users.user_id = ?', ['u1', 'u1'], ctx, p, { strict: true }).ok, true);

    const inj = worker.injectTenantPolicy('SELECT * FROM posts, users', [], ctx, { ...p, mode: 'inject' }, { strict: true });
    assert.equal(inj.ok, true);
    assert.match(inj.sql, /posts\.user_id = \?/);
    assert.match(inj.sql, /users\.user_id = \?/);
});


test('워커 템플릿: 테넌트 테이블의 위험한 upsert 차단', () => {
    const p = {
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } },
    };
    const ctx = { user_id: 'u1' };
    const base = 'INSERT INTO posts (id,user_id,title) VALUES (?,?,?)';
    const params = ['victim-post', 'u1', 'x'];

    assert.equal(worker.verifyTenantPolicy(base, params, ctx, p).ok, true);
    assert.equal(worker.verifyTenantPolicy(base + ' ON CONFLICT DO NOTHING', params, ctx, p).ok, true);
    assert.equal(worker.verifyTenantPolicy(base + ' ON CONFLICT(id,user_id) DO UPDATE SET title=excluded.title', params, ctx, p).ok, true);
    assert.equal(worker.verifyTenantPolicy('INSERT OR IGNORE INTO posts (id,user_id,title) VALUES (?,?,?)', params, ctx, p).ok, true);

    for (const sql of [
        base + ' ON CONFLICT(id) DO UPDATE SET title=excluded.title',
        base + ' ON CONFLICT DO UPDATE SET title=excluded.title',
        'INSERT OR REPLACE INTO posts (id,user_id,title) VALUES (?,?,?)',
        'REPLACE INTO posts (id,user_id,title) VALUES (?,?,?)',
        'UPDATE OR REPLACE posts SET title = ? WHERE posts.user_id = ?',
    ]) {
        const r = worker.verifyTenantPolicy(sql, params, ctx, p);
        assert.equal(r.ok, false, sql);
        assert.equal(r.code, 'UPSERT_TENANT_RISK', sql);
    }
});


test('워커 템플릿: 따옴표 내부 ? 로 placeholder 인덱스를 흔들 수 없음', () => {
    const policy = normalizePolicyConfig({
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } },
    });
    const ctx = { user_id: 'u1' };
    const sql = 'SELECT * FROM posts WHERE "x?y" = ? AND posts.user_id = ? AND title = ?';
    const r = worker.verifyTenantPolicy(sql, ['x?y', 'victim', 'u1'], ctx, policy, { strict: true });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'TENANT_MISMATCH');
    assert.equal(worker.verifyTenantPolicy(sql, ['x?y', 'u1', 'u1'], ctx, policy, { strict: true }).ok, true);
    assert.equal(worker.verifyTenantPolicy('SELECT * FROM posts WHERE "user_id" = ?', ['u1'], ctx, policy, { strict: true }).ok, true);
});

test('워커 템플릿: 테넌트 컬럼 재할당(SET user_id) 차단', () => {
    const p = {
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } },
    };
    const ctx = { user_id: 'u1' };

    assert.equal(worker.verifyTenantPolicy('UPDATE posts SET title = ? WHERE posts.user_id = ?', ['x', 'u1'], ctx, p).ok, true);
    assert.equal(worker.verifyTenantPolicy('UPDATE posts SET user_id = ? WHERE posts.user_id = ?', ['u1', 'u1'], ctx, p).ok, true);
    assert.equal(worker.verifyTenantPolicy('UPDATE posts SET user_id = posts.user_id WHERE posts.user_id = ?', ['u1'], ctx, p).ok, true);

    for (const [sql, params] of [
        ['UPDATE posts SET user_id = ? WHERE posts.user_id = ?', ['victim', 'u1']],
        ['UPDATE posts SET "user_id" = ? WHERE posts.user_id = ?', ['victim', 'u1']],
        ['UPDATE posts SET posts.user_id = ? WHERE posts.user_id = ?', ['victim', 'u1']],
        ["UPDATE posts SET user_id = 'victim' WHERE posts.user_id = ?", ['u1']],
        ['UPDATE posts SET title = ?, user_id = ? WHERE posts.user_id = ?', ['x', 'victim', 'u1']],
        ['UPDATE posts SET user_id = (SELECT user_id FROM posts WHERE id = ?) WHERE posts.user_id = ?', ['victim', 'u1']],
    ]) {
        const r = worker.verifyTenantPolicy(sql, params, ctx, p);
        assert.equal(r.ok, false, sql);
        assert.equal(r.code, 'TENANT_COLUMN_REASSIGN', sql);
    }
});


test('워커 템플릿: UNION/INTERSECT/EXCEPT 브랜치별 테넌트 필터 검증', () => {
    const p = {
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } },
    };
    const ctx = { user_id: 'u1' };

    assert.equal(worker.verifyTenantPolicy(
        'SELECT * FROM posts WHERE posts.user_id = ? UNION SELECT * FROM posts WHERE posts.user_id = ?',
        ['u1', 'u1'], ctx, p
    ).ok, true);
    assert.equal(worker.verifyTenantPolicy(
        'SELECT * FROM posts p WHERE p.user_id = ? UNION ALL SELECT * FROM posts p WHERE p.user_id = ?',
        ['u1', 'u1'], ctx, p
    ).ok, true);
    assert.equal(worker.verifyTenantPolicy(
        'SELECT * FROM posts WHERE posts.user_id = ? UNION SELECT * FROM posts WHERE user_id = ?',
        ['u1', 'u1'], ctx, p
    ).ok, true);

    for (const sql of [
        'SELECT * FROM posts WHERE posts.user_id = ? UNION SELECT * FROM posts',
        'SELECT * FROM posts p WHERE p.user_id = ? UNION ALL SELECT * FROM posts p',
        'SELECT * FROM posts WHERE posts.user_id = ? INTERSECT SELECT * FROM posts',
        'SELECT * FROM posts WHERE posts.user_id = ? EXCEPT SELECT * FROM posts',
    ]) {
        assert.equal(worker.verifyTenantPolicy(sql, ['u1', 'u1'], ctx, p).ok, false, sql);
    }

    const nested = worker.verifyTenantPolicy(
        'SELECT * FROM posts WHERE posts.user_id = ? AND id IN (SELECT id FROM posts UNION SELECT id FROM posts)',
        ['u1'], ctx, p
    );
    assert.equal(nested.ok, false);
    assert.equal(nested.code, 'COMPOUND_SELECT_UNSUPPORTED');
});

test('워커 템플릿: 위치 기반 외 파라미터(?2/:name) 거부', () => {
    const p = {
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } },
    };
    const ctx = { user_id: 'u1' };

    const bad = worker.verifyTenantPolicy('SELECT * FROM posts WHERE user_id = ?2', ['u1', 'victim'], ctx, p);
    assert.equal(bad.ok, false);
    assert.equal(bad.code, 'NON_POSITIONAL_PARAM');

    const allow = worker.validateSqlAllowlist('SELECT * FROM posts WHERE user_id = :uid', ALLOWLIST);
    assert.equal(allow.allowed, false);
});

test('워커 템플릿: 부정/추가 비교 테넌트 조건 거부', () => {
    const p = {
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } },
    };
    const ctx = { user_id: 'u1' };

    for (const sql of [
        'SELECT * FROM posts WHERE NOT user_id = ?',
        'SELECT * FROM posts WHERE user_id = ? IS NOT TRUE',
        'SELECT * FROM posts WHERE user_id = ? = 0',
        'SELECT * FROM posts WHERE CASE WHEN user_id = ? THEN 1 END',
        'SELECT * FROM posts WHERE user_id = ? OR 1=1',
    ]) {
        const r = worker.verifyTenantPolicy(sql, ['u1'], ctx, p);
        assert.equal(r.ok, false, sql);
        assert.ok(r.code === 'NO_TENANT_FILTER' || r.code === 'LOOSE_OR', sql + ' → ' + r.code);
    }

    assert.equal(worker.verifyTenantPolicy('SELECT * FROM posts WHERE user_id = ?', ['u1'], ctx, p).ok, true);
    assert.equal(worker.verifyTenantPolicy('SELECT * FROM posts WHERE user_id = ? COLLATE NOCASE', ['u1'], ctx, p).ok, true);
});
