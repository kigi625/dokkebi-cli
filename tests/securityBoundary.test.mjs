/**
 * 보안 경계 회귀 테스트
 *
 *   1. 내부 시스템 테이블(_dokkebi_*, sqlite_*)은 클라이언트 SQL 에서 항상 차단
 *   2. Allowlist: DML 의 읽기 원본(JOIN/서브쿼리/INSERT..SELECT)도 SELECT 권한 필요
 *   3. Authorization: SQL 이 참조하는 "모든" 테이블을 검사 (JOIN/INSERT..SELECT 우회 차단)
 *   4. Tenant Policy: JWT 기반 인증이 구성되면 requireJwtTenant 기본 ON
 *
 * 실행: node --test tests/securityBoundary.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
    validateSqlAllowlist,
    findInternalTableRef,
    isInternalTableName,
    extractAllowlist,
} from '../src/core/sqlAllowlist.js';
import {
    normalizeAuthorizationConfig,
    extractOpAndTables,
    evaluateSqlAuthorization,
} from '../src/core/authorizationPolicy.js';
import { normalizePolicyConfig } from '../src/core/policyEngine.js';
import { verifyJwtHs256 } from '../src/core/authorizationPolicy.js';
import { createHmac } from 'node:crypto';

const ALLOW = {
    version: 1,
    tables: [
        { name: 'posts', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] },
        { name: 'users', ops: ['SELECT'] },
        { name: 'audit_only', ops: ['INSERT'] },
        // 과거 빌드 산출물 호환: allowlist 에 시스템 테이블이 남아 있어도 프록시가 거부해야 한다.
        { name: '_dokkebi_sessions', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE'] },
    ],
    rawAllowed: false,
};

// ─────────────────────────────────────────────────────────────
// 1. 내부 시스템 테이블 차단
// ─────────────────────────────────────────────────────────────

test('findInternalTableRef: 세션/키 테이블 및 sqlite_master 탐지', () => {
    assert.equal(findInternalTableRef('SELECT enc_key FROM _dokkebi_sessions'), '_dokkebi_sessions');
    assert.equal(findInternalTableRef('SELECT * FROM sqlite_master'), 'sqlite_master');
    assert.equal(findInternalTableRef('SELECT k.priv_jwk FROM main._dokkebi_ephemeral_keys k'), '_dokkebi_ephemeral_keys');
    assert.equal(findInternalTableRef('SELECT * FROM "main"."_dokkebi_sessions"'), '_dokkebi_sessions');
    assert.equal(findInternalTableRef('SELECT * FROM posts'), null);
});

test('validateSqlAllowlist: allowlist 가 시스템 테이블을 포함해도 거부', () => {
    const cases = [
        'SELECT session_id, enc_key, sig_key FROM _dokkebi_sessions',
        'SELECT * FROM sqlite_master',
        'DELETE FROM _dokkebi_security',
        'UPDATE _dokkebi_sessions SET tenant_json = ? WHERE session_id = ?',
        'SELECT * FROM "_dokkebi_ephemeral_keys"',
    ];
    for (const sql of cases) {
        const r = validateSqlAllowlist(sql, ALLOW, { strict: true });
        assert.equal(r.allowed, false, sql);
    }
});

test('validateSqlAllowlist: allowlist 가 없고 strict=false 여도 내부 테이블은 차단', () => {
    const r = validateSqlAllowlist('SELECT enc_key FROM _dokkebi_sessions', null, { strict: false });
    assert.equal(r.allowed, false);
    assert.match(String(r.reason), /내부 시스템 테이블/);
});

test('validateSqlAllowlist: 클라이언트 DDL 차단', () => {
    for (const sql of [
        'CREATE TABLE _dokkebi_evil (x INT)',
        'CREATE TABLE IF NOT EXISTS posts_copy (id INT)',
        'CREATE INDEX idx_posts ON posts(title)',
        'ALTER TABLE posts ADD COLUMN x TEXT',
        'DROP TABLE posts',
    ]) {
        const r = validateSqlAllowlist(sql, ALLOW, { strict: true });
        assert.equal(r.allowed, false, sql);
    }
});

test('isInternalTableName', () => {
    assert.equal(isInternalTableName('_dokkebi_sessions'), true);
    assert.equal(isInternalTableName('sqlite_master'), true);
    assert.equal(isInternalTableName('posts'), false);
});

test('extractAllowlist: 시스템 테이블을 더 이상 허용목록에 넣지 않는다', async () => {
    // backend/models, backend/controllers 가 없는 최소 디렉터리 → 빈 allowlist
    const fs = await import('node:fs/promises');
    const os = await import('node:os');
    const path = await import('node:path');
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dokkebi-allow-'));
    try {
        await fs.mkdir(path.join(root, 'backend', 'models'), { recursive: true });
        await fs.mkdir(path.join(root, 'backend', 'controllers'), { recursive: true });
        await fs.writeFile(
            path.join(root, 'backend', 'models', 'index.ts'),
            `import { table, col, t } from 'dokkebi-dsl';\nexport const posts = table('posts', { id: col('id', t.uuid().primaryKey()) });\n`,
            'utf-8',
        );
        const allow = await extractAllowlist(root);
        const names = allow.tables.map((t) => t.name);
        assert.ok(names.includes('posts'));
        assert.equal(names.some((n) => n.startsWith('_dokkebi_') || n.startsWith('sqlite_')), false);
    } finally {
        await fs.rm(root, { recursive: true, force: true });
    }
});

// ─────────────────────────────────────────────────────────────
// 2. Allowlist — 읽기 원본 테이블도 SELECT 권한 필요
// ─────────────────────────────────────────────────────────────

test('validateSqlAllowlist: INSERT/UPDATE 의 서브쿼리 원본은 SELECT 권한 필요', () => {
    const withSelect = {
        tables: [
            { name: 'posts', ops: ['SELECT', 'UPDATE', 'INSERT'] },
            { name: 'users', ops: ['SELECT'] },
        ],
    };
    const withoutSelect = {
        tables: [
            { name: 'posts', ops: ['SELECT', 'UPDATE', 'INSERT'] },
            { name: 'users', ops: ['INSERT'] },
        ],
    };
    const sql = 'UPDATE posts SET title = (SELECT password_hash FROM users LIMIT 1) WHERE id = ?';
    assert.equal(validateSqlAllowlist(sql, withSelect, { strict: true }).allowed, true);
    assert.equal(validateSqlAllowlist(sql, withoutSelect, { strict: true }).allowed, false);

    const ins = 'INSERT INTO posts (user_id, title) SELECT user_id, password_hash FROM users';
    assert.equal(validateSqlAllowlist(ins, withSelect, { strict: true }).allowed, true);
    assert.equal(validateSqlAllowlist(ins, { tables: [
        { name: 'posts', ops: ['INSERT'] },
        { name: 'users', ops: ['INSERT'] },
    ] }, { strict: true }).allowed, false);

    // 주 연산 대상은 SELECT 없이도 INSERT/UPDATE 가능해야 한다.
    assert.equal(validateSqlAllowlist('INSERT INTO posts (user_id) VALUES (?)', { tables: [
        { name: 'posts', ops: ['INSERT'] },
    ] }, { strict: true }).allowed, true);
});

// ─────────────────────────────────────────────────────────────
// 3. Authorization — 참조하는 모든 테이블 검사
// ─────────────────────────────────────────────────────────────

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
const USER_JWT = { valid: true, payload: { role: 'user', user_id: 'u1' } };
const ADMIN_JWT = { valid: true, payload: { role: 'admin', user_id: 'a1' } };

test('extractOpAndTables: JOIN / INSERT..SELECT 의 모든 테이블 추출', () => {
    const join = extractOpAndTables('SELECT * FROM posts JOIN users ON users.id = posts.user_id');
    assert.equal(join.op, 'SELECT');
    assert.equal(join.primary, 'posts');
    assert.deepEqual([...join.tables].sort(), ['posts', 'users']);

    const ins = extractOpAndTables('INSERT INTO posts (user_id, title) SELECT user_id, password_hash FROM users');
    assert.equal(ins.op, 'INSERT');
    assert.equal(ins.primary, 'posts');
    assert.deepEqual([...ins.tables].sort(), ['posts', 'users']);
});

test('evaluateSqlAuthorization: JOIN 으로 보호 테이블 읽기 차단', () => {
    const sql = 'SELECT * FROM posts JOIN users ON users.id = posts.user_id';
    assert.equal(evaluateSqlAuthorization(AUTHZ, sql, USER_JWT).ok, false);
    assert.equal(evaluateSqlAuthorization(AUTHZ, sql, ADMIN_JWT).ok, true);
    // 단일 posts 조회는 public 이므로 비로그인도 허용
    assert.equal(evaluateSqlAuthorization(AUTHZ, 'SELECT * FROM posts', null).ok, true);
});

test('evaluateSqlAuthorization: upsert/REPLACE 는 부수 쓰기 권한까지 요구', () => {
    const policy = normalizeAuthorizationConfig({
        enabled: true,
        mode: 'strict',
        rules: {
            'SELECT:posts': { public: true },
            'INSERT:posts': { auth: true },
            'UPDATE:posts': { roles: ['admin'] },
            'DELETE:posts': { roles: ['admin'] },
            '*': { deny: true },
        },
    });
    const user = { valid: true, payload: { role: 'user', user_id: 'u1' } };
    const admin = { valid: true, payload: { role: 'admin', user_id: 'a1' } };

    const upsert = 'INSERT INTO posts (id,user_id,title) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET title=?';
    assert.equal(evaluateSqlAuthorization(policy, upsert, user).ok, false);
    assert.equal(evaluateSqlAuthorization(policy, upsert, admin).ok, true);

    const doNothing = 'INSERT INTO posts (id,user_id,title) VALUES (?,?,?) ON CONFLICT(id) DO NOTHING';
    assert.equal(evaluateSqlAuthorization(policy, doNothing, user).ok, true);

    for (const sql of [
        'INSERT OR REPLACE INTO posts (id,user_id,title) VALUES (?,?,?)',
        'REPLACE INTO posts (id,user_id,title) VALUES (?,?,?)',
        'UPDATE OR REPLACE posts SET title=? WHERE id=?',
    ]) {
        assert.equal(evaluateSqlAuthorization(policy, sql, user).ok, false, sql);
        assert.equal(evaluateSqlAuthorization(policy, sql, admin).ok, true, sql);
    }

    const meta = extractOpAndTables(upsert);
    assert.equal(meta.op, 'INSERT');
    assert.equal(meta.primary, 'posts');
    assert.deepEqual(meta.secondary, ['UPDATE']);
});

test('validateSqlAllowlist: 부수 쓰기 연산도 allowlist ops 를 요구', () => {
    const insertOnly = {
        version: 1,
        tables: [{ name: 'posts', ops: ['SELECT', 'INSERT'] }],
        rawAllowed: false,
    };
    const allOps = {
        version: 1,
        tables: [{ name: 'posts', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] }],
        rawAllowed: false,
    };
    const upsert = 'INSERT INTO posts (id,user_id,title) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET title=?';
    assert.equal(validateSqlAllowlist(upsert, insertOnly).allowed, false);
    assert.equal(validateSqlAllowlist(upsert, allOps).allowed, true);
    assert.equal(
        validateSqlAllowlist('INSERT INTO posts (id) VALUES (?) ON CONFLICT(id) DO NOTHING', insertOnly).allowed,
        true,
    );
    for (const sql of [
        'INSERT OR REPLACE INTO posts (id) VALUES (?)',
        'REPLACE INTO posts (id) VALUES (?)',
    ]) {
        assert.equal(validateSqlAllowlist(sql, insertOnly).allowed, false, sql);
    }
    const updateOnly = {
        version: 1,
        tables: [{ name: 'posts', ops: ['SELECT', 'UPDATE'] }],
        rawAllowed: false,
    };
    assert.equal(validateSqlAllowlist('UPDATE OR REPLACE posts SET title=? WHERE id=?', updateOnly).allowed, false);
});

test('evaluateSqlAuthorization: INSERT..SELECT 로 보호 테이블 값 빼돌리기 차단', () => {
    const sql = 'INSERT INTO posts (user_id, title) SELECT user_id, password_hash FROM users';
    const user = evaluateSqlAuthorization(AUTHZ, sql, USER_JWT);
    assert.equal(user.ok, false);
    assert.equal(user.table, 'users');
    assert.equal(user.op, 'SELECT'); // 서브쿼리 원본은 읽기로 평가
    assert.equal(evaluateSqlAuthorization(AUTHZ, sql, ADMIN_JWT).ok, true);
});

// ─────────────────────────────────────────────────────────────
// 4. Tenant — JWT 기반 인증 구성 시 기본으로 JWT 전용
// ─────────────────────────────────────────────────────────────

test('normalizePolicyConfig: authorization/auth.login 활성 시 requireJwtTenant 기본 true', () => {
    const base = { enabled: true, mode: 'inject', tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } } };
    assert.equal(normalizePolicyConfig(base, { authorizationEnabled: true }).requireJwtTenant, true);
    assert.equal(normalizePolicyConfig(base, { authLoginEnabled: true }).requireJwtTenant, true);
    assert.equal(normalizePolicyConfig(base, {}).requireJwtTenant, false);
    // 명시값이 항상 우선
    assert.equal(
        normalizePolicyConfig({ ...base, requireJwtTenant: false }, { authorizationEnabled: true }).requireJwtTenant,
        false,
    );
    assert.equal(
        normalizePolicyConfig({ ...base, requireJwtTenant: true }, {}).requireJwtTenant,
        true,
    );
});

// ─────────────────────────────────────────────────────────────
// 5. JWT — exp 필수 (exp 없는 토큰은 영구 유효가 되므로 거부)
// ─────────────────────────────────────────────────────────────

function signHs256(payload, secret) {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const head = b64({ alg: 'HS256', typ: 'JWT' });
    const body = b64(payload);
    const sig = createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url');
    return `${head}.${body}.${sig}`;
}

test('verifyJwtHs256: exp 없는 토큰 거부, exp 있는 토큰 허용', async () => {
    const secret = 'test-secret-0123456789abcdef0123456789abcdef';
    const noExp = signHs256({ sub: 'u1', role: 'admin' }, secret);
    const withExp = signHs256({ sub: 'u1', role: 'admin', exp: Math.floor(Date.now() / 1000) + 60 }, secret);
    assert.equal((await verifyJwtHs256(noExp, { secret })).valid, false);
    assert.equal((await verifyJwtHs256(withExp, { secret })).valid, true);
});
