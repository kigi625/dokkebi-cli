/**
 * SQL 형태/테넌트 우회 회귀 테스트 (C1~C3)
 *
 *   C1. `WITH ... DELETE/UPDATE/INSERT` 을 SELECT 로 오판하지 않는지
 *   C2. 테넌트 조건을 서브쿼리/괄호 OR 로 위장해 우회할 수 없는지
 *   C3. `mode: 'optional'` 이 클레임 존재 시 실제로 격리하는지
 *
 * 실행: node --test tests/sqlShapeHardening.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { detectOuterOp, outerStatement } from '../src/core/sqlShape.js';
import { validateSqlAllowlist } from '../src/core/sqlAllowlist.js';
import {
    normalizeAuthorizationConfig,
    extractOpAndTables,
    evaluateSqlAuthorization,
} from '../src/core/authorizationPolicy.js';
import {
    normalizePolicyConfig,
    verifyTenantPolicy,
    injectTenantPolicy,
} from '../src/core/policyEngine.js';

// ─────────────────────────────────────────────────────────────
// C1. WITH + DML
// ─────────────────────────────────────────────────────────────

test('detectOuterOp: CTE 뒤 DML 을 정확히 판별', () => {
    assert.equal(detectOuterOp('WITH X AS (SELECT 1) DELETE FROM POSTS').op, 'DELETE');
    assert.equal(detectOuterOp('WITH X AS (SELECT 1) UPDATE POSTS SET A = 1').op, 'UPDATE');
    assert.equal(detectOuterOp('WITH X AS (SELECT 1) INSERT INTO POSTS (A) VALUES (1)').op, 'INSERT');
    assert.equal(detectOuterOp('WITH X AS (SELECT 1) SELECT * FROM X').op, 'SELECT');
    assert.equal(detectOuterOp('SELECT * FROM POSTS').op, 'SELECT');
    assert.equal(detectOuterOp('EXPLAIN SELECT * FROM POSTS').op, null);
    assert.equal(outerStatement('WITH X AS (SELECT 1) DELETE FROM POSTS'), 'DELETE FROM POSTS');
});

test('C1: allowlist 가 WITH-DML 의 쓰기 권한을 요구', () => {
    const selectOnly = { tables: [{ name: 'posts', ops: ['SELECT'] }] };
    for (const sql of [
        'WITH x AS (SELECT 1) DELETE FROM posts',
        'WITH x AS (SELECT 1) UPDATE posts SET a = 1',
        'WITH x AS (SELECT 1) INSERT INTO posts (a) VALUES (1)',
    ]) {
        const r = validateSqlAllowlist(sql, selectOnly);
        assert.equal(r.allowed, false, sql);
    }
    const full = { tables: [{ name: 'posts', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] }] };
    assert.equal(validateSqlAllowlist('WITH x AS (SELECT 1) DELETE FROM posts', full).allowed, true);
});

test('C1: Authorization 이 WITH-DML 을 SELECT 규칙으로 통과시키지 않음', () => {
    const authz = normalizeAuthorizationConfig({
        enabled: true, mode: 'strict',
        rules: {
            'SELECT:posts': { public: true },
            'DELETE:posts': { roles: ['admin'] },
            'UPDATE:posts': { roles: ['admin'] },
            '*': { deny: true },
        },
    });
    const user = { valid: true, payload: { role: 'user' } };
    const admin = { valid: true, payload: { role: 'admin' } };
    for (const sql of [
        'WITH x AS (SELECT 1) DELETE FROM posts',
        'WITH x AS (SELECT 1) UPDATE posts SET a = 1',
    ]) {
        assert.equal(extractOpAndTables(sql).op, sql.includes('DELETE') ? 'DELETE' : 'UPDATE');
        assert.equal(evaluateSqlAuthorization(authz, sql, user).ok, false, sql);
        assert.equal(evaluateSqlAuthorization(authz, sql, admin).ok, true, sql);
    }
});

// ─────────────────────────────────────────────────────────────
// C2. Tenant 우회
// ─────────────────────────────────────────────────────────────

const ctx = { user_id: 'u1' };
function policy(mode) {
    return normalizePolicyConfig({
        enabled: true, mode, strict: true, claim: 'user_id',
        tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } },
    });
}

test('C2 verify: 정상 필터는 통과, 우회 패턴은 거부', () => {
    const p = policy('verify');
    const ok = [
        ['SELECT * FROM posts WHERE user_id = ?', ['u1']],
        ['SELECT * FROM posts WHERE (user_id = ?)', ['u1']],
        ['UPDATE posts SET x = ? WHERE id = ? AND user_id = ?', ['a', '5', 'u1']],
    ];
    for (const [sql, params] of ok) {
        assert.equal(verifyTenantPolicy(sql, params, ctx, p, { strict: true }).ok, true, sql);
    }
    const bad = [
        ['SELECT * FROM posts WHERE (user_id = ? OR 1=1)', ['u1']],
        ['DELETE FROM posts WHERE id = ? AND (SELECT 1 FROM posts WHERE user_id = ?)', ['5', 'u1']],
        ['UPDATE posts SET x = (SELECT 1 FROM posts WHERE user_id = ?) WHERE id = ?', ['u1', '5']],
        ['WITH x AS (SELECT 1) DELETE FROM posts', []],
    ];
    for (const [sql, params] of bad) {
        assert.equal(verifyTenantPolicy(sql, params, ctx, p, { strict: true }).ok, false, sql);
    }
});

test('C2 inject: 우회 패턴에 바깥 테넌트 필터를 주입하고 재검증 통과', () => {
    const p = policy('inject');
    const cases = [
        ['SELECT * FROM posts WHERE (user_id = ? OR 1=1)', ['u1']],
        ['DELETE FROM posts WHERE id = ? AND (SELECT 1 FROM posts WHERE user_id = ?)', ['5', 'u1']],
        ['UPDATE posts SET x = (SELECT 1 FROM posts WHERE user_id = ?) WHERE id = ?', ['u1', '5']],
    ];
    for (const [sql, params] of cases) {
        const r = injectTenantPolicy(sql, params, ctx, p, { strict: true });
        assert.equal(r.ok, true, sql);
        assert.match(r.sql, /user_id = \?/);
        const v = verifyTenantPolicy(r.sql, r.params, { user_id: 'u1' }, policy('verify'), { strict: true });
        assert.equal(v.ok, true, `${sql} -> ${r.sql}`);
        // 다른 테넌트 값으로는 실패해야 한다.
        const v2 = verifyTenantPolicy(r.sql, r.params, { user_id: 'u2' }, policy('verify'), { strict: true });
        assert.equal(v2.ok, false);
    }
});

test('C2 inject: DELETE 에서 서브쿼리 뒤가 아닌 바깥 WHERE 에 AND 로 붙는다', () => {
    const p = policy('inject');
    const r = injectTenantPolicy(
        'DELETE FROM posts WHERE id = ? AND (SELECT 1 FROM posts WHERE user_id = ?)',
        ['5', 'u1'], ctx, p, { strict: true },
    );
    assert.equal(r.ok, true);
    assert.match(r.sql, /AND \(posts\.user_id = \?\)\s*$/);
});

// ─────────────────────────────────────────────────────────────
// C3. optional 모드
// ─────────────────────────────────────────────────────────────

test("C3: optional 은 클레임이 있으면 enforce, 없으면 공개", () => {
    const opt = normalizePolicyConfig({
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: { posts: { tenantColumn: 'user_id', mode: 'optional' } },
    });
    // 클레임 없음 → 공개
    assert.equal(verifyTenantPolicy('SELECT * FROM posts', [], null, opt, { strict: true }).ok, true);
    // 클레임 있음 + 필터 없음 → 거부
    assert.equal(verifyTenantPolicy('SELECT * FROM posts', [], { user_id: 'u1' }, opt, { strict: true }).ok, false);
    // 클레임 있음 + 필터 있음 → 통과
    assert.equal(
        verifyTenantPolicy('SELECT * FROM posts WHERE user_id = ?', ['u1'], { user_id: 'u1' }, opt, { strict: true }).ok,
        true,
    );
});

test('C3: optional + inject 는 클레임이 있을 때만 주입', () => {
    const inj = normalizePolicyConfig({
        enabled: true, mode: 'inject', strict: true, claim: 'user_id',
        tables: { posts: { tenantColumn: 'user_id', mode: 'optional' } },
    });
    const withClaim = injectTenantPolicy('SELECT * FROM posts', [], { user_id: 'u1' }, inj, { strict: true });
    assert.equal(withClaim.ok, true);
    assert.equal(withClaim.injected, true);
    assert.match(withClaim.sql, /user_id = \?/);

    const noClaim = injectTenantPolicy('SELECT * FROM posts', [], null, inj, { strict: true });
    assert.equal(noClaim.ok, true);
    assert.equal(noClaim.injected, false);
});

test('C3: optional 은 모호한 매핑(site_id ← user_id)을 강제하지 않는다', () => {
    const amb = normalizePolicyConfig({
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: { inquiries: { tenantColumn: 'site_id', mode: 'optional' } },
    });
    // tenantColumn(site_id) != claim(user_id) & sessionClaim 없음 → 매핑 모호 → 스킵
    assert.equal(
        verifyTenantPolicy('SELECT * FROM inquiries', [], { user_id: 'u1' }, amb, { strict: true }).ok,
        true,
    );
    // sessionClaim 을 명시하면 그 클레임으로 강제
    const explicit = normalizePolicyConfig({
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: { inquiries: { tenantColumn: 'site_id', sessionClaim: 'site_id', mode: 'optional' } },
    });
    assert.equal(
        verifyTenantPolicy('SELECT * FROM inquiries', [], { user_id: 'u1' }, explicit, { strict: true }).ok,
        true, // site_id 클레임이 없으므로 optional 스킵
    );
    assert.equal(
        verifyTenantPolicy('SELECT * FROM inquiries', [], { site_id: 's1' }, explicit, { strict: true }).ok,
        false, // site_id 클레임이 있으면 필터 필요
    );
    assert.equal(
        verifyTenantPolicy('SELECT * FROM inquiries WHERE site_id = ?', ['s1'], { site_id: 's1' }, explicit, { strict: true }).ok,
        true,
    );
});

// ─────────────────────────────────────────────────────────────
// C4. 콤마 조인 (`FROM a, b`) 테이블 추출
// ─────────────────────────────────────────────────────────────

test('C4: 콤마 조인으로 보호 테이블을 숨길 수 없다', () => {
    const allow = { version: 1, rawAllowed: false, tables: [{ name: 'posts', ops: ['SELECT'] }] };
    assert.equal(validateSqlAllowlist('SELECT * FROM posts', allow).allowed, true);
    for (const sql of [
        'SELECT * FROM posts, users',
        'SELECT * FROM posts p, "users" u',
        'SELECT * FROM posts, main.users',
        'SELECT * FROM posts, [users]',
        'SELECT * FROM posts JOIN [users] ON 1=1',
        'SELECT * FROM posts, (SELECT * FROM [users])',
        'SELECT * FROM "main"."users"',
        'SELECT * FROM posts, [main].[users]',
        'SELECT * FROM posts, (users)',
        'SELECT * FROM (posts) p, users u',
        'SELECT * FROM ((users))',
        'UPDATE posts SET x = 1 FROM [users] WHERE users.id = posts.id',
    ]) {
        assert.equal(validateSqlAllowlist(sql, allow).allowed, false, sql);
        const t = extractOpAndTables(sql);
        assert.ok(t.tables.includes('users'), sql + ' -> ' + t.tables.join(','));
    }

    const authz = normalizeAuthorizationConfig({
        enabled: true, mode: 'strict',
        rules: {
            'SELECT:posts': { public: true },
            'SELECT:users': { roles: ['admin'] },
            '*': { deny: true },
        },
    });
    const user = { valid: true, payload: { role: 'user' } };
    assert.equal(evaluateSqlAuthorization(authz, 'SELECT * FROM posts, users', user).ok, false);

    const p = normalizePolicyConfig({
        enabled: true, mode: 'verify', strict: true, claim: 'user_id',
        tables: {
            posts: { tenantColumn: 'user_id', mode: 'enforce' },
            users: { tenantColumn: 'user_id', mode: 'enforce' },
        },
    });
    const ctx = { user_id: 'u1' };
    // 다중 테이블에서 비한정 user_id 는 다른 테이블 컬럼일 수 있으므로 인정하지 않는다.
    assert.equal(verifyTenantPolicy('SELECT * FROM posts, users WHERE user_id = ?', ['u1'], ctx, p, { strict: true }).ok, false);
    assert.equal(verifyTenantPolicy('SELECT * FROM posts, users WHERE posts.user_id = ? AND users.user_id = ?', ['u1', 'u1'], ctx, p, { strict: true }).ok, true);

    const inj = injectTenantPolicy('SELECT * FROM posts, users', [], ctx, normalizePolicyConfig({ ...p, mode: 'inject' }), { strict: true });
    assert.equal(inj.ok, true);
    assert.match(inj.sql, /posts\.user_id = \?/);
    assert.match(inj.sql, /users\.user_id = \?/);
});
