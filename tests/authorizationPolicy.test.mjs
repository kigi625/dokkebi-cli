/**
 * Authorization Policy 단위 테스트
 *
 * 실행: node --test tests/authorizationPolicy.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import {
    normalizeAuthorizationConfig,
    matchRule,
    authorize,
    verifyJwtHs256,
    extractOpAndTable,
} from '../src/core/authorizationPolicy.js';

// ─────────────────────────────────────────────────────────────
// 1. Config 정규화
// ─────────────────────────────────────────────────────────────

test('normalizeAuthorizationConfig: enabled=false 면 null', () => {
    assert.equal(normalizeAuthorizationConfig({ enabled: false, rules: {} }), null);
    assert.equal(normalizeAuthorizationConfig(null), null);
    assert.equal(normalizeAuthorizationConfig(undefined), null);
});

test('normalizeAuthorizationConfig: 기본 필드 채워지고 규칙이 우선순위 순으로 정렬됨', () => {
    const out = normalizeAuthorizationConfig({
        rules: {
            '*': { auth: true },
            'DELETE:*': { roles: ['admin'] },
            'DELETE:posts': { roles: ['admin', 'moderator'] },
            'SELECT:posts': { public: true },
        },
    });
    assert.ok(out);
    assert.equal(out.enabled, true);
    assert.equal(out.mode, 'warn');
    assert.equal(out.jwtSecretEnv, 'DOKKEBI_JWT_SECRET');
    assert.equal(out.claim, 'role');
    assert.equal(out.clockSkewSec, 30);
    // 가장 구체적(DELETE:posts, SELECT:posts) > 반구체적(DELETE:*) > 디폴트(*)
    assert.equal(out.rules[0].key, 'DELETE:posts');
    assert.equal(out.rules[out.rules.length - 1].key, '*');
});

test('normalizeAuthorizationConfig: 유효하지 않은 OP/spec 은 드랍', () => {
    const out = normalizeAuthorizationConfig({
        rules: {
            'DROP:tbl': { auth: true }, // 유효하지 않은 OP
            'DELETE:': { auth: true },  // 빈 테이블
            'SELECT:posts': {},          // 스펙 없음
            'DELETE:posts': { roles: ['admin'] },
        },
    });
    assert.equal(out.rules.length, 1);
    assert.equal(out.rules[0].key, 'DELETE:posts');
});

test('normalizeAuthorizationConfig: mode=strict 설정', () => {
    const out = normalizeAuthorizationConfig({
        mode: 'strict',
        rules: { '*': { auth: true } },
    });
    assert.equal(out.mode, 'strict');
});

// ─────────────────────────────────────────────────────────────
// 2. 규칙 매칭
// ─────────────────────────────────────────────────────────────

test('matchRule: 가장 구체적인 규칙이 선택됨', () => {
    const policy = normalizeAuthorizationConfig({
        rules: {
            '*': { auth: true },
            'DELETE:*': { roles: ['admin'] },
            'DELETE:posts': { roles: ['author'] },
        },
    });
    assert.equal(matchRule(policy, 'DELETE', 'posts').key, 'DELETE:posts');
    assert.equal(matchRule(policy, 'DELETE', 'users').key, 'DELETE:*');
    assert.equal(matchRule(policy, 'SELECT', 'users').key, '*');
});

test('matchRule: 매칭 없으면 null', () => {
    const policy = normalizeAuthorizationConfig({
        rules: { 'DELETE:posts': { roles: ['admin'] } },
    });
    assert.equal(matchRule(policy, 'SELECT', 'users'), null);
});

test('matchRule: 테이블 대소문자 무관', () => {
    const policy = normalizeAuthorizationConfig({
        rules: { 'DELETE:Posts': { roles: ['admin'] } },
    });
    assert.equal(matchRule(policy, 'DELETE', 'POSTS').key, 'DELETE:Posts');
});

// ─────────────────────────────────────────────────────────────
// 3. 인가 판정
// ─────────────────────────────────────────────────────────────

test('authorize: public 규칙은 JWT 없이 통과', () => {
    const policy = normalizeAuthorizationConfig({
        rules: { 'SELECT:posts': { public: true } },
    });
    const matched = matchRule(policy, 'SELECT', 'posts');
    const res = authorize(matched, policy, null);
    assert.equal(res.ok, true);
});

test('authorize: auth 규칙은 JWT 없으면 거부', () => {
    const policy = normalizeAuthorizationConfig({
        rules: { 'INSERT:posts': { auth: true } },
    });
    const matched = matchRule(policy, 'INSERT', 'posts');
    const res = authorize(matched, policy, null);
    assert.equal(res.ok, false);
    assert.equal(res.code, 'AUTH_REQUIRED');
});

test('authorize: auth 규칙은 유효한 JWT 면 통과', () => {
    const policy = normalizeAuthorizationConfig({
        rules: { 'INSERT:posts': { auth: true } },
    });
    const matched = matchRule(policy, 'INSERT', 'posts');
    const res = authorize(matched, policy, { valid: true, payload: { sub: 'u1' } });
    assert.equal(res.ok, true);
});

test('authorize: roles 규칙은 role 불일치 시 ROLE_FORBIDDEN', () => {
    const policy = normalizeAuthorizationConfig({
        rules: { 'DELETE:posts': { roles: ['admin'] } },
    });
    const matched = matchRule(policy, 'DELETE', 'posts');
    const res = authorize(matched, policy, { valid: true, payload: { role: 'user' } });
    assert.equal(res.ok, false);
    assert.equal(res.code, 'ROLE_FORBIDDEN');
});

test('authorize: roles 규칙은 role 일치 시 통과', () => {
    const policy = normalizeAuthorizationConfig({
        rules: { 'DELETE:posts': { roles: ['admin', 'moderator'] } },
    });
    const matched = matchRule(policy, 'DELETE', 'posts');
    const res = authorize(matched, policy, { valid: true, payload: { role: 'moderator' } });
    assert.equal(res.ok, true);
    assert.equal(res.role, 'moderator');
});

test('authorize: role 이 배열인 경우도 지원', () => {
    const policy = normalizeAuthorizationConfig({
        rules: { 'DELETE:posts': { roles: ['admin'] } },
    });
    const matched = matchRule(policy, 'DELETE', 'posts');
    const res = authorize(matched, policy, { valid: true, payload: { role: ['user', 'admin'] } });
    assert.equal(res.ok, true);
});

test('authorize: role 클레임 커스텀', () => {
    const policy = normalizeAuthorizationConfig({
        claim: 'permissions',
        rules: { 'DELETE:posts': { roles: ['admin'] } },
    });
    const matched = matchRule(policy, 'DELETE', 'posts');
    const res = authorize(matched, policy, { valid: true, payload: { permissions: 'admin' } });
    assert.equal(res.ok, true);
});

test('authorize: JWT 무효면 AUTH_REQUIRED + 이유 포함', () => {
    const policy = normalizeAuthorizationConfig({
        rules: { 'DELETE:posts': { roles: ['admin'] } },
    });
    const matched = matchRule(policy, 'DELETE', 'posts');
    const res = authorize(matched, policy, { valid: false, reason: '만료됨' });
    assert.equal(res.ok, false);
    assert.equal(res.code, 'AUTH_REQUIRED');
    assert.ok(res.reason.includes('만료됨'));
});

test('authorize: deny 규칙은 무조건 거부', () => {
    const policy = normalizeAuthorizationConfig({
        rules: { 'DELETE:users': { deny: true } },
    });
    const matched = matchRule(policy, 'DELETE', 'users');
    const res = authorize(matched, policy, { valid: true, payload: { role: 'admin' } });
    assert.equal(res.ok, false);
    assert.equal(res.code, 'RULE_DENY');
});

test('authorize: warn 모드 + 규칙 미매칭 → 통과', () => {
    const policy = normalizeAuthorizationConfig({
        mode: 'warn',
        rules: { 'DELETE:posts': { roles: ['admin'] } },
    });
    const res = authorize(null, policy, null);
    assert.equal(res.ok, true);
});

test('authorize: strict 모드 + 규칙 미매칭 → NO_RULE', () => {
    const policy = normalizeAuthorizationConfig({
        mode: 'strict',
        rules: { 'DELETE:posts': { roles: ['admin'] } },
    });
    const res = authorize(null, policy, null);
    assert.equal(res.ok, false);
    assert.equal(res.code, 'NO_RULE');
});

// ─────────────────────────────────────────────────────────────
// 4. JWT 서명 검증 (HS256)
// ─────────────────────────────────────────────────────────────

async function signHs256(payload, secret, headerOverride) {
    const enc = (obj) => {
        const json = JSON.stringify(obj);
        const b64 = Buffer.from(json, 'utf-8').toString('base64');
        return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    const header = headerOverride || { alg: 'HS256', typ: 'JWT' };
    const h64 = enc(header);
    const p64 = enc(payload);
    const data = `${h64}.${p64}`;
    const key = await webcrypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    );
    const sig = await webcrypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
    const sigB64 = Buffer.from(sig).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return `${h64}.${p64}.${sigB64}`;
}

test('verifyJwtHs256: 올바른 서명이면 valid=true', async () => {
    const secret = 'super-secret-key';
    const token = await signHs256({ sub: 'u1', role: 'admin', exp: Math.floor(Date.now() / 1000) + 3600 }, secret);
    const res = await verifyJwtHs256(token, { secret, crypto: webcrypto });
    assert.equal(res.valid, true);
    assert.equal(res.payload.role, 'admin');
});

test('verifyJwtHs256: 잘못된 secret 이면 valid=false', async () => {
    const token = await signHs256({ sub: 'u1', role: 'admin', exp: Math.floor(Date.now() / 1000) + 3600 }, 'secret-a');
    const res = await verifyJwtHs256(token, { secret: 'secret-b', crypto: webcrypto });
    assert.equal(res.valid, false);
    assert.ok(res.reason.includes('서명'));
});

test('verifyJwtHs256: 만료된 JWT 거부', async () => {
    const secret = 'super-secret-key';
    const token = await signHs256({ sub: 'u1', exp: Math.floor(Date.now() / 1000) - 3600 }, secret);
    const res = await verifyJwtHs256(token, { secret, clockSkewSec: 0, crypto: webcrypto });
    assert.equal(res.valid, false);
    assert.ok(res.reason.includes('만료'));
});

test('verifyJwtHs256: clockSkew 내에서는 허용', async () => {
    const secret = 'super-secret-key';
    const token = await signHs256({ sub: 'u1', exp: Math.floor(Date.now() / 1000) - 10 }, secret);
    const res = await verifyJwtHs256(token, { secret, clockSkewSec: 60, crypto: webcrypto });
    assert.equal(res.valid, true);
});

test('verifyJwtHs256: issuer 검증', async () => {
    const secret = 'super-secret-key';
    const token = await signHs256({ sub: 'u1', iss: 'my-app', exp: Math.floor(Date.now() / 1000) + 3600 }, secret);
    const r1 = await verifyJwtHs256(token, { secret, issuer: 'my-app', crypto: webcrypto });
    assert.equal(r1.valid, true);
    const r2 = await verifyJwtHs256(token, { secret, issuer: 'other-app', crypto: webcrypto });
    assert.equal(r2.valid, false);
    assert.ok(r2.reason.includes('iss'));
});

test('verifyJwtHs256: audience 검증 (배열/문자열 모두 지원)', async () => {
    const secret = 'super-secret-key';
    const token1 = await signHs256({ sub: 'u1', aud: 'web', exp: Math.floor(Date.now() / 1000) + 3600 }, secret);
    const r1 = await verifyJwtHs256(token1, { secret, audience: 'web', crypto: webcrypto });
    assert.equal(r1.valid, true);

    const token2 = await signHs256({ sub: 'u1', aud: ['web', 'mobile'], exp: Math.floor(Date.now() / 1000) + 3600 }, secret);
    const r2 = await verifyJwtHs256(token2, { secret, audience: 'mobile', crypto: webcrypto });
    assert.equal(r2.valid, true);

    const r3 = await verifyJwtHs256(token1, { secret, audience: 'mobile', crypto: webcrypto });
    assert.equal(r3.valid, false);
});

test('verifyJwtHs256: 비 HS256 알고리즘 거부', async () => {
    const secret = 'super-secret-key';
    const token = await signHs256({ sub: 'u1' }, secret, { alg: 'HS512', typ: 'JWT' });
    const res = await verifyJwtHs256(token, { secret, crypto: webcrypto });
    assert.equal(res.valid, false);
    assert.ok(res.reason.includes('알고리즘'));
});

test('verifyJwtHs256: 빈 token / 형식 오류', async () => {
    assert.equal((await verifyJwtHs256('', { secret: 'x', crypto: webcrypto })).valid, false);
    assert.equal((await verifyJwtHs256('a.b', { secret: 'x', crypto: webcrypto })).valid, false);
});

// ─────────────────────────────────────────────────────────────
// 5. SQL op/table 추출 (워커 인라인 버전과 동일해야 함)
// ─────────────────────────────────────────────────────────────

test('extractOpAndTable: 기본 SQL 패턴', () => {
    assert.deepEqual(extractOpAndTable('SELECT * FROM posts WHERE id = ?'), { op: 'SELECT', table: 'posts' });
    assert.deepEqual(extractOpAndTable('INSERT INTO posts (title) VALUES (?)'), { op: 'INSERT', table: 'posts' });
    assert.deepEqual(extractOpAndTable('UPDATE posts SET title = ? WHERE id = ?'), { op: 'UPDATE', table: 'posts' });
    assert.deepEqual(extractOpAndTable('DELETE FROM posts WHERE id = ?'), { op: 'DELETE', table: 'posts' });
});

test('extractOpAndTable: CTE/WITH 도 SELECT 로 분류', () => {
    const r = extractOpAndTable('WITH recent AS (SELECT * FROM posts LIMIT 10) SELECT * FROM recent');
    assert.equal(r.op, 'SELECT');
});

test('extractOpAndTable: 스키마 접두사 제거 후 소문자 테이블 반환', () => {
    assert.equal(extractOpAndTable('SELECT * FROM main.posts').table, 'posts');
    assert.equal(extractOpAndTable('SELECT * FROM "Posts"').table, 'posts');
});

test('extractOpAndTable: CREATE TABLE', () => {
    assert.deepEqual(extractOpAndTable('CREATE TABLE IF NOT EXISTS users (id INT)'), { op: 'CREATE', table: 'users' });
});

test('extractOpAndTable: 파싱 불가 SQL', () => {
    assert.deepEqual(extractOpAndTable(''), { op: null, table: null });
    assert.deepEqual(extractOpAndTable('DROP TABLE posts'), { op: null, table: null });
});

test('extractOpAndTable: 주석/문자열에 포함된 키워드는 무시', () => {
    const r = extractOpAndTable("SELECT * FROM posts -- INSERT INTO foo\nWHERE x = 'DELETE FROM y'");
    assert.equal(r.op, 'SELECT');
    assert.equal(r.table, 'posts');
});

// ─────────────────────────────────────────────────────────────
// 6. 통합 시나리오 — 실제 규칙으로 E2E 판정
// ─────────────────────────────────────────────────────────────

test('통합: posts DELETE 는 admin 만, SELECT 는 public', async () => {
    const policy = normalizeAuthorizationConfig({
        rules: {
            'SELECT:posts': { public: true },
            'INSERT:posts': { auth: true },
            'UPDATE:posts': { roles: ['admin', 'author'] },
            'DELETE:posts': { roles: ['admin'] },
            '*': { auth: true },
        },
    });

    // 누구나 SELECT
    {
        const { op, table } = extractOpAndTable('SELECT * FROM posts');
        const m = matchRule(policy, op, table);
        assert.equal(authorize(m, policy, null).ok, true);
    }

    // INSERT 는 JWT 필수
    {
        const { op, table } = extractOpAndTable('INSERT INTO posts (title) VALUES (?)');
        const m = matchRule(policy, op, table);
        assert.equal(authorize(m, policy, null).ok, false);
        assert.equal(authorize(m, policy, { valid: true, payload: { sub: 'u1' } }).ok, true);
    }

    // DELETE 는 admin 만
    {
        const { op, table } = extractOpAndTable('DELETE FROM posts WHERE id = ?');
        const m = matchRule(policy, op, table);
        const user = { valid: true, payload: { role: 'user' } };
        const admin = { valid: true, payload: { role: 'admin' } };
        assert.equal(authorize(m, policy, user).ok, false);
        assert.equal(authorize(m, policy, admin).ok, true);
    }

    // UPDATE 는 admin 또는 author
    {
        const { op, table } = extractOpAndTable('UPDATE posts SET title = ? WHERE id = ?');
        const m = matchRule(policy, op, table);
        assert.equal(authorize(m, policy, { valid: true, payload: { role: 'author' } }).ok, true);
        assert.equal(authorize(m, policy, { valid: true, payload: { role: 'user' } }).ok, false);
    }

    // 규칙에 없는 테이블 → 디폴트 '*' 매칭 → auth 필요
    {
        const { op, table } = extractOpAndTable('SELECT * FROM internal_logs');
        const m = matchRule(policy, op, table);
        assert.equal(m.key, '*');
        assert.equal(authorize(m, policy, null).ok, false);
        assert.equal(authorize(m, policy, { valid: true, payload: { sub: 'x' } }).ok, true);
    }
});
