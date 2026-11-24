/**
 * JWT 시크릿/클레임 하드닝 회귀 테스트 (H3/H4)
 *
 * 실행: node --test tests/jwtHardening.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
    normalizeAuthorizationConfig,
    resolveJwtSecret,
    jwtIdentityFromPayload,
} from '../src/core/authorizationPolicy.js';

test('resolveJwtSecret: 단일 시크릿만 선택 (JWT_SECRET 우선)', () => {
    const meta = normalizeAuthorizationConfig({ enabled: true, rules: { '*': { auth: true } } });
    const env = { JWT_SECRET: 'weak-legacy', DOKKEBI_JWT_SECRET: 'canonical' };
    const r = resolveJwtSecret(env, meta);
    assert.equal(r.secret, 'weak-legacy');
    assert.equal(r.source, 'JWT_SECRET');
});

test('resolveJwtSecret: DOKKEBI 만 있으면 DOKKEBI 사용', () => {
    const meta = normalizeAuthorizationConfig({ enabled: true, rules: { '*': { auth: true } } });
    const r = resolveJwtSecret({ DOKKEBI_JWT_SECRET: 'canonical' }, meta);
    assert.equal(r.secret, 'canonical');
    assert.equal(r.source, 'DOKKEBI_JWT_SECRET');
});

test('resolveJwtSecret: jwtSecretEnv 를 명시하면 그 바인딩만 사용', () => {
    const meta = normalizeAuthorizationConfig({
        enabled: true,
        jwtSecretEnv: 'MY_APP_JWT',
        rules: { '*': { auth: true } },
    });
    assert.equal(meta.jwtSecretEnvExplicit, true);
    const r = resolveJwtSecret({ MY_APP_JWT: 'mine', JWT_SECRET: 'weak', DOKKEBI_JWT_SECRET: 'other' }, meta);
    assert.equal(r.secret, 'mine');
    assert.equal(r.source, 'MY_APP_JWT');
    // 명시 바인딩이 비어 있으면 다른 시크릿으로 대체하지 않는다.
    const empty = resolveJwtSecret({ JWT_SECRET: 'weak' }, meta);
    assert.equal(empty.secret, '');
});

test('resolveJwtSecret: 시크릿 없음', () => {
    const meta = normalizeAuthorizationConfig({ enabled: true, rules: { '*': { auth: true } } });
    assert.equal(resolveJwtSecret({}, meta).secret, '');
});

test('jwtIdentityFromPayload: 명시 claim 우선, 없을 때만 userId/user_id fallback', () => {
    assert.equal(jwtIdentityFromPayload({ user_id: 'u1', org_id: 'o1' }, 'org_id'), 'o1');
    assert.equal(jwtIdentityFromPayload({ user_id: 'u1' }, 'org_id'), 'u1');
    assert.equal(jwtIdentityFromPayload({ userId: 'u2' }, 'user_id'), 'u2');
    assert.equal(jwtIdentityFromPayload({}, 'user_id'), null);
    assert.equal(jwtIdentityFromPayload(null, 'user_id'), null);
});
