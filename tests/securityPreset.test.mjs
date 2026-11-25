/**
 * security.preset: 'production' / audit 회귀 테스트
 *
 * 실행: node --test tests/securityPreset.test.mjs tests/securityAudit.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { applySecurityPreset } from '../src/core/dokkebiConfigLoad.js';
import { checkProductionPreflight } from '../src/core/securityAudit.js';

test("preset: 'production' — strict + CSP + panel + ADL enforce", () => {
    const out = applySecurityPreset({ security: { preset: 'production' } }, { quiet: true });
    assert.equal(out.security.level, 'strict');
    assert.equal(out.security.strictCsp, true);
    assert.equal(out.security.panelIpGuard, true);
    assert.deepEqual(out.security.activeDefense, { enabled: true, mode: 'enforce' });
    assert.equal(out.policy.mode, 'inject');
    assert.equal(out.authorization.mode, 'strict');
    assert.equal(out.queryRegistry.strict, true);
});

test("preset: 'production' — 사용자 명시값이 우선", () => {
    const out = applySecurityPreset({
        security: {
            preset: 'production',
            level: 'standard',
            strictCsp: false,
            panelIpGuard: false,
            activeDefense: { enabled: true, mode: 'monitor' },
        },
    }, { quiet: true });
    assert.equal(out.security.level, 'standard');
    assert.equal(out.security.strictCsp, false);
    assert.equal(out.security.panelIpGuard, false);
    assert.equal(out.security.activeDefense.mode, 'monitor');
    assert.equal(out.policy.mode, 'verify'); // standard
    assert.equal(out.authorization.mode, 'warn');
});

test("preset: 'production' — capabilities 는 feature 선언 시에만 자동 활성", () => {
    const none = applySecurityPreset({ security: { preset: 'production' } }, { quiet: true });
    assert.equal(none.security.capabilities?.enabled, undefined);

    const withFeatures = applySecurityPreset({
        security: {
            preset: 'production',
            capabilities: { features: { 'image.generate': { roles: ['premium'] } } },
        },
    }, { quiet: true });
    assert.equal(withFeatures.security.capabilities.enabled, true);
});

test("preset 미지정 + level 미지정 — 기존 동작 유지", () => {
    const out = applySecurityPreset({ security: {} }, { quiet: true });
    assert.equal(out.security.level, undefined);
    assert.equal(out.policy, undefined);
});

test("production preflight: 필수 값 누락 시 issue", () => {
    const r = checkProductionPreflight({
        security: {},
        policyMeta: { enabled: true, tables: {} },
        authzMeta: { enabled: true, mode: 'strict' },
        panelIpGuardEnabled: true,
        env: {},
    });
    // CORS/패널 IP 는 선택 옵션이므로 issue 가 아니다. JWT 만 차단한다.
    assert.equal(r.issues.length, 1);
    assert.ok(r.issues[0].includes('JWT'));
    assert.equal(r.issues.some((w) => w.includes('CORS') || w.includes('PANEL_ALLOWED_IPS')), false);
    assert.ok(r.warnings.some((w) => w.includes('DOKKEBI_ADMIN_PASSWORD')));
});

test("production preflight: 값이 모두 있으면 issue 0", () => {
    const r = checkProductionPreflight({
        security: { cors: { allowedOrigins: ['https://app.example.com'] } },
        policyMeta: { enabled: true, tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } } },
        authzMeta: { enabled: true, mode: 'strict' },
        panelIpGuardEnabled: true,
        env: {
            JWT_SECRET: '0123456789abcdef0123456789abcdef',
            DOKKEBI_ADMIN_PASSWORD: '0123456789abcdef0123',
            DOKKEBI_PANEL_ALLOWED_IPS: '203.0.113.10',
        },
    });
    assert.deepEqual(r.issues, []);
    assert.deepEqual(r.warnings, []);
});

test("production preflight: authz warn 모드는 issue", () => {
    const r = checkProductionPreflight({
        security: { cors: { allowedOrigins: ['https://app.example.com'] } },
        policyMeta: { enabled: true, tables: {} },
        authzMeta: { enabled: true, mode: 'warn' },
        panelIpGuardEnabled: false,
        env: { JWT_SECRET: '0123456789abcdef0123456789abcdef' },
    });
    assert.ok(r.issues.some((i) => i.includes('strict')));
});
