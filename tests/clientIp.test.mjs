/**
 * 클라이언트 IP 신뢰 정책 / 관제 IP allowlist 회귀 테스트
 *
 * 실행: node --test tests/clientIp.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { resolveClientIp, trustProxyFromEnv } from '../src/core/clientIp.js';
import { handleAdminRoute } from '../src/core/adminPanel.js';

function reqWith({ socketIp = '127.0.0.1', headers = {}, url = '/_dokkebi/_panel', method = 'GET' } = {}) {
    return { url, method, headers, socket: { remoteAddress: socketIp } };
}
function mockRes() {
    const out = { status: 0, body: '' };
    const res = {
        writeHead(status) { out.status = status; return res; },
        end(body) { out.body = body == null ? '' : String(body); },
        setHeader() { return res; },
    };
    return { res, out };
}

test('resolveClientIp: 기본은 소켓 IP, XFF/CF 헤더 무시', () => {
    const req = reqWith({ headers: { 'x-forwarded-for': '203.0.113.5', 'cf-connecting-ip': '198.51.100.9' } });
    assert.equal(resolveClientIp(req, { trustProxy: false }), '127.0.0.1');
});

test('resolveClientIp: trustProxy=true 일 때만 헤더 신뢰 (CF > XFF)', () => {
    const req = reqWith({ headers: { 'x-forwarded-for': '203.0.113.5, 10.0.0.1', 'cf-connecting-ip': '198.51.100.9' } });
    assert.equal(resolveClientIp(req, { trustProxy: true }), '198.51.100.9');
    const req2 = reqWith({ headers: { 'x-forwarded-for': '203.0.113.5, 10.0.0.1' } });
    assert.equal(resolveClientIp(req2, { trustProxy: true }), '203.0.113.5');
});

test('trustProxyFromEnv', () => {
    assert.equal(trustProxyFromEnv({}), false);
    assert.equal(trustProxyFromEnv({ DOKKEBI_TRUST_PROXY: '1' }), true);
    assert.equal(trustProxyFromEnv({ TRUST_PROXY: 'true' }), true);
    assert.equal(trustProxyFromEnv({ DOKKEBI_TRUST_PROXY: 'off' }), false);
});

test('관제 IP allowlist: XFF 위조로 우회할 수 없다 (trustProxy=false)', async () => {
    const { res, out } = mockRes();
    const req = reqWith({ headers: { 'x-forwarded-for': '203.0.113.5' } });
    await handleAdminRoute(req, res, {
        adminPassword: 'pw', adminAllowedIps: '203.0.113.5', panelIpGuardEnabled: true,
        dbType: 'd1', dbConfig: {}, proxyDbQuery: async () => ({ rows: [] }),
        projectName: 't', mode: 'serve', trustProxy: false,
    });
    assert.equal(out.status, 403);
});

test('관제 IP allowlist: 신뢰 프록시 모드에서는 헤더 IP 로 허용', async () => {
    const { res, out } = mockRes();
    const req = reqWith({ headers: { 'x-forwarded-for': '203.0.113.5' } });
    await handleAdminRoute(req, res, {
        adminPassword: 'pw', adminAllowedIps: '203.0.113.5', panelIpGuardEnabled: true,
        dbType: 'd1', dbConfig: {}, proxyDbQuery: async () => ({ rows: [] }),
        projectName: 't', mode: 'serve', trustProxy: true,
    });
    assert.equal(out.status, 200);
});
