/**
 * dok security --audit 수집기 테스트
 *
 * 실행: node --test tests/securityAudit.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { collectSecurityAudit, formatSecurityAudit } from '../src/core/securityAudit.js';

async function makeProject({ config, env = '', gitignore = '', worker = '' }) {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dok-audit-'));
    await fs.writeFile(path.join(root, 'dokkebi.config.mjs'), config, 'utf-8');
    if (env) await fs.writeFile(path.join(root, '.env'), env, 'utf-8');
    if (gitignore) await fs.writeFile(path.join(root, '.gitignore'), gitignore, 'utf-8');
    if (worker) {
        await fs.mkdir(path.join(root, 'worker', 'api', '_dokkebi'), { recursive: true });
        await fs.writeFile(path.join(root, 'worker', 'api', '_dokkebi', 'db.ts'), worker, 'utf-8');
    }
    return root;
}
const GI = '.env\n.dokkebi/\n.dev.vars\n.dokkebi-secrets.json\n';
const WORKER = 'function findInternalTableRef(){} function _az_checkSql(){}';

test('audit: 기본 프로젝트는 여러 경고를 낸다', async () => {
    const root = await makeProject({
        config: `export default { proxyMode: 'serverless', security: {} };`,
        gitignore: GI,
        worker: WORKER,
    });
    try {
        const r = await collectSecurityAudit(root);
        const ids = r.findings.map((f) => f.id);
        assert.ok(ids.includes('level.unset'));
        assert.ok(ids.includes('policy.off'));
        assert.ok(ids.includes('authz.off'));
        assert.ok(ids.includes('csp.off'));
        assert.ok(ids.includes('cors.wildcard'));
        assert.equal(r.counts.error, 0);
        assert.match(formatSecurityAudit(r), /Security audit/);
    } finally {
        await fs.rm(root, { recursive: true, force: true });
    }
});

test('audit: production preset + 필수 값이 모두 있으면 error 0', async () => {
    const root = await makeProject({
        config: `export default {
  proxyMode: 'serverless',
  security: {
    preset: 'production',
    cors: { allowedOrigins: ['https://app.example.com'] },
  },
  policy: { tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } } },
  authorization: { rules: { '*': { auth: true } } },
};`,
        env: [
            'JWT_SECRET=0123456789abcdef0123456789abcdef',
            'DOKKEBI_ADMIN_PASSWORD=0123456789abcdef0123',
            'DOKKEBI_PANEL_ALLOWED_IPS=203.0.113.10',
        ].join('\n') + '\n',
        gitignore: GI,
        worker: WORKER,
    });
    try {
        const r = await collectSecurityAudit(root);
        assert.equal(r.counts.error, 0, JSON.stringify(r.findings, null, 2));
        const ids = r.findings.map((f) => f.id);
        assert.ok(ids.includes('preset.production'));
        assert.ok(!ids.includes('cors.wildcard'));
        assert.ok(!ids.includes('panel.noIps'));
        await fs.rm(root, { recursive: true, force: true });
    } catch (e) {
        await fs.rm(root, { recursive: true, force: true });
        throw e;
    }
});

test('audit: production 인데 JWT/패널 IP 누락이면 error', async () => {
    const root = await makeProject({
        config: `export default {
  proxyMode: 'serverless',
  security: { preset: 'production', cors: { allowedOrigins: ['https://app.example.com'] } },
  authorization: { rules: { '*': { auth: true } } },
};`,
        gitignore: GI,
        worker: WORKER,
    });
    try {
        const r = await collectSecurityAudit(root);
        const ids = r.findings.map((f) => f.id);
        assert.ok(ids.includes('jwt.missing'));
        assert.ok(ids.includes('panel.noIps'));
        assert.equal(r.counts.error >= 2, true);
    } finally {
        await fs.rm(root, { recursive: true, force: true });
    }
});

test('audit: JWT 다중 시크릿 / 모호한 테넌트 매핑 경고', async () => {
    const root = await makeProject({
        config: `export default {
  proxyMode: 'serverless',
  security: { level: 'strict' },
  policy: { tables: { inquiries: { tenantColumn: 'site_id', mode: 'optional' } } },
  authorization: { mode: 'strict', rules: { '*': { auth: true } } },
};`,
        env: [
            'JWT_SECRET=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'DOKKEBI_JWT_SECRET=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        ].join('\n') + '\n',
        gitignore: GI,
        worker: WORKER,
    });
    try {
        const r = await collectSecurityAudit(root);
        const ids = r.findings.map((f) => f.id);
        assert.ok(ids.includes('jwt.multiple'));
        assert.ok(ids.includes('policy.ambiguousTables'));
    } finally {
        await fs.rm(root, { recursive: true, force: true });
    }
});

test('audit: .gitignore 누락 경고', async () => {
    const root = await makeProject({
        config: `export default { security: {} };`,
        gitignore: 'node_modules/\n',
    });
    try {
        const r = await collectSecurityAudit(root);
        const ids = r.findings.map((f) => f.id);
        assert.ok(ids.some((id) => id.startsWith('gitignore.')));
    } finally {
        await fs.rm(root, { recursive: true, force: true });
    }
});
