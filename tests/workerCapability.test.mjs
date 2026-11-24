/**
 * worker/_dokkebi/capability.ts (서버측 Signed Unlock Token 검증) 실행 테스트
 *
 * 템플릿을 esbuild 로 JS 변환 후 직접 호출한다.
 * 실행: node --test tests/workerCapability.test.mjs   (esbuild 필요)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { createHmac } from 'node:crypto';

import { workerCapability } from '../src/core/projectGenerator.js';

const SECRET = 'cap-secret-0123456789abcdef0123456789abcdef';

const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'dokkebi-cap-'));
const tsPath = path.join(dir, 'capability.ts');
await fs.writeFile(tsPath, workerCapability(), 'utf-8');
const out = await build({
    entryPoints: [tsPath],
    bundle: true,
    format: 'esm',
    target: 'es2022',
    platform: 'neutral',
    write: false,
});
const jsPath = path.join(dir, 'capability.mjs');
await fs.writeFile(jsPath, out.outputFiles[0].text, 'utf-8');
const { verifyCapability } = await import(pathToFileURL(jsPath).href);
test.after(async () => { await fs.rm(dir, { recursive: true, force: true }); });

function b64url(o) {
    return Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
}
function signCap(payload, secret = SECRET) {
    const head = b64url({ alg: 'HS256', typ: 'DOKKEBI-CAP', v: 1 });
    const body = b64url(payload);
    const sig = createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url');
    return `${head}.${body}.${sig}`;
}
function reqWith(token) {
    return new Request('https://example.com/api/ai/image', {
        headers: token ? { 'x-dokkebi-capability': token } : {},
    });
}
const env = { DOKKEBI_CAPABILITY_SECRET: SECRET };

test('verifyCapability: 유효 토큰 통과 + stateHash 바인딩', async () => {
    const token = signCap({
        feature: 'image.generate', sid: 's1', stateHash: 'h1', sub: 'u1', role: 'premium',
        iat: Date.now(), exp: Date.now() + 10_000,
    });
    const ok = await verifyCapability(reqWith(token), env, 'image.generate', { stateHash: 'h1' });
    assert.equal(ok.ok, true);
    assert.equal(ok.payload.sub, 'u1');

    const mismatch = await verifyCapability(reqWith(token), env, 'image.generate', { stateHash: 'other' });
    assert.equal(mismatch.ok, false);
    assert.equal(mismatch.code, 'CAPABILITY_STATE_MISMATCH');
});

test('verifyCapability: feature 불일치 / 만료 / 서명 위조 / secret 누락 거부', async () => {
    const base = { feature: 'image.generate', sid: 's1', iat: Date.now(), exp: Date.now() + 10_000 };
    const wrongFeature = await verifyCapability(reqWith(signCap(base)), env, 'admin.export');
    assert.equal(wrongFeature.code, 'CAPABILITY_FEATURE_MISMATCH');

    const expired = await verifyCapability(reqWith(signCap({ ...base, exp: Date.now() - 1 })), env, 'image.generate');
    assert.equal(expired.code, 'CAPABILITY_EXPIRED');

    const noExp = await verifyCapability(reqWith(signCap({ feature: 'image.generate' })), env, 'image.generate');
    assert.equal(noExp.code, 'CAPABILITY_EXPIRED');

    const forged = await verifyCapability(reqWith(signCap(base, 'wrong-secret-0123456789abcdef0123456789')), env, 'image.generate');
    assert.equal(forged.code, 'CAPABILITY_BAD_SIGNATURE');

    const noSecret = await verifyCapability(reqWith(signCap(base)), {}, 'image.generate');
    assert.equal(noSecret.code, 'CAPABILITY_SECRET_MISSING');

    const noToken = await verifyCapability(reqWith(''), env, 'image.generate');
    assert.equal(noToken.code, 'CAPABILITY_MISSING');
});

test('verifyCapability: Authorization: Capability 헤더도 인정', async () => {
    const token = signCap({ feature: 'admin.export', exp: Date.now() + 5000 });
    const req = new Request('https://example.com/api/admin/export', {
        headers: { authorization: `Capability ${token}` },
    });
    assert.equal((await verifyCapability(req, env, 'admin.export')).ok, true);
});
