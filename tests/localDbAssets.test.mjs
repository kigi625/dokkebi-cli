/**
 * sql.js 로컬 번들 / CDN SRI fallback 테스트 (4번)
 *
 * 실행: node --test tests/localDbAssets.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { copySqlJsAssets } from '../src/core/localDbAssets.js';
import { generateBootstrapScript } from '../src/core/opaqueHandle.js';
import { workerAdmin, workerAdminApi, workerMiddleware } from '../src/core/projectGenerator.js';

test('copySqlJsAssets: sql-wasm.js / .wasm 를 대상 디렉터리로 복사', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'dok-sqljs-'));
    try {
        const ok = await copySqlJsAssets(dir);
        assert.equal(ok, true);
        const js = await fs.stat(path.join(dir, 'sql-wasm.js'));
        const wasm = await fs.stat(path.join(dir, 'sql-wasm.wasm'));
        assert.ok(js.size > 1000);
        assert.ok(wasm.size > 1000);
    } finally {
        await fs.rm(dir, { recursive: true, force: true });
    }
});

test('bootstrap: 로컬 base 를 사용하고 CDN fallback 은 SRI 를 갖는다', () => {
    const html = generateBootstrapScript({ dbType: 'd1', localDbMode: true, sqljsBase: '/dokkebi/' });
    assert.match(html, /"\/dokkebi\/"/);
    assert.match(html, /sha384-1fHJox8K973mCCD3PTAOc0ljrAGXD2VeK8zf\+vNIdx55pWPULNlpxKMkU8bF4nUd/);
    assert.match(html, /cdn\.jsdelivr\.net\/npm\/sql\.js@1\.11\.0/);
});

test('bootstrap: sqljsBase 가 없으면 CDN 을 기본으로 사용', () => {
    const html = generateBootstrapScript({ dbType: 'd1', localDbMode: true });
    assert.match(html, /var _sqlBase = "" \|\| _SQLJS_CDN/);
});

test('admin panel: CSP / XFO 헤더 포함', () => {
    const src = workerAdmin('demo');
    assert.match(src, /frame-ancestors 'none'/);
    assert.match(src, /X-Frame-Options/);
    assert.match(src, /&quot;/, 'esc must escape quotes for attribute contexts');
});

test('admin panel: cross-origin ACAO 를 내보내지 않는다', () => {
    for (const src of [workerAdmin('demo'), workerAdminApi('demo')]) {
        assert.equal(src.includes('Access-Control-Allow-Origin'), false);
    }
});

test('middleware: 내부 경로를 substring 이 아니라 exact/prefix 로 제외한다', () => {
    const src = workerMiddleware();
    assert.match(src, /path === p \|\| path\.startsWith\(p \+ '\/'\)/);
    assert.equal(src.includes('path.includes(p)'), false);
});
