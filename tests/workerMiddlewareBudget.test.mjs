/**
 * 미들웨어 요청 로그 폭주 방어 테스트
 *
 *   middleware.ts.tpl 을 esbuild 로 변환해 내부 함수를 직접 호출한다.
 *   - 고유 경로 폭주 시 isolate 단위 쓰기 예산(600/min)으로 제한
 *   - _reqDedup 맵 하드 캡
 *
 * 실행: node --test tests/workerMiddlewareBudget.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

async function loadMiddlewareInternals() {
    const tplPath = path.resolve('src/templates/worker/middleware.ts.tpl');
    const source = await fs.readFile(tplPath, 'utf-8')
        + '\nexport { _shouldWriteReqLog, _takeErrLogToken, _pruneReqDedup, _reqDedup, _REQ_DEDUP_MAX, _REQ_LOG_MAX_PER_MIN, _ERR_LOG_MAX_PER_MIN };\n';
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'dokkebi-mw-'));
    const tsPath = path.join(dir, 'middleware.ts');
    await fs.writeFile(tsPath, source, 'utf-8');
    const out = await build({
        entryPoints: [tsPath],
        bundle: true,
        format: 'esm',
        target: 'es2022',
        platform: 'neutral',
        write: false,
    });
    const jsPath = path.join(dir, 'middleware.mjs');
    await fs.writeFile(jsPath, out.outputFiles[0].text, 'utf-8');
    return import(pathToFileURL(jsPath).href);
}

test('미들웨어: 고유 경로 폭주는 분당 예산으로 제한', async () => {
    const mw = await loadMiddlewareInternals();
    const now = Date.now();
    let written = 0;
    for (let i = 0; i < mw._REQ_LOG_MAX_PER_MIN + 5; i++) {
        if (mw._shouldWriteReqLog('GET', '/api/flood/' + i, 200, '203.0.113.7', now)) written++;
    }
    assert.equal(written, mw._REQ_LOG_MAX_PER_MIN);
    assert.equal(mw._shouldWriteReqLog('GET', '/api/flood/another', 200, '203.0.113.7', now), false);
});

test('미들웨어: 동일 요청은 TTL 내 중복 기록하지 않음 (예산도 소모하지 않음)', async () => {
    const mw = await loadMiddlewareInternals();
    const now = Date.now();
    assert.equal(mw._shouldWriteReqLog('GET', '/api/same', 200, '203.0.113.8', now), true);
    assert.equal(mw._shouldWriteReqLog('GET', '/api/same', 200, '203.0.113.8', now + 1000), false);
    // 남은 예산으로 다른 경로는 계속 기록 가능
    assert.equal(mw._shouldWriteReqLog('GET', '/api/other', 200, '203.0.113.8', now + 1000), true);
});

test('미들웨어: dedup 맵은 하드 캡 아래로 유지', async () => {
    const mw = await loadMiddlewareInternals();
    for (let i = 0; i < mw._REQ_DEDUP_MAX + 500; i++) {
        mw._reqDedup.set('k' + i, Date.now() + 10_000);
    }
    mw._pruneReqDedup(Date.now());
    assert.ok(mw._reqDedup.size <= Math.floor(mw._REQ_DEDUP_MAX * 0.8));
});

test('미들웨어: 5xx 오류 로그도 분당 예산으로 제한', async () => {
    const mw = await loadMiddlewareInternals();
    const now = Date.now();
    let ok = 0;
    for (let i = 0; i < mw._ERR_LOG_MAX_PER_MIN + 3; i++) {
        if (mw._takeErrLogToken(now)) ok++;
    }
    assert.equal(ok, mw._ERR_LOG_MAX_PER_MIN);
});
