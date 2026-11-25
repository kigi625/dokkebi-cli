import test from 'node:test';
import assert from 'node:assert/strict';

import { normalizeCorsConfig, corsHeadersFor } from '../src/core/cors.js';

test('normalizeCorsConfig: 문자열 목록을 trim/filter 한다', () => {
    const cfg = normalizeCorsConfig({ cors: { allowedOrigins: [' https://a.example ', '', null, 'https://b.example'] } });
    assert.deepEqual(cfg.origins, ['https://a.example', 'https://b.example']);
});

test('corsHeadersFor: 설정이 없으면 기존처럼 *', () => {
    assert.equal(corsHeadersFor('https://evil.example', { origins: [] })['Access-Control-Allow-Origin'], '*');
    assert.equal(corsHeadersFor('', { origins: ['*'] })['Access-Control-Allow-Origin'], '*');
});

test('corsHeadersFor: 허용된 Origin 만 echo 하고 Vary 를 붙인다', () => {
    const cfg = { origins: ['https://app.example'] };
    const ok = corsHeadersFor('https://app.example', cfg);
    assert.equal(ok['Access-Control-Allow-Origin'], 'https://app.example');
    assert.equal(ok.Vary, 'Origin');

    const bad = corsHeadersFor('https://evil.example', cfg);
    assert.equal(bad['Access-Control-Allow-Origin'], undefined);
    assert.equal(bad.Vary, 'Origin');
});
