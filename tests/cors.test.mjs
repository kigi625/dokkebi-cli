import test from 'node:test';
import assert from 'node:assert/strict';

import { normalizeCorsConfig, corsHeadersFor, deriveCorsOrigins, resolveCorsConfig } from '../src/core/cors.js';

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

test('deriveCorsOrigins: 배포 도메인과 pages.dev 를 유도한다', () => {
    const origins = deriveCorsOrigins({
        deploy: {
            cloudflarePages: { domain: 'app.example.com' },
            cloudflare: { project: 'myapp' },
            r2: { domain: 'https://cdn.example.com/' },
        },
    });
    assert.deepEqual(origins, [
        'https://app.example.com',
        'https://cdn.example.com',
        'https://myapp.pages.dev',
    ]);
});

test('resolveCorsConfig: 수동 설정이 있으면 자동 유도를 하지 않는다', () => {
    const manual = resolveCorsConfig(
        { cors: { allowedOrigins: ['https://only.example'] } },
        { deploy: { cloudflare: { project: 'myapp' } } },
    );
    assert.deepEqual(manual.origins, ['https://only.example']);
    assert.deepEqual(manual.derived, []);
});

test('resolveCorsConfig: auto=false 면 유도하지 않는다', () => {
    const off = resolveCorsConfig(
        { cors: { auto: false } },
        { deploy: { cloudflare: { project: 'myapp' } } },
    );
    assert.deepEqual(off.origins, []);
});
