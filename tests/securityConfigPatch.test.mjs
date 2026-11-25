import test from 'node:test';
import assert from 'node:assert/strict';

import { patchDokkebiConfigText } from '../src/core/securityConfigPatch.js';

test('patchDokkebiConfigText: logging.level 을 security.level 로 오인하지 않는다', () => {
    const text = `export default {\n  logging: { level: 'error' },\n  security: {\n    level: 'standard',\n  },\n  backend: {},\n};\n`;
    const baseline = { logging: { level: 'error' }, security: { level: 'standard' } };
    const draft = {
        logging: { level: 'error' },
        security: { level: 'strict', preset: 'production', cors: { allowedOrigins: ['https://a.example'] } },
    };
    const r = patchDokkebiConfigText(text, baseline, draft);
    assert.match(r.text, /logging: \{ level: 'error' \}/);
    assert.match(r.text, /security: \{/);
    assert.match(r.text, /preset: 'production'/);
    assert.match(r.text, /level: 'strict'/);
    assert.match(r.text, /allowedOrigins: \["https:\/\/a\.example"\]/);
    assert.deepEqual(r.warnings, []);
});

test('patchDokkebiConfigText: cors.allowedOrigins 배열을 교체한다', () => {
    const text = `export default {\n  security: {\n    cors: { allowedOrigins: ['https://old.example'] },\n  },\n};\n`;
    const baseline = { security: { cors: { allowedOrigins: ['https://old.example'] } } };
    const draft = { security: { cors: { allowedOrigins: ['https://new.example'] } } };
    const r = patchDokkebiConfigText(text, baseline, draft);
    assert.match(r.text, /https:\/\/new\.example/);
    assert.equal(r.text.includes('old.example'), false);
});
