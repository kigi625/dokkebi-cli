import test from 'node:test';
import assert from 'node:assert/strict';

import { sanitizeLogText, sanitizeLogTag } from '../src/core/logSanitize.js';

test('sanitizeLogText: ANSI/OSC/제어문자/개행을 제거한다', () => {
    const out = sanitizeLogText('hi\u001b[31mred\u001b[0m\u001b]52;c;ZXZpbA==\u0007\n[dokkebi] fake');
    assert.equal(out.includes('\u001b'), false);
    assert.equal(out.includes('\n'), false);
    assert.equal(out.includes('fake'), true);
});

test('sanitizeLogText: 길이를 제한한다', () => {
    assert.equal(sanitizeLogText('x'.repeat(100), 10).length, 10);
});

test('sanitizeLogTag: 안전한 문자만 남긴다', () => {
    assert.equal(sanitizeLogTag('wasm\u001b[31m\n[admin]'), 'wasm31madmin');
    assert.equal(sanitizeLogTag(''), 'log');
});
