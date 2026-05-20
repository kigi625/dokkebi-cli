import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isBundleEncryptEnabled } from '../src/core/buildWasm.js';

// 번들 암호화는 항상 강제 ON — config / env 로 끌 수 없다.

test('config false is ignored — always true', () => {
    assert.equal(isBundleEncryptEnabled(false, {}), true);
});

test('env off is ignored — always true', () => {
    assert.equal(isBundleEncryptEnabled(undefined, { DOKKEBI_BUNDLE_ENCRYPT: 'off' }), true);
    assert.equal(isBundleEncryptEnabled(undefined, { DOKKEBI_BUNDLE_ENCRYPT: '0' }), true);
});

test('config false + env on still true', () => {
    assert.equal(isBundleEncryptEnabled(false, { DOKKEBI_BUNDLE_ENCRYPT: 'on' }), true);
});

test('default (no args) is true', () => {
    assert.equal(isBundleEncryptEnabled(), true);
});

test('config true / env on are also true', () => {
    assert.equal(isBundleEncryptEnabled(true, {}), true);
    assert.equal(isBundleEncryptEnabled(undefined, { DOKKEBI_BUNDLE_ENCRYPT: 'on' }), true);
});
