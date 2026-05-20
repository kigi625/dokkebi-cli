/**
 * hardeningFlags 단위 테스트
 *
 * 실행: node tests/hardeningFlags.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { getHardeningFlags } from '../src/core/hardeningFlags.js';

test('기본: unset 이면 rotate·pow ON, allEnabled true', () => {
    const f = getHardeningFlags({});
    assert.equal(f.allEnabled, true);
    assert.equal(f.rotate, true);
    assert.equal(f.pow, true);
});

test('DOKKEBI_HARDENING=off 이면 전부 OFF', () => {
    const f = getHardeningFlags({ DOKKEBI_HARDENING: 'off' });
    assert.equal(f.allEnabled, false);
    assert.equal(f.rotate, false);
    assert.equal(f.pow, false);
});

test('DOKKEBI_HARDENING=off 는 개별 ON 을 덮어씀', () => {
    const f = getHardeningFlags({
        DOKKEBI_HARDENING: 'OFF',
        DOKKEBI_HARDENING_ROTATE: 'on',
        DOKKEBI_HARDENING_POW: 'true',
    });
    assert.equal(f.allEnabled, false);
    assert.equal(f.rotate, false);
    assert.equal(f.pow, false);
});

test('DOKKEBI_HARDENING_ROTATE=off 만 rotate OFF', () => {
    const f = getHardeningFlags({ DOKKEBI_HARDENING_ROTATE: 'off' });
    assert.equal(f.allEnabled, true);
    assert.equal(f.rotate, false);
    assert.equal(f.pow, true);
});

test('DOKKEBI_HARDENING_POW=0 만 pow OFF', () => {
    const f = getHardeningFlags({ DOKKEBI_HARDENING_POW: '0' });
    assert.equal(f.allEnabled, true);
    assert.equal(f.rotate, true);
    assert.equal(f.pow, false);
});

test('둘 다 개별 OFF', () => {
    const f = getHardeningFlags({
        DOKKEBI_HARDENING_ROTATE: 'false',
        DOKKEBI_HARDENING_POW: 'no',
    });
    assert.equal(f.rotate, false);
    assert.equal(f.pow, false);
});
