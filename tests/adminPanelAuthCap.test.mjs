/**
 * 관제 패널 로그인 시도 맵 상한 테스트
 *
 * 실행: node --test tests/adminPanelAuthCap.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { __authAttempts, __pruneAuthAttempts, __AUTH_ATTEMPTS_MAX } from '../src/core/adminPanel.js';

test('adminPanel: _authAttempts 맵은 상한 아래로 유지된다', () => {
    const now = Date.now();
    for (let i = 0; i < __AUTH_ATTEMPTS_MAX + 1000; i++) {
        __authAttempts.set('ip-' + i, { count: 1, resetAt: now + 60_000, lockedUntil: 0 });
    }
    __pruneAuthAttempts(now);
    assert.ok(__authAttempts.size <= Math.floor(__AUTH_ATTEMPTS_MAX * 0.8));
});
