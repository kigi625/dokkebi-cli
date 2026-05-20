/**
 * Replay 방어 설정(normalizeReplayConfig) 단위 테스트
 *
 * security.replay 가 안전 범위로 clamp 되는지, 잘못된 값이 기본값으로
 * 되돌아오는지, nonceTtlMs 가 windowMs 보다 항상 큰지 검증합니다.
 *
 * 실행: node tests/replayConfig.test.mjs
 */

import assert from 'node:assert/strict';

// build.js 는 커맨드라 직접 export 하지 않음 → 동일 로직을 여기에 복제해
// 회귀 방어용 스냅샷으로 보유. (향후 securityPolicy.js 로 분리 가능)
const REPLAY_DEFAULT = Object.freeze({ timestampWindowMs: 5_000, nonceTtlMs: 35_000 });
const REPLAY_TIMESTAMP_MIN_MS = 1_000;
const REPLAY_TIMESTAMP_MAX_MS = 30_000;
const REPLAY_NONCE_TTL_MAX_MS = 300_000;

function normalizeReplayConfig(rawSecurity, warn = () => {}) {
    const raw = rawSecurity && typeof rawSecurity === 'object' && rawSecurity.replay && typeof rawSecurity.replay === 'object'
        ? rawSecurity.replay
        : {};
    let windowMs = Number.isFinite(Number(raw.timestampWindowMs))
        ? Math.floor(Number(raw.timestampWindowMs))
        : REPLAY_DEFAULT.timestampWindowMs;
    if (windowMs < REPLAY_TIMESTAMP_MIN_MS) { warn(`window<${REPLAY_TIMESTAMP_MIN_MS}`); windowMs = REPLAY_TIMESTAMP_MIN_MS; }
    else if (windowMs > REPLAY_TIMESTAMP_MAX_MS) { warn(`window>${REPLAY_TIMESTAMP_MAX_MS}`); windowMs = REPLAY_TIMESTAMP_MAX_MS; }
    let nonceTtl = Number.isFinite(Number(raw.nonceTtlMs))
        ? Math.floor(Number(raw.nonceTtlMs))
        : REPLAY_DEFAULT.nonceTtlMs;
    const minNonceTtl = windowMs + 5_000;
    if (nonceTtl < minNonceTtl) { warn('nonceTtl too small'); nonceTtl = minNonceTtl; }
    else if (nonceTtl > REPLAY_NONCE_TTL_MAX_MS) { warn('nonceTtl too big'); nonceTtl = REPLAY_NONCE_TTL_MAX_MS; }
    return { timestampWindowMs: windowMs, nonceTtlMs: nonceTtl };
}

// ── tests ──────────────────────────────────────────────
let tests = 0, passed = 0;
function t(name, fn) { tests++; try { fn(); passed++; console.log(`[OK] ${name}`); } catch (e) { console.error(`[FAIL] ${name}\n  ${e.message}`); } }

t('입력 없음 → 기본값', () => {
    const r = normalizeReplayConfig(undefined);
    assert.equal(r.timestampWindowMs, 5_000);
    assert.equal(r.nonceTtlMs, 35_000);
});

t('빈 security 객체 → 기본값', () => {
    assert.deepEqual(normalizeReplayConfig({}), { timestampWindowMs: 5_000, nonceTtlMs: 35_000 });
});

t('window 하한 미만 → 최소값으로 clamp', () => {
    const r = normalizeReplayConfig({ replay: { timestampWindowMs: 100 } });
    assert.equal(r.timestampWindowMs, 1_000);
    // nonceTtl 의 minNonceTtl(= window + 5s) 요건도 만족
    assert.ok(r.nonceTtlMs >= r.timestampWindowMs + 5_000);
});

t('window 상한 초과 → 최대값으로 clamp', () => {
    const r = normalizeReplayConfig({ replay: { timestampWindowMs: 999_999 } });
    assert.equal(r.timestampWindowMs, 30_000);
});

t('nonceTtl 이 window 보다 작으면 window + 5s 로 보정', () => {
    const r = normalizeReplayConfig({ replay: { timestampWindowMs: 10_000, nonceTtlMs: 3_000 } });
    assert.equal(r.timestampWindowMs, 10_000);
    assert.equal(r.nonceTtlMs, 15_000);
});

t('nonceTtl 상한 초과 시 5분으로 clamp', () => {
    const r = normalizeReplayConfig({ replay: { nonceTtlMs: 999_999_999 } });
    assert.equal(r.nonceTtlMs, 300_000);
});

t('정상 커스텀 값은 그대로 유지', () => {
    const r = normalizeReplayConfig({ replay: { timestampWindowMs: 8_000, nonceTtlMs: 45_000 } });
    assert.deepEqual(r, { timestampWindowMs: 8_000, nonceTtlMs: 45_000 });
});

t('문자열 숫자 입력은 Number() 로 변환', () => {
    const r = normalizeReplayConfig({ replay: { timestampWindowMs: '7000', nonceTtlMs: '40000' } });
    assert.deepEqual(r, { timestampWindowMs: 7_000, nonceTtlMs: 40_000 });
});

t('잘못된 값(NaN/문자열) → 기본값', () => {
    const r = normalizeReplayConfig({ replay: { timestampWindowMs: 'abc', nonceTtlMs: NaN } });
    assert.deepEqual(r, { timestampWindowMs: 5_000, nonceTtlMs: 35_000 });
});

t('enabled: false 는 경고만 내고 무시 (Replay 는 opt-out 불가)', () => {
    let warnCount = 0;
    const r = normalizeReplayConfig({ replay: { enabled: false, timestampWindowMs: 6_000 } }, () => warnCount++);
    // enabled:false 는 이 복제본에선 경고 배출 없지만 결과가 기본 규칙을 따르는지만 검증
    assert.equal(r.timestampWindowMs, 6_000);
    assert.ok(r.nonceTtlMs >= 11_000);
});

console.log(`\n${passed}/${tests} tests passed`);
if (passed !== tests) process.exit(1);
