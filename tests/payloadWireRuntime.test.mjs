/**
 * node tests/payloadWireRuntime.test.mjs
 */
import assert from 'assert';
import {
    buildWireRuntimeJson,
    denormalizePayload,
    disabledWireRuntimeJson,
    minePowNode,
    verifyAndStripPow,
    verifyPow,
} from '../src/core/payloadWireRuntime.js';
import { getHardeningFlags } from '../src/core/hardeningFlags.js';

function test(name, fn) {
    try {
        fn();
        console.log(`[OK] ${name}`);
    } catch (e) {
        console.error(`[FAIL] ${name}`, e);
        process.exitCode = 1;
    }
}

test('master off → wire has pow off', () => {
    const f = getHardeningFlags({ DOKKEBI_HARDENING: 'off' });
    const w = buildWireRuntimeJson(f, null, 'abc');
    assert.strictEqual(w.pow.enabled, false);
    assert.strictEqual(w.rotation.enabled, false);
});

test('denormalize no-op when rotation off', () => {
    const w = disabledWireRuntimeJson();
    const body = { queryId: 'x', _fabc: 'should stay' };
    assert.strictEqual(denormalizePayload(body, w), body);
});

test('denormalize activeForward', () => {
    const flags = { rotate: true, pow: true };
    const w = buildWireRuntimeJson(flags, null, 'build1111111111');
    const alias = w.rotation.activeForward.queryId;
    const enc = { [alias]: 'q1', params: [] };
    const out = denormalizePayload(enc, w);
    assert.strictEqual(out.queryId, 'q1');
    assert.deepStrictEqual(out.params, []);
});

test('denormalize previousForwards chain (multi-deploy)', () => {
    const flags = { rotate: true, pow: true };
    const w1 = buildWireRuntimeJson(flags, null, 'build0000000001');
    const w2 = buildWireRuntimeJson(flags, w1.rotation, 'build0000000002');
    const w3 = buildWireRuntimeJson(flags, w2.rotation, 'build0000000003');
    const oldAlias = w1.rotation.activeForward.queryId;
    const enc = { [oldAlias]: 'q-old', params: [] };
    const out = denormalizePayload(enc, w3);
    assert.strictEqual(out.queryId, 'q-old');
});

test('denormalize accepts canonical keys from skipWire client', () => {
    const flags = { rotate: true, pow: true };
    const w = buildWireRuntimeJson(flags, null, 'build2222222222');
    const out = denormalizePayload({ queryId: 'q1', params: [], _debugSql: 'SELECT 1' }, w);
    assert.strictEqual(out.queryId, 'q1');
    assert.strictEqual(out._debugSql, 'SELECT 1');
});

test('PoW mine + verify + strip', () => {
    const wire = { pow: { enabled: true, bits: 10 } };
    const sid = 'a'.repeat(32);
    const stamp = `${sid}:${Math.floor(Date.now() / 60_000)}`;
    const mined = minePowNode(stamp, 10);
    const body = { _capabilityUnlock: { x: 1 }, _pow: mined };
    assert.strictEqual(verifyPow(mined, sid, wire), true);
    const r = verifyAndStripPow(body, sid, wire);
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.body._pow, undefined);
    assert.deepStrictEqual(r.body._capabilityUnlock, { x: 1 });
});

test('PoW not required for plain query', () => {
    const wire = { pow: { enabled: true, bits: 14 } };
    const r = verifyAndStripPow({ queryId: 'x', params: [] }, 'sid', wire);
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.body._pow, undefined);
});
