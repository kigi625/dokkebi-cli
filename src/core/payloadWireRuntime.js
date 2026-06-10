/**
 * DB 봉투 내부 JSON — 필드명 회전(역매핑) + 경량 PoW 검증.
 * - Worker emit (TS 문자열 생성) 과 dev/serve 의 Node 경로에서 동일 알고리즘을 공유한다.
 */

import fs from 'fs/promises';
import path from 'path';
import { createHash } from 'crypto';

/** 회전 대상 (외부 공개 API 계약이 아닌 암호화 내부 페이로드 키만) */
export const PAYLOAD_FIELD_ROTATE_CANONICAL = [
    'queryId',
    'params',
    '_debugSql',
    '_setTenant',
    '_login',
    '_attest',
    '_capabilityUnlock',
    'sql',
    '_jwt',
];

/** @returns {ReturnType<typeof buildWireRuntimeJson>} */
const MAX_WIRE_PREVIOUS_FORWARDS = 5;

export function disabledWireRuntimeJson() {
    return {
        version: 1,
        rotation: { enabled: false, buildId: '', activeForward: {}, previousForward: null, previousForwards: [] },
        pow: { enabled: false, bits: 14 },
    };
}

/** @type {Map<string, { mtimeMs: number, json: ReturnType<typeof disabledWireRuntimeJson> }>} */
const _wireDistCache = new Map();

/**
 * dev/serve 로컬 DB 프록시: dist/dokkebi/wire-runtime.json 과 동일 설정 적용.
 * proxyMode !== 'serverless' 이면 항상 비활성(클라이언트가 정규 키 사용).
 * @param {string|null|undefined} distRoot
 * @param {string} proxyMode
 */
export async function loadWireRuntimeForLocalProxy(distRoot, proxyMode) {
    if (proxyMode !== 'serverless' || !distRoot) return disabledWireRuntimeJson();
    const filePath = path.join(distRoot, 'dokkebi', 'wire-runtime.json');
    try {
        const st = await fs.stat(filePath);
        const prev = _wireDistCache.get(filePath);
        if (prev && prev.mtimeMs === st.mtimeMs) return prev.json;
        const json = JSON.parse(await fs.readFile(filePath, 'utf-8'));
        _wireDistCache.set(filePath, { mtimeMs: st.mtimeMs, json });
        return json;
    } catch {
        return disabledWireRuntimeJson();
    }
}

/**
 * @param {{ rotate?: boolean, pow?: boolean }} flags
 * @param {{ enabled?: boolean, activeForward?: Record<string,string>, buildId?: string }|null} previousState
 * @param {string} buildId
 */
/** @param {unknown} previousState rotation-state.json | rotation-history entry | { previousForwards } */
export function collectPreviousForwards(previousState) {
    /** @type {Record<string, string>[]} */
    const list = [];
    const push = (m) => {
        if (!m || typeof m !== 'object' || !Object.keys(m).length) return;
        const key = JSON.stringify(m);
        if (list.some((x) => JSON.stringify(x) === key)) return;
        list.push({ ...m });
    };
    if (Array.isArray(previousState?.previousForwards)) {
        for (const m of previousState.previousForwards) push(m);
    }
    if (Array.isArray(previousState?.forwards)) {
        for (const entry of previousState.forwards) push(entry?.activeForward);
    }
    push(previousState?.activeForward);
    if (previousState?.enabled && previousState?.activeForward) push(previousState.activeForward);
    return list.slice(-MAX_WIRE_PREVIOUS_FORWARDS);
}

export function buildWireRuntimeJson(flags, previousState, buildId) {
    const rotation = {
        enabled: false,
        buildId: String(buildId || '').slice(0, 16),
        activeForward: {},
        previousForward: null,
        previousForwards: [],
    };
    const pow = { enabled: flags.pow !== false, bits: 14 };

    if (!flags.rotate) {
        return { version: 1, rotation, pow };
    }

    const activeForward = {};
    for (const canon of PAYLOAD_FIELD_ROTATE_CANONICAL) {
        activeForward[canon] = `_f${createHash('sha256').update(`${buildId}:${canon}`).digest('hex').slice(0, 20)}`;
    }
    rotation.enabled = true;
    rotation.activeForward = activeForward;
    const prevList = collectPreviousForwards(previousState);
    rotation.previousForwards = prevList;
    if (prevList.length > 0) {
        rotation.previousForward = { ...prevList[prevList.length - 1] };
    }

    return { version: 1, rotation, pow };
}

/** @param {Record<string, unknown>} body */
export function powPayloadRequired(body) {
    if (!body || typeof body !== 'object') return false;
    if (body._capabilityUnlock !== undefined) return true;
    const att = body._attest;
    if (att && typeof att === 'object' && att.request === true) return true;
    return false;
}

function _invertForward(forward) {
    if (!forward || typeof forward !== 'object') return null;
    /** @type {Record<string, string>} */
    const rev = {};
    for (const [c, a] of Object.entries(forward)) {
        if (typeof a === 'string' && a) rev[a] = c;
    }
    return rev;
}

/**
 * @param {Record<string, unknown>} body
 * @param {{ rotation?: { enabled?: boolean, activeForward?: Record<string,string>, previousForward?: Record<string,string>|null } }} wire
 */
function _canonFieldFromWireKey(k, activeR, previousForwards) {
    if (activeR && activeR[k]) return activeR[k];
    if (PAYLOAD_FIELD_ROTATE_CANONICAL.includes(k)) return k;
    const prevList = Array.isArray(previousForwards) ? previousForwards : [];
    for (let i = prevList.length - 1; i >= 0; i--) {
        const pr = _invertForward(prevList[i]);
        if (pr && pr[k]) return pr[k];
    }
    return k;
}

export function denormalizePayload(body, wire) {
    const rot = wire?.rotation;
    if (!rot?.enabled) return body;
    const activeR = _invertForward(rot.activeForward);
    const prevList = rot.previousForwards?.length
        ? rot.previousForwards
        : (rot.previousForward ? [rot.previousForward] : []);
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const k of Object.keys(body)) {
        const canon = _canonFieldFromWireKey(k, activeR, prevList);
        out[canon] = body[k];
    }
    return out;
}

function _leadingZeroBitsFromSha256Hex(hex) {
    const buf = Buffer.from(hex, 'hex');
    let bits = 0;
    for (let i = 0; i < buf.length; i++) {
        const b = buf[i];
        if (b === 0) {
            bits += 8;
            continue;
        }
        for (let j = 7; j >= 0; j--) {
            if ((b >> j) & 1) return bits;
            bits++;
        }
        return bits;
    }
    return bits;
}

/**
 * Node(crypto) 경로 — 클라이언트는 WebCrypto 로 동일 난이도를 맞춘다.
 * @param {string} stamp
 * @param {number} bits
 */
export function minePowNode(stamp, bits) {
    const want = Math.max(8, Math.min(22, Math.floor(Number(bits) || 14)));
    let c = 0;
    const max = 8_000_000;
    while (c < max) {
        const h = createHash('sha256').update(`${stamp}:${String(c)}`).digest('hex');
        if (_leadingZeroBitsFromSha256Hex(h) >= want) {
            return { stamp, bits: want, counter: c };
        }
        c++;
    }
    throw new Error(`[dokkebi] PoW mine failed (bits=${want})`);
}

/**
 * @param {unknown} obj
 * @param {string} sid
 * @param {{ pow?: { enabled?: boolean, bits?: number } }} wire
 */
export function verifyPow(obj, sid, wire) {
    if (!wire?.pow?.enabled) return true;
    if (!obj || typeof obj !== 'object') return false;
    const bits = Math.max(8, Math.min(22, Math.floor(Number(wire.pow.bits) || 14)));
    const stamp = obj.stamp;
    const c = obj.counter;
    if (typeof stamp !== 'string' || !stamp.startsWith(`${sid}:`)) return false;
    const parts = stamp.split(':');
    if (parts.length < 2) return false;
    const slot = Number(parts[1]);
    if (!Number.isFinite(slot)) return false;
    const nowSlot = Math.floor(Date.now() / 60_000);
    if (slot !== nowSlot && slot !== nowSlot - 1) return false;
    if (!Number.isFinite(c) || c < 0 || c > 20_000_000) return false;
    const h = createHash('sha256').update(`${stamp}:${String(c)}`).digest('hex');
    return _leadingZeroBitsFromSha256Hex(h) >= bits;
}

/**
 * @param {Record<string, unknown>} body
 * @param {string} sid
 * @param {{ rotation?: object, pow?: object }} wire
 * @returns {{ ok: boolean, body: Record<string, unknown>, error?: string }}
 */
export function verifyAndStripPow(body, sid, wire) {
    if (!powPayloadRequired(body)) return { ok: true, body };
    if (!wire?.pow?.enabled) return { ok: true, body };
    const powObj = body._pow;
    if (!powObj || typeof powObj !== 'object') {
        return { ok: false, body, error: 'PoW가 필요한 요청입니다 (_pow 누락).' };
    }
    if (!verifyPow(powObj, sid, wire)) {
        return { ok: false, body, error: 'PoW 검증 실패 (재시도하세요).' };
    }
    const next = { ...body };
    delete next._pow;
    return { ok: true, body: next };
}

/**
 * Worker / dev 에 넣을 TS 모듈 소스 생성.
 * @param {ReturnType<typeof buildWireRuntimeJson>} wire
 */
export function emitPayloadWireTs(wire) {
    const json = JSON.stringify(wire);
    // dok update 가 설치 버전을 추적하려면 첫 줄에 @dokkebi-version 필요 (commands/update.js WORKER_FILES 와 동기)
    return `// @dokkebi-version: 2
// @dokkebi-generated — payload wire (rotation + PoW). dok build 가 덮어씁니다.
export const WIRE_RUNTIME = ${json} as const;

/**
 * AES-GCM 출력 등 긴 바이너리 → base64.
 * String.fromCharCode에 전체 바이트를 spread 하면 인자 개수 한도로 스택이 터진다 (배치 DB 응답 등).
 */
export function encBytesToB64(input: ArrayBuffer | Uint8Array): string {
  const u8 = input instanceof Uint8Array ? input : new Uint8Array(input);
  const CHUNK = 8192;
  let bin = '';
  for (let i = 0; i < u8.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK) as unknown as number[]);
  }
  return btoa(bin);
}

function _invertForward(forward: Record<string, string> | null | undefined): Record<string, string> | null {
  if (!forward) return null;
  const rev: Record<string, string> = {};
  for (const [c, a] of Object.entries(forward)) {
    if (typeof a === 'string' && a) rev[a] = c;
  }
  return rev;
}

export function denormalizeDbPayload(body: Record<string, unknown>): Record<string, unknown> {
  const rot = (WIRE_RUNTIME as any).rotation;
  if (!rot?.enabled) return body;
  const activeR = _invertForward(rot.activeForward as Record<string, string>);
  const prevList: Record<string, string>[] = Array.isArray(rot.previousForwards) && rot.previousForwards.length
    ? rot.previousForwards
    : (rot.previousForward ? [rot.previousForward as Record<string, string>] : []);
  const _CANON = ${JSON.stringify(PAYLOAD_FIELD_ROTATE_CANONICAL)};
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(body)) {
    let canon = activeR && activeR[k];
    if (!canon && _CANON.indexOf(k) >= 0) canon = k;
    if (!canon) {
      for (let i = prevList.length - 1; i >= 0; i--) {
        const pr = _invertForward(prevList[i]);
        if (pr && pr[k]) { canon = pr[k]; break; }
      }
    }
    if (!canon) canon = k;
    out[canon] = body[k];
  }
  return out;
}

function _leadingZeroBitsHex(hex: string): number {
  const clean = hex.length % 2 === 1 ? '0' + hex : hex;
  const buf = new Uint8Array(clean.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
  let bits = 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b === 0) {
      bits += 8;
      continue;
    }
    for (let j = 7; j >= 0; j--) {
      if ((b >> j) & 1) return bits;
      bits++;
    }
    return bits;
  }
  return bits;
}

function _powRequired(p: Record<string, unknown>): boolean {
  if (p._capabilityUnlock !== undefined) return true;
  const att = p._attest as any;
  if (att && typeof att === 'object' && att.request === true) return true;
  return false;
}

export async function verifyAndStripPowDb(
  payload: Record<string, unknown>,
  sid: string,
): Promise<{ ok: true; payload: Record<string, unknown> } | { ok: false; error: string }> {
  const powCfg = (WIRE_RUNTIME as any).pow;
  if (!powCfg?.enabled || !_powRequired(payload)) return { ok: true, payload };
  const obj = payload._pow as any;
  if (!obj || typeof obj !== 'object') return { ok: false, error: 'PoW가 필요한 요청입니다 (_pow 누락).' };
  const bits = Math.max(8, Math.min(22, Math.floor(Number(powCfg.bits) || 14)));
  const stamp = String(obj.stamp || '');
  const c = Number(obj.counter);
  if (!stamp.startsWith(sid + ':')) return { ok: false, error: 'PoW stamp 불일치.' };
  const parts = stamp.split(':');
  if (parts.length < 2) return { ok: false, error: 'PoW stamp 형식 오류.' };
  const slot = Number(parts[1]);
  const nowSlot = Math.floor(Date.now() / 60_000);
  if (slot !== nowSlot && slot !== nowSlot - 1) return { ok: false, error: 'PoW stamp 만료.' };
  if (!Number.isFinite(c) || c < 0 || c > 20_000_000) return { ok: false, error: 'PoW counter 범위 오류.' };
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(stamp + ':' + String(c)));
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  if (_leadingZeroBitsHex(hex) < bits) return { ok: false, error: 'PoW 난이도 불충분.' };
  const next: Record<string, unknown> = { ...payload };
  delete next._pow;
  return { ok: true, payload: next };
}
`;
}
