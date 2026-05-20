/**
 * dokkebi Guest-side Runtime
 *
 * QuickJS WASM 내부에서 실행되는 백엔드 API입니다.
 * WIT 인터페이스를 통해 Host(브라우저)와 통신합니다.
 *
 * 아키텍처:
 *   - router: Express 스타일 라우터 (MVC의 C 레이어)
 *   - ctx: 요청/응답 컨텍스트
 *   - db: dokkebi-dsl 연결 (Type-safe 쿼리)
 *   - middleware: 인증, 로깅, CORS 등
 *
 * 사용 예:
 *   import { router, db } from 'dokkebi:runtime';
 *   import { users } from '../models/index.js';
 *
 *   router.get('/users', async (ctx) => {
 *     const { rows } = await db.select(users).exec();
 *     return ctx.json(rows);
 *   });
 */

import { createDb } from 'dokkebi-dsl';

// ─────────────────────────────────────────────────────────────
// 에러 테이블 직접 SQL 실행용 (initRuntime에서 설정)
// ─────────────────────────────────────────────────────────────
let _rawExec = null;

// ─────────────────────────────────────────────────────────────
// 전역 Host 연결 (QuickJS에서 globalThis.__dokkebi_host__ 로 주입됨)
// ─────────────────────────────────────────────────────────────

function getHost() {
    const host = globalThis.__dokkebi_host__;
    if (!host) {
        throw new Error('[dokkebi:runtime] Host 함수가 주입되지 않았습니다. 초기화 순서를 확인하세요.');
    }
    return host;
}

// ─────────────────────────────────────────────────────────────
// WebCrypto Polyfill
//
// QuickJS WASM 런타임에는 표준 `globalThis.crypto` 가 주입되지 않는다.
// 따라서 Host 브리지로 노출된 `__dokkebi_host__.crypto` 를 이용해
// 표준 WebCrypto API 의 실용적인 서브셋을 자동 설치한다.
//
// 지원 범위:
//   - crypto.getRandomValues(typedArray)
//   - crypto.randomUUID()
//   - crypto.subtle.digest('SHA-256', data)
//   - crypto.subtle.importKey('raw', bytes, 'HMAC'|{name:'HMAC',hash:'SHA-256'}, ...)
//   - crypto.subtle.sign('HMAC', key, data)
//   - crypto.subtle.verify('HMAC', key, signature, data)
//
// 이 폴리필은 모듈 로드 즉시 실행되어 사용자 백엔드 코드가
// `crypto.xxx` 를 호출하더라도 `crypto is not defined` 가 발생하지 않도록 한다.
// ─────────────────────────────────────────────────────────────
(function installWebCryptoPolyfill() {
    if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
        return; // 런타임에 이미 제공되면 건드리지 않는다.
    }

    const TA_CTORS = [
        typeof Uint8Array        !== 'undefined' ? Uint8Array        : null,
        typeof Uint8ClampedArray !== 'undefined' ? Uint8ClampedArray : null,
        typeof Int8Array         !== 'undefined' ? Int8Array         : null,
        typeof Uint16Array       !== 'undefined' ? Uint16Array       : null,
        typeof Int16Array        !== 'undefined' ? Int16Array        : null,
        typeof Uint32Array       !== 'undefined' ? Uint32Array       : null,
        typeof Int32Array        !== 'undefined' ? Int32Array        : null,
        typeof BigUint64Array    !== 'undefined' ? BigUint64Array    : null,
        typeof BigInt64Array     !== 'undefined' ? BigInt64Array     : null,
    ].filter(Boolean);

    function hostCrypto() {
        const h = globalThis.__dokkebi_host__;
        return (h && h.crypto) ? h.crypto : null;
    }

    function toByteArray(data) {
        if (data instanceof ArrayBuffer) return Array.from(new Uint8Array(data));
        if (ArrayBuffer.isView(data)) {
            return Array.from(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
        }
        if (Array.isArray(data)) return data.map((v) => v & 0xff);
        throw new TypeError('BufferSource 가 필요합니다.');
    }

    function algoName(a) {
        if (typeof a === 'string') return a;
        if (a && typeof a === 'object' && typeof a.name === 'string') return a.name;
        return '';
    }

    function getRandomValues(out) {
        const isTA = out && TA_CTORS.some((T) => out instanceof T);
        if (!isTA) {
            throw new TypeError('crypto.getRandomValues: TypedArray 가 필요합니다.');
        }
        if (out.byteLength > 65536) {
            throw new Error('QuotaExceededError: 최대 65536 바이트까지 지원합니다.');
        }
        const view = new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
        const hc = hostCrypto();
        if (hc && typeof hc.randomBytes === 'function') {
            try {
                const parsed = _parseHostResult(hc.randomBytes(view.byteLength));
                if (Array.isArray(parsed) && parsed.length === view.byteLength) {
                    for (let i = 0; i < parsed.length; i++) view[i] = parsed[i] & 0xff;
                    return out;
                }
            } catch { /* 아래 폴백 사용 */ }
        }
        // 최후의 폴백: Math.random 기반 (암호학적으로 안전하지 않음, 경고 없이 사용)
        for (let i = 0; i < view.length; i++) view[i] = (Math.random() * 256) | 0;
        return out;
    }

    const HEX_TABLE = new Array(256);
    for (let i = 0; i < 256; i++) HEX_TABLE[i] = (i < 16 ? '0' : '') + i.toString(16);

    function randomUUID() {
        const b = new Uint8Array(16);
        getRandomValues(b);
        b[6] = (b[6] & 0x0f) | 0x40; // version 4
        b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
        return (
            HEX_TABLE[b[0]] + HEX_TABLE[b[1]] + HEX_TABLE[b[2]] + HEX_TABLE[b[3]] + '-' +
            HEX_TABLE[b[4]] + HEX_TABLE[b[5]] + '-' +
            HEX_TABLE[b[6]] + HEX_TABLE[b[7]] + '-' +
            HEX_TABLE[b[8]] + HEX_TABLE[b[9]] + '-' +
            HEX_TABLE[b[10]] + HEX_TABLE[b[11]] + HEX_TABLE[b[12]] +
            HEX_TABLE[b[13]] + HEX_TABLE[b[14]] + HEX_TABLE[b[15]]
        );
    }

    async function subtleDigest(algorithm, data) {
        const name = algoName(algorithm);
        if (name !== 'SHA-256') {
            throw new Error('crypto.subtle.digest: 현재 폴리필은 SHA-256 만 지원합니다. (요청: ' + name + ')');
        }
        const hc = hostCrypto();
        if (!hc || typeof hc.hashSha256 !== 'function') {
            throw new Error('crypto.subtle.digest: host.crypto.hashSha256 브리지가 없습니다. dokkebi-cli 를 업데이트하세요.');
        }
        const bytes = toByteArray(data);
        const result = await hc.hashSha256(bytes);
        const arr = _parseHostResult(result);
        return new Uint8Array(arr).buffer;
    }

    async function subtleImportKey(format, keyData, algorithm, extractable, usages) {
        if (format !== 'raw') {
            throw new Error("crypto.subtle.importKey 폴리필: 현재 'raw' 형식만 지원합니다.");
        }
        const name = algoName(algorithm);
        if (name !== 'HMAC') {
            throw new Error('crypto.subtle.importKey 폴리필: 현재 HMAC 만 지원합니다. (요청: ' + name + ')');
        }
        const hash = (typeof algorithm === 'object' && algorithm) ? algoName(algorithm.hash) : 'SHA-256';
        if (hash !== 'SHA-256') {
            throw new Error('crypto.subtle.importKey 폴리필: HMAC 은 SHA-256 만 지원합니다.');
        }
        return {
            type: 'secret',
            extractable: !!extractable,
            algorithm: { name: 'HMAC', hash: { name: 'SHA-256' } },
            usages: Array.isArray(usages) ? usages.slice() : [],
            __dokkebiPolyfilledKey: true,
            __rawBytes: toByteArray(keyData),
        };
    }

    async function subtleSign(algorithm, key, data) {
        const name = algoName(algorithm);
        if (name !== 'HMAC') {
            throw new Error('crypto.subtle.sign 폴리필: 현재 HMAC 만 지원합니다. (요청: ' + name + ')');
        }
        if (!key || !key.__dokkebiPolyfilledKey || !Array.isArray(key.__rawBytes)) {
            throw new Error('crypto.subtle.sign 폴리필: importKey 로 생성된 키가 필요합니다.');
        }
        const hc = hostCrypto();
        if (!hc || typeof hc.hmacSign !== 'function') {
            throw new Error('crypto.subtle.sign: host.crypto.hmacSign 브리지가 없습니다.');
        }
        const result = await hc.hmacSign(key.__rawBytes, toByteArray(data));
        const arr = _parseHostResult(result);
        return new Uint8Array(arr).buffer;
    }

    async function subtleVerify(algorithm, key, signature, data) {
        const expected = new Uint8Array(await subtleSign(algorithm, key, data));
        const provided = new Uint8Array(toByteArray(signature));
        if (expected.length !== provided.length) return false;
        let diff = 0;
        for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ provided[i];
        return diff === 0;
    }

    const subtle = {
        digest: subtleDigest,
        importKey: subtleImportKey,
        sign: subtleSign,
        verify: subtleVerify,
    };

    const cryptoObj = { getRandomValues, randomUUID, subtle };

    try {
        Object.defineProperty(globalThis, 'crypto', {
            value: cryptoObj,
            writable: false,
            configurable: true,
            enumerable: false,
        });
    } catch {
        globalThis.crypto = cryptoObj;
    }
})();

// ─────────────────────────────────────────────────────────────
// 컨텍스트 (ctx)
// ─────────────────────────────────────────────────────────────

class Context {
    constructor(request) {
        this.method = request.method;
        this.path = request.path;
        this.query = parseQueryString(request.query || '');
        // HTTP 헤더는 대소문자 구분 없음(case-insensitive) — 모두 소문자로 정규화
        this.headers = Object.fromEntries(
            (request.headers || []).map(([k, v]) => [k.toLowerCase(), v])
        );
        this.rawBody = request.body || '';

        // 파라미터 (라우터에서 주입)
        this.params = {};
    }

    /** JSON 본문 파싱 */
    get body() {
        if (this._parsedBody !== undefined) return this._parsedBody;
        try {
            this._parsedBody = this.rawBody ? JSON.parse(this.rawBody) : null;
        } catch {
            this._parsedBody = null;
        }
        return this._parsedBody;
    }

    // ── 응답 헬퍼 ──────────────────────────────────────────

    json(data, status = 200) {
        return _response(status, JSON.stringify(data), [
            ['Content-Type', 'application/json; charset=utf-8'],
        ]);
    }

    text(body, status = 200) {
        return _response(status, body, [['Content-Type', 'text/plain; charset=utf-8']]);
    }

    html(body, status = 200) {
        return _response(status, body, [['Content-Type', 'text/html; charset=utf-8']]);
    }

    status(code) {
        this._statusOverride = code;
        return this;
    }

    notFound(message = 'Not Found') {
        return this.json({ error: message }, 404);
    }

    unauthorized(message = 'Unauthorized') {
        return this.json({ error: message }, 401);
    }

    forbidden(message = 'Forbidden') {
        return this.json({ error: message }, 403);
    }

    badRequest(message = 'Bad Request') {
        return this.json({ error: message }, 400);
    }

    serverError(message = 'Internal Server Error') {
        return this.json({ error: message }, 500);
    }

    /** 헤더 설정 */
    header(name, value) {
        this._extraHeaders = this._extraHeaders || [];
        this._extraHeaders.push([name, value]);
        return this;
    }

    // ── Phase B — Sharding-aware DB API (단일 D1 호환 매핑) ──
    // 단일 D1 (`type:'d1'`):
    //   ctx.shardFor({k}) === ctx.global() === ctx.db() === 모듈의 `db`
    // 샤딩 (`type:'d1-sharded'`, 후속 PR):
    //   ctx.shardFor({user_id: '...'}) → 라우팅된 샤드 핸들
    //   ctx.global()                  → global DB 핸들 (있으면)
    //   ctx.fanout(fn, {concurrency}) → 모든 샤드에 fn 실행
    //   ctx.db()                      → 단일 D1: env.DB / 샤딩: 첫 샤드 + 워닝
    //
    // 본 단계 (B-2) 는 API 시그니처를 제공하고 모두 단일 핸들로 라우팅합니다.
    // 호스트 레이어가 multi-binding 을 지원하기 전까지는 의도적 동일 동작.

    /**
     * 샤드 키 객체로 단일 샤드 DB 핸들 반환.
     * @param {Record<string, string|number|bigint>} key
     * @returns {object} dokkebi-dsl QueryBuilder factory (ctx.db 와 동일 인터페이스)
     */
    shardFor(key) {
        const cfg = _shardConfigSnapshot();
        if (cfg && cfg.sharded && cfg.strategy && cfg.strategy.key) {
            const keyName = cfg.strategy.key;
            // 빌드 타임 검증 항목(B-4)이지만 런타임 가드도 추가:
            if (key && typeof key === 'object' && !(keyName in key)) {
                console.warn(`[dokkebi:shard] ctx.shardFor 호출에 strategy.key '${keyName}' 가 없습니다 — 키: ${JSON.stringify(Object.keys(key))}`);
            }
        }
        // B-2 단계: 모든 모드에서 단일 _db 반환. multi-handle 라우팅은 host 레이어 PR 에서 활성.
        if (!_db) throw new Error('[dokkebi:runtime] DB 가 초기화되지 않았습니다 (initRuntime 호출 누락).');
        return _db;
    }

    /**
     * 글로벌 DB 핸들 (사이드 카탈로그용). 단일 모드에서는 _db 와 동일.
     * @returns {object|null}
     */
    global() {
        const cfg = _shardConfigSnapshot();
        if (cfg && cfg.sharded && !cfg.global) return null;
        return _db || null;
    }

    /**
     * 모든 샤드에 동일 작업 실행 (관제·집계용 명시 API).
     * 단일 모드에서는 fn 한 번 호출.
     * @template R
     * @param {(db: object) => Promise<R>} fn
     * @param {{ concurrency?: number }} [opts]
     * @returns {Promise<R[]>}
     */
    async fanout(fn, opts) {
        if (typeof fn !== 'function') throw new TypeError('[dokkebi:fanout] fn 함수가 필요합니다.');
        if (!_db) throw new Error('[dokkebi:runtime] DB 가 초기화되지 않았습니다.');
        const cfg = _shardConfigSnapshot();
        const concurrency = Math.max(1, Math.min(8, Number(opts && opts.concurrency) || 8));
        // 단일 모드: 1개 핸들. 샤딩 모드 (후속 PR): cfg.shards.length 개 핸들 병렬 실행.
        const handles = (cfg && cfg.sharded && Array.isArray(cfg._handles) && cfg._handles.length > 0)
            ? cfg._handles
            : [_db];
        const out = new Array(handles.length);
        let i = 0;
        async function worker() {
            while (true) {
                const idx = i++;
                if (idx >= handles.length) return;
                out[idx] = await fn(handles[idx]);
            }
        }
        const workers = [];
        for (let w = 0; w < Math.min(concurrency, handles.length); w++) workers.push(worker());
        await Promise.all(workers);
        return out;
    }

    /**
     * 명시적 샤드 키 없이 호출하는 일반 DB 핸들.
     * 단일 D1: 모듈 `db` 와 동일.
     * 샤딩 모드: 첫 샤드 + 런타임 워닝 (`ctx.shardFor({...})` 사용 권장).
     */
    db() {
        const cfg = _shardConfigSnapshot();
        if (cfg && cfg.sharded) {
            console.warn('[dokkebi:shard] ctx.db() 는 샤딩 모드에서 첫 샤드로 라우팅됩니다. ctx.shardFor({key}) 사용을 권장합니다.');
        }
        if (!_db) throw new Error('[dokkebi:runtime] DB 가 초기화되지 않았습니다.');
        return _db;
    }
}

function _response(status, body, headers) {
    return { status, body, headers };
}

function parseQueryString(qs) {
    if (!qs) return {};
    return Object.fromEntries(
        qs.split('&').map((pair) => {
            const [k, v] = pair.split('=').map(decodeURIComponent);
            return [k, v ?? ''];
        })
    );
}

// ─────────────────────────────────────────────────────────────
// 미들웨어 시스템
// ─────────────────────────────────────────────────────────────

const _globalMiddlewares = [];

/** 전역 미들웨어 등록 */
export function use(fn) {
    _globalMiddlewares.push(fn);
}

async function runMiddlewares(ctx, middlewares) {
    for (const mw of middlewares) {
        const result = await mw(ctx);
        if (result) return result; // 미들웨어가 응답 반환 시 중단
    }
    return null;
}

// ─────────────────────────────────────────────────────────────
// 라우터
// ─────────────────────────────────────────────────────────────

class Router {
    constructor(prefix = '') {
        this._prefix = prefix;
        this._routes = [];
        this._middlewares = [];
    }

    _addRoute(method, path, ...handlers) {
        const fullPath = this._prefix + path;
        const guard = findCapabilityGuard(method.toUpperCase(), fullPath);
        const routeHandlers = guard ? [createCapabilityGuard(guard), ...handlers] : handlers;
        this._routes.push({
            method: method.toUpperCase(),
            pattern: fullPath,
            regex: pathToRegex(fullPath),
            paramNames: extractParamNames(fullPath),
            handlers: routeHandlers,
            middlewares: [...this._middlewares],
            capabilityGuard: guard || null,
        });
        return this;
    }

    get(path, ...handlers)    { return this._addRoute('GET',    path, ...handlers); }
    post(path, ...handlers)   { return this._addRoute('POST',   path, ...handlers); }
    put(path, ...handlers)    { return this._addRoute('PUT',    path, ...handlers); }
    patch(path, ...handlers)  { return this._addRoute('PATCH',  path, ...handlers); }
    delete(path, ...handlers) { return this._addRoute('DELETE', path, ...handlers); }

    /** 라우터 레벨 미들웨어 */
    use(fn) {
        this._middlewares.push(fn);
        return this;
    }

    /** 하위 라우터 마운트 */
    mount(prefix, subRouter) {
        for (const route of subRouter._routes) {
            const pattern = this._prefix + prefix + route.pattern.slice(subRouter._prefix.length);
            const guard = findCapabilityGuard(route.method, pattern) || route.capabilityGuard || null;
            const handlers = guard && !route.capabilityGuard
                ? [createCapabilityGuard(guard), ...route.handlers]
                : route.handlers;
            this._routes.push({
                ...route,
                pattern,
                regex: pathToRegex(pattern),
                paramNames: extractParamNames(pattern),
                handlers,
                capabilityGuard: guard,
            });
        }
        return this;
    }

    /** 라우트 목록 반환 */
    get routes() {
        return this._routes;
    }
}

/** 패스 → 정규식 변환 (/users/:id → /users/([^/]+)) */
function pathToRegex(pattern) {
    const escaped = pattern
        .replace(/\//g, '\\/')
        .replace(/:([a-zA-Z_][a-zA-Z0-9_]*)/g, '([^/]+)');
    return new RegExp(`^${escaped}$`);
}

/** 패스 파라미터 이름 추출 (:id → ['id']) */
function extractParamNames(pattern) {
    const names = [];
    const re = /:([a-zA-Z_][a-zA-Z0-9_]*)/g;
    let m;
    while ((m = re.exec(pattern))) names.push(m[1]);
    return names;
}

function findCapabilityGuard(method, path) {
    const cfg = globalThis.__dokkebi_capability_guards__;
    if (!cfg?.enabled || !Array.isArray(cfg.routes)) return null;
    const normalizedMethod = String(method || '').toUpperCase();
    const normalizedPath = String(path || '');
    for (const route of cfg.routes) {
        if (!route || !route.feature) continue;
        const guardMethod = String(route.method || '').toUpperCase();
        if (guardMethod !== '*' && guardMethod !== normalizedMethod) continue;
        if (String(route.path || '') !== normalizedPath) continue;
        return {
            method: normalizedMethod,
            path: normalizedPath,
            feature: String(route.feature),
            ttlMs: Number(route.ttlMs) || undefined,
        };
    }
    return null;
}

function createCapabilityGuard(guard) {
    return async (ctx) => {
        const authHeader = ctx.headers?.authorization || ctx.headers?.Authorization || '';
        const jwt = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
        const unlocked = await capability.unlock(guard.feature, {
            jwt,
            ttlMs: guard.ttlMs,
            state: {
                method: ctx.method,
                path: ctx.path,
                params: ctx.params || {},
                query: ctx.query || {},
            },
        });
        if (!unlocked?.ok) {
            const status = unlocked?.code === 'UNAUTHORIZED' ? 401 : 403;
            return ctx.json({
                error: unlocked?.error || 'Capability unlock failed',
                code: unlocked?.code || 'CAPABILITY_DENIED',
                feature: guard.feature,
            }, status);
        }
        ctx.capability = unlocked.capability || unlocked;
        return null;
    };
}

// ─────────────────────────────────────────────────────────────
// 빌트인 미들웨어
// ─────────────────────────────────────────────────────────────

/**
 * CORS 미들웨어
 * @param {object} opts - { origin, methods, headers }
 */
export function cors(opts = {}) {
    const origin = opts.origin || '*';
    const methods = opts.methods || 'GET, POST, PUT, DELETE, OPTIONS';
    const allowedHeaders = opts.headers || 'Content-Type, Authorization';

    return (ctx) => {
        ctx.header('Access-Control-Allow-Origin', origin);
        ctx.header('Access-Control-Allow-Methods', methods);
        ctx.header('Access-Control-Allow-Headers', allowedHeaders);
        if (ctx.method === 'OPTIONS') {
            return ctx.text('', 204);
        }
        return null;
    };
}

/**
 * 요청 로거 미들웨어
 */
export function logger() {
    return (ctx) => {
        const start = Date.now();
        console.log(`[dokkebi] → ${ctx.method} ${ctx.path}`);
        // 응답 후처리는 핸들러에서 진행됨
        return null;
    };
}

/**
 * JWT 인증 미들웨어
 * @param {string} secret - JWT 서명 비밀키
 * @param {string[]} excludePaths - 인증 제외 경로
 */
export function jwtAuth(secret, excludePaths = []) {
    return async (ctx) => {
        if (excludePaths.some((p) => ctx.path.startsWith(p))) return null;

        const authHeader = ctx.headers['authorization'] || ctx.headers['Authorization'];
        if (!authHeader?.startsWith('Bearer ')) {
            return ctx.unauthorized('인증 토큰이 필요합니다.');
        }

        const token = authHeader.slice(7);
        try {
            ctx.user = await verifyJwt(token, secret);
            return null;
        } catch (e) {
            return ctx.unauthorized('유효하지 않은 토큰: ' + e.message);
        }
    };
}

// ─────────────────────────────────────────────────────────────
// JWT 유틸리티 (Host crypto 사용)
// ─────────────────────────────────────────────────────────────

function base64urlEncode(bytes) {
    const b64 = btoa(String.fromCharCode(...bytes));
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlDecode(str) {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    return atob(padded);
}

/**
 * JWT 서명 생성
 * @param {object} payload  - JWT 페이로드
 * @param {string} secret   - 비밀키
 * @param {number} [expiresIn=3600] - 유효기간(초)
 */
export async function signJwt(payload, secret, expiresIn = 3600) {
    const host = getHost();
    const header = { alg: 'HS256', typ: 'JWT' };
    // nowMillis 반환값은 JSON 문자열 또는 숫자일 수 있음
    const nowRaw = host.crypto.nowMillis();
    const now = Math.floor(Number(_parseHostResult(nowRaw)) / 1000);

    const fullPayload = { ...payload, iat: now, exp: now + expiresIn };
    const headerB64 = base64urlEncode(
        Array.from(new TextEncoder().encode(JSON.stringify(header)))
    );
    const payloadB64 = base64urlEncode(
        Array.from(new TextEncoder().encode(JSON.stringify(fullPayload)))
    );
    const signingInput = `${headerB64}.${payloadB64}`;
    const keyBytes = Array.from(new TextEncoder().encode(secret));
    const dataBytes = Array.from(new TextEncoder().encode(signingInput));
    // hmacSign은 JSON 문자열 "[1,2,...]" 또는 배열로 반환될 수 있음
    const sigRaw = await host.crypto.hmacSign(keyBytes, dataBytes);
    const sigB64 = base64urlEncode(_parseHostResult(sigRaw));
    return `${signingInput}.${sigB64}`;
}

/**
 * JWT 검증
 * @param {string} token   - JWT 토큰
 * @param {string} secret  - 비밀키
 * @returns {object} 페이로드
 */
export async function verifyJwt(token, secret) {
    const host = getHost();
    const [headerB64, payloadB64, sigB64] = token.split('.');
    if (!headerB64 || !payloadB64 || !sigB64) {
        throw new Error('잘못된 JWT 형식');
    }

    const signingInput = `${headerB64}.${payloadB64}`;
    const keyBytes = Array.from(new TextEncoder().encode(secret));
    const dataBytes = Array.from(new TextEncoder().encode(signingInput));
    const expectedSigRaw = await host.crypto.hmacSign(keyBytes, dataBytes);
    const expectedB64 = base64urlEncode(_parseHostResult(expectedSigRaw));

    if (expectedB64 !== sigB64) {
        throw new Error('서명 검증 실패');
    }

    const payload = JSON.parse(base64urlDecode(payloadB64));
    const nowRaw = host.crypto.nowMillis();
    const now = Math.floor(Number(_parseHostResult(nowRaw)) / 1000);
    if (payload.exp && payload.exp < now) {
        throw new Error('토큰 만료됨');
    }
    return payload;
}

// ─────────────────────────────────────────────────────────────
// 런타임 싱글톤 + 초기화
// ─────────────────────────────────────────────────────────────

const _router = new Router();
let _db = null;
let _dbHandle = null;
let _initialized = false;
let _blockRaw = false;

// ── Phase B — Sharding 런타임 상태 ────────────────────────────
// initRuntime({ shardConfig }) 으로 주입. 단일 D1 모드에서는 sharded:false 또는 null.
// 샤딩 모드 (후속 PR):  { sharded:true, strategy:{key,hash}, shards:[...], global:{...}, _handles:[Db,...] }
let _shardConfig = null;
function _shardConfigSnapshot() { return _shardConfig; }
/** 결정적 fnv1a 32-bit hash — shardConfig.hashString('fnv1a') 와 100% 일치. */
export function _shardHashFnv1a(input) {
    const s = String(input);
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    return h >>> 0;
}
/**
 * 샤드 키 → shard index. Phase A 의 shardConfig.shardForKey 와 동일 알고리즘.
 * @param {string|number|bigint} keyValue
 * @param {object} cfg shard config (sharded=true 가정)
 */
export function _shardIndexForKey(keyValue, cfg) {
    if (!cfg || !cfg.sharded || !cfg.strategy) return 0;
    const buckets = (cfg.strategy.virtualBuckets || (cfg.shards || []).length) >>> 0;
    if (buckets === 0) return 0;
    // B-2 는 fnv1a 만 동기 지원. sha1/sha256 은 SubtleCrypto 비동기 (B-3+에서 제공).
    const h = _shardHashFnv1a(String(keyValue));
    const bucket = h % buckets;
    const total = (cfg.shards || []).length || 1;
    return bucket % total;
}

// ─────────────────────────────────────────────────────────────
// 보안 설정
// ─────────────────────────────────────────────────────────────

/**
 * db.raw() 호출을 차단합니다.
 * dokkebi.config.js에서 security.blockRaw: true 설정 시 자동 호출됩니다.
 */
export function blockRawSql() {
    _blockRaw = true;
}

/**
 * 세션에 인증된 사용자 정보를 바인딩합니다.
 * 로그인 성공 후 호출하면, 이후 요청에서 ctx.user 정보가
 * 서버 측 DB 프록시 세션에 바인딩되어 RLS(Row-Level Security) 효과를 냅니다.
 *
 * @param {{ userId: string, role?: string }} userInfo
 * @returns {Promise<boolean>}
 */
export async function bindSession(userInfo) {
    if (!userInfo?.userId) return false;
    const host = getHost();
    try {
        const result = await host.db.dbExecute(
            _dbHandle,
            '__DOKKEBI_BIND_SESSION__',
            [userInfo.userId, userInfo.role || 'user']
        );
        return true;
    } catch { return false; }
}

export const capability = {
    async unlock(feature, opts = {}) {
        const host = getHost();
        if (!host.capability || typeof host.capability.unlock !== 'function') {
            return { ok: false, code: 'CAPABILITY_UNAVAILABLE', error: 'capability host bridge가 없습니다.' };
        }
        const raw = await host.capability.unlock(String(feature || ''), opts || {});
        return _parseHostResult(raw);
    },
};

/**
 * 호스트 함수 반환값 정규화
 * QJS 호스트 함수는 JSON 문자열로 반환하므로 파싱이 필요합니다.
 */
function _parseHostResult(raw) {
    if (typeof raw === 'string') {
        try { return JSON.parse(raw); } catch { return raw; }
    }
    return raw;
}

/**
 * 런타임 초기화 (Host에서 호출)
 * @param {object} opts - { dbHandle, dbType, shardConfig? }
 *   - dbHandle: 단일 핸들 (단일 D1 모드, 또는 샤딩 모드의 첫 샤드)
 *   - shardConfig: 선택. shardConfig.normalizeDatabaseConfig 결과 + (선택) _handles 배열.
 *                 미주입(undefined/null) 시 단일 D1 모드로 간주.
 */
export function initRuntime({ dbHandle, dbType, shardConfig }) {
    _dbHandle = dbHandle;
    _shardConfig = shardConfig && typeof shardConfig === 'object' ? shardConfig : null;
    const host = getHost();

    // dokkebi-dsl에 연결되는 실행 함수
    // host.db.dbExecute는 JSON 문자열을 반환하므로 파싱 후 반환
    // 브라우저 부트스트랩: SELECT 로 시작하는 SQL 은 네트워크 직렬 큐 없이 전송되므로
    // 여러 _execSql(SELECT…) 가 동시에 in-flight 될 수 있음 (쓰기·WITH 등은 직렬).
    //
    // ⚠️ 주의: params 는 dokkebi-dsl 의 normalizeBind 에서 이미
    // null / number / string / boolean / ISO 문자열로 정규화된 상태이므로
    // 절대 .map(String) 으로 강제 문자열화하지 말 것.
    // (그렇게 하면 null 이 "null" 문자열이 되어 SQL NULL 이 깨진다.)
    const runtimeContext = {
        _execSql: async (sql, params) => {
            const safeParams = Array.isArray(params) ? params : [];
            const raw = await host.db.dbExecute(dbHandle, sql, safeParams);
            return _parseHostResult(raw);
        },
    };

    _rawExec = runtimeContext._execSql;
    _db = createDb(runtimeContext);
    if (_blockRaw && _db) _db._rawBlocked = true;
    _initialized = true;

    // _dokkebi_errors 에러 테이블 자동 생성 (실패해도 무시)
    _rawExec(
        `CREATE TABLE IF NOT EXISTS "_dokkebi_errors" (
            "id"      TEXT NOT NULL PRIMARY KEY,
            "ts"      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            "source"  TEXT NOT NULL DEFAULT 'wasm',
            "level"   TEXT NOT NULL DEFAULT 'error',
            "message" TEXT NOT NULL,
            "stack"   TEXT,
            "path"    TEXT,
            "method"  TEXT,
            "context" TEXT
        )`,
        []
    ).catch(() => {});

    return true;
}

// ─────────────────────────────────────────────────────────────
// 요청 처리 진입점 (WIT export: guest-router.handle-request)
// ─────────────────────────────────────────────────────────────

/**
 * dokkebi 요청 디스패처
 * Host(브라우저)에서 이 함수를 호출합니다.
 *
 * @param {object} request - WIT DokkebiRequest
 * @returns {object} WIT DokkebiResponse
 */
export async function handleRequest(request) {
    const ctx = new Context(request);
    const _reqStart = Date.now();

    let finalRes;
    try {
        // 전역 미들웨어 실행
        const mwResult = await runMiddlewares(ctx, _globalMiddlewares);
        if (mwResult) { finalRes = finalizeResponse(mwResult, ctx); }
        else {
            // 라우트 매칭
            let matched = false;
            for (const route of _router.routes) {
                if (route.method !== ctx.method && route.method !== '*') continue;

                const match = ctx.path.match(route.regex);
                if (!match) continue;
                matched = true;

                // URL 파라미터 주입
                route.paramNames.forEach((name, i) => {
                    ctx.params[name] = decodeURIComponent(match[i + 1]);
                });

                // 라우트 레벨 미들웨어
                const routeMwResult = await runMiddlewares(ctx, route.middlewares);
                if (routeMwResult) { finalRes = finalizeResponse(routeMwResult, ctx); break; }

                // 핸들러 실행 (마지막 핸들러가 응답 반환)
                let response = null;
                for (const handler of route.handlers) {
                    response = await handler(ctx);
                    if (response) break;
                }

                if (response) { finalRes = finalizeResponse(response, ctx); break; }
            }

            if (!finalRes) {
                const nfRes = ctx.notFound(`경로를 찾을 수 없습니다: ${ctx.method} ${ctx.path}`);
                // 라우트가 아예 등록되지 않은 경우 → 호스트(브라우저) fetch 인터셉터가
                // 실제 네트워크(예: Cloudflare Pages Functions) 로 폴스루할 수 있도록
                // 마커 헤더를 부착한다. 한 번이라도 매칭된 라우트가 있었다면 WASM 이
                // 의도적으로 404 를 낸 것이므로 폴스루하지 않는다.
                if (!matched) {
                    nfRes.headers = [...(nfRes.headers || []), ['X-Dokkebi-Route', 'miss']];
                }
                finalRes = finalizeResponse(nfRes, matched ? undefined : ctx);
            }
        }
    } catch (e) {
        console.error('[dokkebi:runtime] 처리 오류:', e);

        // _dokkebi_errors 테이블에 자동 저장 (실패해도 앱 동작에 영향 없음)
        if (_rawExec) {
            try {
                const errId = Math.random().toString(36).slice(2) + Date.now().toString(36);
                const errTs = new Date().toISOString().replace('T', ' ').slice(0, 19);
                const msg   = (e && e.message ? e.message : String(e)).slice(0, 1000);
                const stack = (e && e.stack   ? e.stack   : '').slice(0, 2000);
                _rawExec(
                    `INSERT OR IGNORE INTO "_dokkebi_errors" ("id","ts","source","level","message","stack","path","method") VALUES (?,?,?,?,?,?,?,?)`,
                    [errId, errTs, 'wasm', 'error', msg, stack, ctx.path, ctx.method]
                ).catch(() => {});
            } catch { /* 에러 로깅 실패 무시 */ }
        }

        finalRes = finalizeResponse(ctx.serverError('서버 내부 오류가 발생했습니다.'), ctx);
    }

    // 모든 요청에 대해 완료 로그 출력 (CLI가 파싱해서 _dokkebi_requests 에 기록)
    const duration = Date.now() - _reqStart;
    console.info(`${ctx.method} ${ctx.path} → ${finalRes.status} (${duration}ms)`);

    return finalRes;
}

function finalizeResponse(res, ctx) {
    const headers = [...(res.headers || [])];
    if (ctx._extraHeaders) {
        headers.push(...ctx._extraHeaders);
    }
    return { status: res.status, body: res.body || '', headers };
}

// ─────────────────────────────────────────────────────────────
// OPFS 데이터 파이프라인 (청크 기반 대용량 I/O)
// QuickJS 라우트 핸들러에서 OPFS 파일을 청크 단위로 읽고 쓸 수 있습니다.
// ─────────────────────────────────────────────────────────────

export const opfs = {
    /**
     * OPFS 파일에서 청크 읽기 (base64 반환)
     * @param {string} path - OPFS 파일 경로
     * @param {number} offset - 시작 바이트 오프셋
     * @param {number} length - 읽을 바이트 수
     * @returns {Promise<string>} base64 인코딩된 청크
     */
    async readChunk(path, offset, length) {
        const host = getHost();
        const raw = await host.opfs.readChunk(path, offset, length);
        return _parseHostResult(raw);
    },

    /**
     * OPFS 파일에 청크 쓰기
     * @param {string} path - OPFS 파일 경로
     * @param {number} offset - 쓸 바이트 오프셋
     * @param {string} base64Data - base64 인코딩된 데이터
     */
    async writeChunk(path, offset, base64Data) {
        const host = getHost();
        await host.opfs.writeChunk(path, offset, base64Data);
    },

    /**
     * OPFS 파일 메타데이터 조회
     * @param {string} path - OPFS 파일 경로
     * @returns {Promise<{size: number, lastModified: number} | null>}
     */
    async stat(path) {
        const host = getHost();
        const raw = await host.opfs.stat(path);
        return _parseHostResult(raw);
    },

    /**
     * OPFS 파일 삭제
     * @param {string} path - OPFS 파일 경로
     */
    async remove(path) {
        const host = getHost();
        await host.opfs.remove(path);
    },

    /**
     * OPFS 디렉토리 재귀 삭제
     * @param {string} dirPath - 삭제할 디렉토리 경로
     */
    async removeDir(dirPath) {
        const host = getHost();
        await host.opfs.removeDir(dirPath);
    },

    /**
     * OPFS 디렉토리 파일 목록 조회
     * @param {string} [dirPath=''] - 조회할 디렉토리 경로
     * @returns {Promise<string[]>}
     */
    async list(dirPath) {
        const host = getHost();
        const raw = await host.opfs.list(dirPath || '');
        return _parseHostResult(raw);
    },

    /**
     * OPFS 파일을 청크 단위로 순회 처리하는 헬퍼
     * @param {string} path - OPFS 파일 경로
     * @param {number} chunkSize - 청크 크기 (기본 1MB)
     * @param {function} callback - (base64Chunk, offset, totalSize) => Promise
     */
    async processChunks(path, chunkSize, callback) {
        const info = await this.stat(path);
        if (!info || !info.size) return;
        const size = info.size;
        const cs = chunkSize || (1024 * 1024);
        let offset = 0;
        while (offset < size) {
            const chunk = await this.readChunk(path, offset, cs);
            await callback(chunk, offset, size);
            offset += cs;
        }
    },

    /**
     * 청크 단위 처리 후 원본+결과 파일 자동 정리
     * @param {string} inputPath - 입력 파일 경로
     * @param {string} outputPath - 출력 파일 경로
     * @param {number} chunkSize - 청크 크기 (기본 1MB)
     * @param {function} transform - (base64Chunk, offset, totalSize) => Promise<string|null>
     *   base64 청크를 받아 변환된 base64 반환, null 반환 시 해당 청크 건너뜀
     * @param {object} [opts] - { keepInput: false, keepOutput: false }
     * @returns {Promise<{outputPath: string, inputSize: number, outputSize: number}>}
     */
    async processAndCleanup(inputPath, outputPath, chunkSize, transform, opts) {
        const info = await this.stat(inputPath);
        if (!info || !info.size) throw new Error('Input file not found: ' + inputPath);
        const size = info.size;
        const cs = chunkSize || (1024 * 1024);
        let offset = 0;
        let outOffset = 0;

        while (offset < size) {
            const chunk = await this.readChunk(inputPath, offset, cs);
            const result = await transform(chunk, offset, size);
            if (result) {
                await this.writeChunk(outputPath, outOffset, result);
                const decoded = atob(result);
                outOffset += decoded.length;
            }
            offset += cs;
        }

        const outInfo = await this.stat(outputPath);
        const o = opts || {};
        if (!o.keepInput) { try { await this.remove(inputPath); } catch {} }

        return {
            outputPath: outputPath,
            inputSize: size,
            outputSize: outInfo ? outInfo.size : outOffset,
        };
    },

    /**
     * 지정 디렉토리 내 모든 파일 정리 (임시 데이터 삭제)
     * @param {string} dirPath - 정리할 디렉토리 경로
     */
    async cleanup(dirPath) {
        try { await this.removeDir(dirPath); } catch {}
    },
};

// ─────────────────────────────────────────────────────────────
// 플러그인 API: ai (플러그인 활성화 시에만 동작)
// ─────────────────────────────────────────────────────────────

export const ai = {
    async complete(opts) {
        const host = getHost();
        if (!host.ai) throw new Error('[dokkebi:ai] ai 플러그인이 활성화되지 않았습니다. dokkebi.config.js에서 plugins.ai.enabled: true 를 설정하세요.');
        const raw = await host.ai.aiComplete(
            opts.model || 'claude-sonnet-4-20250514',
            opts.system || '',
            JSON.stringify(opts.messages || []),
            opts.maxTokens || 4096,
            opts.temperature ?? 0.7
        );
        return _parseHostResult(raw);
    },

    streamStart(opts) {
        const host = getHost();
        if (!host.ai) throw new Error('[dokkebi:ai] ai 플러그인이 활성화되지 않았습니다.');
        const raw = host.ai.aiStreamStart(
            opts.model || 'claude-sonnet-4-20250514',
            opts.system || '',
            JSON.stringify(opts.messages || []),
            opts.maxTokens || 4096,
            opts.temperature ?? 0.7,
            opts.thinkingBudget || 0
        );
        const parsed = _parseHostResult(raw);
        if (!parsed.ok) throw new Error(parsed.error);
        return parsed.value;
    },

    streamPoll(streamId) {
        const host = getHost();
        if (!host.ai) throw new Error('[dokkebi:ai] ai 플러그인이 활성화되지 않았습니다.');
        const raw = host.ai.aiStreamPoll(streamId);
        const parsed = _parseHostResult(raw);
        if (!parsed.ok) throw new Error(parsed.error);
        return parsed.value;
    },

    streamCancel(streamId) {
        const host = getHost();
        if (!host.ai) return;
        host.ai.aiStreamCancel(streamId);
    },
};

// ─────────────────────────────────────────────────────────────
// 플러그인 API: httpFetch (플러그인 활성화 시에만 동작)
// ─────────────────────────────────────────────────────────────

export const httpFetch = {
    async request(url, opts = {}) {
        const host = getHost();
        if (!host.fetch) throw new Error('[dokkebi:fetch] fetch 플러그인이 활성화되지 않았습니다. dokkebi.config.js에서 plugins.fetch를 설정하세요.');
        const raw = await host.fetch.httpFetch(url, JSON.stringify({
            method: opts.method || 'GET',
            headers: opts.headers ? Object.entries(opts.headers) : [],
            body: opts.body || null,
            timeoutMs: opts.timeoutMs || null,
        }));
        return _parseHostResult(raw);
    },

    async get(url, headers) {
        return this.request(url, { method: 'GET', headers });
    },

    async post(url, body, headers) {
        return this.request(url, {
            method: 'POST',
            body: typeof body === 'string' ? body : JSON.stringify(body),
            headers: { 'Content-Type': 'application/json; charset=utf-8', ...(headers || {}) },
        });
    },
};

// ─────────────────────────────────────────────────────────────
// 플러그인 API: bundle (플러그인 활성화 시에만 동작)
// ─────────────────────────────────────────────────────────────

export const bundle = {
    async build(projectRoot, opts = {}) {
        const host = getHost();
        if (!host.bundle) throw new Error('[dokkebi:bundle] bundle 플러그인이 활성화되지 않았습니다.');
        const raw = await host.bundle.bundleBuild(projectRoot, JSON.stringify(opts));
        return _parseHostResult(raw);
    },

    generateImportMap(dependencies) {
        const host = getHost();
        if (!host.bundle) throw new Error('[dokkebi:bundle] bundle 플러그인이 활성화되지 않았습니다.');
        const result = host.bundle.generateImportMap(
            Array.isArray(dependencies) ? dependencies : Object.entries(dependencies)
        );
        return _parseHostResult(result);
    },
};

// ─────────────────────────────────────────────────────────────
// 공개 exports
// ─────────────────────────────────────────────────────────────

/**
 * 같은 WASM 요청 안에서 서로 독립적인 읽기 전용 DB 작업을 한꺼번에 기다립니다 (Promise.all).
 * 순수 SELECT 는 부트스트랩이 네트워크 직렬 큐를 쓰지 않으므로, 이 헬퍼 없이도
 * `const p1 = db.select(...).exec(); const p2 = db.select(...).exec(); await Promise.all([p1,p2])`
 * 처럼 직접 동시에 호출해도 병렬 전송됩니다. 이 함수는 의도 표현·배열 정리용입니다.
 * @param {Promise<any>[]} promises - exec() 등으로 만든 Promise 배열
 */
export function parallelReads(promises) {
    return Promise.all(promises);
}

export { _router as router };
export { _db as db };
export { Context };

// QuickJS 글로벌에 진입점 등록
// (Host가 __dokkebi_handle_request__ 를 호출함)
if (typeof globalThis !== 'undefined') {
    globalThis.__dokkebi_handle_request__ = async (reqJson) => {
        const req = JSON.parse(reqJson);
        const res = await handleRequest(req);
        return JSON.stringify(res);
    };

    globalThis.__dokkebi_init__ = (dbHandle, dbType, shardConfigJson) => {
        let shardConfig = null;
        if (shardConfigJson) {
            try {
                shardConfig = typeof shardConfigJson === 'string' ? JSON.parse(shardConfigJson) : shardConfigJson;
            } catch { shardConfig = null; }
        }
        return JSON.stringify(initRuntime({ dbHandle, dbType, shardConfig }));
    };
}
