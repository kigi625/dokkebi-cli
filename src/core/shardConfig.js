/**
 * Sharding 설정 정규화·검증 (Phase A).
 *
 * `dokkebi.config.js` 의 `database` 객체에서 다음 필드를 받습니다:
 *
 *   database: {
 *     type: 'd1' | 'd1-sharded',
 *     // 단일 D1 (type='d1')
 *     accountId, databaseId, apiToken, apiBase,
 *     binding,                       // 선택. 기본 'DB'
 *     sessions: true | { mode: 'first-unconstrained' | 'first-primary' },
 *
 *     // 샤딩 (type='d1-sharded')
 *     shards: [{ id, binding, databaseId?, databaseName? }, ...],
 *     strategy: { kind: 'hash', key: 'user_id', hash: 'fnv1a' },
 *     global: { binding, databaseId?, databaseName? },  // 선택
 *   }
 *
 * 런타임은 별도 PR. 본 모듈은 **CLI(provision/migrate)** 와 **문서/검증** 에서
 * 재사용합니다.
 */

/** @typedef {{ id: string, binding: string, databaseId?: string, databaseName?: string }} ShardEntry */
/** @typedef {{ kind: 'hash', key: string, hash?: 'fnv1a' | 'sha1' | 'sha256', virtualBuckets?: number }} ShardStrategy */
/** @typedef {{
 *   type: 'd1' | 'd1-sharded',
 *   sharded: boolean,
 *   binding: string,
 *   sessions: { enabled: boolean, mode: 'first-unconstrained' | 'first-primary' },
 *   shards: ShardEntry[],
 *   strategy: ShardStrategy | null,
 *   global: ShardEntry | null,
 * }} NormalizedDb */

const VALID_HASH = new Set(['fnv1a', 'sha1', 'sha256']);

/**
 * @param {unknown} raw
 * @returns {{ ok: true, value: NormalizedDb } | { ok: false, errors: string[] }}
 */
export function normalizeDatabaseConfig(raw) {
    const errors = [];
    if (!raw || typeof raw !== 'object') {
        return { ok: false, errors: ['database: 설정이 비어있습니다'] };
    }

    const db = /** @type {Record<string, unknown>} */ (raw);
    const type = String(db.type || 'd1');
    const sharded = type === 'd1-sharded';

    // sessions 옵션 (단일/샤딩 둘 다)
    const sess = db.sessions;
    let sessions = { enabled: false, mode: /** @type {'first-unconstrained' | 'first-primary'} */ ('first-unconstrained') };
    if (sess === true) sessions.enabled = true;
    else if (sess && typeof sess === 'object') {
        sessions.enabled = /** @type {{enabled?: unknown}} */ (sess).enabled !== false;
        const m = /** @type {{mode?: unknown}} */ (sess).mode;
        if (m === 'first-primary') sessions.mode = 'first-primary';
    }

    /** @type {ShardEntry[]} */
    let shards = [];
    /** @type {ShardStrategy | null} */
    let strategy = null;
    /** @type {ShardEntry | null} */
    let globalEntry = null;
    let binding = String(db.binding || 'DB');

    if (sharded) {
        const rawShards = Array.isArray(db.shards) ? db.shards : [];
        if (rawShards.length < 2) {
            errors.push('database.shards: 샤딩 모드는 최소 2개의 샤드가 필요합니다');
        }
        const seenId = new Set();
        const seenBinding = new Set();
        rawShards.forEach((s, i) => {
            if (!s || typeof s !== 'object') {
                errors.push(`database.shards[${i}]: 객체여야 합니다`);
                return;
            }
            const id = String(/** @type {{id?: unknown}} */ (s).id || '').trim();
            const b = String(/** @type {{binding?: unknown}} */ (s).binding || '').trim();
            if (!id) errors.push(`database.shards[${i}].id 누락`);
            if (!b) errors.push(`database.shards[${i}].binding 누락 (예: 'DB_S0')`);
            if (id && seenId.has(id)) errors.push(`database.shards[${i}].id 중복: ${id}`);
            if (b && seenBinding.has(b)) errors.push(`database.shards[${i}].binding 중복: ${b}`);
            seenId.add(id);
            seenBinding.add(b);
            shards.push({
                id,
                binding: b,
                databaseId: optString(s, 'databaseId'),
                databaseName: optString(s, 'databaseName'),
            });
        });

        const strat = db.strategy;
        if (!strat || typeof strat !== 'object') {
            errors.push("database.strategy 가 필요합니다 (예: { kind: 'hash', key: 'user_id' })");
        } else {
            const kind = String(/** @type {{kind?: unknown}} */ (strat).kind || '');
            const key = String(/** @type {{key?: unknown}} */ (strat).key || '').trim();
            const hash = String(/** @type {{hash?: unknown}} */ (strat).hash || 'fnv1a');
            const vb = /** @type {{virtualBuckets?: unknown}} */ (strat).virtualBuckets;
            if (kind !== 'hash') {
                errors.push(`database.strategy.kind: 현재 'hash' 만 지원합니다 (받음: '${kind}')`);
            }
            if (!key) errors.push('database.strategy.key 가 필요합니다 (샤드 키 컬럼명, 예: user_id)');
            if (!VALID_HASH.has(hash)) errors.push(`database.strategy.hash: '${hash}' 미지원 (fnv1a | sha1 | sha256)`);
            const virtualBuckets = typeof vb === 'number' && Number.isFinite(vb) ? Math.floor(vb) : undefined;
            if (virtualBuckets !== undefined && (virtualBuckets < shards.length || virtualBuckets > 4096)) {
                errors.push(`database.strategy.virtualBuckets: shards.length(${shards.length}) ~ 4096 사이여야 합니다`);
            }
            if (errors.length === 0) {
                strategy = { kind: 'hash', key, hash: /** @type {any} */ (hash), ...(virtualBuckets ? { virtualBuckets } : {}) };
            }
        }

        const g = db.global;
        if (g && typeof g === 'object') {
            const id = String(/** @type {{id?: unknown}} */ (g).id || 'global').trim();
            const b = String(/** @type {{binding?: unknown}} */ (g).binding || '').trim();
            if (!b) errors.push("database.global.binding 누락 (예: 'DB_GLOBAL')");
            globalEntry = {
                id,
                binding: b,
                databaseId: optString(g, 'databaseId'),
                databaseName: optString(g, 'databaseName'),
            };
        }

        binding = ''; // 샤딩 모드는 단일 binding 사용 안 함
    }

    if (errors.length > 0) return { ok: false, errors };

    return {
        ok: true,
        value: { type: /** @type {any} */ (type), sharded, binding, sessions, shards, strategy, global: globalEntry },
    };
}

/**
 * @param {unknown} obj
 * @param {string} key
 */
function optString(obj, key) {
    if (!obj || typeof obj !== 'object') return undefined;
    const v = /** @type {Record<string, unknown>} */ (obj)[key];
    if (v == null) return undefined;
    const s = String(v).trim();
    return s || undefined;
}

/**
 * deterministic hash → shard index. fnv1a 기본(빠름·결정적·런타임/CLI 동일).
 *
 * @param {string} keyValue
 * @param {NormalizedDb} db
 * @returns {{ shardId: string, binding: string, index: number, bucket: number } | null}
 */
export function shardForKey(keyValue, db) {
    if (!db.sharded || db.shards.length === 0 || !db.strategy) return null;
    const algo = db.strategy.hash || 'fnv1a';
    const buckets = db.strategy.virtualBuckets || db.shards.length;
    const h = hashString(String(keyValue), algo);
    const bucket = h % buckets;
    const index = bucket % db.shards.length;
    const s = db.shards[index];
    return { shardId: s.id, binding: s.binding, index, bucket };
}

/**
 * @param {string} input
 * @param {'fnv1a' | 'sha1' | 'sha256'} algo
 * @returns {number} unsigned 32-bit
 */
export function hashString(input, algo) {
    const s = String(input);
    if (algo === 'fnv1a') {
        let h = 0x811c9dc5;
        for (let i = 0; i < s.length; i++) {
            h ^= s.charCodeAt(i);
            h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
        }
        return h >>> 0;
    }
    // sha1/sha256 — Node only (CLI 컨텍스트). 런타임은 SubtleCrypto로 별도 구현.
    const crypto = /** @type {any} */ (globalThis).require ? null : null; // eslint-disable-line no-unused-vars
    // dynamic import via top-level — keep CLI-only path simple
    // (정상 호출: import('crypto') 이후 사용. 본 함수는 CLI 동기 경로에서만 sha 사용)
    throw new Error(`hashString: ${algo} 는 CLI 동기 경로에서 미지원 — fnv1a 사용 또는 별도 구현 필요`);
}

/**
 * Phase B-4 정합성 검증.
 *
 * 사용자가 dokkebi.config.js 에 샤딩(`type:'d1-sharded'`) 을 켜두고도 정책 엔진의
 * `sessionClaim` 을 다른 컬럼으로 두면 **샤드 격리와 정책 격리가 불일치** 합니다.
 * 빌드 타임에 워닝(strict 모드면 에러) 으로 표면화합니다.
 *
 * @param {NormalizedDb} db          - normalizeDatabaseConfig 결과
 * @param {object|null}  policyCfg   - dokkebi.config.js .policy
 * @param {object}       opts        - { strict?:boolean }
 * @returns {{ warnings: string[], errors: string[] }}
 */
export function verifyShardConsistency(db, policyCfg = null, opts = {}) {
    const warnings = [];
    const errors = [];
    if (!db || !db.sharded) return { warnings, errors }; // 단일 D1 — 검증 무관
    const strict = !!opts.strict || !!(policyCfg && policyCfg.strict === true);
    const stratKey = db.strategy && db.strategy.key;
    if (!stratKey) {
        errors.push("database.strategy.key 가 비어있습니다 — 샤딩 모드는 라우팅 키가 필수입니다.");
        return { warnings, errors };
    }
    const tables = (policyCfg && policyCfg.tables) || {};
    for (const tname of Object.keys(tables)) {
        const t = tables[tname] || {};
        if (t.scope === 'shared' || t.scope === 'global') continue; // 샤드 격리 대상 아님
        const claim = t.sessionClaim || t.tenantColumn;
        if (!claim) continue; // 정의 안 된 테이블은 정책 엔진이 별도 처리
        if (claim !== stratKey) {
            const msg = `policy.tables.${tname}.sessionClaim='${claim}' ≠ strategy.key='${stratKey}' — 샤드 격리와 정책 격리가 어긋납니다.`;
            if (strict) errors.push(msg);
            else warnings.push(msg);
        }
    }
    if (db.sessions && !db.sessions.enabled) {
        warnings.push("database.sessions.enabled=false — 샤딩 모드에서 read replica 효과를 얻으려면 sessions: true 권장.");
    }
    return { warnings, errors };
}

/**
 * 런타임/문서용으로 사용하기 좋은 요약.
 * @param {NormalizedDb} db
 */
export function summarizeShardConfig(db) {
    if (!db.sharded) {
        return `single D1 (binding=${db.binding})${db.sessions.enabled ? ', sessions=on' : ''}`;
    }
    const key = db.strategy?.key || '?';
    const hash = db.strategy?.hash || 'fnv1a';
    const vb = db.strategy?.virtualBuckets ? `, vbuckets=${db.strategy.virtualBuckets}` : '';
    return `sharded ${db.shards.length} (key=${key}, hash=${hash}${vb})${db.global ? ' + global' : ''}${db.sessions.enabled ? ', sessions=on' : ''}`;
}
