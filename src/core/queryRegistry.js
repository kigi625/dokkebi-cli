// @dokkebi-module: queryRegistry
// ──────────────────────────────────────────────────────────────
// Query Registry (Stage 3) — 빌드 타임 쿼리 수집 + canonicalize + hash
//
// 설계 문서: docs/design/QUERY_REGISTRY.md
//
// 역할:
//   1) DSL 이 만들어내는 모든 SQL shape 를 빌드 타임에 수집
//   2) SQL 문자열을 canonical 형태로 정규화 후 SHA-256 으로 queryId 산출
//   3) `{ queryId → { sql, meta } }` 레지스트리를 JSON 으로 직렬화
//   4) Pages Function 에 임베드 가능한 형태로 제공
//
// 수집 방법 (v1):
//   A) 정적 추출 (1차) — backend 모듈에서 export 된 레지스트리 선언 읽기
//   B) Dry-run (2차, 향후) — backend bundle 을 샌드박스 실행해 자동 수집
//
// 현재 버전은 A + `sql-allowlist.json` 추출 메타를 교차 참고해
// 개발자가 명시적으로 선언하거나 DSL 로 작성한 쿼리를 등록합니다.
// dev 모드에서는 런타임 자동 학습 으로 누락 shape 를 보완합니다.
// ──────────────────────────────────────────────────────────────

import fs from 'fs/promises';
import path from 'path';
import { createHash } from 'crypto';

export const REGISTRY_VERSION = 1;

// ─────────────────────────────────────────────────────────────
// Canonicalize — SQL 문자열을 shape 비교 가능한 형태로 정규화
// ─────────────────────────────────────────────────────────────

/**
 * 주석과 리터럴을 canonical 형태로 정규화합니다.
 *
 * - `-- ... \n` 라인 주석 제거
 * - `/* ... *\/` 블록 주석 제거
 * - `'...'` 문자열 리터럴 → `?` (파라미터로 수렴)
 * - `"..."` / `` `...` `` 식별자 quote → 내용과 따옴표 모두 보존
 *   (SQLite/D1 은 `"col"` 을 식별자로 취급 — shape 비교 시 식별자는 동일해야 함)
 */
function stripStringsAndComments(sql) {
    let out = '';
    let i = 0;
    const n = sql.length;
    while (i < n) {
        const ch = sql[i];
        const next = sql[i + 1];

        if (ch === '-' && next === '-') {
            while (i < n && sql[i] !== '\n') i++;
            out += ' ';
            continue;
        }
        if (ch === '/' && next === '*') {
            i += 2;
            while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i++;
            i += 2;
            out += ' ';
            continue;
        }
        if (ch === "'") {
            out += '?';
            i++;
            while (i < n) {
                if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; }
                if (sql[i] === "'") { i++; break; }
                i++;
            }
            continue;
        }
        if (ch === '"') {
            out += '"';
            i++;
            while (i < n) {
                if (sql[i] === '"' && sql[i + 1] === '"') { out += '""'; i += 2; continue; }
                if (sql[i] === '"') { out += '"'; i++; break; }
                out += sql[i];
                i++;
            }
            continue;
        }
        if (ch === '`') {
            out += '`';
            i++;
            while (i < n) {
                if (sql[i] === '`') { out += '`'; i++; break; }
                out += sql[i];
                i++;
            }
            continue;
        }
        out += ch;
        i++;
    }
    return out;
}

const KEYWORDS = [
    'SELECT', 'FROM', 'WHERE', 'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET',
    'DELETE', 'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'OFFSET', 'JOIN', 'LEFT',
    'RIGHT', 'INNER', 'OUTER', 'CROSS', 'ON', 'AND', 'OR', 'NOT', 'NULL',
    'IS', 'IN', 'BETWEEN', 'LIKE', 'AS', 'ASC', 'DESC', 'CREATE', 'TABLE',
    'IF', 'EXISTS', 'PRIMARY', 'KEY', 'UNIQUE', 'FOREIGN', 'REFERENCES',
    'RETURNING', 'WITH', 'RECURSIVE', 'UNION', 'ALL', 'DISTINCT',
];
const KEYWORD_RE = new RegExp(
    '\\b(' + KEYWORDS.join('|') + ')\\b', 'gi'
);

/**
 * Canonical SQL 생성.
 * - 주석/문자열 제거 (리터럴은 `?` 로 수렴)
 * - 키워드 대문자화
 * - 공백 정규화
 * - 식별자(`"col"`, `"table"`) 대소문자는 보존 (D1/SQLite 구분)
 *
 * DSL 에서 파라미터는 이미 `?` placeholder 로 나오므로 safe.
 */
export function canonicalizeSql(sql) {
    if (typeof sql !== 'string') return '';
    let s = stripStringsAndComments(sql);
    s = s.replace(/\s+/g, ' ').trim();
    s = s.replace(KEYWORD_RE, (m) => m.toUpperCase());
    s = s.replace(/\s*,\s*/g, ', ');
    s = s.replace(/\s*\(\s*/g, ' (').replace(/\s*\)\s*/g, ') ');
    s = s.replace(/\s+/g, ' ').trim();
    // IN (?, ?, ...) → IN (?) : 파라미터 개수와 무관하게 동일 queryId 생성
    s = s.replace(/\bIN \(\?(?:, \?)*\)/g, 'IN (?)');
    return s;
}

/**
 * Canonical SQL 에서 SHA-256 prefix(16자리) 기반 queryId 생성.
 * 형태: `q_<16 hex>`  (총 18자 — 네트워크 오버헤드 최소)
 */
export function computeQueryId(sql) {
    const canonical = canonicalizeSql(sql);
    const hash = createHash('sha256').update(canonical, 'utf-8').digest('hex');
    return 'q_' + hash.slice(0, 16);
}

// ─────────────────────────────────────────────────────────────
// 쿼리 shape 분석 (primary op / tables / param 수)
// ─────────────────────────────────────────────────────────────

/** canonical SQL 에서 주 연산을 판별 (SELECT/INSERT/UPDATE/DELETE/CREATE/...) */
export function detectOp(canonicalSql) {
    const upper = canonicalSql.toUpperCase().trimStart();
    if (upper.startsWith('WITH ')) {
        const m = upper.match(/\)\s*(SELECT|INSERT|UPDATE|DELETE)\b/);
        return m ? m[1] : null;
    }
    const m = upper.match(/^(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b/);
    return m ? m[1] : null;
}

/** 쿼리에서 언급된 모든 테이블(이중따옴표/일반 식별자) 추출 */
export function extractTables(canonicalSql) {
    const upper = canonicalSql.toUpperCase();
    const tables = new Set();
    const patterns = [
        /\bFROM\s+"?([a-zA-Z_][\w]*)"?/g,
        /\bJOIN\s+"?([a-zA-Z_][\w]*)"?/g,
        /\bINTO\s+"?([a-zA-Z_][\w]*)"?/g,
        /\bUPDATE\s+"?([a-zA-Z_][\w]*)"?/g,
    ];
    for (const re of patterns) {
        let m;
        while ((m = re.exec(upper)) !== null) {
            tables.add(m[1].toLowerCase());
        }
    }
    return [...tables];
}

/** `?` 파라미터 개수 */
export function countParams(canonicalSql) {
    const m = canonicalSql.match(/\?/g);
    return m ? m.length : 0;
}

// ─────────────────────────────────────────────────────────────
// Registry 엔트리 생성
// ─────────────────────────────────────────────────────────────

/**
 * dev/learn 병합 시 canonical DDL 과 혼동되어 `DEFAULT ?` 로 저장된 문장 복구.
 * SQLite 는 CREATE TABLE 의 DEFAULT 절에 바인딩(`?`)을 허용하지 않음 → D1 syntax error.
 */
const REPAIR_DOKKEBI_ERRORS_DDL = 'CREATE TABLE IF NOT EXISTS "_dokkebi_errors" ("id" TEXT NOT NULL PRIMARY KEY, "ts" TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, "source" TEXT NOT NULL DEFAULT \'wasm\', "level" TEXT NOT NULL DEFAULT \'error\', "message" TEXT NOT NULL, "stack" TEXT, "path" TEXT, "method" TEXT, "context" TEXT)';

export function repairRegistrySql(sql) {
    if (typeof sql !== 'string') return sql;
    if (!/^\s*CREATE\s+TABLE/i.test(sql)) return sql;
    if (!/\bDEFAULT\s*\?/i.test(sql)) return sql;
    if (/"_dokkebi_errors"/i.test(sql)) return REPAIR_DOKKEBI_ERRORS_DDL;
    return sql;
}

function normalizeRegistryEntry(entry) {
    if (typeof entry?.sql !== 'string') return entry;
    const sql = repairRegistrySql(entry.sql);
    const paramCount = (sql.match(/\?/g) || []).length;
    return { ...entry, sql, paramCount };
}

/**
 * 단일 SQL 로부터 레지스트리 엔트리를 만듭니다.
 * @param {string} sql - 원본 SQL (DSL._compile() 결과 등)
 * @param {object} opts - 선택 메타
 * @param {string[]} opts.sources - 출처 파일 힌트 배열
 * @param {string} opts.op - 사전 지정된 op (자동 감지 시 생략 가능)
 */
export function createEntry(sql, opts = {}) {
    const fixed = repairRegistrySql(sql);
    const canonical = canonicalizeSql(fixed);
    const queryId = computeQueryId(fixed);
    const op = opts.op || detectOp(canonical);
    const tables = extractTables(canonical);
    // 바인딩 개수는 원문 기준 — canonical 은 문자열 리터럴을 ? 로 바꿔
    // CREATE TABLE ... DEFAULT 'wasm' 같은 문장을 깨뜨리며 paramCount 도 왜곡함.
    const paramCount = (typeof fixed === 'string' ? fixed.match(/\?/g) : null)?.length ?? 0;
    return {
        queryId,
        sql: fixed,
        op,
        tables,
        paramCount,
        sources: opts.sources || [],
        // Stage 1/2 에서 채움 (현재는 placeholder)
        tenantPolicy: opts.tenantPolicy || null,
        tenantColumn: opts.tenantColumn || null,
    };
}

// ─────────────────────────────────────────────────────────────
// Registry 컨테이너
// ─────────────────────────────────────────────────────────────

export class QueryRegistry {
    constructor() {
        this._entries = new Map();
    }

    size() {
        return this._entries.size;
    }

    has(queryId) {
        return this._entries.has(queryId);
    }

    get(queryId) {
        return this._entries.get(queryId) || null;
    }

    /** 엔트리 추가. 동일 queryId 가 이미 있으면 sources 병합 */
    add(entry) {
        if (!entry || !entry.queryId) return;
        entry = normalizeRegistryEntry(entry);
        const prev = this._entries.get(entry.queryId);
        if (!prev) {
            this._entries.set(entry.queryId, {
                ...entry,
                sources: [...(entry.sources || [])],
            });
            return;
        }
        const prevN = normalizeRegistryEntry(prev);
        const merged = {
            ...prevN,
            sources: mergeSources(prevN.sources, entry.sources),
            tenantPolicy: entry.tenantPolicy ?? prevN.tenantPolicy,
            tenantColumn: entry.tenantColumn ?? prevN.tenantColumn,
        };
        this._entries.set(entry.queryId, merged);
    }

    /** SQL 문자열로 직접 추가 (흔한 진입점) */
    addSql(sql, opts) {
        const entry = createEntry(sql, opts);
        this.add(entry);
        return entry.queryId;
    }

    /** 다른 registry 병합 */
    merge(other) {
        if (!other) return;
        const iterable = other instanceof QueryRegistry
            ? other._entries.values()
            : Array.isArray(other)
                ? other
                : Object.values(other.queries || {});
        for (const entry of iterable) {
            this.add(entry);
        }
    }

    /** JSON 직렬화 (파일/임베드 용) */
    toJSON(extra = {}) {
        const queries = {};
        for (const [id, entry] of this._entries) queries[id] = entry;
        return {
            version: REGISTRY_VERSION,
            generatedAt: new Date().toISOString(),
            ...extra,
            queries,
        };
    }

    /** 메타만 요약 (통계 로그 용) */
    stats() {
        const stats = { total: this._entries.size, byOp: {}, byTable: {} };
        for (const e of this._entries.values()) {
            if (e.op) stats.byOp[e.op] = (stats.byOp[e.op] || 0) + 1;
            for (const t of e.tables || []) {
                stats.byTable[t] = (stats.byTable[t] || 0) + 1;
            }
        }
        return stats;
    }
}

function mergeSources(a, b) {
    const seen = new Set();
    const key = (s) => (typeof s === 'string' ? s : `${s.file || ''}::${s.symbol || ''}`);
    const out = [];
    for (const s of [...(a || []), ...(b || [])]) {
        const k = key(s);
        if (seen.has(k)) continue;
        seen.add(k);
        out.push(s);
    }
    return out;
}

// ─────────────────────────────────────────────────────────────
// 백엔드 번들에서 명시적 선언 추출 (1차 구현 — safe, no eval)
// ─────────────────────────────────────────────────────────────

/**
 * backend/ 하위 .ts/.js 소스에서 다음 패턴을 찾아 수집합니다.
 *
 *   // @dokkebi-query: SELECT "id" FROM "users" WHERE "id" = ?
 *   // @dokkebi-query: INSERT INTO "orders" ("user_id","qty") VALUES (?,?)
 *
 * 이 주석은 개발자가 DSL 로 표현하기 어려운 쿼리 shape 를 명시적으로
 * 레지스트리에 등록하고 싶을 때 사용합니다. DSL 로 작성된 쿼리의 경우
 * dev 런타임 자동 학습 (s3-dev) 이 기본 수집 경로입니다.
 */
export async function collectDeclarativeQueries(projectDir) {
    const registry = new QueryRegistry();
    const roots = ['backend', 'backend/controllers', 'backend/queries'];
    const seen = new Set();

    for (const root of roots) {
        const abs = path.join(projectDir, root);
        let exists = true;
        try { await fs.access(abs); } catch { exists = false; }
        if (!exists) continue;
        await walk(abs, async (file) => {
            if (seen.has(file)) return;
            seen.add(file);
            if (!/\.(ts|tsx|js|mjs)$/.test(file)) return;
            let content;
            try { content = await fs.readFile(file, 'utf-8'); } catch { return; }
            const re = /\/\/\s*@dokkebi-query:\s*([^\n]+)/gi;
            let m;
            while ((m = re.exec(content)) !== null) {
                const sqlText = m[1].trim();
                if (!sqlText) continue;
                registry.addSql(sqlText, {
                    sources: [{
                        file: path.relative(projectDir, file),
                        symbol: '@dokkebi-query',
                    }],
                });
            }
        });
    }
    return registry;
}

async function walk(dir, visit) {
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); }
    catch { return; }
    for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) await walk(full, visit);
        else await visit(full);
    }
}

// ─────────────────────────────────────────────────────────────
// 학습된 쿼리 병합 (dev 모드에서 런타임이 저장한 캐시)
// ─────────────────────────────────────────────────────────────

/** `.dokkebi/query-registry.learned.json` 에 저장된 내용을 로드/병합 */
export async function loadLearnedRegistry(projectDir) {
    const p = path.join(projectDir, '.dokkebi', 'query-registry.learned.json');
    try {
        const buf = await fs.readFile(p, 'utf-8');
        const json = JSON.parse(buf);
        if (!json || !json.queries) return new QueryRegistry();
        const reg = new QueryRegistry();
        reg.merge({ queries: Object.values(json.queries) });
        return reg;
    } catch {
        return new QueryRegistry();
    }
}

/** 학습 파일 덮어쓰기 (dev 런타임이 갱신 호출) */
export async function writeLearnedRegistry(projectDir, registry) {
    const dir = path.join(projectDir, '.dokkebi');
    await fs.mkdir(dir, { recursive: true });
    const p = path.join(dir, 'query-registry.learned.json');
    const json = registry.toJSON({ source: 'dev-learn' });
    await fs.writeFile(p, JSON.stringify(json, null, 2), 'utf-8');
    return p;
}

// ─────────────────────────────────────────────────────────────
// 최종 레지스트리 구성 (build.js 에서 호출)
// ─────────────────────────────────────────────────────────────

/**
 * 빌드 타임 레지스트리를 조립합니다.
 * 병합 순서 (후자가 sources 를 덧붙임 — queryId 동일하면 자동 중복 제거):
 *   1. declarative (`// @dokkebi-query:` 주석) — 개발자 명시 등록
 *   2. scanned     (backend 소스 정적 스캔 — `.prepare('...')` 등 SQL 리터럴)
 *   3. learned     (`.dokkebi/query-registry.learned.json` — dev 런타임 학습)
 *
 * @param {string} projectDir
 * @param {object} opts
 * @param {string}  [opts.buildHash]
 * @param {boolean} [opts.includeLearned=true] — deploy 에서는 false 권장
 * @param {boolean} [opts.includeScan=true]    — 정적 스캐너 활성화
 * @param {string[]} [opts.scanRoots]          — 스캐너 커스텀 루트
 * @param {boolean} [opts.verbose=false]       — 스캔 상세 로그
 */
export async function buildRegistry(projectDir, opts = {}) {
    const {
        includeLearned = true,
        includeScan = true,
        buildHash = null,
        scanRoots,
        verbose = false,
    } = opts;
    const registry = new QueryRegistry();
    const sources = { declarative: 0, scanned: 0, learned: 0, dynamicSamples: [] };

    const declarative = await collectDeclarativeQueries(projectDir);
    sources.declarative = declarative.size();
    registry.merge(declarative);

    let opTableStats = null;
    if (includeScan) {
        const { scanProjectQueries } = await import('./queryScanner.js');
        const { registry: scanned, stats, opTableStats: scanStats } = await scanProjectQueries(projectDir, {
            roots: scanRoots,
            verbose,
        });
        sources.scanned = scanned.size();
        sources.dynamicSamples = stats.dynamicSamples;
        registry.merge(scanned);
        opTableStats = scanStats;
    }

    if (includeLearned) {
        const learned = await loadLearnedRegistry(projectDir);
        sources.learned = learned.size();
        registry.merge(learned);
    }
    return { registry, buildHash, sources, opTableStats };
}

/** 레지스트리를 디스크에 직렬화 */
export async function writeRegistry(registry, outPath, extra = {}) {
    const dir = path.dirname(outPath);
    await fs.mkdir(dir, { recursive: true });
    const json = registry.toJSON(extra);
    await fs.writeFile(outPath, JSON.stringify(json, null, 2), 'utf-8');
    return outPath;
}

/** 파일에서 레지스트리 로드 (없으면 빈 레지스트리) */
export async function loadRegistry(registryPath) {
    try {
        const buf = await fs.readFile(registryPath, 'utf-8');
        const json = JSON.parse(buf);
        const reg = new QueryRegistry();
        if (json && json.queries) {
            reg.merge({ queries: Object.values(json.queries) });
        }
        return reg;
    } catch {
        return new QueryRegistry();
    }
}
