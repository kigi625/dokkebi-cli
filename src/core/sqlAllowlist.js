/**
 * SQL Allowlist — 빌드 타임 자동 추출 + 런타임 검증
 *
 * 빌드 타임:
 *   1. backend/models/ 에서 defineTable/table 호출을 스캔하여 테이블명 추출
 *   2. backend/controllers/ 에서 db.select/insert/update/delete 사용 패턴 추출
 *   3. sql-allowlist.json 생성 → dist/dokkebi/sql-allowlist.json
 *
 * 런타임:
 *   DB 프록시가 SQL 실행 전에 allowlist 검증
 *   → 허용되지 않은 테이블/연산 조합은 거부
 */

import fs from 'fs/promises';
import path from 'path';
import { detectOuterOp, outerStatement, detectPrimaryTableOf, extractTableRefs, hasNonPositionalParameters } from './sqlShape.js';

// ─────────────────────────────────────────────────────────────
// 내부 시스템 테이블 접근 차단
//
//   `_dokkebi_sessions` 에는 전 세션의 enc_key/sig_key 가, `_dokkebi_ephemeral_keys`
//   에는 핸드셰이크 개인키 JWK 가 들어 있다. 따라서 클라이언트(브라우저 WASM)
//   SQL 이 이 테이블을 읽을 수 있으면 세션 하이재킹·감사로그 삭제가 가능하다.
//   내부 코드(worker 의 `_internalDb`, dok serve)만 직접 prepare 로 접근하며,
//   프록시를 통과하는 클라이언트 SQL 은 allowlist 유무와 무관하게 항상 차단한다.
//   (로그/감사 테이블도 포함 — 변조·삭제 방지)
// ─────────────────────────────────────────────────────────────
const INTERNAL_TABLE_PREFIX = '_dokkebi_';

export function isInternalTableName(name) {
    const n = String(name || '').toLowerCase();
    return n.startsWith(INTERNAL_TABLE_PREFIX) || n === 'sqlite_master' || n.startsWith('sqlite_');
}

/**
 * 클라이언트 SQL 이 내부 테이블(_dokkebi_*, sqlite_*)을 참조하는지 검사.
 * @param {string} sql
 * @returns {string|null} 참조된 내부 테이블명 (없으면 null)
 */
export function findInternalTableRef(sql) {
    if (typeof sql !== 'string' || sql.length === 0) return null;
    const normalized = stripStringsAndComments(sql).replace(/\s+/g, ' ').trim();
    for (const t of extractAllTables(normalized)) {
        if (isInternalTableName(t)) return t;
    }
    // CREATE TABLE 대상은 FROM/JOIN 패턴에 걸리지 않으므로 별도 검사.
    const m = /\bCREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["'`]?([A-Za-z_][\w]*)["'`]?/i.exec(normalized);
    if (m && isInternalTableName(m[1])) return m[1];
    // 인용/스키마 표기("main"."_dokkebi_x" 등) 우회 방어 — 예약 접두사 토큰 자체를 검사.
    const token = /(?:^|[^A-Za-z0-9_])(?:"|`|'|\[)?((?:_dokkebi_|sqlite_)[A-Za-z0-9_]*)/i.exec(normalized);
    if (token) return token[1];
    return null;
}

/** 세션 키스토어 — 사용자 SQL(UNION/JOIN/CREATE AS 포함)에서 하드 거부 */
export const KEYSTORE_TABLES = Object.freeze([
    '_dokkebi_sessions',
    '_dokkebi_ephemeral_keys',
    '_dokkebi_nonces',
]);

/**
 * 정규화된 SQL 이 키스토어 테이블을 참조하는지 검사.
 * 문자열 리터럴은 호출 전에 strip 되어 있어야 한다.
 * @param {string} normalized
 * @returns {string|null} 매칭된 테이블명
 */
export function findKeystoreTableRef(normalized) {
    const compact = String(normalized || '').replace(/["'`[\]]/g, '');
    for (const name of KEYSTORE_TABLES) {
        const re = new RegExp(`(^|[^A-Za-z0-9])${name}([^A-Za-z0-9]|$)`, 'i');
        if (re.test(compact)) return name;
    }
    return null;
}

/**
 * 빌드 타임: 백엔드 소스에서 SQL 허용목록 자동 추출
 *
 * @param {string} sourceRoot - 프로젝트 루트
 * @param {object} [opts]
 * @param {object} [opts.policy] - normalizePolicyConfig() 결과. 주어지면 v2 스키마로 출력.
 * @returns {object} v1 또는 v2 allowlist
 */
export async function extractAllowlist(sourceRoot, opts = {}) {
    const backendDir = path.join(sourceRoot, 'backend');
    const modelsDir = path.join(backendDir, 'models');
    const controllersDir = path.join(backendDir, 'controllers');

    // Step 1: 모델에서 테이블명 + 변수명→테이블명 alias 맵 추출
    //   예: export const buildTasks = table('build_tasks', ...)
    //       → tableNames 에 'build_tasks' 포함, varAliasMap['buildTasks'] = 'build_tasks'
    //   이 alias 맵이 없으면 camelCase 변수명(buildTasks) 으로 DML 호출이
    //   snake_case 테이블(build_tasks) 로 연결되지 못해 INSERT/UPDATE/DELETE 가 누락된다.
    const { tableNames, varAliasMap } = await extractTableNames(modelsDir);
    console.log(`[dokkebi:allowlist] 감지된 테이블: ${tableNames.join(', ') || '(없음)'}`);
    const aliasCount = Object.keys(varAliasMap).length;
    if (aliasCount > 0) {
        console.log(`[dokkebi:allowlist] 변수명 alias: ${aliasCount}개 (${Object.entries(varAliasMap).map(([v, t]) => `${v}→${t}`).slice(0, 6).join(', ')}${aliasCount > 6 ? ', ...' : ''})`);
    }

    // Step 2: 컨트롤러에서 테이블별 연산 추출
    const tableOps = await extractOperations(controllersDir, tableNames, varAliasMap);

    // Step 3: db.raw() 사용 여부 감지
    const rawUsed = await detectRawUsage(controllersDir);
    if (rawUsed) {
        console.warn('[dokkebi:allowlist] ⚠ db.raw() 사용 감지 — 보안 강화를 위해 제거를 권장합니다.');
    }

    // Step 4: 허용목록 구성
    const tables = tableNames.map(name => ({
        name,
        ops: tableOps[name] || ['SELECT'],
    }));

    const policy = opts.policy;
    // policy 가 명시되고 enabled === true 면 v2 스키마로 출력.
    if (policy && policy.enabled) {
        const tablesV2 = tables.map((t) => {
            const tp = findPolicyForTable(policy.tables, t.name);
            if (tp) {
                return {
                    name: t.name,
                    ops: t.ops,
                    policy: {
                        mode: tp.mode || 'none',
                        tenantColumn: tp.tenantColumn,
                    },
                };
            }
            return { name: t.name, ops: t.ops };
        });
        return {
            version: 2,
            tenant: { source: 'session', claim: policy.claim || 'user_id' },
            policy: {
                mode: policy.mode || 'verify',
                strict: policy.strict !== false,
                defaultMode: policy.defaultMode || 'none',
            },
            tables: tablesV2,
            rawAllowed: rawUsed,
            generatedAt: new Date().toISOString(),
        };
    }

    return {
        version: 1,
        tables,
        rawAllowed: rawUsed,
        generatedAt: new Date().toISOString(),
    };
}

function findPolicyForTable(tables, name) {
    if (!tables) return null;
    const lower = name.toLowerCase();
    for (const [k, v] of Object.entries(tables)) {
        if (k.toLowerCase() === lower) return v;
    }
    return null;
}

/**
 * 모델 파일에서 테이블명 + 변수명→테이블명 alias 맵 추출
 * defineTable('users', ...) / table('users', ...) 패턴을 스캔
 *
 * 반환:
 *   tableNames  - 실제 SQL 테이블명 목록 (snake_case 가 일반적)
 *   varAliasMap - `export const <varName> = table('<tableName>', ...)` 에서 추출한
 *                 변수명→테이블명 매핑. 컨트롤러에서 `db.insert(buildTasks, ...)` 같은
 *                 호출을 만났을 때 `buildTasks` → `build_tasks` 로 해석하기 위해 사용.
 */
async function extractTableNames(modelsDir) {
    const names = new Set();
    const varAliasMap = {};

    let files;
    try {
        files = await fs.readdir(modelsDir, { withFileTypes: true });
    } catch {
        return { tableNames: [], varAliasMap: {} };
    }

    // 테이블 선언 패턴 (공통):
    //   export const <varName> = table('<tableName>', ...)
    //   export const <varName> = defineTable('<tableName>', ...)
    //   const <varName> = table('<tableName>', ...)
    // 앞의 export 유무, const/let/var, 공백을 모두 허용.
    const declRegex = /(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:defineTable|table)\s*\(\s*['"]([^'"]+)['"]/g;

    for (const entry of files) {
        if (!entry.isFile()) continue;
        if (!/\.(ts|js|tsx|jsx)$/.test(entry.name)) continue;

        const content = await fs.readFile(path.join(modelsDir, entry.name), 'utf-8');

        // defineTable('tablename', ...) / table('tablename', ...) — 테이블명만 수집 (fallback)
        const defineMatches = content.matchAll(/defineTable\s*\(\s*['"]([^'"]+)['"]/g);
        for (const m of defineMatches) names.add(m[1]);

        const tableMatches = content.matchAll(/\btable\s*\(\s*['"]([^'"]+)['"]/g);
        for (const m of tableMatches) names.add(m[1]);

        // export const <var> = table('<name>', ...) — 변수명↔테이블명 alias 매핑
        const declMatches = content.matchAll(declRegex);
        for (const m of declMatches) {
            const varName = m[1];
            const tableName = m[2];
            names.add(tableName);
            if (varName !== tableName) varAliasMap[varName] = tableName;
        }
    }

    return { tableNames: [...names], varAliasMap };
}

/**
 * 컨트롤러 파일에서 테이블별 사용 연산 추출
 * db.select(users) → SELECT on users 테이블
 * db.insert(users, ...) → INSERT on users 테이블
 * db.update(users, ...) → UPDATE on users 테이블
 * db.delete(users) → DELETE on users 테이블
 *
 * @param {string} controllersDir
 * @param {string[]} knownTables  - snake_case 테이블명 목록
 * @param {Record<string, string>} [varAliasMap]
 *        변수명(camelCase) → 테이블명(snake_case) 매핑. models 스캔으로 사전 구축됨.
 */
async function extractOperations(controllersDir, knownTables, varAliasMap = {}) {
    const ops = {};
    for (const t of knownTables) ops[t] = new Set();

    let files;
    try {
        files = await collectFiles(controllersDir);
    } catch {
        return ops;
    }

    /** 변수명을 실제 테이블명으로 해석. importMap → varAliasMap → 원문 순으로 조회. */
    function resolveTable(varOrTable, importMap) {
        if (importMap && importMap[varOrTable]) return importMap[varOrTable];
        if (varAliasMap[varOrTable]) return varAliasMap[varOrTable];
        return varOrTable;
    }

    for (const filePath of files) {
        const content = await fs.readFile(filePath, 'utf-8');

        // import { users, products } from '../models/index.js'
        // 변수명 → 테이블명 매핑 구축 (파일별 import alias)
        const importMap = buildImportMap(content, knownTables, varAliasMap);

        // db.select(varName) → SELECT
        const selectMatches = content.matchAll(/\.select\s*\(\s*(\w+)/g);
        for (const m of selectMatches) {
            const tableName = resolveTable(m[1], importMap);
            if (ops[tableName]) ops[tableName].add('SELECT');
        }

        // db.insert(varName, ...) → INSERT
        const insertMatches = content.matchAll(/\.insert\s*\(\s*(\w+)/g);
        for (const m of insertMatches) {
            const tableName = resolveTable(m[1], importMap);
            if (ops[tableName]) ops[tableName].add('INSERT');
        }

        // db.update(varName, ...) → UPDATE
        const updateMatches = content.matchAll(/\.update\s*\(\s*(\w+)/g);
        for (const m of updateMatches) {
            const tableName = resolveTable(m[1], importMap);
            if (ops[tableName]) ops[tableName].add('UPDATE');
        }

        // db.delete(varName) → DELETE
        const deleteMatches = content.matchAll(/\.delete\s*\(\s*(\w+)/g);
        for (const m of deleteMatches) {
            const tableName = resolveTable(m[1], importMap);
            if (ops[tableName]) ops[tableName].add('DELETE');
        }

        // db.raw('UPDATE table SET ...') / db.raw("SELECT * FROM table") 등 raw SQL 스캔
        const rawMatches = content.matchAll(/\.raw\s*\(\s*['"`]([^'"`]+)['"`]/g);
        for (const m of rawMatches) {
            const rawSql = m[1].trim();
            const upper = rawSql.toUpperCase();
            let rawOp = null;
            if (upper.startsWith('SELECT'))        rawOp = 'SELECT';
            else if (upper.startsWith('INSERT'))   rawOp = 'INSERT';
            else if (upper.startsWith('UPDATE'))   rawOp = 'UPDATE';
            else if (upper.startsWith('DELETE'))   rawOp = 'DELETE';
            if (!rawOp) continue;

            // UPDATE <table> SET ... / INSERT INTO <table> / DELETE FROM <table> / SELECT ... FROM <table>
            let tableMatch = null;
            if (rawOp === 'UPDATE') {
                tableMatch = rawSql.match(/UPDATE\s+["'`]?(\w+)["'`]?\s+SET/i);
            } else if (rawOp === 'INSERT') {
                tableMatch = rawSql.match(/INSERT\s+(?:OR\s+\w+\s+)?INTO\s+["'`]?(\w+)["'`]/i);
            } else if (rawOp === 'DELETE') {
                tableMatch = rawSql.match(/DELETE\s+FROM\s+["'`]?(\w+)["'`]/i);
            } else if (rawOp === 'SELECT') {
                tableMatch = rawSql.match(/FROM\s+["'`]?(\w+)["'`]/i);
            }
            if (!tableMatch) continue;
            const rawTable = tableMatch[1].toLowerCase();
            if (ops[rawTable]) ops[rawTable].add(rawOp);
        }
    }

    // Set → Array 변환
    const result = {};
    for (const [t, opSet] of Object.entries(ops)) {
        result[t] = [...opSet];
        if (result[t].length === 0) result[t] = ['SELECT'];
    }
    return result;
}

/**
 * import 구문에서 변수명 → 테이블명 매핑 구축
 * import { users, products } from '../models/...'
 */
function buildImportMap(content, knownTables, varAliasMap = {}) {
    const map = {};
    /** 주어진 심볼이 테이블명(직접 매칭) 이거나 varAliasMap 의 변수명이면 실제 테이블명을 리턴. */
    const resolveSymbol = (sym) => {
        if (knownTables.includes(sym)) return sym;
        if (varAliasMap[sym]) return varAliasMap[sym];
        return null;
    };

    // Named import: import { users, products as prods } from '...'
    const importMatches = content.matchAll(/import\s*\{([^}]+)\}\s*from\s*['"][^'"]*models[^'"]*['"]/g);
    for (const m of importMatches) {
        const imports = m[1].split(',').map(s => s.trim());
        for (const imp of imports) {
            const asMatch = imp.match(/(\w+)\s+as\s+(\w+)/);
            if (asMatch) {
                const orig = asMatch[1];
                const alias = asMatch[2];
                const resolved = resolveSymbol(orig);
                if (resolved) map[alias] = resolved;
            } else {
                const name = imp.trim();
                const resolved = resolveSymbol(name);
                if (resolved) map[name] = resolved;
            }
        }
    }
    return map;
}

/**
 * db.raw() 사용 여부 감지
 */
async function detectRawUsage(controllersDir) {
    let files;
    try {
        files = await collectFiles(controllersDir);
    } catch {
        return false;
    }

    for (const filePath of files) {
        const content = await fs.readFile(filePath, 'utf-8');
        if (/\bdb\.raw\s*\(/.test(content)) return true;
    }
    return false;
}

/**
 * 디렉토리 재귀 파일 수집
 */
async function collectFiles(dir) {
    const results = [];
    let entries;
    try {
        entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
        return results;
    }
    for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            results.push(...await collectFiles(full));
        } else if (/\.(ts|js|tsx|jsx)$/.test(entry.name)) {
            results.push(full);
        }
    }
    return results;
}

// ─────────────────────────────────────────────────────────────
// 런타임 SQL 검증 (강화 버전)
//
// 기본 방침:
//   1) fail-closed — allowlist 없으면 전부 거부
//   2) 문자열 리터럴/주석 제거 후 분석 → 주석 기반 우회 방어
//   3) 모든 테이블 참조(FROM/JOIN/INTO/UPDATE) 추출 → 전부 allowlist에 있어야 함
//      → UNION, 서브쿼리, JOIN을 통한 미등록 테이블 접근 차단
//   4) 다중 문장(;) 차단 → stacked query injection 방어
//   5) CREATE TABLE 은 시스템 테이블 접두사(_dokkebi_)만 허용
// ─────────────────────────────────────────────────────────────

// 위험한 토큰: 파서 수준에서 전수 차단
const DANGEROUS_TOKENS = [
    'ATTACH', 'DETACH',          // SQLite 다른 DB 파일 첨부
    'PRAGMA',                    // SQLite 설정 변경 (일부는 무해하지만 일괄 차단)
    'EXEC', 'EXECUTE',           // 저장 프로시저
    'LOAD_EXTENSION',            // SQLite 확장 로드
    'INTO OUTFILE', 'INTO DUMPFILE', // MySQL 파일 쓰기
    'LOAD DATA',                 // MySQL
    'COPY',                      // PostgreSQL 파일 I/O
    'INFORMATION_SCHEMA',        // 스키마 enumeration
    'PG_SLEEP', 'SLEEP(',        // 시간 기반 DoS/블라인드 SQLi
    'BENCHMARK(',                // MySQL 시간 기반
    'WAITFOR',                   // SQL Server
    'XP_', 'SP_EXECUTESQL',      // SQL Server 시스템 프로시저
];

/**
 * SQL에서 문자열 리터럴·주석을 공백으로 대체한 정규화된 문자열 반환
 * 문자열 안의 "--" 나 "union" 같은 토큰이 오탐되지 않도록 함
 */
function stripStringsAndComments(sql) {
    let out = '';
    let i = 0;
    const n = sql.length;
    while (i < n) {
        const ch = sql[i];
        const next = sql[i + 1];

        // 라인 주석 --
        if (ch === '-' && next === '-') {
            while (i < n && sql[i] !== '\n') i++;
            out += ' ';
            continue;
        }
        // 블록 주석 /* ... */
        if (ch === '/' && next === '*') {
            i += 2;
            while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i++;
            i += 2;
            out += ' ';
            continue;
        }
        // 작은따옴표 문자열 (SQL 표준은 '' 로 이스케이프)
        if (ch === "'") {
            i++;
            while (i < n) {
                if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; }
                if (sql[i] === "'") { i++; break; }
                i++;
            }
            out += " '' ";
            continue;
        }
        // 큰따옴표 식별자/문자열 (일부 DB에서 문자열로 취급)
        // 식별자 기능 보존을 위해 내용은 제거하되 따옴표는 유지
        if (ch === '"') {
            out += '"';
            i++;
            while (i < n) {
                if (sql[i] === '"' && sql[i + 1] === '"') { i += 2; continue; }
                if (sql[i] === '"') { out += '"'; i++; break; }
                out += sql[i];
                i++;
            }
            continue;
        }
        // 백틱 식별자 (MySQL)
        if (ch === '`') {
            out += '`';
            i++;
            while (i < n && sql[i] !== '`') { out += sql[i]; i++; }
            if (sql[i] === '`') { out += '`'; i++; }
            continue;
        }
        out += ch;
        i++;
    }
    return out;
}

/**
 * 다중 문장(;) 감지 — 끝에 붙은 단일 ; 는 허용
 */
function hasMultipleStatements(normalized) {
    // 마지막 ; 는 trim 후 제거
    const trimmed = normalized.replace(/;\s*$/, '');
    return /;/.test(trimmed);
}

/**
 * 위험 토큰 감지
 */
function containsDangerousToken(normalizedUpper) {
    for (const token of DANGEROUS_TOKENS) {
        // INTO OUTFILE 같은 다중 단어 토큰은 공백 정규화 후 포함 검사
        const needle = token.replace(/\s+/g, ' ');
        // 워드 바운더리가 필요한 경우 간단 검사 (영문자/숫자/언더스코어 경계)
        if (needle.endsWith('(')) {
            if (normalizedUpper.includes(needle)) return token;
        } else {
            const idx = normalizedUpper.indexOf(needle);
            if (idx === -1) continue;
            const before = normalizedUpper[idx - 1];
            const after  = normalizedUpper[idx + needle.length];
            const isBoundary = (c) => c === undefined || !/[A-Z0-9_]/.test(c);
            if (isBoundary(before) && (needle.includes(' ') || isBoundary(after))) return token;
        }
    }
    return null;
}

/**
 * SQL에서 CTE 이름 집합 추출 (WITH name AS (...), name2 AS (...) ...)
 * CTE는 실제 테이블이 아니므로 allowlist 검증에서 제외되어야 함
 */
function extractCteNames(normalizedUpper) {
    const names = new Set();
    // WITH [RECURSIVE] name [(...)] AS (  형태의 CTE 헤더
    // 단일 패스로 WITH 블록만 대상으로
    const withMatch = /^\s*WITH\s+(?:RECURSIVE\s+)?(.+?)\b(SELECT|INSERT|UPDATE|DELETE)\b/is.exec(normalizedUpper);
    if (!withMatch) return names;
    const cteBlock = withMatch[1];
    // name AS ( 패턴
    const re = /\b([A-Z_][\w]*)\s*(?:\([^)]*\))?\s+AS\s*\(/gi;
    let m;
    while ((m = re.exec(cteBlock)) !== null) {
        names.add(m[1].toLowerCase());
    }
    return names;
}

/**
 * SQL에서 모든 테이블 참조 추출 (FROM/JOIN/INTO/UPDATE)
 * 별칭이나 스키마 접두사(schema.table)는 마지막 이름만 사용
 * CTE 이름은 제외
 */
function extractAllTables(normalized) {
    const tables = new Set();
    const upper = normalized.toUpperCase();
    const cteNames = extractCteNames(upper);
    for (const ref of extractTableRefs(normalized)) {
        const baseName = String(ref.name);
        if (cteNames.has(baseName.toLowerCase())) continue;
        tables.add(baseName);
    }
    return [...tables];
}

/**
 * 기본 연산 판별 (첫 키워드)
 */
function detectPrimaryOp(normalizedUpper) {
    // `WITH ... DELETE` 를 SELECT 로 오판하지 않도록 괄호 밖 문장 키워드를 사용한다.
    return detectOuterOp(normalizedUpper).op;
}

/**
 * SQL 쿼리를 허용목록과 대조하여 검증 (fail-closed)
 *
 * @param {string} sql - 실행하려는 SQL
 * @param {object|null} allowlist - extractAllowlist() 결과
 * @param {object} [opts]
 * @param {boolean} [opts.strict=true] - allowlist 없을 때 fail-closed (기본 true)
 * @returns {{ allowed: boolean, reason?: string }}
 */
export function validateSqlAllowlist(sql, allowlist, opts = {}) {
    const strict = opts.strict !== false;

    if (typeof sql !== 'string' || sql.length === 0) {
        return { allowed: false, reason: 'SQL이 비어 있습니다.' };
    }

    const hasAllowlist = !!(allowlist && Array.isArray(allowlist.tables) && allowlist.tables.length > 0);

    // 1) 문자열/주석 제거 → 토큰 분석용 정규화 (항상 수행)
    const normalized = stripStringsAndComments(sql).replace(/\s+/g, ' ').trim();
    const upper = normalized.toUpperCase();

    // 1-b) 위치 기반(?) 이외의 파라미터 표기 차단 (항상 수행)
    //      `?2` 는 정책 엔진의 파라미터 인덱스 계산을 어긋나게 한다.
    if (hasNonPositionalParameters(normalized)) {
        return { allowed: false, reason: '위치 기반(?) 이외의 파라미터 표기는 허용되지 않습니다.' };
    }

    // 2) 다중 문장 차단 (항상 수행)
    if (hasMultipleStatements(normalized)) {
        return { allowed: false, reason: '다중 SQL 문장은 허용되지 않습니다.' };
    }

    // 3) 위험 토큰 차단 (항상 수행)
    const danger = containsDangerousToken(upper);
    if (danger) {
        return { allowed: false, reason: `위험한 SQL 토큰 감지: ${danger}` };
    }

    // 3-b) 내부 시스템 테이블(_dokkebi_* · sqlite_*) 참조 차단 (항상 수행, fail-closed)
    //      allowlist 가 없거나 strict=false 인 모드에서도 반드시 막아야 한다.
    //      (기존 keyStore 전용 차단보다 넓게 적용 — 로그/감사 테이블 변조 방지)
    const internalRef = findInternalTableRef(sql);
    if (internalRef) {
        return { allowed: false, reason: `내부 시스템 테이블에는 접근할 수 없습니다: "${internalRef}"` };
    }

    // 3-c) 클라이언트 DDL 차단 — 스키마 변경은 빌드·마이그레이션 경로에서만 수행한다.
    if (/^(?:CREATE|ALTER|DROP|TRUNCATE|REINDEX|VACUUM)\b/.test(upper)) {
        return { allowed: false, reason: 'DDL(CREATE/ALTER/DROP)은 클라이언트 SQL 에서 허용되지 않습니다.' };
    }

    // allowlist 부재 시:
    //   strict=true → 모든 쿼리 거부 (fail-closed)
    //   strict=false → 위 공통 검증만 통과하면 허용 (하위 호환)
    if (!hasAllowlist) {
        if (strict) {
            return { allowed: false, reason: 'SQL allowlist가 없어 모든 쿼리를 거부합니다. (빌드 시 생성 필요)' };
        }
        return { allowed: true };
    }

    // 4) 기본 연산 판별
    const op = detectPrimaryOp(upper);
    if (!op) {
        return { allowed: false, reason: `허용되지 않은 SQL 연산: ${normalized.slice(0, 30)}` };
    }

    // 허용 테이블 맵 (일반 검증에서 사용)
    const allowedMap = new Map();
    for (const t of allowlist.tables) allowedMap.set(t.name.toLowerCase(), t);

    // 5) 모든 테이블 참조 추출 → 전부 allowlist에 있어야 함
    const allTables = extractAllTables(upper).map(t => t.toLowerCase());
    // CTE 전용 쿼리(WITH ... SELECT * FROM cte)의 경우 외부 테이블 참조가 0개일 수 있음
    // → upper가 WITH로 시작하면 0개도 허용 (CTE 이름만 참조)
    if (allTables.length === 0 && !upper.trimStart().startsWith('WITH')) {
        return { allowed: false, reason: 'SQL에서 테이블명을 추출할 수 없습니다.' };
    }

    // 주 연산 대상(첫 FROM/INTO/UPDATE) 과 CTE 이름은 아래 루프에서 함께 사용한다.
    const cteNames = extractCteNames(upper);
    const primaryTable = detectPrimaryTable(upper, op);
    const primaryLower = primaryTable ? primaryTable.toLowerCase() : '';

    for (const t of allTables) {
        const entry = allowedMap.get(t);
        if (!entry) {
            return {
                allowed: false,
                reason: `허용되지 않은 테이블: "${t}" (등록된 테이블: ${[...allowedMap.keys()].join(', ')})`,
            };
        }
        // 읽기 참조 검증:
        //   - SELECT 문의 모든 테이블은 SELECT 권한 필요
        //   - INSERT/UPDATE/DELETE 에서 주 연산 대상이 아닌 테이블은 JOIN/서브쿼리/
        //     INSERT ... SELECT 의 원본이므로 SELECT 권한 필요
        //     (예: INSERT INTO posts SELECT ... FROM users → users 는 SELECT)
        const isPrimary = !!primaryLower && t === primaryLower;
        if ((op === 'SELECT' || !isPrimary) && !entry.ops.includes('SELECT')) {
            return { allowed: false, reason: `테이블 "${t}"에 대한 SELECT가 허용되지 않습니다.` };
        }
    }

    // 6) 주 연산이 대상 테이블에 허용되는지 확인 (INSERT/UPDATE/DELETE)
    // CTE 이름은 실제 테이블이 아니므로 primary 검증에서 스킵
    if (primaryTable && !cteNames.has(primaryLower)) {
        const entry = allowedMap.get(primaryLower);
        if (!entry || !entry.ops.includes(op)) {
            return {
                allowed: false,
                reason: `테이블 "${primaryTable}"에 대한 ${op} 연산이 허용되지 않습니다. (허용: ${entry?.ops.join(', ') || '(없음)'})`,
            };
        }
    }

    return { allowed: true };
}

/**
 * 주 연산의 대상 테이블 추출
 */
function detectPrimaryTable(normalizedUpper, op) {
    // CTE 본문이 아니라 바깥 문장에서 대상을 찾는다.
    return detectPrimaryTableOf(outerStatement(normalizedUpper), op);
}

/**
 * 허용목록 파일을 로드
 * @param {string} filePath - sql-allowlist.json 경로
 * @returns {object|null}
 */
export async function loadAllowlist(filePath) {
    try {
        const content = await fs.readFile(filePath, 'utf-8');
        return JSON.parse(content);
    } catch {
        return null;
    }
}
