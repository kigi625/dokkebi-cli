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

// dokkebi 내부 시스템 테이블 — 항상 허용
const SYSTEM_TABLES = [
    '_dokkebi_errors',
    '_dokkebi_requests',
    '_dokkebi_security',
    '_dokkebi_sessions',
    '_dokkebi_ephemeral_keys',
    '_dokkebi_nonces',
    'sqlite_master',
];

const SYSTEM_OPS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE'];

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

    // 시스템 테이블 추가
    for (const sysTable of SYSTEM_TABLES) {
        tables.push({ name: sysTable, ops: [...SYSTEM_OPS] });
    }

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
    // 식별자 매칭: schema.name 형태를 허용하고, 따옴표/백틱으로 둘러싼 형태도 허용
    const ident = `["'` + '`' + `]?([a-zA-Z_][\\w]*(?:\\.[a-zA-Z_][\\w]*)?)["'` + '`' + `]?`;
    const keywords = ['FROM', 'JOIN', 'INTO', 'UPDATE'];
    for (const kw of keywords) {
        const re = new RegExp(`\\b${kw}\\s+${ident}`, 'gi');
        let m;
        while ((m = re.exec(normalized)) !== null) {
            const name = m[1];
            // 스키마 분리: public.users → users
            const parts = name.split('.');
            const baseName = parts[parts.length - 1];
            if (cteNames.has(baseName.toLowerCase())) continue;
            tables.add(baseName);
        }
    }
    return [...tables];
}

/**
 * 기본 연산 판별 (첫 키워드)
 */
function detectPrimaryOp(normalizedUpper) {
    const head = normalizedUpper.trimStart();
    if (head.startsWith('SELECT'))   return 'SELECT';
    if (head.startsWith('INSERT'))   return 'INSERT';
    if (head.startsWith('UPDATE'))   return 'UPDATE';
    if (head.startsWith('DELETE'))   return 'DELETE';
    if (head.startsWith('WITH'))     return 'SELECT';  // CTE는 최종적으로 SELECT/INSERT/UPDATE/DELETE 중 하나
    if (head.startsWith('CREATE TABLE')) return 'CREATE';
    return null;
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

    // 2) 다중 문장 차단 (항상 수행)
    if (hasMultipleStatements(normalized)) {
        return { allowed: false, reason: '다중 SQL 문장은 허용되지 않습니다.' };
    }

    // 3) 위험 토큰 차단 (항상 수행)
    const danger = containsDangerousToken(upper);
    if (danger) {
        return { allowed: false, reason: `위험한 SQL 토큰 감지: ${danger}` };
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

    // 허용 테이블 맵 (CREATE 참조 검증 + 일반 검증 모두에서 사용)
    const allowedMap = new Map();
    for (const t of allowlist.tables) allowedMap.set(t.name.toLowerCase(), t);

    // 5) CREATE TABLE은 시스템 테이블(_dokkebi_*)만 허용
    if (op === 'CREATE') {
        // CREATE TABLE [IF NOT EXISTS] [schema.]name 형태의 테이블명 추출
        // extractAllTables 는 FROM/JOIN/INTO/UPDATE 만 보므로 CREATE는 별도 추출 필요
        const ident = `["'` + '`' + `]?([a-zA-Z_][\\w]*(?:\\.[a-zA-Z_][\\w]*)?)["'` + '`' + `]?`;
        const createRe = new RegExp(`\\bCREATE\\s+(?:TEMP(?:ORARY)?\\s+)?TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?${ident}`, 'i');
        const m = normalized.match(createRe);
        if (!m) {
            return { allowed: false, reason: 'CREATE TABLE 구문에서 테이블명을 추출할 수 없습니다.' };
        }
        const rawName = m[1];
        const baseName = rawName.split('.').pop().toLowerCase();
        if (!baseName.startsWith('_dokkebi_')) {
            return { allowed: false, reason: `CREATE TABLE은 _dokkebi_* 시스템 테이블만 허용됩니다. (요청: ${rawName})` };
        }
        // 추가로 CREATE 바디 안에서 FROM/JOIN 등으로 다른 테이블 참조가 있는지 (CREATE TABLE ... AS SELECT ...)
        const referenced = extractAllTables(upper).map(t => t.toLowerCase());
        for (const t of referenced) {
            if (t === baseName) continue;
            if (!allowedMap.get(t)) {
                return { allowed: false, reason: `CREATE TABLE 중 허용되지 않은 참조 테이블: "${t}"` };
            }
        }
        return { allowed: true };
    }

    // 6) 모든 테이블 참조 추출 → 전부 allowlist에 있어야 함
    const allTables = extractAllTables(upper).map(t => t.toLowerCase());
    // CTE 전용 쿼리(WITH ... SELECT * FROM cte)의 경우 외부 테이블 참조가 0개일 수 있음
    // → upper가 WITH로 시작하면 0개도 허용 (CTE 이름만 참조)
    if (allTables.length === 0 && !upper.trimStart().startsWith('WITH')) {
        return { allowed: false, reason: 'SQL에서 테이블명을 추출할 수 없습니다.' };
    }

    for (const t of allTables) {
        const entry = allowedMap.get(t);
        if (!entry) {
            return {
                allowed: false,
                reason: `허용되지 않은 테이블: "${t}" (등록된 테이블: ${[...allowedMap.keys()].filter(n => !n.startsWith('_dokkebi_') && n !== 'sqlite_master').join(', ')})`,
            };
        }
        // 주 연산(op) 확인은 기본 대상 테이블에 한해 수행하는 것이 일반적이지만,
        // 여기서는 "참조된 모든 테이블에 대해 최소 SELECT 이상" 으로 검증 → UNION/JOIN이 INSERT-only 테이블을 노출하지 못하도록
        if (op === 'SELECT' && !entry.ops.includes('SELECT')) {
            return { allowed: false, reason: `테이블 "${t}"에 대한 SELECT가 허용되지 않습니다.` };
        }
    }

    // 7) 주 연산이 대상 테이블에 허용되는지 확인 (INSERT/UPDATE/DELETE)
    // 기본 대상은 INSERT/UPDATE의 경우 첫 테이블, DELETE의 경우 FROM 다음 첫 테이블
    // CTE 이름은 실제 테이블이 아니므로 primary 검증에서 스킵
    const cteNames = extractCteNames(upper);
    const primaryTable = detectPrimaryTable(upper, op);
    if (primaryTable && !cteNames.has(primaryTable.toLowerCase())) {
        const entry = allowedMap.get(primaryTable.toLowerCase());
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
    const ident = `["'` + '`' + `]?([A-Z_][\\w]*(?:\\.[A-Z_][\\w]*)?)["'` + '`' + `]?`;
    const patterns = {
        SELECT: new RegExp(`\\bFROM\\s+${ident}`),
        INSERT: new RegExp(`\\bINTO\\s+${ident}`),
        UPDATE: new RegExp(`\\bUPDATE\\s+${ident}`),
        DELETE: new RegExp(`\\bFROM\\s+${ident}`),
    };
    const p = patterns[op];
    if (!p) return null;
    const m = normalizedUpper.match(p);
    if (!m) return null;
    const parts = m[1].split('.');
    return parts[parts.length - 1];
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
