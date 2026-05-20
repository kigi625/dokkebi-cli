// @dokkebi-module: policyInference
// ──────────────────────────────────────────────────────────────
// Policy Inference — convention 기반 자동 추론 엔진
//
// 목적:
//   Tenant Policy / Authorization Policy 는 본질적으로 "어느 테이블에
//   어떤 tenant 컬럼이 있는가" 와 "어느 연산에 어떤 역할이 필요한가" 를
//   선언하는 작업이다. 이 정보는 **이미 모델 DSL (table(...)) 과 컨트롤러의
//   SQL 리터럴** 에 충분히 남아 있으므로 빌드 타임에 정적 분석으로 추출해
//   dokkebi.config.js 의 수동 작성량을 크게 줄일 수 있다.
//
// 추론 전략:
//   1) 모델 스캔 — backend/models/**.ts 의 table('name', { col(...) }) 블록을
//      균형 괄호 매칭으로 추출하고, 컬럼명 휴리스틱으로 tenant 컬럼 감지.
//   2) 컨트롤러 SQL 스캔 — queryScanner 결과에서 (op, table) 쌍 수집.
//   3) 규칙 생성 — 각 (op, table) 에 대해 기본 스펙 배정 (SELECT=public,
//      INSERT=auth, UPDATE/DELETE=auth 또는 민감 테이블이면 roles:['admin']).
//   4) Merge — 사용자가 config 에 명시한 값이 **항상 우선**.
//
// Fail-mode:
//   tenant 컬럼을 추론하지 못한 테이블 → `mode: 'none'` 으로 등록 (공개로 간주)
//   + console.warn 으로 빌드 로그에 표시. 사용자는 로그를 보고 config 에 직접
//   지정하여 보호 대상으로 승격할 수 있다.
//
// 핵심 원칙:
//   - 추론은 "편의성 레이어" 일 뿐, 보안 결정은 사용자 명시값이 최우선.
//   - 추론 결과를 **반드시 로그로 노출** 해 blind acceptance 를 막는다.
//   - 추론 결과는 `dok policy:scaffold` 로 dokkebi.config.js 에 영속화 가능.
// ──────────────────────────────────────────────────────────────

import fs from 'fs/promises';
import path from 'path';

// ─────────────────────────────────────────────────────────────
// 규약 (convention) — 튜닝 가능한 상수
// ─────────────────────────────────────────────────────────────

// 테이블의 tenant 컬럼 후보 (우선순위 순)
// ── 먼저 정확 매칭(exact) 후보 → 이후 *_token 일반 패턴 fallback
const TENANT_COLUMN_CANDIDATES = [
    'user_id',
    'owner_id',
    'author_id',
    'tenant_id',
    'workspace_id',
    'account_id',
    'org_id',
    'organization_id',
    'created_by',
    'creator_id',
    'creator_token',
    'sender_token',
    'author_token',
    'owner_token',
    'subscriber_token',
    'collaborator_token',
    'member_token',
    'participant_token',
];

// "*_token" 일반 패턴 중 tenant 가 **아닌** prefix (거짓양성 차단)
// 예: password_token, refresh_token, access_token 등은 tenant 가 아니라 인증 토큰
const NON_TENANT_TOKEN_PREFIXES = new Set([
    'password', 'reset', 'refresh', 'access', 'id', 'csrf', 'api', 'webhook',
    'verification', 'invite', 'activation', 'magic', 'session', 'bearer',
    'confirmation', 'oauth', 'jwt',
]);

// 단일 'token' 컬럼이 있을 때 테넌트로 간주할 테이블 접미사 관례
// (예: push_subscriptions, event_subscribers, user_sessions 등)
const TOKEN_OWNED_TABLE_SUFFIXES = [
    '_subscriptions', '_subscribers', '_sessions', '_tokens', '_devices',
    '_registrations', '_endpoints',
];

// 공유/참조 테이블 관례 — tenant 컬럼을 찾지 못해도 "공유 테이블" 로 간주 (경고 제거)
// 이 테이블들은 대개 전역 읽기 전용 참조 데이터다.
const SHARED_TABLE_NAMES = new Set([
    'templates', 'categories', 'tags', 'labels', 'settings', 'metadata',
    'configs', 'configurations', 'countries', 'languages', 'currencies',
    'timezones', 'feature_flags', 'plans', 'prices', 'translations',
]);

// 민감 테이블 — UPDATE/DELETE 기본 권한을 roles:['admin'] 으로 상승
const SENSITIVE_TABLES = new Set([
    'users',
    'roles',
    'permissions',
    'user_roles',
    'payments',
    'billing',
    'subscriptions',
    'api_keys',
    'webhooks',
]);

// 본인 프로필 테이블 — tenant 컬럼이 'id' (자기 자신)
const SELF_TENANT_TABLES = new Set(['users']);

// self-tenant 테이블의 관례적 세션 클레임 이름.
//   users.id 는 로그인 흐름상 세션에는 'user_id' 로 저장되는 게 관례이므로,
//   scaffold 는 users 의 sessionClaim 을 'user_id' 로 지정 (엔진이 자동 매핑).
const SELF_TENANT_SESSION_CLAIM = 'user_id';

// 시스템(내부) 테이블 접두사 — 추론에서 제외 (SQL Allowlist 전담)
const SYSTEM_TABLE_PREFIX = '_dokkebi_';

// SQLite 엔진 내장 메타 테이블 — 추론 제외
const SQLITE_INTERNAL_TABLES = new Set([
    'sqlite_master',
    'sqlite_sequence',
    'sqlite_stat1',
    'sqlite_stat4',
    'sqlite_temp_master',
]);

const MODEL_ROOTS = [
    'backend/models',
    'src/backend/models',
    'server/models',
    'backend',
    'src/backend',
    'src/models',
    'models',
];

const MODEL_EXTS = new Set(['.ts', '.tsx', '.js', '.mjs', '.mts', '.cts']);

// ─────────────────────────────────────────────────────────────
// 모델 파일 파싱 — table('X', { col('c', ...), ... }) 블록 추출
// ─────────────────────────────────────────────────────────────

/**
 * 소스에서 table('name', { ... }, { ...options }) 호출을 찾아
 * { name, columns[], options? } 배열로 반환.
 * 중첩된 {}, (), 문자열, 주석을 고려한 균형 매칭.
 * 최소한의 파싱으로 ts-morph 같은 AST 의존을 피한다.
 *
 * options 추출 (v6+):
 *   - tenant: 'col' | { column: 'col', claim?: '...', mode?: '...' }
 *   - access: { read?: spec, write?: spec, delete?: spec, all?: spec }
 *     spec: { public: true } | { auth: true } | { roles: [...] } | { deny: true }
 *
 * 옵션 본문은 정확한 JS 평가 없이 정적 패턴으로만 추출한다.
 * 사용자가 변수/함수 호출로 옵션을 만들면 추출되지 않음 — 이 경우
 * dokkebi.config.js 에 명시 권장.
 */
export function extractTableDefinitions(source) {
    const results = [];
    const { sanitized, stringRanges } = _tokenizeForScan(source);
    const re = /\btable\s*\(\s*(['"`])([A-Za-z_][\w]*)\1\s*,\s*\{/g;
    let m;
    while ((m = re.exec(sanitized)) !== null) {
        // table( 자체가 문자열 리터럴 내부면 스킵
        if (_inAnyRange(stringRanges, m.index)) continue;
        const tableName = m[2];
        const openIdx = sanitized.indexOf('{', m.index + m[0].length - 1);
        if (openIdx < 0) continue;
        const closeIdx = _findBalancedClose(sanitized, openIdx, '{', '}');
        if (closeIdx < 0) continue;
        const body = sanitized.slice(openIdx + 1, closeIdx);
        const columns = _extractColumns(body);

        // 세 번째 인자(options) 추출 — `, {` 까지 스캔
        let options = null;
        let scan = closeIdx + 1;
        while (scan < sanitized.length && /\s/.test(sanitized[scan])) scan++;
        if (sanitized[scan] === ',') {
            scan++;
            while (scan < sanitized.length && /\s/.test(sanitized[scan])) scan++;
            if (sanitized[scan] === '{') {
                const optClose = _findBalancedClose(sanitized, scan, '{', '}');
                if (optClose > scan) {
                    const optBody = sanitized.slice(scan + 1, optClose);
                    options = _extractTableOptions(optBody);
                }
            }
        }

        const def = { name: tableName, columns };
        if (options) def.options = options;
        results.push(def);
    }
    return results;
}

/**
 * table(...) 의 세 번째 인자 옵션 객체에서 tenant / access 를 추출.
 * 정적 패턴 매칭만 사용 — 변수 참조나 함수 호출은 무시.
 */
function _extractTableOptions(body) {
    const out = {};

    // tenant: 'col' 또는 tenant: { column: 'col', claim: '...', mode: '...' }
    const tenantStr = body.match(/\btenant\s*:\s*(['"`])([A-Za-z_][\w]*)\1/);
    if (tenantStr) {
        out.tenant = { column: tenantStr[2], mode: 'enforce' };
    } else {
        const tenantObjOpen = body.search(/\btenant\s*:\s*\{/);
        if (tenantObjOpen >= 0) {
            const open = body.indexOf('{', tenantObjOpen);
            const close = _findBalancedClose(body, open, '{', '}');
            if (close > open) {
                const inner = body.slice(open + 1, close);
                const colM = inner.match(/\bcolumn\s*:\s*(['"`])([A-Za-z_][\w]*)\1/);
                const claimM = inner.match(/\bclaim\s*:\s*(['"`])([A-Za-z_][\w]*)\1/);
                const modeM = inner.match(/\bmode\s*:\s*(['"`])([A-Za-z_][\w]*)\1/);
                if (colM) {
                    out.tenant = {
                        column: colM[2],
                        claim: claimM ? claimM[2] : undefined,
                        mode: modeM ? modeM[2] : 'enforce',
                    };
                }
            }
        }
    }

    // access: { read: {...}, write: {...}, delete: {...}, all: {...} }
    const accessOpen = body.search(/\baccess\s*:\s*\{/);
    if (accessOpen >= 0) {
        const open = body.indexOf('{', accessOpen);
        const close = _findBalancedClose(body, open, '{', '}');
        if (close > open) {
            const accessBody = body.slice(open + 1, close);
            const access = {};
            for (const verb of ['read', 'write', 'delete', 'all', 'create']) {
                const verbOpen = accessBody.search(new RegExp(`\\b${verb}\\s*:\\s*\\{`));
                if (verbOpen < 0) continue;
                const vOpen = accessBody.indexOf('{', verbOpen);
                const vClose = _findBalancedClose(accessBody, vOpen, '{', '}');
                if (vClose <= vOpen) continue;
                const vBody = accessBody.slice(vOpen + 1, vClose);
                const spec = _parseAccessSpec(vBody);
                if (spec) access[verb] = spec;
            }
            if (Object.keys(access).length > 0) out.access = access;
        }
    }

    return Object.keys(out).length > 0 ? out : null;
}

function _parseAccessSpec(body) {
    if (/\bdeny\s*:\s*true\b/.test(body)) return { deny: true };
    if (/\bpublic\s*:\s*true\b/.test(body)) return { public: true };
    // roles: ['admin', 'premium']
    const rolesM = body.match(/\broles\s*:\s*\[([^\]]*)\]/);
    if (rolesM) {
        const list = rolesM[1].match(/(['"`])([^'"`]+)\1/g) || [];
        const roles = list.map((s) => s.slice(1, -1)).filter(Boolean);
        if (roles.length > 0) return { roles };
    }
    if (/\bauth\s*:\s*true\b/.test(body)) return { auth: true };
    return null;
}

function _extractColumns(body) {
    // `<jsKey>: col('<sqlName>', t.xxx()[.yyy()...])` 형태에서 SQL 컬럼명 추출.
    // jsKey 와 sqlName 은 보통 snake/camel 쌍이며, 우리는 SQL 컬럼명을 신뢰한다.
    const cols = [];
    const re = /\bcol\s*\(\s*(['"`])([A-Za-z_][\w]*)\1\s*,/g;
    let m;
    while ((m = re.exec(body)) !== null) {
        cols.push(m[2]);
    }
    return cols;
}

// ─────────────────────────────────────────────────────────────
// Tenant 컬럼 추론
// ─────────────────────────────────────────────────────────────

/**
 * 주어진 테이블 정의에 대해 tenant 컬럼 후보를 반환.
 * @returns {{ tenantColumn: string, reason: string } | null}
 */
export function inferTenantColumn(tableDef, opts = {}) {
    const name = String(tableDef.name || '').toLowerCase();
    const cols = tableDef.columns || [];
    const colSet = new Set(cols.map((c) => c.toLowerCase()));

    if (SELF_TENANT_TABLES.has(name) && colSet.has('id')) {
        return { tenantColumn: 'id', reason: 'self-tenant(users)' };
    }

    // 1) 정확 매칭 후보
    for (const candidate of TENANT_COLUMN_CANDIDATES) {
        if (colSet.has(candidate)) {
            return { tenantColumn: candidate, reason: 'convention' };
        }
    }

    // 2) 테이블 접미사가 TOKEN_OWNED_TABLE_SUFFIXES 와 일치 + 단일 'token' 컬럼 존재
    //    이 경우 테이블 설계상 `token` 이 "주" tenant 식별자이므로 다른 *_token 컬럼보다 우선.
    //    예: push_subscriptions.token (app_push_token 보다 token 이 주 식별자)
    if (colSet.has('token')) {
        for (const suffix of TOKEN_OWNED_TABLE_SUFFIXES) {
            if (name.endsWith(suffix)) {
                return { tenantColumn: 'token', reason: `token-owned-table(${suffix})` };
            }
        }
    }

    // 3) *_token 일반 패턴 — 거짓양성 prefix 는 제외
    //    collaborator_token / author_token / subscriber_token 등이 자동 감지됨
    for (const col of cols) {
        const lc = col.toLowerCase();
        if (!lc.endsWith('_token')) continue;
        const prefix = lc.slice(0, -'_token'.length);
        if (NON_TENANT_TOKEN_PREFIXES.has(prefix)) continue;
        return { tenantColumn: lc, reason: `token-pattern(${prefix})` };
    }

    return null;
}

/**
 * 테이블 하나에 대한 세션 클레임 이름을 추론한다.
 *
 * 규칙:
 *   - self-tenant 테이블 (users.id) → 'user_id'
 *     (로그인 흐름상 세션에는 관례적으로 'user_id' 키로 user.id 가 저장됨)
 *   - 그 외 → tenantColumn 과 동일한 이름
 *     (notofly 의 creator_token / sender_token / token 등은 세션에 같은 이름으로 저장
 *      — 프론트에서 ctx.setSessionTenant({ creator_token: hashValue }) 한 줄로 연동)
 *
 * 엔진의 _resolveTenantClaim 이 table > global > tenantCol 순서로 fallback 하므로
 * 여기서 명시하지 않아도 기본 동작은 맞지만, scaffold 출력에 **명시**해 두어야
 * 사용자가 "어떤 이름을 세션에 넣어야 하는지" 를 바로 읽어낼 수 있다.
 *
 * @param {string} tableName
 * @param {{ tenantColumn: string, reason: string }} inferred
 * @returns {string}
 */
export function _inferSessionClaim(tableName, inferred) {
    if (inferred.reason && inferred.reason.startsWith('self-tenant')) {
        return SELF_TENANT_SESSION_CLAIM;
    }
    return inferred.tenantColumn;
}

/**
 * 테이블이 "공유/참조" 테이블인지 추론.
 * - SHARED_TABLE_NAMES 관례 이름이거나
 * - tenant 후보도 없고 *_id FK 도 없는 순수 참조 테이블이면 공유로 간주.
 *
 * 공유 테이블은 tenant 경고를 발생시키지 않는다. (배포 시 "왜 안 막히지?" 노이즈 제거)
 * Authorization 레벨에서 SELECT=public / 쓰기=admin 으로 자동 분류된다.
 */
export function isSharedTable(tableDef) {
    const name = String(tableDef.name || '').toLowerCase();
    const cols = tableDef.columns || [];
    if (SHARED_TABLE_NAMES.has(name)) return true;

    // 보수적: *_id FK 가 하나도 없고 tenant 후보도 없는 테이블은 참조 테이블로 간주
    const hasFk = cols.some((c) => {
        const lc = c.toLowerCase();
        return lc.endsWith('_id') && lc !== 'id';
    });
    const hasTenantLike = cols.some((c) => {
        const lc = c.toLowerCase();
        return (
            TENANT_COLUMN_CANDIDATES.includes(lc) ||
            (lc.endsWith('_token') && !NON_TENANT_TOKEN_PREFIXES.has(lc.slice(0, -'_token'.length))) ||
            lc === 'token'
        );
    });
    return !hasFk && !hasTenantLike;
}

// ─────────────────────────────────────────────────────────────
// Authorization 규칙 추론
// ─────────────────────────────────────────────────────────────

/**
 * (op, table) 쌍에 대한 기본 규칙 스펙을 반환. null 이면 규칙 생성 생략.
 */
export function defaultAuthzSpec(op, table) {
    const opU = String(op || '').toUpperCase();
    const tblL = String(table || '').toLowerCase();

    if (!tblL || tblL.startsWith(SYSTEM_TABLE_PREFIX)) return null;
    if (SQLITE_INTERNAL_TABLES.has(tblL)) return null;

    if (opU === 'SELECT') return { public: true };
    if (opU === 'INSERT') return { auth: true };
    if (opU === 'UPDATE' || opU === 'DELETE') {
        if (SENSITIVE_TABLES.has(tblL)) return { roles: ['admin'] };
        return { auth: true };
    }
    // CREATE / DDL 은 SQL Allowlist 전담 — 인가 정책 규칙 생략
    return null;
}

// ─────────────────────────────────────────────────────────────
// 메인 엔트리 — 모델 + SQL 스캔 결과로 추론 결과 생성
// ─────────────────────────────────────────────────────────────

/**
 * @param {string} projectDir
 * @param {{
 *   opTableStats?: Map<string, { op: string, table: string, count: number }>,
 *   modelRoots?: string[],
 *   verbose?: boolean,
 * }} [opts]
 * @returns {Promise<{
 *   tables: Record<string, { tenantColumn?: string, mode: string, _inferred: true, _reason?: string }>,
 *   rules: Record<string, { public?: boolean, auth?: boolean, roles?: string[], deny?: boolean, _inferred: true }>,
 *   warnings: string[],
 *   scannedModelFiles: number,
 *   detectedTables: string[],
 *   undetectedTables: string[],
 * }>}
 */
export async function inferPolicyFromProject(projectDir, opts = {}) {
    const roots = opts.modelRoots || MODEL_ROOTS;
    const verbose = !!opts.verbose;

    const tableDefs = await _collectAllModels(projectDir, roots);
    const scannedFiles = tableDefs._scannedFiles;
    const allDefs = tableDefs.defs;

    const tables = {};
    const warnings = [];
    const detectedTables = [];
    const undetectedTables = [];
    const sharedTables = [];
    // table(...) 의 access 옵션에서 추출된 명시적 권한 규칙
    // 키: "OP:table" — 'read' → SELECT / 'write' → INSERT,UPDATE / 'delete' → DELETE / 'all' → 모든 op
    const explicitAuthzRules = {};

    for (const def of allDefs) {
        if (def.name.startsWith(SYSTEM_TABLE_PREFIX)) continue;

        // ── DSL 명시 옵션 우선 ─────────────────────────────────
        // table('x', { ... }, { tenant: 'user_id', access: {...} }) 가 있으면
        // convention 추론 대신 이 값을 사용.
        const explicitTenant = def.options && def.options.tenant;
        const explicitAccess = def.options && def.options.access;

        if (explicitTenant && explicitTenant.column) {
            tables[def.name] = {
                tenantColumn: explicitTenant.column,
                mode: explicitTenant.mode || 'enforce',
                sessionClaim: explicitTenant.claim || explicitTenant.column,
                _inferred: true,
                _reason: 'dsl-explicit-tenant',
            };
            detectedTables.push(def.name);
            if (verbose) {
                console.log(`[policyInference]   ✓ ${def.name}.${explicitTenant.column} (DSL 명시)`);
            }
        } else if (def.options && def.options.tenant === false) {
            // tenant: false → 명시적 공개 테이블
            tables[def.name] = {
                mode: 'none',
                shared: true,
                _inferred: true,
                _reason: 'dsl-explicit-public',
            };
            sharedTables.push(def.name);
        } else {
            const inferred = inferTenantColumn(def);
            if (inferred) {
                tables[def.name] = {
                    tenantColumn: inferred.tenantColumn,
                    mode: 'enforce',
                    sessionClaim: _inferSessionClaim(def.name, inferred),
                    _inferred: true,
                    _reason: inferred.reason,
                };
                detectedTables.push(def.name);
                if (verbose) {
                    console.log(`[policyInference]   ✓ ${def.name}.${inferred.tenantColumn} (${inferred.reason})`);
                }
            } else if (isSharedTable(def)) {
                // 공유/참조 테이블 — 경고 없이 명시적으로 shared 로 분류
                tables[def.name] = {
                    mode: 'none',
                    shared: true,
                    _inferred: true,
                    _reason: 'shared-reference-table',
                };
                sharedTables.push(def.name);
                if (verbose) {
                    console.log(`[policyInference]   ◎ ${def.name} (shared reference table)`);
                }
            } else {
                // tenant 컬럼 미감지 → 공개 테이블 취급 (mode: none) + 경고
                tables[def.name] = {
                    mode: 'none',
                    _inferred: true,
                    _reason: 'no-tenant-column-detected',
                };
                undetectedTables.push(def.name);
                warnings.push(
                    `[tenant] '${def.name}' 테이블에서 tenant 컬럼을 추론하지 못했습니다. ` +
                    `사용자 격리가 필요하면 dokkebi.config.js 의 policy.tables.${def.name}.tenantColumn 에 명시하세요.`
                );
            }
        }

        // ── DSL access 옵션을 명시적 인가 규칙으로 등록 ─────────
        // table('x', { ... }, { access: { read: { roles: ['premium'] }, ... } })
        //   → "SELECT:x" / "INSERT:x" / "UPDATE:x" / "DELETE:x" 규칙으로 변환
        if (explicitAccess) {
            _expandAccessToRules(def.name, explicitAccess, explicitAuthzRules);
        }
    }

    // Authorization rules — (op, table) 쌍 기반
    const rules = {};
    const opTableStats = opts.opTableStats || new Map();
    const seenKeys = new Set();
    for (const stat of opTableStats.values()) {
        if (!stat.op || !stat.table) continue;
        const key = `${String(stat.op).toUpperCase()}:${String(stat.table).toLowerCase()}`;
        if (seenKeys.has(key)) continue;
        seenKeys.add(key);
        const spec = defaultAuthzSpec(stat.op, stat.table);
        if (!spec) continue;
        rules[key] = { ...spec, _inferred: true };
    }

    // 명시적 access 규칙은 convention 보다 우선 (덮어쓰기)
    for (const [key, spec] of Object.entries(explicitAuthzRules)) {
        rules[key] = { ...spec, _inferred: true, _explicit: true };
    }

    return {
        tables,
        rules,
        warnings,
        scannedModelFiles: scannedFiles,
        detectedTables,
        undetectedTables,
        sharedTables,
    };
}

/**
 * DSL 의 access 옵션을 (op, table) 규칙 키로 확장.
 *   read   → SELECT
 *   write  → INSERT, UPDATE
 *   delete → DELETE
 *   create → CREATE
 *   all    → 모든 op (위 규칙들이 명시되지 않았을 때만 적용)
 */
function _expandAccessToRules(tableName, access, target) {
    const tbl = String(tableName).toLowerCase();
    const set = (op, spec) => {
        if (!spec) return;
        target[`${op}:${tbl}`] = spec;
    };
    if (access.read)   set('SELECT', access.read);
    if (access.write) {
        set('INSERT', access.write);
        set('UPDATE', access.write);
    }
    if (access.delete) set('DELETE', access.delete);
    if (access.create) set('CREATE', access.create);
    if (access.all) {
        for (const op of ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE']) {
            const k = `${op}:${tbl}`;
            if (target[k] === undefined) target[k] = access.all;
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Merge — 사용자 명시값 > 추론값
// ─────────────────────────────────────────────────────────────

/**
 * 사용자 config 와 추론 결과를 병합. 사용자 명시값은 **항상 우선**.
 *
 * 기본 정책(안전 우선):
 *   - build-time 에서 자동 추론된 값은 **config 에 병합하지 않습니다**.
 *     대신 추론 결과만 반환해 로그로 노출하고, 사용자는
 *     `dok policy:scaffold` 또는 직접 편집으로 영속화합니다.
 *   - 명시적 opt-in: userConfig.policy.autoApply: true 또는
 *                   userConfig.authorization.autoApply: true 이면
 *                   build-time 병합을 활성 (기존 개발 경험 개선).
 *
 * @param {any} userConfig        dokkebi.config.js 의 전체 config 객체
 * @param {{ tables: object, rules: object }} inferred
 * @returns {{
 *   merged: any,                 // 사용자 config 의 얕은 복제 (autoApply 가 true 일 때만 병합)
 *   policyAdds: string[],        // 추론에서 새로 추가된 테이블 이름 (autoApply 시)
 *   authzAdds: string[],         // 추론에서 새로 추가된 규칙 키 (autoApply 시)
 *   policyAutoSuggestions: string[],  // autoApply 가 아닐 때 제안만 (로그용)
 *   authzAutoSuggestions: string[],
 * }}
 */
export function mergeInferredIntoConfig(userConfig, inferred) {
    const merged = { ...(userConfig || {}) };
    const policyAdds = [];
    const authzAdds = [];
    const policyAutoSuggestions = [];
    const authzAutoSuggestions = [];

    // ── Tenant Policy ──────────────────────────────────────────
    const userPolicy = merged.policy;
    const userExplicitDisabled = userPolicy && userPolicy.enabled === false;
    const policyAutoApply = !!(userPolicy && userPolicy.autoApply === true);

    if (!userExplicitDisabled && inferred && inferred.tables) {
        for (const [tname, cfg] of Object.entries(inferred.tables)) {
            if (cfg.mode !== 'enforce' || !cfg.tenantColumn) continue;
            const userTables = (userPolicy && userPolicy.tables) || {};
            if (userTables[tname] !== undefined) continue; // 사용자 명시 우선
            policyAutoSuggestions.push(tname);
        }

        if (policyAutoApply && policyAutoSuggestions.length > 0) {
            const nextPolicy = { ...(userPolicy || {}) };
            // autoApply 는 사용자가 위험을 인지하고 켠 것이므로 inject + strict 로 강하게
            if (nextPolicy.enabled === undefined) nextPolicy.enabled = true;
            if (!nextPolicy.mode) nextPolicy.mode = 'verify';
            const userTables = { ...(nextPolicy.tables || {}) };
            for (const tname of policyAutoSuggestions) {
                const cfg = inferred.tables[tname];
                userTables[tname] = { tenantColumn: cfg.tenantColumn, mode: 'enforce' };
                policyAdds.push(tname);
            }
            nextPolicy.tables = userTables;
            merged.policy = nextPolicy;
        }
    }

    // ── Authorization Policy ───────────────────────────────────
    const userAuthz = merged.authorization;
    const userAuthzDisabled = userAuthz && userAuthz.enabled === false;
    const authzAutoApply = !!(userAuthz && userAuthz.autoApply === true);

    if (!userAuthzDisabled && inferred && inferred.rules) {
        for (const [key, _spec] of Object.entries(inferred.rules)) {
            const userRules = (userAuthz && userAuthz.rules) || {};
            if (userRules[key] !== undefined) continue;
            authzAutoSuggestions.push(key);
        }

        if (authzAutoApply && authzAutoSuggestions.length > 0) {
            const nextAuthz = { ...(userAuthz || {}) };
            if (nextAuthz.enabled === undefined) nextAuthz.enabled = true;
            if (!nextAuthz.mode) nextAuthz.mode = 'warn';
            const userRules = { ...(nextAuthz.rules || {}) };
            for (const key of authzAutoSuggestions) {
                const { _inferred, ...pure } = inferred.rules[key];
                userRules[key] = pure;
                authzAdds.push(key);
            }
            if (userRules['*'] === undefined) {
                userRules['*'] = { public: true };
                if (!authzAdds.includes('*')) authzAdds.push('*');
            }
            nextAuthz.rules = userRules;
            merged.authorization = nextAuthz;
        }
    }

    return { merged, policyAdds, authzAdds, policyAutoSuggestions, authzAutoSuggestions };
}

// ─────────────────────────────────────────────────────────────
// 내부 유틸
// ─────────────────────────────────────────────────────────────

async function _collectAllModels(projectDir, roots) {
    const allDefs = [];
    const seen = new Set();
    let scannedFiles = 0;

    const ignoreDirs = new Set([
        'node_modules', '.git', '.dokkebi', 'dist', 'build', 'out',
        '.next', '.nuxt', '.vite', '.cache', 'coverage', '.turbo',
    ]);

    for (const root of roots) {
        const abs = path.join(projectDir, root);
        let exists = true;
        try { await fs.access(abs); } catch { exists = false; }
        if (!exists) continue;

        await _walk(abs, ignoreDirs, async (file) => {
            if (seen.has(file)) return;
            seen.add(file);
            if (!MODEL_EXTS.has(path.extname(file))) return;
            let content;
            try { content = await fs.readFile(file, 'utf-8'); } catch { return; }
            // 성능: 파일 안에 "table(" 문자열이 없으면 스킵
            if (content.indexOf('table(') < 0 && content.indexOf('table (') < 0) return;
            const defs = extractTableDefinitions(content);
            if (defs.length > 0) {
                scannedFiles++;
                for (const d of defs) {
                    // 같은 테이블명이 여러 파일에 있으면 첫 번째만 채택 (경고 생략)
                    if (allDefs.some((existing) => existing.name === d.name)) continue;
                    allDefs.push(d);
                }
            }
        });
    }

    return { defs: allDefs, _scannedFiles: scannedFiles };
}

async function _walk(dir, ignoreDirs, visit) {
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); }
    catch { return; }
    for (const entry of entries) {
        if (ignoreDirs.has(entry.name)) continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) await _walk(full, ignoreDirs, visit);
        else await visit(full);
    }
}

/**
 * 주석을 제거하고, 소스 내 문자열 리터럴의 시작/끝 인덱스 목록을 반환.
 * 반환 sanitized 는 원본과 길이 보존 (주석만 공백 치환). 따라서 인덱스는 원본과 호환.
 */
function _tokenizeForScan(source) {
    let out = '';
    const stringRanges = [];
    const n = source.length;
    let i = 0;
    while (i < n) {
        const ch = source[i];
        const next = source[i + 1];
        if (ch === '/' && next === '/') {
            while (i < n && source[i] !== '\n') { out += ' '; i++; }
            continue;
        }
        if (ch === '/' && next === '*') {
            out += '  '; i += 2;
            while (i < n && !(source[i] === '*' && source[i + 1] === '/')) {
                out += source[i] === '\n' ? '\n' : ' ';
                i++;
            }
            if (i < n) { out += '  '; i += 2; }
            continue;
        }
        if (ch === "'" || ch === '"') {
            const start = i;
            out += ch; i++;
            while (i < n) {
                const c = source[i];
                if (c === '\\') { out += c + (source[i + 1] || ''); i += 2; continue; }
                out += c; i++;
                if (c === ch) break;
                if (c === '\n') { /* 이미 out 에 포함 */ }
            }
            stringRanges.push([start, i]);
            continue;
        }
        if (ch === '`') {
            const start = i;
            out += '`'; i++;
            while (i < n) {
                const c = source[i];
                if (c === '\\') { out += c + (source[i + 1] || ''); i += 2; continue; }
                if (c === '`') { out += '`'; i++; break; }
                if (c === '$' && source[i + 1] === '{') {
                    // 템플릿 interpolation — 실제 코드이므로 그대로 보존
                    out += '${'; i += 2;
                    let depth = 1;
                    while (i < n && depth > 0) {
                        const cc = source[i];
                        if (cc === '{') depth++;
                        else if (cc === '}') depth--;
                        out += cc; i++;
                    }
                    continue;
                }
                out += c; i++;
            }
            stringRanges.push([start, i]);
            continue;
        }
        out += ch; i++;
    }
    return { sanitized: out, stringRanges };
}

function _inAnyRange(ranges, idx) {
    for (const [s, e] of ranges) {
        if (idx >= s && idx < e) return true;
    }
    return false;
}

function _stripCommentsOutsideStrings(source) {
    // 주석 제거 + 문자열 리터럴 내용을 공백으로 치환 (따옴표는 남김).
    // table('x', {...}) 스캔 시 문자열 내부의 'table(' 같은 거짓 양성을 차단.
    let out = '';
    const n = source.length;
    let i = 0;
    while (i < n) {
        const ch = source[i];
        const next = source[i + 1];
        if (ch === '/' && next === '/') { while (i < n && source[i] !== '\n') i++; continue; }
        if (ch === '/' && next === '*') {
            i += 2;
            while (i < n && !(source[i] === '*' && source[i + 1] === '/')) i++;
            i += 2;
            continue;
        }
        if (ch === "'" || ch === '"') {
            // 따옴표로 둘러싼 문자열 — 내용은 공백으로 치환하되 시작/끝 따옴표는 유지.
            // 단, 정규식 ['"`]?<name>['"`]? 매칭을 위해 따옴표는 남긴다.
            out += ch;
            const quote = ch;
            i++;
            while (i < n) {
                const c = source[i];
                if (c === '\\') { out += '  '; i += 2; continue; }
                if (c === quote) { out += c; i++; break; }
                if (c === '\n') out += '\n'; else out += ' ';
                i++;
            }
            continue;
        }
        if (ch === '`') {
            // 템플릿 리터럴 — 내부 ${} 는 실제 코드이므로 보존, 일반 텍스트는 공백 치환.
            out += '`';
            i++;
            while (i < n) {
                const c = source[i];
                if (c === '\\') { out += '  '; i += 2; continue; }
                if (c === '`') { out += '`'; i++; break; }
                if (c === '$' && source[i + 1] === '{') {
                    out += '${';
                    i += 2;
                    let depth = 1;
                    while (i < n && depth > 0) {
                        const cc = source[i];
                        if (cc === '{') depth++;
                        else if (cc === '}') depth--;
                        out += cc;
                        i++;
                    }
                    continue;
                }
                if (c === '\n') out += '\n'; else out += ' ';
                i++;
            }
            continue;
        }
        out += ch;
        i++;
    }
    return out;
}

function _findBalancedClose(src, openIdx, openCh, closeCh) {
    let depth = 0;
    const n = src.length;
    for (let i = openIdx; i < n; i++) {
        const ch = src[i];
        const next = src[i + 1];
        // 주석/문자열은 이미 제거된 상태지만 백틱은 남을 수 있음 → 단순 깊이 추적
        if (ch === "'" || ch === '"' || ch === '`') {
            const quote = ch;
            i++;
            while (i < n) {
                const c = src[i];
                if (c === '\\') { i += 2; continue; }
                if (c === quote) break;
                i++;
            }
            continue;
        }
        if (ch === openCh) depth++;
        else if (ch === closeCh) {
            depth--;
            if (depth === 0) return i;
        }
    }
    return -1;
}
