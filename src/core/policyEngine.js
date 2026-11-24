/**
 * Tenant Policy Engine — pseudo-RLS for D1
 *
 * 도깨비는 Cloudflare D1 을 지원하지만 D1 은 PostgreSQL 과 같은 RLS
 * (Row-Level Security) 를 제공하지 않습니다. 본 엔진은 모든 SQL 이 반드시
 * Pages Function 이라는 단일 게이트를 통과한다는 점을 이용해, 서버 측에서
 * 테이블별로 "반드시 세션 테넌트 조건이 포함되어야 한다" 를 강제합니다.
 *
 * 두 가지 모드:
 *   verify  — SQL 이 필요한 WHERE (또는 INSERT 컬럼) 조건을 갖추지 못하면 거부
 *   inject  — verify 에 실패한 SQL 에 테넌트 조건을 자동 주입 (v5.2)
 *
 * 설계 문서: docs/design/TENANT_POLICY.md
 *
 * ⚠ 중요: 이 파일은 *순수 JS* 로만 작성되어 있으며 Node, Browser,
 * Cloudflare Workers 어디서든 동작합니다. projectGenerator.js 는 이
 * 파일의 "본문" 을 문자열 템플릿으로 임베드하므로, 외부 의존성을 추가하지
 * 마세요.
 */

export const POLICY_ENGINE_VERSION = 1;

// ─────────────────────────────────────────────────────────────────────
// 내부 유틸 (sqlAllowlist / queryRegistry 와 일관된 구현)
// ─────────────────────────────────────────────────────────────────────

/**
 * 문자열 리터럴 / 주석을 안전하게 제거한 정규화된 SQL 반환.
 * 큰따옴표·백틱 식별자는 원형 유지 (SQLite 호환).
 * 작은따옴표 문자열은 ''(빈 문자열) 로 대체 — 토큰 카운팅에는 영향 없음.
 */
import { detectOuterOp, outerStatement } from './sqlShape.js';

export function stripStringsAndComments(sql) {
    let out = '';
    let i = 0;
    const n = sql.length;
    while (i < n) {
        const ch = sql[i];
        const next = sql[i + 1];

        // -- 라인 주석
        if (ch === '-' && next === '-') {
            while (i < n && sql[i] !== '\n') i++;
            out += ' ';
            continue;
        }
        // /* 블록 주석 */
        if (ch === '/' && next === '*') {
            i += 2;
            while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i++;
            i += 2;
            out += ' ';
            continue;
        }
        // '문자열'
        if (ch === "'") {
            out += "''";
            i++;
            while (i < n) {
                if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; }
                if (sql[i] === "'") { i++; break; }
                i++;
            }
            continue;
        }
        // "식별자" (SQLite — 내용 보존)
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
        // `식별자` (MySQL)
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

export function normalizeSql(sql) {
    return stripStringsAndComments(sql).replace(/\s+/g, ' ').trim();
}

export function detectPrimaryOp(upper) {
    // CTE 뒤 DML(`WITH ... DELETE`)을 SELECT 로 오판하지 않도록 괄호 밖 키워드를 사용.
    return detectOuterOp(upper).op;
}

const _RESERVED_AS_ALIAS = new Set([
    'WHERE', 'SET', 'VALUES', 'ON', 'GROUP', 'ORDER', 'LIMIT', 'HAVING',
    'UNION', 'INNER', 'LEFT', 'RIGHT', 'FULL', 'CROSS', 'OUTER', 'NATURAL',
    'AS', 'USING', 'AND', 'OR', 'RETURNING', 'INTERSECT', 'EXCEPT', 'FROM',
    'JOIN', 'INTO', 'UPDATE', 'SELECT', 'INSERT', 'DELETE',
]);

/**
 * FROM / JOIN / INTO / UPDATE 뒤의 테이블 참조 + 별칭 추출.
 * @returns {Array<{name: string, alias: string|null, offset: number, keyword: string}>}
 */
export function extractTableRefs(normalized) {
    const refs = [];
    // 식별자 + 옵션 별칭
    const identPat = String.raw`["` + '`' + String.raw`]?([a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)?)["` + '`' + String.raw`]?`;
    const aliasPat = String.raw`(?:\s+(?:AS\s+)?["` + '`' + String.raw`]?([a-zA-Z_][\w]*)["` + '`' + String.raw`]?)?`;
    const keywords = ['FROM', 'JOIN', 'INTO', 'UPDATE'];
    for (const kw of keywords) {
        const re = new RegExp(String.raw`\b` + kw + String.raw`\s+` + identPat + aliasPat, 'gi');
        let m;
        while ((m = re.exec(normalized)) !== null) {
            const full = m[1];
            const parts = full.split('.');
            const baseName = parts[parts.length - 1];
            const aliasRaw = m[2];
            const isValidAlias = aliasRaw && !_RESERVED_AS_ALIAS.has(aliasRaw.toUpperCase());
            refs.push({
                name: baseName,
                alias: isValidAlias ? aliasRaw : null,
                offset: m.index,
                keyword: kw.toUpperCase(),
            });
        }
    }
    return refs;
}

/**
 * WHERE 절 범위 추출. 첫 WHERE 부터 ORDER BY / GROUP BY / LIMIT / HAVING /
 * RETURNING / UNION / ; / 끝 까지.
 * @returns {{start:number, end:number, text:string} | null}
 */
// 괄호 밖(depth 0)의 WHERE 와 그 뒤 tail 키워드 위치를 찾는다.
// 문자열/주석/인용 식별자를 건너뛰므로 raw SQL 에도 사용할 수 있다.
function _scanOuterWhere(sql) {
    let depth = 0;
    let whereEnd = -1;
    let tailStart = -1;
    const n = sql.length;
    const TAIL = new Set(['ORDER', 'GROUP', 'LIMIT', 'HAVING', 'RETURNING', 'UNION', 'INTERSECT', 'EXCEPT']);
    for (let i = 0; i < n; i++) {
        const ch = sql[i];
        const nx = sql[i + 1];
        if (ch === '-' && nx === '-') { while (i < n && sql[i] !== '\n') i++; continue; }
        if (ch === '/' && nx === '*') { i += 2; while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i++; i++; continue; }
        if (ch === "'") {
            i++;
            while (i < n) {
                if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; }
                if (sql[i] === "'") break;
                i++;
            }
            continue;
        }
        if (ch === '"' || ch === '`') {
            const q = ch; i++;
            while (i < n) {
                if (sql[i] === q) { if (sql[i + 1] === q) { i += 2; continue; } break; }
                i++;
            }
            continue;
        }
        if (ch === '(') { depth++; continue; }
        if (ch === ')') { if (depth > 0) depth--; continue; }
        if (depth !== 0) continue;
        if (ch === ';') { if (tailStart < 0) tailStart = i; break; }
        if (!/[A-Za-z_]/.test(ch)) continue;
        let j = i;
        while (j < n && /[A-Za-z0-9_]/.test(sql[j])) j++;
        const word = sql.slice(i, j).toUpperCase();
        if (whereEnd < 0) {
            if (word === 'WHERE') whereEnd = j;
        } else if (TAIL.has(word)) {
            tailStart = i;
            break;
        }
        i = j - 1;
    }
    return { whereEnd, tailStart };
}

function _countQMarksRaw(sql, offset) {
    let count = 0;
    let depth = 0;
    const n = Math.min(offset, sql.length);
    for (let i = 0; i < n; i++) {
        const ch = sql[i];
        const nx = sql[i + 1];
        if (ch === '-' && nx === '-') { while (i < n && sql[i] !== '\n') i++; continue; }
        if (ch === '/' && nx === '*') { i += 2; while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i++; i++; continue; }
        if (ch === "'") {
            i++;
            while (i < n) {
                if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; }
                if (sql[i] === "'") break;
                i++;
            }
            continue;
        }
        if (ch === '"' || ch === '`') {
            const q = ch; i++;
            while (i < n) {
                if (sql[i] === q) { if (sql[i + 1] === q) { i += 2; continue; } break; }
                i++;
            }
            continue;
        }
        if (ch === '(') { depth++; continue; }
        if (ch === ')') { if (depth > 0) depth--; continue; }
        if (ch === '?' && depth >= 0) count++;
    }
    return count;
}

export function extractWhereClause(normalized) {
    // 서브쿼리 안의 WHERE 가 아니라 **바깥 문장**의 WHERE 만 사용한다.
    // (예: UPDATE ... SET x=(SELECT ... WHERE user_id=?) WHERE id=? → 바깥 WHERE)
    const { whereEnd, tailStart } = _scanOuterWhere(normalized);
    if (whereEnd < 0) return null;
    const end = tailStart >= 0 ? tailStart : normalized.length;
    return { start: whereEnd, end, text: normalized.slice(whereEnd, end) };
}

/**
 * WHERE 절 최상위 (괄호 깊이 0) 에 OR 가 있는지.
 * OR 가 최상위에 있으면 테넌트 필터가 느슨해질 수 있어 보안상 거부.
 */
export function hasTopLevelOr(whereText) {
    const upper = whereText.toUpperCase();
    let depth = 0;
    for (let i = 0; i < upper.length; i++) {
        const ch = upper[i];
        if (ch === '(') depth++;
        else if (ch === ')') depth--;
        else if (depth === 0) {
            if (upper.slice(i, i + 3) === 'OR ' || upper.slice(i, i + 4) === 'OR\t' || upper.slice(i, i + 3) === 'OR\n') {
                const before = upper[i - 1];
                if (before === undefined || !/[A-Z0-9_]/.test(before)) return true;
            }
        }
    }
    return false;
}

/**
 * WHERE 절을 depth 0 기준 AND 로만 분할 (각 conjunct 는 OR/서브를 포함할 수 있음).
 * @returns {Array<{ start: number, end: number }>} whereText 기준 반열린 구간 [start, end)
 */
function splitTopLevelAndWhere(whereText, upper) {
    const spans = [];
    let depth = 0;
    let segStart = 0;
    for (let i = 0; i < whereText.length; i++) {
        const ch = whereText[i];
        if (ch === '(') depth++;
        else if (ch === ')') depth--;
        if (depth === 0 && i + 5 <= upper.length && upper.slice(i, i + 5) === ' AND ') {
            spans.push({ start: segStart, end: i });
            i += 4;
            segStart = i + 1;
            continue;
        }
    }
    spans.push({ start: segStart, end: whereText.length });
    return spans.filter((sp) => sp.end > sp.start);
}

/**
 * conjunct 앞뒤 공백 + 한 겹씩 `( … )` 만 감싼 경우 벗겨 낸다 (dokkebi-dsl and() 레거시).
 * @returns {{ inner: string, relOffset: number }} inner 기준 0, relOffset = sub 문자열 기준 inner 시작
 */
function peelWrappedConjunct(sub) {
    const lead = sub.search(/\S/);
    if (lead < 0) return { inner: '', relOffset: 0 };
    let s = sub.slice(lead);
    let rel = lead;
    for (;;) {
        const w = (s.match(/^\s*/) || [''])[0].length;
        rel += w;
        s = s.slice(w).trimEnd();
        if (!s.startsWith('(')) break;
        let d = 0;
        let closeAt = -1;
        for (let k = 0; k < s.length; k++) {
            if (s[k] === '(') d++;
            else if (s[k] === ')') {
                d--;
                if (d === 0) {
                    closeAt = k;
                    break;
                }
            }
        }
        if (closeAt !== s.length - 1) break;
        rel += 1;
        s = s.slice(1, -1).trimEnd();
    }
    return { inner: s, relOffset: rel };
}

/**
 * WHERE 절에서 `[alias.]col = ?` 패턴을 찾아, 괄호 깊이 0 인 것의 첫 매치 반환.
 * @returns {{ index: number, length: number, qIndex: number } | null}
 *   qIndex: whereText 내에서 '?' 가 위치한 문자 인덱스
 */
function findTenantConditionInUpper(upper, alias, col) {
    const colUp = col.toUpperCase();
    const aliasUp = alias ? alias.toUpperCase() : null;

    // 후보 패턴 나열 (우선순위: alias.col → "col" (DSL/SQLite 따옴표 식별자) → col)
    const patterns = [];
    if (aliasUp) {
        patterns.push(new RegExp(String.raw`\b` + aliasUp + String.raw`\.` + colUp + String.raw`\s*=\s*\?`, 'g'));
        patterns.push(new RegExp(String.raw`\b` + aliasUp + String.raw`\.\s*"` + colUp + String.raw`"\s*=\s*\?`, 'g'));
        patterns.push(new RegExp(String.raw`"` + aliasUp + String.raw`"\.\s*"` + colUp + String.raw`"\s*=\s*\?`, 'g'));
    }
    patterns.push(new RegExp(String.raw`"` + colUp + String.raw`"\s*=\s*\?`, 'g'));
    // 별칭 없는 col = ? (단, 앞에 점이 없어야 타 테이블 col 과 혼동 X)
    patterns.push(new RegExp(String.raw`(?:^|[^A-Z0-9_.])` + colUp + String.raw`\s*=\s*\?`, 'g'));

    for (const re of patterns) {
        let m;
        while ((m = re.exec(upper)) !== null) {
            let depth = 0;
            // 매치의 첫 글자가 '(' 인 경우(패턴이 앞 문자를 소비)도 깊이에 포함해야 한다.
            const depthEnd = m.index + (upper[m.index] === '(' ? 1 : 0);
            for (let i = 0; i < depthEnd; i++) {
                if (upper[i] === '(') depth++;
                else if (upper[i] === ')') depth--;
            }
            if (depth !== 0) continue;
            const qRel = m[0].lastIndexOf('?');
            const qIdx = m.index + qRel;
            return { index: m.index, length: m[0].length, qIndex: qIdx };
        }
    }
    return null;
}

export function findTenantCondition(whereText, alias, col) {
    const upper = whereText.toUpperCase();
    let r = findTenantConditionInUpper(upper, alias, col);
    if (r) return r;
    for (const sp of splitTopLevelAndWhere(whereText, upper)) {
        const sub = whereText.slice(sp.start, sp.end);
        const subUpper = upper.slice(sp.start, sp.end);
        const { inner, relOffset } = peelWrappedConjunct(sub);
        if (!inner) continue;
        // 괄호로 감싼 "서브쿼리" 내부의 tenant 조건은 바깥 행 필터가 아니다.
        if (/\bSELECT\b/i.test(inner)) continue;
        // (tenant = ? OR ...) 처럼 OR 로 느슨해진 conjunct 는 인정하지 않는다.
        if (hasTopLevelOr(inner)) continue;
        const innerUpper = subUpper.slice(relOffset, relOffset + inner.length);
        r = findTenantConditionInUpper(innerUpper, alias, col);
        if (r) {
            const shift = sp.start + relOffset;
            return {
                index: shift + r.index,
                length: r.length,
                qIndex: shift + r.qIndex,
            };
        }
    }
    return null;
}

/**
 * 주어진 오프셋 앞쪽의 '?' 개수를 센다. normalized SQL 기준.
 */
export function countQMarksBefore(normalized, offset) {
    let count = 0;
    const end = Math.min(offset, normalized.length);
    for (let i = 0; i < end; i++) {
        if (normalized[i] === '?') count++;
    }
    return count;
}

/**
 * INSERT INTO t (c1, c2, ...) VALUES (?, ?, ...) 의 컬럼 리스트 추출.
 * @returns {{ cols: string[], colsOffset: number, valuesOffset: number } | null}
 */
export function extractInsertColumns(normalized) {
    // INSERT INTO tbl (c1, c2) VALUES (?, ?)
    const re = /\bINSERT\s+INTO\s+(?:["`]?[\w]+["`]?(?:\.[\w]+)?)\s*\(([^)]*)\)\s*VALUES\s*\(/i;
    const m = re.exec(normalized);
    if (!m) return null;
    const raw = m[1];
    const cols = raw.split(',').map((s) => s.trim().replace(/^["`]|["`]$/g, ''));
    const colsOffset = m.index + m[0].lastIndexOf('(' + raw + ')') + 1;
    // 파라미터 인덱스는 VALUES (...) 안의 ? 개수만으로 결정되어도 OK — 앞 문장 끝까지의 개수.
    const valuesOffset = m.index + m[0].length;
    return { cols, colsOffset, valuesOffset };
}

/**
 * policy.tables 에서 대소문자 무시로 정책 찾기
 */
export function findTablePolicy(tables, name) {
    if (!tables || typeof tables !== 'object') return null;
    const lower = name.toLowerCase();
    for (const key of Object.keys(tables)) {
        if (key.toLowerCase() === lower) return tables[key];
    }
    return null;
}

/**
 * 테이블 하나에 대한 세션 tenant 클레임을 해석한다.
 *
 * 해석 순서 (첫 번째로 "세션에 실제 값이 있는" 키를 선택):
 *   1) tableClaim   — policy.tables[X].sessionClaim (테이블 명시 override)
 *   2) globalClaim  — policy.sessionClaim / policy.claim (전역 기본)
 *   3) tenantCol    — 컬럼명과 동일한 이름의 세션 키 (관례 fallback)
 *
 * 세 후보 중 어느 것도 세션에 값이 없으면 첫 후보 이름과 undefined 반환.
 * (에러 메시지를 "가장 명시적으로 지정된 이름" 으로 노출하기 위해.)
 *
 * @returns {[string, unknown]} [선택된 claim 이름, 세션에서 읽은 값]
 */
/**
 * optional 모드에서 "모호하지 않은" 테넌트 매핑만 강제할지 판단.
 *   - 테이블에 sessionClaim 이 명시됨 → 강제
 *   - tenantColumn 이름 == 전역 claim 이름 → 강제 (예: sites.user_id / user_id)
 *   - 그 외 (예: inquiries.site_id + 전역 user_id) → 매핑이 모호하므로 스킵(공개)
 *     ※ 이 경우 테이블에 sessionClaim 을 명시해야 격리가 켜진다.
 */
function optionalEnforceable(tp, globalClaim) {
    if (!tp) return false;
    if (tp.sessionClaim) return true;
    return String(tp.tenantColumn || '').toLowerCase() === String(globalClaim || '').toLowerCase();
}

export function _resolveTenantClaim(tenantContext, tableClaim, globalClaim, tenantCol) {
    // sessionClaim 명시 시 그 클레임만 사용 (FK 컬럼에 user_id 가 들어가는 오매핑 방지)
    if (tableClaim) {
        const tv = tenantContext ? tenantContext[tableClaim] : undefined;
        return [tableClaim, tv];
    }
    const candidates = [];
    if (globalClaim) candidates.push(globalClaim);
    if (tenantCol && !candidates.includes(tenantCol)) candidates.push(tenantCol);
    if (candidates.length === 0) return ['user_id', undefined];

    if (!tenantContext) return [candidates[0], undefined];
    for (const c of candidates) {
        const v = tenantContext[c];
        if (v !== undefined && v !== null) return [c, v];
    }
    return [candidates[0], undefined];
}

// ─────────────────────────────────────────────────────────────────────
// verifyTenantPolicy (Stage 1)
// ─────────────────────────────────────────────────────────────────────

/**
 * SQL 이 테넌트 정책을 준수하는지 검증.
 *
 * @param {string} sql
 * @param {unknown[]} params
 * @param {Record<string, any> | null} tenantContext — 세션에서 가져온 클레임
 * @param {object | null} policy — { claim, tables: { [name]: { tenantColumn, mode } }, strict? }
 * @param {object} [opts]
 * @param {boolean} [opts.strict] — 파싱 실패 시 거부 여부 (기본: policy.strict ?? true)
 * @returns {{ ok: true } | { ok: false, reason: string, code: string, table?: string }}
 */
export function verifyTenantPolicy(sql, params, tenantContext, policy, opts = {}) {
    if (!policy || !policy.tables || Object.keys(policy.tables).length === 0) {
        return { ok: true };
    }

    const strict = opts.strict ?? (policy.strict !== false);
    const globalClaim = policy.claim || 'user_id';

    // 관리자는 bypass
    if (tenantContext && tenantContext._isAdmin === true) return { ok: true };

    const normalized = normalizeSql(sql);
    const upper = normalized.toUpperCase();
    const op = detectPrimaryOp(upper);

    if (!op) {
        return strict
            ? { ok: false, code: 'UNPARSEABLE', reason: 'SQL 연산을 파싱할 수 없습니다.' }
            : { ok: true };
    }
    // CREATE / DDL 은 이미 sqlAllowlist 가 별도 처리. 정책 검증은 skip.
    if (op === 'CREATE') return { ok: true };

    const refs = extractTableRefs(normalized);
    for (const ref of refs) {
        const tp = findTablePolicy(policy.tables, ref.name);
        if (!tp) continue; // 선언 안 된 테이블은 스킵 (defaultMode='none' 과 동일)
        const mode = tp.mode;
        if (mode === 'none') continue;
        // optional: 클레임이 있으면 enforce, 없으면 공개(스킵) — 문서화된 동작.
        if (mode !== 'enforce' && mode !== 'inject' && mode !== 'optional') continue;
        if (mode === 'optional' && !optionalEnforceable(tp, globalClaim)) continue;

        const tenantCol = tp.tenantColumn;
        if (!tenantCol) continue;

        // 테이블별 claim 해석 (우선순위):
        //   1) tp.sessionClaim  — 테이블 override
        //   2) globalClaim       — policy.sessionClaim / policy.claim (하위호환)
        //   3) tenantCol         — 관례 fallback: 세션 키 이름 == 컬럼명
        //      (notofly 처럼 테이블마다 다른 해시 토큰을 tenant 로 쓰는 경우 편의)
        const [claim, expected] = _resolveTenantClaim(tenantContext, tp.sessionClaim, globalClaim, tenantCol);

        if (mode === 'optional' && (expected === undefined || expected === null)) continue;
        if (expected === undefined || expected === null) {
            return {
                ok: false,
                code: 'TENANT_MISSING',
                reason: '테넌트 클레임 "' + claim + '" 가 세션에 없습니다. 로그인/식별 후 ctx.setSessionTenant({ ' + claim + ': <값> }) 를 호출했는지 확인하세요.',
                table: ref.name,
            };
        }

        if (op === 'INSERT') {
            // INSERT 의 주 대상 테이블 (INTO) 에만 컬럼 리스트 검사 적용
            if (ref.keyword === 'INTO') {
                const ci = extractInsertColumns(normalized);
                if (!ci) {
                    return {
                        ok: false,
                        code: 'INSERT_NO_COLUMNS',
                        reason: 'INSERT 문에 컬럼 리스트가 없어 테넌트 컬럼을 검증할 수 없습니다. INSERT INTO ' + ref.name + ' (col, ...) VALUES (...) 형태를 사용하세요.',
                        table: ref.name,
                    };
                }
                const idx = ci.cols.findIndex((c) => c.toLowerCase() === tenantCol.toLowerCase());
                if (idx < 0) {
                    return {
                        ok: false,
                        code: 'INSERT_MISSING_TENANT_COL',
                        reason: 'INSERT 컬럼 리스트에 테넌트 컬럼 "' + tenantCol + '" 가 없습니다.',
                        table: ref.name,
                    };
                }
                const paramValue = params[idx];
                if (String(paramValue) !== String(expected)) {
                    return {
                        ok: false,
                        code: 'TENANT_MISMATCH',
                        reason: 'INSERT ' + ref.name + '.' + tenantCol + ' 값이 세션 테넌트와 일치하지 않습니다.',
                        table: ref.name,
                    };
                }
            }
            // INSERT 의 SELECT subquery 참조는 v1 에서 unsupported — strict 거부
            else if (strict) {
                return {
                    ok: false,
                    code: 'UNSUPPORTED_INSERT_SUBQUERY',
                    reason: 'INSERT ... SELECT (서브쿼리 포함) 에서 테넌트 참조 검증은 아직 지원하지 않습니다.',
                    table: ref.name,
                };
            }
        } else {
            // SELECT / UPDATE / DELETE
            const where = extractWhereClause(normalized);
            if (!where) {
                return {
                    ok: false,
                    code: 'NO_WHERE',
                    reason: op + ' 문에 WHERE 절이 없어 ' + ref.name + '.' + tenantCol + ' 조건을 확인할 수 없습니다.',
                    table: ref.name,
                };
            }
            if (hasTopLevelOr(where.text)) {
                return {
                    ok: false,
                    code: 'LOOSE_OR',
                    reason: 'WHERE 최상단에 OR 가 있어 테넌트 필터가 느슨해집니다. AND 체인으로 재작성하세요.',
                    table: ref.name,
                };
            }
            const cond = findTenantCondition(where.text, ref.alias, tenantCol);
            if (!cond) {
                return {
                    ok: false,
                    code: 'NO_TENANT_FILTER',
                    reason: 'WHERE 절에 ' + (ref.alias ? ref.alias + '.' : '') + tenantCol + ' = ? 조건이 없습니다.',
                    table: ref.name,
                };
            }
            // params 인덱스 계산: normalized 전체에서 WHERE 시작 + cond.qIndex 전까지 '?' 개수
            const absQOffset = where.start + cond.qIndex;
            const paramIdx = countQMarksBefore(normalized, absQOffset);
            const paramValue = params[paramIdx];
            if (String(paramValue) !== String(expected)) {
                return {
                    ok: false,
                    code: 'TENANT_MISMATCH',
                    reason: ref.name + '.' + tenantCol + ' 값이 세션 테넌트와 일치하지 않습니다.',
                    table: ref.name,
                };
            }
        }
    }

    return { ok: true };
}

// ─────────────────────────────────────────────────────────────────────
// injectTenantPolicy (Stage 2)
// ─────────────────────────────────────────────────────────────────────

/**
 * SQL 에 테넌트 조건을 자동 주입.
 *
 * 원칙:
 *   - verify 가 이미 통과하는 쿼리는 그대로 반환 (중복 주입 방지)
 *   - 실패하는 쿼리만 주입 시도
 *   - 주입 실패 시 strict=true 에선 reject, false 에선 원본 반환
 *
 * 지원 범위 (v5.2 초기):
 *   - SELECT / UPDATE / DELETE: 단일 FROM/UPDATE 테이블에 한해 WHERE 부착
 *   - INSERT INTO t (...) VALUES (...): 컬럼 리스트 끝에 tenantCol 추가, params 끝에 expected append
 *   - JOIN 은 주 테이블에만 주입 (보조 테이블은 verify 가 "optional" 또는 "none" 이어야 함)
 *
 * @returns {{ ok: true, sql: string, params: unknown[], injected: boolean } | { ok: false, reason: string, code: string, table?: string }}
 */
export function injectTenantPolicy(sql, params, tenantContext, policy, opts = {}) {
    if (!policy || !policy.tables || Object.keys(policy.tables).length === 0) {
        return { ok: true, sql, params, injected: false };
    }
    const strict = opts.strict ?? (policy.strict !== false);
    const globalClaim = policy.claim || 'user_id';

    if (tenantContext && tenantContext._isAdmin === true) {
        return { ok: true, sql, params, injected: false };
    }

    // 일단 verify 시도 — 이미 안전하면 건드리지 않음
    const pre = verifyTenantPolicy(sql, params, tenantContext, policy, { strict: false });
    if (pre.ok) return { ok: true, sql, params, injected: false };

    const normalized = normalizeSql(sql);
    const upper = normalized.toUpperCase();
    const op = detectPrimaryOp(upper);

    if (!op || op === 'CREATE') {
        if (strict) return { ok: false, code: 'UNSUPPORTED_OP', reason: '주입 불가능한 SQL 연산입니다.' };
        return { ok: true, sql, params, injected: false };
    }

    const refs = extractTableRefs(normalized);

    // enforce/inject 대상 참조만 수집
    const targets = [];
    for (const ref of refs) {
        const tp = findTablePolicy(policy.tables, ref.name);
        if (!tp) continue;
        const _optionalOk = tp.mode !== 'optional' || optionalEnforceable(tp, globalClaim);
        if ((tp.mode === 'enforce' || tp.mode === 'inject' || (tp.mode === 'optional' && _optionalOk)) && tp.tenantColumn) {
            targets.push({ ref, policy: tp });
        }
    }
    if (targets.length === 0) return { ok: true, sql, params, injected: false };

    // 초기 구현 단순화: 주 대상 테이블(INSERT=INTO, UPDATE=UPDATE, DELETE=FROM, SELECT=첫 FROM) 하나만 주입.
    // 여러 enforce 테이블이 JOIN 되어 있으면 각각 verify 실패 원인에 따라 추가 주입할 수도 있지만,
    // 복잡도 관리상 초기는 "첫 번째 대상" + "verify 로 재확인" 루프로 해결.
    // → 반복 주입 (최대 N 회) 로 모든 enforce 참조를 채우는 단순 루프.

    let curSql = sql;
    let curParams = params.slice();
    const MAX_ROUNDS = targets.length + 2;
    let injectedAny = false;

    for (let round = 0; round < MAX_ROUNDS; round++) {
        const vr = verifyTenantPolicy(curSql, curParams, tenantContext, policy, { strict: false });
        if (vr.ok) return { ok: true, sql: curSql, params: curParams, injected: injectedAny };

        // vr.table 을 기반으로 해당 ref 에 주입 시도
        const failingTable = vr.table;
        const failingCode = vr.code;
        if (!failingTable) break;

        const normalizedCur = normalizeSql(curSql);
        const curRefs = extractTableRefs(normalizedCur);
        const curOp = detectPrimaryOp(normalizedCur.toUpperCase());
        const outerStart = detectOuterOp(normalizedCur.toUpperCase()).index;
        const opKeyword = curOp === 'INSERT' ? 'INTO' : curOp === 'UPDATE' ? 'UPDATE' : 'FROM';
        const candidateRefs = curRefs
            .filter((r) => r.name.toLowerCase() === failingTable.toLowerCase())
            .filter((r) => (outerStart < 0 ? true : r.offset >= outerStart))
            .filter((r) => r.keyword === opKeyword || (curOp === 'SELECT' && r.keyword === 'FROM'))
            .sort((a, b) => a.offset - b.offset);
        const tRef = candidateRefs[0] || curRefs
            .filter((r) => r.name.toLowerCase() === failingTable.toLowerCase())
            .sort((a, b) => a.offset - b.offset)[0];
        if (!tRef) break;
        const tp = findTablePolicy(policy.tables, failingTable);
        if (!tp || !tp.tenantColumn) break;
        const tenantCol = tp.tenantColumn;

        // 테이블별 claim 해석 — expected 를 실패한 테이블 기준으로 다시 결정
        const [failingClaim, failingExpected] = _resolveTenantClaim(tenantContext, tp.sessionClaim, globalClaim, tenantCol);
        if (failingExpected === undefined || failingExpected === null) {
            return {
                ok: false,
                code: 'TENANT_MISSING',
                reason: '테넌트 클레임 "' + failingClaim + '" 가 세션에 없어 ' + failingTable + ' 에 주입할 수 없습니다.',
                table: failingTable,
            };
        }

        const rewrite = _rewriteOne(curSql, curParams, curOp, tRef, tenantCol, failingExpected, failingCode);
        if (!rewrite) {
            if (strict) {
                return {
                    ok: false,
                    code: 'INJECT_FAILED',
                    reason: '테넌트 조건 주입 실패: ' + failingTable + '.' + tenantCol,
                    table: failingTable,
                };
            }
            return { ok: true, sql: curSql, params: curParams, injected: injectedAny };
        }
        curSql = rewrite.sql;
        curParams = rewrite.params;
        injectedAny = true;
    }

    // 최종 재검증
    const final = verifyTenantPolicy(curSql, curParams, tenantContext, policy, { strict: false });
    if (final.ok) return { ok: true, sql: curSql, params: curParams, injected: injectedAny };
    if (strict) {
        return {
            ok: false,
            code: 'INJECT_INCOMPLETE',
            reason: '주입 후에도 정책 위반이 남아있습니다: ' + (final.reason || ''),
            table: final.table,
        };
    }
    return { ok: true, sql: curSql, params: curParams, injected: injectedAny };
}

/**
 * 한 테이블에 대해 tenant 조건 주입을 시도.
 * SQL 원문(curSql) 에 직접 문자열 편집을 수행하며, 토큰 매칭은 normalize 된 공간에서 계산.
 * 원문 과 normalize 간 오프셋 보존을 위해 정규화는 "공백 정리" 전까지만 적용.
 */
function _rewriteOne(sql, params, op, ref, tenantCol, expected, failingCode) {
    // 주입 대상이 주 테이블인지 판단. INSERT 는 INTO 만, UPDATE 는 UPDATE 뒤, DELETE/SELECT 는 FROM.
    const allowedKeywordByOp = {
        SELECT: new Set(['FROM', 'JOIN']),
        UPDATE: new Set(['UPDATE']),
        DELETE: new Set(['FROM']),
        INSERT: new Set(['INTO']),
    };
    const allowed = allowedKeywordByOp[op];
    if (!allowed || !allowed.has(ref.keyword)) return null;

    if (op === 'INSERT') {
        return _injectInsert(sql, params, ref, tenantCol, expected);
    }
    // SELECT / UPDATE / DELETE — WHERE 조작
    return _injectWhere(sql, params, op, ref, tenantCol, expected);
}

function _injectInsert(sql, params, ref, tenantCol, expected) {
    // INSERT INTO t (c1, c2) VALUES (?, ?)[, (?, ?)]*
    // → INSERT INTO t (c1, c2, tenantCol) VALUES (?, ?, ?)[, (?, ?, ?)]*
    //   params 에는 각 VALUES 튜플 끝에 expected 를 append (멀티 row 지원은 초기엔 단일만)
    //
    // 안전을 위해 단순 케이스 (단일 VALUES 튜플) 만 지원. 복수/서브쿼리/ON CONFLICT 등은 skip.
    const re = /(\bINSERT\s+INTO\s+(?:["`]?[\w]+["`]?(?:\.[\w]+)?)\s*\()([^)]*)(\)\s*VALUES\s*\()([^)]*)(\))/i;
    const m = re.exec(sql);
    if (!m) return null;

    const prefix = m[1];
    const colList = m[2];
    const mid = m[3];
    const valList = m[4];
    const suffix = m[5];

    // 이미 tenantCol 이 있으면 주입 안 함 (값 미스매치면 verify 가 나중에 거부)
    const cols = colList.split(',').map((s) => s.trim().replace(/^["`]|["`]$/g, ''));
    if (cols.some((c) => c.toLowerCase() === tenantCol.toLowerCase())) return null;

    // VALUES 안에 ? 의 개수
    const valCount = (valList.match(/\?/g) || []).length;
    if (valCount !== cols.length) return null; // 리터럴 혼용 등 복잡 케이스 skip

    // 새 컬럼/값 주입
    const newColList = colList.trim() + ', ' + tenantCol;
    const newValList = valList.trim() + ', ?';

    // params: INSERT 는 VALUES 의 ? 순서대로 바인딩되므로, 파라미터 리스트 끝에 append
    // 단, 이 INSERT 앞에 CTE 같은 게 있는 경우는 다름 → 단순 INSERT 만 가정
    // params 는 전체 리스트 → "이 INSERT 의 VALUES 에 해당하는 위치" 를 찾아야 함
    // 간단히: 전체 ? 개수 = params.length. VALUES 가 마지막 그룹이라면 params 끝에 append.
    // CTE 포함 INSERT 는 초기 미지원.
    const totalQ = (sql.match(/\?/g) || []).length;
    if (totalQ !== params.length) return null;

    const newSql = sql.slice(0, m.index)
        + prefix + newColList + mid + newValList + suffix
        + sql.slice(m.index + m[0].length);
    const newParams = params.slice();
    newParams.push(expected);
    return { sql: newSql, params: newParams };
}

function _injectWhere(sql, params, op, ref, tenantCol, expected) {
    // ref.alias 가 있으면 `alias.tenantCol = ?`, 없으면 `tenantCol = ?`
    const colExpr = (ref.alias ? ref.alias + '.' : '') + tenantCol;
    const cond = colExpr + ' = ?';

    // 바깥 문장의 WHERE 만 대상으로 한다 (서브쿼리 WHERE 오삽입 방지).
    const { whereEnd, tailStart } = _scanOuterWhere(sql);
    const insertAt = tailStart >= 0 ? tailStart : sql.length;
    let newSql;
    if (whereEnd >= 0) {
        newSql = sql.slice(0, insertAt).trimEnd() + ' AND (' + cond + ') ' + sql.slice(insertAt).trimStart();
    } else {
        newSql = sql.slice(0, insertAt).trimEnd() + ' WHERE ' + cond + ' ' + sql.slice(insertAt).trimStart();
    }
    newSql = newSql.replace(/\s+/g, ' ');

    const markerIdx = _findInjectedQMarkIndex(newSql, cond);
    if (markerIdx < 0) return null;
    // 문자열/주석 내부 '?' 는 제외하고 센다.
    const beforeCount = _countQMarksRaw(newSql, markerIdx);
    const newParams = params.slice();
    newParams.splice(beforeCount, 0, expected);
    return { sql: newSql, params: newParams };
}

/**
 * 새로 주입된 cond 문자열의 '?' 위치(절대 오프셋) 를 찾는다.
 * 주입 전 sql 에도 동일 cond 가 있을 수 있으나 주입된 건 특정 패턴 " AND (col = ?)" 또는 " WHERE col = ?"
 */
function _findInjectedQMarkIndex(newSql, cond) {
    // 주입 마커: ' AND (' + cond + ')' 또는 ' WHERE ' + cond + ' '
    // 둘 다 cond 의 마지막 '?' 가 새로 삽입된 것.
    const markers = [' AND (' + cond + ')', ' WHERE ' + cond];
    for (const marker of markers) {
        const i = newSql.lastIndexOf(marker);
        if (i >= 0) {
            const q = marker.lastIndexOf('?');
            return i + q;
        }
    }
    // fallback: cond 자체 마지막 '?'
    const i = newSql.lastIndexOf(cond);
    if (i >= 0) return i + cond.lastIndexOf('?');
    return -1;
}

// ─────────────────────────────────────────────────────────────────────
// policy 메타데이터 빌드 헬퍼 (build.js 에서 사용)
// ─────────────────────────────────────────────────────────────────────

/**
 * dokkebi.config.js 의 policy 섹션을 allowlist v2 에 병합할 수 있는 형태로 정규화.
 *
 * @param {object | undefined} configPolicy
 * @param {{ authorizationEnabled?: boolean, authLoginEnabled?: boolean }} [opts]
 *   - requireJwtTenant 미지정 시: authorization/auth.login 이 켜져 있으면 JWT 전용
 *     (worker 측 로그인·JWT 로 서버가 신분을 아는 구성에서 세션 tenant 위조를 막는다)
 * @returns {{ enabled: boolean, mode: 'off'|'verify'|'inject', claim: string, strict: boolean, requireJwtTenant: boolean, tables: Record<string, {tenantColumn?: string, mode: string}> } | null}
 */
export function normalizePolicyConfig(configPolicy, opts = {}) {
    if (!configPolicy || configPolicy.enabled === false) {
        return { enabled: false, mode: 'off', claim: 'user_id', strict: true, requireJwtTenant: false, tables: {} };
    }
    const mode = (configPolicy.mode || 'verify').toLowerCase();
    const claim = configPolicy.sessionClaim || configPolicy.claim || 'user_id';
    const strict = configPolicy.strict !== false;
    // JWT 전용 테넌트: 명시값 우선, 없으면 JWT 기반 인증이 구성돼 있을 때 자동 적용.
    const requireJwtTenant = configPolicy.requireJwtTenant === undefined
        ? !!(opts.authorizationEnabled || opts.authLoginEnabled)
        : configPolicy.requireJwtTenant === true;
    const tables = {};
    const rawTables = configPolicy.tables || {};
    for (const [tname, tcfg] of Object.entries(rawTables)) {
        if (!tcfg || typeof tcfg !== 'object') continue;
        const tMode = (tcfg.mode || (tcfg.tenantColumn ? 'enforce' : 'none')).toLowerCase();
        tables[tname] = {
            tenantColumn: tcfg.tenantColumn,
            mode: tMode,
            // 테이블 레벨에서 명시한 세션 클레임 이름 (예: users.sessionClaim = 'user_id').
            // 없으면 엔진이 globalClaim → tenantColumn 순으로 fallback.
            sessionClaim: tcfg.sessionClaim || undefined,
        };
    }
    return { enabled: true, mode, claim, strict, requireJwtTenant, tables };
}
