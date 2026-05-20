/**
 * dokkebi Authorization Policy (Stage 4)
 *
 * 목적:
 *   브라우저(WASM) 안의 "role === 'admin'" 같은 권한 체크는 공격자가 번들을
 *   패치/리버싱해 우회할 수 있어 **신뢰할 수 없습니다**. 이 모듈은 DB 프록시
 *   레이어에서 JWT 의 role 클레임을 검증해 "연산(SQL op) + 테이블" 단위로
 *   허가 여부를 판정합니다. SQL Allowlist/Query Registry 와 독립적으로 동작.
 *
 * 동작 개요:
 *   1. 클라이언트가 `Authorization: Bearer <jwt>` 헤더(또는 세션 tenant_json
 *      의 `jwt` 필드)를 함께 전송
 *   2. 워커가 JWT 서명 검증 (HS256, secret 은 Pages 환경변수)
 *   3. JWT payload 에서 role 추출 (기본 필드: `role`)
 *   4. 요청 SQL 의 primary op + table 을 추출해 규칙과 매칭
 *   5. 규칙 불일치 → 403
 *
 * 규칙 우선순위 (위에서 아래):
 *   1) "OP:table"       — 가장 구체적 매칭 (예: "DELETE:posts")
 *   2) "OP:*"           — 연산 와일드카드 (예: "DELETE:*")
 *   3) "*:table"        — 테이블 와일드카드
 *   4) "*"              — 디폴트
 *
 * 규칙 값:
 *   { public: true }            — 인증/인가 불필요 (누구나 허용)
 *   { auth: true }              — 로그인만 필요 (유효한 JWT)
 *   { roles: ['admin', ...] }   — 해당 role 중 하나 필요 (auth: true 자동 포함)
 *   { deny: true }              — 명시적 차단
 *
 * 페일 모드:
 *   - 규칙 '*' 미정의 → { mode: 'warn' } 에서는 통과 + 빌드 로그에 경고 (기존 호환)
 *                       { mode: 'strict' } 에서는 전부 거부
 *
 * ⚠ 본 모듈이 다루지 않는 것:
 *   - row-level 인가 ("유저가 자기 글만 수정") → Tenant Policy 조합
 *   - 세션/로그인/JWT 발급 → 사용자 구현 (examples/auth-proxy 참조)
 *   - 프론트엔드 권한 UI → 클라이언트 판단은 UX 용도일 뿐
 */

// ─────────────────────────────────────────────────────────────
// Config 정규화 — dokkebi.config.js 의 authorization 섹션 검증/정규화
// ─────────────────────────────────────────────────────────────

const VALID_OPS = new Set(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', '*']);

/**
 * @param {any} raw - dokkebi.config.js 의 authorization 섹션 (any)
 * @returns {{
 *   enabled: boolean,
 *   mode: 'warn' | 'strict',
 *   jwtSecretEnv: string,
 *   jwtAlgorithm: 'HS256',
 *   claim: string,
 *   audience: string | null,
 *   issuer: string | null,
 *   clockSkewSec: number,
 *   rules: Array<{ op: string, table: string, spec: any, priority: number, key: string }>,
 * } | null}
 */
export function normalizeAuthorizationConfig(raw) {
    if (!raw || typeof raw !== 'object') return null;
    if (raw.enabled === false) return null;

    const rulesIn = raw.rules || {};
    const rules = [];
    for (const key of Object.keys(rulesIn)) {
        const spec = rulesIn[key];
        if (!spec || typeof spec !== 'object') continue;

        // key 포맷: "OP:table" | "OP:*" | "*:table" | "*"
        let op, table;
        if (key === '*') {
            op = '*'; table = '*';
        } else {
            const colonIdx = key.indexOf(':');
            if (colonIdx < 0) continue;
            op = key.slice(0, colonIdx).trim().toUpperCase();
            table = key.slice(colonIdx + 1).trim();
        }

        if (!VALID_OPS.has(op)) continue;
        if (!table) continue;

        const priority = _rulePriority(op, table);
        const normalizedSpec = _normalizeRuleSpec(spec);
        if (!normalizedSpec) continue;
        rules.push({ op, table: table.toLowerCase(), spec: normalizedSpec, priority, key });
    }

    rules.sort((a, b) => b.priority - a.priority);

    return {
        enabled: true,
        mode: raw.mode === 'strict' ? 'strict' : 'warn',
        jwtSecretEnv: String(raw.jwtSecretEnv || raw.jwtSecretBinding || 'DOKKEBI_JWT_SECRET'),
        jwtAlgorithm: 'HS256',
        claim: String(raw.claim || 'role'),
        audience: raw.audience || null,
        issuer: raw.issuer || null,
        clockSkewSec: Number.isFinite(raw.clockSkewSec) ? Math.max(0, raw.clockSkewSec) : 30,
        rules,
    };
}

function _rulePriority(op, table) {
    // 더 구체적인 규칙일수록 우선순위가 높음
    if (op !== '*' && table !== '*') return 3;
    if (op !== '*' && table === '*') return 2;
    if (op === '*' && table !== '*') return 2; // 같은 단계로 취급
    return 0;
}

function _normalizeRuleSpec(spec) {
    const out = {};
    if (spec.public === true) { out.public = true; return out; }
    if (spec.deny === true) { out.deny = true; return out; }
    if (Array.isArray(spec.roles) && spec.roles.length > 0) {
        out.roles = spec.roles.map((r) => String(r));
        return out;
    }
    if (spec.auth === true) { out.auth = true; return out; }
    return null;
}

// ─────────────────────────────────────────────────────────────
// 규칙 매칭 — 주어진 op/table 에 가장 적합한 규칙 한 개 반환
// ─────────────────────────────────────────────────────────────

/**
 * @param {ReturnType<typeof normalizeAuthorizationConfig>} policy
 * @param {string} op    - 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'CREATE'
 * @param {string} table - 소문자/원본 상관없음
 * @returns {{ spec: any, key: string } | null}
 */
export function matchRule(policy, op, table) {
    if (!policy || !policy.rules || policy.rules.length === 0) return null;
    const opU = String(op || '').toUpperCase();
    const tblL = String(table || '').toLowerCase();
    for (const rule of policy.rules) {
        const opMatch = rule.op === '*' || rule.op === opU;
        const tblMatch = rule.table === '*' || rule.table === tblL;
        if (opMatch && tblMatch) return { spec: rule.spec, key: rule.key };
    }
    return null;
}

// ─────────────────────────────────────────────────────────────
// 인가 판정 — 매칭된 규칙 + JWT payload 로 허가 여부 결정
// ─────────────────────────────────────────────────────────────

/**
 * @param {ReturnType<typeof matchRule> | null} matched - matchRule() 결과
 * @param {ReturnType<typeof normalizeAuthorizationConfig>} policy
 * @param {{ payload: any, valid: boolean, reason?: string } | null} jwt
 * @returns {{ ok: boolean, code?: string, reason?: string, role?: string }}
 */
export function authorize(matched, policy, jwt) {
    if (!matched) {
        if (policy.mode === 'strict') {
            return { ok: false, code: 'NO_RULE', reason: '해당 연산에 대한 인가 규칙이 정의되지 않았습니다.' };
        }
        return { ok: true };
    }
    const spec = matched.spec;
    if (spec.deny === true) {
        return { ok: false, code: 'RULE_DENY', reason: `규칙 '${matched.key}' 에 의해 거부되었습니다.` };
    }
    if (spec.public === true) {
        return { ok: true };
    }

    if (!jwt || !jwt.valid) {
        const reason = jwt?.reason ? `JWT 검증 실패: ${jwt.reason}` : '로그인이 필요합니다.';
        return { ok: false, code: 'AUTH_REQUIRED', reason };
    }

    if (spec.auth === true && !spec.roles) {
        return { ok: true };
    }

    if (Array.isArray(spec.roles) && spec.roles.length > 0) {
        const claim = policy.claim || 'role';
        const userRole = jwt.payload?.[claim];
        if (userRole === undefined || userRole === null) {
            return { ok: false, code: 'ROLE_MISSING', reason: `JWT 에 '${claim}' 클레임이 없습니다.` };
        }
        const userRoles = Array.isArray(userRole) ? userRole.map(String) : [String(userRole)];
        const allowed = spec.roles.some((r) => userRoles.includes(r));
        if (!allowed) {
            return { ok: false, code: 'ROLE_FORBIDDEN', reason: `필요한 role: [${spec.roles.join(', ')}], 현재: ${userRoles.join(', ')}`, role: userRoles[0] };
        }
        return { ok: true, role: userRoles[0] };
    }

    return { ok: false, code: 'SPEC_INVALID', reason: '규칙 스펙이 유효하지 않습니다.' };
}

// ─────────────────────────────────────────────────────────────
// JWT 검증 — HS256 (Web Crypto 사용, 워커/Node 모두 호환)
// ─────────────────────────────────────────────────────────────

/**
 * JWT (HS256) 검증. 서명 + exp/nbf/iss/aud 만 검사. 클레임 내용은 호출자 책임.
 *
 * @param {string} token - "xxx.yyy.zzz"
 * @param {{
 *   secret: string,
 *   audience?: string | null,
 *   issuer?: string | null,
 *   clockSkewSec?: number,
 *   crypto?: Crypto,
 *   nowMs?: number,
 * }} opts
 */
export async function verifyJwtHs256(token, opts) {
    if (!token || typeof token !== 'string') {
        return { valid: false, reason: 'JWT 가 비어있습니다.' };
    }
    const parts = token.split('.');
    if (parts.length !== 3) {
        return { valid: false, reason: 'JWT 형식이 아닙니다.' };
    }

    const [headerB64, payloadB64, sigB64] = parts;
    let header, payload;
    try {
        header = JSON.parse(_b64urlDecodeToString(headerB64));
        payload = JSON.parse(_b64urlDecodeToString(payloadB64));
    } catch {
        return { valid: false, reason: 'JWT 헤더/페이로드를 파싱할 수 없습니다.' };
    }

    if (!header || header.typ !== 'JWT' || header.alg !== 'HS256') {
        return { valid: false, reason: '지원하지 않는 JWT 알고리즘 (HS256 만 허용).' };
    }

    const cryptoRef = opts.crypto || (typeof crypto !== 'undefined' ? crypto : null);
    if (!cryptoRef || !cryptoRef.subtle) {
        return { valid: false, reason: 'crypto.subtle 을 사용할 수 없는 환경입니다.' };
    }

    const secretBytes = new TextEncoder().encode(opts.secret || '');
    if (secretBytes.length === 0) {
        return { valid: false, reason: 'JWT secret 이 설정되지 않았습니다.' };
    }

    const key = await cryptoRef.subtle.importKey(
        'raw',
        secretBytes,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify'],
    );

    const sigBytes = _b64urlToBytes(sigB64);
    const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const valid = await cryptoRef.subtle.verify('HMAC', key, sigBytes, data);
    if (!valid) {
        return { valid: false, reason: 'JWT 서명 불일치.' };
    }

    const nowMs = opts.nowMs ?? Date.now();
    const skewMs = (opts.clockSkewSec ?? 30) * 1000;

    if (typeof payload.exp === 'number' && nowMs > payload.exp * 1000 + skewMs) {
        return { valid: false, reason: 'JWT 가 만료되었습니다.' };
    }
    if (typeof payload.nbf === 'number' && nowMs + skewMs < payload.nbf * 1000) {
        return { valid: false, reason: 'JWT 가 아직 유효하지 않습니다 (nbf).' };
    }
    if (opts.issuer && payload.iss !== opts.issuer) {
        return { valid: false, reason: 'JWT issuer 불일치.' };
    }
    if (opts.audience) {
        const aud = payload.aud;
        const audList = Array.isArray(aud) ? aud : [aud];
        if (!audList.includes(opts.audience)) {
            return { valid: false, reason: 'JWT audience 불일치.' };
        }
    }

    return { valid: true, payload, header };
}

function _b64urlDecodeToString(s) {
    const bytes = _b64urlToBytes(s);
    return new TextDecoder().decode(bytes);
}

function _b64urlToBytes(s) {
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
    const base64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
    // 환경 독립: atob 가 있으면 사용, 아니면 Buffer 폴백
    if (typeof atob !== 'undefined') {
        const bin = atob(base64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }
    return new Uint8Array(Buffer.from(base64, 'base64'));
}

// ─────────────────────────────────────────────────────────────
// SQL → (op, primaryTable) 추출 — 워커 인라인 버전과 동일해야 함
// ─────────────────────────────────────────────────────────────

/**
 * SQL 에서 주 연산과 주 테이블을 추출. 파싱 불가 시 { op: null, table: null }.
 * 워커 db.ts 에 인라인된 extract 로직과 일치해야 합니다.
 */
export function extractOpAndTable(sql) {
    if (typeof sql !== 'string' || sql.length === 0) return { op: null, table: null };
    const normalized = _stripStringsAndComments(sql).replace(/\s+/g, ' ').trim();
    const upper = normalized.toUpperCase();
    const head = upper.trimStart();
    let op = null;
    if (head.startsWith('SELECT')) op = 'SELECT';
    else if (head.startsWith('WITH')) op = 'SELECT';
    else if (head.startsWith('INSERT')) op = 'INSERT';
    else if (head.startsWith('UPDATE')) op = 'UPDATE';
    else if (head.startsWith('DELETE')) op = 'DELETE';
    else if (head.startsWith('CREATE TABLE')) op = 'CREATE';
    if (!op) return { op: null, table: null };

    const ident = '["\'`]?([A-Z_][\\w]*(?:\\.[A-Z_][\\w]*)?)["\'`]?';
    const patterns = {
        SELECT: new RegExp('\\bFROM\\s+' + ident),
        INSERT: new RegExp('\\bINTO\\s+' + ident),
        UPDATE: new RegExp('\\bUPDATE\\s+' + ident),
        DELETE: new RegExp('\\bFROM\\s+' + ident),
        CREATE: new RegExp('\\bTABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?' + ident),
    };
    const m = upper.match(patterns[op]);
    if (!m) return { op, table: null };
    const parts = m[1].split('.');
    return { op, table: parts[parts.length - 1].toLowerCase() };
}

function _stripStringsAndComments(sql) {
    let out = '';
    let i = 0;
    const n = sql.length;
    while (i < n) {
        const ch = sql[i];
        const next = sql[i + 1];
        if (ch === '-' && next === '-') { while (i < n && sql[i] !== '\n') i++; out += ' '; continue; }
        if (ch === '/' && next === '*') { i += 2; while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i++; i += 2; out += ' '; continue; }
        if (ch === "'") { i++; while (i < n) { if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; } if (sql[i] === "'") { i++; break; } i++; } out += " '' "; continue; }
        if (ch === '"') { out += '"'; i++; while (i < n) { if (sql[i] === '"' && sql[i + 1] === '"') { out += '""'; i += 2; continue; } if (sql[i] === '"') { out += '"'; i++; break; } out += sql[i]; i++; } continue; }
        if (ch === '`') { out += '`'; i++; while (i < n && sql[i] !== '`') { out += sql[i]; i++; } if (sql[i] === '`') { out += '`'; i++; } continue; }
        out += ch;
        i++;
    }
    return out;
}
