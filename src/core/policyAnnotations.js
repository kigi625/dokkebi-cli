// @dokkebi-module: policyAnnotations
// ──────────────────────────────────────────────────────────────
// Policy Annotations — 컨트롤러/서비스 코드의 JSDoc 어노테이션을
// 정적 분석으로 추출해 Authorization Policy 와 Tenant Policy 의
// 추가 입력으로 사용한다.
//
// 지원 어노테이션 (JSDoc 안 어디에나 위치 가능):
//
//   @dokkebi-policy table:NAME access:VERB [public:true | auth:true |
//                   roles:['r1','r2'] | deny:true]
//
//     - VERB: read | write | delete | create | all
//     - 여러 개 선언 가능. 한 줄 한 선언.
//
//   @dokkebi-tenant table:NAME column:COL [claim:NAME] [mode:enforce|none]
//
//   @dokkebi-capability feature:NAME route:"METHOD /path" [roles:['r1','r2'] |
//                       auth:true | public:true | deny:true] [ttl:10000]
//
//     DSL 에 옵션을 추가하지 못하는 경우(서드파티 모델 등) 컨트롤러에서
//     명시할 수 있는 폴백 채널.
//
// 예:
//   /**
//    * @dokkebi-policy table:premium_contents access:read roles:['premium','admin']
//    * @dokkebi-policy table:premium_contents access:write roles:['admin']
//    * @dokkebi-policy table:public_blog     access:read public:true
//    * @dokkebi-tenant table:notes column:user_id
//    */
//   router.get('/api/premium/contents', async () => { ... });
//
// 우선순위 (낮음 → 높음):
//   1) convention 추론 (policyInference.js)
//   2) DSL 의 table(...) 옵션
//   3) JSDoc @dokkebi-policy / @dokkebi-tenant
//   4) dokkebi.config.js 명시값
//
// 핵심 원칙:
//   - 어노테이션은 **선언적**이며, 빌드 타임에만 읽힌다.
//   - 런타임에는 영향이 없으며 일반 JSDoc 으로도 무해하게 보인다.
//   - 추출된 규칙은 빌드 로그로 노출 (blind acceptance 방지).
// ──────────────────────────────────────────────────────────────

import fs from 'fs/promises';
import path from 'path';

const CONTROLLER_ROOTS = [
    'backend/controllers',
    'backend/services',
    'backend/api',
    'backend',
    'src/backend/controllers',
    'src/backend',
    'server/controllers',
    'server',
];

const CTRL_EXTS = new Set(['.ts', '.tsx', '.js', '.mjs', '.mts', '.cts']);

const IGNORE_DIRS = new Set([
    'node_modules', '.git', '.dokkebi', '_dokkebi', 'dist', 'build', 'out',
    '.next', '.nuxt', '.vite', '.cache', 'coverage', '.turbo', 'models',
]);

/**
 * @returns {Promise<{
 *   rules: Record<string, { public?: boolean; auth?: boolean; roles?: string[]; deny?: boolean }>,
 *   tenants: Record<string, { tenantColumn: string; sessionClaim?: string; mode?: 'enforce' | 'none' }>,
 *   scannedFiles: number,
 *   capabilities: Record<string, { routes: string[], public?: boolean; auth?: boolean; roles?: string[]; deny?: boolean; ttlMs?: number }>,
 *   sources: Array<{ file: string; line: number; raw: string }>,
 * }>}
 */
export async function scanPolicyAnnotations(projectDir, opts = {}) {
    const roots = opts.controllerRoots || CONTROLLER_ROOTS;
    const verbose = !!opts.verbose;

    const rules = {};
    const tenants = {};
    const capabilities = {};
    const sources = [];
    let scannedFiles = 0;

    const seen = new Set();
    for (const root of roots) {
        const abs = path.join(projectDir, root);
        let exists = true;
        try { await fs.access(abs); } catch { exists = false; }
        if (!exists) continue;

        await _walk(abs, IGNORE_DIRS, async (file) => {
            if (seen.has(file)) return;
            seen.add(file);
            if (!CTRL_EXTS.has(path.extname(file))) return;
            let content;
            try { content = await fs.readFile(file, 'utf-8'); } catch { return; }
            // 빠른 스킵: 어노테이션 키워드가 없으면 패스
            if (content.indexOf('@dokkebi-policy') < 0 &&
                content.indexOf('@dokkebi-tenant') < 0 &&
                content.indexOf('@dokkebi-capability') < 0) return;

            const found = extractAnnotations(content);
            if (found.policies.length === 0 && found.tenants.length === 0 && found.capabilities.length === 0) return;

            scannedFiles++;
            const relFile = path.relative(projectDir, file);

            for (const p of found.policies) {
                const key = `${p.op}:${p.table.toLowerCase()}`;
                rules[key] = p.spec;
                sources.push({ file: relFile, line: p.line, raw: p.raw });
                if (verbose) {
                    console.log(`[policyAnnotations]   ✓ ${key} ← ${relFile}:${p.line}`);
                }
            }
            for (const tn of found.tenants) {
                tenants[tn.table] = {
                    tenantColumn: tn.column,
                    sessionClaim: tn.claim || tn.column,
                    mode: tn.mode || 'enforce',
                };
                sources.push({ file: relFile, line: tn.line, raw: tn.raw });
                if (verbose) {
                    console.log(`[policyAnnotations]   ✓ tenant ${tn.table}.${tn.column} ← ${relFile}:${tn.line}`);
                }
            }
            for (const cap of found.capabilities) {
                if (!capabilities[cap.feature]) {
                    capabilities[cap.feature] = { routes: [] };
                }
                const cur = capabilities[cap.feature];
                cur.routes = Array.from(new Set([...(cur.routes || []), cap.route]));
                if (cap.spec.public === true) cur.public = true;
                if (cap.spec.auth === true) cur.auth = true;
                if (Array.isArray(cap.spec.roles)) cur.roles = cap.spec.roles;
                if (cap.spec.deny === true) cur.deny = true;
                if (Number.isFinite(cap.spec.ttlMs)) cur.ttlMs = cap.spec.ttlMs;
                sources.push({ file: relFile, line: cap.line, raw: cap.raw });
                if (verbose) {
                    console.log(`[policyAnnotations]   ✓ capability ${cap.feature} ${cap.route} ← ${relFile}:${cap.line}`);
                }
            }
        });
    }

    return { rules, tenants, capabilities, scannedFiles, sources };
}

/**
 * 단일 소스 파일에서 @dokkebi-policy / @dokkebi-tenant 어노테이션을 추출.
 * JSDoc(/** ... *\/) 또는 라인 주석(//) 어디에 있어도 인식.
 */
export function extractAnnotations(source) {
    const policies = [];
    const tenants = [];
    const capabilities = [];

    const lines = source.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];

        const polMatch = raw.match(/@dokkebi-policy\s+(.+)$/);
        if (polMatch) {
            const parsed = _parsePolicyLine(polMatch[1]);
            if (Array.isArray(parsed)) {
                for (const item of parsed) {
                    policies.push({ ...item, line: i + 1, raw: raw.trim() });
                }
            } else if (parsed) {
                policies.push({ ...parsed, line: i + 1, raw: raw.trim() });
            }
        }

        const tnMatch = raw.match(/@dokkebi-tenant\s+(.+)$/);
        if (tnMatch) {
            const parsed = _parseTenantLine(tnMatch[1]);
            if (parsed) tenants.push({ ...parsed, line: i + 1, raw: raw.trim() });
        }

        const capMatch = raw.match(/@dokkebi-capability\s+(.+)$/);
        if (capMatch) {
            const parsed = _parseCapabilityLine(capMatch[1]);
            if (parsed) capabilities.push({ ...parsed, line: i + 1, raw: raw.trim() });
        }
    }

    return { policies, tenants, capabilities };
}

/**
 * "table:premium_contents access:read roles:['premium','admin']" → 파싱.
 * key:value 토큰 사이는 공백 구분.
 */
function _parsePolicyLine(body) {
    const tokens = _tokenizeKv(body);
    let table = null;
    let access = null;
    const spec = {};

    for (const { key, value } of tokens) {
        const k = key.toLowerCase();
        if (k === 'table')  table = value;
        else if (k === 'access') access = value.toLowerCase();
        else if (k === 'public' && _truthy(value)) spec.public = true;
        else if (k === 'auth'   && _truthy(value)) spec.auth = true;
        else if (k === 'deny'   && _truthy(value)) spec.deny = true;
        else if (k === 'roles') {
            const roles = _parseList(value);
            if (roles.length > 0) spec.roles = roles;
        }
    }

    if (!table || !access) return null;

    // access verb → SQL op 변환
    const ops = _accessVerbToOps(access);
    if (ops.length === 0) return null;

    if (Object.keys(spec).length === 0) return null;

    return ops.map((op) => ({ op, table, spec }));
}

function _accessVerbToOps(verb) {
    switch (verb) {
        case 'read':   return ['SELECT'];
        case 'write':  return ['INSERT', 'UPDATE'];
        case 'delete': return ['DELETE'];
        case 'create': return ['CREATE'];
        case 'all':    return ['SELECT', 'INSERT', 'UPDATE', 'DELETE'];
        default:
            // SELECT / INSERT / UPDATE / DELETE 직접 입력 허용
            const upper = verb.toUpperCase();
            if (['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE'].includes(upper)) {
                return [upper];
            }
            return [];
    }
}

function _parseTenantLine(body) {
    const tokens = _tokenizeKv(body);
    let table = null, column = null, claim = null, mode = null;

    for (const { key, value } of tokens) {
        const k = key.toLowerCase();
        if (k === 'table')  table = value;
        else if (k === 'column') column = value;
        else if (k === 'claim')  claim = value;
        else if (k === 'mode')   mode = value;
    }

    if (!table || !column) return null;
    return { table, column, claim, mode };
}

function _parseCapabilityLine(body) {
    const tokens = _tokenizeKv(body);
    let feature = null;
    let route = null;
    const spec = {};
    for (const { key, value } of tokens) {
        const k = key.toLowerCase();
        if (k === 'feature') feature = value;
        else if (k === 'route') route = _stripQuotes(value);
        else if (k === 'public' && _truthy(value)) spec.public = true;
        else if (k === 'auth' && _truthy(value)) spec.auth = true;
        else if (k === 'deny' && _truthy(value)) spec.deny = true;
        else if (k === 'roles') {
            const roles = _parseList(value);
            if (roles.length > 0) spec.roles = roles;
        } else if (k === 'ttl' || k === 'ttlms') {
            const n = Number(value);
            if (Number.isFinite(n) && n > 0) spec.ttlMs = Math.floor(n);
        }
    }
    if (!feature || !route || Object.keys(spec).length === 0) return null;
    return { feature, route: _normalizeRoute(route), spec };
}

function _stripQuotes(value) {
    const s = String(value || '').trim();
    if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'")) || (s.startsWith('`') && s.endsWith('`'))) {
        return s.slice(1, -1);
    }
    return s;
}

function _normalizeRoute(route) {
    const s = String(route || '').trim().replace(/\s+/g, ' ');
    const m = /^([A-Za-z*]+)\s+(.+)$/.exec(s);
    if (!m) return s;
    return `${m[1].toUpperCase()} ${m[2]}`;
}

/**
 * "key:value key:['a','b'] key:value" 형태를 토큰 단위로 분리.
 * 따옴표/대괄호 안의 공백은 보존.
 */
function _tokenizeKv(input) {
    const out = [];
    const n = input.length;
    let i = 0;

    while (i < n) {
        // 공백 스킵
        while (i < n && /\s/.test(input[i])) i++;
        if (i >= n) break;

        // key 추출
        let kStart = i;
        while (i < n && /[A-Za-z_][A-Za-z0-9_-]*/.test(input[i])) i++;
        const key = input.slice(kStart, i);
        if (!key) { i++; continue; }

        // ':' 구분자
        if (input[i] !== ':') {
            // bare key (e.g. "public") → value=true 로 처리
            out.push({ key, value: 'true' });
            continue;
        }
        i++;

        // value 추출 — 다음 공백까지, 단 [...] 또는 '...' / "..." 안의 공백은 보존
        let vStart = i;
        let depth = 0;
        let quote = null;
        while (i < n) {
            const ch = input[i];
            if (quote) {
                if (ch === quote) quote = null;
                i++; continue;
            }
            if (ch === "'" || ch === '"' || ch === '`') { quote = ch; i++; continue; }
            if (ch === '[' || ch === '(' || ch === '{') { depth++; i++; continue; }
            if (ch === ']' || ch === ')' || ch === '}') { depth--; i++; continue; }
            if (depth === 0 && /\s/.test(ch)) break;
            i++;
        }
        const value = input.slice(vStart, i).trim();
        if (value) out.push({ key, value });
    }

    return out;
}

function _truthy(v) {
    if (v === undefined || v === null) return false;
    const s = String(v).toLowerCase();
    return s === 'true' || s === '1' || s === 'yes';
}

function _parseList(value) {
    if (!value) return [];
    // ['a', "b", `c`] 형태에서 항목만 추출
    const m = value.match(/^\[(.*)\]$/);
    const inner = m ? m[1] : value;
    const items = inner.match(/(['"`])([^'"`]+)\1/g) || [];
    return items.map((s) => s.slice(1, -1)).filter(Boolean);
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
 * scanPolicyAnnotations 결과를 inferPolicyFromProject 결과와 병합.
 * 어노테이션 규칙은 convention 추론보다 우선 (덮어쓰기).
 */
export function mergeAnnotationsIntoInferred(inferred, annotations) {
    const out = {
        ...inferred,
        rules: { ...(inferred.rules || {}) },
        tables: { ...(inferred.tables || {}) },
    };

    // tenant 어노테이션 → tables 덮어쓰기
    for (const [tableName, tn] of Object.entries(annotations.tenants || {})) {
        out.tables[tableName] = {
            tenantColumn: tn.tenantColumn,
            mode: tn.mode || 'enforce',
            sessionClaim: tn.sessionClaim || tn.tenantColumn,
            _inferred: true,
            _explicit: true,
            _reason: 'jsdoc-annotation',
        };
        if (!out.detectedTables) out.detectedTables = [];
        if (!out.detectedTables.includes(tableName)) out.detectedTables.push(tableName);
    }

    // policy 어노테이션 → rules 덮어쓰기 (단일 op 단위로 이미 분해됨)
    for (const [key, spec] of Object.entries(annotations.rules || {})) {
        out.rules[key] = { ...spec, _inferred: true, _explicit: true };
    }

    return out;
}
