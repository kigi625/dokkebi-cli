// @dokkebi-module: queryScanner
// ──────────────────────────────────────────────────────────────
// Query Scanner — backend/** (+ frontend 소스) 정적 스캔으로
// 실제 코드에 작성된 SQL 문자열 리터럴을 자동 수집한다.
//
// 목적:
//   `dok dev` 런타임 학습만으로는 개발자가 실행하지 않은 경로의
//   쿼리 shape 이 레지스트리에 누락된다. 정적 스캔을 병행하면
//   `dok build` / `dok deploy` 시점에 코드에 존재하는 모든 SQL 을
//   한번에 수집할 수 있다.
//
// 수집 대상:
//   - `.prepare("...")`, `.prepare('...')`, `.prepare(`...`)`
//   - `.exec("...")`, `.execute("...")`, `.run("...")`, `.all("...")`
//   - ``sql`...` `` / ``raw`...` `` / ``db`...` `` (tagged template)
//   - **자유 형식 string literal** 중 SQL 키워드로 시작하는 것
//     (const SQL = "SELECT ..." 같은 흔한 패턴 포괄)
//
// 필터:
//   - SQL 후보는 첫 토큰이 SELECT/INSERT/UPDATE/DELETE/WITH/REPLACE 여야 함
//   - 템플릿 리터럴의 `${...}` interpolation 이 있으면 기록하되
//     canonicalize 결과가 빈 파라미터(`?`) 로 수렴하는 경우만 채택.
//     (자유 문자열 치환은 shape 가 동적이라 queryId 가 불안정)
//   - 최소 길이 8 (너무 짧은 거짓 양성 차단)
//
// 한계:
//   - 주석 내부, 문자열 내부의 "SELECT ..." 우연 매치는 거르지 못함 → 낮은 noise
//   - 동적으로 합쳐지는 SQL (e.g. `"SELECT * FROM " + table`) 은 미수집.
//     이런 케이스는 `// @dokkebi-query: ...` 주석으로 명시 권장.
// ──────────────────────────────────────────────────────────────

import fs from 'fs/promises';
import path from 'path';
import { QueryRegistry } from './queryRegistry.js';
import { extractOpAndTable } from './authorizationPolicy.js';

const SQL_START_RE = /^\s*(SELECT|INSERT|UPDATE|DELETE|WITH|REPLACE|CREATE\s+TABLE|CREATE\s+INDEX)\b/i;

const DEFAULT_ROOTS = [
    'backend',
    'src/backend',
    'server',
    'functions',
    'workers',
    'api',
    'src/api',
    'src/server',
];

const IGNORE_DIRS = new Set([
    'node_modules', '.git', '.dokkebi', '_dokkebi', 'dist', 'build', 'out',
    '.next', '.nuxt', '.vite', '.cache', 'coverage', '.turbo',
]);

/**
 * 소스 파일에서 문자열 리터럴을 뽑아낸다.
 * 반환: [{ value, quote, dynamic, line }]
 *   - value: 리터럴 내용 (따옴표 제외)
 *   - quote: '"' | "'" | '`'
 *   - dynamic: 백틱 안에 ${} 포함 여부
 *   - line: 1-based 라인 번호
 */
export function extractStringLiterals(source) {
    const out = [];
    const n = source.length;
    let i = 0;
    let line = 1;

    while (i < n) {
        const ch = source[i];
        const next = source[i + 1];

        // 라인 카운터
        if (ch === '\n') { line++; i++; continue; }

        // 라인 주석
        if (ch === '/' && next === '/') {
            while (i < n && source[i] !== '\n') i++;
            continue;
        }
        // 블록 주석
        if (ch === '/' && next === '*') {
            i += 2;
            while (i < n && !(source[i] === '*' && source[i + 1] === '/')) {
                if (source[i] === '\n') line++;
                i++;
            }
            i += 2;
            continue;
        }
        // 정규식 리터럴은 대충 skip (앞 토큰 상관없이 / 다음 탐욕 방어)
        //   false positive 를 줄이기 위해 SQL 후보 SELECT/INSERT/... 로 2차 필터가 있음.

        // 문자열 리터럴
        if (ch === '"' || ch === "'") {
            const quote = ch;
            const startLine = line;
            i++;
            let buf = '';
            while (i < n) {
                const c = source[i];
                if (c === '\\') { buf += source[i + 1] || ''; i += 2; continue; }
                if (c === quote) { i++; break; }
                if (c === '\n') line++;
                buf += c;
                i++;
            }
            out.push({ value: buf, quote, dynamic: false, line: startLine });
            continue;
        }

        // 백틱 (템플릿 리터럴)
        if (ch === '`') {
            const startLine = line;
            i++;
            let buf = '';
            let dynamic = false;
            while (i < n) {
                const c = source[i];
                if (c === '\\') { buf += (source[i + 1] || ''); i += 2; continue; }
                if (c === '`') { i++; break; }
                if (c === '$' && source[i + 1] === '{') {
                    dynamic = true;
                    buf += '?'; // placeholder 로 수렴
                    i += 2;
                    let depth = 1;
                    while (i < n && depth > 0) {
                        const cc = source[i];
                        if (cc === '{') depth++;
                        else if (cc === '}') depth--;
                        if (cc === '\n') line++;
                        i++;
                    }
                    continue;
                }
                if (c === '\n') line++;
                buf += c;
                i++;
            }
            out.push({ value: buf, quote: '`', dynamic, line: startLine });
            continue;
        }

        i++;
    }
    return out;
}

/**
 * 단일 파일에서 SQL 후보를 추출해 registry 에 추가한다.
 * opTableStats 가 주어지면 각 SQL 의 (op, table) 을 집계에 반영.
 */
export function scanFile(registry, source, relPath, opTableStats = null) {
    let added = 0, skippedDynamic = 0;
    const literals = extractStringLiterals(source);
    for (const lit of literals) {
        const v = lit.value;
        if (!v || v.length < 8) continue;
        if (!SQL_START_RE.test(v)) continue;

        // 템플릿 리터럴의 ${} 는 `?` 로 치환되어 canonical 로 수렴.
        //   그러나 컬럼/테이블 명이 동적이면 queryId 가 실제 호출과 불일치.
        //   → 템플릿 리터럴이면서 dynamic 이면 경고용으로만 기록하고 레지스트리엔 추가 (낮은 우선순위).
        //   실제로 많은 DSL 은 ${} 를 파라미터로 사용하므로 대부분 정상 동작.
        if (lit.dynamic) skippedDynamic++;

        try {
            registry.addSql(v, {
                sources: [{
                    file: relPath,
                    symbol: `scan:L${lit.line}${lit.dynamic ? ':dynamic' : ''}`,
                }],
            });
            added++;
        } catch { /* invalid SQL text — 조용히 skip */ }

        // (op, table) 통계 수집 — policyInference 가 사용
        if (opTableStats) {
            try {
                const { op, table } = extractOpAndTable(v);
                if (op && table) {
                    const key = `${op}:${table}`;
                    const cur = opTableStats.get(key);
                    if (cur) cur.count++;
                    else opTableStats.set(key, { op, table, count: 1 });
                }
            } catch { /* ignore */ }
        }
    }
    return { added, skippedDynamic };
}

/**
 * 프로젝트 디렉토리 전체를 정적 스캔.
 * @param {string} projectDir
 * @param {object} [opts]
 * @param {string[]} [opts.roots]   스캔 루트 (기본: backend 계열 + src 일부)
 * @param {string[]} [opts.extensions] (기본: .ts/.tsx/.js/.mjs/.cjs)
 * @param {boolean} [opts.verbose=false]
 */
export async function scanProjectQueries(projectDir, opts = {}) {
    const exts = opts.extensions || ['.ts', '.tsx', '.js', '.mjs', '.cjs', '.mts', '.cts'];
    const roots = opts.roots || DEFAULT_ROOTS;
    const verbose = !!opts.verbose;
    const registry = new QueryRegistry();
    const opTableStats = new Map(); // "OP:table" → { op, table, count }

    let fileCount = 0;
    let addedTotal = 0;
    let dynamicTotal = 0;
    const seen = new Set();
    const dynamicSamples = [];

    for (const root of roots) {
        const abs = path.join(projectDir, root);
        let exists = true;
        try { await fs.access(abs); } catch { exists = false; }
        if (!exists) continue;

        await walk(abs, async (file) => {
            if (seen.has(file)) return;
            seen.add(file);
            const ext = path.extname(file);
            if (!exts.includes(ext)) return;

            let content;
            try { content = await fs.readFile(file, 'utf-8'); } catch { return; }

            const rel = path.relative(projectDir, file);
            const r = scanFile(registry, content, rel, opTableStats);
            if (r.added > 0 || r.skippedDynamic > 0) {
                fileCount++;
                addedTotal += r.added;
                dynamicTotal += r.skippedDynamic;
                if (verbose && r.added > 0) {
                    console.log(`[queryScanner]   + ${rel} (${r.added} 쿼리${r.skippedDynamic ? `, 동적 ${r.skippedDynamic}` : ''})`);
                }
                if (r.skippedDynamic > 0 && dynamicSamples.length < 5) {
                    dynamicSamples.push(rel);
                }
            }
        });
    }

    return {
        registry,
        opTableStats,
        stats: {
            files: fileCount,
            added: addedTotal,
            dynamic: dynamicTotal,
            dynamicSamples,
        },
    };
}

async function walk(dir, visit) {
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); }
    catch { return; }
    for (const entry of entries) {
        if (IGNORE_DIRS.has(entry.name)) continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) await walk(full, visit);
        else await visit(full);
    }
}
