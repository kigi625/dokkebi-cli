/**
 * Dokkebi SEO — 라우터 스캔 (PR1)
 *
 * frontend/src/**\/*.{tsx,jsx,ts,js} 를 정규식으로 스캔해
 * react-router-dom 의 <Route path="..." element={<X/>}> 패턴과
 * createBrowserRouter([{ path, element }]) 패턴을 추출한다.
 *
 * 의도적으로 AST 파서(@babel/parser) 의존성을 추가하지 않는다 — 도깨비 다른
 * 스캐너 (policyAnnotations.js, queryScanner.js) 와 동일하게 정규식 + 윈도잉으로
 * 안정적인 결과를 낸다. 거짓양성은 inferPageMeta.js 가 추가 검증한다.
 *
 * 출력 형식:
 *   ScannedRoute = {
 *     path: '/projects/:id',
 *     componentName: 'BlogPostPage',
 *     componentFile: '/abs/path/to/BlogPostPage.tsx' | null,
 *     isDynamic: boolean,
 *     params: ['id'],
 *     protected: boolean,    // <ProtectedRoute> 래핑 여부
 *     redirect: boolean,     // <Navigate> 만 있는 라우트
 *     declaredIn: '/abs/path/to/App.tsx',
 *     line: 42,
 *   }
 */

import path from 'path';
import fs from 'fs/promises';

const ROUTE_FILE_RE = /\.(tsx|jsx|ts|js)$/;
const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', '.git', '.next', '.dokkebi', 'coverage']);

// <Route path="..." element={<X .../>} /> — 자식 노드 없는 형태와 자식 element 모두 허용.
// 멀티라인 element 도 허용 (\s 사용).
const ROUTE_JSX_RE = /<Route\s+([^>]*?)(?:\/>|>)/gms;

// element={<Foo .../>} 또는 element={<Foo>...</Foo>}
const ELEMENT_INNER_RE = /element\s*=\s*\{\s*([\s\S]*?)\s*\}\s*(?:\/>|>|path|children|index|caseSensitive)/;

// path="..." (싱글/더블/템플릿)
const PATH_ATTR_RE = /\bpath\s*=\s*(?:"([^"]*)"|'([^']*)'|`([^`]*)`)/;

// element 내부에서 첫 컴포넌트 이름 추출. <Foo /> 또는 <Foo>...
const FIRST_COMPONENT_RE = /<\s*([A-Z][A-Za-z0-9_]*)\b/;

// ProtectedRoute / RequireAuth / AuthRequired … 패턴
const PROTECTED_NAMES = /^(?:Protected[A-Za-z]*|RequireAuth|AuthRequired|PrivateRoute|AuthGuard|GuardedRoute)$/;

// <Navigate to="..." replace />  (redirect 라우트 식별)
const NAVIGATE_RE = /<\s*Navigate\b/;

/**
 * @param {string} dir
 * @returns {Promise<string[]>}
 */
async function walk(dir) {
    const out = [];
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); }
    catch { return out; }
    for (const ent of entries) {
        if (ent.name.startsWith('.') && ent.name !== '.') continue;
        const p = path.join(dir, ent.name);
        if (ent.isDirectory()) {
            if (SKIP_DIRS.has(ent.name)) continue;
            out.push(...(await walk(p)));
        } else if (ent.isFile() && ROUTE_FILE_RE.test(ent.name)) {
            out.push(p);
        }
    }
    return out;
}

/**
 * import 문에서 컴포넌트 이름 → 파일 경로 매핑.
 * import Foo from './pages/Foo';
 * import { Foo } from './pages/Foo';
 * import Foo, { Bar } from './pages/Foo';
 */
function buildImportMap(source, fromFile, frontendDir) {
    const map = {};
    const importRe = /import\s+(?:type\s+)?(?:([A-Za-z_$][\w$]*)(?:\s*,\s*\{([^}]*)\})?|\{([^}]*)\})\s+from\s+['"]([^'"]+)['"]/g;
    let m;
    while ((m = importRe.exec(source)) !== null) {
        const def = m[1];
        const named = m[2] || m[3];
        const spec = m[4];
        if (!spec) continue;
        const resolved = resolveImport(spec, fromFile, frontendDir);
        if (def) map[def] = resolved;
        if (named) {
            for (const part of named.split(',')) {
                const name = part.trim().split(/\s+as\s+/i)[0].trim();
                if (name) map[name] = resolved;
            }
        }
    }
    return map;
}

function resolveImport(spec, fromFile, frontendDir) {
    if (!spec) return null;
    // 외부 패키지 (react-router-dom 등) 는 매핑 불필요
    if (!spec.startsWith('.') && !spec.startsWith('/')) return null;
    let abs = spec.startsWith('/') ? spec : path.resolve(path.dirname(fromFile), spec);
    // 확장자 미포함 → 후보 시도
    const exts = ['.tsx', '.jsx', '.ts', '.js'];
    return { rawSpec: spec, base: abs, exts, frontendDir };
}

async function realFileFromImport(meta) {
    if (!meta || typeof meta !== 'object' || !meta.base) return null;
    const candidates = [
        meta.base,
        ...meta.exts.map(e => meta.base + e),
        ...meta.exts.map(e => path.join(meta.base, 'index' + e)),
    ];
    for (const c of candidates) {
        try { await fs.access(c); return c; } catch { /* next */ }
    }
    return null;
}

function paramsOf(routePath) {
    const out = [];
    if (typeof routePath !== 'string') return out;
    for (const m of routePath.matchAll(/:([A-Za-z_][\w]*)/g)) out.push(m[1]);
    return out;
}

function lineOfIndex(source, idx) {
    let line = 1;
    for (let i = 0; i < idx && i < source.length; i++) if (source.charCodeAt(i) === 10) line++;
    return line;
}

/**
 * 한 파일에서 <Route> 선언을 파싱한다. 부모(<Route ... > children) 의 path 를
 * 자식의 prefix 로 합치는 단순 stack 추적도 수행한다 — react-router v6 nested
 * 라우트 대응.
 *
 * `<Route` 토큰을 발견하면 거기서부터 brace/quote 인지 스캐너로 태그를 완성
 * (열림 `>` 또는 자체 닫힘 `/>` 까지). 이렇게 해야 element={<X />} 처럼 attrs
 * 안에 `>` 가 있는 케이스를 안전하게 처리한다.
 */
function parseRoutesFromFile(source) {
    const tokens = [];
    const unresolved = []; // 동적 path 표현식 추적 — 리포트로 노출

    // 1) <Route 시작 위치를 모두 찾음
    const startRe = /<\s*Route\b/g;
    let sm;
    while ((sm = startRe.exec(source)) !== null) {
        const startIdx = sm.index;
        const tagAfter = scanJsxTag(source, sm.index + sm[0].length);
        if (!tagAfter) continue;
        const { attrsRaw, selfClose, endIdx } = tagAfter;
        const lineNo = lineOfIndex(source, startIdx);
        const pm = PATH_ATTR_RE.exec(attrsRaw);
        let localPath = pm ? (pm[1] ?? pm[2] ?? pm[3] ?? '') : null;

        // path={...} 표현식 추출 (문자열 리터럴이 아닐 때)
        let pathExprInner = null;
        if (localPath == null) {
            const exprIdx = attrsRaw.search(/\bpath\s*=\s*\{/);
            if (exprIdx >= 0) {
                const braceStart = attrsRaw.indexOf('{', exprIdx);
                if (braceStart >= 0) {
                    let depth = 0;
                    for (let i = braceStart; i < attrsRaw.length; i++) {
                        const ch = attrsRaw[i];
                        if (ch === '{') depth++;
                        else if (ch === '}') {
                            depth--;
                            if (depth === 0) {
                                pathExprInner = attrsRaw.slice(braceStart + 1, i).trim();
                                break;
                            }
                        }
                    }
                }
            }
        }

        // element={ ... } 추출
        let elementInner = null;
        const eIdx = attrsRaw.search(/\belement\s*=/);
        if (eIdx >= 0) {
            const braceStart = attrsRaw.indexOf('{', eIdx);
            if (braceStart >= 0) {
                let depth = 0;
                for (let i = braceStart; i < attrsRaw.length; i++) {
                    const ch = attrsRaw[i];
                    if (ch === '{') depth++;
                    else if (ch === '}') {
                        depth--;
                        if (depth === 0) {
                            elementInner = attrsRaw.slice(braceStart + 1, i).trim();
                            break;
                        }
                    }
                }
            }
        }
        tokens.push({
            kind: 'open',
            attrsRaw,
            path: localPath,
            pathExpr: pathExprInner,
            elementInner,
            selfClose,
            line: lineNo,
            index: startIdx,
            endIdx,
        });
    }

    // 2) </Route>
    const closeRe = /<\s*\/\s*Route\s*>/gms;
    let mc;
    while ((mc = closeRe.exec(source)) !== null) {
        tokens.push({ kind: 'close', index: mc.index });
    }
    tokens.sort((a, b) => a.index - b.index);

    // 3) stack 으로 nested path 합성
    const stack = [];
    const routes = [];
    for (const tk of tokens) {
        if (tk.kind === 'close') { stack.pop(); continue; }
        const parentPath = stack.length > 0 ? stack[stack.length - 1].path : '';

        // 동적 path 표현식 처리: path={`/${id}`} 또는 path={`/prefix/${item.slug}`}
        // 같은 파일에서 .map(...) 데이터 배열을 찾아 정적 path 목록으로 펼친다.
        if (tk.path == null && tk.pathExpr) {
            const expanded = expandPathExpr(tk.pathExpr, source, tk.elementInner);
            if (expanded && expanded.length > 0) {
                for (const exp of expanded) {
                    const combined = combinePaths(parentPath, exp.path);
                    if (exp.elementInner) {
                        routes.push({
                            combinedPath: combined,
                            elementInner: exp.elementInner,
                            line: tk.line,
                        });
                    }
                }
            } else {
                unresolved.push({
                    expression: 'path={' + tk.pathExpr + '}',
                    line: tk.line,
                });
            }
            // 동적 path 라우트는 자식을 가지지 않는 자체 닫힘이 일반적이므로 stack push 생략
            continue;
        }

        const own = tk.path == null ? '' : tk.path;
        const combined = combinePaths(parentPath, own);
        if (tk.path != null) {
            // children-as-element nested 라우트는 elementInner 가 없을 수도 있다.
            // 이 경우는 스킵 (정적 prerender 대상 아님).
            if (tk.elementInner) {
                routes.push({
                    combinedPath: combined,
                    elementInner: tk.elementInner,
                    line: tk.line,
                });
            }
        }
        if (!tk.selfClose) stack.push({ path: combined });
    }
    return { routes, unresolved };
}

/**
 * `path={`/${id}`}` 와 같은 템플릿 리터럴 path 표현식과 그 주변의
 * `.map(...)` 패턴을 분석해 정적 path 목록으로 펼친다.
 *
 * 지원 패턴:
 *   const FOO = [{ id: 'a', element: <A/> }, { id: 'b', element: <B/> }];
 *   FOO.map(({ id, element }) => <Route key={id} path={`/${id}`} element={element} />);
 *
 * 또는 더 단순한:
 *   ['a','b','c'].map(id => <Route path={`/${id}`} element={<X/>} />);
 *
 * 추출 키 후보: id, slug, path, key, name.
 *
 * @param {string} pathExpr
 * @param {string} source
 * @param {string|null} elementInner
 * @returns {Array<{path: string, elementInner: string|null}>}
 */
function expandPathExpr(pathExpr, source, elementInner) {
    // 템플릿 리터럴 안의 `${var}` 패턴 추출
    // pathExpr 는 attrs slice 그대로이므로 백틱 포함 가능: ` `/${id}` `
    const tplMatch = /^\s*`([^`]*)`\s*$/.exec(pathExpr);
    if (!tplMatch) return [];
    const tpl = tplMatch[1]; // `/${id}` → /${id}
    // ${...} 토큰들을 차례로 치환할 수 있는지 검사. 단일 식별자 또는 a.b 만 허용.
    const exprRefs = [];
    const tplPattern = tpl.replace(/\$\{([^}]+)\}/g, (_, ref) => {
        exprRefs.push(ref.trim());
        return '\u0000'; // 자리표시자
    });
    if (exprRefs.length === 0) {
        // 정적 템플릿 문자열 — 그대로 사용
        return [{ path: tpl, elementInner }];
    }

    // 같은 파일에서 .map(...) 호출의 인자 식별자가 일치하는 케이스 찾기
    // 1) ARR.map(({ id, ... }) => <Route ... />)  — destructured object
    // 2) ARR.map((item) => <Route ... path={`/${item.id}`} />) — member access
    // 3) ['a','b'].map(x => <Route path={`/${x}`} />) — inline array

    // 가장 간단: pathExpr 의 첫 ref 가 'id' 면 같은 파일의 [{id:'..'}, ...] 배열 데이터를 찾는다.
    const primaryRef = exprRefs[0];
    const primaryProp = primaryRef.includes('.') ? primaryRef.split('.').pop() : primaryRef;

    const candidates = collectArrayItems(source, primaryProp);
    if (candidates.length === 0) return [];

    return candidates.map((item) => {
        const value = item[primaryProp];
        if (typeof value !== 'string') return null;
        const expandedPath = tplPattern.replace(/\u0000/g, value);
        return { path: expandedPath, elementInner: item.__elementInner || elementInner };
    }).filter(Boolean);
}

/**
 * 파일 전체에서 `[{ <propName>: 'literal', ... }, ...]` 리터럴 배열을 찾아
 * 각 항목의 정적 문자열 키를 추출한다.
 *
 * 추가로 같은 항목에 element: <X /> 가 있으면 그 컴포넌트 이름을 함께 반환.
 */
function collectArrayItems(source, propName) {
    const out = [];
    if (!propName) return out;
    // 객체 리터럴 안에 `propName: '...'` 또는 `propName: "..."` 가 있으면 한 항목으로 본다.
    const itemRe = new RegExp('\\{[^{}]*?\\b' + propName + '\\s*:\\s*[\'"`]([^\'"`]+)[\'"`][^{}]*?\\}', 'gs');
    let m;
    while ((m = itemRe.exec(source)) !== null) {
        const block = m[0];
        const value = m[1];
        // element: <X .../> 또는 element: <X>...</X> 추출
        let elementInner = null;
        const elMatch = /\belement\s*:\s*(<[^>]+\/>|<[A-Z][A-Za-z0-9_]*\b[^>]*>)/.exec(block);
        if (elMatch) elementInner = elMatch[1];
        else {
            // element: VarName 형태 — 변수명만 있는 경우 element 추정 안되므로 null 유지
        }
        out.push({ [propName]: value, __elementInner: elementInner });
    }
    return out;
}

/**
 * JSX 여는 태그 끝(`>` 또는 `/>`)까지 스캔. brace/string/template literal 깊이를 추적해
 * attrs 안의 `>` 를 무시한다.
 *
 * @param {string} src
 * @param {number} startIdx - "<Route" 직후 첫 글자
 * @returns {{ attrsRaw: string, selfClose: boolean, endIdx: number } | null}
 */
function scanJsxTag(src, startIdx) {
    let i = startIdx;
    let braceDepth = 0;
    let str = null; // '"' | "'" | '`'
    let inLineComment = false;
    let inBlockComment = false;
    const attrStart = i;
    while (i < src.length) {
        const ch = src[i];
        const next = src[i + 1];

        if (inLineComment) {
            if (ch === '\n') inLineComment = false;
            i++; continue;
        }
        if (inBlockComment) {
            if (ch === '*' && next === '/') { inBlockComment = false; i += 2; continue; }
            i++; continue;
        }
        if (str) {
            if (ch === '\\') { i += 2; continue; }
            if (ch === str) str = null;
            i++; continue;
        }

        if (braceDepth === 0) {
            if (ch === '/' && next === '>') {
                return { attrsRaw: src.slice(attrStart, i), selfClose: true, endIdx: i + 2 };
            }
            if (ch === '>') {
                return { attrsRaw: src.slice(attrStart, i), selfClose: false, endIdx: i + 1 };
            }
        }

        if (ch === '/' && next === '/') { inLineComment = true; i += 2; continue; }
        if (ch === '/' && next === '*') { inBlockComment = true; i += 2; continue; }
        if (ch === '"' || ch === "'" || ch === '`') { str = ch; i++; continue; }
        if (ch === '{') { braceDepth++; i++; continue; }
        if (ch === '}') { braceDepth = Math.max(0, braceDepth - 1); i++; continue; }
        i++;
    }
    return null;
}

function combinePaths(parent, child) {
    if (!parent) return normalizePath(child || '');
    if (!child) return normalizePath(parent);
    if (child.startsWith('/')) return normalizePath(child);
    return normalizePath(parent.replace(/\/+$/, '') + '/' + child.replace(/^\/+/, ''));
}

function normalizePath(p) {
    if (!p) return '/';
    if (!p.startsWith('/')) p = '/' + p;
    // /a/b/ → /a/b (루트는 / 유지)
    if (p.length > 1) p = p.replace(/\/+$/, '');
    return p.replace(/\/{2,}/g, '/');
}

/**
 * elementInner ("<ProtectedRoute><BlogPostPage/></ProtectedRoute>" 또는 "<BlogPostPage/>"
 * 또는 "<Navigate to=\"/\" replace />" 등) 에서 컴포넌트 이름·redirect 여부·protected 여부 판정.
 */
function classifyElement(elementInner) {
    const out = { componentName: null, protected: false, redirect: false };
    if (!elementInner) return out;
    const first = FIRST_COMPONENT_RE.exec(elementInner);
    if (!first) return out;
    let name = first[1];
    if (PROTECTED_NAMES.test(name)) {
        out.protected = true;
        // 안쪽 첫 컴포넌트로 한 단계 더 들어간다
        const rest = elementInner.slice(first.index + first[0].length);
        const inner = FIRST_COMPONENT_RE.exec(rest);
        if (inner) name = inner[1];
    }
    if (name === 'Navigate') {
        out.redirect = true;
        out.componentName = 'Navigate';
        return out;
    }
    out.componentName = name;
    if (NAVIGATE_RE.test(elementInner)) out.redirect = true;
    return out;
}

/**
 * frontend 디렉터리 전체 스캔.
 * @param {string} frontendDir
 * @param {object} [opts]
 * @param {boolean} [opts.verbose]
 * @returns {Promise<{routes: Array<object>, scannedFiles: number, sourceFiles: string[]}>}
 */
export async function scanRouter(frontendDir, opts = {}) {
    const verbose = !!opts.verbose;
    const srcDir = await pickSrcDir(frontendDir);
    const files = await walk(srcDir);
    const result = [];
    let scanned = 0;
    const sourceFilesWithRoutes = new Set();
    const allUnresolved = [];

    for (const file of files) {
        let src;
        try { src = await fs.readFile(file, 'utf-8'); }
        catch { continue; }
        scanned++;
        // 빠른 거름망 — react-router-dom 또는 <Route 가 없으면 skip
        if (!/\bRoute\b/.test(src) || !/<\s*Route\b/.test(src)) continue;

        const importMap = buildImportMap(src, file, frontendDir);
        const parsed = parseRoutesFromFile(src);
        const found = parsed.routes;
        if (parsed.unresolved && parsed.unresolved.length > 0) {
            for (const u of parsed.unresolved) {
                allUnresolved.push({ ...u, file });
            }
        }
        if (found.length === 0) continue;
        sourceFilesWithRoutes.add(file);

        for (const r of found) {
            const cls = classifyElement(r.elementInner);
            if (!cls.componentName) continue;
            const importMeta = importMap[cls.componentName];
            const componentFile = await realFileFromImport(importMeta);
            const params = paramsOf(r.combinedPath);
            result.push({
                path: r.combinedPath,
                componentName: cls.componentName,
                componentFile,
                isDynamic: params.length > 0 || r.combinedPath.includes('*'),
                params,
                protected: cls.protected,
                redirect: cls.redirect,
                declaredIn: file,
                line: r.line,
            });
        }
    }

    // 중복 제거 — 같은 path+component 는 첫 발견만 유지 (legacy redirect 라우트 우선순위는 declaration order)
    const dedup = [];
    const seen = new Set();
    for (const r of result) {
        const key = r.path + '\0' + (r.componentName || '');
        if (seen.has(key)) continue;
        seen.add(key);
        dedup.push(r);
    }

    if (verbose) {
        console.log(`[dokkebi][seo] router scan: ${scanned} files, ${dedup.length} routes from ${sourceFilesWithRoutes.size} declarators`);
    }

    return {
        routes: dedup,
        scannedFiles: scanned,
        sourceFiles: Array.from(sourceFilesWithRoutes),
        unresolvedRoutes: allUnresolved,
    };
}

async function pickSrcDir(frontendDir) {
    const candidates = [
        path.join(frontendDir, 'src'),
        frontendDir,
    ];
    for (const c of candidates) {
        try {
            const stat = await fs.stat(c);
            if (stat.isDirectory()) return c;
        } catch { /* next */ }
    }
    return frontendDir;
}
