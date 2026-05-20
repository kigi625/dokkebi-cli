/**
 * Dokkebi SEO — 동적 라우트 D1 enumerate (PR2)
 *
 * 동적 라우트(/posts/:slug, /products/:id, /:lang/:username/post/:slug 등) 를
 * D1 데이터베이스에서 직접 조회해 정적 path 목록으로 펼친다.
 *
 * Zero-Config 자동 매칭 흐름:
 *   1) D1 sqlite_master 에서 모든 테이블 스키마 조회 (PRAGMA table_info)
 *   2) 라우트 path 의 정적 prefix(/posts/) + 마지막 동적 세그먼트 이름(:slug)
 *      을 단서로 후보 테이블 자동 매칭
 *   3) 컬럼 자동 감지:
 *        - id     ← :id   (PK 우선) | :slug → slug | :username → username
 *        - title  ← title | name | subject | headline
 *        - desc   ← description | summary | excerpt | content (앞 160자)
 *        - image  ← thumbnail | cover_image | og_image | image
 *        - lastmod← updated_at | modified_at | created_at
 *        - public ← public=1 | is_published=1 | status='published'
 *   4) Authorization Policy 가 SELECT:<table> 을 인증 필요로 두면 enumerate 스킵
 *      → Edge SEO Renderer (PR3) 위임 신호로 unresolved 에 기록
 *   5) 사용자가 seo.dynamic[].pattern + table 또는 query 를 명시하면
 *      그게 자동 매칭을 덮어쓴다.
 *
 * 출력:
 *   { expanded: Array<{path, title, description, image, lastmod, source: 'd1', __sourceTable, __sourceRow}>,
 *     skipped: Array<{pattern, reason}>,
 *     diagnostics: {tables: number, queries: number} }
 */

import { d1Execute, validateD1Config } from '../d1Integration.js';

const LANG_PARAM_NAMES = new Set(['lang', 'locale', 'language']);
const TITLE_COLS = ['title', 'name', 'subject', 'headline', 'label'];
const DESC_COLS  = ['description', 'summary', 'excerpt', 'content', 'body', 'subtitle'];
const IMAGE_COLS = ['thumbnail', 'thumbnail_url', 'cover_image', 'cover_url', 'og_image', 'image', 'image_url'];
const TIME_COLS  = ['updated_at', 'modified_at', 'created_at', 'published_at'];
const PUBLIC_BOOL_COLS = ['public', 'is_public', 'is_published', 'published', 'visible', 'is_visible'];

/**
 * D1 자격 검증. apiToken/accountId/databaseId 가 없으면 enumerate 자체 skip.
 */
function isD1Available(dbConfig) {
    if (!dbConfig || dbConfig.type !== 'd1') return false;
    const v = validateD1Config(dbConfig);
    return v.ok;
}

async function listTables(dbConfig) {
    const out = await d1Execute(dbConfig, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_dokkebi_%' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' AND name NOT LIKE 'd1\\_%' ESCAPE '\\' AND name NOT LIKE 'cf\\_%' ESCAPE '\\'");
    const rows = out.results || out.rows || [];
    return rows.map(r => r.name).filter(Boolean);
}

async function tableColumns(dbConfig, table) {
    const out = await d1Execute(dbConfig, `PRAGMA table_info("${String(table).replace(/"/g, '""')}")`);
    const rows = out.results || out.rows || [];
    return rows.map(r => ({ name: r.name, type: String(r.type || '').toUpperCase(), pk: !!r.pk, notnull: !!r.notnull }));
}

/**
 * 컬럼 후보 매칭 — 대소문자 무시.
 */
function pickFirstMatching(cols, candidates) {
    const lc = new Set(cols.map(c => c.name.toLowerCase()));
    for (const cand of candidates) {
        if (lc.has(cand.toLowerCase())) {
            return cols.find(c => c.name.toLowerCase() === cand.toLowerCase()).name;
        }
    }
    return null;
}

/**
 * 라우트 path 의 정적 prefix (마지막 동적 세그먼트 이전까지) + 마지막 동적 세그먼트 이름
 * → 테이블명 후보 자동 추정.
 *   /posts/:slug                       → prefix=posts, paramName=slug
 *   /products/:id                      → prefix=products, paramName=id
 *   /:lang/:username/post/:slug        → prefix=post, paramName=slug
 *   /blog/:slug                        → prefix=blog, paramName=slug
 */
function inferTableFromRoute(routePath, allTables) {
    const segs = routePath.split('/').filter(Boolean);
    if (segs.length === 0) return null;

    // 마지막 동적 세그먼트의 직전 정적 세그먼트
    let prefixSeg = null;
    let paramSeg = null;
    for (let i = segs.length - 1; i >= 0; i--) {
        if (segs[i].startsWith(':') || segs[i] === '*') {
            paramSeg = segs[i].replace(/^:/, '');
            // 직전 정적 세그먼트
            for (let j = i - 1; j >= 0; j--) {
                if (!segs[j].startsWith(':') && segs[j] !== '*') {
                    prefixSeg = segs[j];
                    break;
                }
            }
            break;
        }
    }
    if (!paramSeg) return null;

    const lcTables = new Map();
    for (const t of allTables) lcTables.set(t.toLowerCase(), t);

    const candidates = [];
    if (prefixSeg) {
        candidates.push(prefixSeg);
        if (!prefixSeg.endsWith('s')) candidates.push(prefixSeg + 's');
        if (prefixSeg.endsWith('s')) candidates.push(prefixSeg.slice(0, -1));
        // /post/:slug → posts 도 가능, /blog/ → blog_posts 후보
        candidates.push(prefixSeg + '_posts', prefixSeg + 'posts');
    }
    // paramSeg 자체가 테이블명일 수도 있음
    //   /:userId    → users
    //   /:user_id   → users
    //   /:username  → users (name suffix 제거 후 복수)
    //   /:slug      → 의미 없음 (skip)
    if (paramSeg) {
        const lc = paramSeg.toLowerCase();
        if (lc === 'slug' || lc === 'id') {
            // 의미 없는 단어 — prefix 기반에 의존
        } else if (paramSeg.endsWith('Id')) {
            const base = paramSeg.slice(0, -2).toLowerCase();
            candidates.push(base, base + 's');
        } else if (paramSeg.endsWith('_id')) {
            const base = paramSeg.slice(0, -3).toLowerCase();
            candidates.push(base, base + 's');
        } else if (paramSeg.endsWith('name') || paramSeg.endsWith('Name')) {
            // username → user(s), userName → user(s)
            const base = paramSeg.replace(/[Nn]ame$/, '').toLowerCase();
            if (base) candidates.push(base, base + 's');
        } else {
            // 일반 명사 단수/복수 후보
            candidates.push(lc);
            if (!lc.endsWith('s')) candidates.push(lc + 's');
            if (lc.endsWith('s')) candidates.push(lc.slice(0, -1));
        }
    }

    for (const c of candidates) {
        const hit = lcTables.get(c.toLowerCase());
        if (hit) return { table: hit, paramSeg, prefixSeg, matched: c };
    }
    return null;
}

/**
 * 라우트의 마지막 동적 세그먼트 이름 ↔ 테이블 컬럼 매칭.
 *   :id        → id (PK 우선)
 *   :slug      → slug
 *   :username  → username
 *   :userId    → user_id 또는 id
 */
function pickKeyColumn(cols, paramName) {
    const norm = paramName.replace(/Id$/, '_id').replace(/[A-Z]/g, c => '_' + c.toLowerCase()).replace(/^_/, '');
    const direct = pickFirstMatching(cols, [paramName, norm, paramName.toLowerCase()]);
    if (direct) return direct;
    // PK fallback
    const pk = cols.find(c => c.pk);
    if (pk) return pk.name;
    return null;
}

/**
 * Authorization Policy 가 SELECT:<table> 을 공개로 두는지 검사.
 * authzMeta 가 없거나 disabled 면 모두 공개로 간주.
 *
 * @param {object} authzMeta - normalizeAuthorizationConfig 결과
 * @param {string} table
 * @returns {boolean}
 */
function isTablePubliclySelectable(authzMeta, table) {
    if (!authzMeta || !authzMeta.enabled) return true;
    const rules = authzMeta.rules || [];
    const lc = String(table).toLowerCase();
    // op === 'SELECT' 매치 우선, 없으면 와일드카드. authorizationPolicy 의 normalize 결과
    // 형태에 따라 rule 객체 형태가 다를 수 있어 안전하게 처리.
    for (const r of rules) {
        const op = String(r.op || r.operation || '').toUpperCase();
        const tb = String(r.table || '').toLowerCase();
        if ((op === 'SELECT' || op === '*') && (tb === lc || tb === '*')) {
            if (r.public === true) return true;
            if (r.auth === true || (Array.isArray(r.roles) && r.roles.length > 0) || r.deny === true) {
                return false;
            }
        }
    }
    // 명시적 매치 없음 → 안전하게 공개로 간주 (사용자가 명시 안 했으면 SELECT 는 공개로 두는 도깨비 기본 패턴).
    return true;
}

function isDokkebiInternalPath(p) {
    return p.startsWith('/_dokkebi/') || p.startsWith('/api/_dokkebi/') || p.startsWith('/.dokkebi/');
}

/**
 * 라우트 + 매칭된 테이블 정보로 SELECT 쿼리 + path 합성 함수 빌드.
 *
 * @returns {{ sql: string, build: (row: object) => string|null, columns: object }}
 */
function buildEnumerateQuery(routePath, table, cols, paramSeg, opts = {}) {
    const keyCol = pickKeyColumn(cols, paramSeg);
    if (!keyCol) return null;
    const titleCol = pickFirstMatching(cols, TITLE_COLS);
    const descCol  = pickFirstMatching(cols, DESC_COLS);
    const imageCol = pickFirstMatching(cols, IMAGE_COLS);
    const timeCol  = pickFirstMatching(cols, TIME_COLS);
    const publicCol = pickFirstMatching(cols, PUBLIC_BOOL_COLS);

    // 다른 :param 세그먼트 중 row 컬럼과 매칭 가능한 것들을 찾아둔다.
    //   - :lang / :locale → row.locale / row.lang 컬럼으로 매핑하면
    //     hreflang expander 우회 가능 (한 row 당 1 lang).
    //   - :username 등 → 같은 테이블에 author_* / *_name 같은 컬럼이 있을 때만.
    //     없으면 매칭 실패로 표시되어 사용자가 seo.dynamic[].query 로 JOIN SQL 명시.
    const paramToCol = {};
    const segs = routePath.split('/').filter(Boolean);
    for (const seg of segs) {
        if (!seg.startsWith(':')) continue;
        const name = seg.slice(1);
        if (name === paramSeg) continue;
        if (LANG_PARAM_NAMES.has(name.toLowerCase())) {
            const langCol = pickFirstMatching(cols, ['locale', 'lang', 'language']);
            if (langCol) paramToCol[name] = langCol;
            continue;
        }
        const candidates = [
            name,
            name.replace(/Id$/, '_id'),
            name.toLowerCase(),
            'author_' + name,
            'author_' + name + 'name',
            name + '_name',
        ];
        const hit = pickFirstMatching(cols, candidates);
        if (hit) paramToCol[name] = hit;
    }

    const selectCols = [keyCol];
    if (titleCol) selectCols.push(titleCol);
    if (descCol)  selectCols.push(descCol);
    if (imageCol) selectCols.push(imageCol);
    if (timeCol)  selectCols.push(timeCol);
    for (const c of Object.values(paramToCol)) {
        if (!selectCols.includes(c)) selectCols.push(c);
    }

    const safeTable = `"${String(table).replace(/"/g, '""')}"`;
    let sql = `SELECT ${selectCols.map(c => `"${c}"`).join(', ')} FROM ${safeTable}`;
    const where = [];
    if (publicCol) {
        // 자동 추론: 'is_published' 또는 'status' 같은 텍스트 컬럼은 별도지만
        // 여기 매칭된 BOOL 컬럼은 1/true 로 통일.
        where.push(`"${publicCol}" = 1`);
    }
    // 'status' 컬럼 (text) 추가 휴리스틱 — 안전하게 published 만 통과
    if (cols.find(c => c.name.toLowerCase() === 'status')) {
        where.push(`("status" IS NULL OR "status" IN ('published','public','active'))`);
    }
    // soft-delete 자동 회피
    if (cols.find(c => c.name.toLowerCase() === 'deleted_at')) {
        where.push(`"deleted_at" IS NULL`);
    }
    if (where.length > 0) sql += ' WHERE ' + where.join(' AND ');
    if (timeCol) sql += ` ORDER BY "${timeCol}" DESC`;
    sql += ` LIMIT ${Math.max(1, Math.min(50_000, opts.limit || 5000))}`;

    /**
     * 라우트 path 의 :paramSeg + paramToCol 에 매핑된 :param 들을 row 로부터 치환.
     * 매핑 안 된 :param (대표적으로 :lang) 은 hreflang expander 가 후속 처리.
     */
    function build(row) {
        const v = row[keyCol];
        if (v == null) return null;
        let out = routePath.replace(new RegExp(':' + paramSeg + '\\b'), encodeURIComponent(String(v)));
        for (const [name, col] of Object.entries(paramToCol)) {
            const cv = row[col];
            if (cv == null) return null;
            out = out.replace(new RegExp(':' + name + '\\b'), encodeURIComponent(String(cv)));
        }
        return out;
    }

    return {
        sql,
        build,
        columns: { keyCol, titleCol, descCol, imageCol, timeCol, publicCol },
        paramToCol,
    };
}

/**
 * 사용자가 명시한 seo.dynamic[] 항목으로 enumerate.
 */
async function runUserSpecified(dbConfig, spec, allTables, _verbose) {
    const pattern = spec.pattern;
    if (typeof pattern !== 'string' || !pattern) return null;
    const segs = pattern.split('/').filter(Boolean);
    let paramSeg = null;
    for (let i = segs.length - 1; i >= 0; i--) {
        if (segs[i].startsWith(':')) { paramSeg = segs[i].replace(/^:/, ''); break; }
    }
    if (!paramSeg) return { skipped: { pattern, reason: 'no-dynamic-segment' } };

    let sql = null;
    let table = null;
    let columns = null;
    let build = null;
    if (typeof spec.query === 'string' && spec.query.trim()) {
        sql = spec.query.trim();
        // build/columns 는 첫 row 받은 후 자동 추론.
    } else if (typeof spec.table === 'string' && spec.table.trim()) {
        table = spec.table.trim();
        if (!allTables.includes(table)) {
            return { skipped: { pattern, reason: `table-not-found:${table}` } };
        }
        const cols = await tableColumns(dbConfig, table);
        const built = buildEnumerateQuery(pattern, table, cols, paramSeg, { limit: spec.limit });
        if (!built) return { skipped: { pattern, reason: 'no-key-column' } };
        sql = built.sql;
        columns = built.columns;
        build = built.build;
    } else {
        return { skipped: { pattern, reason: 'need-table-or-query' } };
    }

    const out = await d1Execute(dbConfig, sql);
    const rows = out.results || out.rows || [];

    // user query 모드: 첫 row 의 키들로 build/columns 자동 추론
    if (!build && rows.length > 0) {
        const sampleKeys = Object.keys(rows[0] || {});
        const lc = new Map(sampleKeys.map(k => [k.toLowerCase(), k]));
        const keyCol = lc.get(paramSeg.toLowerCase()) || lc.get('id') || sampleKeys[0];
        const titleCol = pickFirstFromKeys(sampleKeys, TITLE_COLS);
        const descCol  = pickFirstFromKeys(sampleKeys, DESC_COLS);
        const imageCol = pickFirstFromKeys(sampleKeys, IMAGE_COLS);
        const timeCol  = pickFirstFromKeys(sampleKeys, TIME_COLS);
        // 다른 :param 매핑 — 컬럼명 일치 우선
        const paramToCol = {};
        for (const seg of pattern.split('/').filter(Boolean)) {
            if (!seg.startsWith(':')) continue;
            const name = seg.slice(1);
            if (name === paramSeg) continue;
            const candidates = LANG_PARAM_NAMES.has(name.toLowerCase())
                ? ['locale', 'lang', 'language']
                : [name, name.replace(/Id$/, '_id'), name.toLowerCase()];
            const hit = pickFirstFromKeys(sampleKeys, candidates);
            if (hit) paramToCol[name] = hit;
        }
        columns = { keyCol, titleCol, descCol, imageCol, timeCol };
        // user-query 모드의 paramToCol 도 외부로 노출 (PR3 routeMeta 에서 재사용)
        spec.__paramToCol = paramToCol;
        build = (row) => {
            const v = row[keyCol];
            if (v == null) return null;
            let p = pattern.replace(new RegExp(':' + paramSeg + '\\b'), encodeURIComponent(String(v)));
            for (const [name, col] of Object.entries(paramToCol)) {
                const cv = row[col];
                if (cv == null) return null;
                p = p.replace(new RegExp(':' + name + '\\b'), encodeURIComponent(String(cv)));
            }
            return p;
        };
    }

    return { rows, table, paramSeg, columns, build, source: 'user-config', userQuery: sql, paramToCol: spec.__paramToCol || null };
}

function pickFirstFromKeys(keys, candidates) {
    const lc = new Map(keys.map(k => [k.toLowerCase(), k]));
    for (const c of candidates) {
        const hit = lc.get(c.toLowerCase());
        if (hit) return hit;
    }
    return null;
}

/**
 * @param {object} args
 * @param {Array<object>} args.dynamicRoutes - scanRouter 결과 중 isDynamic=true 인 라우트
 * @param {object} args.dbConfig
 * @param {object} args.authzMeta
 * @param {object} args.seoConfig
 * @param {boolean} [args.verbose]
 * @returns {Promise<{
 *   expanded: Array<{path, title, description, image, lastmod, sourceTable, sourceRoute, jsonLdHints}>,
 *   skipped: Array<{pattern, reason}>,
 *   diagnostics: {available: boolean, tables: number, queries: number}
 * }>}
 */
export async function enumerateDynamicRoutes(args) {
    const { dynamicRoutes, dbConfig, authzMeta, seoConfig, verbose } = args;
    const result = {
        expanded: [],
        skipped: [],
        // PR3: 각 dynamic 라우트의 SQL/컬럼 매핑 — Edge SEO Renderer 가 빌드 후 새로 추가된
        // 레코드를 1건 lookup 하는 데 사용. dist/.dokkebi/seo-routes.json 으로 emit.
        routeMeta: [],
        diagnostics: { available: false, tables: 0, queries: 0 },
    };

    if (!isD1Available(dbConfig)) {
        for (const r of dynamicRoutes) result.skipped.push({ pattern: r.path, reason: 'd1-credentials-missing' });
        return result;
    }

    let allTables;
    try {
        allTables = await listTables(dbConfig);
    } catch (e) {
        for (const r of dynamicRoutes) result.skipped.push({ pattern: r.path, reason: `d1-list-tables-failed:${e?.message || e}` });
        return result;
    }
    result.diagnostics.available = true;
    result.diagnostics.tables = allTables.length;

    // 사용자 명시 spec 우선 매칭 인덱스
    const userSpecs = Array.isArray(seoConfig.dynamic) ? seoConfig.dynamic : [];
    const userSpecByPattern = new Map();
    for (const s of userSpecs) {
        if (!s) continue;
        const key = typeof s.pattern === 'string' ? s.pattern
                  : typeof s.path === 'string' ? s.path
                  : null;
        if (key) userSpecByPattern.set(key, { ...s, pattern: key });
    }

    for (const route of dynamicRoutes) {
        if (route.redirect) {
            result.skipped.push({ pattern: route.path, reason: 'redirect-route' });
            continue;
        }
        if (route.protected) {
            // 인증 필요한 라우트(로그인 후 접근 가능한 글쓰기/관리 등) 는 검색 대상 아님.
            result.skipped.push({ pattern: route.path, reason: 'protected-route' });
            continue;
        }
        if (isDokkebiInternalPath(route.path)) {
            result.skipped.push({ pattern: route.path, reason: 'dokkebi-internal' });
            continue;
        }

        const spec = userSpecByPattern.get(route.path);
        let runOutcome = null;
        try {
            if (spec) {
                runOutcome = await runUserSpecified(dbConfig, spec, allTables, verbose);
                if (runOutcome?.skipped) {
                    result.skipped.push(runOutcome.skipped);
                    continue;
                }
            } else {
                // 자동 매칭
                const inferred = inferTableFromRoute(route.path, allTables);
                if (!inferred) {
                    result.skipped.push({ pattern: route.path, reason: 'no-table-match' });
                    continue;
                }
                if (!isTablePubliclySelectable(authzMeta, inferred.table)) {
                    result.skipped.push({ pattern: route.path, reason: `auth-required:${inferred.table}` });
                    continue;
                }
                const cols = await tableColumns(dbConfig, inferred.table);
                const built = buildEnumerateQuery(route.path, inferred.table, cols, inferred.paramSeg);
                if (!built) {
                    result.skipped.push({ pattern: route.path, reason: 'no-key-column' });
                    continue;
                }
                // 자동 매칭 못한 :param 이 남았는지 미리 체크 — 사용자가 즉시 가이드 받도록.
                const _segs = route.path.split('/').filter(Boolean);
                const _unmappable = [];
                for (const seg of _segs) {
                    if (!seg.startsWith(':')) continue;
                    const name = seg.slice(1);
                    if (name === inferred.paramSeg) continue;
                    if (LANG_PARAM_NAMES.has(name.toLowerCase())) continue;
                    if (!built.paramToCol || !built.paramToCol[name]) _unmappable.push(name);
                }
                if (_unmappable.length > 0) {
                    result.skipped.push({
                        pattern: route.path,
                        reason: `unmappable-params:${_unmappable.join(',')} (테이블 ${inferred.table} 에 매칭 컬럼 없음 — seo.dynamic[].query 로 JOIN SQL 명시 필요)`,
                    });
                    continue;
                }
                const out = await d1Execute(dbConfig, built.sql);
                const rows = out.results || out.rows || [];
                runOutcome = {
                    rows,
                    table: inferred.table,
                    paramSeg: inferred.paramSeg,
                    columns: built.columns,
                    build: built.build,
                    source: 'auto',
                    paramToCol: built.paramToCol || null,
                    userQuery: null,
                };
            }
        } catch (e) {
            result.skipped.push({ pattern: route.path, reason: `enumerate-failed:${e?.message || e}` });
            continue;
        }

        result.diagnostics.queries++;

        if (!runOutcome || !runOutcome.rows) continue;

        // PR3: 라우트 메타 보존 (Edge Renderer 가 1건 lookup SQL 합성에 사용)
        if (runOutcome.columns) {
            result.routeMeta.push({
                pattern: route.path,
                table: runOutcome.table || null,
                paramSeg: runOutcome.paramSeg,
                columns: runOutcome.columns,
                paramToCol: runOutcome.paramToCol || null,
                source: runOutcome.source || 'auto',
                userQuery: runOutcome.userQuery || null,
            });
        }

        // 다른 :param 세그먼트(:lang, :username) 가 남아있을 때는 PR2 에서는 prerender 불가 → skip 표시
        // (PR2.5+에서 hreflang expander 가 :lang 만 추가 처리). 여기서는 우선 build() 결과의 path
        // 에 다른 :param 이 남아있는지 검사한다.
        for (const row of runOutcome.rows) {
            let p;
            try {
                p = runOutcome.build ? runOutcome.build(row) : null;
            } catch { p = null; }
            if (!p) continue;
            // :param 잔여 검사 (lang 등) — hreflang expander 가 처리할 영역
            const remaining = p.match(/:([A-Za-z_][\w]*)/g);
            const item = {
                path: p,
                paramRemaining: remaining || [],
                title: runOutcome.columns?.titleCol ? row[runOutcome.columns.titleCol] : null,
                description: runOutcome.columns?.descCol ? row[runOutcome.columns.descCol] : null,
                image: runOutcome.columns?.imageCol ? row[runOutcome.columns.imageCol] : null,
                lastmod: runOutcome.columns?.timeCol ? row[runOutcome.columns.timeCol] : null,
                sourceTable: runOutcome.table || null,
                sourceRoute: route.path,
                row, // JSON-LD 추론에서 사용
            };
            result.expanded.push(item);
        }

        if (verbose) {
            console.log(`[dokkebi][seo] enumerate ${route.path} ← ${runOutcome.table}: ${runOutcome.rows.length} rows`);
        }
    }

    return result;
}
