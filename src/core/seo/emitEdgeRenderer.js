/**
 * Dokkebi SEO — Edge SEO Renderer 산출 (PR3)
 *
 * 빌드 시점에 다음을 생성:
 *   1) functions/_middleware.js       — 봇 UA 면 SEO renderer 로 위임
 *   2) functions/_dokkebi-seo.js       — 동적 라우트 1건 lookup → HTML 합성 → KV 캐시
 *   3) dist/.dokkebi/seo-routes.json   — 라우트 패턴 + lookup SQL 메타 (Function 이 inline 으로 import)
 *
 * 동작:
 *   - 사용자 요청이 들어오면 _middleware 가 UA 검사
 *   - 봇이면 _dokkebi-seo Function 으로 forward → KV(SEO_CACHE) 조회
 *   - miss 면 D1 (env.DB) 에서 패턴 매칭되는 1건 lookup → 정적 dist/index.html 베이스에 메타 주입
 *   - 결과 KV 에 24h 캐시 (TTL config 가능)
 *   - 일반 사용자(브라우저) 는 정적 자산 그대로 응답 → CSR 정상 진행
 *
 * 안전성:
 *   - DB binding(env.DB) 또는 KV binding(env.SEO_CACHE) 가 없으면 정적 HTML 그대로 fallback
 *   - 빌드 시 D1 enumerate 가 없었던 라우트는 routeMeta 에 없음 → fallback
 *   - userQuery 는 그대로 임베드되지만 ?-bind 로 사용자 입력 격리 (SQL injection 방지)
 *
 * 보안 — Pages Functions 는 Worker 와 동일하게 격리 실행. _seo-routes.json 의 SQL 은
 * 빌드 산출물 디렉토리 (.dokkebi/) 에 두고 functions/ 안에서만 import — 정적 자산으로
 * 노출되지 않도록 _routes.json 에서 .dokkebi/ 를 exclude 하지 않아 그대로 정적 자산
 * 경로에 가긴 하지만, 민감한 파일이 아니라 sitemap 보조용 메타임. (보안상 진짜 secret
 * 은 worker env 변수만 사용)
 */

import path from 'path';
import fs from 'fs/promises';

const FUNCTIONS_DIR = 'functions';

/**
 * 봇 UA 정규식 — 메이저 검색엔진 + 소셜 + 한국 검색엔진.
 * 화이트리스트 방식 (오탐보다 누락이 안전).
 */
const BOT_UA_PATTERN = String.raw`(?:googlebot|bingbot|slurp|duckduckbot|yandex(?:bot)?|baiduspider|sogou|exabot|facebot|facebookexternalhit|twitterbot|linkedinbot|slackbot|discordbot|telegrambot|whatsapp|skypeuripreview|applebot|petalbot|naver|yeti|daum|kakao|kagibot|chatgpt-user|gptbot|claudebot|perplexitybot|amazonbot|bytespider|ia_archiver|crawler|spider|bot)`;

/**
 * @param {object} args
 * @param {string} args.outDir - dist
 * @param {string} args.sourceRoot - 프로젝트 루트
 * @param {object} args.seoConfig - normalize 된 SEO config
 * @param {Array} args.routeMeta - enumerate 단계의 routeMeta
 * @param {boolean} args.dbAvailable - D1 자격 보유 여부 (없으면 emit 자체 skip)
 * @returns {Promise<{ written: string[], skipped: boolean, reason?: string }>}
 */
export async function emitEdgeRenderer(args) {
    const { outDir, sourceRoot, seoConfig, routeMeta, dbAvailable } = args;

    if (seoConfig?.edgeRenderer?.enabled === false) {
        return { written: [], skipped: true, reason: 'disabled' };
    }
    if (!routeMeta || routeMeta.length === 0) {
        return { written: [], skipped: true, reason: 'no-route-meta' };
    }
    if (!dbAvailable) {
        // D1 자격 없으면 빌드 타임 enumerate 도 못 했고 런타임에 D1 lookup 도 못 함 → 의미 없음
        return { written: [], skipped: true, reason: 'd1-unavailable' };
    }

    // 빌드 산출물 dist/index.html 의 존재만 확인 (Function 안에서는 env.ASSETS.fetch 로 가져옴).
    const baseHtmlPath = path.join(outDir, 'index.html');
    try {
        await fs.access(baseHtmlPath);
    } catch {
        return { written: [], skipped: true, reason: 'no-base-html' };
    }

    // routeMeta → 정적 path 패턴 컴파일 정보 (path-to-regex 단순화 버전)
    const compiled = routeMeta.map(rm => ({
        pattern: rm.pattern,
        regex: patternToRegexStr(rm.pattern),
        paramOrder: collectParams(rm.pattern),
        paramSeg: rm.paramSeg,
        table: rm.table,
        columns: rm.columns,
        paramToCol: rm.paramToCol || {},
        userQuery: rm.userQuery || null,
        sourceRoute: rm.pattern,
    }));

    const routesJson = {
        version: 1,
        generatedAt: new Date().toISOString(),
        baseUrl: seoConfig.baseUrl || null,
        siteName: seoConfig.defaults?.siteName || null,
        defaultImage: seoConfig.defaults?.image || null,
        routes: compiled,
    };

    const dotDir = path.join(outDir, '.dokkebi');
    await fs.mkdir(dotDir, { recursive: true });
    const routesJsonPath = path.join(dotDir, 'seo-routes.json');
    await fs.writeFile(routesJsonPath, JSON.stringify(routesJson, null, 2), 'utf-8');

    // functions/ 디렉토리는 프로젝트 루트 기준 (Cloudflare Pages convention)
    const fnDir = path.join(sourceRoot, FUNCTIONS_DIR);
    await fs.mkdir(fnDir, { recursive: true });

    const middlewareCode = renderMiddleware();
    const rendererCode = renderEdgeRenderer({ routesJson, seoConfig });

    const mwPath = path.join(fnDir, '_middleware.js');
    // Cloudflare Pages 파일 라우팅: catch-all 하위경로 매칭은 [[path]] 동적 세그먼트 필요.
    // functions/_dokkebi-seo.js → /_dokkebi-seo 정확 매칭만 됨 (하위 경로 매칭 X).
    // functions/_dokkebi-seo/[[path]].js → /_dokkebi-seo/* 모두 매칭.
    const rendererDir = path.join(fnDir, '_dokkebi-seo');
    await fs.mkdir(rendererDir, { recursive: true });
    const rendererPath = path.join(rendererDir, '[[path]].js');
    // 이전 빌드의 _dokkebi-seo.js (단일 파일) 잔재 정리.
    try { await fs.unlink(path.join(fnDir, '_dokkebi-seo.js')); } catch {}

    // 기존 _middleware 가 있으면 dokkebi 마커 또는 SEO 위임 흔적 확인 후만 덮어쓴다 (사용자 코드 보호).
    const existingMw = await safeRead(mwPath);
    const hasSeoIntegration = existingMw && (
        /@dokkebi-seo-middleware/.test(existingMw) ||
        /\/_dokkebi-seo/.test(existingMw) ||
        /dokkebiSeoTryHandle/.test(existingMw)
    );
    if (existingMw && !hasSeoIntegration) {
        // 사용자/기존 미들웨어 보존 — renderer 만 emit + 가이드용 패치 스니펫 추가 출력.
        await fs.writeFile(rendererPath, rendererCode, 'utf-8');
        const patchPath = path.join(fnDir, '_dokkebi-seo.middleware-patch.js');
        await fs.writeFile(patchPath, renderMiddlewarePatchSnippet(), 'utf-8');
        return {
            written: [
                path.relative(sourceRoot, rendererPath),
                path.relative(sourceRoot, patchPath),
                path.relative(sourceRoot, routesJsonPath),
            ],
            skipped: false,
            note: 'user-middleware-preserved',
            patchPath: path.relative(sourceRoot, patchPath),
        };
    }

    if (existingMw && hasSeoIntegration) {
        // 사용자가 SEO 봇 분기를 이미 통합함 — renderer 만 emit, 미들웨어/패치 건드리지 않음.
        await fs.writeFile(rendererPath, rendererCode, 'utf-8');
        // 오래된 patch 스니펫이 남아있으면 정리 (선택).
        try { await fs.unlink(path.join(fnDir, '_dokkebi-seo.middleware-patch.js')); } catch {}
        return {
            written: [
                path.relative(sourceRoot, rendererPath),
                path.relative(sourceRoot, routesJsonPath),
            ],
            skipped: false,
            note: 'user-middleware-integrated',
        };
    }

    await fs.writeFile(mwPath, middlewareCode, 'utf-8');
    await fs.writeFile(rendererPath, rendererCode, 'utf-8');

    return {
        written: [
            path.relative(sourceRoot, mwPath),
            path.relative(sourceRoot, rendererPath),
            path.relative(sourceRoot, routesJsonPath),
        ],
        skipped: false,
    };
}

async function safeRead(p) {
    try { return await fs.readFile(p, 'utf-8'); } catch { return null; }
}

/**
 * "/posts/:slug" → "^/posts/([^/]+)/?$"
 * 정적 prefix 는 그대로, :param 은 [^/]+ 그룹.
 */
function patternToRegexStr(pattern) {
    const segs = pattern.split('/').filter(Boolean);
    const parts = segs.map(s => {
        if (s.startsWith(':')) return '([^/]+)';
        return escapeRegex(s);
    });
    return '^/' + parts.join('/') + '/?$';
}

function collectParams(pattern) {
    const out = [];
    for (const s of pattern.split('/').filter(Boolean)) {
        if (s.startsWith(':')) out.push(s.slice(1));
    }
    return out;
}

function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ─────────────────────────────────────────────────────────────
// Function 코드 generator
// ─────────────────────────────────────────────────────────────

function renderMiddlewarePatchSnippet() {
    return `// Dokkebi SEO Edge Renderer — 기존 functions/_middleware.js 에 통합하기 위한 스니펫
//
// 사용법:
//   1) 기존 _middleware.js 의 export const onRequest 또는 onRequest 배열 시작 부분에 아래 함수를 추가.
//   2) 기존 미들웨어 흐름 앞에 \`if (await dokkebiSeoTryHandle(context)) return;\` 한 줄을 호출.
//
// 또는 onRequest 배열을 쓰는 경우:
//   export const onRequest = [dokkebiSeoTryHandle, ...기존미들웨어들];

const DOKKEBI_BOT_UA_RE = new RegExp(${JSON.stringify(BOT_UA_PATTERN)}, 'i');

export async function dokkebiSeoTryHandle(context) {
    const { request } = context;
    if (request.method !== 'GET' && request.method !== 'HEAD') return null;
    const ua = request.headers.get('user-agent') || '';
    if (!DOKKEBI_BOT_UA_RE.test(ua)) return null;
    const url = new URL(request.url);
    if (/\\.[a-z0-9]{1,8}(?:$|\\?)/i.test(url.pathname)) return null;
    try {
        const seoUrl = new URL('/_dokkebi-seo' + url.pathname + url.search, request.url);
        const seoRes = await fetch(seoUrl.toString(), {
            headers: { 'x-dokkebi-seo': '1', 'x-original-ua': ua },
            cf: { cacheTtl: 0 },
        });
        if (seoRes.ok) return seoRes;
    } catch (_e) { /* fallback */ }
    return null;
}
`;
}

function renderMiddleware() {
    return `// @dokkebi-seo-middleware: 1
// Dokkebi 자동 생성 — 봇 UA 가 GET 요청하면 _dokkebi-seo Function 으로 위임.
// 이 파일을 직접 수정하지 마세요. 사용자 미들웨어가 필요하면 _middleware.user.js 에 작성.

const BOT_UA_RE = new RegExp(${JSON.stringify(BOT_UA_PATTERN)}, 'i');

export const onRequest = async (context) => {
    const { request, next, env } = context;
    if (request.method !== 'GET' && request.method !== 'HEAD') return next();

    const ua = request.headers.get('user-agent') || '';
    if (!BOT_UA_RE.test(ua)) return next();

    // 정적 자산은 그대로 통과 (확장자 가지면 봇이라도 정적 응답).
    const url = new URL(request.url);
    if (/\\.[a-z0-9]{1,8}(?:$|\\?)/i.test(url.pathname)) return next();

    // SEO renderer 로 위임. fetch 실패 시 정적 fallback.
    try {
        const seoUrl = new URL('/_dokkebi-seo' + url.pathname + url.search, request.url);
        // Pages Functions: 같은 프로젝트의 다른 Function 을 호출하려면 fetch 로 self-loopback.
        const seoRes = await fetch(seoUrl.toString(), {
            headers: { 'x-dokkebi-seo': '1', 'x-original-ua': ua },
            cf: { cacheTtl: 0 },
        });
        if (seoRes.ok) return seoRes;
    } catch (_e) {
        // 무시 — fallback
    }
    return next();
};
`;
}

function renderEdgeRenderer({ routesJson, seoConfig }) {
    const cacheTtl = (seoConfig?.edgeRenderer?.cacheTtlSeconds) || 86400;

    return `// @dokkebi-seo-renderer: 1
// Dokkebi 자동 생성 — 동적 라우트 1건을 D1 에서 fetch 해 메타 주입한 HTML 응답.
// 환경 binding 필수: env.ASSETS (Pages 자동), env.DB (D1), env.SEO_CACHE (KV, 선택)
// 이 파일을 직접 수정하지 마세요.

const ROUTES = ${JSON.stringify(routesJson, null, 2)};
const CACHE_TTL_SECONDS = ${cacheTtl};
const DEFAULT_IMAGE = ROUTES.defaultImage;
const SITE_NAME     = ROUTES.siteName;
const BASE_URL      = ROUTES.baseUrl;

// ── Phase B — sharding-aware DB resolver (단일 D1: env.DB 폴백) ─
const _DOKKEBI_INTERNAL_BINDING = '__DOKKEBI_PH_INTERNAL_BINDING__' || 'DB';
function _userDbForSql(env) {
    return (env && env[_DOKKEBI_INTERNAL_BINDING]) || (env && env.DB);
}

export const onRequest = async (context) => {
    const { request, env } = context;
    const url = new URL(request.url);
    // /_dokkebi-seo 프리픽스 떼기
    let pathname = url.pathname.replace(/^\\/_dokkebi-seo/, '') || '/';
    if (!pathname.startsWith('/')) pathname = '/' + pathname;

    const cacheKey = 'seo:' + pathname;

    // 1) KV 캐시 hit?
    if (env.SEO_CACHE) {
        try {
            const hit = await env.SEO_CACHE.get(cacheKey);
            if (hit) return new Response(hit, { headers: htmlHeaders('HIT') });
        } catch (_e) { /* ignore */ }
    }

    // 2) 라우트 패턴 매칭
    const matched = matchRoute(pathname);
    if (!matched) {
        return await fetchAssetsAsHtml(request, env, 'PASS');
    }

    // 3) D1 lookup (DB binding 없으면 정적 fallback)
    const _seoDb = _userDbForSql(env);
    if (!_seoDb) {
        return await fetchAssetsAsHtml(request, env, 'NO-DB');
    }
    let row = null;
    try {
        row = await lookupOne(_seoDb, matched);
    } catch (e) {
        return await fetchAssetsAsHtml(request, env, 'DB-ERR');
    }
    if (!row) {
        return await fetchAssetsAsHtml(request, env, 'NOT-FOUND');
    }

    // 4) 베이스 HTML 가져오기 (Pages ASSETS) → 메타 주입
    const baseHtml = await fetchBaseHtml(request, env);
    if (!baseHtml) {
        return new Response('SEO base html unavailable', { status: 502 });
    }
    const meta = buildMetaFromRow(row, matched, pathname);
    const html = injectMeta(baseHtml, meta);

    // 5) KV 캐시 저장 (TTL)
    if (env.SEO_CACHE) {
        try {
            await env.SEO_CACHE.put(cacheKey, html, { expirationTtl: CACHE_TTL_SECONDS });
        } catch (_e) { /* ignore */ }
    }

    return new Response(html, { headers: htmlHeaders('MISS') });
};

async function fetchBaseHtml(request, env) {
    try {
        const indexUrl = new URL('/index.html', request.url);
        // Pages 의 ASSETS binding 우선, 없으면 self-loopback
        if (env.ASSETS && typeof env.ASSETS.fetch === 'function') {
            const r = await env.ASSETS.fetch(indexUrl.toString());
            if (r.ok) return await r.text();
        }
        const r2 = await fetch(indexUrl.toString(), { cf: { cacheTtl: 60 } });
        if (r2.ok) return await r2.text();
    } catch (_e) { /* ignore */ }
    return null;
}

async function fetchAssetsAsHtml(request, env, status) {
    const html = await fetchBaseHtml(request, env);
    if (!html) return new Response('Not found', { status: 404 });
    return new Response(html, { headers: htmlHeaders(status) });
}

function htmlHeaders(cacheStatus) {
    return {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'public, max-age=300, s-maxage=86400',
        'x-dokkebi-seo': cacheStatus,
        'x-robots-tag': 'index, follow',
    };
}

function matchRoute(pathname) {
    for (const r of ROUTES.routes) {
        const re = new RegExp(r.regex);
        const m = re.exec(pathname);
        if (m) {
            const params = {};
            r.paramOrder.forEach((p, i) => { params[p] = decodeURIComponent(m[i + 1] || ''); });
            return { ...r, params };
        }
    }
    return null;
}

async function lookupOne(db, route) {
    if (route.userQuery) {
        // user 가 SQL 명시한 경우 — WHERE 결합으로 단건 추출
        // 1) WHERE 절을 그대로 두고, AND 로 동적 조건 추가하기 위해 query 를 서브쿼리로 감쌈
        const sub = '(' + route.userQuery + ')';
        const wheres = [];
        const binds = [];
        const keyCol = route.columns?.keyCol;
        const keyParam = route.paramSeg;
        if (keyCol && route.params[keyParam] != null) {
            wheres.push('"' + keyCol + '" = ?');
            binds.push(route.params[keyParam]);
        }
        for (const [pname, col] of Object.entries(route.paramToCol || {})) {
            if (route.params[pname] != null) {
                wheres.push('"' + col + '" = ?');
                binds.push(route.params[pname]);
            }
        }
        if (wheres.length === 0) return null;
        const sql = 'SELECT * FROM ' + sub + ' AS _seo_q WHERE ' + wheres.join(' AND ') + ' LIMIT 1';
        const stmt = db.prepare(sql).bind(...binds);
        const out = await stmt.first();
        return out || null;
    }
    // 자동 매칭 모드
    if (!route.table || !route.columns?.keyCol) return null;
    const wheres = ['"' + route.columns.keyCol + '" = ?'];
    const binds = [route.params[route.paramSeg]];
    for (const [pname, col] of Object.entries(route.paramToCol || {})) {
        if (route.params[pname] != null) {
            wheres.push('"' + col + '" = ?');
            binds.push(route.params[pname]);
        }
    }
    const sql = 'SELECT * FROM "' + route.table + '" WHERE ' + wheres.join(' AND ') + ' LIMIT 1';
    const stmt = db.prepare(sql).bind(...binds);
    return await stmt.first();
}

function buildMetaFromRow(row, route, pathname) {
    const cols = route.columns || {};
    const title = cols.titleCol ? row[cols.titleCol] : null;
    const description = cols.descCol ? row[cols.descCol] : null;
    const image = cols.imageCol ? row[cols.imageCol] : DEFAULT_IMAGE;
    const lastmod = cols.timeCol ? row[cols.timeCol] : null;
    const fullTitle = title ? (SITE_NAME ? title + ' - ' + SITE_NAME : title) : SITE_NAME;
    const fullUrl = BASE_URL ? new URL(pathname, BASE_URL).toString() : pathname;
    const desc = description ? String(description).slice(0, 200) : '';
    const ogImage = image
        ? (image.startsWith('http') ? image : BASE_URL ? new URL(image, BASE_URL).toString() : image)
        : null;
    return { title: fullTitle, description: desc, image: ogImage, url: fullUrl, lastmod };
}

function injectMeta(html, meta) {
    const tags = [];
    const e = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    if (meta.title) {
        tags.push('<title data-dokkebi-seo>' + e(meta.title) + '</title>');
        tags.push('<meta property="og:title" content="' + e(meta.title) + '" data-dokkebi-seo />');
        tags.push('<meta name="twitter:title" content="' + e(meta.title) + '" data-dokkebi-seo />');
    }
    if (meta.description) {
        tags.push('<meta name="description" content="' + e(meta.description) + '" data-dokkebi-seo />');
        tags.push('<meta property="og:description" content="' + e(meta.description) + '" data-dokkebi-seo />');
        tags.push('<meta name="twitter:description" content="' + e(meta.description) + '" data-dokkebi-seo />');
    }
    if (meta.image) {
        tags.push('<meta property="og:image" content="' + e(meta.image) + '" data-dokkebi-seo />');
        tags.push('<meta name="twitter:image" content="' + e(meta.image) + '" data-dokkebi-seo />');
    }
    if (meta.url) {
        tags.push('<link rel="canonical" href="' + e(meta.url) + '" data-dokkebi-seo />');
        tags.push('<meta property="og:url" content="' + e(meta.url) + '" data-dokkebi-seo />');
    }
    tags.push('<meta name="twitter:card" content="summary_large_image" data-dokkebi-seo />');
    tags.push('<meta name="x-dokkebi-seo-rendered" content="edge" data-dokkebi-seo />');

    // 기존 <title> 제거 + </head> 직전 삽입
    // 기존 <title> 제거 + 빌드타임 prerender 의 기존 data-dokkebi-seo 마커 메타도 모두 제거
    // (런타임 page-specific 메타로 완전 교체)
    let next = html.replace(/<title[^>]*>[\\s\\S]*?<\\/title>/gi, '');
    next = next.replace(/<(?:meta|link)[^>]*\\bdata-dokkebi-seo\\b[^>]*\\/?>\\s*/gi, '');
    next = next.replace(/<\\/head>/i, tags.join('\\n') + '\\n</head>');
    return next;
}
`
        .replace(/__DOKKEBI_PH_INTERNAL_BINDING__/g, 'DB');
}
