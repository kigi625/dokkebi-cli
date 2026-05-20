/**
 * Dokkebi SEO — 페이지 컴포넌트 메타 추론 (PR1)
 *
 * 라우트별 페이지 컴포넌트 파일에서 title/description/image 후보를 추출.
 *
 * 우선순위 (각 단계마다 confidence 점수 부여):
 *   1.0  @dokkebi-seo magic comment   (명시적 사용자 선언)
 *   0.9  dokkebi.seo.set({...}) 정적 인자
 *   0.8  첫 <h1>{...}</h1> 의 정적 텍스트
 *   0.7  첫 <p> 정적 텍스트 (description)
 *   0.7  <img src="..." /> 정적 경로 (og:image)
 *   0.6  컴포넌트명 → 한글 라벨 휴리스틱
 *   0.4  i18n locale 키 fuzzy 매칭
 *   0.3  fallback (defaults)
 *
 * 주의: AST 없이 정규식만 사용 — 동적 표현식(예: title={t('foo')}) 은 추출 못함.
 *      그런 라우트는 리포트에서 ⚠ 표시되어 사용자가 명시 hint 추가하도록 유도.
 */

import path from 'path';
import fs from 'fs/promises';

// @dokkebi-seo
//   title: 블로그 글
//   description: 도깨비 블로그
//   image: /og/blog.png
//   noindex: true
const MAGIC_BLOCK_RE = /\/\*\*?\s*[\s\S]*?@dokkebi-seo\b([\s\S]*?)\*\//;
const MAGIC_LINE_RE  = /@dokkebi-seo\s+([a-zA-Z]+)\s*:\s*(.+?)\s*$/gm;

// dokkebi.seo.set({ title: '...', description: '...', image: '...' })
// 정적 리터럴만 추출. 동적 식은 무시.
const SEO_SET_RE = /dokkebi\s*\.\s*seo\s*\.\s*set\s*\(\s*\{([\s\S]*?)\}\s*\)/;

// JSX 첫 <h1>...</h1> — 정적 텍스트만 (자식 노드 없을 때)
const H1_RE = /<\s*h1\b[^>]*>\s*([^<{][^<]*?)\s*<\s*\/\s*h1\s*>/i;

// 첫 <p>...</p> — 짧으면 description 후보
const P_RE  = /<\s*p\b[^>]*>\s*([^<{][^<]*?)\s*<\s*\/\s*p\s*>/i;

// 첫 <img src="..." /> — public/ 또는 absolute path 만 신뢰
const IMG_RE = /<\s*img\b[^>]*\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|`([^`]*)`)/i;

// 컴포넌트명 → 한글 라벨 휴리스틱
const COMPONENT_HINTS = [
    [/Home(Page)?$/i,      '홈'],
    [/Login(Page)?$/i,     '로그인'],
    [/Register(Page)?$/i,  '회원가입'],
    [/Signup(Page)?$/i,    '회원가입'],
    [/Pricing(Page)?$/i,   '요금제'],
    [/About(Page|Us)?$/i,  '소개'],
    [/Contact(Page|Us)?$/i,'문의'],
    [/Profile(Page)?$/i,   '프로필'],
    [/Settings(Page)?$/i,  '설정'],
    [/Dashboard$/i,        '대시보드'],
    [/Manage(Page)?$/i,    '관리'],
    [/Admin(Page|Panel)?$/i,'관리자'],
    [/BlogHome(Page)?$/i,  '블로그'],
    [/BlogPost(Page)?$/i,  '블로그 글'],
    [/BlogCategory(Page)?$/i,'블로그 카테고리'],
    [/Post(Page)?$/i,      '게시물'],
    [/Article(Page)?$/i,   '게시물'],
    [/Product(Page|Detail)?$/i,'상품'],
    [/Cart(Page)?$/i,      '장바구니'],
    [/Checkout(Page)?$/i,  '결제'],
    [/Search(Page|Result)?$/i,'검색'],
    [/Write(Page)?$/i,     '글쓰기'],
    [/MyPage$/i,           '내 정보'],
    [/Tickets?(Page)?$/i,  '티켓'],
    [/Sessions?(Page)?$/i, '세션'],
    [/Public(Home|Guide|Page)?$/i,'안내'],
    [/Page$/i,             '페이지'], // 마지막 fallback
];

// 컴포넌트명만으로 noindex 처리하면 false-positive 발생 (예: 문서 사이트의 "AdminPanel"
// 가이드 페이지도 noindex 가 됨). 따라서 라우트 path 도 함께 고려해 사용자 인증/관리
// 영역 path (/login, /admin/*, /manage/* 등) 일 때만 noindex 한다.
const NOINDEX_NAME_PATTERNS = [
    /^Login(Page)?$/, /^Register(Page)?$/, /^Signup(Page)?$/,
    /^MyPage$/, /^Checkout(Page)?$/,
];
const NOINDEX_PATH_PATTERNS = [
    /^\/login(\/|$)/, /^\/register(\/|$)/, /^\/signup(\/|$)/,
    /^\/admin(\/|$)/, /^\/manage(\/|$)/, /^\/dashboard(\/|$)/,
    /^\/settings(\/|$)/, /^\/profile(\/|$)/, /^\/account(\/|$)/,
    /^\/checkout(\/|$)/, /^\/my(\/|$)/, /^\/me(\/|$)/, /^\/mypage(\/|$)/,
    /^\/write(\/|$)/,
];

function trimTo(s, max) {
    if (!s) return '';
    s = String(s).replace(/\s+/g, ' ').trim();
    return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function parseMagicBlock(source) {
    const m = MAGIC_BLOCK_RE.exec(source);
    if (!m) return null;
    const body = m[1];
    const out = {};
    let lm;
    MAGIC_LINE_RE.lastIndex = 0;
    while ((lm = MAGIC_LINE_RE.exec('@dokkebi-seo placeholder\n' + body)) !== null) {
        const key = lm[1].toLowerCase();
        const val = lm[2].trim();
        if (key === 'noindex') out[key] = /^(true|1|yes)$/i.test(val);
        else out[key] = val;
    }
    // body 자체에서 직접 "key: value" 라인 파싱 (주석 정리 후)
    for (const rawLine of body.split(/\r?\n/)) {
        const cleaned = rawLine.replace(/^\s*\*?\s*/, '').trim();
        if (!cleaned || cleaned.startsWith('@')) continue;
        const idx = cleaned.indexOf(':');
        if (idx < 0) continue;
        const k = cleaned.slice(0, idx).trim().toLowerCase();
        const v = cleaned.slice(idx + 1).trim();
        if (!k || !v) continue;
        if (['title', 'description', 'image', 'siteName', 'twitterCard', 'jsonld'].includes(k)) {
            out[k] = v;
        } else if (k === 'noindex') {
            out[k] = /^(true|1|yes)$/i.test(v);
        }
    }
    return Object.keys(out).length > 0 ? out : null;
}

function parseSeoSetCall(source) {
    const m = SEO_SET_RE.exec(source);
    if (!m) return null;
    const body = m[1];
    const out = {};
    // title: '...' 또는 title: "..." (정적 리터럴만)
    for (const k of ['title', 'description', 'image']) {
        const re = new RegExp(`\\b${k}\\s*:\\s*(?:'([^']+)'|"([^"]+)"|\`([^\`]+)\`)`);
        const mm = re.exec(body);
        if (mm) out[k] = mm[1] ?? mm[2] ?? mm[3];
    }
    return Object.keys(out).length > 0 ? out : null;
}

function looksDynamic(s) {
    if (!s) return true;
    // {var}, ${var}, <Component> 같은 토큰이 있으면 동적
    return /[\{\$<]/.test(s);
}

function inferFromComponentName(name) {
    if (!name) return null;
    for (const [re, label] of COMPONENT_HINTS) {
        if (re.test(name)) return label;
    }
    return null;
}

function shouldNoIndexByName(name, routePath) {
    const nameMatch = name && NOINDEX_NAME_PATTERNS.some(re => re.test(name));
    const pathMatch = routePath && NOINDEX_PATH_PATTERNS.some(re => re.test(routePath));
    // 사용자 인증/관리 영역은 path 만으로도 NOINDEX. 단순 이름 매칭만으로는 NOINDEX 하지 않는다.
    return pathMatch || (nameMatch && pathMatch);
}

/**
 * locale json 파일에서 컴포넌트명/path 와 가까운 키 fuzzy 매칭.
 * 단순 substring 매칭 — 도깨비 자체 i18n 은 ko/en 만 지원하므로 가벼운 휴리스틱이면 충분.
 */
function fuzzyLocale(localeMap, hintTokens) {
    if (!localeMap || !hintTokens || hintTokens.length === 0) return null;
    const flat = flattenLocale(localeMap);
    const lcTokens = hintTokens.map(t => t.toLowerCase());
    let best = null;
    let bestScore = 0;
    for (const [key, val] of Object.entries(flat)) {
        if (typeof val !== 'string' || val.length > 80) continue;
        let score = 0;
        const lk = key.toLowerCase();
        for (const t of lcTokens) {
            if (!t) continue;
            if (lk.includes(t)) score += 2;
            else if (lk.includes(t.slice(0, 4))) score += 1;
        }
        if (score > bestScore) { bestScore = score; best = val; }
    }
    return best && bestScore >= 2 ? best : null;
}

function flattenLocale(obj, prefix = '') {
    const out = {};
    if (!obj || typeof obj !== 'object') return out;
    for (const [k, v] of Object.entries(obj)) {
        const key = prefix ? prefix + '.' + k : k;
        if (v && typeof v === 'object') Object.assign(out, flattenLocale(v, key));
        else out[key] = v;
    }
    return out;
}

async function loadLocales(frontendDir) {
    // frontend/src/i18n/locales/{ko,en}.json — 도깨비 표준
    const candidates = [
        path.join(frontendDir, 'src', 'i18n', 'locales'),
        path.join(frontendDir, 'src', 'locales'),
        path.join(frontendDir, 'src', 'i18n'),
    ];
    for (const dir of candidates) {
        try {
            const ents = await fs.readdir(dir, { withFileTypes: true });
            const out = {};
            for (const e of ents) {
                if (!e.isFile() || !e.name.endsWith('.json')) continue;
                const lang = path.basename(e.name, '.json');
                try {
                    out[lang] = JSON.parse(await fs.readFile(path.join(dir, e.name), 'utf-8'));
                } catch { /* skip */ }
            }
            if (Object.keys(out).length > 0) return out;
        } catch { /* next */ }
    }
    return {};
}

function tokensFromComponentName(name) {
    if (!name) return [];
    const tokens = [];
    let cur = '';
    for (const ch of name) {
        if (/[A-Z]/.test(ch) && cur) { tokens.push(cur); cur = ''; }
        cur += ch;
    }
    if (cur) tokens.push(cur);
    return tokens.map(t => t.toLowerCase()).filter(t => t && t !== 'page' && t !== 'component');
}

/**
 * 한 라우트의 메타 추론.
 * @param {object} route - scanRouter 의 ScannedRoute
 * @param {object} ctx
 * @param {object} ctx.locales - { ko: {...}, en: {...} }
 * @param {object} ctx.defaults - { siteName, image, locale, ... }
 * @returns {Promise<{title, description, image, noindex, sources, confidence, jsonld?: any}>}
 */
export async function inferPageMeta(route, ctx) {
    const sources = {};
    const out = {
        title: null,
        description: null,
        image: null,
        noindex: false,
        sources,
        confidence: { title: 0, description: 0, image: 0 },
    };

    // 1) <ProtectedRoute> 또는 <Navigate> 라우트 → 자동 noindex
    if (route.protected || route.redirect) {
        out.noindex = true;
        sources.noindex = route.protected ? 'protected-route' : 'redirect';
    }

    // 컴포넌트명 + path 조합 기반 noindex (사용자 인증/관리 영역만)
    if (!out.noindex && shouldNoIndexByName(route.componentName, route.path)) {
        out.noindex = true;
        sources.noindex = 'auth-area-path';
    }

    let source = null;
    if (route.componentFile) {
        try { source = await fs.readFile(route.componentFile, 'utf-8'); }
        catch { /* skip */ }
    }

    // 2) magic comment (최우선)
    if (source) {
        const magic = parseMagicBlock(source);
        if (magic) {
            if (magic.title)       { out.title = magic.title; out.confidence.title = 1.0; sources.title = '@dokkebi-seo'; }
            if (magic.description) { out.description = magic.description; out.confidence.description = 1.0; sources.description = '@dokkebi-seo'; }
            if (magic.image)       { out.image = magic.image; out.confidence.image = 1.0; sources.image = '@dokkebi-seo'; }
            if (magic.noindex === true) { out.noindex = true; sources.noindex = '@dokkebi-seo'; }
            if (magic.noindex === false) { out.noindex = false; sources.noindex = '@dokkebi-seo'; }
        }
    }

    // 3) dokkebi.seo.set({ ... }) 정적 인자
    if (source && (!out.title || !out.description || !out.image)) {
        const setMeta = parseSeoSetCall(source);
        if (setMeta) {
            if (!out.title && setMeta.title)             { out.title = setMeta.title; out.confidence.title = 0.9; sources.title = 'dokkebi.seo.set'; }
            if (!out.description && setMeta.description) { out.description = setMeta.description; out.confidence.description = 0.9; sources.description = 'dokkebi.seo.set'; }
            if (!out.image && setMeta.image)             { out.image = setMeta.image; out.confidence.image = 0.9; sources.image = 'dokkebi.seo.set'; }
        }
    }

    // 4) JSX heuristics
    if (source) {
        if (!out.title) {
            const m = H1_RE.exec(source);
            if (m && !looksDynamic(m[1])) {
                const txt = m[1].trim();
                // 너무 짧거나 (3자 미만), 의미 없는 placeholder 는 거른다.
                if (txt.length >= 3 && !/^(test|hi|hello|hello world|todo)$/i.test(txt)) {
                    out.title = trimTo(txt, 60);
                    out.confidence.title = 0.8;
                    sources.title = 'h1';
                }
            }
        }
        if (!out.description) {
            const m = P_RE.exec(source);
            if (m && !looksDynamic(m[1]) && m[1].length >= 12) {
                out.description = trimTo(m[1], 160);
                out.confidence.description = 0.7;
                sources.description = 'first-p';
            }
        }
        if (!out.image) {
            const m = IMG_RE.exec(source);
            const src = m ? (m[1] ?? m[2] ?? m[3] ?? '') : '';
            if (src && !looksDynamic(src) && (src.startsWith('/') || src.startsWith('http'))) {
                out.image = src;
                out.confidence.image = 0.7;
                sources.image = 'first-img';
            }
        }
    }

    // 5) 컴포넌트명 휴리스틱
    if (!out.title) {
        const label = inferFromComponentName(route.componentName);
        if (label && label !== '페이지') {
            out.title = label;
            out.confidence.title = 0.6;
            sources.title = 'component-name';
        }
    }

    // 6) i18n locale fuzzy
    if (!out.title && ctx.locales) {
        const tokens = tokensFromComponentName(route.componentName);
        for (const lang of Object.keys(ctx.locales)) {
            const v = fuzzyLocale(ctx.locales[lang], tokens);
            if (v) {
                out.title = trimTo(v, 60);
                out.confidence.title = 0.4;
                sources.title = `i18n:${lang}`;
                break;
            }
        }
    }

    // 7) defaults fallback — 컴포넌트명 PascalCase split 우선, path prettify 후순위
    if (!out.title) {
        const baseName = ctx.defaults?.siteName || 'Site';
        const splitName = splitPascalCase(route.componentName);
        const label = inferFromComponentName(route.componentName) || splitName || prettyPath(route.path);
        out.title = label === baseName ? baseName : `${label} - ${baseName}`;
        out.confidence.title = splitName ? 0.5 : 0.3;
        sources.title = splitName ? 'component-name-split' : 'fallback';
    }
    // siteName 접미사 자동 부착 (이미 들어가 있으면 skip)
    if (out.title && ctx.defaults?.siteName && !out.title.includes(ctx.defaults.siteName) && out.confidence.title >= 0.6 && route.path !== '/') {
        out.title = `${out.title} - ${ctx.defaults.siteName}`;
    }
    if (!out.image && ctx.defaults?.image) {
        out.image = ctx.defaults.image;
        out.confidence.image = 0.3;
        sources.image = 'defaults';
    }
    if (!out.description && ctx.defaults?.description) {
        out.description = ctx.defaults.description;
        out.confidence.description = 0.3;
        sources.description = 'defaults';
    }
    return out;
}

function splitPascalCase(name) {
    if (!name) return '';
    // BlogPostPage → "Blog Post Page" → "Blog Post" (Page suffix 제거)
    const parts = [];
    let cur = '';
    for (const ch of name) {
        if (/[A-Z]/.test(ch) && cur) { parts.push(cur); cur = ''; }
        cur += ch;
    }
    if (cur) parts.push(cur);
    const filtered = parts.filter(p => !/^(Page|Component|View|Screen)$/i.test(p));
    if (filtered.length === 0) return '';
    return filtered.join(' ');
}

function prettyPath(p) {
    if (!p || p === '/') return '홈';
    const seg = p.split('/').filter(Boolean).filter(s => !s.startsWith(':') && s !== '*');
    if (seg.length === 0) return '홈';
    return seg.map(s => s.replace(/[-_]/g, ' ')).join(' › ');
}

/**
 * 모든 라우트에 대해 메타 추론 일괄 수행.
 * @param {Array<object>} routes
 * @param {object} opts
 * @param {string} opts.frontendDir
 * @param {object} opts.defaults
 */
export async function inferAllPageMetas(routes, opts) {
    const locales = await loadLocales(opts.frontendDir);
    const out = [];
    for (const r of routes) {
        const meta = await inferPageMeta(r, { locales, defaults: opts.defaults || {} });
        out.push({ route: r, meta });
    }
    return { items: out, locales: Object.keys(locales) };
}
