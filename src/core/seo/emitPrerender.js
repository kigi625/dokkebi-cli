/**
 * Dokkebi SEO — 정적 prerender (PR1)
 *
 * dist/index.html 을 base 템플릿으로 라우트별 복제 (dist/<route>/index.html)
 * 후 <title>/meta/og/twitter/JSON-LD/link[hreflang]/canonical 을 주입.
 *
 * 동적 라우트 (`:id`, `:slug`, `*`) 는 PR2 에서 D1 enumerate 로 처리. PR1 에서는
 * 정적 라우트만 prerender 한다.
 *
 * 기존 사용자 정의 <meta>/<title> 은 보존하되, 도깨비가 주입한 태그는
 * `data-dokkebi-seo` 속성으로 표시되어 재빌드 시 같은 속성만 교체된다.
 */

import path from 'path';
import fs from 'fs/promises';

const DOKKEBI_SEO_BLOCK_START = '<!-- dokkebi:seo:start -->';
const DOKKEBI_SEO_BLOCK_END   = '<!-- dokkebi:seo:end -->';

function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function absUrl(baseUrl, p) {
    if (!p) return '';
    if (/^https?:\/\//.test(p)) return p;
    if (!baseUrl) return p;
    const b = baseUrl.replace(/\/+$/, '');
    const pp = p.startsWith('/') ? p : '/' + p;
    return b + pp;
}

function buildSeoBlock({ route, meta, seoConfig, alternates }) {
    const lines = [];
    const tag = (s) => lines.push('  ' + s);

    const baseUrl = seoConfig.baseUrl || '';
    const canonical = absUrl(baseUrl, route.path === '/' ? '/' : route.path);
    const imageAbs = absUrl(baseUrl, meta.image);
    const siteName = seoConfig.defaults.siteName;
    const locale = seoConfig.defaults.locale || 'ko';
    const twitterCard = seoConfig.defaults.twitterCard || 'summary_large_image';

    if (meta.title)       tag(`<title data-dokkebi-seo>${escapeHtml(meta.title)}</title>`);
    if (meta.description) tag(`<meta name="description" content="${escapeHtml(meta.description)}" data-dokkebi-seo />`);
    if (meta.noindex)     tag(`<meta name="robots" content="noindex,nofollow" data-dokkebi-seo />`);
    else                  tag(`<meta name="robots" content="index,follow" data-dokkebi-seo />`);
    if (canonical)        tag(`<link rel="canonical" href="${escapeHtml(canonical)}" data-dokkebi-seo />`);

    // OpenGraph
    if (meta.title)       tag(`<meta property="og:title" content="${escapeHtml(meta.title)}" data-dokkebi-seo />`);
    if (meta.description) tag(`<meta property="og:description" content="${escapeHtml(meta.description)}" data-dokkebi-seo />`);
    if (canonical)        tag(`<meta property="og:url" content="${escapeHtml(canonical)}" data-dokkebi-seo />`);
    if (siteName)         tag(`<meta property="og:site_name" content="${escapeHtml(siteName)}" data-dokkebi-seo />`);
    tag(`<meta property="og:type" content="${escapeHtml(route.path === '/' ? 'website' : 'article')}" data-dokkebi-seo />`);
    if (locale)           tag(`<meta property="og:locale" content="${escapeHtml(locale)}" data-dokkebi-seo />`);
    if (imageAbs)         tag(`<meta property="og:image" content="${escapeHtml(imageAbs)}" data-dokkebi-seo />`);

    // Twitter
    tag(`<meta name="twitter:card" content="${escapeHtml(twitterCard)}" data-dokkebi-seo />`);
    if (meta.title)       tag(`<meta name="twitter:title" content="${escapeHtml(meta.title)}" data-dokkebi-seo />`);
    if (meta.description) tag(`<meta name="twitter:description" content="${escapeHtml(meta.description)}" data-dokkebi-seo />`);
    if (imageAbs)         tag(`<meta name="twitter:image" content="${escapeHtml(imageAbs)}" data-dokkebi-seo />`);

    // hreflang (PR1: i18n 라우트 alternates 가 있을 때만)
    if (Array.isArray(alternates) && alternates.length > 0 && seoConfig.hreflang.enabled) {
        for (const alt of alternates) {
            tag(`<link rel="alternate" hreflang="${escapeHtml(alt.lang)}" href="${escapeHtml(absUrl(baseUrl, alt.path))}" data-dokkebi-seo />`);
        }
    }

    // JSON-LD (기본 WebPage / 홈은 WebSite)
    if (seoConfig.jsonLd.enabled) {
        const jsonLd = meta.jsonLd || (route.path === '/'
            ? {
                '@context': 'https://schema.org',
                '@type': 'WebSite',
                name: siteName || meta.title,
                url: baseUrl || canonical,
              }
            : {
                '@context': 'https://schema.org',
                '@type': 'WebPage',
                name: meta.title,
                description: meta.description || undefined,
                url: canonical,
                image: imageAbs || undefined,
              });
        tag(`<script type="application/ld+json" data-dokkebi-seo>${JSON.stringify(jsonLd)}</script>`);
    }

    return [DOKKEBI_SEO_BLOCK_START, ...lines, DOKKEBI_SEO_BLOCK_END].join('\n');
}

/**
 * 기존 HTML 에서 dokkebi:seo 블록을 교체하거나, 없으면 </head> 직전에 삽입.
 * 추가로 사용자가 직접 박은 정적 <title>/<meta name="description"> 이 있다면
 * 도깨비 주입 태그가 충돌하지 않도록 그대로 둔다 (data-dokkebi-seo 속성으로
 * 구분).
 */
function injectSeoBlock(html, seoBlock) {
    const startIdx = html.indexOf(DOKKEBI_SEO_BLOCK_START);
    const endIdx = html.indexOf(DOKKEBI_SEO_BLOCK_END);
    if (startIdx >= 0 && endIdx > startIdx) {
        return html.slice(0, startIdx) + seoBlock + html.slice(endIdx + DOKKEBI_SEO_BLOCK_END.length);
    }

    // 페이지별 prerender 의 경우, frontend/index.html 의 사이트 기본 <title>/og:title/
    // og:description/og:url/og:image/og:locale/twitter:* 가 그대로 남으면 봇이 둘 다 보고
    // 첫 번째(사이트 기본) 를 우선시한다. 도깨비 SEO 블록 주입 전에 기본 메타 1세트를 제거.
    // 단 data-dokkebi-seo 마커가 있는 메타(이전 빌드 산출물 등)는 유지 — SEO 블록과 같이 갱신됨.
    let cleaned = html;
    const stripIfNotMarked = (tagRegex) => {
        cleaned = cleaned.replace(tagRegex, (m) => /\bdata-dokkebi-seo\b/i.test(m) ? m : '');
    };
    // <title>...</title> — 첫 번째 1개만 제거
    cleaned = cleaned.replace(/<title[^>]*>[\s\S]*?<\/title>/i, (m) => /\bdata-dokkebi-seo\b/i.test(m) ? m : '');
    // 도깨비가 주입할 메타와 겹치는 것들을 마커 없을 때만 제거
    stripIfNotMarked(/<meta[^>]*\bname=["']description["'][^>]*\/?>/gi);
    stripIfNotMarked(/<meta[^>]*\bname=["']robots["'][^>]*\/?>/gi);
    stripIfNotMarked(/<link[^>]*\brel=["']canonical["'][^>]*\/?>/gi);
    stripIfNotMarked(/<meta[^>]*\bproperty=["']og:(?:title|description|url|image|site_name|type|locale)["'][^>]*\/?>/gi);
    stripIfNotMarked(/<meta[^>]*\bname=["']twitter:(?:card|title|description|image)["'][^>]*\/?>/gi);
    stripIfNotMarked(/<link[^>]*\brel=["']alternate["'][^>]*\bhreflang=[^>]*\/?>/gi);

    const headCloseRe = /<\/head\s*>/i;
    const m2 = headCloseRe.exec(cleaned);
    if (m2) {
        return cleaned.slice(0, m2.index) + seoBlock + '\n' + cleaned.slice(m2.index);
    }
    return seoBlock + '\n' + cleaned;
}

function pathToFsDir(p, outDir) {
    if (p === '/' || p === '') return outDir;
    const segs = p.split('/').filter(Boolean);
    return path.join(outDir, ...segs);
}

/**
 * 정적 라우트 prerender + 동적 enumerate 결과 prerender.
 *
 * @param {object} args
 * @param {string} args.outDir - dist 절대경로
 * @param {Array<{route, meta}>} args.items - 정적 라우트 + 메타
 * @param {Array<object>} [args.dynamicItems] - enumerate 결과 (PR2). 각 항목:
 *   { path, title, description, image, lastmod, sourceTable, sourceRoute, alternates?, lang?, jsonLd? }
 *   noindex 는 sourceRoute 의 protected/redirect 로부터 결정 (보수적).
 * @param {object} args.seoConfig
 * @returns {Promise<{written, skipped}>}
 */
export async function emitPrerender({ outDir, items, dynamicItems, seoConfig }) {
    if (!seoConfig.prerender.enabled) return { written: [], skipped: items.map(i => ({ path: i.route.path, reason: 'prerender:disabled' })) };

    const baseHtmlPath = path.join(outDir, 'index.html');
    let baseHtml;
    try { baseHtml = await fs.readFile(baseHtmlPath, 'utf-8'); }
    catch (e) {
        return { written: [], skipped: [{ path: '*', reason: `no-base-html: ${e.message}` }] };
    }

    const written = [];
    const skipped = [];
    let count = 0;
    // 도깨비 내부 prefix 는 어떤 경우에도 prerender 하지 않는다 (관제/내부 API).
    const isDokkebiInternal = (p) =>
        p.startsWith('/_dokkebi/') ||
        p.startsWith('/api/_dokkebi/') ||
        p.startsWith('/.dokkebi/');

    for (const { route, meta } of items) {
        if (isDokkebiInternal(route.path)) {
            skipped.push({ path: route.path, reason: 'dokkebi-internal' });
            continue;
        }
        if (count >= seoConfig.prerender.maxPages) {
            skipped.push({ path: route.path, reason: 'maxPages-exceeded' });
            continue;
        }
        if (route.isDynamic) {
            // PR2 에서 D1 enumerate 로 처리. PR1 에서는 skip.
            skipped.push({ path: route.path, reason: 'dynamic:deferred-to-PR2' });
            continue;
        }
        if (route.redirect) {
            skipped.push({ path: route.path, reason: 'redirect-route' });
            continue;
        }
        const block = buildSeoBlock({ route, meta, seoConfig, alternates: null });
        const out = injectSeoBlock(baseHtml, block);
        if (route.path === '/') {
            await fs.writeFile(baseHtmlPath, out, 'utf-8');
            written.push({ path: '/', file: baseHtmlPath, noindex: !!meta.noindex });
        } else {
            const dir = pathToFsDir(route.path, outDir);
            await fs.mkdir(dir, { recursive: true });
            const filePath = path.join(dir, 'index.html');
            await fs.writeFile(filePath, out, 'utf-8');
            written.push({ path: route.path, file: filePath, noindex: !!meta.noindex });
        }
        count++;
    }

    // ── 동적 enumerate 결과 prerender (PR2) ────────────────
    if (Array.isArray(dynamicItems)) {
        for (const it of dynamicItems) {
            if (!it || !it.path) continue;
            if (isDokkebiInternal(it.path)) {
                skipped.push({ path: it.path, reason: 'dokkebi-internal' });
                continue;
            }
            if (count >= seoConfig.prerender.maxPages) {
                skipped.push({ path: it.path, reason: 'maxPages-exceeded' });
                continue;
            }
            // 가짜 route/meta 객체 생성 — 정적 라우트와 동일 buildSeoBlock 재사용
            const fauxRoute = { path: it.path, redirect: false };
            const fauxMeta = {
                title: it.title,
                description: it.description,
                image: it.image,
                noindex: !!it.noindex,
                jsonLd: it.jsonLd || null,
            };
            const block = buildSeoBlock({
                route: fauxRoute,
                meta: fauxMeta,
                seoConfig,
                alternates: it.alternates || null,
            });
            const out = injectSeoBlock(baseHtml, block);
            const dir = pathToFsDir(it.path, outDir);
            await fs.mkdir(dir, { recursive: true });
            const filePath = path.join(dir, 'index.html');
            await fs.writeFile(filePath, out, 'utf-8');
            written.push({
                path: it.path,
                file: filePath,
                noindex: !!it.noindex,
                lastmod: it.lastmod ? String(it.lastmod).slice(0, 10) : null,
            });
            count++;
        }
    }

    return { written, skipped };
}
