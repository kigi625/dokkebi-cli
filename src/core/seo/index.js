/**
 * Dokkebi SEO — 파이프라인 오케스트레이터 (PR1)
 *
 * dok build 가 runFrontendBuild 직후 호출. 자동 추론 → prerender → sitemap → report.
 * 모든 단계는 실패해도 빌드를 막지 않는다 (경고만 출력).
 */

import { scanRouter } from './scanRouter.js';
import { inferAllPageMetas } from './inferPageMeta.js';
import { normalizeSeoConfig } from './normalizeSeoConfig.js';
import { emitPrerender } from './emitPrerender.js';
import { emitSitemapAndRobots } from './emitSitemap.js';
import { emitReport } from './emitReport.js';
import { enumerateDynamicRoutes } from './enumerateDynamic.js';
import { buildJsonLdForItem } from './inferJsonLd.js';
import { expandHreflangForItems } from './expandHreflang.js';
import { emitEdgeRenderer } from './emitEdgeRenderer.js';

/**
 * 사용자가 routes/dynamic 으로 지정한 오버라이드를 자동 추론 결과 위에 머지.
 */
function applyConfigOverrides(items, seoConfig) {
    if (!seoConfig.routes) return items;
    return items.map(({ route, meta }) => {
        const ov = seoConfig.routes[route.path];
        if (!ov) return { route, meta };
        const next = { ...meta };
        if (typeof ov.title === 'string')       { next.title = ov.title; next.confidence = { ...next.confidence, title: 1.0 }; next.sources = { ...next.sources, title: 'config' }; }
        if (typeof ov.description === 'string') { next.description = ov.description; next.confidence = { ...next.confidence, description: 1.0 }; next.sources = { ...next.sources, description: 'config' }; }
        if (typeof ov.image === 'string')       { next.image = ov.image; next.confidence = { ...next.confidence, image: 1.0 }; next.sources = { ...next.sources, image: 'config' }; }
        if (typeof ov.noindex === 'boolean')    { next.noindex = ov.noindex; next.sources = { ...next.sources, noindex: 'config' }; }
        if (ov.jsonLd && typeof ov.jsonLd === 'object') next.jsonLd = ov.jsonLd;
        return { route, meta: next };
    });
}

/**
 * @param {object} args
 * @param {string} args.sourceRoot
 * @param {string} args.frontendDir
 * @param {string} args.outDir
 * @param {object} args.dokkebiConfig
 * @param {object} [args.dbConfig] - PR2: D1 enumerate 용 자격 (resolveDbConfig 결과)
 * @param {object} [args.authzMeta] - PR2: normalizeAuthorizationConfig 결과
 * @param {boolean} [args.verbose]
 * @returns {Promise<{enabled: boolean, summary?: object, manifestPath?: string, reportPath?: string} | null>}
 */
export async function runSeoPipeline(args) {
    const { sourceRoot, frontendDir, outDir, dokkebiConfig, dbConfig, authzMeta, verbose } = args;
    const seoConfig = await normalizeSeoConfig(dokkebiConfig, { sourceRoot, frontendDir });
    if (!seoConfig.enabled) {
        return { enabled: false };
    }

    const scanned = await scanRouter(frontendDir, { verbose });

    // 사용자가 명시한 routes (config.seo.routes) 만 있고 라우터 스캔이 0건이어도
    // 그 라우트들은 prerender 한다 (state 기반 SPA / 자체 라우터 사용 케이스).
    const configRoutePaths = Object.keys(seoConfig.routes || {});
    const fauxRoutesFromConfig = configRoutePaths.map((p) => ({
        path: p,
        componentName: null,
        componentFile: null,
        isDynamic: /[:*]/.test(p),
        params: [],
        protected: false,
        redirect: false,
        declaredIn: null,
        line: 0,
    }));
    const allRoutes = [...scanned.routes];
    for (const fr of fauxRoutesFromConfig) {
        if (!allRoutes.some(r => r.path === fr.path)) allRoutes.push(fr);
    }

    const inferred = await inferAllPageMetas(allRoutes, {
        frontendDir,
        defaults: seoConfig.defaults,
    });

    const items = applyConfigOverrides(inferred.items, seoConfig);

    // ── PR2: 동적 라우트 D1 enumerate ───────────────────────
    // isDynamic 인 라우트만 대상. dbConfig 가 없으면 graceful skip.
    const dynamicSource = items
        .map(it => it.route)
        .filter(r => r.isDynamic && !r.redirect);
    const enumerateResult = await enumerateDynamicRoutes({
        dynamicRoutes: dynamicSource,
        dbConfig,
        authzMeta,
        seoConfig,
        verbose,
    });

    // ── PR2: hreflang 확장 (남은 :lang 세그먼트 → locale 별 path 펼침) ─
    const hreflang = expandHreflangForItems(enumerateResult.expanded, {
        locales: inferred.locales,
        enabled: seoConfig.hreflang.enabled,
    });

    // 동적 라우트의 noindex 결정 — sourceRoute 의 정적 메타가 noindex 면 동적도 noindex.
    const staticByPath = new Map(items.map(it => [it.route.path, it.meta]));
    const dynamicItems = hreflang.items.map((it) => {
        const srcMeta = staticByPath.get(it.sourceRoute);
        const noindex = !!(srcMeta && srcMeta.noindex);
        const jsonLd = seoConfig.jsonLd.enabled
            ? buildJsonLdForItem(it, { baseUrl: seoConfig.baseUrl, siteName: seoConfig.defaults.siteName })
            : null;
        return { ...it, noindex, jsonLd };
    });

    // 라우트 0건이면 prerender/sitemap 은 비워두고 진단 리포트만 남긴다.
    const hasAnything = items.length > 0 || dynamicItems.length > 0;
    const prerender = hasAnything
        ? await emitPrerender({ outDir, items, dynamicItems, seoConfig })
        : { written: [], skipped: [] };
    const sitemap = hasAnything
        ? await emitSitemapAndRobots({ outDir, written: prerender.written, seoConfig })
        : { sitemap: null, robots: null, urlCount: 0 };

    // ── PR3: Edge SEO Renderer 산출 (long-tail 동적 페이지 + 빌드 후 추가 컨텐츠) ─
    // dbConfig 가 있고 routeMeta 가 있을 때만 emit. 봇 UA 만 위임 → 정상 사용자 영향 없음.
    let edgeRenderer = { written: [], skipped: true, reason: 'not-attempted' };
    try {
        edgeRenderer = await emitEdgeRenderer({
            outDir,
            sourceRoot,
            seoConfig,
            routeMeta: enumerateResult.routeMeta || [],
            dbAvailable: enumerateResult.diagnostics.available,
        });
    } catch (e) {
        edgeRenderer = { written: [], skipped: true, reason: `error:${e?.message || e}` };
    }

    const report = await emitReport({
        sourceRoot,
        outDir,
        seoConfig,
        items,
        prerender,
        sitemap,
        locales: inferred.locales,
        scannedFiles: scanned.scannedFiles,
        dynamic: {
            sourceRoutes: dynamicSource.length,
            expanded: dynamicItems.length,
            skipped: enumerateResult.skipped,
            hreflangSkipped: hreflang.skipped,
            tablesAvailable: enumerateResult.diagnostics.available,
            tablesCount: enumerateResult.diagnostics.tables,
            queries: enumerateResult.diagnostics.queries,
            // 라우트별 prerender 카운트 (정확)
            byRoute: dynamicItems.reduce((acc, it) => {
                acc[it.sourceRoute] = (acc[it.sourceRoute] || 0) + 1;
                return acc;
            }, {}),
        },
        diagnostics: {
            routerDetected: scanned.routes.length > 0,
            sourceFiles: scanned.sourceFiles,
            unresolvedRoutes: scanned.unresolvedRoutes || [],
        },
    });

    return {
        enabled: true,
        seoConfig,
        scanned: { scannedFiles: scanned.scannedFiles, sourceFiles: scanned.sourceFiles },
        prerender,
        sitemap,
        edgeRenderer,
        manifestPath: report.manifestPath,
        reportPath: report.reportPath,
        summary: {
            ...report.summary,
            dynamicExpanded: dynamicItems.length,
            dynamicSourceRoutes: dynamicSource.length,
            dynamicSkipped: enumerateResult.skipped.length,
            d1Available: enumerateResult.diagnostics.available,
            edgeRendererEmitted: edgeRenderer.written?.length || 0,
        },
    };
}
