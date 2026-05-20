/**
 * Dokkebi SEO — manifest + 사람용 리포트 (PR1)
 *
 * 산출물:
 *   dist/.dokkebi/seo-manifest.json   (재빌드 캐시 + Edge Renderer 입력)
 *   dist/.dokkebi/seo-report.md       (사용자 검토용 — 빌드 끝에 콘솔 요약도)
 */

import path from 'path';
import fs from 'fs/promises';

function pad(s, n) {
    s = String(s == null ? '' : s);
    if (s.length >= n) return s.slice(0, n);
    return s + ' '.repeat(n - s.length);
}

function indexOk(r, m) {
    if (m.noindex) return '❌ noindex';
    if (r.protected) return '❌ protected';
    if (r.redirect) return '↪ redirect';
    return '✅';
}

function fmtConfidence(c, src) {
    if (!c) return '—';
    return `${(c).toFixed(1)} (${src || '?'})`;
}

/**
 * @param {object} args
 * @param {string} args.sourceRoot
 * @param {string} args.outDir
 * @param {object} args.seoConfig
 * @param {Array<{route, meta}>} args.items
 * @param {{written: Array, skipped: Array}} args.prerender
 * @param {{sitemap: string|null, robots: string|null, urlCount: number}} args.sitemap
 * @param {Array<string>} args.locales
 * @param {number} args.scannedFiles
 * @returns {Promise<{manifestPath: string, reportPath: string, summary: object}>}
 */
export async function emitReport(args) {
    const {
        outDir, seoConfig, items, prerender, sitemap, locales, scannedFiles,
        diagnostics, dynamic,
    } = args;

    const dir = path.join(outDir, '.dokkebi');
    await fs.mkdir(dir, { recursive: true });

    const minConf = seoConfig.inferenceMinConfidence;
    const lowConf = items.filter(({ meta }) => {
        const c = Math.min(
            meta.confidence?.title ?? 0,
            meta.confidence?.description ?? 1, // description 누락은 별도 카운트
        );
        return c < minConf;
    });
    const missingDesc = items.filter(({ meta }) => !meta.description);
    const missingImg  = items.filter(({ meta }) => !meta.image);

    const manifest = {
        version: 1,
        generatedAt: new Date().toISOString(),
        baseUrl: seoConfig.baseUrl,
        defaults: seoConfig.defaults,
        routes: items.map(({ route, meta }) => ({
            path: route.path,
            componentName: route.componentName,
            componentFile: route.componentFile ? path.relative(args.sourceRoot, route.componentFile) : null,
            isDynamic: route.isDynamic,
            params: route.params,
            protected: route.protected,
            redirect: route.redirect,
            title: meta.title,
            description: meta.description,
            image: meta.image,
            noindex: meta.noindex,
            sources: meta.sources,
            confidence: meta.confidence,
            jsonLd: meta.jsonLd || null,
        })),
        prerender: {
            written: prerender.written.map(w => ({ path: w.path, file: path.relative(outDir, w.file), noindex: w.noindex })),
            skipped: prerender.skipped,
        },
        sitemap: {
            file: sitemap.sitemap ? path.relative(outDir, sitemap.sitemap) : null,
            urlCount: sitemap.urlCount,
        },
        robots: sitemap.robots ? path.relative(outDir, sitemap.robots) : null,
        locales,
        scannedFiles,
        dynamic: dynamic || null,
    };
    const manifestPath = path.join(dir, 'seo-manifest.json');
    await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');

    // 사람용 리포트
    const lines = [];
    lines.push('# Dokkebi SEO 빌드 리포트');
    lines.push('');
    lines.push(`- 생성: ${manifest.generatedAt}`);
    lines.push(`- 사이트: ${seoConfig.defaults.siteName || '(미지정)'} · baseUrl: ${seoConfig.baseUrl || '(미지정)'}`);
    lines.push(`- 기본 OG 이미지: ${seoConfig.defaults.image || '(없음 — public/og-default.png 권장)'}`);
    lines.push(`- 라우트: ${items.length}개 · prerender: ${prerender.written.length}개 · sitemap: ${sitemap.urlCount}개 URL · 스캔 파일 ${scannedFiles}개`);
    lines.push(`- i18n locales: ${locales.length > 0 ? locales.join(', ') : '(없음)'}`);
    lines.push('');

    // ── 라우터 미감지 진단 ───────────────────────────────────
    if (diagnostics && !diagnostics.routerDetected && items.length === 0) {
        lines.push('## ⚠ 라우터를 감지하지 못했습니다');
        lines.push('');
        lines.push('다음 중 하나에 해당할 수 있습니다:');
        lines.push('');
        lines.push('1. **`react-router-dom` 을 사용하지 않음** (state 기반 SPA, 자체 라우터 등)');
        lines.push('   → `dokkebi.config.js` 의 `seo.routes` 에 페이지를 직접 선언하세요:');
        lines.push('');
        lines.push('   ```js');
        lines.push('   seo: {');
        lines.push('     routes: {');
        lines.push("       '/':         { title: '홈', description: '...' },");
        lines.push("       '/about':    { title: '소개' },");
        lines.push("       '/pricing':  { title: '요금제' },");
        lines.push('     },');
        lines.push('   }');
        lines.push('   ```');
        lines.push('');
        lines.push('2. **동적 path 표현식 사용** (예: `<Route path={`/${id}`} />` 또는 `.map(...)` 패턴)');
        lines.push('   → 도깨비가 데이터 배열을 추론하지 못한 경우. 같은 방법으로 `seo.routes` 에 명시하거나,');
        lines.push('   라우트 path 를 정적 문자열로 풀어서 작성하세요.');
        lines.push('');
        lines.push('3. **frontend/src 가 다른 경로**에 있음 → `frontend.entry` 를 확인.');
        lines.push('');
    } else if (diagnostics && Array.isArray(diagnostics.unresolvedRoutes) && diagnostics.unresolvedRoutes.length > 0) {
        lines.push(`## ⚠ 동적 path 표현식 (${diagnostics.unresolvedRoutes.length}건) — 추론 불가`);
        lines.push('');
        for (const u of diagnostics.unresolvedRoutes.slice(0, 10)) {
            lines.push(`- \`${escapeMd(u.expression)}\`  (${u.file ? path.relative(args.sourceRoot, u.file) : '?'}:${u.line || '?'})`);
        }
        if (diagnostics.unresolvedRoutes.length > 10) {
            lines.push(`- … 외 ${diagnostics.unresolvedRoutes.length - 10}건`);
        }
        lines.push('');
        lines.push('해결: 라우트 path 를 정적 문자열로 풀거나, `dokkebi.config.js` 의 `seo.routes` 에 결과 path 를 직접 명시하세요.');
        lines.push('');
    }

    const staticItems = items.filter(({ route }) => !route.isDynamic);
    const dynamicItems = items.filter(({ route }) => route.isDynamic);

    if (staticItems.length > 0) {
        lines.push(`## 정적 라우트 (${staticItems.length})`);
        lines.push('');
        lines.push('| 경로 | title (출처/신뢰도) | description (출처/신뢰도) | indexable |');
        lines.push('|---|---|---|---|');
        for (const { route, meta } of staticItems) {
            lines.push(`| \`${route.path}\` | ${escapeMd(meta.title)} <br/><sub>${meta.sources?.title || '?'} · ${(meta.confidence?.title || 0).toFixed(1)}</sub> | ${escapeMd(meta.description) || '(없음)'} <br/><sub>${meta.sources?.description || '?'} · ${(meta.confidence?.description || 0).toFixed(1)}</sub> | ${indexOk(route, meta)} |`);
        }
        lines.push('');
    }

    if (dynamicItems.length > 0) {
        const dyn = dynamic || {};
        lines.push(`## 동적 라우트 (${dynamicItems.length})`);
        lines.push('');
        if (!dyn.tablesAvailable) {
            lines.push(`> ⚠ D1 자격(\`accountId\`/\`databaseId\`/\`apiToken\`) 이 없어 enumerate 를 스킵했습니다. \`.env\` 또는 \`dokkebi.config.js\` 의 \`database\` 를 설정하면 빌드 타임 prerender 가 활성화됩니다.`);
            lines.push('');
        } else {
            lines.push(`- D1 테이블 ${dyn.tablesCount}개 감지 · enumerate 쿼리 ${dyn.queries}회 · 펼친 페이지 **${dyn.expanded || 0}**개`);
            lines.push('');
        }
        const byRoute = (dynamic && dynamic.byRoute) || {};
        for (const { route } of dynamicItems) {
            const cnt = byRoute[route.path] || 0;
            lines.push(`- \`${route.path}\` → ${route.componentName} · prerender **${cnt}**개`);
        }
        if (Array.isArray(dyn.skipped) && dyn.skipped.length > 0) {
            lines.push('');
            lines.push(`### 동적 라우트 스킵 (${dyn.skipped.length})`);
            for (const s of dyn.skipped.slice(0, 20)) {
                lines.push(`- \`${escapeMd(s.pattern)}\` — ${escapeMd(s.reason)}`);
            }
            if (dyn.skipped.length > 20) lines.push(`- … 외 ${dyn.skipped.length - 20}건`);
        }
        if (Array.isArray(dyn.hreflangSkipped) && dyn.hreflangSkipped.length > 0) {
            lines.push('');
            lines.push(`### hreflang 확장 실패 (${dyn.hreflangSkipped.length})`);
            for (const s of dyn.hreflangSkipped.slice(0, 10)) {
                lines.push(`- \`${escapeMd(s.path)}\` — ${escapeMd(s.reason)}`);
            }
        }
        lines.push('');
    }

    // 확인 필요
    const issues = [];
    for (const { route, meta } of items) {
        const tConf = meta.confidence?.title || 0;
        if (tConf < minConf && !route.protected && !route.redirect) {
            issues.push(`- \`${route.path}\`: title 신뢰도 ${tConf.toFixed(1)} < ${minConf} — 페이지 컴포넌트(${route.componentFile ? path.relative(args.sourceRoot, route.componentFile) : '?'}) 상단에 \`@dokkebi-seo title: ...\` 추가 권장.`);
        }
        if (!meta.description && !route.protected && !route.redirect) {
            issues.push(`- \`${route.path}\`: description 미추출 — \`@dokkebi-seo description: ...\` 또는 \`<p>\` 첫 단락 추가.`);
        }
    }
    if (issues.length > 0) {
        lines.push(`## ⚠ 확인 필요 (${issues.length})`);
        lines.push('');
        lines.push(...issues);
        lines.push('');
    }

    if (missingImg.length > 0 && !seoConfig.defaults.image) {
        lines.push(`## 권장: OG 이미지 추가`);
        lines.push('');
        lines.push(`- \`frontend/public/og-default.png\` 을 추가하면 모든 페이지가 자동으로 사용합니다 (1200x630 권장).`);
        lines.push('');
    }

    lines.push('---');
    lines.push('이 리포트는 dok build 가 자동 생성합니다. 라우트별 hint 는 페이지 컴포넌트 상단에 다음과 같이 추가하세요:');
    lines.push('');
    lines.push('```tsx');
    lines.push('/** @dokkebi-seo');
    lines.push(' *  title: 도깨비 블로그 — 글');
    lines.push(' *  description: 도깨비 블로그의 개별 글 페이지');
    lines.push(' *  image: /og/blog-post.png');
    lines.push(' */');
    lines.push('export default function BlogPostPage() { ... }');
    lines.push('```');
    lines.push('');
    const reportPath = path.join(dir, 'seo-report.md');
    await fs.writeFile(reportPath, lines.join('\n'), 'utf-8');

    return {
        manifestPath,
        reportPath,
        summary: {
            routes: items.length,
            prerendered: prerender.written.length,
            sitemapUrls: sitemap.urlCount,
            lowConfidence: lowConf.length,
            missingDescription: missingDesc.length,
            missingImage: missingImg.length,
            dynamicDeferred: dynamicItems.length,
        },
    };
}

function escapeMd(s) {
    if (!s) return '';
    return String(s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

