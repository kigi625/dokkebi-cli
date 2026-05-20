/**
 * Dokkebi SEO — sitemap.xml + robots.txt (PR1)
 */

import path from 'path';
import fs from 'fs/promises';

function escapeXml(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

function absUrl(baseUrl, p) {
    if (!p) return baseUrl || '';
    if (/^https?:\/\//.test(p)) return p;
    if (!baseUrl) return p;
    const b = baseUrl.replace(/\/+$/, '');
    const pp = p.startsWith('/') ? p : '/' + p;
    return b + pp;
}

/**
 * @param {object} args
 * @param {string} args.outDir
 * @param {Array<{path, file, noindex, lastmod?: string}>} args.written - prerender 결과
 * @param {object} args.seoConfig
 * @returns {Promise<{sitemap: string|null, robots: string|null, urlCount: number}>}
 */
export async function emitSitemapAndRobots({ outDir, written, seoConfig }) {
    let sitemapPath = null;
    let robotsPath = null;
    let urlCount = 0;

    // 도깨비 내부 prefix 는 sitemap/robots 양쪽 모두에서 자동 차단.
    const isDokkebiInternal = (p) =>
        p.startsWith('/_dokkebi/') ||
        p.startsWith('/api/_dokkebi/') ||
        p.startsWith('/.dokkebi/') ||
        p === '/build-version.json';

    const splitAt = Math.max(1_000, Math.min(50_000, seoConfig.sitemap.splitAt || 50_000));

    if (seoConfig.sitemap.enabled) {
        const indexable = written.filter(w => !w.noindex && !isDokkebiInternal(w.path));
        urlCount = indexable.length;
        const today = new Date().toISOString().slice(0, 10);

        const renderUrlSet = (chunk) => {
            const lines = [
                '<?xml version="1.0" encoding="UTF-8"?>',
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">',
            ];
            for (const w of chunk) {
                const url = absUrl(seoConfig.baseUrl || '', w.path);
                if (!url) continue;
                lines.push('  <url>');
                lines.push(`    <loc>${escapeXml(url)}</loc>`);
                lines.push(`    <lastmod>${escapeXml(w.lastmod || today)}</lastmod>`);
                lines.push(`    <changefreq>${escapeXml(w.path === '/' ? 'daily' : 'weekly')}</changefreq>`);
                lines.push(`    <priority>${w.path === '/' ? '1.0' : '0.7'}</priority>`);
                if (Array.isArray(w.alternates)) {
                    for (const alt of w.alternates) {
                        const altUrl = absUrl(seoConfig.baseUrl || '', alt.path);
                        if (!altUrl) continue;
                        lines.push(`    <xhtml:link rel="alternate" hreflang="${escapeXml(alt.lang)}" href="${escapeXml(altUrl)}" />`);
                    }
                }
                lines.push('  </url>');
            }
            lines.push('</urlset>');
            return lines.join('\n');
        };

        if (indexable.length <= splitAt) {
            sitemapPath = path.join(outDir, 'sitemap.xml');
            await fs.writeFile(sitemapPath, renderUrlSet(indexable), 'utf-8');
        } else {
            // 대용량: sitemap-1.xml ... + sitemap.xml (sitemapindex)
            const baseUrl = seoConfig.baseUrl || '';
            const chunks = [];
            for (let i = 0; i < indexable.length; i += splitAt) {
                chunks.push(indexable.slice(i, i + splitAt));
            }
            const indexLines = [
                '<?xml version="1.0" encoding="UTF-8"?>',
                '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
            ];
            for (let i = 0; i < chunks.length; i++) {
                const fname = `sitemap-${i + 1}.xml`;
                await fs.writeFile(path.join(outDir, fname), renderUrlSet(chunks[i]), 'utf-8');
                indexLines.push('  <sitemap>');
                indexLines.push(`    <loc>${escapeXml(absUrl(baseUrl, '/' + fname))}</loc>`);
                indexLines.push(`    <lastmod>${escapeXml(new Date().toISOString().slice(0, 10))}</lastmod>`);
                indexLines.push('  </sitemap>');
            }
            indexLines.push('</sitemapindex>');
            sitemapPath = path.join(outDir, 'sitemap.xml');
            await fs.writeFile(sitemapPath, indexLines.join('\n'), 'utf-8');
        }
    }

    if (seoConfig.robots.enabled) {
        const baseUrl = seoConfig.baseUrl || '';
        const sitemapUrl = baseUrl ? absUrl(baseUrl, '/sitemap.xml') : '/sitemap.xml';
        const noindexPaths = written.filter(w => w.noindex).map(w => w.path);
        const lines = [
            'User-agent: *',
            'Allow: /',
        ];
        // 도깨비 프레임워크 내부 경로는 항상 차단 — 관제 패널/내부 API 는
        // panelIpGuard 로 이미 접근 차단되지만, 검색엔진 인덱싱 자체를 막아
        // 로그 노이즈와 정보 노출 표면을 줄인다.
        const dokkebiInternalDisallow = [
            '/_dokkebi/',          // 관제 패널 + 내부 API
            '/api/_dokkebi/',      // Pages Function 내부 라우트
            '/.dokkebi/',          // 빌드 메타 (혹시 노출되더라도)
            '/build-version.json',
        ];
        for (const p of dokkebiInternalDisallow) lines.push(`Disallow: ${p}`);
        for (const p of noindexPaths) {
            // 중복 회피 (이미 dokkebi 내부 차단 prefix 안이면 skip)
            if (!dokkebiInternalDisallow.some(prefix => p.startsWith(prefix))) {
                lines.push(`Disallow: ${p}`);
            }
        }
        if (seoConfig.sitemap.enabled) {
            lines.push('');
            lines.push(`Sitemap: ${sitemapUrl}`);
        }
        robotsPath = path.join(outDir, 'robots.txt');
        await fs.writeFile(robotsPath, lines.join('\n') + '\n', 'utf-8');
    }

    return { sitemap: sitemapPath, robots: robotsPath, urlCount };
}
