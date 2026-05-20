/**
 * Dokkebi SEO — 사용자 config 정규화 (PR1)
 *
 * dokkebi.config.js 의 `seo` 블록은 모두 선택. 미설정·부분설정·전체설정
 * 모두 동일한 정규화 객체를 반환해 후속 단계가 분기 없이 동작하도록 함.
 *
 * 자동 추론된 baseUrl/siteName/image 도 여기서 결정한다 (deploy.cloudflarePages.domain
 * → baseUrl, package.json name → siteName, public/og-default.png → image).
 */

import path from 'path';
import fs from 'fs/promises';

const DEFAULTS = {
    enabled: true,
    baseUrl: '',
    defaults: {
        siteName: '',
        locale: 'ko',
        image: '',
        twitterCard: 'summary_large_image',
        description: '',
    },
    routes: {},
    dynamic: [],
    prerender: { enabled: true, concurrency: 8, maxPages: 50_000 },
    sitemap: { enabled: true, splitAt: 50_000 },
    robots: { enabled: true },
    edgeRenderer: { enabled: true, cacheTtlSeconds: 86_400 },
    jsonLd: { enabled: true },
    hreflang: { enabled: true },
    inferenceMinConfidence: 0.5,
};

function pickBool(v, fb) { return typeof v === 'boolean' ? v : fb; }
function pickNum(v, fb, lo, hi) {
    const n = Number(v);
    if (!Number.isFinite(n)) return fb;
    let r = Math.floor(n);
    if (lo != null) r = Math.max(lo, r);
    if (hi != null) r = Math.min(hi, r);
    return r;
}
function pickStr(v, fb) { return typeof v === 'string' && v.trim() ? v : fb; }

async function detectSiteName(sourceRoot, fb) {
    if (fb) return fb;
    try {
        const pkg = JSON.parse(await fs.readFile(path.join(sourceRoot, 'package.json'), 'utf-8'));
        if (pkg?.name) {
            return String(pkg.name)
                .replace(/^@[^/]+\//, '')
                .replace(/[-_]/g, ' ')
                .replace(/\b\w/g, (c) => c.toUpperCase());
        }
    } catch { /* skip */ }
    return path.basename(sourceRoot);
}

async function detectDefaultImage(frontendDir, fb) {
    if (fb) return fb;
    const candidates = [
        'og-default.png', 'og-default.jpg', 'og.png', 'og.jpg',
        'og-image.png', 'og-image.jpg', 'social-card.png',
    ];
    const publicDir = path.join(frontendDir, 'public');
    for (const c of candidates) {
        try {
            await fs.access(path.join(publicDir, c));
            return '/' + c;
        } catch { /* next */ }
    }
    return '';
}

function detectBaseUrl(rawConfig, fb) {
    if (fb) return fb;
    const cf = rawConfig?.deploy?.cloudflarePages?.domain;
    if (cf) return cf.startsWith('http') ? cf : `https://${cf}`;
    const r2 = rawConfig?.deploy?.r2?.domain;
    if (r2) return r2.startsWith('http') ? r2 : `https://${r2}`;
    return '';
}

/**
 * @param {object} dokkebiConfig - applySecurityPreset 적용된 config
 * @param {object} ctx - { sourceRoot, frontendDir }
 * @returns {Promise<object>} normalized seo config
 */
export async function normalizeSeoConfig(dokkebiConfig, ctx) {
    const raw = dokkebiConfig?.seo && typeof dokkebiConfig.seo === 'object' ? dokkebiConfig.seo : {};

    const out = JSON.parse(JSON.stringify(DEFAULTS));
    out.enabled = pickBool(raw.enabled, true);
    out.baseUrl = pickStr(raw.baseUrl, detectBaseUrl(dokkebiConfig, ''));
    out.defaults.siteName    = await detectSiteName(ctx.sourceRoot, pickStr(raw.defaults?.siteName, ''));
    out.defaults.locale      = pickStr(raw.defaults?.locale, 'ko');
    out.defaults.image       = await detectDefaultImage(ctx.frontendDir, pickStr(raw.defaults?.image, ''));
    out.defaults.twitterCard = pickStr(raw.defaults?.twitterCard, 'summary_large_image');
    out.defaults.description = pickStr(raw.defaults?.description, '');

    if (raw.routes && typeof raw.routes === 'object') {
        for (const [k, v] of Object.entries(raw.routes)) {
            if (v && typeof v === 'object') out.routes[k] = { ...v };
        }
    }
    if (Array.isArray(raw.dynamic)) {
        out.dynamic = raw.dynamic
            .filter((d) => d && typeof d === 'object' && (typeof d.pattern === 'string' || typeof d.path === 'string'))
            .map((d) => ({ ...d, pattern: d.pattern || d.path }));
    }

    out.prerender.enabled     = pickBool(raw.prerender?.enabled, true);
    out.prerender.concurrency = pickNum(raw.prerender?.concurrency, 8, 1, 32);
    out.prerender.maxPages    = pickNum(raw.prerender?.maxPages, 50_000, 1, 1_000_000);
    out.sitemap.enabled       = pickBool(raw.sitemap?.enabled, true);
    out.sitemap.splitAt       = pickNum(raw.sitemap?.splitAt, 50_000, 1_000, 50_000);
    out.robots.enabled        = pickBool(raw.robots?.enabled, true);
    out.edgeRenderer.enabled = pickBool(raw.edgeRenderer?.enabled, true); // PR3: 기본 ON (D1 자격 + dynamic 라우트 있을 때만 실효)
    out.edgeRenderer.cacheTtlSeconds = pickNum(
        raw.edgeRenderer?.cacheTtlSeconds ?? raw.edgeRenderer?.cacheTtlSec,
        86_400, 60, 30 * 86_400,
    );
    out.jsonLd.enabled        = pickBool(raw.jsonLd?.enabled, true);
    out.hreflang.enabled      = pickBool(raw.hreflang?.enabled, true);
    out.inferenceMinConfidence = Math.max(0, Math.min(1, Number(raw.inferenceMinConfidence) || 0.5));

    return out;
}
