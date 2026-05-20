/**
 * Dokkebi SEO — schema.org JSON-LD 자동 추론 (PR2)
 *
 * 테이블명/라우트 패턴에서 schema.org @type 을 추론하고, D1 row 의 컬럼을
 * 표준 schema.org 속성으로 매핑한다.
 *
 * 정적 라우트는 이미 emitPrerender 에서 WebPage/WebSite JSON-LD 가 들어가므로
 * 이 모듈은 동적(enumerate) 라우트에 한정한다.
 */

const TYPE_BY_TABLE = [
    [/^(blog_)?posts?$/i,         'BlogPosting'],
    [/^articles?$/i,              'Article'],
    [/^blog_articles?$/i,         'BlogPosting'],
    [/^news(_items)?$/i,          'NewsArticle'],
    [/^products?$/i,              'Product'],
    [/^items?$/i,                 'Product'],
    [/^events?$/i,                'Event'],
    [/^courses?$/i,               'Course'],
    [/^recipes?$/i,               'Recipe'],
    [/^videos?$/i,                'VideoObject'],
    [/^jobs?$/i,                  'JobPosting'],
    [/^users?$|^profiles?$/i,     'ProfilePage'],
    [/_projects?$/i,              'CreativeWork'],
    [/^sessions?$|^tickets?$/i,   'Event'],
    [/^categories$|^tags$/i,      'CollectionPage'],
];

function pickType(table, routePath) {
    if (table) {
        for (const [re, t] of TYPE_BY_TABLE) if (re.test(table)) return t;
    }
    if (routePath) {
        if (/\/blog\//.test(routePath) || /\/post\//.test(routePath)) return 'BlogPosting';
        if (/\/product\//.test(routePath)) return 'Product';
        if (/\/event\//.test(routePath)) return 'Event';
    }
    return 'WebPage';
}

function absUrl(baseUrl, p) {
    if (!p) return undefined;
    if (/^https?:\/\//.test(p)) return p;
    if (!baseUrl) return p;
    return baseUrl.replace(/\/+$/, '') + (p.startsWith('/') ? p : '/' + p);
}

function trim160(s) {
    if (!s) return undefined;
    const t = String(s).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    return t.length > 160 ? t.slice(0, 159) + '…' : t;
}

/**
 * @param {object} item - enumerateDynamicRoutes 의 expanded[]
 * @param {object} ctx  - { baseUrl, siteName }
 */
export function buildJsonLdForItem(item, ctx) {
    const type = pickType(item.sourceTable, item.sourceRoute);
    const url = absUrl(ctx.baseUrl, item.path);
    const image = absUrl(ctx.baseUrl, item.image);
    const ld = {
        '@context': 'https://schema.org',
        '@type': type,
        name: item.title || undefined,
        headline: type === 'BlogPosting' || type === 'Article' || type === 'NewsArticle' ? (item.title || undefined) : undefined,
        description: trim160(item.description),
        url,
        image,
        dateModified: item.lastmod || undefined,
    };
    // 게시물 계열은 datePublished 필드 매핑
    if (item.row) {
        if (item.row.published_at) ld.datePublished = item.row.published_at;
        else if (item.row.created_at) ld.datePublished = item.row.created_at;
        // author/username 후보
        if (item.row.author_name) ld.author = { '@type': 'Person', name: item.row.author_name };
        else if (item.row.username) ld.author = { '@type': 'Person', name: item.row.username };
    }
    if (ctx.siteName) {
        ld.isPartOf = { '@type': 'WebSite', name: ctx.siteName, url: ctx.baseUrl || undefined };
    }
    // undefined 정리
    return JSON.parse(JSON.stringify(ld));
}
