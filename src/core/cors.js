/**
 * security.cors 정규화 — 워커 템플릿에 임베드할 허용 오리진 목록.
 * 비어 있거나 '*' 이면 기존 동작(*), 그 외에는 해당 오리진만 ACAO 로 반환한다.
 */
export function normalizeCorsConfig(security) {
    const raw = security && typeof security === 'object' ? security.cors : null;
    const list = raw && Array.isArray(raw.allowedOrigins) ? raw.allowedOrigins : [];
    const origins = list
        .map((v) => String(v || '').trim())
        .filter(Boolean);
    return { origins };
}

/**
 * 요청 Origin 과 CORS 설정으로 응답 헤더를 만든다 (serve/dev 공용).
 * 설정이 비어 있거나 '*' 이면 기존 동작(ACAO *)을 유지한다.
 *
 * @param {string} origin
 * @param {{ origins?: string[] }} config
 * @returns {Record<string, string>}
 */
export function corsHeadersFor(origin, config) {
    const origins = Array.isArray(config?.origins) ? config.origins : [];
    const out = { Vary: 'Origin' };
    if (origins.length === 0 || origins.includes('*')) {
        out['Access-Control-Allow-Origin'] = '*';
    } else if (origin && origins.includes(origin)) {
        out['Access-Control-Allow-Origin'] = origin;
    }
    return out;
}

function _normalizeOrigin(value) {
    let s = String(value || '').trim();
    if (!s) return '';
    if (!/^https?:\/\//i.test(s)) s = 'https://' + s.replace(/^\/+/, '');
    return s.replace(/\/+$/, '');
}

/**
 * 배포 설정에서 CORS 오리진 후보를 유도한다.
 * - deploy.cloudflarePages.domain / deploy.cloudflare.domain
 * - deploy.r2.domain / deploy.s3.domain
 * - <project>.pages.dev (project 는 deploy.cloudflare.project 또는 프로젝트 디렉터리명)
 *
 * @param {object} config
 * @param {{ projectName?: string }} [opts]
 * @returns {string[]}
 */
export function deriveCorsOrigins(config, opts = {}) {
    const out = [];
    const add = (v) => {
        const origin = _normalizeOrigin(v);
        if (origin && !out.includes(origin)) out.push(origin);
    };
    const deploy = config && typeof config === 'object' ? (config.deploy || {}) : {};
    add(deploy.cloudflarePages?.domain);
    add(deploy.cloudflare?.domain);
    add(deploy.r2?.domain);
    add(deploy.s3?.domain);
    const project = deploy.cloudflare?.project
        || deploy.cloudflarePages?.project
        || opts.projectName
        || '';
    if (project) add(`${project}.pages.dev`);
    return out;
}

/**
 * 기존 allowedOrigins 가 있으면 그대로 존중하고, 비어 있을 때만 자동 유도한다.
 * security.cors.auto === false 로 끌 수 있다.
 *
 * @param {object} security
 * @param {object} config
 * @param {{ projectName?: string }} [opts]
 * @returns {{ origins: string[], derived: string[] }}
 */
export function resolveCorsConfig(security, config, opts = {}) {
    const base = normalizeCorsConfig(security);
    const auto = security?.cors?.auto !== false;
    if (base.origins.length > 0 || !auto) {
        return { origins: base.origins, derived: [] };
    }
    const derived = deriveCorsOrigins(config, opts);
    return { origins: derived, derived };
}
