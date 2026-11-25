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
