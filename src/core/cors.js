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
