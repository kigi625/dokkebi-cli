/**
 * 클라이언트 IP 해석 — 프록시 헤더 신뢰 정책
 *
 * `X-Forwarded-For` / `CF-Connecting-IP` 는 **클라이언트가 임의로 보낼 수 있는 헤더**다.
 * `dok serve` / `dok dev` 는 0.0.0.0 에 바인딩되므로, 이 헤더를 기본적으로 신뢰하면
 *   - IP 기반 레이트리밋 우회
 *   - `DOKKEBI_PANEL_ALLOWED_IPS` (관제 패널 IP allowlist) 우회
 *   - 감사 로그 IP 위조
 * 가 가능하다.
 *
 * 따라서 기본값은 **소켓 피어 주소**만 사용하고, 신뢰할 수 있는 리버스 프록시
 * (Cloudflare Tunnel, nginx 등) 뒤에 있을 때만 `DOKKEBI_TRUST_PROXY=1` 로 헤더를 신뢰한다.
 */

function _firstHeaderValue(v) {
    if (Array.isArray(v)) v = v[0];
    return typeof v === 'string' ? v.split(',')[0].trim() : '';
}

export function trustProxyFromEnv(env = process.env) {
    const v = String(env?.DOKKEBI_TRUST_PROXY ?? env?.TRUST_PROXY ?? '').toLowerCase();
    return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

/**
 * @param {import('http').IncomingMessage} req
 * @param {{ trustProxy?: boolean }} [opts]
 * @returns {string}
 */
export function resolveClientIp(req, opts = {}) {
    const socketIp = req?.socket?.remoteAddress || '';
    if (opts.trustProxy !== true) return socketIp || 'unknown';
    const cf = _firstHeaderValue(req?.headers?.['cf-connecting-ip']);
    if (cf) return cf;
    const xff = _firstHeaderValue(req?.headers?.['x-forwarded-for']);
    if (xff) return xff;
    return socketIp || 'unknown';
}

export function isLoopbackIp(ip) {
    const s = String(ip || '').replace(/^::ffff:/, '');
    return s === '::1' || s === '127.0.0.1' || s.startsWith('127.');
}
