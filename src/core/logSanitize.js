/**
 * 로그 문자열 정화 — 터미널 이스케이프/제어문자/개행 주입 방어.
 *
 * 로그 수집 엔드포인트는 인증이 없고 본문이 공격자 제어값이므로,
 * 콘솔에 그대로 출력하면 ANSI/OSC 시퀀스로 운영자 터미널을 조작하거나
 * 개행으로 가짜 로그 라인을 만들 수 있다.
 *
 * @param {unknown} value
 * @param {number} [maxLen]
 * @returns {string}
 */
export function sanitizeLogText(value, maxLen = 2000) {
    let s = String(value ?? '');
    // ANSI CSI / OSC 시퀀스 제거 (터미널 조작)
    s = s.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '');
    s = s.replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '');
    // C0 제어문자 제거 (탭/개행 포함 → 로그 라인 위조 방지)
    s = s.replace(/[\x00-\x1F\x7F]/g, ' ');
    // 연속 공백 정리
    s = s.replace(/[ \t]{2,}/g, ' ').trim();
    const limit = Math.max(0, Math.floor(Number(maxLen) || 0));
    return limit > 0 ? s.slice(0, limit) : s;
}

/**
 * 로그 태그는 콘솔 prefix 에 들어가므로 안전한 문자만 허용한다.
 * @param {unknown} value
 * @param {number} [maxLen]
 */
export function sanitizeLogTag(value, maxLen = 64) {
    const s = String(value ?? '').replace(/[^A-Za-z0-9_.:-]/g, '').slice(0, Math.max(0, maxLen));
    return s || 'log';
}
