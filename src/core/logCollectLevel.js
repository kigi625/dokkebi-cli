/**
 * 원격 로그 수집(/api/_dokkebi/log) 최소 레벨 — Spring Boot root logger 와 유사:
 * 지정한 레벨 이상(심각도 동일·상위)만 전송.
 *
 * 순위: debug < log < info < warn < error
 */

/** @type {readonly string[]} */
export const LOG_LEVEL_ORDER = ['debug', 'log', 'info', 'warn', 'error'];

const LEVEL_RANK = Object.fromEntries(LOG_LEVEL_ORDER.map((l, i) => [l, i]));

/**
 * @param {unknown} raw
 * @returns {'debug'|'log'|'info'|'warn'|'error'}
 */
export function normalizeLogCollectLevel(raw) {
    const s = String(raw || 'error').trim().toLowerCase();
    if (LEVEL_RANK[s] !== undefined) return /** @type {any} */ (s);
    return 'error';
}

/**
 * @param {string} level
 */
export function logLevelRank(level) {
    const k = String(level || '').toLowerCase();
    const r = LEVEL_RANK[k];
    return r === undefined ? -1 : r;
}

/**
 * 원격 전송 여부: entryLevel 의 심각도가 minLevel 이상이면 true
 * @param {string} minLevel — normalize 된 값
 * @param {string} entryLevel — console / _sendLog 에 넘긴 level
 */
export function shouldCollectRemoteLog(minLevel, entryLevel) {
    const minR = logLevelRank(minLevel);
    const entR = logLevelRank(entryLevel);
    if (entR < 0) return minR <= 0;
    return entR >= minR;
}

/**
 * 빌드 시 번들에서 제거할 console 메서드 이름 — minLevel 미만(더 낮은 심각도)만
 * @param {string} minLevel — normalized
 * @returns {string[]}
 */
export function consoleMethodsToStripFromBundle(minLevel) {
    const idx = logLevelRank(minLevel);
    if (idx < 0) return [...LOG_LEVEL_ORDER];
    return LOG_LEVEL_ORDER.slice(0, idx);
}
