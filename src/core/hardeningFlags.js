/**
 * Hardening feature flags (PR-1 scaffold).
 *
 * PR-2+: 빌드 emit / Worker 가 여기만 import 하도록 단일 진입점을 둔다.
 * 이 모듈은 아직 빌드 파이프라인에 연결되지 않았다 (동작 변화 없음).
 *
 * 환경 변수 (대소문자 무시, trim):
 *   DOKKEBI_HARDENING=off          — 마스터 스위치: rotate·pow 모두 OFF
 *   DOKKEBI_HARDENING_ROTATE=off  — 빌드별 식별자/봉투 필드 회전 OFF (PR-2+)
 *   DOKKEBI_HARDENING_POW=off      — 경량 PoW OFF (PR-3+)
 *
 * unset 시: rotate·pow 는 ON (디폴트). 마스터만 off 면 전부 OFF.
 */

function _isOff(val) {
    if (val == null || val === '') return false;
    const s = String(val).trim().toLowerCase();
    return s === '0' || s === 'false' || s === 'off' || s === 'no' || s === 'disabled';
}

/**
 * @param {Record<string, string | undefined>} [env]  기본값 process.env (Node). 테스트에서 객체 주입.
 * @returns {{ allEnabled: boolean, rotate: boolean, pow: boolean }}
 */
export function getHardeningFlags(env = typeof process !== 'undefined' && process.env ? process.env : {}) {
    const e = env && typeof env === 'object' ? env : {};
    if (_isOff(e.DOKKEBI_HARDENING)) {
        return { allEnabled: false, rotate: false, pow: false };
    }
    return {
        allEnabled: true,
        rotate: !_isOff(e.DOKKEBI_HARDENING_ROTATE),
        pow: !_isOff(e.DOKKEBI_HARDENING_POW),
    };
}
