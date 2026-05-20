/**
 * iframe embed 허용 목록 — serve.js · deploy.js 에서 동일하게 유지.
 * Toonify(?page=embed), NotoFly, YouTube 등 외부 임베드용.
 */
export const CSP_FRAME_SRC_ALLOWLIST =
  "'self' https://www.youtube.com https://youtube.com https://www.youtube-nocookie.com https://notofly.com https://www.notofly.com https://toonify.app https://www.toonify.app";

/** dev 전용: StackBlitz / WebContainer / 로컬 Pages 프록시 */
export const CSP_FRAME_SRC_DEV_EXTRA =
  ' https://stackblitz.com https://*.stackblitz.com https://*.webcontainer-api.io https://*.local-credentialless.webcontainer-api.io https://*.local-corp.webcontainer-api.io http://localhost:* http://127.0.0.1:*';

export function frameSrcDirective(mode) {
  const hosts =
    mode === 'dev'
      ? `${CSP_FRAME_SRC_ALLOWLIST}${CSP_FRAME_SRC_DEV_EXTRA}`
      : CSP_FRAME_SRC_ALLOWLIST;
  return `frame-src ${hosts}`;
}
