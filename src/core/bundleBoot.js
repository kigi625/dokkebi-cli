/**
 * 번들 복호화 키( BC_KEY ) HTML 주입용 래핑 — Node(dok serve) 와 동일 알고리즘을
 * Worker(opaqueHandle / workerRootMiddleware) 가 Web Crypto 로 재현한다.
 *
 * HKDF(salt=nonce, ikm=HMAC-SHA256(secret, nonce), info="dokkebi-bc-wrap-v1|"+h12) → AES-256 KEK
 * KEK 로 32바이트 BC_KEY(hex 문자열의 바이트가 아니라 raw 16바이트... 실제는 hex 디코드) 를 AES-GCM 래핑.
 */

import { createCipheriv, createHmac, hkdfSync, randomBytes } from 'crypto';

/** @param {Buffer} buf */
export function b64urlFromBuffer(buf) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/**
 * @param {string} bootSecret - DOKKEBI_BUNDLE_BOOT_SECRET
 * @param {string} bcKeyHex    - __DOKKEBI_BC_KEY__ (64 hex)
 * @param {string} bundleHash12 - backend-bundle.sha256 앞 12자
 * @returns {{ v: number, n: string, t: string, w: string } | null}
 */
export function buildBundleBootPayload(bootSecret, bcKeyHex, bundleHash12) {
    const sec = typeof bootSecret === 'string' ? bootSecret : '';
    const hex = typeof bcKeyHex === 'string' ? bcKeyHex.replace(/\s/g, '') : '';
    const h12 = typeof bundleHash12 === 'string' ? bundleHash12.slice(0, 12) : '';
    if (!sec || !hex || hex.length < 64 || !h12) return null;

    const keyBytes = Buffer.from(hex.slice(0, 64), 'hex');
    if (keyBytes.length !== 32) return null;

    const nonce = randomBytes(16);
    const token = createHmac('sha256', Buffer.from(sec, 'utf-8')).update(nonce).digest();
    const info = Buffer.concat([Buffer.from('dokkebi-bc-wrap-v1|', 'utf8'), Buffer.from(h12, 'utf8')]);
    const kek = Buffer.from(hkdfSync('sha256', token, nonce, info, 32));

    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', kek, iv);
    const enc = Buffer.concat([cipher.update(keyBytes), cipher.final()]);
    const tag = cipher.getAuthTag();
    const w = Buffer.concat([iv, enc, tag]);

    return {
        v: 1,
        n: b64urlFromBuffer(nonce),
        t: b64urlFromBuffer(token),
        w: b64urlFromBuffer(w),
    };
}

/**
 * @param {string} html
 * @param {{ v: number, n: string, t: string, w: string }} payload
 * @returns {string}
 */
export function injectBundleBootScript(html, payload) {
    const json = JSON.stringify(payload).replace(/</g, '\\u003c');
    const tag = `<script>window.__DOKKEBI_BOOT__=${json};</script>`;
    if (/<head[^>]*>/i.test(html)) {
        return html.replace(/<head([^>]*)>/i, `<head$1>${tag}`);
    }
    return tag + html;
}
