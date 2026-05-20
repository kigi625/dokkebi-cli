/**
 * 부트스트랩 콘솔 attribution — Ed25519 sealed payload.
 *
 * `src/assets/dokkebi-attribution.seal.json` 이 없거나 서명이 맞지 않으면 빌드(dev/serve 포함) 즉시 실패.
 * seal 재생성: 로컬에만 두는 signer (`tools/attribution-seal-sign.mjs`) + 비밀키 — 둘 다 .gitignore.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import url from 'url';

const __filename = url.fileURLToPath(import.meta.url);
const PKG_ROOT = path.resolve(path.dirname(__filename), '..');
export const DEFAULT_ATTRIBUTION_SEAL_PATH = path.join(PKG_ROOT, 'assets', 'dokkebi-attribution.seal.json');

/** @param {unknown} obj */
export function canonicalStringifyPayloadForSeal(obj) {
    if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
    if (Array.isArray(obj)) return '[' + obj.map((item) => canonicalStringifyPayloadForSeal(item)).join(',') + ']';
    const keys = Object.keys(obj).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalStringifyPayloadForSeal(obj[k])).join(',') + '}';
}

const ATTRIBUTION_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAaAjBBb6d3rSvM0awJ9AR0LDteLj0A/eqmp2Brml0bbQ=
-----END PUBLIC KEY-----
`;

/** @typedef {{ brandLeft: string, brandRight: string, subtitle: string, creator: string, contactLabel: string, contactUrl: string, licenseLine: string }} AttributionSealPayload */

/**
 * @param {string} [sealPath]
 * @returns {AttributionSealPayload}
 */
export function loadAttributionSealPayloadSync(sealPath = DEFAULT_ATTRIBUTION_SEAL_PATH) {
    if (!fs.existsSync(sealPath)) {
        throw new Error(
            `[dokkebi] attribution seal 없음: ${sealPath}\n`,
        );
    }
    let parsed;
    try {
        parsed = JSON.parse(fs.readFileSync(sealPath, 'utf8'));
    } catch {
        throw new Error(`[dokkebi] attribution seal JSON 파싱 실패: ${sealPath}`);
    }
    if (!parsed || parsed.v !== 1 || typeof parsed.sig_b64 !== 'string'
        || !parsed.payload || typeof parsed.payload !== 'object') {
        throw new Error(`[dokkebi] attribution seal 형식 오류: ${sealPath}`);
    }
    const msg = canonicalStringifyPayloadForSeal(parsed.payload);
    let sig;
    try {
        sig = Buffer.from(parsed.sig_b64, 'base64');
    } catch {
        throw new Error('[dokkebi] attribution seal 서명 디코드 실패');
    }
    const pubkey = crypto.createPublicKey(ATTRIBUTION_PUBLIC_KEY_PEM);
    const ok = crypto.verify(null, Buffer.from(msg, 'utf8'), pubkey, sig);
    if (!ok) {
        throw new Error('[dokkebi] attribution seal 서명 검증 실패 (변조 또는 잘못된 키)');
    }

    /** @type {AttributionSealPayload} */
    const p = parsed.payload;
    const required = ['brandLeft', 'brandRight', 'subtitle', 'creator', 'contactLabel', 'contactUrl', 'licenseLine'];
    for (const k of required) {
        if (typeof p[k] !== 'string') {
            throw new Error(`[dokkebi] attribution seal payload.${k} 문자열 필요`);
        }
    }
    return p;
}

/**
 * `bootstrap.js.tpl` placeholder 치환 목록 (console 배너).
 * @returns {Array<{ find: string, replace: string }>}
 */
export function getAttributionSealTemplateReplacements(sealPath) {
    const p = loadAttributionSealPayloadSync(sealPath);
    return [
        { find: '__DOKKEBI_PH_ATTR_BRAND_L__', replace: JSON.stringify(p.brandLeft) },
        { find: '__DOKKEBI_PH_ATTR_BRAND_R__', replace: JSON.stringify(p.brandRight) },
        { find: '__DOKKEBI_PH_ATTR_SUBTITLE__', replace: JSON.stringify(p.subtitle) },
        { find: '__DOKKEBI_PH_ATTR_CREATOR__', replace: JSON.stringify(p.creator) },
        { find: '__DOKKEBI_PH_ATTR_CONTACT_L__', replace: JSON.stringify(p.contactLabel) },
        { find: '__DOKKEBI_PH_ATTR_CONTACT_URL__', replace: JSON.stringify(p.contactUrl) },
        { find: '__DOKKEBI_PH_ATTR_LICENSE__', replace: JSON.stringify(p.licenseLine) },
    ];
}
