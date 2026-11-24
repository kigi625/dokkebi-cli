// worker/api/_dokkebi/capability.ts
// ─────────────────────────────────────────────────────────────
// Signed Unlock Token — **서버측 검증 헬퍼**
//
// 브라우저(WASM)의 자동 라우트 가드(`security.capabilities.features[*].routes`)는
// 번들 패치로 우회될 수 있다. 따라서 고비용/유료/관리 작업을 실제로 수행하는
// `worker/api/**` 라우트에서는 이 함수로 토큰을 **재검증**해야 한다.
//
// 사용 예 (worker/api/ai/image.ts):
//   import { verifyCapability } from '../_dokkebi/capability.js';
//
//   export const onRequestPost = async (ctx) => {
//     const cap = await verifyCapability(ctx.request, ctx.env, 'image.generate', {
//       stateHash: await sha256Hex(ctx.request.headers.get('x-prompt-hash') || ''),
//     });
//     if (!cap.ok) {
//       return new Response(JSON.stringify({ ok: false, code: cap.code }), { status: 403 });
//     }
//     // cap.payload.sub / cap.payload.stateHash 를 실제 실행 입력에 바인딩할 것
//   };
//
// 토큰 전달:
//   X-Dokkebi-Capability: <token>        (권장)
//   Authorization: Capability <token>
// ─────────────────────────────────────────────────────────────

export interface CapabilityEnv {
  DOKKEBI_CAPABILITY_SECRET?: string;
  [key: string]: unknown;
}

export interface CapabilityVerifyResult {
  ok: boolean;
  code?: string;
  reason?: string;
  payload?: Record<string, any>;
}

function _cap_b64urlToBytes(s: string): Uint8Array | null {
  try {
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
    const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
    if (typeof atob !== 'undefined') {
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    return null;
  } catch {
    return null;
  }
}

function _cap_readToken(req: Request): string {
  const h = req.headers.get('x-dokkebi-capability') || '';
  if (h.trim()) return h.trim();
  const auth = req.headers.get('authorization') || '';
  const m = /^Capability\s+(.+)$/i.exec(auth.trim());
  return m ? m[1].trim() : '';
}

/**
 * capability 토큰을 검증한다.
 *
 * @param req 요청
 * @param env Worker env (DOKKEBI_CAPABILITY_SECRET 필요)
 * @param feature 요구 기능 이름 (발급된 `feature` 와 정확히 일치해야 함)
 * @param opts.stateHash 를 넘기면 토큰의 stateHash 와 일치해야 한다 (입력 바인딩)
 */
export async function verifyCapability(
  req: Request,
  env: CapabilityEnv,
  feature: string,
  opts: { stateHash?: string } = {},
): Promise<CapabilityVerifyResult> {
  const secret = String(env?.DOKKEBI_CAPABILITY_SECRET || '');
  if (!secret) return { ok: false, code: 'CAPABILITY_SECRET_MISSING', reason: 'DOKKEBI_CAPABILITY_SECRET 미설정' };

  const token = _cap_readToken(req);
  if (!token) return { ok: false, code: 'CAPABILITY_MISSING', reason: 'capability 토큰이 없습니다.' };

  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, code: 'CAPABILITY_MALFORMED', reason: '토큰 형식이 올바르지 않습니다.' };
  const [h64, p64, sigB64] = parts;

  let header: any, payload: any;
  try {
    const hb = _cap_b64urlToBytes(h64);
    const pb = _cap_b64urlToBytes(p64);
    if (!hb || !pb) return { ok: false, code: 'CAPABILITY_MALFORMED' };
    header = JSON.parse(new TextDecoder().decode(hb));
    payload = JSON.parse(new TextDecoder().decode(pb));
  } catch {
    return { ok: false, code: 'CAPABILITY_MALFORMED', reason: '토큰을 파싱할 수 없습니다.' };
  }
  if (!header || header.typ !== 'DOKKEBI-CAP' || header.alg !== 'HS256') {
    return { ok: false, code: 'CAPABILITY_ALG', reason: '지원하지 않는 토큰 형식입니다.' };
  }

  const sig = _cap_b64urlToBytes(sigB64);
  if (!sig) return { ok: false, code: 'CAPABILITY_MALFORMED' };
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'],
  );
  const data = new TextEncoder().encode(h64 + '.' + p64);
  const sigOk = await crypto.subtle.verify('HMAC', key, sig, data).catch(() => false);
  if (!sigOk) return { ok: false, code: 'CAPABILITY_BAD_SIGNATURE' };

  if (typeof payload?.exp !== 'number' || payload.exp < Date.now()) {
    return { ok: false, code: 'CAPABILITY_EXPIRED' };
  }
  if (String(payload?.feature || '') !== String(feature)) {
    return { ok: false, code: 'CAPABILITY_FEATURE_MISMATCH' };
  }
  if (opts.stateHash !== undefined) {
    if (typeof payload?.stateHash !== 'string' || payload.stateHash !== String(opts.stateHash)) {
      return { ok: false, code: 'CAPABILITY_STATE_MISMATCH' };
    }
  }

  return { ok: true, payload: payload as Record<string, any> };
}
