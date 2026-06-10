// @dokkebi-version: 3
// worker/api/_dokkebi/handshake.ts
// Cloudflare Pages Function — ECDH P-256 핸드셰이크 (Ephemeral 키 — Forward Secrecy)
//
// GET  /api/_dokkebi/handshake → Ephemeral 서버 공개키 + keyId 반환
// POST /api/_dokkebi/handshake {clientPubKey, keyId} → D1 세션 생성 + sessionId 반환
//
// Worker Secrets (dok deploy 가 자동 등록):
//   DOKKEBI_SERVER_JWK     — EC P-256 개인키 JWK (JSON 문자열) — 폴백용
//   DOKKEBI_SESSION_SECRET — 32바이트 세션 서명키 (Hex 문자열)
//   __DOKKEBI_BC_KEY__     — 현재 빌드의 암호화 번들 복호화 키 (호환용)
//   __DOKKEBI_BC_KEY_MAP__ — 최근 N개 빌드의 키 맵 JSON: { "<bundleHash 앞 12자>": "<keyHex>" }
//                            무중단 배포(zero-downtime) 지원 — 옛 HTML 사용자에게도
//                            그 빌드의 키로 응답하기 위함. 빌드마다 누적/GC 됨.

import { encBytesToB64 } from './_payloadWire.js';


// ── Phase B — internal DB resolver (build-time injected) ─
//   단일 D1: _internalDb(env),  샤딩: env[GLOBAL || SHARDS[0]] (placeholder 미치환 시 env.DB 폴백)
const _DOKKEBI_INTERNAL_BINDING: string = '__DOKKEBI_PH_INTERNAL_BINDING__' || 'DB';
function _internalDb(env: any): D1Database {
  const b = env && (env as any)[_DOKKEBI_INTERNAL_BINDING];
  return (b as D1Database) || (env && _internalDb(env));
}
export interface Env {
  DB: D1Database;
  DOKKEBI_SERVER_JWK: string;
  DOKKEBI_SESSION_SECRET: string;
  __DOKKEBI_BC_KEY__?: string;
  __DOKKEBI_BC_KEY_MAP__?: string;
  [key: string]: unknown;
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

const EPHEMERAL_TTL_MS = 60_000;
// ── C-1 방어: 인가용 JWT 서명 시크릿은 절대 클라이언트로 내려보내지 않는다. ──
//   HS256 은 대칭키이므로, 시크릿이 브라우저에 도달하면 누구나 임의 role/user_id JWT 를
//   위조해 Authorization Policy 와 JWT 기반 테넌트 격리를 무력화할 수 있다.
//   로그인/토큰 발급은 워커측 `_login`(DB 검증 + 워커 전용 시크릿 서명) 으로만 수행한다.
//   여기서는 번들 복호화 키(__DOKKEBI_BC_KEY__) 만 전달한다.
const CLIENT_HANDSHAKE_SECRET_KEYS = ['__DOKKEBI_BC_KEY__'] as const;

// 무중단 배포 — 클라이언트가 보낸 ?bh=<bundleHash 앞 12자> 와 매칭되는 키를
// __DOKKEBI_BC_KEY_MAP__ JSON 에서 찾는다.
// 반환:
//   { status: 'matched', key }   → bh 매칭 성공
//   { status: 'matched' }        → MAP/직접 키에 이 bh 없음 — BC 없이 핸드셰이크 (평문·스테일 MAP·전파 지연)
//   { status: 'fallback', key }  → bh 미제공 (구버전) + 직접 키
function _pickBcKeyForBundle(env: Env, requestedBh: string): { status: 'matched' | 'fallback' | 'pending' | 'no_key'; key?: string } {
  const direct = (env as any).__DOKKEBI_BC_KEY__;
  const directHash = String((env as any).__DOKKEBI_BC_HASH__ || '').slice(0, 12);
  const rawMap = (env as any).__DOKKEBI_BC_KEY_MAP__;
  const bh12 = String(requestedBh || '').slice(0, 12);
  let parsedMap: Record<string, string> | null = null;
  if (typeof rawMap === 'string' && rawMap) {
    try {
      const parsed = JSON.parse(rawMap);
      if (parsed && typeof parsed === 'object') parsedMap = parsed;
    } catch { /* malformed map */ }
  }
  if (bh12) {
    if (parsedMap && typeof parsedMap[bh12] === 'string' && parsedMap[bh12]) {
      return { status: 'matched', key: parsedMap[bh12] };
    }
    if (typeof direct === 'string' && direct && directHash && directHash === bh12) {
      return { status: 'matched', key: direct };
    }
    // 클라가 들고 있는 번들 해시에 매칭되는 키가 없다 → Worker Secret 전파 지연으로 추정.
    // 잘못된 키로 폴백하지 말고 prop_pending 으로 알려 클라가 백오프 재시도하도록 한다.
    return { status: 'pending' };
  }
  if (typeof direct === 'string' && direct) return { status: 'fallback', key: direct };
  // bh 미제공 + direct 키도 없음 → 키 자체가 등록 전 (첫 deploy 직후 등) → 동일하게 pending 처리.
  return { status: 'pending' };
}

type HandshakeSecretsResult =
  | { status: 'matched' | 'fallback'; secrets: Record<string, string> }
  | { status: 'pending' | 'no_key'; secrets: Record<string, string> };

function pickClientHandshakeSecrets(env: Env, requestedBh?: string): HandshakeSecretsResult {
  const picked: Record<string, string> = {};
  const bc = _pickBcKeyForBundle(env, requestedBh || '');
  if (bc.status === 'matched' || bc.status === 'fallback') {
    if (bc.key) picked.__DOKKEBI_BC_KEY__ = bc.key;
  }
  // 2) 그 외 클라이언트 허용 시크릿이 추가되면 여기서 합친다
  for (const key of CLIENT_HANDSHAKE_SECRET_KEYS) {
    if (key === '__DOKKEBI_BC_KEY__') continue;
    const fromBinding = (env as any)[key];
    if (typeof fromBinding === 'string' && fromBinding) picked[key] = fromBinding;
  }
  return { status: bc.status, secrets: picked };
}

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env } = ctx;
  const method = request.method;

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  const headers = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...CORS };

  try {
    ctx.waitUntil(ensureSecurityTables(_internalDb(env)));

    if (method === 'GET') {
      const ephemeral = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
      );
      const pubRaw = await crypto.subtle.exportKey('raw', ephemeral.publicKey);
      const privJwk = await crypto.subtle.exportKey('jwk', ephemeral.privateKey);
      const keyId = crypto.randomUUID();

      await _internalDb(env).prepare(
        `INSERT INTO _dokkebi_ephemeral_keys (key_id, priv_jwk, created_at) VALUES (?, ?, ?)`
      ).bind(keyId, JSON.stringify(privJwk), Date.now()).run();

      ctx.waitUntil(
        _internalDb(env).prepare(`DELETE FROM _dokkebi_ephemeral_keys WHERE created_at < ?`)
          .bind(Date.now() - EPHEMERAL_TTL_MS).run().catch(() => {})
      );

      const serverPubKey = encBytesToB64(pubRaw);
      return new Response(JSON.stringify({ serverPubKey, keyId }), { headers });
    }

    if (method === 'POST') {
      const body = await request.json<{ clientPubKey?: string; keyId?: string; bh?: string }>();
      const { clientPubKey, keyId } = body;
      // 무중단 배포 — 클라이언트가 들고 있는 bundleHash 앞 12자 (없으면 빈값으로 폴백)
      const requestedBh = (() => {
        try { const u = new URL(request.url); return String(u.searchParams.get('bh') || body?.bh || ''); }
        catch { return String(body?.bh || ''); }
      })();
      if (!clientPubKey) {
        return new Response(JSON.stringify({ error: 'clientPubKey 필드가 없습니다' }), { status: 400, headers });
      }
      if (!keyId) {
        return new Response(JSON.stringify({ error: 'keyId 필드가 없습니다' }), { status: 400, headers });
      }


      const row = await _internalDb(env).prepare(
        `SELECT priv_jwk FROM _dokkebi_ephemeral_keys WHERE key_id = ? AND created_at > ?`
      ).bind(keyId, Date.now() - EPHEMERAL_TTL_MS).first<{ priv_jwk: string }>();

      if (!row) {
        return new Response(JSON.stringify({ error: '키 교환 정보가 만료되었습니다. 페이지를 새로고침하세요.' }), { status: 400, headers });
      }

      // 무중단 배포 (SECURITY.md §6.5 ④) — 클라가 보낸 bh 가 현재 BC_KEY_MAP / direct 키와
      // 매칭되지 않으면 Worker Secret 전파 지연으로 보고, 잘못된 키로 폴백하지 않고
      // prop_pending 으로 즉시 응답한다. 클라이언트 SDK 가 retryAfterMs 만큼 백오프 후 재시도.
      // 200 으로 응답해 브라우저 콘솔에 빨간 네트워크 에러가 노출되지 않도록 한다.
      const handshakeResultEarly = pickClientHandshakeSecrets(env, requestedBh);
      if (handshakeResultEarly.status === 'pending') {
        return new Response(JSON.stringify({
          pending: true,
          code: 'prop_pending',
          retryAfterMs: 5000,
        }), { headers });
      }

      const ephemeralPriv = await crypto.subtle.importKey(
        'jwk', JSON.parse(row.priv_jwk),
        { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
      );
      const clientPubBytes = Uint8Array.from(atob(clientPubKey), (c) => c.charCodeAt(0));
      const clientPub = await crypto.subtle.importKey(
        'raw', clientPubBytes, { name: 'ECDH', namedCurve: 'P-256' }, false, []
      );

      const sharedBits = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: clientPub }, ephemeralPriv, 256
      );
      const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveBits']);

      const encKeyBits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('dokkebi-enc') },
        hkdfKey, 256
      );
      const sigKeyBits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('dokkebi-sig') },
        hkdfKey, 256
      );

      const sessionId = crypto.randomUUID();
      const encKeyB64 = encBytesToB64(encKeyBits);
      const sigKeyB64 = encBytesToB64(sigKeyBits);

      await _internalDb(env).batch([
        _internalDb(env).prepare(`DELETE FROM _dokkebi_ephemeral_keys WHERE key_id = ?`).bind(keyId),
        _internalDb(env).prepare(`INSERT INTO _dokkebi_sessions (session_id, enc_key, sig_key, created_at) VALUES (?, ?, ?, ?)`).bind(sessionId, encKeyB64, sigKeyB64, Date.now()),
      ]);

      // 클라이언트에는 암호화 번들 복호화 키만 전달한다.
      // OPENAI_API_KEY / SUPABASE_SERVICE_KEY 같은 서버 전용 키는 Worker Secret에 남기고
      // 추후 Worker-side operation/proxy에서만 사용해야 한다.
      const responseData: Record<string, string> = { sessionId };
      const envSecrets = handshakeResultEarly.secrets;
      if (Object.keys(envSecrets).length > 0) {
        const encKeyForSecrets = await crypto.subtle.importKey(
          'raw', encKeyBits, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
        );
        const secIv = crypto.getRandomValues(new Uint8Array(12));
        const secPlain = new TextEncoder().encode(JSON.stringify(envSecrets));
        const secEnc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: secIv }, encKeyForSecrets, secPlain);
        responseData.encSecrets = encBytesToB64(secEnc);
        responseData.encSecretsIv = encBytesToB64(secIv);
      }

      new Uint8Array(sharedBits).fill(0);

      return new Response(JSON.stringify(responseData), { headers });
    }

    return new Response('Method Not Allowed', { status: 405, headers });
  } catch (e: unknown) {
    return new Response(JSON.stringify({ error: '핸드셰이크 처리 중 오류가 발생했습니다.' }), { status: 500, headers });
  }
};

let _tablesReady = false;
async function ensureSecurityTables(db: D1Database) {
  if (_tablesReady) return;
  try {
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_ephemeral_keys (key_id TEXT PRIMARY KEY, priv_jwk TEXT NOT NULL, created_at INTEGER NOT NULL)`),
      db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_sessions (session_id TEXT PRIMARY KEY, enc_key TEXT NOT NULL, sig_key TEXT NOT NULL, created_at INTEGER NOT NULL, tenant_json TEXT)`),
      db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_nonces (nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)`),
    ]);
    // 기존 테이블에 tenant_json 컬럼이 없으면 추가 (v5 이전 배포 업그레이드용)
    //   SQLite 는 IF NOT EXISTS 미지원이라 try/catch 로 감쌈.
    try {
      await db.prepare(`ALTER TABLE _dokkebi_sessions ADD COLUMN tenant_json TEXT`).run();
    } catch { /* 컬럼 이미 존재 → 무시 */ }
    _tablesReady = true;
  } catch { /* 이미 존재 시 무시 */ }
}
