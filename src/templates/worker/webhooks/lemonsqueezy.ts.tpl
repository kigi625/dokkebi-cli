
// ── Phase B — internal DB resolver (build-time injected) ─
//   단일 D1: _internalDb(env),  샤딩: env[GLOBAL || SHARDS[0]] (placeholder 미치환 시 env.DB 폴백)
const _DOKKEBI_INTERNAL_BINDING: string = '__DOKKEBI_PH_INTERNAL_BINDING__' || 'DB';
function _internalDb(env: any): D1Database {
  const b = env && (env as any)[_DOKKEBI_INTERNAL_BINDING];
  return (b as D1Database) || (env && _internalDb(env));
}
// worker/api/webhooks/lemonsqueezy.ts
// Lemon Squeezy 웹훅 예제 템플릿 (Cloudflare Pages Functions)
// 경로: POST /api/webhooks/lemonsqueezy
//
// 이 파일은 "참고용 기본 패턴"입니다.
// 1) X-Signature(HMAC-SHA256) 검증
// 2) event_id 기준 중복 처리(idempotency)
// 3) 이벤트별 비즈니스 로직 분기

export interface Env {
  LEMON_SQUEEZY_WEBHOOK_SECRET?: string;
  DB?: D1Database;
}

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256Hex(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return hex(sig);
}

function safeEqualHex(a: string, b: string): boolean {
  const aa = (a || '').toLowerCase();
  const bb = (b || '').toLowerCase();
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i += 1) diff |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  return diff === 0;
}

async function ensureWebhookTable(db: D1Database) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_webhook_events (
    event_id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    event_name TEXT,
    received_at INTEGER NOT NULL
  )`).run();
}

async function markWebhookProcessed(db: D1Database, eventId: string, eventName: string): Promise<boolean> {
  await ensureWebhookTable(db);
  const r = await db
    .prepare(`INSERT OR IGNORE INTO _dokkebi_webhook_events (event_id, provider, event_name, received_at) VALUES (?, 'lemonsqueezy', ?, ?)`)
    .bind(eventId, eventName || '', Date.now())
    .run();
  const changes = (r as any)?.meta?.changes ?? (r as any)?.changes ?? 0;
  return changes > 0;
}

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const secret = env.LEMON_SQUEEZY_WEBHOOK_SECRET || '';
  if (!secret) return new Response('Webhook secret missing', { status: 503 });

  const raw = await request.text();
  const signature = request.headers.get('X-Signature') || '';
  const expected = await hmacSha256Hex(secret, raw);
  if (!signature || !safeEqualHex(signature, expected)) {
    return new Response('Invalid signature', { status: 401 });
  }

  const body = JSON.parse(raw || '{}') as any;
  const eventName = String(body?.meta?.event_name || 'unknown');
  const eventId = String(body?.data?.id || body?.meta?.custom_data?.event_id || '');
  if (!eventId) return new Response('Missing event id', { status: 400 });

  if (_internalDb(env)) {
    const firstSeen = await markWebhookProcessed(_internalDb(env), eventId, eventName);
    if (!firstSeen) return new Response('OK (duplicate)', { status: 200 });
  }

  // TODO: 비즈니스 처리 예시
  // if (eventName === 'order_created') { ... }
  // if (eventName === 'subscription_created') { ... }
  // if (eventName === 'subscription_cancelled') { ... }

  return new Response('OK', { status: 200 });
};
