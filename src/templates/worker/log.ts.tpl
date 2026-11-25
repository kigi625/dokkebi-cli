
// ── Phase B — internal DB resolver (build-time injected) ─
//   단일 D1: _internalDb(env),  샤딩: env[GLOBAL || SHARDS[0]] (placeholder 미치환 시 env.DB 폴백)
const _DOKKEBI_INTERNAL_BINDING: string = '__DOKKEBI_PH_INTERNAL_BINDING__' || 'DB';
function _internalDb(env: any): D1Database {
  const b = env && (env as any)[_DOKKEBI_INTERNAL_BINDING];
  if (b) return b as D1Database;
  if (env && env.DB) return env.DB as D1Database; // 내부 바인딩 미설정 시 기본 DB
  throw new Error('[dokkebi] D1 바인딩 "' + _DOKKEBI_INTERNAL_BINDING + '" 이 없습니다. wrangler.toml 의 d1_databases 를 확인하세요.');
}
// @dokkebi-version: 4
// worker/api/_dokkebi/log.ts
// Cloudflare Pages Function — WASM VM 로그 수집
// POST /api/_dokkebi/log {level, tag, messages}

export interface Env {
  DB?: D1Database;
}

const _CORS_ORIGINS: string[] = __DOKKEBI_PH_CORS__;
function _corsHeadersFor(req: Request): Record<string, string> {
  const out: Record<string, string> = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin',
  };
  const origin = req.headers.get('Origin') || '';
  if (_CORS_ORIGINS.length === 0 || _CORS_ORIGINS.includes('*')) {
    out['Access-Control-Allow-Origin'] = '*';
  } else if (origin && _CORS_ORIGINS.includes(origin)) {
    out['Access-Control-Allow-Origin'] = origin;
  }
  return out;
}

const LEVEL_ICON: Record<string, string> = {
  error: '✗',
  warn:  '⚠',
  info:  '▸',
  log:   '▸',
  debug: '▸',
};

// ── DoS 방어 — IP 토큰버킷 + 본문 크기 상한 ─────────────────
//   로그 엔드포인트는 인증이 없으므로, 제한이 없으면 무제한 console/D1 쓰기
//   증폭에 악용된다. (SECURITY.md §2.5 의 600/min · 64KB 와 일치)
const _logBuckets = new Map<string, { tokens: number; refillAt: number }>();
const _LOG_BUCKETS_MAX = 5000;
const _LOG_RPM = 600;
const _LOG_BODY_MAX = 64 * 1024;
const _LOG_MAX_MESSAGES = 50;

function _logIp(req: Request): string {
  return req.headers.get('CF-Connecting-IP')
    || (req.headers.get('X-Forwarded-For') || '').split(',')[0].trim()
    || 'unknown';
}
function _logRateLimited(ip: string): boolean {
  const refillMs = Math.max(50, Math.floor(60_000 / _LOG_RPM));
  const now = Date.now();
  let b = _logBuckets.get(ip);
  if (!b) {
    if (_logBuckets.size >= _LOG_BUCKETS_MAX) _logBuckets.clear();
    b = { tokens: _LOG_RPM, refillAt: now };
    _logBuckets.set(ip, b);
  }
  const n = Math.floor((now - b.refillAt) / refillMs);
  if (n > 0) {
    b.tokens = Math.min(_LOG_RPM, b.tokens + n);
    b.refillAt = now;
  }
  if (b.tokens <= 0) return true;
  b.tokens -= 1;
  return false;
}

async function _saveErrorToDb(db: D1Database, tag: string, message: string, stack: string) {
  try {
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const source = tag === 'wasm' ? 'wasm' : 'host';
    await db.prepare(
      `INSERT OR IGNORE INTO "_dokkebi_errors" ("id","source","level","message","stack") VALUES (?,?,?,?,?)`
    ).bind(id, source, 'error', message.slice(0, 1000), stack.slice(0, 2000)).run();
  } catch { /* 에러 로그 저장 실패 무시 */ }
}

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env } = ctx;

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: _corsHeadersFor(request) });
  }
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  try {
    const _ip = _logIp(request);
    if (_logRateLimited(_ip)) {
      return new Response(JSON.stringify({ ok: false, code: 'LOG_RATE_LIMIT', error: '로그 전송량이 너무 많습니다.' }), {
        status: 429, headers: { 'Content-Type': 'application/json', ..._corsHeadersFor(request) },
      });
    }
    const _len = Number(request.headers.get('content-length') || 0);
    if (Number.isFinite(_len) && _len > _LOG_BODY_MAX) {
      return new Response(JSON.stringify({ ok: false, code: 'PAYLOAD_TOO_LARGE', error: '로그 본문이 너무 큽니다.' }), {
        status: 413, headers: { 'Content-Type': 'application/json', ..._corsHeadersFor(request) },
      });
    }

    const parsed: any = await request.json<any>().catch(() => null);
    if (!parsed || typeof parsed !== 'object') {
      return new Response('ok', { headers: { 'Content-Type': 'text/plain', ..._corsHeadersFor(request) } });
    }
    const level = (typeof parsed.level === 'string' && Object.prototype.hasOwnProperty.call(LEVEL_ICON, parsed.level)) ? parsed.level : 'log';
    const tag = (typeof parsed.tag === 'string' ? parsed.tag : 'wasm').slice(0, 64);
    const rawMessages = Array.isArray(parsed.messages) ? parsed.messages.slice(0, _LOG_MAX_MESSAGES) : [];
    const icon = LEVEL_ICON[level] || '▸';
    const prefix = `[dokkebi:${tag}] ${icon}`;

    const line = rawMessages
      .map((m: unknown) => {
        if (m === null || m === undefined) return '';
        if (typeof m === 'object') {
          try { return JSON.stringify(m).slice(0, 2000); } catch { return '[object]'; }
        }
        return String(m).slice(0, 2000);
      })
      .join(' ')
      .slice(0, 8000);

    if (level === 'error') console.error(prefix, line);
    else if (level === 'warn') console.warn(prefix, line);
    else console.log(prefix, line);

    // error 레벨 또는 미처리 예외/프로미스 거부는 _dokkebi_errors 에도 기록
    const isError = level === 'error' || tag === 'uncaught' || tag === 'unhandled-promise';
    let _errDb: D1Database | null = null;
    if (isError) { try { _errDb = _internalDb(env); } catch { _errDb = null; } }
    if (_errDb) {
      const logLines = line.split('\\n');
      const msgLine = logLines[0].trim();
      const stackLines = logLines.slice(1).join('\\n').trim();
      await _saveErrorToDb(_errDb, tag, msgLine, stackLines);
    }
  } catch { /* 무시 */ }

  return new Response('ok', {
    headers: { 'Content-Type': 'text/plain', ..._corsHeadersFor(request) },
  });
};
