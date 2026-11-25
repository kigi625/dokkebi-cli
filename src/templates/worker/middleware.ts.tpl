
// ── Phase B — internal DB resolver (build-time injected) ─
//   단일 D1: _internalDb(env),  샤딩: env[GLOBAL || SHARDS[0]] (placeholder 미치환 시 env.DB 폴백)
const _DOKKEBI_INTERNAL_BINDING: string = '__DOKKEBI_PH_INTERNAL_BINDING__' || 'DB';
function _internalDb(env: any): D1Database {
  const b = env && (env as any)[_DOKKEBI_INTERNAL_BINDING];
  if (b) return b as D1Database;
  if (env && env.DB) return env.DB as D1Database; // 내부 바인딩 미설정 시 기본 DB
  throw new Error('[dokkebi] D1 바인딩 "' + _DOKKEBI_INTERNAL_BINDING + '" 이 없습니다. wrangler.toml 의 d1_databases 를 확인하세요.');
}
// @dokkebi-version: 2
// worker/api/_middleware.ts
// Cloudflare Pages 미들웨어 — /api/* 요청 자동 추적
// 모든 API 요청의 method/path/status/duration/IP를 _dokkebi_requests에 기록
// 5xx 응답은 _dokkebi_errors에도 기록

export interface Env {
  DB?: D1Database;
}

// 내부 도깨비 경로는 집계에서 제외 (이중 집계 방지 + 관제 패널 자체 트래픽 제외)
// 주의: includes() 로 판정하면 `/api/foo/_dokkebi/db` 같은 경로가 로그를 회피한다.
//       정확히 일치하거나 하위 경로일 때만 제외한다.
const SKIP_PATHS = [
  '/api/_dokkebi/db', '/api/_dokkebi/handshake', '/api/_dokkebi/log', '/api/_dokkebi/_panel',
  '/_dokkebi/db', '/_dokkebi/handshake', '/_dokkebi/log', '/_dokkebi/_panel',
];
function _isInternalPath(path: string): boolean {
  return SKIP_PATHS.some((p) => path === p || path.startsWith(p + '/'));
}
const LOW_VALUE_PATHS = ['/api/health', '/favicon.ico'];

const _reqDedup = new Map<string, number>();
const _REQ_DEDUP_TTL_MS = 10_000;
const _REQ_DEDUP_MAX = 2048;
function _pruneReqDedup(now: number) {
  if (_reqDedup.size <= _REQ_DEDUP_MAX) return;
  for (const [k, until] of _reqDedup) {
    if (until <= now) _reqDedup.delete(k);
    if (_reqDedup.size <= Math.floor(_REQ_DEDUP_MAX * 0.8)) break;
  }
}
function _shouldWriteReqLog(method: string, path: string, status: number, ip: string, now: number) {
  if (LOW_VALUE_PATHS.some(p => path === p)) return false;
  const key = [method || '-', path || '-', String(Math.floor(Number(status || 0) / 100)), ip || '-'].join('|');
  const until = _reqDedup.get(key);
  if (until && until > now) return false;
  _reqDedup.set(key, now + _REQ_DEDUP_TTL_MS);
  _pruneReqDedup(now);
  return true;
}

async function insertRequest(
  db: D1Database,
  method: string, path: string, status: number, durationMs: number, ip: string
) {
  try {
    const now = Date.now();
    if (!_shouldWriteReqLog(method, path, status, ip, now)) return;
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    await db.prepare(
      `INSERT OR IGNORE INTO "_dokkebi_requests" ("id","method","path","status","duration_ms","ip") VALUES (?,?,?,?,?,?)`
    ).bind(id, method, path, status, durationMs, ip).run();
  } catch { /* 로깅 실패 무시 */ }
}

async function insertError(
  db: D1Database,
  path: string, method: string, status: number, message: string
) {
  try {
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    await db.prepare(
      `INSERT OR IGNORE INTO "_dokkebi_errors" ("id","source","level","message","path","method") VALUES (?,?,?,?,?,?)`
    ).bind(id, 'worker', 'error', message.slice(0, 500), path, method).run();
  } catch { /* 로깅 실패 무시 */ }
}

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env, next } = ctx;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  const isInternal = _isInternalPath(path);

  if (!env.DB || isInternal || method === 'OPTIONS') {
    return next();
  }

  const ip = request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')?.split(',')[0].trim()
    || '';
  const start = Date.now();

  let response: Response;
  try {
    response = await next();
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    const duration = Date.now() - start;
    ctx.waitUntil(insertRequest(_internalDb(env), method, path, 500, duration, ip));
    ctx.waitUntil(insertError(_internalDb(env), path, method, 500, msg));
    throw e;
  }

  const status = response.status;
  const duration = Date.now() - start;

  ctx.waitUntil(insertRequest(_internalDb(env), method, path, status, duration, ip));

  if (status >= 500) {
    ctx.waitUntil(insertError(_internalDb(env), path, method, status, `HTTP ${status}`));
  }

  return response;
};
