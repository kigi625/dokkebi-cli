
// ── Phase B — internal DB resolver (build-time injected) ─
//   단일 D1: _internalDb(env),  샤딩: env[GLOBAL || SHARDS[0]] (placeholder 미치환 시 env.DB 폴백)
const _DOKKEBI_INTERNAL_BINDING: string = '__DOKKEBI_PH_INTERNAL_BINDING__' || 'DB';
function _internalDb(env: any): D1Database {
  const b = env && (env as any)[_DOKKEBI_INTERNAL_BINDING];
  if (b) return b as D1Database;
  if (env && env.DB) return env.DB as D1Database; // 내부 바인딩 미설정 시 기본 DB
  throw new Error('[dokkebi] D1 바인딩 "' + _DOKKEBI_INTERNAL_BINDING + '" 이 없습니다. wrangler.toml 의 d1_databases 를 확인하세요.');
}
// @dokkebi-version: 3
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

// 고유 경로 폭주(예: /api/x/<random>)로 D1 로그 테이블이 무한히 커지는 것을
// 막기 위한 isolate 단위 쓰기 예산. 초과분은 로그만 생략하고 요청은 통과시킨다.
const _REQ_LOG_MAX_PER_MIN = 600;
const _ERR_LOG_MAX_PER_MIN = 60;
let _reqLogTokens = _REQ_LOG_MAX_PER_MIN;
let _reqLogRefillAt = 0;
let _errLogTokens = _ERR_LOG_MAX_PER_MIN;
let _errLogRefillAt = 0;

function _takeBudget(tokens: number, refillAt: number, max: number, now: number): [boolean, number, number] {
  if (refillAt === 0) refillAt = now;
  const refillMs = Math.max(50, Math.floor(60_000 / max));
  const refill = Math.floor((now - refillAt) / refillMs);
  if (refill > 0) {
    tokens = Math.min(max, tokens + refill);
    refillAt = now;
  }
  if (tokens <= 0) return [false, tokens, refillAt];
  return [true, tokens - 1, refillAt];
}
function _takeReqLogToken(now: number): boolean {
  const [ok, tokens, refillAt] = _takeBudget(_reqLogTokens, _reqLogRefillAt, _REQ_LOG_MAX_PER_MIN, now);
  _reqLogTokens = tokens; _reqLogRefillAt = refillAt;
  return ok;
}
function _takeErrLogToken(now: number): boolean {
  const [ok, tokens, refillAt] = _takeBudget(_errLogTokens, _errLogRefillAt, _ERR_LOG_MAX_PER_MIN, now);
  _errLogTokens = tokens; _errLogRefillAt = refillAt;
  return ok;
}

function _pruneReqDedup(now: number) {
  if (_reqDedup.size <= _REQ_DEDUP_MAX) return;
  for (const [k, until] of _reqDedup) {
    if (until <= now) _reqDedup.delete(k);
    if (_reqDedup.size <= Math.floor(_REQ_DEDUP_MAX * 0.8)) break;
  }
  // 만료 항목이 부족해도 상한 아래로 내려가도록 가장 오래된 항목부터 제거.
  while (_reqDedup.size > Math.floor(_REQ_DEDUP_MAX * 0.8)) {
    const oldest = _reqDedup.keys().next().value;
    if (oldest === undefined) break;
    _reqDedup.delete(oldest);
  }
}
function _shouldWriteReqLog(method: string, path: string, status: number, ip: string, now: number) {
  if (LOW_VALUE_PATHS.some(p => path === p)) return false;
  const key = [method || '-', path || '-', String(Math.floor(Number(status || 0) / 100)), ip || '-'].join('|');
  const until = _reqDedup.get(key);
  if (until && until > now) return false;
  if (!_takeReqLogToken(now)) return false;
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
    const now = Date.now();
    if (!_takeErrLogToken(now)) return;
    const id = Math.random().toString(36).slice(2) + now.toString(36);
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
