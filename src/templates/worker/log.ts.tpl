
// ── Phase B — internal DB resolver (build-time injected) ─
//   단일 D1: _internalDb(env),  샤딩: env[GLOBAL || SHARDS[0]] (placeholder 미치환 시 env.DB 폴백)
const _DOKKEBI_INTERNAL_BINDING: string = '__DOKKEBI_PH_INTERNAL_BINDING__' || 'DB';
function _internalDb(env: any): D1Database {
  const b = env && (env as any)[_DOKKEBI_INTERNAL_BINDING];
  return (b as D1Database) || (env && _internalDb(env));
}
// @dokkebi-version: 3
// worker/api/_dokkebi/log.ts
// Cloudflare Pages Function — WASM VM 로그 수집
// POST /api/_dokkebi/log {level, tag, messages}

export interface Env {
  DB?: D1Database;
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

const LEVEL_ICON: Record<string, string> = {
  error: '✗',
  warn:  '⚠',
  info:  '▸',
  log:   '▸',
  debug: '▸',
};

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
    return new Response(null, { status: 204, headers: CORS });
  }
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  try {
    const { level = 'log', tag = 'wasm', messages = [] } = await request.json<any>();
    const icon = LEVEL_ICON[level] || '▸';
    const prefix = `[dokkebi:${tag}] ${icon}`;

    const line = messages
      .map((m: unknown) => (typeof m === 'object' ? JSON.stringify(m) : String(m)))
      .join(' ');

    if (level === 'error') console.error(prefix, line);
    else if (level === 'warn') console.warn(prefix, line);
    else console.log(prefix, line);

    // error 레벨 또는 미처리 예외/프로미스 거부는 _dokkebi_errors 에도 기록
    const isError = level === 'error' || tag === 'uncaught' || tag === 'unhandled-promise';
    if (isError && _internalDb(env)) {
      const logLines = line.split('\\n');
      const msgLine = logLines[0].trim();
      const stackLines = logLines.slice(1).join('\\n').trim();
      await _saveErrorToDb(_internalDb(env), tag, msgLine, stackLines);
    }
  } catch { /* 무시 */ }

  return new Response('ok', {
    headers: { 'Content-Type': 'text/plain', ...CORS },
  });
};
