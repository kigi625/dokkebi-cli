
// ── Phase B — internal DB resolver (build-time injected) ─
//   단일 D1: _internalDb(env),  샤딩: env[GLOBAL || SHARDS[0]] (placeholder 미치환 시 env.DB 폴백)
const _DOKKEBI_INTERNAL_BINDING: string = '__DOKKEBI_PH_INTERNAL_BINDING__' || 'DB';
function _internalDb(env: any): D1Database {
  const b = env && (env as any)[_DOKKEBI_INTERNAL_BINDING];
  return (b as D1Database) || (env && _internalDb(env));
}
// @dokkebi-version: 4
// worker/api/_dokkebi/_panel.ts
// Cloudflare Pages Function — 관제 어드민 API
// GET  /_dokkebi/_panel          → 대시보드 HTML
// POST /_dokkebi/_panel/auth     → 비밀번호 인증 → 토큰 발급
// GET  /_dokkebi/_panel/api/*    → 통계/에러/보안 데이터 (토큰 필수)
// GET  /_dokkebi/_panel/api/security-info → 보안 구성/커버리지 (Phase 2-⑧)
// GET  /_dokkebi/_panel/api/adl/* → 능동 방어(ADL) 상태/블랙리스트 (Phase 3-C)

// Phase 1-③ · Phase 2-⑧ 빌드 시 embed 된 보안 구성 요약.
const _SECURITY_SUMMARY: any = "__DOKKEBI_PLACEHOLDER_SUMMARY__";
const _PANEL_IP_GUARD_ENABLED = false;
//
// 환경변수:
//   DOKKEBI_ADMIN_PASSWORD  — Cloudflare Worker 시크릿 설정 필요
//   DOKKEBI_PANEL_ALLOWED_IPS — 선택. 쉼표 구분 IP/CIDR allowlist

export interface Env {
  DOKKEBI_ADMIN_PASSWORD?: string;
  DOKKEBI_PANEL_ALLOWED_IPS?: string;
  DOKKEBI_ADMIN_ALLOWED_IPS?: string;
  DB?: D1Database;           // D1 사용 시
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const _AUTH_ATTEMPTS = new Map<string, { count: number; resetAt: number; blockUntil: number }>();
const _AUTH_WINDOW_MS = 5 * 60_000;
const _AUTH_BLOCK_MS = 15 * 60_000;
const _AUTH_MAX_FAILS = 8;
function _authIp(req: Request): string {
  const xf = req.headers.get('X-Forwarded-For') || '';
  return req.headers.get('CF-Connecting-IP') || xf.split(',')[0].trim() || 'unknown';
}
function _normalizeIp(ip: string): string {
  return String(ip || '').trim().replace(/^::ffff:/, '');
}
function _ipv4ToInt(ip: string): number | null {
  const parts = _normalizeIp(ip).split('.');
  if (parts.length !== 4) return null;
  let out = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    out = (out << 8) + n;
  }
  return out >>> 0;
}
function _ipRuleMatch(ip: string, rule: string): boolean {
  const target = _normalizeIp(ip);
  const r = _normalizeIp(rule);
  if (!r) return false;
  if (r === '*' || r === target) return true;
  const slash = r.indexOf('/');
  if (slash < 0) return false;
  const base = r.slice(0, slash);
  const bits = Number(r.slice(slash + 1));
  const baseInt = _ipv4ToInt(base);
  const ipInt = _ipv4ToInt(target);
  if (baseInt === null || ipInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}
function _panelIpAllowed(req: Request, env: Env): { ok: boolean; ip: string } {
  const ip = _authIp(req);
  if (!_PANEL_IP_GUARD_ENABLED) return { ok: true, ip };
  const raw = String(env.DOKKEBI_PANEL_ALLOWED_IPS || env.DOKKEBI_ADMIN_ALLOWED_IPS || '').trim();
  if (!raw) return { ok: true, ip };
  const rules = raw.split(',').map(s => s.trim()).filter(Boolean);
  return { ok: rules.some(rule => _ipRuleMatch(ip, rule)), ip };
}
function _authAllow(ip: string): boolean {
  const now = Date.now();
  const cur = _AUTH_ATTEMPTS.get(ip);
  if (!cur) return true;
  if (cur.blockUntil > now) return false;
  if (cur.resetAt <= now) { _AUTH_ATTEMPTS.delete(ip); return true; }
  return true;
}
function _authFail(ip: string) {
  const now = Date.now();
  const cur = _AUTH_ATTEMPTS.get(ip);
  if (!cur || cur.resetAt <= now) {
    _AUTH_ATTEMPTS.set(ip, { count: 1, resetAt: now + _AUTH_WINDOW_MS, blockUntil: 0 });
    return;
  }
  cur.count += 1;
  if (cur.count >= _AUTH_MAX_FAILS) {
    cur.blockUntil = now + _AUTH_BLOCK_MS;
    cur.count = 0;
    cur.resetAt = now + _AUTH_WINDOW_MS;
  }
}
function _authSuccess(ip: string) {
  _AUTH_ATTEMPTS.delete(ip);
}

function randHex(n: number) {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function hmacHex(key: string, msg: string) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(key),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function createToken(password: string) {
  const exp = Date.now() + 4 * 3600_000;
  const nonce = randHex(16);
  const payload = `${exp}:${nonce}`;
  const sig = await hmacHex(password + ':admin:token', payload);
  return `${payload}.${sig}`;
}

async function verifyToken(token: string, password: string): Promise<boolean> {
  if (!token || !token.includes('.')) return false;
  const lastDot = token.lastIndexOf('.');
  const payload = token.slice(0, lastDot);
  const sig = token.slice(lastDot + 1);
  if (!payload || !sig) return false;
  const expected = await hmacHex(password + ':admin:token', payload);
  if (sig !== expected) return false;
  const exp = parseInt(payload.split(':')[0], 10);
  return !isNaN(exp) && Date.now() < exp;
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS },
  });
}

// ── D1 쿼리 헬퍼 ──────────────────────────────────────────────
async function q(db: D1Database, sql: string, params: unknown[] = []) {
  try {
    const r = await db.prepare(sql).bind(...params).all();
    return { rows: r.results || [] };
  } catch { return { rows: [] }; }
}

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env } = ctx;
  const url     = new URL(request.url);
  const urlPath = url.pathname;
  const adminPassword = env.DOKKEBI_ADMIN_PASSWORD || '';

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  const ipGate = _panelIpAllowed(request, env);
  if (!ipGate.ok) {
    if (_internalDb(env)) {
      ctx.waitUntil(_internalDb(env).prepare(`INSERT OR IGNORE INTO "_dokkebi_security" ("id","type","ip","path","detail") VALUES (?,?,?,?,?)`)
        .bind(crypto.randomUUID(), 'panel_ip_block', ipGate.ip, urlPath, 'IP not in DOKKEBI_PANEL_ALLOWED_IPS').run().catch(() => {}));
    }
    return json({ error: '접근이 허용되지 않은 IP 입니다.' }, 403);
  }

  // 어드민 비밀번호 미설정 안내
  if (!adminPassword) {
    return new Response(
      '<!DOCTYPE html><html><body style="font-family:monospace;padding:40px;background:#0d1117;color:#e6edf3">'
      + '<h2>⚙️ 도깨비 관제 어드민</h2>'
      + '<p>관제 어드민을 활성화하려면 Cloudflare Worker 시크릿을 설정하세요:</p>'
      + '<pre style="background:#161b22;padding:16px;border-radius:8px">wrangler secret put DOKKEBI_ADMIN_PASSWORD</pre>'
      + '</body></html>',
      { status: 503, headers: { 'Content-Type': 'text/html' } }
    );
  }

  // ── 어드민 HTML ────────────────────────────────────────────
  if ((urlPath.endsWith('/_dokkebi/_panel') || urlPath.endsWith('/_dokkebi/_panel/')) && request.method === 'GET') {
    // 서버리스 모드에서는 클라이언트 사이드 어드민 HTML을 반환
    // (동일한 /_dokkebi/_panel/api/* 엔드포인트를 사용)
    return new Response(ADMIN_HTML.replaceAll('__PROJECT__', '__DOKKEBI_PLACEHOLDER_PROJECT__').replaceAll('__MODE__', 'serverless'), {
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }

  // ── 인증 ────────────────────────────────────────────────────
  if (urlPath.endsWith('/_dokkebi/_panel/auth') && request.method === 'POST') {
    const ip = _authIp(request);
    if (!_authAllow(ip)) return json({ error: '요청이 너무 많습니다. 잠시 후 다시 시도하세요.' }, 429);
    const { password } = await request.json<any>().catch(() => ({} as any));
    if (!password || password !== adminPassword) {
      _authFail(ip);
      return json({ error: '비밀번호가 올바르지 않습니다.' }, 401);
    }
    _authSuccess(ip);
    const token = await createToken(adminPassword);
    return json({ token, expires: Date.now() + 4 * 3600_000 });
  }

  // ── API (토큰 필수) ────────────────────────────────────────
  if (urlPath.includes('/_dokkebi/_panel/api/')) {
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!await verifyToken(token, adminPassword)) {
      return json({ error: '인증이 필요합니다.' }, 401);
    }

    const db  = env.DB;
    if (!db) return json({ error: 'D1 DB가 연결되지 않았습니다.' }, 503);

    const apiSub = urlPath.slice('/_dokkebi/_panel/api/'.length);
    const qs     = url.searchParams;
    const limit  = Math.min(Number(qs.get('limit') || 50), 200);
    const offset = Number(qs.get('offset') || 0);

    if (apiSub === 'overview') {
      const [err, sec, req24, act] = await Promise.all([
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_errors" WHERE ts >= datetime('now','-24 hours')`),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_security" WHERE ts >= datetime('now','-24 hours')`),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_requests" WHERE ts >= datetime('now','-24 hours')`),
        q(db, `SELECT COUNT(DISTINCT ip) as cnt FROM "_dokkebi_requests" WHERE ts >= datetime('now','-5 minutes')`),
      ]);
      const trend = await q(db,
        `SELECT date(ts) as day, COUNT(*) as cnt FROM "_dokkebi_requests"
         WHERE ts >= datetime('now','-7 days') GROUP BY day ORDER BY day`);
      return json({
        activeUsers:  act.rows[0]?.cnt ?? 0,
        errors24h:    err.rows[0]?.cnt ?? 0,
        security24h:  sec.rows[0]?.cnt ?? 0,
        requests24h:  req24.rows[0]?.cnt ?? 0,
        trend:        trend.rows,
        mode: 'serverless',
      });
    }

    if (apiSub === 'errors') {
      const lv = qs.get('level') || ''; const search = qs.get('search') || '';
      const from = qs.get('from') || ''; const to = qs.get('to') || '';
      const conds: string[] = []; const params: any[] = [];
      if (lv) { conds.push('level = ?'); params.push(lv); }
      if (search) { conds.push('(message LIKE ? OR path LIKE ?)'); params.push('%'+search+'%', '%'+search+'%'); }
      if (from) { conds.push("ts >= ?"); params.push(from); }
      if (to) { conds.push("ts <= ?"); params.push(to); }
      const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
      const [rows, total] = await Promise.all([
        q(db, `SELECT id,ts,source,level,message,stack,path,method FROM "_dokkebi_errors" ${where} ORDER BY ts DESC LIMIT ? OFFSET ?`, [...params, limit, offset]),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_errors" ${where}`, params),
      ]);
      return json({ rows: rows.rows, total: total.rows[0]?.cnt ?? 0 });
    }

    if (apiSub === 'security') {
      const ip = qs.get('ip') || ''; const type = qs.get('type') || '';
      const from = qs.get('from') || ''; const to = qs.get('to') || '';
      const secConds: string[] = []; const secParams: any[] = [];
      const reqConds: string[] = []; const reqParams: any[] = [];
      if (ip) { secConds.push('ip LIKE ?'); secParams.push('%'+ip+'%'); reqConds.push('ip LIKE ?'); reqParams.push('%'+ip+'%'); }
      if (type) {
        if (type === 'request') secConds.push('1 = 0');
        else { secConds.push('type = ?'); secParams.push(type); reqConds.push('1 = 0'); }
      }
      if (from) { secConds.push("ts >= ?"); secParams.push(from); reqConds.push("ts >= ?"); reqParams.push(from); }
      if (to) { secConds.push("ts <= ?"); secParams.push(to); reqConds.push("ts <= ?"); reqParams.push(to); }
      const secWhere = secConds.length ? 'WHERE ' + secConds.join(' AND ') : '';
      const reqWhere = reqConds.length ? 'WHERE ' + reqConds.join(' AND ') : '';
      const [rows, secTotal, reqTotal] = await Promise.all([
        q(db, `SELECT id,ts,type,ip,path,detail FROM (
          SELECT id,ts,type,ip,path,detail FROM "_dokkebi_security" ${secWhere}
          UNION ALL
          SELECT id,ts,'request' as type,ip,path,(method || ' ' || status || ' ' || duration_ms || 'ms') as detail FROM "_dokkebi_requests" ${reqWhere}
        ) ORDER BY ts DESC LIMIT ? OFFSET ?`, [...secParams, ...reqParams, limit, offset]),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_security" ${secWhere}`, secParams),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_requests" ${reqWhere}`, reqParams),
      ]);
      return json({ rows: rows.rows, total: Number(secTotal.rows[0]?.cnt ?? 0) + Number(reqTotal.rows[0]?.cnt ?? 0) });
    }

    if (apiSub === 'requests') {
      const ip = qs.get('ip') || '';
      const from = qs.get('from') || ''; const to = qs.get('to') || '';
      const conds: string[] = []; const params: any[] = [];
      if (ip) { conds.push('ip LIKE ?'); params.push('%'+ip+'%'); }
      if (from) { conds.push("ts >= ?"); params.push(from); }
      if (to) { conds.push("ts <= ?"); params.push(to); }
      const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
      const [rows, total] = await Promise.all([
        q(db, `SELECT id,ts,method,path,status,duration_ms,ip FROM "_dokkebi_requests" ${where} ORDER BY ts DESC LIMIT ? OFFSET ?`, [...params, limit, offset]),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_requests" ${where}`, params),
      ]);
      return json({ rows: rows.rows, total: total.rows[0]?.cnt ?? 0 });
    }

    if (apiSub === 'errors/clear' && request.method === 'POST') {
      await db.prepare(`DELETE FROM "_dokkebi_errors"`).run();
      return json({ ok: true });
    }
    if (apiSub === 'security/clear' && request.method === 'POST') {
      await db.prepare(`DELETE FROM "_dokkebi_security"`).run();
      await db.prepare(`DELETE FROM "_dokkebi_requests"`).run();
      return json({ ok: true });
    }
    if (apiSub === 'requests/clear' && request.method === 'POST') {
      await db.prepare(`DELETE FROM "_dokkebi_requests"`).run();
      return json({ ok: true });
    }

    // Phase 2-⑧ 보안 커버리지 + 빌드 서명 정보
    if (apiSub === 'security-info') {
      return json(_SECURITY_SUMMARY);
    }

    // Phase 3-C — ADL 상태 (블랙리스트 / 분석 last_run / 카운트)
    if (apiSub === 'adl/status') {
      const now = Date.now();
      const [bl, sus, lr, byKind, recentDetect, recentBlock] = await Promise.all([
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_blacklist" WHERE expires_at > ?`, [now]),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_adl_suspicion" WHERE expires_at > ?`, [now]),
        q(db, `SELECT value FROM "_dokkebi_adl_state" WHERE key = 'last_run' LIMIT 1`),
        q(db, `SELECT kind, COUNT(*) as cnt FROM "_dokkebi_blacklist" WHERE expires_at > ? GROUP BY kind`, [now]),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_security" WHERE type='adl_detect' AND ts >= datetime('now','-24 hours')`),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_security" WHERE type='adl_block'  AND ts >= datetime('now','-24 hours')`),
      ]);
      const lastRun = Number(lr.rows[0]?.value || 0);
      const cfg = (_SECURITY_SUMMARY && _SECURITY_SUMMARY.activeDefense) || { enabled: false };
      return json({
        config: cfg,
        blacklistCount: bl.rows[0]?.cnt ?? 0,
        suspicionCount: sus.rows[0]?.cnt ?? 0,
        byKind: byKind.rows,
        lastRun,
        lastRunAgoSec: lastRun ? Math.floor((now - lastRun) / 1000) : null,
        detect24h: recentDetect.rows[0]?.cnt ?? 0,
        block24h: recentBlock.rows[0]?.cnt ?? 0,
      });
    }
    if (apiSub === 'adl/blacklist') {
      const now = Date.now();
      const [rows, total] = await Promise.all([
        q(db, `SELECT key,kind,reason,score,expires_at,created_at FROM "_dokkebi_blacklist" WHERE expires_at > ? ORDER BY created_at DESC LIMIT ? OFFSET ?`, [now, limit, offset]),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_blacklist" WHERE expires_at > ?`, [now]),
      ]);
      return json({ rows: rows.rows, total: total.rows[0]?.cnt ?? 0 });
    }
    if (apiSub === 'adl/suspicion') {
      const now = Date.now();
      const [rows, total] = await Promise.all([
        q(db, `SELECT key,kind,reason,score,expires_at,created_at FROM "_dokkebi_adl_suspicion" WHERE expires_at > ? ORDER BY created_at DESC LIMIT ? OFFSET ?`, [now, limit, offset]),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_adl_suspicion" WHERE expires_at > ?`, [now]),
      ]);
      return json({ rows: rows.rows, total: total.rows[0]?.cnt ?? 0 });
    }
    if (apiSub === 'adl/run' && request.method === 'POST') {
      // 관리자 강제 분석 — 분산락 무시, 즉시 실행 (인라인).
      try {
        const now = Date.now();
        // ADL 테이블 부트스트랩
        await db.batch([
          db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_blacklist (key TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT, score REAL DEFAULT 0, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (key, kind))`),
          db.prepare(`CREATE INDEX IF NOT EXISTS _dokkebi_bl_exp ON _dokkebi_blacklist (expires_at)`),
          db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_adl_suspicion (key TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT, score REAL DEFAULT 0, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (key, kind))`),
          db.prepare(`CREATE INDEX IF NOT EXISTS _dokkebi_susp_exp ON _dokkebi_adl_suspicion (expires_at)`),
          db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_adl_state (key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER NOT NULL)`),
        ]);
        const cfg = (_SECURITY_SUMMARY && _SECURITY_SUMMARY.activeDefense) || {};
        const adlMode = String(cfg.mode || 'monitor').toLowerCase();
        const insTbl = adlMode === 'monitor' ? '_dokkebi_adl_suspicion' : '_dokkebi_blacklist';
        // 1) IP 빈도 이상치 — Z-score
        const ttl1h = 60*60*1000; const ttl30m = 30*60*1000;
        try {
          const r = await db.prepare(`SELECT ip, COUNT(*) as cnt FROM "_dokkebi_requests" WHERE ts >= datetime('now','-5 minutes') AND ip <> '' GROUP BY ip HAVING cnt > 30 ORDER BY cnt DESC LIMIT 100`).all();
          const ips = (r.results||[]).map(x=>({ip:String(x.ip),cnt:Number(x.cnt)}));
          if (ips.length) {
            const counts = ips.map(a=>a.cnt);
            const mean = counts.reduce((a,b)=>a+b,0)/counts.length;
            const variance = counts.reduce((a,b)=>a+(b-mean)*(b-mean),0)/Math.max(1,counts.length);
            const std = Math.sqrt(variance); const threshold = Math.max(60, mean+3*std);
            const stmts = [];
            for (const a of ips) {
              if (a.cnt < threshold) continue;
              const z = std>0?(a.cnt-mean)/std:3;
              stmts.push(db.prepare('INSERT INTO ' + insTbl + ` (key,kind,reason,score,expires_at,created_at) VALUES (?,'ip',?,?,?,?) ON CONFLICT(key,kind) DO UPDATE SET reason=excluded.reason,score=excluded.score,expires_at=excluded.expires_at`).bind(a.ip,'rate-anomaly: '+a.cnt+'req/5m (z='+z.toFixed(1)+')',Math.min(1,z/6),now+ttl1h,now));
            }
            if (stmts.length) try { await db.batch(stmts); } catch {}
          }
        } catch {}
        // 2) IP 실패 누적
        try {
          const r = await db.prepare(`SELECT ip, COUNT(*) as cnt FROM "_dokkebi_security" WHERE ts >= datetime('now','-10 minutes') AND ip <> '' AND type <> 'query_fallback' GROUP BY ip HAVING cnt >= 5 ORDER BY cnt DESC LIMIT 50`).all();
          const stmts = [];
          for (const row of (r.results||[])) {
            stmts.push(db.prepare('INSERT INTO ' + insTbl + ` (key,kind,reason,score,expires_at,created_at) VALUES (?,'ip',?,?,?,?) ON CONFLICT(key,kind) DO UPDATE SET reason=excluded.reason,score=excluded.score,expires_at=excluded.expires_at`).bind(String(row.ip),'security-fail: '+row.cnt+' events/10m',Math.min(1,Number(row.cnt)/20),now+ttl30m,now));
          }
          if (stmts.length) try { await db.batch(stmts); } catch {}
        } catch {}
        // 3) 만료 항목 GC
        try { await db.prepare(`DELETE FROM _dokkebi_blacklist WHERE expires_at <= ?`).bind(now).run(); } catch {}
        try { await db.prepare(`DELETE FROM _dokkebi_adl_suspicion WHERE expires_at <= ?`).bind(now).run(); } catch {}
        // last_run 갱신
        await db.prepare(`INSERT INTO _dokkebi_adl_state (key,value,updated_at) VALUES ('last_run', ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`).bind(String(now), now).run();
        return json({ ok: true, message: '능동 방어 분석이 즉시 실행되었습니다.' });
      } catch (e) {
        return json({ ok: false, message: '분석 실행 중 오류: ' + (e instanceof Error ? e.message : String(e)) }, 500);
      }
    }
    if (apiSub === 'adl/blacklist/clear' && request.method === 'POST') {
      try { await db.prepare(`DELETE FROM "_dokkebi_blacklist"`).run(); } catch { /* */ }
      return json({ ok: true });
    }
    if (apiSub === 'adl/suspicion/clear' && request.method === 'POST') {
      try { await db.prepare(`DELETE FROM "_dokkebi_adl_suspicion"`).run(); } catch { /* */ }
      return json({ ok: true });
    }
    if (apiSub === 'adl/blacklist/delete' && request.method === 'POST') {
      try {
        const body = await request.json();
        const key = String(body.key || '');
        const kind = String(body.kind || 'ip');
        if (!key) return json({ ok: false, error: 'key 필수' }, 400);
        await db.prepare(`DELETE FROM "_dokkebi_blacklist" WHERE key = ? AND kind = ?`).bind(key, kind).run();
        return json({ ok: true });
      } catch (e) { return json({ ok: false, error: String(e) }, 500); }
    }
    if (apiSub === 'adl/suspicion/delete' && request.method === 'POST') {
      try {
        const body = await request.json();
        const key = String(body.key || '');
        const kind = String(body.kind || 'ip');
        if (!key) return json({ ok: false, error: 'key 필수' }, 400);
        await db.prepare(`DELETE FROM "_dokkebi_adl_suspicion" WHERE key = ? AND kind = ?`).bind(key, kind).run();
        return json({ ok: true });
      } catch (e) { return json({ ok: false, error: String(e) }, 500); }
    }
    if (apiSub === 'adl/blacklist/add' && request.method === 'POST') {
      try {
        const body = await request.json();
        const key = String(body.key || '').trim();
        const kind = String(body.kind || 'ip');
        const reason = String(body.reason || 'manual');
        const score = Math.max(0, Math.min(1, Number(body.score ?? 1)));
        const durationMs = Math.max(60_000, Number(body.durationMs ?? 24*60*60*1000));
        if (!key) return json({ ok: false, error: 'key(IP 등) 필수' }, 400);
        if (!['ip','sid','ipua'].includes(kind)) return json({ ok: false, error: 'kind 는 ip/sid/ipua 중 하나' }, 400);
        const now = Date.now();
        await db.prepare(`INSERT INTO _dokkebi_blacklist (key,kind,reason,score,expires_at,created_at) VALUES (?,?,?,?,?,?) ON CONFLICT(key,kind) DO UPDATE SET reason=excluded.reason,score=excluded.score,expires_at=excluded.expires_at`).bind(key, kind, reason, score, now + durationMs, now).run();
        return json({ ok: true });
      } catch (e) { return json({ ok: false, error: String(e) }, 500); }
    }
    if (apiSub === 'ai/analyze' && request.method === 'POST') {
      try { await db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_ai_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, report TEXT, used_ai INTEGER DEFAULT 0, stats TEXT, created_at TEXT NOT NULL)`).run(); } catch {}
      const [secRows, reqStats, errStats, blCount] = await Promise.all([
        q(db, `SELECT type, ip, path, detail, ts FROM "_dokkebi_security" ORDER BY ts DESC LIMIT 100`),
        q(db, `SELECT COUNT(*) as total, SUM(CASE WHEN CAST(status AS INTEGER)>=400 THEN 1 ELSE 0 END) as errors, COUNT(DISTINCT ip) as unique_ips FROM "_dokkebi_requests" WHERE ts>=datetime('now','-1 hours')`),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_errors" WHERE ts>=datetime('now','-1 hours')`),
        q(db, `SELECT COUNT(*) as cnt FROM "_dokkebi_blacklist" WHERE expires_at > ?`, [Date.now()]),
      ]);
      const secData = secRows.rows;
      const typeCounts: Record<string,number> = {}; const ipCounts: Record<string,number> = {};
      for (const row of secData) { const t = String(row.type||'unknown'); typeCounts[t]=(typeCounts[t]||0)+1; if (row.ip) { const ip=String(row.ip); ipCounts[ip]=(ipCounts[ip]||0)+1; } }
      const topIps = Object.entries(ipCounts).sort((a,b)=>b[1]-a[1]).slice(0,5);
      const reqStat = reqStats.rows[0]||{total:0,errors:0,unique_ips:0};
      const errCount = Number(errStats.rows[0]?.cnt||0); const blActive = Number(blCount.rows[0]?.cnt||0);
      let report = ''; let usedAI = false;
      const aiBinding = (env as any).AI;
      if (aiBinding) {
        const typeLines = Object.entries(typeCounts).map(([k,v])=>`- ${k}: ${v}건`).join('\n')||'- 없음';
        const ipLines = topIps.map(([ip,cnt])=>`- ${ip}: ${cnt}건`).join('\n')||'- 없음';
        const prompt = `당신은 웹 보안 전문가입니다. 아래 데이터를 분석하고 한국어로 보안 리포트를 작성하세요.\n\n[지난 1시간 요청 통계]\n- 총 요청: ${reqStat.total}건 | 오류(4xx/5xx): ${reqStat.errors}건 | 고유 IP: ${reqStat.unique_ips}개\n\n[보안 이벤트 유형별]\n${typeLines}\n\n[상위 의심 IP]\n${ipLines}\n\n[현재 차단 IP 수]: ${blActive}개 | [앱 에러(1h)]: ${errCount}건\n\n위험도(낮음/중간/높음), 주요 위협 패턴, 권장 조치를 포함하여 4~6문장으로 요약하세요.`;
        try { const aiRes: any = await aiBinding.run('@cf/meta/llama-3.1-8b-instruct', { messages: [{role:'user', content:prompt}], max_tokens: 600 }); report = aiRes?.response || aiRes?.choices?.[0]?.message?.content || ''; if (report) usedAI = true; } catch {}
      }
      if (!report) {
        const threats: string[] = [];
        if ((typeCounts['sql_inject']||0)>3) threats.push(`SQL 인젝션 시도 ${typeCounts['sql_inject']}건 감지`);
        if ((typeCounts['hmac_fail']||0)>10) threats.push(`HMAC 인증 실패 ${typeCounts['hmac_fail']}건 — 무차별 대입 의심`);
        if ((typeCounts['rate_limit']||0)>20) threats.push(`레이트 리밋 초과 ${typeCounts['rate_limit']}건 — DDoS 가능성`);
        if ((typeCounts['replay_attempt']||0)>2) threats.push(`리플레이 공격 ${typeCounts['replay_attempt']}건 감지`);
        if ((typeCounts['mutation_budget']||0)>5) threats.push(`Mutation 예산 초과 ${typeCounts['mutation_budget']}건`);
        const errRate = Number(reqStat.total)>0 ? Math.round(Number(reqStat.errors)/Number(reqStat.total)*100) : 0;
        if (errRate>20) threats.push(`오류율 ${errRate}% — 서비스 이상 가능성`);
        if (topIps[0]?.[1]>30) threats.push(`IP ${topIps[0][0]} 집중 요청 ${topIps[0][1]}건`);
        report = threats.length === 0
          ? `현재 특별한 위협이 감지되지 않습니다. 지난 1시간 요청 ${reqStat.total}건 중 오류 ${reqStat.errors}건, 보안 이벤트 ${secData.length}건이 기록되었으며 정상 운영 중입니다.${blActive>0?' 현재 '+blActive+'개 IP가 차단 중입니다.':''}`
          : `⚠️ 주의가 필요한 보안 이슈가 감지되었습니다.\n\n${threats.map(t=>`• ${t}`).join('\n')}${blActive>0?'\n\n현재 '+blActive+'개 IP가 차단 중입니다.':''}`;
      }
      const stats = {typeCounts,topIps,reqStat,errCount,blActive};
      const analyzedAt = new Date().toISOString();
      try { await db.prepare(`INSERT INTO _dokkebi_ai_reports (report, used_ai, stats, created_at) VALUES (?,?,?,?)`).bind(report, usedAI?1:0, JSON.stringify(stats), analyzedAt).run(); } catch {}
      return json({ok:true, report, usedAI, stats, analyzedAt});
    }
    if (apiSub === 'ai/history') {
      try { await db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_ai_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, report TEXT, used_ai INTEGER DEFAULT 0, stats TEXT, created_at TEXT NOT NULL)`).run(); } catch {}
      const [rows, total] = await Promise.all([
        q(db, `SELECT id,report,used_ai,stats,created_at FROM _dokkebi_ai_reports ORDER BY created_at DESC LIMIT ? OFFSET ?`, [limit, offset]),
        q(db, `SELECT COUNT(*) as cnt FROM _dokkebi_ai_reports`),
      ]);
      return json({ rows: rows.rows, total: total.rows[0]?.cnt ?? 0 });
    }

    return json({ error: '알 수 없는 API 경로' }, 404);
  }

  return new Response('Not Found', { status: 404 });
};

// ── 어드민 HTML (인라인) ───────────────────────────────────────
// 전체 어드민 HTML은 dok serve 모드와 공유하며 경량 버전을 인라인으로 포함
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>도깨비 관제 · __PROJECT__</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#8b5cf6;--green:#3fb950;--red:#f85149;--yellow:#d29922}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
#login{display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:40px;width:360px;text-align:center}
.logo{font-size:40px;margin-bottom:8px}.card h1{font-size:20px;margin-bottom:4px}
.card p{color:var(--muted);margin-bottom:24px;font-size:13px}
input[type=password]{width:100%;padding:10px 14px;background:#0d1117;border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;margin-bottom:12px;outline:none}
.btn{width:100%;padding:10px;background:var(--accent);color:#fff;border:none;border-radius:8px;font-size:14px;cursor:pointer}
.err{color:var(--red);font-size:13px;margin-top:8px}
#app{display:none}
header{display:flex;align-items:center;gap:12px;padding:0 20px;height:52px;border-bottom:1px solid var(--border);background:var(--surface)}
header h2{flex:1;font-size:15px}.mode{font-size:11px;padding:2px 8px;border-radius:12px;background:rgba(139,92,246,.2);color:var(--accent)}
.logout{padding:5px 12px;background:none;border:1px solid var(--border);border-radius:6px;color:var(--text);cursor:pointer;font-size:12px}
.layout{display:flex;height:calc(100vh - 52px)}
nav{width:180px;border-right:1px solid var(--border);padding:12px 8px}
nav button{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;background:none;border:none;border-radius:6px;color:var(--muted);font-size:13px;cursor:pointer;margin-bottom:2px}
nav button.active{background:rgba(139,92,246,.2);color:var(--accent)}
main{flex:1;overflow-y:auto;padding:20px}
.tab{display:none}.tab.active{display:block}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.scard{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px}
.scard .lbl{font-size:12px;color:var(--muted);margin-bottom:4px}.scard .val{font-size:28px;font-weight:700}
.scard.accent .val{color:var(--accent)}.scard.red .val{color:var(--red)}.scard.yellow .val{color:var(--yellow)}.scard.green .val{color:var(--green)}
.tbl{border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-top:12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{padding:10px 12px;text-align:left;color:var(--muted);border-bottom:1px solid var(--border);background:var(--surface)}
td{padding:8px 12px;border-bottom:1px solid var(--border);word-break:break-all}tr:last-child td{border-bottom:none}
.badge{padding:2px 7px;border-radius:4px;font-size:11px}.badge-error{background:rgba(248,81,73,.15);color:var(--red)}
.badge-hmac{background:rgba(248,81,73,.15);color:var(--red)}.badge-rate{background:rgba(210,153,34,.15);color:var(--yellow)}
.badge-info{background:rgba(63,185,80,.15);color:var(--green)}
.badge-warn{background:rgba(210,153,34,.15);color:var(--yellow)}
.badge-danger{background:rgba(248,81,73,.15);color:var(--red)}
.empty{padding:40px;text-align:center;color:var(--muted)}
.banner{padding:12px 16px;border-radius:10px;margin-bottom:16px;display:none;font-size:13px;line-height:1.5}
.banner.warn{background:rgba(210,153,34,.15);border:1px solid rgba(210,153,34,.4);color:#d29922;display:block}
.banner.danger{background:rgba(248,81,73,.15);border:1px solid rgba(248,81,73,.4);color:#f85149;display:block}
.sec-hero{display:flex;gap:16px;margin-bottom:16px}
.sec-score{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;width:200px;text-align:center}
.sec-score .num{font-size:48px;font-weight:700;color:var(--accent);line-height:1}
.sec-score .sub{font-size:12px;color:var(--muted);margin-top:4px}
.sec-score.excellent .num{color:var(--green)} .sec-score.warn .num{color:var(--yellow)} .sec-score.danger .num{color:var(--red)}
.sec-feats{flex:1;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;display:grid;grid-template-columns:repeat(2,1fr);gap:8px}
.sec-feat{display:flex;align-items:center;gap:8px;font-size:13px}
.sec-feat .dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}
.sec-feat.on .dot{background:var(--green)}
.sec-feat.off{opacity:.55}
.sec-feat .w{margin-left:auto;font-size:11px;color:var(--muted)}
.sec-meta{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;margin-top:12px}
.sec-meta h4{font-size:13px;color:var(--muted);margin-bottom:8px;font-weight:500}
.sec-meta code{font-family:ui-monospace,monospace;font-size:12px;background:#0d1117;padding:2px 6px;border-radius:4px;color:#e6edf3}
.sec-rec{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;margin-top:12px}
.sec-rec ul{padding-left:20px;color:var(--muted);font-size:13px;line-height:1.7}
</style></head><body>
<div id="login"><div class="card">
  <div class="logo">👺</div><h1>도깨비 관제</h1>
  <p>__PROJECT__ · <span class="mode">__MODE__</span></p>
  <input type="password" id="pw" placeholder="관리자 비밀번호">
  <button class="btn" onclick="doLogin()">로그인</button>
  <div class="err" id="err"></div>
</div></div>
<div id="app">
<header>
  <span style="font-size:20px">👺</span>
  <h2>도깨비 관제 · __PROJECT__</h2>
  <span class="mode">__MODE__</span>
  <button class="logout" onclick="doLogout()">로그아웃</button>
</header>
<div class="layout">
<nav>
  <button class="active" data-tab="overview" onclick="go('overview',this)">📊 개요</button>
  <button data-tab="status" onclick="go('status',this)">🔒 상태</button>
  <button data-tab="adl" onclick="go('adl',this)">🤖 능동방어</button>
  <button data-tab="errors" onclick="go('errors',this)">🔴 에러</button>
  <button data-tab="security" onclick="go('security',this)">🛡 이벤트</button>
  <button data-tab="ai" onclick="go('ai',this)">🔍 AI 분석</button>
</nav>
<main>
<div class="tab active" id="tab-overview">
  <div id="sec-banner" class="banner"></div>
  <div class="cards">
    <div class="scard accent"><div class="lbl">접속자(5분)</div><div class="val" id="c0">-</div></div>
    <div class="scard green"><div class="lbl">요청(24h)</div><div class="val" id="c1">-</div></div>
    <div class="scard red"><div class="lbl">에러(24h)</div><div class="val" id="c2">-</div></div>
    <div class="scard yellow"><div class="lbl">보안(24h)</div><div class="val" id="c3">-</div></div>
  </div>
</div>
<div class="tab" id="tab-status">
  <h3 style="margin-bottom:12px">🔒 보안 상태 & 커버리지</h3>
  <div class="sec-hero">
    <div class="sec-score" id="sec-score"><div class="num" id="sec-num">-</div><div class="sub" id="sec-lvl">점수 로딩 중…</div></div>
    <div class="sec-feats" id="sec-feats"></div>
  </div>
  <div class="sec-meta"><h4>빌드 서명 (공급망 트레이서빌리티)</h4><div id="sec-bm"></div></div>
  <div class="sec-rec"><h4 style="font-size:13px;color:var(--muted);margin-bottom:8px;font-weight:500">💡 권고사항</h4><ul id="sec-rec"></ul></div>
</div>
<div class="tab" id="tab-adl">
  <h3 style="margin-bottom:12px">🤖 능동 방어 (Active Defense Layer)</h3>
  <div id="adl-summary" style="margin-bottom:14px"></div>
  <div class="cards" style="grid-template-columns:repeat(auto-fill,minmax(148px,1fr));margin-bottom:14px">
    <div class="scard accent"><div class="lbl">활성 차단(현재)</div><div class="val" id="adl-bl">-</div></div>
    <div class="scard yellow"><div class="lbl">의심·자동(현재)</div><div class="val" id="adl-sus">-</div></div>
    <div class="scard green"><div class="lbl">감지(24h)</div><div class="val" id="adl-d24">-</div></div>
    <div class="scard red"><div class="lbl">차단(24h)</div><div class="val" id="adl-b24">-</div></div>
    <div class="scard yellow"><div class="lbl">마지막 분석</div><div class="val" id="adl-lr" style="font-size:14px">-</div></div>
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
    <button class="btn" style="width:auto;padding:8px 14px" onclick="adlRun()">분석 즉시 실행</button>
    <button class="btn" style="width:auto;padding:8px 14px;background:var(--red)" onclick="adlClear()">차단 목록 초기화</button>
    <button class="btn" style="width:auto;padding:8px 14px;background:#a855f7;border:none;color:#fff" onclick="adlSusClear()">의심 목록 초기화</button>
  </div>
  <details style="margin-bottom:14px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:0">
    <summary style="padding:10px 14px;cursor:pointer;font-size:13px;font-weight:500;color:var(--muted)">➕ IP/키 수동 추가</summary>
    <div style="padding:10px 14px 14px;display:flex;gap:8px;flex-wrap:wrap;align-items:end">
      <div><label style="font-size:11px;color:var(--muted)">키(IP 등)</label><input id="adl-add-key" style="display:block;width:180px;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:13px" placeholder="121.174.77.100"></div>
      <div><label style="font-size:11px;color:var(--muted)">유형</label><select id="adl-add-kind" style="display:block;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:13px"><option value="ip">ip</option><option value="sid">sid</option><option value="ipua">ipua</option></select></div>
      <div><label style="font-size:11px;color:var(--muted)">사유</label><input id="adl-add-reason" style="display:block;width:160px;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:13px" placeholder="manual" value="manual"></div>
      <div><label style="font-size:11px;color:var(--muted)">차단 기간</label><select id="adl-add-dur" style="display:block;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:13px"><option value="1800000">30분</option><option value="3600000">1시간</option><option value="86400000" selected>24시간</option><option value="604800000">7일</option><option value="2592000000">30일</option></select></div>
      <button class="btn" style="width:auto;padding:6px 14px;font-size:13px" onclick="adlAdd()">추가</button>
    </div>
  </details>
  <h4 style="font-size:13px;color:var(--muted);margin:12px 0 6px">활성 차단 목록</h4>
  <div class="tbl"><table><thead><tr><th>키</th><th>유형</th><th>사유</th><th>스코어</th><th>만료</th><th style="width:50px"></th></tr></thead><tbody id="adl-tb"></tbody></table></div>
  <h4 style="font-size:13px;color:var(--muted);margin:16px 0 6px">의심 리스트 <span style="font-weight:400;color:var(--muted);font-size:12px">· monitor 모드에서 자동 분석만 적재 (엣지 차단 없음)</span></h4>
  <div class="tbl"><table><thead><tr><th>키</th><th>유형</th><th>사유</th><th>스코어</th><th>만료</th><th style="width:50px"></th></tr></thead><tbody id="adl-sus-tb"></tbody></table></div>
</div>
<div class="tab" id="tab-errors">
  <h3 style="margin-bottom:12px">에러 로그</h3>
  <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end;margin-bottom:12px">
    <div><label style="font-size:11px;color:var(--muted)">검색</label><input id="err-search" style="display:block;width:180px;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:13px" placeholder="메시지 또는 경로"></div>
    <div><label style="font-size:11px;color:var(--muted)">시작</label><input id="err-from" type="datetime-local" style="display:block;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:13px"></div>
    <div><label style="font-size:11px;color:var(--muted)">종료</label><input id="err-to" type="datetime-local" style="display:block;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:13px"></div>
    <button class="btn" style="width:auto;padding:6px 14px;font-size:13px" onclick="_errPage=0;loadE()">조회</button>
    <button class="btn" style="width:auto;padding:6px 14px;font-size:13px;background:var(--muted)" onclick="document.getElementById('err-search').value='';document.getElementById('err-from').value='';document.getElementById('err-to').value='';_errPage=0;loadE()">초기화</button>
  </div>
  <div class="tbl"><table><thead><tr><th>시간</th><th>레벨</th><th>경로</th><th>메시지</th></tr></thead><tbody id="err-tb"></tbody></table></div>
  <div id="err-pager" style="display:flex;align-items:center;justify-content:center;gap:12px;margin-top:10px;font-size:13px;color:var(--muted)"></div>
</div>
<div class="tab" id="tab-security">
  <h3 style="margin-bottom:12px">이벤트 / 요청 통합 로그</h3>
  <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end;margin-bottom:12px">
    <div><label style="font-size:11px;color:var(--muted)">IP</label><input id="sec-ip" style="display:block;width:160px;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:13px" placeholder="IP 검색"></div>
    <div><label style="font-size:11px;color:var(--muted)">시작</label><input id="sec-from" type="datetime-local" style="display:block;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:13px"></div>
    <div><label style="font-size:11px;color:var(--muted)">종료</label><input id="sec-to" type="datetime-local" style="display:block;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);font-size:13px"></div>
    <button class="btn" style="width:auto;padding:6px 14px;font-size:13px" onclick="_secPage=0;loadS()">조회</button>
    <button class="btn" style="width:auto;padding:6px 14px;font-size:13px;background:var(--muted)" onclick="document.getElementById('sec-ip').value='';document.getElementById('sec-from').value='';document.getElementById('sec-to').value='';_secPage=0;loadS()">초기화</button>
  </div>
  <div class="tbl"><table><thead><tr><th>시간</th><th>유형</th><th>판정</th><th>IP</th><th>경로</th><th>상세</th></tr></thead><tbody id="sec-tb"></tbody></table></div>
  <div id="sec-pager" style="display:flex;align-items:center;justify-content:center;gap:12px;margin-top:10px;font-size:13px;color:var(--muted)"></div>
</div>
<div class="tab" id="tab-ai">
  <h3 style="margin-bottom:4px">🔍 AI 보안 분석</h3>
  <p style="font-size:13px;color:var(--muted);margin-bottom:16px">지난 1시간 로그·보안 이벤트를 분석해 위협 리포트를 생성합니다.</p>
  <button id="ai-btn" class="btn" style="width:auto;padding:10px 20px;margin-bottom:16px" onclick="runAi()">분석 실행</button>
  <div id="ai-out" style="display:none;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <span style="font-size:13px;color:var(--muted)" id="ai-meta"></span>
    </div>
    <div id="ai-report" style="font-size:14px;line-height:1.8;white-space:pre-wrap"></div>
    <div id="ai-stats" style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border)"></div>
  </div>
  <h4 style="font-size:13px;color:var(--muted);margin:20px 0 8px">📋 분석 이력</h4>
  <div id="ai-history"></div>
</div>
</main></div></div>
<script>
// 현재 페이지 경로 기준으로 베이스 URL 자동 감지
// serve/dev:   /_dokkebi/_panel   → /_dokkebi/_panel/auth
// serverless: /api/_dokkebi/_panel → /api/_dokkebi/_panel/auth
const _BASE=location.pathname.replace(/[/]+$/,'');
const TK='dok_admin_token';let _t=sessionStorage.getItem(TK)||'';
const _FEAT_LBL={opaqueHandle:'Opaque Handle',replay:'Replay 방어',allowlist:'SQL Allowlist',registry:'Query Registry',pregate:'세션 Pre-gate',envelopeCap:'Envelope Cap',counter:'Monotonic Counter',codeProtect:'코드 보호',codeEncrypt:'번들 암호화',tenantPolicy:'Tenant Policy',authzPolicy:'Authorization',webauthn:'WebAuthn',integritySig:'빌드 서명',strictCsp:'Strict CSP',activeDefense:'능동 방어(ADL)',capabilities:'Signed Unlock Token',capChain:'Capability Chain',attestation:'Bundle Attestation',panelIpGuard:'패널 IP allowlist',zeroDowntime:'무중단 배포'};
async function doLogin(){const pw=document.getElementById('pw').value;if(!pw)return;
  const r=await fetch(_BASE+'/auth',{method:'POST',headers:{'Content-Type':'application/json; charset=utf-8'},body:JSON.stringify({password:pw})});
  const d=await r.json();if(!r.ok){document.getElementById('err').textContent=d.error;return;}
  _t=d.token;sessionStorage.setItem(TK,_t);document.getElementById('login').style.display='none';document.getElementById('app').style.display='block';init();}
function doLogout(){sessionStorage.removeItem(TK);location.reload();}
document.getElementById('pw').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});
async function api(p){const r=await fetch(_BASE+'/api/'+p,{headers:{'Authorization':'Bearer '+_t}});if(r.status===401){doLogout();throw new Error('auth');}return r.json();}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');}
function ft(ts){try{return new Date(ts.endsWith('Z')?ts:ts+'Z').toLocaleString('ko-KR',{timeZone:'Asia/Seoul',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});}catch{return ts;}}
function go(t,b){document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('nav button').forEach(x=>x.classList.remove('active'));document.getElementById('tab-'+t).classList.add('active');b.classList.add('active');
  if(t==='errors'){_errPage=0;loadE();}if(t==='security'){_secPage=0;loadS();}if(t==='status')loadSt();if(t==='adl')loadAdl();if(t==='ai')loadAiHistory();}
async function loadOv(){try{const d=await api('overview');document.getElementById('c0').textContent=d.activeUsers??0;document.getElementById('c1').textContent=d.requests24h??0;document.getElementById('c2').textContent=d.errors24h??0;document.getElementById('c3').textContent=d.security24h??0;}catch{}}
const _PZ=50;let _errPage=0,_secPage=0;
function _pager(el,page,total,fn){const pages=Math.ceil(total/_PZ);if(pages<=1){el.innerHTML='';return;}el.innerHTML='<button style="background:none;border:1px solid var(--border);color:var(--text);border-radius:4px;padding:4px 10px;cursor:pointer"'+(page<=0?' disabled':'')+' onclick="'+fn+'('+(page-1)+')">◀ 이전</button><span>'+((page+1))+' / '+pages+' ('+total+'건)</span><button style="background:none;border:1px solid var(--border);color:var(--text);border-radius:4px;padding:4px 10px;cursor:pointer"'+(page>=pages-1?' disabled':'')+' onclick="'+fn+'('+(page+1)+')">다음 ▶</button>';}
function _dtVal(id){const v=document.getElementById(id).value;return v?new Date(v).toISOString():'';}
function errGo(p){_errPage=p;loadE();}function secGo(p){_secPage=p;loadS();}
async function loadE(){try{let u='errors?limit='+_PZ+'&offset='+(_errPage*_PZ);const s=document.getElementById('err-search').value.trim();if(s)u+='&search='+encodeURIComponent(s);const f=_dtVal('err-from');if(f)u+='&from='+encodeURIComponent(f);const t=_dtVal('err-to');if(t)u+='&to='+encodeURIComponent(t);
  const d=await api(u);const tb=document.getElementById('err-tb');if(!d.rows?.length){tb.innerHTML='<tr><td colspan=4 class=empty>에러 없음 ✅</td></tr>';document.getElementById('err-pager').innerHTML='';return;}
  tb.innerHTML=d.rows.map(r=>'<tr><td style="white-space:nowrap">'+ft(r.ts)+'</td><td><span class="badge badge-error">'+esc(r.level)+'</span></td><td>'+esc(r.path)+'</td><td>'+esc(r.message)+'</td></tr>').join('');_pager(document.getElementById('err-pager'),_errPage,d.total,'errGo');}catch{}}
function _secRiskMeta(type, detail){
  const t=String(type||'');
  const d=String(detail||'').toLowerCase();
  if(t==='request' || t==='db_audit') return {label:'정상', cls:'badge-info'};
  if(t==='query_fallback') return {label:'정상(auto)', cls:'badge-info'};
  if(t==='query_learned' || t==='tenant_injected' || t==='adl_detect') return {label:'주의', cls:'badge-warn'};
  if(t==='mutation_budget' || t==='rate_limit') return {label:'주의', cls:'badge-warn'};
  if(t==='adl_block' || t==='hmac_fail' || t==='sql_inject' || t==='replay_attempt') return {label:'공격의심', cls:'badge-danger'};
  if(t==='authz_denied') return {label: d.includes('auth_required') ? '주의' : '공격의심', cls: d.includes('auth_required') ? 'badge-warn' : 'badge-danger'};
  if(t==='query_not_registered' || t==='raw_sql_blocked' || t==='sql_blocked' || t==='tenant_policy_violation') return {label:'공격의심', cls:'badge-danger'};
  return {label:'주의', cls:'badge-warn'};
}
async function loadS(){try{let u='security?limit='+_PZ+'&offset='+(_secPage*_PZ);const ip=document.getElementById('sec-ip').value.trim();if(ip)u+='&ip='+encodeURIComponent(ip);const f=_dtVal('sec-from');if(f)u+='&from='+encodeURIComponent(f);const t=_dtVal('sec-to');if(t)u+='&to='+encodeURIComponent(t);
  const d=await api(u);const LBL={request:'요청',db_audit:'DB Audit',hmac_fail:'HMAC',rate_limit:'레이트',sql_inject:'SQL',replay_attempt:'Replay',mutation_budget:'Mutation',query_fallback:'쿼리폴백',query_not_registered:'미등록쿼리',adl_detect:'ADL감지',adl_block:'ADL차단'};
  const tb=document.getElementById('sec-tb');if(!d.rows?.length){tb.innerHTML='<tr><td colspan=6 class=empty>이벤트 없음 ✅</td></tr>';document.getElementById('sec-pager').innerHTML='';return;}
  tb.innerHTML=d.rows.map(r=>{const risk=_secRiskMeta(r.type,r.detail);return '<tr><td style="white-space:nowrap">'+ft(r.ts)+'</td><td><span class="badge '+risk.cls+'">'+(LBL[r.type]||r.type)+'</span></td><td><span class="badge '+risk.cls+'">'+risk.label+'</span></td><td>'+esc(r.ip)+'</td><td>'+esc(r.path)+'</td><td>'+esc(r.detail)+'</td></tr>';}).join('');_pager(document.getElementById('sec-pager'),_secPage,d.total,'secGo');}catch{}}
async function loadSt(){try{const d=await api('security-info');_renderStatus(d);}catch{}}
async function loadAdl(){try{const s=await api('adl/status');_renderAdlSummary(s);
  const [r,rs]=await Promise.all([api('adl/blacklist?limit=50'),api('adl/suspicion?limit=50')]);const tb=document.getElementById('adl-tb');
  if(!r.rows||!r.rows.length){tb.innerHTML='<tr><td colspan=6 class=empty>활성 차단 없음 ✅</td></tr>';}else{
  tb.innerHTML=r.rows.map(x=>'<tr><td><code>'+esc(x.key)+'</code></td><td><span class="badge badge-hmac">'+esc(x.kind)+'</span></td><td>'+esc(x.reason||'')+'</td><td>'+(Number(x.score||0)).toFixed(2)+'</td><td>'+ft(new Date(Number(x.expires_at)).toISOString())+'</td><td><button onclick="adlDel(this)" data-key="'+esc(x.key)+'" data-kind="'+esc(x.kind)+'" style="background:none;border:none;color:var(--red);cursor:pointer;font-size:15px" title="삭제">✕</button></td></tr>').join('');}
  const tbS=document.getElementById('adl-sus-tb');if(!rs.rows||!rs.rows.length){tbS.innerHTML='<tr><td colspan=6 class=empty>의심 항목 없음</td></tr>';}else{
  tbS.innerHTML=rs.rows.map(x=>'<tr><td><code>'+esc(x.key)+'</code></td><td><span class="badge badge-warn">'+esc(x.kind)+'</span></td><td>'+esc(x.reason||'')+'</td><td>'+(Number(x.score||0)).toFixed(2)+'</td><td>'+ft(new Date(Number(x.expires_at)).toISOString())+'</td><td><button onclick="adlSusDel(this)" data-key="'+esc(x.key)+'" data-kind="'+esc(x.kind)+'" style="background:none;border:none;color:var(--red);cursor:pointer;font-size:15px" title="삭제">✕</button></td></tr>').join('');}}catch{}}
function _renderAdlSummary(d){const cfg=d.config||{enabled:false};
  document.getElementById('adl-bl').textContent=d.blacklistCount??0;
  document.getElementById('adl-sus').textContent=d.suspicionCount??0;
  document.getElementById('adl-d24').textContent=d.detect24h??0;
  document.getElementById('adl-b24').textContent=d.block24h??0;
  document.getElementById('adl-lr').textContent=d.lastRun?(_fmtAgo(d.lastRunAgoSec)):'아직 없음';
  const sum=document.getElementById('adl-summary');
  if(!cfg.enabled){sum.innerHTML='<div class="banner warn">⚠ 능동 방어가 비활성 상태입니다 — <code>security.activeDefense.enabled: true</code> 로 활성하면 행동 기반 차단이 작동합니다.</div>';return;}
  const md=cfg.mode==='enforce'?'<span style="color:var(--red);font-weight:600">enforce</span>':'<span style="color:var(--yellow)">monitor</span>';
  const tg=cfg.trigger==='lazy'?'Lazy(핫패스)':'Cron';
  const intMin=Math.round((cfg.intervalMs||300000)/60000);
  const monNote=cfg.mode!=='enforce'?'<div style="margin-top:8px;font-size:12px;color:var(--muted)">monitor: 자동 분석 결과는 <strong>의심 리스트</strong>에만 쌓이며 실제 IP 차단은 하지 않습니다. 수동 추가는 활성 차단 목록에 바로 반영됩니다.</div>':'';
  sum.innerHTML='<div class="banner" style="background:rgba(139,92,246,.08);border:1px solid rgba(139,92,246,.4);color:var(--text);padding:12px;border-radius:8px">모드 '+md+' · 트리거 '+tg+' · 분석주기 '+intMin+'분 · 샘플 '+((cfg.sampleRate||0.01)*100).toFixed(2)+'%'+(cfg.useWorkersAI?' · Workers AI ON':'')+monNote+'</div>';}
function _fmtAgo(s){if(s==null)return '-';if(s<60)return s+'초 전';if(s<3600)return Math.floor(s/60)+'분 전';return Math.floor(s/3600)+'시간 전';}
async function adlRun(){try{const r=await fetch(_BASE+'/api/adl/run',{method:'POST',headers:{'Authorization':'Bearer '+_t}});const d=await r.json().catch(()=>({}));if(r.ok){alert(d.message||'능동 방어 분석이 완료되었습니다.');setTimeout(loadAdl,1500);}else{alert('분석 실패: '+(d.message||r.statusText));}}catch(e){alert('분석 요청 중 오류: '+e.message);}}
async function adlClear(){if(!confirm('현재 활성 차단 목록을 모두 제거합니다. 계속할까요?'))return;try{await fetch(_BASE+'/api/adl/blacklist/clear',{method:'POST',headers:{'Authorization':'Bearer '+_t}});loadAdl();}catch{}}
async function adlSusClear(){if(!confirm('의심 리스트(자동 분석 적재)를 모두 비웁니다. 계속할까요?'))return;try{await fetch(_BASE+'/api/adl/suspicion/clear',{method:'POST',headers:{'Authorization':'Bearer '+_t}});loadAdl();}catch{}}
async function adlDel(el){const key=el.getAttribute('data-key');const kind=el.getAttribute('data-kind');if(!confirm(key+' ('+kind+') 항목을 차단 목록에서 제거할까요?'))return;try{const r=await fetch(_BASE+'/api/adl/blacklist/delete',{method:'POST',headers:{'Authorization':'Bearer '+_t,'Content-Type':'application/json; charset=utf-8'},body:JSON.stringify({key,kind})});if(r.ok)loadAdl();else alert('삭제 실패');}catch(e){alert('오류: '+e.message);}}
async function adlSusDel(el){const key=el.getAttribute('data-key');const kind=el.getAttribute('data-kind');if(!confirm(key+' ('+kind+') 항목을 의심 목록에서 제거할까요?'))return;try{const r=await fetch(_BASE+'/api/adl/suspicion/delete',{method:'POST',headers:{'Authorization':'Bearer '+_t,'Content-Type':'application/json; charset=utf-8'},body:JSON.stringify({key,kind})});if(r.ok)loadAdl();else alert('삭제 실패');}catch(e){alert('오류: '+e.message);}}
async function adlAdd(){const key=document.getElementById('adl-add-key').value.trim();if(!key){alert('키(IP 등)를 입력하세요');return;}const kind=document.getElementById('adl-add-kind').value;const reason=document.getElementById('adl-add-reason').value||'manual';const dur=Number(document.getElementById('adl-add-dur').value);try{const r=await fetch(_BASE+'/api/adl/blacklist/add',{method:'POST',headers:{'Authorization':'Bearer '+_t,'Content-Type':'application/json; charset=utf-8'},body:JSON.stringify({key,kind,reason,durationMs:dur})});const d=await r.json().catch(()=>({}));if(r.ok){document.getElementById('adl-add-key').value='';loadAdl();}else{alert('추가 실패: '+(d.error||r.statusText));}}catch(e){alert('오류: '+e.message);}}
function _renderStatus(d){const cov=d.coverage||{score:0,enabled:{},weights:{},recommendations:[],level:'danger'};
  const sNum=document.getElementById('sec-num');sNum.textContent=cov.score+' / 100';
  const sEl=document.getElementById('sec-score');sEl.classList.remove('excellent','warn','danger');sEl.classList.add(cov.level||'warn');
  document.getElementById('sec-lvl').textContent=({excellent:'보안 상태 우수 ✅',good:'양호 — 추가 강화 권장',warn:'⚠ 미흡 — 활성 필요',danger:'🚨 위험 — 즉시 점검'})[cov.level]||'';
  const fe=document.getElementById('sec-feats');fe.innerHTML=Object.entries(cov.enabled||{}).map(([k,v])=>'<div class="sec-feat '+(v?'on':'off')+'"><span class="dot"></span><span>'+(_FEAT_LBL[k]||k)+'</span><span class="w">+'+(cov.weights?.[k]||0)+'</span></div>').join('');
  const bm=d.buildMeta||{};
  const sha=bm.source_sha?bm.source_sha.slice(0,10)+(bm.source_dirty?' <span style="color:var(--yellow)">[dirty]</span>':''):'(git 저장소 없음)';
  const ch=bm.controllers_hash?bm.controllers_hash.slice(0,16):'(N/A)';
  const _zd=d.zeroDowntime||{};const _at=d.attestation||{};const _pg=d.panelIpGuard||{};const _cap=d.capabilities||{};
  const _zdLine=_zd.enabled?('<code>'+esc(_zd.bundleAssetName||'')+'</code> · BC_KEY_MAP <code>'+(_zd.bcKeyMapKeys||1)+'</code>개 키 유지'):'<span style="color:var(--muted)">미적용 (구버전 빌드)</span>';
  const _atLine=_at.enabled?('샘플 '+(_at.sampleSize||0)+'청크 · TTL '+Math.round((_at.ttlMs||0)/1000)+'s'+(_at.autoFromCapabilities?' · <span style="color:var(--green);font-size:11px">capability 연동 자동 ON</span>':'')):'<span style="color:var(--muted)">비활성</span>';
  const _pgLine=_pg.enabled?'<span style="color:var(--green)">활성</span> — DOKKEBI_PANEL_ALLOWED_IPS 매칭 IP만 접근':'<span style="color:var(--muted)">비활성 (패널 공개)</span>';
  const _capLine=_cap.enabled?(_cap.features+'개 feature · TTL '+Math.round((_cap.defaultTtlMs||0)/1000)+'s'+(_cap.hasChain?' · <span style="color:var(--green);font-size:11px">Chain 사용</span>':'')):'<span style="color:var(--muted)">비활성</span>';
  document.getElementById('sec-bm').innerHTML='<div style="display:grid;grid-template-columns:140px 1fr;gap:8px;font-size:13px"><div style="color:var(--muted)">git SHA</div><div><code>'+sha+'</code></div><div style="color:var(--muted)">브랜치</div><div><code>'+esc(bm.source_branch||'(n/a)')+'</code></div><div style="color:var(--muted)">컨트롤러 해시</div><div><code>'+ch+'</code> ('+ (bm.controller_count||0) +' 파일)</div><div style="color:var(--muted)">빌드 시각</div><div><code>'+esc(bm.built_at||'(n/a)')+'</code></div><div style="color:var(--muted)">CLI 버전</div><div><code>'+esc(bm.scanner_version||'(n/a)')+'</code></div><div style="grid-column:1/3;border-top:1px solid var(--border);margin-top:6px;padding-top:8px;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em">추가 보안 구성</div><div style="color:var(--muted)">무중단 배포</div><div>'+_zdLine+'</div><div style="color:var(--muted)">Bundle Attestation</div><div>'+_atLine+'</div><div style="color:var(--muted)">Signed Unlock Token</div><div>'+_capLine+'</div><div style="color:var(--muted)">패널 IP allowlist</div><div>'+_pgLine+'</div></div>';
  const rec=cov.recommendations||[];document.getElementById('sec-rec').innerHTML=rec.length?rec.map(r=>'<li>'+esc(r)+'</li>').join(''):'<li style="color:var(--green)">추가 권고사항 없음 — 현재 설정이 양호합니다. ✅</li>';
  const ban=document.getElementById('sec-banner');
  if(cov.level==='danger'){ban.className='banner danger';ban.innerHTML='🚨 <strong>보안 커버리지 '+cov.score+'/100</strong> — 즉시 점검이 필요합니다. 상단 "🔒 상태" 탭에서 상세 확인.';}
  else if(cov.level==='warn'){ban.className='banner warn';ban.innerHTML='⚠ <strong>보안 커버리지 '+cov.score+'/100</strong> — opt-in 보안 기능이 미활성 상태입니다. "🔒 상태" 탭에서 권장사항 확인.';}
  else{ban.className='banner';ban.style.display='none';}}
async function _loadBanner(){try{const d=await api('security-info');_renderStatus(d);}catch{}}
async function runAi(){const btn=document.getElementById('ai-btn');const out=document.getElementById('ai-out');const rep=document.getElementById('ai-report');const meta=document.getElementById('ai-meta');const stats=document.getElementById('ai-stats');
  btn.disabled=true;btn.textContent='분석 중…';out.style.display='none';
  try{const r=await fetch(_BASE+'/api/ai/analyze',{method:'POST',headers:{'Authorization':'Bearer '+_t}});
    if(!r.ok){const e=await r.json().catch(()=>({}));rep.textContent='오류: '+(e.error||r.status);out.style.display='block';return;}
    const d=await r.json();
    rep.textContent=d.report||'(리포트 없음)';
    const at=d.analyzedAt?new Date(d.analyzedAt).toLocaleString('ko-KR',{timeZone:'Asia/Seoul'}):'';
    meta.innerHTML=(d.usedAI?'<span style="color:var(--green);font-size:12px">✦ Workers AI</span>':'<span style="color:var(--muted);font-size:12px">규칙 기반 분석</span>')+' · <span style="font-size:12px;color:var(--muted)">'+at+'</span>';
    const s=d.stats||{};const tc=s.typeCounts||{};
    const typeRows=Object.entries(tc).map(([k,v])=>'<tr><td>'+esc(k)+'</td><td style="text-align:right;color:var(--accent);font-weight:600">'+v+'</td></tr>').join('');
    const ipRows=(s.topIps||[]).map(([ip,cnt])=>'<tr><td><code>'+esc(ip)+'</code></td><td style="text-align:right;color:var(--yellow);font-weight:600">'+cnt+'</td></tr>').join('');
    stats.innerHTML='<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px"><div><h4 style="font-size:12px;color:var(--muted);margin-bottom:6px">이벤트 유형별</h4><table style="width:100%;font-size:12px"><tbody>'+(typeRows||'<tr><td colspan=2 style="color:var(--muted)">없음</td></tr>')+'</tbody></table></div><div><h4 style="font-size:12px;color:var(--muted);margin-bottom:6px">상위 의심 IP</h4><table style="width:100%;font-size:12px"><tbody>'+(ipRows||'<tr><td colspan=2 style="color:var(--muted)">없음</td></tr>')+'</tbody></table></div></div>';
    out.style.display='block';
  }catch(e){rep.textContent='요청 실패: '+e.message;out.style.display='block';}
  finally{btn.disabled=false;btn.textContent='다시 분석';loadAiHistory();}}
async function loadAiHistory(){try{const d=await api('ai/history?limit=10');const el=document.getElementById('ai-history');if(!d.rows||!d.rows.length){el.innerHTML='<div style="color:var(--muted);font-size:13px">분석 이력이 없습니다.</div>';return;}
  el.innerHTML=d.rows.map(r=>{const at=r.created_at?new Date(r.created_at).toLocaleString('ko-KR',{timeZone:'Asia/Seoul'}):'';const ai=Number(r.used_ai)?'✦ AI':'규칙';return '<details style="background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:6px"><summary style="padding:8px 12px;cursor:pointer;font-size:13px;color:var(--muted)"><span style="color:var(--text)">'+at+'</span> · <span style="font-size:12px">'+(ai)+'</span></summary><div style="padding:8px 12px 12px;font-size:13px;white-space:pre-wrap;line-height:1.7">'+esc(r.report||'')+'</div></details>';}).join('');}catch{}}
function init(){loadOv();_loadBanner();setInterval(loadOv,30000);}
if(_t){document.getElementById('login').style.display='none';document.getElementById('app').style.display='block';init();}
</script></body></html>`;
