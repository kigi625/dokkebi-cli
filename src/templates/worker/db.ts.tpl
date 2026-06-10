// @dokkebi-version: 10
// worker/api/_dokkebi/db.ts
// Cloudflare Pages Function — DB 프록시 (D1 세션 + AES-256-GCM 양방향 암호화 + Nonce 재전송 방어)
//
// POST /api/_dokkebi/db {enc, iv, nonce, ts, sig, sid} → {_enc, enc, iv}
//
// 성능 최적화:
//   - 인메모리 세션 캐시 (아이솔레이트 단위) → 핫패스에서 D1 세션 조회 제거
//   - 인메모리 Nonce Set → 즉시 중복 검사, D1은 백그라운드 기록
//   - 사용자 쿼리만 블로킹 D1 호출 (핫패스 ~100-200ms 목표)

import { denormalizeDbPayload, verifyAndStripPowDb, encBytesToB64 } from './_payloadWire.js';

export interface Env {
  DB: D1Database;
  DOKKEBI_SERVER_JWK: string;
  DOKKEBI_SESSION_SECRET: string;
  // Authorization Policy (Stage 4) — 선택. 규칙이 있는 경우에만 필요.
  DOKKEBI_JWT_SECRET?: string;
  /** 앱 로그인 JWT 서명과 동일할 때 DOKKEBI_JWT_SECRET 대신 사용 가능 */
  JWT_SECRET?: string;
  // Signed Unlock Token — secretEnv 로 이름 변경 가능하지만 기본값은 이것입니다.
  DOKKEBI_CAPABILITY_SECRET?: string;
  [key: string]: unknown;
}

interface DbResult {
  rows: string[];
  affected: number;
  lastInsertId: number;
}

interface CachedSession {
  encKey: CryptoKey;
  sigKey: CryptoKey;
  created_at: number;
  tenantJson: string | null;
  // Phase 1-① monotonic request counter (per-session, in-memory only).
  // 클라이언트가 보낸 nonce 의 '{sid}:{counter}:{rand}' 카운터가
  // 이전 값보다 커야만 통과 → 세션 내 순서 강제.
  lastCounter: number;
  // Phase 2-⑤ per-session token bucket (DoS pre-gate).
  bucketTokens: number;
  bucketRefillAt: number;
  // Phase 2-⑦ mutation budget counters (sliding window start).
  writeWindowStart: number;
  writeCount: number;
  deleteWindowStart: number;
  deleteCount: number;
}

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

// ── Replay 방어 파라미터 (dokkebi.config.js → security.replay) ──
//   normalizeReplayConfig() 에서 안전 범위로 clamp 된 값이 주입됩니다.
const _replayCfg: any = __DOKKEBI_PH_REPLAY__;
const TIMESTAMP_WINDOW_MS = Number(_replayCfg?.timestampWindowMs ?? 5_000);
const NONCE_TTL_MS = Number(_replayCfg?.nonceTtlMs ?? 35_000);

// ── Phase 1-② Envelope size cap (pre-crypto) ───────────────
//   Content-Length 가 이 값을 초과하면 JSON 파싱 전에 413 반환.
//   security.replay.maxEnvelopeBytes / preGate (기본 512KB, 미임베드 시 폴백 동일).
const MAX_ENVELOPE_BYTES = Number(_replayCfg?.maxEnvelopeBytes ?? 512 * 1024);

// ── Phase B — Sharding-aware DB resolver (build-time injected) ─
//   단일 D1 모드:    `_internalDb(env)` === env.DB,  `_userDbForSql(env, sql)` === env.DB
//   샤딩 모드:        `_internalDb(env)` = env[GLOBAL || SHARDS[0]],
//                    `_userDbForSql(env, sql)` 은 사용자 SQL 의 샤드 키 값으로 라우팅 (Phase B 후속 PR).
//   본 헬퍼는 빌드 타임 placeholder 를 통해 단일/샤딩을 동일 코드 경로에서 처리합니다.
//   placeholder 가 미치환된 경우(=옛 빌드/누락) 안전한 폴백으로 env.DB 를 사용합니다.
const _DOKKEBI_INTERNAL_BINDING: string = '__DOKKEBI_PH_INTERNAL_BINDING__' || 'DB';
const _DOKKEBI_SHARD_BINDINGS: string[] = (function() {
  try {
    const raw: any = __DOKKEBI_PH_SHARD_BINDINGS__;
    return Array.isArray(raw) ? raw.filter((x: any) => typeof x === 'string') : [];
  } catch { return []; }
})();
function _internalDb(env: Env): D1Database {
  const b = (env as any)[_DOKKEBI_INTERNAL_BINDING];
  if (b) return b as D1Database;
  return env.DB; // 폴백 (placeholder 미치환 / 단일 D1 / 호환)
}
function _userDbForSql(env: Env, _sql?: string): D1Database {
  // Phase B-1: 사용자 SQL 라우팅은 후속 PR (B-2). 현재는 internal 과 동일 동작 → 단일 D1 호환 보장.
  return _internalDb(env);
}

// ── Phase B (B-3) — D1 Sessions 자동 적용 ─────────────────────
//   dokkebi.config.js → database.sessions.{enabled, mode}
//   normalizeDatabaseConfig 결과의 sessions 객체를 빌드 타임에 주입.
//   기본: { enabled:false, mode:'first-unconstrained' } — 옵트인.
const _SESSIONS_CFG: any = __DOKKEBI_PH_SESSIONS__;
const _SESSIONS_ENABLED: boolean = !!(_SESSIONS_CFG && _SESSIONS_CFG.enabled);
const _SESSIONS_MODE_DEFAULT: 'first-unconstrained' | 'first-primary' =
  (_SESSIONS_CFG && _SESSIONS_CFG.mode === 'first-primary') ? 'first-primary' : 'first-unconstrained';
const _BOOKMARK_COOKIE = '__d1b';
const _BOOKMARK_MAX_LEN = 1024;

function _readBookmarkCookie(req: Request): string | null {
  if (!_SESSIONS_ENABLED) return null;
  const c = req.headers.get('Cookie') || '';
  if (!c) return null;
  const m = c.match(/(?:^|;\s*)__d1b=([^;]+)/);
  if (!m) return null;
  const v = decodeURIComponent(m[1] || '').slice(0, _BOOKMARK_MAX_LEN);
  return v || null;
}
/** 사용자 SQL/배치 실행 시 사용할 D1Database — Sessions 활성 시 withSession 적용. */
function _withMaybeSession(
  db: D1Database,
  req: Request,
  isReadOnly: boolean,
): { db: D1Database; using: 'replica' | 'primary' | 'off'; bookmark: string | null } {
  if (!_SESSIONS_ENABLED || typeof (db as any).withSession !== 'function') {
    return { db, using: 'off', bookmark: null };
  }
  const cookieBookmark = _readBookmarkCookie(req);
  // 우선순위: cookie bookmark > read 모드별 기본값
  if (cookieBookmark) {
    return { db: (db as any).withSession(cookieBookmark) as D1Database, using: 'replica', bookmark: cookieBookmark };
  }
  if (isReadOnly) {
    return { db: (db as any).withSession('first-unconstrained') as D1Database, using: 'replica', bookmark: null };
  }
  return { db: (db as any).withSession(_SESSIONS_MODE_DEFAULT === 'first-primary' ? 'first-primary' : 'first-unconstrained') as D1Database, using: 'primary', bookmark: null };
}
/**
 * Worker 응답 헤더(plain object)에 새 D1 bookmark 를 `Set-Cookie` 로 부착.
 * 같은 객체에 'Set-Cookie' 가 이미 있으면 배열로 누적.
 */
function _appendBookmarkCookie(headersObj: Record<string, any>, db: D1Database, prev: string | null): void {
  if (!_SESSIONS_ENABLED || !headersObj) return;
  let bm: string | null = null;
  try {
    if (typeof (db as any).getBookmark === 'function') bm = (db as any).getBookmark();
  } catch { bm = null; }
  if (!bm || bm === prev) return;
  const safe = encodeURIComponent(String(bm).slice(0, _BOOKMARK_MAX_LEN));
  const cookieStr = `${_BOOKMARK_COOKIE}=${safe}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`;
  const existing = headersObj['Set-Cookie'];
  if (Array.isArray(existing)) existing.push(cookieStr);
  else if (typeof existing === 'string') headersObj['Set-Cookie'] = [existing, cookieStr];
  else headersObj['Set-Cookie'] = cookieStr;
}

// ── Phase 2-⑤ Per-session token bucket (DoS pre-gate) ──────
//   timestamp/nonce 체크보다도 먼저 실행되는 가장 저렴한 관문.
//   security.preGate.rpm 으로 조정 가능 (기본 300req/min).
const _PREGATE_RPM = Number(_replayCfg?.pregate?.rpm ?? 300);
const _BUCKET_CAPACITY = Math.max(10, Math.min(10_000, _PREGATE_RPM));
const _BUCKET_REFILL_MS = Math.max(50, Math.floor(60_000 / Math.max(1, _PREGATE_RPM)));

// ── Phase 2-⑦ Mutation budget (per-session, sliding window) ─
//   WRITE (INSERT/UPDATE/DELETE) 및 DELETE 의 분당 상한.
//   security.mutationBudget.{writesPerMinute,deletesPerMinute} 로 조정.
const _WRITE_CAP_PER_MIN = Number(_replayCfg?.mutationBudget?.writesPerMinute ?? 120);
const _DELETE_CAP_PER_MIN = Number(_replayCfg?.mutationBudget?.deletesPerMinute ?? 30);
const _MUTATION_WINDOW_MS = 60_000;

// ── Phase 1-③ 빌드 메타데이터 (공급망 tripwire) ─────────────
//   운영자가 관제 패널에서 현재 프로덕션 워커가 어느 git SHA · 컨트롤러
//   해시 기반으로 빌드됐는지 확인할 수 있도록 embed.
const _buildMeta: any = __DOKKEBI_PH_BUILD_META__;

// ── Bundle Attestation — 빌드 시 임베드된 청크 해시 매니페스트 ─
//   buildMeta.attestation 에 들어있는 hashes[] 와 클라이언트가 응답한 청크
//   해시를 비교해, 사용자 디바이스가 실제로 “이 빌드의 암호화 번들 바이트”
//   를 들고 있는지(=원본 번들 사용중인지) 확인한다.
//   enabled: false 시 모든 attestation 경로는 no-op.
const _attestMeta: any = (_buildMeta && _buildMeta.attestation) || null;
const _ATTEST_ENABLED: boolean = !!(_attestMeta && Array.isArray(_attestMeta.hashes) && _attestMeta.hashes.length > 0);
const _ATTEST_TTL_MS: number = Math.max(30_000, Math.min(30 * 60_000, Number(_attestMeta?.ttlMs || 5 * 60_000)));
const _ATTEST_SAMPLE: number = Math.max(1, Math.min(16, Number(_attestMeta?.sampleSize || 4)));
// sid → { ok: true, until: number } 인메모리 캐시 (TTL 내 attest 통과 세션).
const _attestPassMap = new Map<string, number>();
// sid → { challenge: string[], indices: number[], exp: number }
//   _attestChallenge 발급 시 저장되고, 클라이언트 응답에서 1회 사용 후 폐기.
const _attestChalMap = new Map<string, { nonce: string; indices: number[]; exp: number }>();
function _attestPrune(now: number) {
  if (_attestPassMap.size > 2000) {
    for (const [k, until] of _attestPassMap) { if (until <= now) _attestPassMap.delete(k); }
  }
  if (_attestChalMap.size > 2000) {
    for (const [k, v] of _attestChalMap) { if (!v || v.exp <= now) _attestChalMap.delete(k); }
  }
}
function _attestRandomIndices(): number[] {
  const total = Number(_attestMeta?.count || 0);
  if (total <= 0) return [];
  const want = Math.min(_ATTEST_SAMPLE, total);
  const set = new Set<number>();
  while (set.size < want) {
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    set.add(buf[0] % total);
  }
  return Array.from(set).sort((a, b) => a - b);
}
async function _attestSha256Hex(input: ArrayBuffer | Uint8Array): Promise<string> {
  const buf = input instanceof Uint8Array ? input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) : input;
  const digest = await crypto.subtle.digest('SHA-256', buf);
  const arr = new Uint8Array(digest);
  let out = '';
  for (let i = 0; i < arr.length; i++) out += arr[i].toString(16).padStart(2, '0');
  return out;
}

// ── Cryptographic Checkpoint — Signed Unlock Token ───────────
//   브라우저/WASM 내부의 단순 권한 플래그 변조를 어렵게 하기 위한 opt-in
//   capability layer. 토큰 서명은 클라이언트 세션 sigKey 가 아니라 Worker-only
//   secretEnv 로 수행한다.
const _capabilityMeta: any = __DOKKEBI_PH_CAPABILITY__;

// ── Phase 3 (ADL) — Active Defense Layer 설정 ───────────────
//   security.activeDefense 섹션에서 normalizeActiveDefenseConfig() 로 정규화.
//   enabled: false 면 모든 경로가 no-op → 추가 지연/D1 호출 0.
//   trigger: 'lazy' (기본) — Cron Trigger 없이 핫패스 ctx.waitUntil 로 동작.
//   sampleRate: 0.01 — 1% 요청에서만 트리거 검사 → 다수 사이트 무료 운영.
const _adlCfg: any = __DOKKEBI_PH_ADL__;
const _ADL_ENABLED: boolean = !!_adlCfg?.enabled;
const _ADL_MODE: string = String(_adlCfg?.mode || 'monitor').toLowerCase();
const _ADL_INTERVAL_MS: number = Math.max(60_000, Math.floor(Number(_adlCfg?.intervalMs ?? 5 * 60_000)));
const _ADL_SAMPLE_RATE: number = Math.max(0, Math.min(1, Number(_adlCfg?.sampleRate ?? 0.01)));
const _ADL_RISK_BLOCK: number = Math.max(0, Math.min(1, Number(_adlCfg?.riskBlockThreshold ?? 0.85)));
const _ADL_VERSION: number = Number(_adlCfg?.version ?? 1);

// ── 아이솔레이트 레벨 인메모리 캐시 ──────────────────────────
const _sessionCache = new Map<string, CachedSession>();
const _nonceMap = new Map<string, number>();
let _noncePruneAt = 0;

// Phase 3-A — ADL 인메모리 LRU 캐시 (핫패스 D1 호출 흡수).
//   blacklist: key=ip|sid|ipua → { hit, score, until }. miss 도 캐시(negative cache).
//   risk:      sid           → { score, factors, until }.
//   TTL 60초 — Cron 분석 주기보다 짧게 잡아 갱신 반영 빠름.
const _adlBlMap = new Map<string, { hit: boolean; kind: string; reason: string; score: number; until: number }>();
const _adlRiskMap = new Map<string, { score: number; factors: string; until: number }>();
const _ADL_CACHE_TTL_MS = 60_000;
const _ADL_CACHE_MAX = 1000;
function _adlCachePrune<T>(map: Map<string, T>) {
  if (map.size <= _ADL_CACHE_MAX) return;
  const drop = map.size - _ADL_CACHE_MAX;
  let i = 0;
  for (const k of map.keys()) { if (i++ >= drop) break; map.delete(k); }
}

// Phase 2-⑤ — 세션 캐시가 아직 없을 때(콜드패스 직전) 임시로 토큰 버킷을
// 유지하기 위한 Map. 프루닝: 10분 아이들 시 제거.
const _pregateTmp = new Map<string, { tokens: number; refillAt: number }>();
let _pregateTmpPruneAt = 0;
function prunePregateTmp() {
  const now = Date.now();
  if (now < _pregateTmpPruneAt) return;
  _pregateTmpPruneAt = now + 60_000;
  for (const [k, v] of _pregateTmp) {
    if (now - v.refillAt > 10 * 60_000) _pregateTmp.delete(k);
  }
}

// v5.1 업그레이드용 — 기존 DB 의 _dokkebi_sessions 테이블에 tenant_json 컬럼이
// 없을 경우 ALTER 로 추가. handshake 에서도 실행되지만, 이미 세션을 보유한
// 기존 클라이언트는 핸드셰이크를 재호출하지 않으므로 db 엔드포인트에서도
// 한 번 보장해둔다. SQLite 는 IF NOT EXISTS 미지원이라 try/catch 로 처리.
let _sessionsMigrated = false;
async function _ensureSessionsMigration(db: D1Database) {
  if (_sessionsMigrated) return;
  _sessionsMigrated = true;
  try {
    await db.prepare(`ALTER TABLE _dokkebi_sessions ADD COLUMN tenant_json TEXT`).run();
  } catch { /* 컬럼 이미 존재 → 무시 */ }
}

function pruneNonces() {
  const now = Date.now();
  if (now < _noncePruneAt) return;
  _noncePruneAt = now + NONCE_TTL_MS;
  for (const [k, ts] of _nonceMap) {
    if (now - ts > NONCE_TTL_MS) _nonceMap.delete(k);
  }
}

function pruneSessionCache() {
  const now = Date.now();
  for (const [k, v] of _sessionCache) {
    if (now - v.created_at > SESSION_TTL_MS) _sessionCache.delete(k);
  }
}

// ── Phase 3-A — ADL 테이블 부트스트랩 ───────────────────────────
//   db.ts 핫패스 첫 호출 시 1회만 보장. Cron 없이도 동작 가능.
//   _dokkebi_blacklist  : (key,kind) PK. kind ∈ {'ip','sid','ipua'}.
//   _dokkebi_risk_score : sid PK. 0~1 점수.
//   _dokkebi_adl_state  : 분석 last_run/cursor 등 메타.
let _adlTablesReady = false;
async function _ensureAdlTables(db: D1Database) {
  if (_adlTablesReady) return;
  _adlTablesReady = true;
  try {
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_blacklist (
        key TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT, score REAL DEFAULT 0,
        expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
        PRIMARY KEY (key, kind)
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS _dokkebi_bl_exp ON _dokkebi_blacklist (expires_at)`),
      db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_risk_score (
        sid TEXT PRIMARY KEY, score REAL NOT NULL, factors TEXT, updated_at INTEGER NOT NULL
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_adl_state (
        key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER NOT NULL
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS _dokkebi_adl_suspicion (
        key TEXT NOT NULL, kind TEXT NOT NULL, reason TEXT, score REAL DEFAULT 0,
        expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
        PRIMARY KEY (key, kind)
      )`),
      db.prepare(`CREATE INDEX IF NOT EXISTS _dokkebi_susp_exp ON _dokkebi_adl_suspicion (expires_at)`),
    ]);
  } catch { _adlTablesReady = false; /* 다음 요청에서 재시도 */ }
}

// ── Phase 3-A — Blacklist/Risk 핫패스 lookup ─────────────────────
//   캐시 hit 면 D1 호출 0회. miss → D1 SELECT 1회 (negative 결과도 캐싱).
//   ip / sid 둘 중 하나라도 만료되지 않은 항목이 있으면 차단 후보.
async function _adlLookup(db: D1Database, ip: string, sid: string): Promise<{ kind: string; reason: string; score: number } | null> {
  if (!_ADL_ENABLED) return null;
  const now = Date.now();
  // 캐시 lookup (ip + sid)
  const ipCached = _adlBlMap.get('ip:' + ip);
  const sidCached = sid ? _adlBlMap.get('sid:' + sid) : null;
  const fromCache = (c: { hit: boolean; kind: string; reason: string; score: number; until: number } | undefined | null) => (c && c.until > now) ? c : null;
  const cIp = fromCache(ipCached); const cSid = fromCache(sidCached);
  let hit: { hit: boolean; kind: string; reason: string; score: number } | null = null;
  if (cIp && cIp.hit) hit = cIp;
  else if (cSid && cSid.hit) hit = cSid;
  if (cIp && cSid && !cIp.hit && !cSid.hit) {
    // 둘 다 negative 캐시 → 추가 D1 호출 없이 통과
    return await _adlRiskCheck(db, sid, now);
  }

  // 캐시 미스 → D1 1회 SELECT (ip, sid 동시 조회).
  if (!hit) {
    try {
      const res = await db.prepare(
        `SELECT key, kind, reason, score, expires_at FROM _dokkebi_blacklist
           WHERE expires_at > ? AND (
             (kind = 'ip' AND key = ?) OR
             (kind = 'sid' AND key = ?)
           ) LIMIT 4`
      ).bind(now, ip || '', sid || '').all<{ key: string; kind: string; reason: string; score: number; expires_at: number }>();
      const rows = res.results || [];
      // 결과 캐싱
      const ipRow = rows.find(r => r.kind === 'ip' && r.key === ip);
      const sidRow = rows.find(r => r.kind === 'sid' && r.key === sid);
      const ttl = now + _ADL_CACHE_TTL_MS;
      if (ip) _adlBlMap.set('ip:' + ip, ipRow
        ? { hit: true, kind: 'ip', reason: ipRow.reason || '', score: ipRow.score || 1, until: Math.min(ipRow.expires_at, ttl) }
        : { hit: false, kind: 'ip', reason: '', score: 0, until: ttl });
      if (sid) _adlBlMap.set('sid:' + sid, sidRow
        ? { hit: true, kind: 'sid', reason: sidRow.reason || '', score: sidRow.score || 1, until: Math.min(sidRow.expires_at, ttl) }
        : { hit: false, kind: 'sid', reason: '', score: 0, until: ttl });
      _adlCachePrune(_adlBlMap);
      if (ipRow) hit = { hit: true, kind: 'ip', reason: ipRow.reason || '', score: ipRow.score || 1 };
      else if (sidRow) hit = { hit: true, kind: 'sid', reason: sidRow.reason || '', score: sidRow.score || 1 };
    } catch { /* D1 일시 장애 — 통과 (정적방어가 1차 차단) */ }
  }
  if (hit) return { kind: hit.kind, reason: hit.reason, score: hit.score };
  return await _adlRiskCheck(db, sid, now);
}

async function _adlRiskCheck(db: D1Database, sid: string, now: number): Promise<{ kind: string; reason: string; score: number } | null> {
  if (!sid) return null;
  const cached = _adlRiskMap.get(sid);
  if (cached && cached.until > now) {
    if (cached.score >= _ADL_RISK_BLOCK) return { kind: 'risk', reason: cached.factors || 'risk_score', score: cached.score };
    return null;
  }
  try {
    const r = await db.prepare(
      `SELECT score, factors FROM _dokkebi_risk_score WHERE sid = ? LIMIT 1`
    ).bind(sid).first<{ score: number; factors: string | null }>();
    const score = r ? Number(r.score || 0) : 0;
    const factors = r?.factors || '';
    _adlRiskMap.set(sid, { score, factors, until: now + _ADL_CACHE_TTL_MS });
    _adlCachePrune(_adlRiskMap);
    if (score >= _ADL_RISK_BLOCK) return { kind: 'risk', reason: factors || 'risk_score', score };
  } catch { /* 무시 */ }
  return null;
}

// ── Phase 3-A — Lazy Cron 트리거 (확률적, ctx.waitUntil) ─────────
//   sampleRate 비율로만 last_run 검사 → 다수 사이트 운영 시 D1 read 절감.
//   분산락(쓰기 1회) 으로 동시 실행 방지: AdlState 의 last_run 갱신이 changes=1 일 때만 분석 진행.
async function _maybeRunADL(db: D1Database) {
  if (!_ADL_ENABLED) return;
  await _ensureAdlTables(db);
  const now = Date.now();
  try {
    const r = await db.prepare(
      `SELECT value FROM _dokkebi_adl_state WHERE key = 'last_run' LIMIT 1`
    ).first<{ value: string | null }>();
    const last = r ? Number(r.value || 0) : 0;
    if (now - last < _ADL_INTERVAL_MS) return;

    // 분산락: 동일 last 값을 본 워커만 갱신 성공.
    const upd = await db.prepare(
      `UPDATE _dokkebi_adl_state SET value = ?, updated_at = ? WHERE key = 'last_run' AND (CAST(value AS INTEGER) = ? OR value IS NULL)`
    ).bind(String(now), now, last).run();
    const changes = (upd as any)?.meta?.changes ?? (upd as any)?.changes ?? 0;
    if (changes === 0) {
      // 행이 없거나 다른 워커가 먼저 갱신함. 행이 없는 경우 INSERT 시도.
      const ins = await db.prepare(
        `INSERT OR IGNORE INTO _dokkebi_adl_state (key, value, updated_at) VALUES ('last_run', ?, ?)`
      ).bind(String(now), now).run();
      const insCh = (ins as any)?.meta?.changes ?? (ins as any)?.changes ?? 0;
      if (insCh === 0) return; // 다른 워커가 처리 중
    }

    await _runActiveDefenseAnalysis(db, now);
  } catch { /* 분석 실패 — 다음 주기에 재시도 */ }
}

// ── Phase 3-B — 통계 룰엔진 ───────────────────────────────────────
//   pure SQL aggregation 만 사용 (외부 의존성 0).
//   1) IP 빈도 Z-score : _dokkebi_requests 5분 윈도우. mean+stdev 보다 σ 큰 IP 차단.
//   2) IP 실패율       : _dokkebi_security 10분 윈도우. 임계 초과 IP 차단.
//   3) 세션 risk_score : 보안 이벤트 1시간 가중합 → risk_score 갱신.
async function _runActiveDefenseAnalysis(db: D1Database, now: number) {
  const ttl1h = 60 * 60 * 1000;
  const ttl30m = 30 * 60 * 1000;
  const ipBlockUntil = now + ttl1h;
  const ipBlockUntilShort = now + ttl30m;
  /** monitor: 자동 분석 결과는 의심 목록만 — 실제 차단(blacklist)은 수동 추가·enforce 에서만 */
  const adlTbl = _ADL_MODE === 'monitor' ? '_dokkebi_adl_suspicion' : '_dokkebi_blacklist';

  // 1) IP 빈도 이상치 — 평균 + 3σ 초과시 1시간 차단.
  let abuseIps: { ip: string; cnt: number }[] = [];
  try {
    const r = await db.prepare(
      `SELECT ip, COUNT(*) as cnt FROM "_dokkebi_requests"
         WHERE ts >= datetime('now','-5 minutes') AND ip <> ''
         GROUP BY ip HAVING cnt > 30 ORDER BY cnt DESC LIMIT 100`
    ).all<{ ip: string; cnt: number }>();
    abuseIps = (r.results || []).map(x => ({ ip: String(x.ip), cnt: Number(x.cnt) }));
  } catch { /* */ }

  if (abuseIps.length > 0) {
    const counts = abuseIps.map(a => a.cnt);
    const mean = counts.reduce((a, b) => a + b, 0) / counts.length;
    const variance = counts.reduce((a, b) => a + (b - mean) * (b - mean), 0) / Math.max(1, counts.length);
    const std = Math.sqrt(variance);
    const threshold = Math.max(60, mean + 3 * std);
    const stmts: D1PreparedStatement[] = [];
    for (const a of abuseIps) {
      if (a.cnt < threshold) continue;
      const z = std > 0 ? (a.cnt - mean) / std : 3;
      stmts.push(db.prepare(
        'INSERT INTO ' + adlTbl + ` (key, kind, reason, score, expires_at, created_at)
           VALUES (?, 'ip', ?, ?, ?, ?)
           ON CONFLICT(key, kind) DO UPDATE SET reason=excluded.reason, score=excluded.score, expires_at=excluded.expires_at`
      ).bind(a.ip, 'rate-anomaly: ' + a.cnt + 'req/5m (z=' + z.toFixed(1) + ')', Math.min(1, z / 6), ipBlockUntil, now));
    }
    if (stmts.length) try { await db.batch(stmts); } catch { /* */ }
  }

  // 2) IP 실패 누적 — 보안 이벤트 10분 5건 이상 → 30분 차단.
  try {
    const r = await db.prepare(
      `SELECT ip, COUNT(*) as cnt FROM "_dokkebi_security"
         WHERE ts >= datetime('now','-10 minutes') AND ip <> '' AND type <> 'query_fallback'
         GROUP BY ip HAVING cnt >= 5 ORDER BY cnt DESC LIMIT 50`
    ).all<{ ip: string; cnt: number }>();
    const stmts: D1PreparedStatement[] = [];
    for (const row of (r.results || [])) {
      stmts.push(db.prepare(
        'INSERT INTO ' + adlTbl + ` (key, kind, reason, score, expires_at, created_at)
           VALUES (?, 'ip', ?, ?, ?, ?)
           ON CONFLICT(key, kind) DO UPDATE SET reason=excluded.reason, score=excluded.score, expires_at=excluded.expires_at`
      ).bind(String(row.ip), 'security-fail: ' + row.cnt + ' events/10m', Math.min(1, Number(row.cnt) / 20), ipBlockUntilShort, now));
    }
    if (stmts.length) try { await db.batch(stmts); } catch { /* */ }
  } catch { /* */ }

  // 3) 세션별 risk_score — 1시간 보안 이벤트 가중합.
  //    HMAC fail = 0.4, replay = 0.3, sql_inject = 0.5, mutation_budget = 0.2
  try {
    const r = await db.prepare(
      `SELECT detail, type, COUNT(*) as cnt FROM "_dokkebi_security"
         WHERE ts >= datetime('now','-60 minutes')
         GROUP BY detail, type LIMIT 500`
    ).all<{ detail: string; type: string; cnt: number }>();
    // detail 에서 sid 추출 — 현재 detail 포맷에 sid 미포함 → IP 기준으로만 누적 (확장 여지)
    // 여기서는 sid 추적이 어려우므로 별도 풀 테이블 (_dokkebi_risk_score) 은 비워두고
    // 추후 _setTenant 등에서 sid+detail 결합 시 활성화할 수 있도록 자리만 마련.
    void r;
  } catch { /* */ }

  // 4) 만료 항목 정리 (가벼운 GC).
  try {
    await db.prepare(`DELETE FROM _dokkebi_blacklist WHERE expires_at <= ?`).bind(now).run();
  } catch { /* */ }
  try {
    await db.prepare(`DELETE FROM _dokkebi_adl_suspicion WHERE expires_at <= ?`).bind(now).run();
  } catch { /* */ }
}

// ── 로그 디듀프 캐시 (인메모리) ───────────────────────────────────
// 동일 이벤트가 짧은 시간에 폭주할 때 D1 write 비용을 줄입니다.
const _logDedup = new Map<string, number>();
const _LOG_DEDUP_TTL_MS = 15_000;
const _LOG_DEDUP_MAX = 2048;
function _pruneLogDedup(now: number) {
  if (_logDedup.size <= _LOG_DEDUP_MAX) return;
  for (const [k, until] of _logDedup) {
    if (until <= now) _logDedup.delete(k);
    if (_logDedup.size <= Math.floor(_LOG_DEDUP_MAX * 0.8)) break;
  }
}
function _shouldWriteLog(key: string, now: number): boolean {
  const until = _logDedup.get(key);
  if (until && until > now) return false;
  _logDedup.set(key, now + _LOG_DEDUP_TTL_MS);
  _pruneLogDedup(now);
  return true;
}

async function logSecurity(db: D1Database, type: string, ip: string, path: string, detail: string) {
  try {
    const now = Date.now();
    const dedupKey = ['sec', type, ip || '-', path || '-', String(detail || '').slice(0, 120)].join('|');
    if (!_shouldWriteLog(dedupKey, now)) return;
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    await db.prepare(
      `INSERT OR IGNORE INTO "_dokkebi_security" ("id","type","ip","path","detail") VALUES (?,?,?,?,?)`
    ).bind(id, type, ip, path, detail.slice(0, 500)).run();
  } catch { /* ignore */ }
}

async function logRequest(db: D1Database, method: string, path: string, status: number, durationMs: number, ip: string) {
  try {
    const now = Date.now();
    const statusClass = Math.floor(Number(status || 0) / 100);
    const dedupKey = ['req', method || '-', path || '-', String(statusClass), ip || '-'].join('|');
    if (!_shouldWriteLog(dedupKey, now)) return;
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    await db.prepare(
      `INSERT OR IGNORE INTO "_dokkebi_requests" ("id","method","path","status","duration_ms","ip") VALUES (?,?,?,?,?,?)`
    ).bind(id, method, path, status, durationMs, ip).run();
  } catch { /* ignore */ }
}

async function logError(db: D1Database, source: string, message: string, code: string, table: string) {
  try {
    const now = Date.now();
    const dedupKey = ['err', source || '-', String(message || '').slice(0, 120), code || '-', table || '-'].join('|');
    if (!_shouldWriteLog(dedupKey, now)) return;
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const detail = code ? code + (table ? ' table=' + table : '') : '';
    await db.prepare(
      `INSERT OR IGNORE INTO "_dokkebi_errors" ("id","source","level","message","stack") VALUES (?,?,?,?,?)`
    ).bind(id, source, 'error', message.slice(0, 1000), detail.slice(0, 500)).run();
  } catch { /* ignore */ }
}

function _summarizeDbAudit(sql: string, queryId: string | undefined, params: unknown[], result: any, durationMs: number) {
  try {
    const upper = stripStringsAndComments(sql).replace(/\s+/g, ' ').trim().toUpperCase();
    let op = 'OTHER';
    if (upper.startsWith('SELECT') || upper.startsWith('WITH')) op = 'SELECT';
    else if (upper.startsWith('INSERT')) op = 'INSERT';
    else if (upper.startsWith('UPDATE')) op = 'UPDATE';
    else if (upper.startsWith('DELETE')) op = 'DELETE';
    const table = detectPrimaryTable(upper, op) || '';
    const affected = Number(result?.affected ?? 0);
    const qid = queryId ? String(queryId).slice(0, 48) : '-';
    return `op=${op} table=${table || '-'} qid=${qid} params=${params.length} affected=${affected} dur=${durationMs}`;
  } catch {
    return `qid=${queryId ? String(queryId).slice(0, 48) : '-'} params=${params.length} dur=${durationMs}`;
  }
}

const SQL_MAX_LENGTH = 50_000;

// ─────────────────────────────────────────────────────────────
// SQL 검증 (서버리스/Pages Function 버전)
//   로컬 dok serve 의 sqlAllowlist.js 와 동일한 방어 로직을
//   Cloudflare Workers 런타임(Buffer 없음, Web Crypto) 환경에
//   맞춰 포팅한 버전입니다.
// ─────────────────────────────────────────────────────────────

// 위험 토큰 — 파서 수준에서 전수 차단
const DANGEROUS_TOKENS = [
  'ATTACH', 'DETACH',
  'PRAGMA',
  'EXEC', 'EXECUTE',
  'LOAD_EXTENSION',
  'INTO OUTFILE', 'INTO DUMPFILE',
  'LOAD DATA',
  'COPY',
  'INFORMATION_SCHEMA',
  'PG_SLEEP', 'SLEEP(',
  'BENCHMARK(',
  'WAITFOR',
  'XP_', 'SP_EXECUTESQL',
];

function stripStringsAndComments(sql: string): string {
  let out = '';
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const ch = sql[i];
    const next = sql[i + 1];
    if (ch === '-' && next === '-') {
      while (i < n && sql[i] !== '\n') i++;
      out += ' ';
      continue;
    }
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i++;
      i += 2;
      out += ' ';
      continue;
    }
    if (ch === "'") {
      i++;
      while (i < n) {
        if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; }
        if (sql[i] === "'") { i++; break; }
        i++;
      }
      out += " '' ";
      continue;
    }
    if (ch === '"') {
      out += '"';
      i++;
      while (i < n) {
        if (sql[i] === '"' && sql[i + 1] === '"') { i += 2; continue; }
        if (sql[i] === '"') { out += '"'; i++; break; }
        out += sql[i];
        i++;
      }
      continue;
    }
    if (ch === '`') {
      out += '`';
      i++;
      while (i < n && sql[i] !== '`') { out += sql[i]; i++; }
      if (sql[i] === '`') { out += '`'; i++; }
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

function hasMultipleStatements(normalized: string): boolean {
  const trimmed = normalized.replace(/;\s*$/, '');
  return /;/.test(trimmed);
}

function containsDangerousToken(normalizedUpper: string): string | null {
  for (const token of DANGEROUS_TOKENS) {
    const needle = token.replace(/\s+/g, ' ');
    if (needle.endsWith('(')) {
      if (normalizedUpper.includes(needle)) return token;
    } else {
      const idx = normalizedUpper.indexOf(needle);
      if (idx === -1) continue;
      const before = normalizedUpper[idx - 1];
      const after  = normalizedUpper[idx + needle.length];
      const isBoundary = (c: string | undefined) => c === undefined || !/[A-Z0-9_]/.test(c);
      if (isBoundary(before) && (needle.includes(' ') || isBoundary(after))) return token;
    }
  }
  return null;
}

function extractCteNames(normalizedUpper: string): Set<string> {
  const names = new Set<string>();
  const withMatch = /^\s*WITH\s+(?:RECURSIVE\s+)?(.+?)\b(SELECT|INSERT|UPDATE|DELETE)\b/is.exec(normalizedUpper);
  if (!withMatch) return names;
  const cteBlock = withMatch[1];
  const re = /\b([A-Z_][\w]*)\s*(?:\([^)]*\))?\s+AS\s*\(/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(cteBlock)) !== null) {
    names.add(m[1].toLowerCase());
  }
  return names;
}

function extractAllTables(normalized: string): string[] {
  const tables = new Set<string>();
  const upper = normalized.toUpperCase();
  const cteNames = extractCteNames(upper);
  const ident = '["\'`]?([a-zA-Z_][\\w]*(?:\\.[a-zA-Z_][\\w]*)?)["\'`]?';
  const keywords = ['FROM', 'JOIN', 'INTO', 'UPDATE'];
  for (const kw of keywords) {
    const re = new RegExp('\\b' + kw + '\\s+' + ident, 'gi');
    let m: RegExpExecArray | null;
    while ((m = re.exec(normalized)) !== null) {
      const name = m[1];
      const parts = name.split('.');
      const baseName = parts[parts.length - 1];
      if (cteNames.has(baseName.toLowerCase())) continue;
      tables.add(baseName);
    }
  }
  return [...tables];
}

function detectPrimaryOp(normalizedUpper: string): string | null {
  const head = normalizedUpper.trimStart();
  if (head.startsWith('SELECT'))   return 'SELECT';
  if (head.startsWith('INSERT'))   return 'INSERT';
  if (head.startsWith('UPDATE'))   return 'UPDATE';
  if (head.startsWith('DELETE'))   return 'DELETE';
  if (head.startsWith('WITH'))     return 'SELECT';
  if (head.startsWith('CREATE TABLE')) return 'CREATE';
  return null;
}

function detectPrimaryTable(normalizedUpper: string, op: string): string | null {
  const ident = '["\'`]?([A-Z_][\\w]*(?:\\.[A-Z_][\\w]*)?)["\'`]?';
  const patterns: Record<string, RegExp> = {
    SELECT: new RegExp('\\bFROM\\s+' + ident),
    INSERT: new RegExp('\\bINTO\\s+' + ident),
    UPDATE: new RegExp('\\bUPDATE\\s+' + ident),
    DELETE: new RegExp('\\bFROM\\s+' + ident),
  };
  const p = patterns[op];
  if (!p) return null;
  const m = normalizedUpper.match(p);
  if (!m) return null;
  const parts = m[1].split('.');
  return parts[parts.length - 1];
}

function validateSql(sql: string): { ok: boolean; reason?: string } {
  if (!sql || typeof sql !== 'string') return { ok: false, reason: 'SQL이 비어 있습니다.' };
  if (sql.length > SQL_MAX_LENGTH) return { ok: false, reason: `SQL이 너무 깁니다. (최대 ${SQL_MAX_LENGTH}자)` };
  return { ok: true };
}

// ── SQL Allowlist (빌드 타임 임베드) ─────────────────────
//   dok build 시점에 생성된 sql-allowlist.json 의 내용이
//   이 상수에 직접 치환됩니다. DB 왕복 없음, 배포와 allowlist
//   는 항상 원자적으로 동일 버전입니다.
//   null = 초기 생성 직후(dok build 미실행). strict 모드에서는
//   전 쿼리 거부되므로 반드시 dok build 로 갱신해야 합니다.
const _sqlAllowlist: any = __DOKKEBI_PH_ALLOWLIST__;

// 과거 버전(@dokkebi-version: 3) 호환용 — no-op.
async function loadSqlAllowlist(_db: D1Database): Promise<void> {
  return;
}

// ── Query Registry (Stage 3, 빌드 타임 임베드) ────────────
//   dok build 가 수집한 { queryId -> { sql, op, tables, paramCount, ... } } 맵.
//   null 인 경우 strict 모드에서는 queryId 기반 쿼리를 모두 거부합니다.
//   문서: docs/design/QUERY_REGISTRY.md
const _queryRegistry: any = __DOKKEBI_PH_REGISTRY__;

function lookupRegistryEntry(queryId: string): { sql: string; entry: any } | null {
  if (!_queryRegistry || !_queryRegistry.queries) return null;
  const entry = _queryRegistry.queries[queryId];
  if (!entry || typeof entry.sql !== 'string') return null;
  return { sql: entry.sql, entry };
}

// IN 절 정규화: IN (?, ?, ...) → IN (?) — canonicalizeSql 과 동일 규칙
function _normalizeInClauses(s: string): string {
  return s.replace(/\bIN \(\?(?:, \?)*\)/g, 'IN (?)');
}

// _debugSql 이 레지스트리 SQL 의 IN-변형인지 검증.
// IN 절 파라미터 수만 다르고 나머지 구조가 동일하면 true.
function _isValidInVariant(registrySql: string, debugSql: string): boolean {
  if (!debugSql || typeof debugSql !== 'string') return false;
  const normRegistry = _normalizeInClauses(registrySql);
  // debugSql 에도 최소한의 정규화 적용 (공백·키워드·IN 절)
  let s = debugSql.replace(/\s+/g, ' ').trim();
  s = s.replace(/\s*,\s*/g, ', ');
  s = s.replace(/\s*\(\s*/g, ' (').replace(/\s*\)\s*/g, ') ');
  s = s.replace(/\s+/g, ' ').trim();
  s = _normalizeInClauses(s);
  return normRegistry === s;
}

// ── Tenant Policy (Stage 1/2, 빌드 타임 임베드) ────────────
//   dokkebi.config.js 의 policy 섹션 → normalizePolicyConfig() → 여기 삽입.
//   mode:  off | verify | inject
//   policy.tables = { [tableName]: { tenantColumn, mode } }
//   문서: docs/design/TENANT_POLICY.md
const _policyMeta: any = __DOKKEBI_PH_POLICY__;

// ── Authorization Policy (Stage 4, 빌드 타임 임베드) ────────
//   dokkebi.config.js 의 authorization 섹션 → normalizeAuthorizationConfig().
//   규칙이 정의된 연산/테이블은 JWT 서명 검증 + role 체크를 반드시 통과해야
//   프록시가 쿼리를 실행합니다. Tenant Policy 는 row-level 격리를 담당하고
//   여기서는 "연산 레벨 권한"(예: DELETE posts 는 role=admin 만) 을 담당.
//   문서: docs/design/AUTHORIZATION.md
const _authzMeta: any = __DOKKEBI_PH_AUTHZ__;

// ── 워커측 로그인 메타 (C-1, 빌드 타임 임베드) ───────────────────────────
//   dokkebi.config.js 의 auth.login → normalizeAuthLoginConfig().
//   { enabled, query, passwordColumn, hash, claims, issuer?, audience?, expiresInSec?, bindTenant? }
//   비활성(null)이면 _login 명령은 LOGIN_DISABLED 로 거부된다.
const _authLoginMeta: any = __DOKKEBI_PH_AUTH_LOGIN__;

// JWT HMAC 키 캐시 (아이솔레이트 단위). 비밀값 변경 시 워커 재시작 필요.
let _authzJwtKey: CryptoKey | null = null;
let _authzJwtKeyPromise: Promise<CryptoKey> | null = null;
async function _az_getJwtKey(secret: string): Promise<CryptoKey> {
  if (_authzJwtKey) return _authzJwtKey;
  if (_authzJwtKeyPromise) return _authzJwtKeyPromise;
  _authzJwtKeyPromise = crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  ).then((k) => { _authzJwtKey = k; return k; });
  return _authzJwtKeyPromise;
}

function _az_b64urlToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const base64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(base64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function _az_verifyJwtHs256(token: string, env: Env): Promise<{ valid: boolean; reason?: string; payload?: any }> {
  if (!token) return { valid: false, reason: 'JWT 누락' };
  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, reason: 'JWT 형식 아님' };
  const [h64, p64, s64] = parts;
  let header: any, payload: any;
  try {
    header = JSON.parse(new TextDecoder().decode(_az_b64urlToBytes(h64)));
    payload = JSON.parse(new TextDecoder().decode(_az_b64urlToBytes(p64)));
  } catch { return { valid: false, reason: 'JWT 파싱 실패' }; }
  if (!header || header.alg !== 'HS256' || header.typ !== 'JWT') {
    return { valid: false, reason: '지원하지 않는 알고리즘 (HS256 만)' };
  }
  const secret =
    (typeof env.DOKKEBI_JWT_SECRET === 'string' && env.DOKKEBI_JWT_SECRET) ||
    (typeof env.JWT_SECRET === 'string' && env.JWT_SECRET) ||
    '';
  if (!secret) return { valid: false, reason: 'DOKKEBI_JWT_SECRET 또는 JWT_SECRET 미설정' };
  const key = await _az_getJwtKey(secret);
  const sig = _az_b64urlToBytes(s64);
  const data = new TextEncoder().encode(`${h64}.${p64}`);
  const ok = await crypto.subtle.verify('HMAC', key, sig, data);
  if (!ok) return { valid: false, reason: '서명 불일치' };

  const now = Date.now();
  const skewMs = ((_authzMeta && _authzMeta.clockSkewSec) || 30) * 1000;
  if (typeof payload.exp === 'number' && now > payload.exp * 1000 + skewMs) {
    return { valid: false, reason: '만료됨' };
  }
  if (typeof payload.nbf === 'number' && now + skewMs < payload.nbf * 1000) {
    return { valid: false, reason: 'nbf 미도달' };
  }
  if (_authzMeta?.issuer && payload.iss !== _authzMeta.issuer) {
    return { valid: false, reason: 'iss 불일치' };
  }
  if (_authzMeta?.audience) {
    const aud = payload.aud;
    const audList = Array.isArray(aud) ? aud : [aud];
    if (!audList.includes(_authzMeta.audience)) {
      return { valid: false, reason: 'aud 불일치' };
    }
  }
  return { valid: true, payload };
}

// ── C-1: 워커측 로그인 — DB 검증 + 워커 전용 시크릿 JWT 서명 ──────────────
//   클라이언트는 시크릿을 보유하지 않으며, 토큰 발급은 전적으로 워커에서만 일어난다.
//   비밀번호 저장 형식(hash='pbkdf2'): `pbkdf2$<iterations>$<saltB64url>$<hashB64url>`
let _authLoginSignKey: CryptoKey | null = null;
let _authLoginSignKeyPromise: Promise<CryptoKey> | null = null;
function _login_jwtSecret(env: Env): string {
  return (typeof (env as any).DOKKEBI_JWT_SECRET === 'string' && (env as any).DOKKEBI_JWT_SECRET) ||
         (typeof (env as any).JWT_SECRET === 'string' && (env as any).JWT_SECRET) || '';
}
async function _login_getSignKey(env: Env): Promise<CryptoKey | null> {
  const secret = _login_jwtSecret(env);
  if (!secret) return null;
  if (_authLoginSignKey) return _authLoginSignKey;
  if (_authLoginSignKeyPromise) return _authLoginSignKeyPromise;
  _authLoginSignKeyPromise = crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  ).then((k) => { _authLoginSignKey = k; return k; });
  return _authLoginSignKeyPromise;
}
async function _login_signJwt(env: Env, claims: Record<string, unknown>): Promise<string | null> {
  const key = await _login_getSignKey(env);
  if (!key) return null;
  const nowSec = Math.floor(Date.now() / 1000);
  const ttl = Number(_authLoginMeta?.expiresInSec) > 0 ? Number(_authLoginMeta.expiresInSec) : 3600;
  const payload: Record<string, unknown> = { ...claims, iat: nowSec, exp: nowSec + ttl };
  if (_authLoginMeta?.issuer) payload.iss = _authLoginMeta.issuer;
  if (_authLoginMeta?.audience) payload.aud = _authLoginMeta.audience;
  const h64 = _cap_b64url(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const p64 = _cap_b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const data = new TextEncoder().encode(h64 + '.' + p64);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
  return h64 + '.' + p64 + '.' + _cap_b64url(sig);
}
function _login_b64urlToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function _login_timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // 길이가 달라도 끝까지 돌려 타이밍 누출을 줄인다.
  let diff = a.length ^ b.length;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ (b[i] ?? 0);
  return diff === 0;
}
async function _login_verifyPassword(provided: string, stored: string): Promise<boolean> {
  const scheme = String(_authLoginMeta?.hash || 'pbkdf2').toLowerCase();
  if (scheme === 'plain') {
    return _login_timingSafeEqual(new TextEncoder().encode(provided), new TextEncoder().encode(String(stored || '')));
  }
  const parts = String(stored || '').split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const iter = Number(parts[1]);
  if (!Number.isFinite(iter) || iter < 1 || iter > 5_000_000) return false;
  let salt: Uint8Array, expected: Uint8Array;
  try { salt = _login_b64urlToBytes(parts[2]); expected = _login_b64urlToBytes(parts[3]); }
  catch { return false; }
  if (expected.length === 0) return false;
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(provided), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    baseKey, expected.length * 8,
  );
  return _login_timingSafeEqual(new Uint8Array(bits), expected);
}

function _az_matchRule(op: string, table: string): { spec: any; key: string } | null {
  if (!_authzMeta || !Array.isArray(_authzMeta.rules)) return null;
  const opU = String(op || '').toUpperCase();
  const tblL = String(table || '').toLowerCase();
  for (const rule of _authzMeta.rules) {
    const opMatch = rule.op === '*' || rule.op === opU;
    const tblMatch = rule.table === '*' || rule.table === tblL;
    if (opMatch && tblMatch) return { spec: rule.spec, key: rule.key };
  }
  return null;
}

function _az_authorize(matched: { spec: any; key: string } | null, jwt: { valid: boolean; reason?: string; payload?: any } | null): { ok: boolean; code?: string; reason?: string; role?: string } {
  if (!matched) {
    if (_authzMeta?.mode === 'strict') {
      return { ok: false, code: 'NO_RULE', reason: '해당 연산에 대한 인가 규칙이 정의되지 않았습니다.' };
    }
    return { ok: true };
  }
  const spec = matched.spec;
  if (spec.deny === true) {
    return { ok: false, code: 'RULE_DENY', reason: `규칙 '${matched.key}' 에 의해 거부되었습니다.` };
  }
  if (spec.public === true) return { ok: true };
  if (!jwt || !jwt.valid) {
    return { ok: false, code: 'AUTH_REQUIRED', reason: jwt?.reason ? `JWT 검증 실패: ${jwt.reason}` : '로그인이 필요합니다.' };
  }
  if (spec.auth === true && !spec.roles) return { ok: true };
  if (Array.isArray(spec.roles) && spec.roles.length > 0) {
    const claim = _authzMeta?.claim || 'role';
    const userRole = jwt.payload ? jwt.payload[claim] : undefined;
    if (userRole === undefined || userRole === null) {
      return { ok: false, code: 'ROLE_MISSING', reason: `JWT 에 '${claim}' 클레임이 없습니다.` };
    }
    const userRoles = Array.isArray(userRole) ? userRole.map(String) : [String(userRole)];
    const allowed = spec.roles.some((r: string) => userRoles.includes(r));
    if (!allowed) {
      return { ok: false, code: 'ROLE_FORBIDDEN', reason: `필요한 role: [${spec.roles.join(', ')}], 현재: ${userRoles.join(', ')}`, role: userRoles[0] };
    }
    return { ok: true, role: userRoles[0] };
  }
  return { ok: false, code: 'SPEC_INVALID', reason: '규칙 스펙이 유효하지 않습니다.' };
}

function _az_extractBearerToken(req: Request, payload: any): string | null {
  const h = req.headers.get('Authorization') || req.headers.get('authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  if (m) return m[1].trim();
  // 폴백: 암호화 payload 안에 _jwt 필드로 전달 가능 (네트워크 탭에서 JWT 가 보이지 않음)
  if (payload && typeof payload._jwt === 'string' && payload._jwt.length > 0) return payload._jwt;
  return null;
}

/** 세션 tenant_json + 검증된 JWT 로 테넌트 클레임 보강. 암호화 DB 요청에 _jwt 가 있으면 세션보다 JWT 를 우선(USER_KEY/tenant_json 레이스·구버전 세션으로 인한 TENANT_MISMATCH 방지). */
async function _tenantContextFromSessionAndJwt(
  cached: { tenantJson: string | null },
  req: Request,
  payload: Record<string, unknown>,
  env: Env,
): Promise<any> {
  let base: Record<string, unknown> | null = null;
  if (cached.tenantJson) {
    try {
      const p = JSON.parse(cached.tenantJson);
      if (p && typeof p === 'object' && !Array.isArray(p)) base = p as Record<string, unknown>;
    } catch { /* */ }
  }
  if (!_policyMeta || !_policyMeta.enabled) return base;
  const claim = String(_policyMeta.claim || 'user_id');

  const token = _az_extractBearerToken(req, payload);
  let mergedFromJwt: Record<string, unknown> | null = null;
  if (token) {
    const jwtRes = await _az_verifyJwtHs256(token, env);
    if (jwtRes.valid && jwtRes.payload) {
      const pl = jwtRes.payload as Record<string, unknown>;
      const id = pl.userId ?? pl.user_id ?? pl[claim];
      if (id !== undefined && id !== null) {
        mergedFromJwt = { ...(base || {}), [claim]: String(id) };
      }
    }
  }

  const preferJwtTenant =
    typeof payload._jwt === 'string' &&
    payload._jwt.length > 0 &&
    mergedFromJwt &&
    mergedFromJwt[claim] !== undefined;

  if (preferJwtTenant) return mergedFromJwt;
  if (base && base[claim] !== undefined && base[claim] !== null) return base;
  if (mergedFromJwt) return mergedFromJwt;
  return base;
}

let _capSignKey: CryptoKey | null = null;
let _capSignKeyPromise: Promise<CryptoKey> | null = null;
function _cap_b64url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function _cap_jsonB64(value: any): string {
  return _cap_b64url(new TextEncoder().encode(JSON.stringify(value)));
}
async function _cap_getSignKey(env: Env): Promise<CryptoKey> {
  const envName = String(_capabilityMeta?.secretEnv || 'DOKKEBI_CAPABILITY_SECRET');
  const secret = String((env as any)[envName] || '');
  if (!secret) throw new Error(envName + ' 미설정');
  if (_capSignKey) return _capSignKey;
  if (_capSignKeyPromise) return _capSignKeyPromise;
  _capSignKeyPromise = crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  ).then((k) => { _capSignKey = k; return k; });
  return _capSignKeyPromise;
}
function _cap_featureSpec(feature: string): any | null {
  if (!_capabilityMeta?.enabled || !_capabilityMeta.features) return null;
  const spec = _capabilityMeta.features[String(feature || '')];
  return spec && typeof spec === 'object' ? spec : null;
}
function _cap_authorizeSpec(spec: any, jwt: { valid: boolean; reason?: string; payload?: any } | null): { ok: boolean; code?: string; reason?: string; role?: string } {
  if (!spec) return { ok: false, code: 'CAPABILITY_UNKNOWN', reason: '등록되지 않은 capability feature 입니다.' };
  if (spec.deny === true) return { ok: false, code: 'CAPABILITY_DENY', reason: 'capability 정책에 의해 거부되었습니다.' };
  if (spec.public === true) return { ok: true };
  if (!jwt || !jwt.valid) {
    return { ok: false, code: 'CAPABILITY_AUTH_REQUIRED', reason: jwt?.reason ? 'JWT 검증 실패: ' + jwt.reason : '로그인이 필요합니다.' };
  }
  if (Array.isArray(spec.roles) && spec.roles.length > 0) {
    const claim = _capabilityMeta?.claim || _authzMeta?.claim || 'role';
    const rawRole = jwt.payload ? jwt.payload[claim] : undefined;
    if (rawRole === undefined || rawRole === null) {
      return { ok: false, code: 'CAPABILITY_ROLE_MISSING', reason: "JWT 에 '" + claim + "' 클레임이 없습니다." };
    }
    const roles = Array.isArray(rawRole) ? rawRole.map(String) : [String(rawRole)];
    const allowed = spec.roles.some((r: string) => roles.includes(r));
    if (!allowed) {
      return { ok: false, code: 'CAPABILITY_ROLE_FORBIDDEN', reason: '필요한 role: [' + spec.roles.join(', ') + '], 현재: ' + roles.join(', '), role: roles[0] };
    }
    return { ok: true, role: roles[0] };
  }
  if (spec.auth === true) return { ok: true };
  return { ok: false, code: 'CAPABILITY_SPEC_INVALID', reason: 'capability 정책 스펙이 유효하지 않습니다.' };
}
async function _cap_signToken(env: Env, payload: any): Promise<{ token: string; proof: string }> {
  const header = { alg: 'HS256', typ: 'DOKKEBI-CAP', v: 1 };
  const h64 = _cap_jsonB64(header);
  const p64 = _cap_jsonB64(payload);
  const data = new TextEncoder().encode(h64 + '.' + p64);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await _cap_getSignKey(env), data));
  const proof = _cap_b64url(sig);
  return { token: h64 + '.' + p64 + '.' + proof, proof };
}

// Capability Chain 선행 토큰 검증.
//   클라이언트가 보낸 token 의 HMAC 서명을 자체 secret 으로 재검증한 뒤, payload 를 반환한다.
//   payload.exp 미만이고 sid 가 현재 세션과 동일한 경우에만 성공.
async function _cap_verifyToken(env: Env, sid: string, token: string): Promise<{ ok: boolean; reason?: string; payload?: any }> {
  const t = String(token || '');
  const parts = t.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'TOKEN_MALFORMED' };
  const [h64, p64, proof] = parts;
  const data = new TextEncoder().encode(h64 + '.' + p64);
  const sigBin = atob(proof.replace(/-/g, '+').replace(/_/g, '/').padEnd(proof.length + ((4 - proof.length % 4) % 4), '='));
  const sigBytes = new Uint8Array(sigBin.length);
  for (let i = 0; i < sigBin.length; i++) sigBytes[i] = sigBin.charCodeAt(i);
  const sigKey = await _cap_getSignKey(env);
  const ok = await crypto.subtle.verify('HMAC', sigKey, sigBytes, data).catch(() => false);
  if (!ok) return { ok: false, reason: 'TOKEN_BAD_SIGNATURE' };
  let payload: any;
  try {
    const padded = p64.replace(/-/g, '+').replace(/_/g, '/').padEnd(p64.length + ((4 - p64.length % 4) % 4), '=');
    payload = JSON.parse(atob(padded));
  } catch { return { ok: false, reason: 'TOKEN_PAYLOAD_INVALID' }; }
  if (typeof payload?.exp !== 'number' || payload.exp < Date.now()) return { ok: false, reason: 'TOKEN_EXPIRED' };
  if (String(payload?.sid || '') !== String(sid || '')) return { ok: false, reason: 'TOKEN_SID_MISMATCH' };
  return { ok: true, payload };
}

// ─── policyEngine (워커 인라인 포트 — src/core/policyEngine.js 와 동일 로직) ─
function _pe_stripStringsAndComments(sql: string): string {
  let out = ''; let i = 0; const n = sql.length;
  while (i < n) {
    const ch = sql[i]; const next = sql[i + 1];
    if (ch === '-' && next === '-') { while (i < n && sql[i] !== '\n') i++; out += ' '; continue; }
    if (ch === '/' && next === '*') { i += 2; while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i++; i += 2; out += ' '; continue; }
    if (ch === "'") { out += "''"; i++; while (i < n) { if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; } if (sql[i] === "'") { i++; break; } i++; } continue; }
    if (ch === '"') { out += '"'; i++; while (i < n) { if (sql[i] === '"' && sql[i + 1] === '"') { out += '""'; i += 2; continue; } if (sql[i] === '"') { out += '"'; i++; break; } out += sql[i]; i++; } continue; }
    if (ch === '`') { out += '`'; i++; while (i < n && sql[i] !== '`') { out += sql[i]; i++; } if (sql[i] === '`') { out += '`'; i++; } continue; }
    out += ch; i++;
  }
  return out;
}
function _pe_normalize(sql: string): string {
  return _pe_stripStringsAndComments(sql).replace(/\s+/g, ' ').trim();
}
function _pe_detectOp(upper: string): string | null {
  const head = upper.trimStart();
  if (head.startsWith('SELECT')) return 'SELECT';
  if (head.startsWith('INSERT')) return 'INSERT';
  if (head.startsWith('UPDATE')) return 'UPDATE';
  if (head.startsWith('DELETE')) return 'DELETE';
  if (head.startsWith('WITH'))   return 'SELECT';
  if (head.startsWith('CREATE')) return 'CREATE';
  return null;
}
const _PE_RESERVED = new Set(['WHERE','SET','VALUES','ON','GROUP','ORDER','LIMIT','HAVING','UNION','INNER','LEFT','RIGHT','FULL','CROSS','OUTER','NATURAL','AS','USING','AND','OR','RETURNING','INTERSECT','EXCEPT','FROM','JOIN','INTO','UPDATE','SELECT','INSERT','DELETE']);
function _pe_extractTableRefs(normalized: string): any[] {
  const refs: any[] = [];
  const identPat = '["\'`]?([a-zA-Z_][\\w]*(?:\\.[a-zA-Z_][\\w]*)?)["\'`]?';
  const aliasPat = '(?:\\s+(?:AS\\s+)?["\'`]?([a-zA-Z_][\\w]*)["\'`]?)?';
  const keywords = ['FROM', 'JOIN', 'INTO', 'UPDATE'];
  for (const kw of keywords) {
    const re = new RegExp('\\b' + kw + '\\s+' + identPat + aliasPat, 'gi');
    let m: RegExpExecArray | null;
    while ((m = re.exec(normalized)) !== null) {
      const full = m[1];
      const parts = full.split('.');
      const baseName = parts[parts.length - 1];
      const aliasRaw = m[2];
      const isValidAlias = aliasRaw && !_PE_RESERVED.has(aliasRaw.toUpperCase());
      refs.push({ name: baseName, alias: isValidAlias ? aliasRaw : null, offset: m.index, keyword: kw.toUpperCase() });
    }
  }
  return refs;
}
function _pe_extractWhere(normalized: string): { start: number; end: number; text: string } | null {
  const m = /\bWHERE\b/i.exec(normalized);
  if (!m) return null;
  const start = m.index + m[0].length;
  const remaining = normalized.slice(start);
  const endRe = /\b(ORDER\s+BY|GROUP\s+BY|LIMIT|HAVING|RETURNING|UNION|INTERSECT|EXCEPT)\b|;/i;
  const endMatch = endRe.exec(remaining);
  const end = endMatch ? start + endMatch.index : normalized.length;
  return { start, end, text: normalized.slice(start, end) };
}
function _pe_hasTopLevelOr(whereText: string): boolean {
  const upper = whereText.toUpperCase();
  let depth = 0;
  for (let i = 0; i < upper.length; i++) {
    const ch = upper[i];
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    else if (depth === 0) {
      if (upper.slice(i, i + 3) === 'OR ' || upper.slice(i, i + 4) === 'OR\t' || upper.slice(i, i + 3) === 'OR\n') {
        const before = upper[i - 1];
        if (before === undefined || !/[A-Z0-9_]/.test(before)) return true;
      }
    }
  }
  return false;
}
function _pe_splitTopLevelAndWhere(whereText: string, upper: string): { start: number; end: number }[] {
  const spans: { start: number; end: number }[] = [];
  let depth = 0;
  let segStart = 0;
  for (let i = 0; i < whereText.length; i++) {
    const ch = whereText[i];
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
    if (depth === 0 && i + 5 <= upper.length && upper.slice(i, i + 5) === ' AND ') {
      spans.push({ start: segStart, end: i });
      i += 4;
      segStart = i + 1;
      continue;
    }
  }
  spans.push({ start: segStart, end: whereText.length });
  return spans.filter((sp) => sp.end > sp.start);
}
function _pe_peelWrappedConjunct(sub: string): { inner: string; relOffset: number } {
  const lead = sub.search(/\S/);
  if (lead < 0) return { inner: '', relOffset: 0 };
  let s = sub.slice(lead);
  let rel = lead;
  for (;;) {
    const w = (s.match(/^\s*/) || [''])[0].length;
    rel += w;
    s = s.slice(w).trimEnd();
    if (!s.startsWith('(')) break;
    let d = 0;
    let closeAt = -1;
    for (let k = 0; k < s.length; k++) {
      if (s[k] === '(') d++;
      else if (s[k] === ')') {
        d--;
        if (d === 0) {
          closeAt = k;
          break;
        }
      }
    }
    if (closeAt !== s.length - 1) break;
    rel += 1;
    s = s.slice(1, -1).trimEnd();
  }
  return { inner: s, relOffset: rel };
}
function _pe_findTenantCondInUpper(upper: string, alias: string | null, col: string): { index: number; length: number; qIndex: number } | null {
  const colUp = col.toUpperCase();
  const aliasUp = alias ? alias.toUpperCase() : null;
  const patterns: RegExp[] = [];
  if (aliasUp) {
    patterns.push(new RegExp('\\b' + aliasUp + '\\.' + colUp + '\\s*=\\s*\\?', 'g'));
    patterns.push(new RegExp('\\b' + aliasUp + '\\.\\s*"' + colUp + '"\\s*=\\s*\\?', 'g'));
    patterns.push(new RegExp('"' + aliasUp + '"\\.\\s*"' + colUp + '"\\s*=\\s*\\?', 'g'));
  }
  patterns.push(new RegExp('"' + colUp + '"\\s*=\\s*\\?', 'g'));
  patterns.push(new RegExp('(?:^|[^A-Z0-9_.])' + colUp + '\\s*=\\s*\\?', 'g'));
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(upper)) !== null) {
      let depth = 0;
      for (let i = 0; i < m.index; i++) {
        if (upper[i] === '(') depth++;
        else if (upper[i] === ')') depth--;
      }
      if (depth !== 0) continue;
      const qRel = m[0].lastIndexOf('?');
      return { index: m.index, length: m[0].length, qIndex: m.index + qRel };
    }
  }
  return null;
}
function _pe_findTenantCond(whereText: string, alias: string | null, col: string): { index: number; length: number; qIndex: number } | null {
  const upper = whereText.toUpperCase();
  let r = _pe_findTenantCondInUpper(upper, alias, col);
  if (r) return r;
  for (const sp of _pe_splitTopLevelAndWhere(whereText, upper)) {
    const sub = whereText.slice(sp.start, sp.end);
    const subUpper = upper.slice(sp.start, sp.end);
    const { inner, relOffset } = _pe_peelWrappedConjunct(sub);
    if (!inner) continue;
    const innerUpper = subUpper.slice(relOffset, relOffset + inner.length);
    r = _pe_findTenantCondInUpper(innerUpper, alias, col);
    if (r) {
      const shift = sp.start + relOffset;
      return { index: shift + r.index, length: r.length, qIndex: shift + r.qIndex };
    }
  }
  return null;
}
function _pe_countQMarks(normalized: string, offset: number): number {
  let c = 0;
  const end = Math.min(offset, normalized.length);
  for (let i = 0; i < end; i++) if (normalized[i] === '?') c++;
  return c;
}
function _pe_extractInsertCols(normalized: string): { cols: string[] } | null {
  const re = /\bINSERT\s+INTO\s+(?:["`]?[\w]+["`]?(?:\.[\w]+)?)\s*\(([^)]*)\)\s*VALUES\s*\(/i;
  const m = re.exec(normalized);
  if (!m) return null;
  const cols = m[1].split(',').map((s) => s.trim().replace(/^["`]|["`]$/g, ''));
  return { cols };
}
function _pe_findTablePolicy(tables: any, name: string): any {
  if (!tables) return null;
  const lower = name.toLowerCase();
  for (const k of Object.keys(tables)) {
    if (k.toLowerCase() === lower) return tables[k];
  }
  return null;
}
function _pe_resolveClaim(tenantContext: any, tableClaim: string | undefined, globalClaim: string, tenantCol: string): [string, unknown] {
  const candidates: string[] = [];
  if (tableClaim) candidates.push(tableClaim);
  if (globalClaim && globalClaim !== tableClaim) candidates.push(globalClaim);
  if (tenantCol && !candidates.includes(tenantCol)) candidates.push(tenantCol);
  if (candidates.length === 0) return ['user_id', undefined];
  if (!tenantContext) return [candidates[0], undefined];
  for (const c of candidates) {
    const v = tenantContext[c];
    if (v !== undefined && v !== null) return [c, v];
  }
  return [candidates[0], undefined];
}
function verifyTenantPolicy(sql: string, params: unknown[], tenantContext: any, policy: any, opts: any = {}): any {
  if (!policy || !policy.tables || Object.keys(policy.tables).length === 0) return { ok: true };
  const strict = opts.strict ?? (policy.strict !== false);
  const globalClaim = policy.claim || 'user_id';
  if (tenantContext && tenantContext._isAdmin === true) return { ok: true };
  const normalized = _pe_normalize(sql);
  const upper = normalized.toUpperCase();
  const op = _pe_detectOp(upper);
  if (!op) return strict ? { ok: false, code: 'UNPARSEABLE', reason: 'SQL 연산을 파싱할 수 없습니다.' } : { ok: true };
  if (op === 'CREATE') return { ok: true };
  const refs = _pe_extractTableRefs(normalized);
  for (const ref of refs) {
    const tp = _pe_findTablePolicy(policy.tables, ref.name);
    if (!tp) continue;
    const mode = tp.mode;
    if (mode === 'none' || mode === 'optional') continue;
    if (mode !== 'enforce' && mode !== 'inject') continue;
    const tenantCol = tp.tenantColumn;
    if (!tenantCol) continue;
    const [claim, expected] = _pe_resolveClaim(tenantContext, tp.sessionClaim, globalClaim, tenantCol);
    if (expected === undefined || expected === null) {
      return { ok: false, code: 'TENANT_MISSING', reason: '테넌트 클레임 "' + claim + '" 가 세션에 없습니다.', table: ref.name };
    }
    if (op === 'INSERT') {
      if (ref.keyword === 'INTO') {
        const ci = _pe_extractInsertCols(normalized);
        if (!ci) return { ok: false, code: 'INSERT_NO_COLUMNS', reason: 'INSERT 문에 컬럼 리스트가 없습니다.', table: ref.name };
        const idx = ci.cols.findIndex((c: string) => c.toLowerCase() === tenantCol.toLowerCase());
        if (idx < 0) return { ok: false, code: 'INSERT_MISSING_TENANT_COL', reason: 'INSERT 컬럼 리스트에 테넌트 컬럼 "' + tenantCol + '" 가 없습니다.', table: ref.name };
        if (String(params[idx]) !== String(expected)) {
          return { ok: false, code: 'TENANT_MISMATCH', reason: 'INSERT ' + ref.name + '.' + tenantCol + ' 값이 세션 테넌트와 일치하지 않습니다.', table: ref.name };
        }
      } else if (strict) {
        return { ok: false, code: 'UNSUPPORTED_INSERT_SUBQUERY', reason: 'INSERT ... SELECT 형태는 아직 지원하지 않습니다.', table: ref.name };
      }
    } else {
      const where = _pe_extractWhere(normalized);
      if (!where) return { ok: false, code: 'NO_WHERE', reason: op + ' 문에 WHERE 절이 없어 ' + ref.name + '.' + tenantCol + ' 조건을 확인할 수 없습니다.', table: ref.name };
      if (_pe_hasTopLevelOr(where.text)) return { ok: false, code: 'LOOSE_OR', reason: 'WHERE 최상단에 OR 가 있어 테넌트 필터가 느슨합니다.', table: ref.name };
      const cond = _pe_findTenantCond(where.text, ref.alias, tenantCol);
      if (!cond) return { ok: false, code: 'NO_TENANT_FILTER', reason: 'WHERE 절에 ' + (ref.alias ? ref.alias + '.' : '') + tenantCol + ' = ? 조건이 없습니다.', table: ref.name };
      const absQOffset = where.start + cond.qIndex;
      const paramIdx = _pe_countQMarks(normalized, absQOffset);
      if (String(params[paramIdx]) !== String(expected)) {
        return { ok: false, code: 'TENANT_MISMATCH', reason: ref.name + '.' + tenantCol + ' 값이 세션 테넌트와 일치하지 않습니다.', table: ref.name };
      }
    }
  }
  return { ok: true };
}
function _pe_injectInsert(sql: string, params: unknown[], _ref: any, tenantCol: string, expected: any): any {
  const re = /(\bINSERT\s+INTO\s+(?:["`]?[\w]+["`]?(?:\.[\w]+)?)\s*\()([^)]*)(\)\s*VALUES\s*\()([^)]*)(\))/i;
  const m = re.exec(sql);
  if (!m) return null;
  const colList = m[2]; const valList = m[4];
  const cols = colList.split(',').map((s) => s.trim().replace(/^["`]|["`]$/g, ''));
  if (cols.some((c) => c.toLowerCase() === tenantCol.toLowerCase())) return null;
  const valCount = (valList.match(/\?/g) || []).length;
  if (valCount !== cols.length) return null;
  const totalQ = (sql.match(/\?/g) || []).length;
  if (totalQ !== params.length) return null;
  const newColList = colList.trim() + ', ' + tenantCol;
  const newValList = valList.trim() + ', ?';
  const newSql = sql.slice(0, m.index) + m[1] + newColList + m[3] + newValList + m[5] + sql.slice(m.index + m[0].length);
  return { sql: newSql, params: [...params, expected] };
}
function _pe_injectWhere(sql: string, params: unknown[], _op: string, ref: any, tenantCol: string, expected: any): any {
  const colExpr = (ref.alias ? ref.alias + '.' : '') + tenantCol;
  const cond = colExpr + ' = ?';
  const whereRe = /\bWHERE\b/i;
  const wm = whereRe.exec(sql);
  let newSql: string;
  if (wm) {
    const after = sql.slice(wm.index + wm[0].length);
    const tailRe = /\b(ORDER\s+BY|GROUP\s+BY|LIMIT|HAVING|RETURNING|UNION|INTERSECT|EXCEPT)\b|;/i;
    const tm = tailRe.exec(after);
    const insertAtAbs = wm.index + wm[0].length + (tm ? tm.index : after.length);
    newSql = (sql.slice(0, insertAtAbs).trimEnd() + ' AND (' + cond + ') ' + sql.slice(insertAtAbs).trimStart()).replace(/\s+/g, ' ');
  } else {
    const tailRe = /\b(ORDER\s+BY|GROUP\s+BY|LIMIT|HAVING|RETURNING|UNION|INTERSECT|EXCEPT)\b|;\s*$/i;
    const tm = tailRe.exec(sql);
    const insertAt = tm ? tm.index : sql.length;
    newSql = (sql.slice(0, insertAt).trimEnd() + ' WHERE ' + cond + ' ' + sql.slice(insertAt).trimStart()).replace(/\s+/g, ' ');
  }
  const markers = [' AND (' + cond + ')', ' WHERE ' + cond];
  let markerIdx = -1;
  for (const marker of markers) {
    const i = newSql.lastIndexOf(marker);
    if (i >= 0) { markerIdx = i + marker.lastIndexOf('?'); break; }
  }
  if (markerIdx < 0) markerIdx = newSql.lastIndexOf(cond) + cond.lastIndexOf('?');
  const beforeCount = _pe_countQMarks(newSql, markerIdx);
  const newParams = params.slice();
  newParams.splice(beforeCount, 0, expected);
  return { sql: newSql, params: newParams };
}
function injectTenantPolicy(sql: string, params: unknown[], tenantContext: any, policy: any, opts: any = {}): any {
  if (!policy || !policy.tables || Object.keys(policy.tables).length === 0) return { ok: true, sql, params, injected: false };
  const strict = opts.strict ?? (policy.strict !== false);
  if (tenantContext && tenantContext._isAdmin === true) return { ok: true, sql, params, injected: false };
  const pre = verifyTenantPolicy(sql, params, tenantContext, policy, { strict: false });
  if (pre.ok) return { ok: true, sql, params, injected: false };
  const globalClaim = policy.claim || 'user_id';
  const normalized0 = _pe_normalize(sql);
  const op0 = _pe_detectOp(normalized0.toUpperCase());
  if (!op0 || op0 === 'CREATE') {
    return strict ? { ok: false, code: 'UNSUPPORTED_OP', reason: '주입 불가능한 SQL 연산입니다.' } : { ok: true, sql, params, injected: false };
  }
  const refs0 = _pe_extractTableRefs(normalized0);
  const targets = refs0.filter((r) => {
    const tp = _pe_findTablePolicy(policy.tables, r.name);
    return tp && (tp.mode === 'enforce' || tp.mode === 'inject') && tp.tenantColumn;
  });
  if (targets.length === 0) return { ok: true, sql, params, injected: false };
  let curSql = sql; let curParams = params.slice();
  let injectedAny = false;
  const MAX_ROUNDS = targets.length + 2;
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const vr = verifyTenantPolicy(curSql, curParams, tenantContext, policy, { strict: false });
    if (vr.ok) return { ok: true, sql: curSql, params: curParams, injected: injectedAny };
    const failingTable = vr.table;
    if (!failingTable) break;
    const normalizedCur = _pe_normalize(curSql);
    const curRefs = _pe_extractTableRefs(normalizedCur);
    const tRef = curRefs.find((r) => r.name.toLowerCase() === failingTable.toLowerCase());
    if (!tRef) break;
    const tp = _pe_findTablePolicy(policy.tables, failingTable);
    if (!tp || !tp.tenantColumn) break;
    const tenantCol = tp.tenantColumn;
    const [failingClaim, failingExpected] = _pe_resolveClaim(tenantContext, tp.sessionClaim, globalClaim, tenantCol);
    if (failingExpected === undefined || failingExpected === null) {
      return { ok: false, code: 'TENANT_MISSING', reason: '테넌트 클레임 "' + failingClaim + '" 가 세션에 없어 ' + failingTable + ' 에 주입할 수 없습니다.', table: failingTable };
    }
    const curOp = _pe_detectOp(normalizedCur.toUpperCase());
    const allowedKw: Record<string, Set<string>> = {
      SELECT: new Set(['FROM', 'JOIN']),
      UPDATE: new Set(['UPDATE']),
      DELETE: new Set(['FROM']),
      INSERT: new Set(['INTO']),
    };
    const allowed = curOp ? allowedKw[curOp] : null;
    if (!allowed || !allowed.has(tRef.keyword)) break;
    const rewrite = curOp === 'INSERT'
      ? _pe_injectInsert(curSql, curParams, tRef, tenantCol, failingExpected)
      : _pe_injectWhere(curSql, curParams, curOp, tRef, tenantCol, failingExpected);
    if (!rewrite) {
      return strict
        ? { ok: false, code: 'INJECT_FAILED', reason: '테넌트 조건 주입 실패: ' + failingTable + '.' + tenantCol, table: failingTable }
        : { ok: true, sql: curSql, params: curParams, injected: injectedAny };
    }
    curSql = rewrite.sql; curParams = rewrite.params;
    injectedAny = true;
  }
  const final = verifyTenantPolicy(curSql, curParams, tenantContext, policy, { strict: false });
  if (final.ok) return { ok: true, sql: curSql, params: curParams, injected: injectedAny };
  return strict
    ? { ok: false, code: 'INJECT_INCOMPLETE', reason: '주입 후에도 정책 위반이 남아있습니다: ' + (final.reason || ''), table: final.table }
    : { ok: true, sql: curSql, params: curParams, injected: injectedAny };
}
// ────────────────────────────────────────────────────────────────────────

/**
 * SQL Allowlist 검증 (강화판 — dok serve 의 sqlAllowlist.js 와 동일 로직)
 *
 * - 주석·문자열 스트립 후 분석
 * - 다중 문장 차단 (stacked query 방어)
 * - 위험 토큰 전수 차단 (ATTACH/PRAGMA/SLEEP/BENCHMARK/INFORMATION_SCHEMA 등)
 * - 모든 FROM/JOIN/INTO/UPDATE 테이블 참조가 allowlist 에 있어야 함
 * - CREATE TABLE 은 _dokkebi_* 시스템 테이블만 허용
 * - CTE 는 실제 테이블이 아니므로 검증 제외
 * - strict=true (기본): allowlist 가 없으면 전부 거부 (fail-closed)
 * - strict=false (호환): 공통 방어만 통과시키고 통과
 */
function validateSqlAllowlist(sql: string, opts: { strict?: boolean } = {}): { allowed: boolean; reason?: string } {
  const strict = opts.strict !== false;

  if (typeof sql !== 'string' || sql.length === 0) {
    return { allowed: false, reason: 'SQL이 비어 있습니다.' };
  }

  const hasAllowlist = !!(_sqlAllowlist && Array.isArray(_sqlAllowlist.tables) && _sqlAllowlist.tables.length > 0);

  const normalized = stripStringsAndComments(sql).replace(/\s+/g, ' ').trim();
  const upper = normalized.toUpperCase();

  if (hasMultipleStatements(normalized)) {
    return { allowed: false, reason: '다중 SQL 문장은 허용되지 않습니다.' };
  }

  const danger = containsDangerousToken(upper);
  if (danger) {
    return { allowed: false, reason: `위험한 SQL 토큰 감지: ${danger}` };
  }

  if (!hasAllowlist) {
    if (strict) {
      return { allowed: false, reason: 'SQL allowlist가 없어 모든 쿼리를 거부합니다.' };
    }
    return { allowed: true };
  }

  const op = detectPrimaryOp(upper);
  if (!op) {
    return { allowed: false, reason: `허용되지 않은 SQL 연산: ${normalized.slice(0, 30)}` };
  }

  const allowedMap = new Map<string, any>();
  for (const t of _sqlAllowlist.tables) allowedMap.set(String(t.name).toLowerCase(), t);

  if (op === 'CREATE') {
    const ident = '["\'`]?([a-zA-Z_][\\w]*(?:\\.[a-zA-Z_][\\w]*)?)["\'`]?';
    const createRe = new RegExp('\\bCREATE\\s+(?:TEMP(?:ORARY)?\\s+)?TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?' + ident, 'i');
    const m = normalized.match(createRe);
    if (!m) return { allowed: false, reason: 'CREATE TABLE 구문에서 테이블명을 추출할 수 없습니다.' };
    const rawName = m[1];
    const baseName = rawName.split('.').pop()!.toLowerCase();
    if (!baseName.startsWith('_dokkebi_')) {
      return { allowed: false, reason: `CREATE TABLE은 _dokkebi_* 시스템 테이블만 허용됩니다. (요청: ${rawName})` };
    }
    const referenced = extractAllTables(upper).map(t => t.toLowerCase());
    for (const t of referenced) {
      if (t === baseName) continue;
      if (!allowedMap.get(t)) {
        return { allowed: false, reason: `CREATE TABLE 중 허용되지 않은 참조 테이블: "${t}"` };
      }
    }
    return { allowed: true };
  }

  const allTables = extractAllTables(upper).map(t => t.toLowerCase());
  if (allTables.length === 0 && !upper.trimStart().startsWith('WITH')) {
    return { allowed: false, reason: 'SQL에서 테이블명을 추출할 수 없습니다.' };
  }

  for (const t of allTables) {
    const entry = allowedMap.get(t);
    if (!entry) {
      return { allowed: false, reason: `허용되지 않은 테이블: "${t}"` };
    }
    if (op === 'SELECT' && !entry.ops.includes('SELECT')) {
      return { allowed: false, reason: `테이블 "${t}"에 대한 SELECT가 허용되지 않습니다.` };
    }
  }

  const cteNames = extractCteNames(upper);
  const primaryTable = detectPrimaryTable(upper, op);
  if (primaryTable && !cteNames.has(primaryTable.toLowerCase())) {
    const entry = allowedMap.get(primaryTable.toLowerCase());
    if (!entry || !entry.ops.includes(op)) {
      return {
        allowed: false,
        reason: `테이블 "${primaryTable}"에 대한 ${op} 연산이 허용되지 않습니다. (허용: ${entry?.ops.join(', ') || '(없음)'})`,
      };
    }
  }

  return { allowed: true };
}

function sanitizeError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  if (/Authorization|apiToken|Bearer|apikey|X-Appwrite|DOKKEBI/i.test(msg)) {
    return 'DB 연결 오류가 발생했습니다.';
  }
  const httpMatch = msg.match(/HTTP (\d{3}):/);
  if (httpMatch) return `DB 요청 실패 (HTTP ${httpMatch[1]})`;
  return msg.replace(/\/[^\s]+/g, '[경로]').slice(0, 200);
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const { request, env } = ctx;

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const headers = { 'Content-Type': 'application/json; charset=utf-8', ...CORS };
  const clientIp = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '';
  const reqStart = Date.now();

  // ── Phase 1-② Envelope size cap (pre-parse) ─────────────
  //   파싱/복호화 전에 거대 페이로드를 잘라 CPU DoS 차단.
  const _contentLen = Number(request.headers.get('content-length') || 0);
  if (_contentLen > MAX_ENVELOPE_BYTES) {
    return new Response(JSON.stringify({
      ok: false, code: 'PAYLOAD_TOO_LARGE', error: '요청이 허용 크기를 초과했습니다.',
    }), { status: 413, headers });
  }

  let raw: any;
  try { raw = await request.json(); }
  catch { return new Response(JSON.stringify({ error: '잘못된 요청 본문' }), { status: 400, headers }); }

  try {
    const { sid, enc, iv: ivB64, nonce, ts: reqTs, sig } = raw;

    if (!sid || !enc || !ivB64 || !nonce || !reqTs || !sig) {
      return new Response(JSON.stringify({
        ok: false, code: 'REQUEST_MALFORMED', error: '필수 필드 누락(sid/enc/iv/nonce/ts/sig)',
      }), { status: 400, headers });
    }

    // ── Phase 2-⑤ Per-session pre-gate (cheapest gate) ──────
    //   세션 캐시가 있으면 해당 버킷 기반, 없으면 임시 Map 으로 sid 별
    //   초단위 스로틀. HMAC/AES 앞에 두어 가장 저렴한 관문.
    {
      const now0 = Date.now();
      let bucket = _sessionCache.get(sid as string);
      let tokens: number, refillAt: number;
      if (bucket) {
        tokens = bucket.bucketTokens; refillAt = bucket.bucketRefillAt;
      } else {
        let tmp = _pregateTmp.get(sid as string);
        if (!tmp) { tmp = { tokens: _BUCKET_CAPACITY, refillAt: now0 }; _pregateTmp.set(sid as string, tmp); }
        tokens = tmp.tokens; refillAt = tmp.refillAt;
      }
      const elapsed = Math.max(0, now0 - refillAt);
      const refillN = Math.floor(elapsed / _BUCKET_REFILL_MS);
      if (refillN > 0) {
        tokens = Math.min(_BUCKET_CAPACITY, tokens + refillN);
        refillAt = now0;
      }
      if (tokens <= 0) {
        return new Response(JSON.stringify({
          ok: false, code: 'PREGATE_LIMIT', error: '세션 요청 속도 한도를 초과했습니다.',
        }), { status: 429, headers });
      }
      tokens -= 1;
      if (bucket) {
        bucket.bucketTokens = tokens; bucket.bucketRefillAt = refillAt;
      } else {
        const tmp2 = _pregateTmp.get(sid as string);
        if (tmp2) { tmp2.tokens = tokens; tmp2.refillAt = refillAt; }
      }
    }

    // ── Phase 3-A — Active Defense Layer (ADL) 핫패스 ─────────
    //   인메모리 LRU(60s) 로 캐시. 캐시 hit 면 D1 호출 0회.
    //   monitor 모드 — 차단 없이 감지만 (운영 첫 1주 권장).
    //   enforce 모드 — 즉시 403 ADL_BLOCKED.
    //   ADL 비활성 시(모든 사이트 기본) no-op → 추가 지연 0.
    if (_ADL_ENABLED) {
      const adlHit = await _adlLookup(_internalDb(env), clientIp, String(sid));
      if (adlHit) {
        if (_ADL_MODE === 'enforce') {
          logSecurity(_internalDb(env), 'adl_block', clientIp, '/api/_dokkebi/db', '[' + adlHit.kind + '] ' + adlHit.reason);
          return new Response(JSON.stringify({
            ok: false, code: 'ADL_BLOCKED', error: '능동 방어 시스템에 의해 차단되었습니다.',
          }), { status: 403, headers });
        } else {
          // monitor 모드: 차단 없이 로그만
          logSecurity(_internalDb(env), 'adl_detect', clientIp, '/api/_dokkebi/db', '[' + adlHit.kind + '] ' + adlHit.reason);
        }
      }
      // Lazy Cron — 확률적 트리거. ctx.waitUntil 로 응답 이후 백그라운드 실행.
      if (Math.random() < _ADL_SAMPLE_RATE) {
        ctx.waitUntil(_maybeRunADL(_internalDb(env)));
      }
    }

    // ── 1. Timestamp skew 검증 ───────────────────────────────
    //   code: TIMESTAMP_SKEW — 클라이언트 시계가 서버 시계와 TIMESTAMP_WINDOW_MS 를 초과하여
    //   차이남. 응답에 server_ts 를 포함하여 클라가 자동 보정(한 번 재시도)할 수 있도록 한다.
    const now = Date.now();
    const skew = Number(reqTs) - now;
    if (Math.abs(skew) > TIMESTAMP_WINDOW_MS) {
      return new Response(JSON.stringify({
        ok: false,
        code: 'TIMESTAMP_SKEW',
        error: `요청 시간이 서버와 ${Math.round(Math.abs(skew) / 1000)}초 차이남 (허용: ${Math.round(TIMESTAMP_WINDOW_MS / 1000)}초). 시계를 보정하세요.`,
        server_ts: now,
        window_ms: TIMESTAMP_WINDOW_MS,
      }), {
        status: 403,
        headers: { ...headers, 'Date': new Date(now).toUTCString() },
      });
    }

    // ── 2. Nonce 인메모리 중복 체크 (핫패스) ─────────────────
    //   code: REPLAY_DETECTED — 동일 nonce 를 이 아이솔레이트에서 이미 본 적 있음.
    //   (크로스-아이솔레이트 검사는 §3 참조.)
    pruneNonces();
    if (_nonceMap.has(nonce)) {
      logSecurity(_internalDb(env), 'replay_attempt', clientIp, '/api/_dokkebi/db', 'duplicate nonce (in-memory)');
      return new Response(JSON.stringify({
        ok: false, code: 'REPLAY_DETECTED', error: '중복된 요청 nonce 가 감지되었습니다.',
      }), { status: 403, headers });
    }
    _nonceMap.set(nonce, now);

    // ── 3. 세션 조회 (인메모리 캐시 → D1 폴백) ──────────────
    //   콜드패스(캐시 미스): D1 batch [세션 + nonce] → 크로스 아이솔레이트 replay 차단
    //   핫패스(캐시 히트): 인메모리 nonce만으로 충분 → D1 조회 생략
    let cached = _sessionCache.get(sid as string);
    if (!cached || now - cached.created_at > SESSION_TTL_MS) {
      _sessionCache.delete(sid as string);

      let sessionResult: any, nonceResult: any;
      try {
        [sessionResult, nonceResult] = await _internalDb(env).batch([
          _internalDb(env).prepare(`SELECT enc_key, sig_key, created_at, tenant_json FROM _dokkebi_sessions WHERE session_id = ?`).bind(sid),
          _internalDb(env).prepare(`SELECT 1 FROM _dokkebi_nonces WHERE nonce = ? AND expires_at > ?`).bind(nonce, now),
        ]);
      } catch (e: any) {
        // 구 버전 DB(tenant_json 컬럼 부재) 한정 fallback — ALTER 후 재시도.
        if (String(e?.message || '').includes('tenant_json')) {
          await _ensureSessionsMigration(_internalDb(env));
          [sessionResult, nonceResult] = await _internalDb(env).batch([
            _internalDb(env).prepare(`SELECT enc_key, sig_key, created_at, tenant_json FROM _dokkebi_sessions WHERE session_id = ?`).bind(sid),
            _internalDb(env).prepare(`SELECT 1 FROM _dokkebi_nonces WHERE nonce = ? AND expires_at > ?`).bind(nonce, now),
          ]);
        } else {
          throw e;
        }
      }

      if (nonceResult.results?.length) {
        logSecurity(_internalDb(env), 'replay_attempt', clientIp, '/api/_dokkebi/db', 'cross-isolate duplicate nonce');
        return new Response(JSON.stringify({
          ok: false, code: 'REPLAY_DETECTED', error: '중복된 요청 nonce 가 감지되었습니다 (cross-isolate).',
        }), { status: 403, headers });
      }

      const row = sessionResult.results?.[0] as { enc_key: string; sig_key: string; created_at: number; tenant_json: string | null } | undefined;
      if (!row || now - row.created_at > SESSION_TTL_MS) {
        logSecurity(_internalDb(env), 'session_invalid', clientIp, '/api/_dokkebi/db', 'session not found or expired');
        return new Response(JSON.stringify({
          ok: false, code: 'SESSION_INVALID', error: '세션이 만료되었거나 존재하지 않습니다. 재-handshake 가 필요합니다.',
        }), { status: 403, headers });
      }

      const encKeyBytes = Uint8Array.from(atob(row.enc_key), (c) => c.charCodeAt(0));
      const sigKeyBytes = Uint8Array.from(atob(row.sig_key), (c) => c.charCodeAt(0));
      cached = {
        encKey: await crypto.subtle.importKey('raw', encKeyBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
        sigKey: await crypto.subtle.importKey('raw', sigKeyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']),
        created_at: row.created_at,
        tenantJson: row.tenant_json ?? null,
        lastCounter: 0,
        bucketTokens: _BUCKET_CAPACITY,
        bucketRefillAt: now,
        writeWindowStart: now,
        writeCount: 0,
        deleteWindowStart: now,
        deleteCount: 0,
      };
      _sessionCache.set(sid as string, cached);

      // Phase 1-① cold-path — D1 Nonce 는 블로킹 INSERT 로 고쳐 changes
      // 를 확인한다. 크로스 아이솔레이트에서 동시에 동일 nonce 가 도착해도
      // D1 primary 가 write 를 직렬화하므로 둘 중 하나만 changes=1 이 된다.
      try {
        const res = await _internalDb(env).prepare(
          `INSERT OR IGNORE INTO _dokkebi_nonces (nonce, expires_at) VALUES (?, ?)`
        ).bind(nonce, now + NONCE_TTL_MS).run();
        const changes = (res as any)?.meta?.changes ?? (res as any)?.changes ?? 1;
        if (changes === 0) {
          logSecurity(_internalDb(env), 'replay_attempt', clientIp, '/api/_dokkebi/db', 'd1 primary duplicate nonce');
          return new Response(JSON.stringify({
            ok: false, code: 'REPLAY_DETECTED', error: '중복된 요청 nonce 가 감지되었습니다 (d1).',
          }), { status: 403, headers });
        }
      } catch { /* D1 일시 장애 — 인메모리 방어에 의존 */ }
    } else {
      // Phase 1-① hot-path — 세션 캐시가 있으므로 D1 은 fire-and-forget.
      // (동일 아이솔레이트 내부에서는 _nonceMap 이 이미 막아주며, 크로스
      //  아이솔레이트 race 는 콜드패스에서만 의미가 있다.)
      ctx.waitUntil(
        _internalDb(env).prepare(`INSERT OR IGNORE INTO _dokkebi_nonces (nonce, expires_at) VALUES (?, ?)`)
          .bind(nonce, now + NONCE_TTL_MS).run().catch(() => {})
      );
    }

    // ── 4. 요청 HMAC 검증 (CPU only) ─────────────────────────
    const sigInput = new TextEncoder().encode(`${nonce}:${reqTs}:${enc}`);
    const providedSig = Uint8Array.from(atob(sig), (c) => c.charCodeAt(0));
    const isValidSig = await crypto.subtle.verify('HMAC', cached.sigKey, providedSig, sigInput);
    if (!isValidSig) {
      logSecurity(_internalDb(env), 'hmac_fail', clientIp, '/api/_dokkebi/db', 'request HMAC-SHA256 mismatch');
      return new Response(JSON.stringify({
        ok: false, code: 'SIGNATURE_INVALID', error: '요청 서명이 유효하지 않습니다.',
      }), { status: 403, headers });
    }

    // ── Phase 1-① 세션별 monotonic counter (변경 DB / 특수 명령만 강제) ─
    //   SELECT/WITH 는 클라이언트에서 병렬 전송될 수 있으므로 카운터 역행 검사를 생략한다.
    //   쓰기·테넌트·capability 등은 기존처럼 순서 강제.
    const _enforceMutationCounter = (): Response | null => {
      const parts = String(nonce).split(':');
      if (parts.length >= 2 && parts[0] === sid) {
        const cnt = Number(parts[1]);
        if (Number.isFinite(cnt) && cnt > 0) {
          if (cnt <= cached.lastCounter) {
            logSecurity(_internalDb(env), 'replay_attempt', clientIp, '/api/_dokkebi/db', 'counter regression');
            return new Response(JSON.stringify({
              ok: false, code: 'REPLAY_DETECTED', error: '요청 순서가 역행합니다 (counter).',
            }), { status: 403, headers });
          }
          cached.lastCounter = cnt;
        }
      }
      return null;
    };
    const _isReadOnlySelectSql = (s: string): boolean => {
      const raw = (s || '').replace(/^\uFEFF/, '').trimStart();
      // Phase B-4: 명시적 read 메타 — SQL 선두에 `/*!read*/` 힌트가 있으면 read 로 인식.
      //   동적으로 합성된 SELECT 또는 함수형 view 호출처럼 prefix 가 SELECT 가 아닌
      //   read-only 쿼리를 안전하게 read replica 로 분기시키기 위함.
      if (/^\/\*!\s*read\s*\*\//i.test(raw)) return true;
      if (/^\/\*!\s*write\s*\*\//i.test(raw)) return false;
      const t = raw.toUpperCase();
      // WITH 로 시작하는 문장은 INSERT/UPDATE 등 변형이 있을 수 있어 SELECT 만 카운터 완화
      return t.startsWith('SELECT');
    };

    // ── 5. AES-GCM 복호화 + 메모리 제로화 (CPU only) ─────────
    const combined = Uint8Array.from(atob(enc), (c) => c.charCodeAt(0));
    const ivBytes = Uint8Array.from(atob(ivB64), (c) => c.charCodeAt(0));
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, cached.encKey, combined);
    let payload: Record<string, unknown> = JSON.parse(new TextDecoder().decode(plainBuf));
    new Uint8Array(plainBuf).fill(0);
    payload = denormalizeDbPayload(payload);
    const powRes = await verifyAndStripPowDb(payload, sid as string);
    if (!powRes.ok) {
      return new Response(JSON.stringify({ ok: false, code: 'POW_INVALID', error: powRes.error }), { status: 403, headers });
    }
    payload = powRes.payload;

    // ── 5-batch. 다중 SELECT 를 단일 D1.batch 로 실행 (opaqueHandle read coalesce) ──
    const _batchReadArr = payload._batchRead;
    if (Array.isArray(_batchReadArr) && _batchReadArr.length > 0) {
      const _batchKeyOk = Object.keys(payload).every((k) => k === '_batchRead' || k === '_jwt');
      if (!_batchKeyOk) {
        return new Response(JSON.stringify({ ok: false, error: 'read batch 요청에 허용되지 않은 필드가 있습니다.' }), { status: 400, headers });
      }
      const _MAX_DB_READ_BATCH = 32;
      if (_batchReadArr.length > _MAX_DB_READ_BATCH) {
        return new Response(JSON.stringify({ ok: false, error: 'read batch too large' }), { status: 400, headers });
      }
      await loadSqlAllowlist(_internalDb(env));
      const strictFlagB = String((env as any).DOKKEBI_SQL_STRICT ?? 'true').toLowerCase() !== 'false';
      const queryModeB = String((env as any).DOKKEBI_QUERY_MODE || 'auto').toLowerCase();
      const hasRegistryB = !!_queryRegistry;
      const outerJwtB = typeof payload._jwt === 'string' && payload._jwt ? payload._jwt : '';
      const stmts: D1PreparedStatement[] = [];
      const tenantCtxBatch = (_policyMeta && _policyMeta.enabled && _policyMeta.mode && _policyMeta.mode !== 'off')
        ? await _tenantContextFromSessionAndJwt(cached, request, payload as Record<string, unknown>, env)
        : null;

      for (let _bi = 0; _bi < _batchReadArr.length; _bi++) {
        const rawSub = _batchReadArr[_bi];
        if (!rawSub || typeof rawSub !== 'object') {
          return new Response(JSON.stringify({ ok: false, error: 'batch item malformed' }), { status: 400, headers });
        }
        const subPl: Record<string, unknown> = { ...(rawSub as Record<string, unknown>) };
        if (outerJwtB && subPl._jwt === undefined) subPl._jwt = outerJwtB;

        let queryIdB = subPl.queryId as string | undefined;
        let paramsB: unknown[] = Array.isArray(subPl.params) ? subPl.params : [];
        const _debugSqlB = subPl._debugSql as string | undefined;
        let sqlB: string | undefined = subPl.sql as string | undefined;

        if (queryIdB) {
          const foundB = lookupRegistryEntry(queryIdB);
          if (foundB) {
            if (_debugSqlB && _debugSqlB !== foundB.sql && _isValidInVariant(foundB.sql, _debugSqlB)) {
              sqlB = _debugSqlB;
            } else {
              sqlB = foundB.sql;
            }
          } else if (queryModeB === 'learn' && _debugSqlB) {
            sqlB = _debugSqlB;
            logSecurity(_internalDb(env), 'query_learned', clientIp, '/api/_dokkebi/db', 'batch unregistered queryId: ' + String(queryIdB).slice(0, 30));
          } else if (queryModeB === 'auto' && (_debugSqlB || sqlB)) {
            sqlB = _debugSqlB || sqlB;
            logSecurity(_internalDb(env), 'query_fallback', clientIp, '/api/_dokkebi/db', 'batch queryId fallback: ' + String(queryIdB).slice(0, 30));
          } else {
            logSecurity(_internalDb(env), 'query_not_registered', clientIp, '/api/_dokkebi/db', 'batch queryId ' + String(queryIdB).slice(0, 30));
            return new Response(JSON.stringify({ ok: false, error: '등록되지 않은 쿼리입니다. dev 모드에서 학습 후 재빌드 하세요.' }), { status: 403, headers });
          }
        } else if (typeof sqlB === 'string') {
          if (queryModeB === 'strict' && hasRegistryB) {
            logSecurity(_internalDb(env), 'raw_sql_blocked', clientIp, '/api/_dokkebi/db', 'batch raw sql strict');
            return new Response(JSON.stringify({ ok: false, error: 'strict 모드에서는 queryId 기반 쿼리만 허용됩니다.' }), { status: 403, headers });
          }
        } else {
          return new Response(JSON.stringify({ ok: false, error: 'batch item needs queryId or sql' }), { status: 400, headers });
        }

        const sqlCheckB = validateSql(sqlB!);
        if (!sqlCheckB.ok) {
          logSecurity(_internalDb(env), 'sql_inject', clientIp, '/api/_dokkebi/db', (sqlCheckB.reason || '') + ' | ' + sqlB?.slice(0, 100));
          return new Response(JSON.stringify({ ok: false, error: sqlCheckB.reason }), { status: 403, headers });
        }
        const alCheckB = validateSqlAllowlist(sqlB!, { strict: strictFlagB });
        if (!alCheckB.allowed) {
          logSecurity(_internalDb(env), 'sql_blocked', clientIp, '/api/_dokkebi/db', (alCheckB.reason || '') + ' | ' + sqlB?.slice(0, 100));
          return new Response(JSON.stringify({ ok: false, error: alCheckB.reason }), { status: 403, headers });
        }
        if (!_isReadOnlySelectSql(sqlB!)) {
          logSecurity(_internalDb(env), 'sql_blocked', clientIp, '/api/_dokkebi/db', 'batch item is not read-only SELECT');
          return new Response(JSON.stringify({ ok: false, error: 'read batch may only contain SELECT statements' }), { status: 403, headers });
        }

        if (_policyMeta && _policyMeta.enabled && _policyMeta.mode && _policyMeta.mode !== 'off') {
          const policyModeInner = String(_policyMeta.mode).toLowerCase();
          if (policyModeInner === 'inject') {
            const irB = injectTenantPolicy(sqlB!, paramsB, tenantCtxBatch, _policyMeta, { strict: _policyMeta.strict !== false });
            if (!irB.ok) {
              logSecurity(_internalDb(env), 'tenant_policy_violation', clientIp, '/api/_dokkebi/db', (irB.code || 'INJECT') + ': ' + (irB.reason || '') + ' | ' + sqlB?.slice(0, 100));
              logError(_internalDb(env), 'policy', (irB.reason || '정책 위반').slice(0, 300), irB.code || 'INJECT', irB.table || '');
              return new Response(JSON.stringify({ ok: false, error: irB.reason, code: irB.code, table: irB.table }), { status: 403, headers });
            }
            if (irB.injected) {
              sqlB = irB.sql;
              paramsB = irB.params;
              logSecurity(_internalDb(env), 'tenant_injected', clientIp, '/api/_dokkebi/db', (irB.sql || '').slice(0, 100));
            }
          } else {
            const vrB = verifyTenantPolicy(sqlB!, paramsB, tenantCtxBatch, _policyMeta, { strict: _policyMeta.strict !== false });
            if (!vrB.ok) {
              logSecurity(_internalDb(env), 'tenant_policy_violation', clientIp, '/api/_dokkebi/db', (vrB.code || 'VERIFY') + ': ' + (vrB.reason || '') + ' | ' + sqlB?.slice(0, 100));
              logError(_internalDb(env), 'policy', (vrB.reason || '정책 위반').slice(0, 300), vrB.code || 'VERIFY', vrB.table || '');
              return new Response(JSON.stringify({ ok: false, error: vrB.reason, code: vrB.code, table: vrB.table }), { status: 403, headers });
            }
          }
        }

        if (_authzMeta && _authzMeta.enabled) {
          const az_upperB = sqlB!.toUpperCase().trimStart();
          let az_opB: string | null = null;
          if (az_upperB.startsWith('SELECT') || az_upperB.startsWith('WITH')) az_opB = 'SELECT';
          else if (az_upperB.startsWith('INSERT')) az_opB = 'INSERT';
          else if (az_upperB.startsWith('UPDATE')) az_opB = 'UPDATE';
          else if (az_upperB.startsWith('DELETE')) az_opB = 'DELETE';
          else if (az_upperB.startsWith('CREATE TABLE')) az_opB = 'CREATE';

          const az_primaryB = az_opB ? detectPrimaryTable(stripStringsAndComments(sqlB!).replace(/\s+/g, ' ').trim().toUpperCase(), az_opB) : null;
          const az_tableB = az_primaryB || '';

          const matchedB = _az_matchRule(az_opB || '*', az_tableB);

          let jwtResB: any = null;
          const needsJwtB = matchedB && matchedB.spec && matchedB.spec.public !== true;
          if (needsJwtB) {
            const tokenB = _az_extractBearerToken(request, subPl);
            if (tokenB) {
              jwtResB = await _az_verifyJwtHs256(tokenB, env);
            } else {
              jwtResB = { valid: false, reason: 'Authorization 헤더 없음' };
            }
          }

          const decisionB = _az_authorize(matchedB, jwtResB);
          if (!decisionB.ok) {
            logSecurity(_internalDb(env), 'authz_denied', clientIp, '/api/_dokkebi/db',
              (decisionB.code || 'DENY') + ': ' + (decisionB.reason || '') +
              ' | op=' + (az_opB || '?') + ' table=' + (az_tableB || '?') +
              (matchedB ? ' rule=' + matchedB.key : ' rule=<none>'));
            return new Response(JSON.stringify({
              ok: false,
              error: decisionB.reason,
              code: decisionB.code,
            }), { status: decisionB.code === 'AUTH_REQUIRED' ? 401 : 403, headers });
          }
        }

        // 미리 SQL/params 만 모으고, 실제 prepare 는 sessionDb 에서 1패스로 수행한다 (아래 batch 단계).
        // 기존 코드와 호환을 위해 dummy stmt placeholder 만 누적.
        stmts.push({ __sql: sqlB!, __params: paramsB } as any);
      }

      // Phase B-3: D1 Sessions — batch 는 항상 read-only(위에서 강제 검증) → replica 우선.
      const _batchSession = _withMaybeSession(_userDbForSql(env), request, true);
      const _preparedStmts = stmts.map((s: any) => {
        const ps = _batchSession.db.prepare(s.__sql || s);
        const p = (s && s.__params) || [];
        return p.length > 0 ? ps.bind(...p) : ps;
      });
      const batchRaw = await _batchSession.db.batch(_preparedStmts);
      _appendBookmarkCookie(headers, _batchSession.db, _batchSession.bookmark);
      const outResults: { ok: true; value: DbResult }[] = [];
      for (let _oi = 0; _oi < batchRaw.length; _oi++) {
        const br = batchRaw[_oi];
        outResults.push({
          ok: true,
          value: {
            rows: (br.results || []).map((r) => JSON.stringify(r)),
            affected: br.meta?.changes ?? 0,
            lastInsertId: br.meta?.last_row_id ?? 0,
          },
        });
      }
      ctx.waitUntil(logSecurity(_internalDb(env), 'db_audit', clientIp, '/api/_dokkebi/db', 'op=BATCH_READ n=' + String(outResults.length)));
      ctx.waitUntil(logRequest(_internalDb(env), 'POST', '/api/_dokkebi/db', 200, Date.now() - reqStart, clientIp));
      const batchResponse = JSON.stringify({ ok: true, results: outResults });
      const batchIv = crypto.getRandomValues(new Uint8Array(12));
      const batchPlain = new TextEncoder().encode(batchResponse);
      const batchEnc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: batchIv }, cached.encKey, batchPlain);
      ctx.waitUntil(cleanupExpired(_internalDb(env)));
      return new Response(JSON.stringify({
        _enc: true,
        enc: encBytesToB64(batchEnc),
        iv: encBytesToB64(batchIv),
      }), { headers });
    }

    const queryId = payload.queryId as string | undefined;
    let params: unknown[] = Array.isArray(payload.params) ? payload.params : [];
    const _debugSql = payload._debugSql as string | undefined;
    let sql: string | undefined = payload.sql as string | undefined;

    // ── 5-login. 워커측 로그인 (C-1: 클라이언트 JWT 위조 차단) ───────────────
    //   payload._login: { identifier, password }
    //   워커가 auth.login.query 로 사용자 조회 → 비밀번호 검증(상수시간) →
    //   워커 전용 시크릿으로 JWT 서명 → (옵션) 세션 tenant_json 바인딩 → 토큰 반환.
    const _loginReq: any = payload._login;
    if (_loginReq !== undefined) {
      const _cerrL = _enforceMutationCounter();
      if (_cerrL) return _cerrL;
      const _loginErr = (code: string, msg: string, status = 401): Response =>
        new Response(JSON.stringify({ ok: false, code, error: msg }), { status, headers });
      if (!_authLoginMeta || _authLoginMeta.enabled !== true || !_authLoginMeta.query) {
        return _loginErr('LOGIN_DISABLED', '워커측 로그인이 설정되지 않았습니다 (dokkebi.config.js auth.login).', 400);
      }
      if (!_login_jwtSecret(env)) {
        return _loginErr('LOGIN_NO_SECRET', 'DOKKEBI_JWT_SECRET 미설정 — 토큰을 서명할 수 없습니다.', 500);
      }
      if (!_loginReq || typeof _loginReq !== 'object') return _loginErr('LOGIN_BAD_INPUT', '로그인 입력이 올바르지 않습니다.', 400);
      const identifier = _loginReq.identifier;
      const password = _loginReq.password;
      if (typeof identifier !== 'string' || typeof password !== 'string' || !identifier || !password) {
        return _loginErr('LOGIN_BAD_INPUT', 'identifier/password 가 필요합니다.', 400);
      }
      if (identifier.length > 256 || password.length > 1024) {
        return _loginErr('LOGIN_BAD_INPUT', '입력이 너무 깁니다.', 400);
      }
      let row: Record<string, unknown> | null = null;
      try {
        row = (await _userDbForSql(env).prepare(String(_authLoginMeta.query)).bind(identifier).first()) as any;
      } catch {
        ctx.waitUntil(logSecurity(_internalDb(env), 'login_error', clientIp, '/api/_dokkebi/db', 'login query failed'));
        return _loginErr('LOGIN_ERROR', '로그인 처리 중 오류가 발생했습니다.', 500);
      }
      const pwCol = String(_authLoginMeta.passwordColumn || 'password_hash');
      const stored = row ? row[pwCol] : null;
      // 사용자 부재 시에도 더미 검증을 수행해 타이밍 기반 유저 열거를 줄인다.
      const pwOk = await _login_verifyPassword(password, typeof stored === 'string' ? stored : 'pbkdf2$100000$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
      if (!row || typeof stored !== 'string' || !pwOk) {
        ctx.waitUntil(logSecurity(_internalDb(env), 'login_fail', clientIp, '/api/_dokkebi/db', 'invalid credentials'));
        return _loginErr('LOGIN_INVALID', '아이디 또는 비밀번호가 올바르지 않습니다.', 401);
      }
      // 클레임 매핑 { claimName: dbColumn } — 예약(`_`) 클레임은 차단(C-2 와 동일 원칙).
      const claims: Record<string, unknown> = {};
      const claimMap = (_authLoginMeta.claims && typeof _authLoginMeta.claims === 'object') ? _authLoginMeta.claims : { user_id: 'id' };
      for (const cName of Object.keys(claimMap)) {
        if (cName.charCodeAt(0) === 95) continue;
        const col = String(claimMap[cName]);
        if (col in (row as object)) claims[cName] = (row as any)[col];
      }
      const token = await _login_signJwt(env, claims);
      if (!token) return _loginErr('LOGIN_NO_SECRET', '토큰 서명 실패.', 500);
      // 세션 tenant_json 에 클레임 바인딩 (Tenant Policy 연동). 예약키는 위에서 차단됨.
      if (_authLoginMeta.bindTenant !== false) {
        const tenantStr = JSON.stringify(claims);
        try {
          await _internalDb(env).prepare(`UPDATE _dokkebi_sessions SET tenant_json = ? WHERE session_id = ?`).bind(tenantStr, sid).run();
        } catch (e: any) {
          if (String(e?.message || '').includes('tenant_json')) {
            await _ensureSessionsMigration(_internalDb(env));
            await _internalDb(env).prepare(`UPDATE _dokkebi_sessions SET tenant_json = ? WHERE session_id = ?`).bind(tenantStr, sid).run();
          }
        }
        cached.tenantJson = tenantStr;
      }
      ctx.waitUntil(logSecurity(_internalDb(env), 'login_ok', clientIp, '/api/_dokkebi/db', 'op=LOGIN'));
      ctx.waitUntil(logRequest(_internalDb(env), 'POST', '/api/_dokkebi/db', 200, Date.now() - reqStart, clientIp));
      const okPayloadL = JSON.stringify({ ok: true, value: { token, claims } });
      const resIvL = crypto.getRandomValues(new Uint8Array(12));
      const resEncL = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: resIvL }, cached.encKey, new TextEncoder().encode(okPayloadL));
      return new Response(JSON.stringify({ _enc: true, enc: encBytesToB64(resEncL), iv: encBytesToB64(resIvL) }), { headers });
    }

    const setTenant: any = payload._setTenant;

    // ── 5-pre. _setTenant 특수 명령 (Stage 1/2 세션 테넌트 설정) ───
    //   DB 쿼리 대신 세션의 tenant_json 을 갱신.
    //   백엔드 컨트롤러가 로그인 검증 후 호출: await ctx.setSessionTenant({ user_id: 'u1' })
    //   payload 예시: { _setTenant: { user_id: 'u1', org_id: 'acme' } }
    //   _setTenant === null 이면 세션 테넌트 클리어 (로그아웃)
    if (setTenant !== undefined) {
      const _cerr0 = _enforceMutationCounter();
      if (_cerr0) return _cerr0;
      // ── C-2 방어: 클라이언트가 보낸 테넌트 객체에 예약 키(`_` 접두) 주입 차단 ──
      //   특히 `_isAdmin` 은 verifyTenantPolicy/injectTenantPolicy 에서 정책 전체를
      //   우회시키므로, 신뢰 불가한 클라이언트(브라우저 WASM 백엔드) 발신 경로로는
      //   절대 설정될 수 없어야 한다. 관리자 승격은 워커측 _login(역할 클레임) 으로만.
      if (setTenant !== null) {
        if (typeof setTenant !== 'object' || Array.isArray(setTenant)) {
          logSecurity(_internalDb(env), 'tenant_reject', clientIp, '/api/_dokkebi/db', 'setTenant must be a plain object');
          return new Response(JSON.stringify({
            ok: false, code: 'TENANT_INVALID', error: '테넌트 값은 객체여야 합니다.',
          }), { status: 400, headers });
        }
        for (const _tk of Object.keys(setTenant)) {
          if (_tk.charCodeAt(0) === 95 /* '_' */) {
            logSecurity(_internalDb(env), 'tenant_reject', clientIp, '/api/_dokkebi/db', 'reserved tenant key: ' + _tk);
            return new Response(JSON.stringify({
              ok: false, code: 'TENANT_RESERVED_KEY', error: "테넌트 키에 예약 접두사('_')는 사용할 수 없습니다: " + _tk,
            }), { status: 400, headers });
          }
        }
      }
      const tenantStr = setTenant === null ? null : JSON.stringify(setTenant);
      try {
        await _internalDb(env).prepare(`UPDATE _dokkebi_sessions SET tenant_json = ? WHERE session_id = ?`).bind(tenantStr, sid).run();
      } catch (e: any) {
        if (String(e?.message || '').includes('tenant_json')) {
          await _ensureSessionsMigration(_internalDb(env));
          await _internalDb(env).prepare(`UPDATE _dokkebi_sessions SET tenant_json = ? WHERE session_id = ?`).bind(tenantStr, sid).run();
        } else { throw e; }
      }
      cached.tenantJson = tenantStr;
      ctx.waitUntil(logSecurity(_internalDb(env), 'db_audit', clientIp, '/api/_dokkebi/db', 'op=SET_TENANT'));
      ctx.waitUntil(logRequest(_internalDb(env), 'POST', '/api/_dokkebi/db', 200, Date.now() - reqStart, clientIp));
      const okPayload = JSON.stringify({ ok: true, value: { tenantUpdated: true } });
      const resIv0 = crypto.getRandomValues(new Uint8Array(12));
      const resPlain0 = new TextEncoder().encode(okPayload);
      const resEnc0 = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: resIv0 }, cached.encKey, resPlain0);
      return new Response(JSON.stringify({
        _enc: true,
        enc: encBytesToB64(resEnc0),
        iv: encBytesToB64(resIv0),
      }), { headers });
    }

    // ── 5-att. Bundle Attestation — 챌린지/검증 ───────────────
    //   payload._attest:
    //     { request: true }                       → 챌린지 발급 (nonce + 무작위 청크 인덱스)
    //     { nonce, hashes: [hex,...] }            → 응답 검증 후 통과 시 _attestPassMap 기록
    //   attestation 비활성/매니페스트 없음 → 즉시 비활성 응답.
    if (payload._attest !== undefined) {
      const _cerrA = _enforceMutationCounter();
      if (_cerrA) return _cerrA;
      const attReq = payload._attest || {};
      const headersAtt = headers;
      _attestPrune(Date.now());
      if (!_ATTEST_ENABLED) {
        return new Response(JSON.stringify({ ok: false, code: 'ATTEST_DISABLED', error: 'Bundle Attestation 이 활성화되지 않았습니다.' }), { status: 403, headers: headersAtt });
      }
      // Step A — 챌린지 발급
      if (attReq.request === true) {
        const indices = _attestRandomIndices();
        const nonce = crypto.randomUUID();
        const exp = Date.now() + 30_000;
        _attestChalMap.set(sid, { nonce, indices, exp });
        const respObj = JSON.stringify({
          ok: true,
          attest: {
            nonce,
            indices,
            chunkSize: Number(_attestMeta?.chunkSize || 0),
            count: Number(_attestMeta?.count || 0),
            totalBytes: Number(_attestMeta?.totalBytes || 0),
            exp,
          },
        });
        const ivA = crypto.getRandomValues(new Uint8Array(12));
        const encA = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivA }, cached.encKey, new TextEncoder().encode(respObj));
        return new Response(JSON.stringify({
          _enc: true,
          enc: encBytesToB64(encA),
          iv: encBytesToB64(ivA),
        }), { headers: headersAtt });
      }
      // Step B — 챌린지 응답 검증
      const cached0 = _attestChalMap.get(sid);
      const nowAtt = Date.now();
      if (!cached0 || cached0.exp < nowAtt || String(cached0.nonce || '') !== String(attReq.nonce || '')) {
        ctx.waitUntil(logSecurity(_internalDb(env), 'attest_failed', clientIp, '/api/_dokkebi/db', 'reason=NONCE_INVALID_OR_EXPIRED'));
        return new Response(JSON.stringify({ ok: false, code: 'ATTEST_NONCE_INVALID', error: 'attest 챌린지가 만료되었거나 일치하지 않습니다.' }), { status: 403, headers: headersAtt });
      }
      _attestChalMap.delete(sid);
      const sentHashes = Array.isArray(attReq.hashes) ? attReq.hashes.map((h: any) => String(h || '').toLowerCase()) : [];
      if (sentHashes.length !== cached0.indices.length) {
        ctx.waitUntil(logSecurity(_internalDb(env), 'attest_failed', clientIp, '/api/_dokkebi/db', 'reason=LEN_MISMATCH expected=' + cached0.indices.length + ' got=' + sentHashes.length));
        return new Response(JSON.stringify({ ok: false, code: 'ATTEST_LEN_MISMATCH', error: 'attest 응답 길이가 챌린지와 다릅니다.' }), { status: 403, headers: headersAtt });
      }
      let mismatchAt = -1;
      for (let i = 0; i < cached0.indices.length; i++) {
        const idx = cached0.indices[i];
        const expected = String(_attestMeta.hashes[idx] || '').toLowerCase();
        if (!expected || expected !== sentHashes[i]) { mismatchAt = idx; break; }
      }
      if (mismatchAt >= 0) {
        ctx.waitUntil(logSecurity(_internalDb(env), 'attest_failed', clientIp, '/api/_dokkebi/db', 'reason=HASH_MISMATCH idx=' + mismatchAt));
        return new Response(JSON.stringify({ ok: false, code: 'ATTEST_HASH_MISMATCH', error: '번들 무결성 검증 실패 (idx=' + mismatchAt + ').' }), { status: 403, headers: headersAtt });
      }
      _attestPassMap.set(sid, nowAtt + _ATTEST_TTL_MS);
      ctx.waitUntil(logSecurity(_internalDb(env), 'attest_passed', clientIp, '/api/_dokkebi/db', 'sample=' + cached0.indices.length + ' ttl=' + _ATTEST_TTL_MS));
      const okJson = JSON.stringify({ ok: true, attest: { passed: true, until: nowAtt + _ATTEST_TTL_MS } });
      const ivOk = crypto.getRandomValues(new Uint8Array(12));
      const encOk = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivOk }, cached.encKey, new TextEncoder().encode(okJson));
      return new Response(JSON.stringify({
        _enc: true,
        enc: encBytesToB64(encOk),
        iv: encBytesToB64(ivOk),
      }), { headers: headersAtt });
    }

    // ── 5-cap. Signed Unlock Token 발급 (Cryptographic Checkpoint) ─
    //   기존 암호화/HMAC/nonce 검증을 통과한 세션에 대해서만 실행된다.
    //   토큰 서명은 Worker-only capability secret 으로 수행하므로 클라이언트가
    //   role 플래그나 분기문을 조작해도 유효한 proof 를 만들 수 없다.
    if (payload._capabilityUnlock !== undefined) {
      const _cerrC = _enforceMutationCounter();
      if (_cerrC) return _cerrC;
      const capReq = payload._capabilityUnlock || {};
      const feature = String(capReq.feature || '').trim();
      if (!_capabilityMeta?.enabled) {
        logSecurity(_internalDb(env), 'capability_denied', clientIp, '/api/_dokkebi/db', 'capabilities disabled feature=' + feature.slice(0, 80));
        return new Response(JSON.stringify({ ok: false, code: 'CAPABILITY_DISABLED', error: 'Signed Unlock Token 이 활성화되지 않았습니다.' }), { status: 403, headers });
      }
      if (!feature) {
        return new Response(JSON.stringify({ ok: false, code: 'CAPABILITY_MALFORMED', error: 'feature 가 필요합니다.' }), { status: 400, headers });
      }
      const spec = _cap_featureSpec(feature);
      let jwtRes: any = null;
      const token = typeof capReq.jwt === 'string' && capReq.jwt ? capReq.jwt : _az_extractBearerToken(request, payload);
      if (token && spec && spec.public !== true) {
        jwtRes = await _az_verifyJwtHs256(token, env);
      }
      const decision = _cap_authorizeSpec(spec, jwtRes);
      if (!decision.ok) {
        logSecurity(_internalDb(env), 'capability_denied', clientIp, '/api/_dokkebi/db',
          (decision.code || 'DENY') + ': ' + (decision.reason || '') + ' | feature=' + feature.slice(0, 80));
        return new Response(JSON.stringify({ ok: false, code: decision.code, error: decision.reason }), {
          status: decision.code === 'CAPABILITY_AUTH_REQUIRED' ? 401 : 403,
          headers,
        });
      }

      // requires.attest — Bundle Attestation 통과 세션만 허용.
      if (spec?.requires?.attest === true) {
        const until = _attestPassMap.get(sid) || 0;
        if (!_ATTEST_ENABLED) {
          logSecurity(_internalDb(env), 'capability_denied', clientIp, '/api/_dokkebi/db', 'CAPABILITY_ATTEST_DISABLED feature=' + feature.slice(0, 80));
          return new Response(JSON.stringify({ ok: false, code: 'CAPABILITY_ATTEST_DISABLED', error: 'attest 가 요구되지만 빌드에 매니페스트가 없습니다.' }), { status: 403, headers });
        }
        if (until < Date.now()) {
          logSecurity(_internalDb(env), 'capability_denied', clientIp, '/api/_dokkebi/db', 'CAPABILITY_ATTEST_REQUIRED feature=' + feature.slice(0, 80));
          return new Response(JSON.stringify({ ok: false, code: 'CAPABILITY_ATTEST_REQUIRED', error: 'attest 챌린지 통과가 필요합니다.' }), { status: 403, headers });
        }
      }

      // requires.prev — 선행 capability 토큰들이 함께 와야 발급. (Capability Chain)
      const reqPrev: string[] = Array.isArray(spec?.requires?.prev) ? spec.requires.prev : [];
      if (reqPrev.length > 0) {
        const sentPrev = Array.isArray(capReq.prevTokens) ? capReq.prevTokens : [];
        const supplied = new Map<string, string>();
        for (const item of sentPrev) {
          if (item && typeof item === 'object' && typeof item.feature === 'string' && typeof item.token === 'string') {
            supplied.set(item.feature, item.token);
          }
        }
        for (const need of reqPrev) {
          const tok = supplied.get(need);
          if (!tok) {
            logSecurity(_internalDb(env), 'capability_denied', clientIp, '/api/_dokkebi/db', 'CAPABILITY_PREV_MISSING need=' + need + ' for=' + feature.slice(0, 80));
            return new Response(JSON.stringify({ ok: false, code: 'CAPABILITY_PREV_MISSING', error: '선행 capability 토큰이 필요합니다: ' + need }), { status: 403, headers });
          }
          const v = await _cap_verifyToken(env, sid, tok);
          if (!v.ok || String(v.payload?.feature || '') !== need) {
            logSecurity(_internalDb(env), 'capability_denied', clientIp, '/api/_dokkebi/db', 'CAPABILITY_PREV_INVALID need=' + need + ' reason=' + (v.reason || 'FEATURE_MISMATCH'));
            return new Response(JSON.stringify({ ok: false, code: 'CAPABILITY_PREV_INVALID', error: '선행 토큰이 유효하지 않습니다: ' + need + ' (' + (v.reason || 'FEATURE_MISMATCH') + ')' }), { status: 403, headers });
          }
        }
      }

      const capNow = Date.now();
      const ttlMs = Math.max(1_000, Math.min(300_000, Number(spec?.ttlMs || _capabilityMeta.defaultTtlMs || 15_000)));
      const capPayload = {
        feature,
        sid,
        bundleHash: String((_buildMeta && ((_buildMeta as any).buildHash || (_buildMeta as any).bundle_hash)) || ''),
        controllersHash: String(_buildMeta?.controllers_hash || ''),
        stateHash: typeof capReq.stateHash === 'string' ? capReq.stateHash.slice(0, 256) : null,
        contextHash: typeof capReq.contextHash === 'string' ? capReq.contextHash.slice(0, 256) : null,
        nonce: crypto.randomUUID(),
        iat: capNow,
        exp: capNow + ttlMs,
        sub: jwtRes?.payload?.sub || jwtRes?.payload?.user_id || jwtRes?.payload?.userId || null,
        role: decision.role || null,
      };
      const signed = await _cap_signToken(env, capPayload);
      ctx.waitUntil(logSecurity(_internalDb(env), 'capability_issued', clientIp, '/api/_dokkebi/db', 'feature=' + feature.slice(0, 80) + ' exp=' + capPayload.exp));
      ctx.waitUntil(logRequest(_internalDb(env), 'POST', '/api/_dokkebi/db', 200, Date.now() - reqStart, clientIp));

      const capResponse = JSON.stringify({
        ok: true,
        capability: {
          token: signed.token,
          proof: signed.proof,
          feature,
          exp: capPayload.exp,
          nonce: capPayload.nonce,
          stateHash: capPayload.stateHash,
        },
      });
      const capIv = crypto.getRandomValues(new Uint8Array(12));
      const capPlain = new TextEncoder().encode(capResponse);
      const capEnc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: capIv }, cached.encKey, capPlain);
      return new Response(JSON.stringify({
        _enc: true,
        enc: encBytesToB64(capEnc),
        iv: encBytesToB64(capIv),
      }), { headers });
    }

    // ── 5a. Query Registry (Stage 3) 경로 해석 ───────────────
    //   모드(DOKKEBI_QUERY_MODE Pages 환경변수):
    //     auto   (기본) — 레지스트리 매치되면 해당 SQL 사용, 아니면 _debugSql/sql 로 폴백
    //                     (레지스트리가 비어있거나 첫 배포 시 기존 v4 수준 방어 유지)
    //     strict        — queryId 만 허용, 미등록이면 403 (레지스트리 필수)
    //     learn         — queryId 우선, 미등록이면 _debugSql 로 대체 (dev 전용)
    //     legacy        — sql 필드 그대로 허용 (업그레이드 과도기용)
    //   어느 모드든 allowlist + validateSql 은 항상 실행되어 방어 깊이 유지.
    const queryMode = String((env as any).DOKKEBI_QUERY_MODE || 'auto').toLowerCase();
    const hasRegistry = !!_queryRegistry;

    if (queryId) {
      const found = lookupRegistryEntry(queryId);
      if (found) {
        // _debugSql 이 있고 IN 절 변형이면 실제 파라미터 수가 맞는 _debugSql 을 사용.
        // 레지스트리의 정규화된 SQL 은 IN (?) 형태로 파라미터 1개만 포함하므로,
        // 런타임 IN 절 크기가 다를 때 _debugSql 로 대체해야 실행이 성공한다.
        if (_debugSql && _debugSql !== found.sql && _isValidInVariant(found.sql, _debugSql)) {
          sql = _debugSql;
        } else {
          sql = found.sql;
        }
      } else if (queryMode === 'learn' && _debugSql) {
        sql = _debugSql;
        logSecurity(_internalDb(env), 'query_learned', clientIp, '/api/_dokkebi/db', 'unregistered queryId used via _debugSql: ' + String(queryId).slice(0, 30));
      } else if (queryMode === 'auto' && (_debugSql || sql)) {
        // auto 모드: 미등록 queryId → _debugSql / sql 로 폴백 (legacy 호환)
        //   allowlist 가 여전히 차단하므로 기존 v4 수준 방어는 유지됨.
        sql = _debugSql || sql;
        logSecurity(_internalDb(env), 'query_fallback', clientIp, '/api/_dokkebi/db', 'queryId not in registry → fallback: ' + String(queryId).slice(0, 30));
      } else {
        logSecurity(_internalDb(env), 'query_not_registered', clientIp, '/api/_dokkebi/db', 'queryId ' + String(queryId).slice(0, 30) + ' not found in registry (mode=' + queryMode + ')');
        return new Response(JSON.stringify({ ok: false, error: '등록되지 않은 쿼리입니다. dev 모드에서 학습 후 재빌드 하세요.' }), { status: 403, headers });
      }
    } else if (typeof sql === 'string') {
      // queryId 없이 sql 직접 전송
      //   strict 모드 + 레지스트리 존재 시에만 차단. 그 외에는 허용 (기존 v4 동작과 동일).
      if (queryMode === 'strict' && hasRegistry) {
        logSecurity(_internalDb(env), 'raw_sql_blocked', clientIp, '/api/_dokkebi/db', 'raw sql rejected in strict mode');
        return new Response(JSON.stringify({ ok: false, error: 'strict 모드에서는 queryId 기반 쿼리만 허용됩니다.' }), { status: 403, headers });
      }
    } else {
      return new Response(JSON.stringify({ ok: false, error: 'queryId 또는 sql 필드가 필요합니다.' }), { status: 400, headers });
    }

    // ── 6. SQL 검증 (CPU only) ───────────────────────────────
    const sqlCheck = validateSql(sql!);
    if (!sqlCheck.ok) {
      logSecurity(_internalDb(env), 'sql_inject', clientIp, '/api/_dokkebi/db', (sqlCheck.reason || '') + ' | ' + sql?.slice(0, 100));
      return new Response(JSON.stringify({ ok: false, error: sqlCheck.reason }), { status: 403, headers });
    }

    // ── 6b. SQL Allowlist 검증 (방어 깊이) ────────────────────
    //   Query Registry 로 1차 차단이 됐더라도 레지스트리 버그 등에
    //   대비해 기존 allowlist 는 그대로 유지합니다.
    await loadSqlAllowlist(_internalDb(env));
    const strictFlag = String((env as any).DOKKEBI_SQL_STRICT ?? 'true').toLowerCase() !== 'false';
    const alCheck = validateSqlAllowlist(sql!, { strict: strictFlag });
    if (!alCheck.allowed) {
      logSecurity(_internalDb(env), 'sql_blocked', clientIp, '/api/_dokkebi/db', (alCheck.reason || '') + ' | ' + sql?.slice(0, 100));
      return new Response(JSON.stringify({ ok: false, error: alCheck.reason }), { status: 403, headers });
    }

    // SELECT/WITH 가 아니면 모노토닉 카운터 검증 (직렬 쓰기·복잡 질의 순서 보장)
    if (!_isReadOnlySelectSql(sql!)) {
      const _cerrSql = _enforceMutationCounter();
      if (_cerrSql) return _cerrSql;
    }

    // ── 6c. Tenant Policy 검증/주입 (Stage 1/2, opt-in) ──────
    //   _policyMeta.mode:
    //     'off'     — 건너뜀 (기본, 하위호환)
    //     'verify'  — SQL 이 테넌트 조건을 갖췄는지 검사, 없으면 403
    //     'inject'  — verify 실패시 자동 주입
    //   tenantContext: 세션 tenant_json + JWT(Authorization / payload._jwt) 로 보강.
    //   문서: docs/design/TENANT_POLICY.md
    if (_policyMeta && _policyMeta.enabled && _policyMeta.mode && _policyMeta.mode !== 'off') {
      const tenantContext: any = await _tenantContextFromSessionAndJwt(cached, request, payload as Record<string, unknown>, env);
      const policyMode = String(_policyMeta.mode).toLowerCase();
      if (policyMode === 'inject') {
        const ir = injectTenantPolicy(sql!, params, tenantContext, _policyMeta, { strict: _policyMeta.strict !== false });
        if (!ir.ok) {
          logSecurity(_internalDb(env), 'tenant_policy_violation', clientIp, '/api/_dokkebi/db', (ir.code || 'INJECT') + ': ' + (ir.reason || '') + ' | ' + sql?.slice(0, 100));
          logError(_internalDb(env), 'policy', (ir.reason || '정책 위반').slice(0, 300), ir.code || 'INJECT', ir.table || '');
          return new Response(JSON.stringify({ ok: false, error: ir.reason, code: ir.code, table: ir.table }), { status: 403, headers });
        }
        if (ir.injected) {
          sql = ir.sql;
          params = ir.params;
          logSecurity(_internalDb(env), 'tenant_injected', clientIp, '/api/_dokkebi/db', (ir.sql || '').slice(0, 100));
        }
      } else {
        // verify 모드 (또는 그 외 명시되지 않은 값 → 기본 verify)
        const vr = verifyTenantPolicy(sql!, params, tenantContext, _policyMeta, { strict: _policyMeta.strict !== false });
        if (!vr.ok) {
          logSecurity(_internalDb(env), 'tenant_policy_violation', clientIp, '/api/_dokkebi/db', (vr.code || 'VERIFY') + ': ' + (vr.reason || '') + ' | ' + sql?.slice(0, 100));
          logError(_internalDb(env), 'policy', (vr.reason || '정책 위반').slice(0, 300), vr.code || 'VERIFY', vr.table || '');
          return new Response(JSON.stringify({ ok: false, error: vr.reason, code: vr.code, table: vr.table }), { status: 403, headers });
        }
      }
    }

    // ── 6d. Authorization Policy (Stage 4, opt-in) ──────────
    //   _authzMeta 가 설정된 경우에만 동작. Tenant Policy 가 주입한 최종 SQL
    //   에서 op/table 을 재추출해 규칙 매칭 → JWT 서명/role 검증 순으로 실행.
    //   403 시 상세 에러 코드: AUTH_REQUIRED, ROLE_MISSING, ROLE_FORBIDDEN,
    //   RULE_DENY, NO_RULE(strict 모드) 등.
    //   문서: docs/design/AUTHORIZATION.md
    if (_authzMeta && _authzMeta.enabled) {
      const az_upper = sql!.toUpperCase().trimStart();
      let az_op: string | null = null;
      if (az_upper.startsWith('SELECT') || az_upper.startsWith('WITH')) az_op = 'SELECT';
      else if (az_upper.startsWith('INSERT')) az_op = 'INSERT';
      else if (az_upper.startsWith('UPDATE')) az_op = 'UPDATE';
      else if (az_upper.startsWith('DELETE')) az_op = 'DELETE';
      else if (az_upper.startsWith('CREATE TABLE')) az_op = 'CREATE';

      const az_primary = az_op ? detectPrimaryTable(stripStringsAndComments(sql!).replace(/\s+/g, ' ').trim().toUpperCase(), az_op) : null;
      const az_table = az_primary || '';

      const matched = _az_matchRule(az_op || '*', az_table);

      // 규칙이 매칭되지 않은 경우: warn 모드면 통과, strict 모드면 NO_RULE
      // 매칭된 경우에만 JWT 검증 시도 (불필요한 검증 비용 절감)
      let jwtRes: any = null;
      const needsJwt = matched && matched.spec && matched.spec.public !== true;
      if (needsJwt) {
        const token = _az_extractBearerToken(request, payload);
        if (token) {
          jwtRes = await _az_verifyJwtHs256(token, env);
        } else {
          jwtRes = { valid: false, reason: 'Authorization 헤더 없음' };
        }
      }

      const decision = _az_authorize(matched, jwtRes);
      if (!decision.ok) {
        logSecurity(_internalDb(env), 'authz_denied', clientIp, '/api/_dokkebi/db',
          (decision.code || 'DENY') + ': ' + (decision.reason || '') +
          ' | op=' + (az_op || '?') + ' table=' + (az_table || '?') +
          (matched ? ' rule=' + matched.key : ' rule=<none>'));
        return new Response(JSON.stringify({
          ok: false,
          error: decision.reason,
          code: decision.code,
        }), { status: decision.code === 'AUTH_REQUIRED' ? 401 : 403, headers });
      }
    }

    // ── Phase 2-⑦ Mutation budget (sliding 1-min window) ────
    //   HMAC 이 통과한 정당 요청만 이 지점에 도달. XSS 하이재킹 시 세션
    //   내부에서 자동화된 대량 쓰기 시도를 차단한다.
    {
      const _up = sql!.toUpperCase().trimStart();
      const _isWrite = _up.startsWith('INSERT') || _up.startsWith('UPDATE') || _up.startsWith('DELETE');
      const _isDelete = _up.startsWith('DELETE');
      if (_isWrite) {
        const _tnow = Date.now();
        if (_tnow - cached.writeWindowStart > _MUTATION_WINDOW_MS) {
          cached.writeWindowStart = _tnow; cached.writeCount = 0;
        }
        if (cached.writeCount + 1 > _WRITE_CAP_PER_MIN) {
          logSecurity(_internalDb(env), 'mutation_budget', clientIp, '/api/_dokkebi/db', 'write quota exceeded for session');
          return new Response(JSON.stringify({
            ok: false, code: 'MUTATION_BUDGET', error: '세션의 분당 쓰기 한도를 초과했습니다.',
          }), { status: 429, headers });
        }
        cached.writeCount += 1;
      }
      if (_isDelete) {
        const _tnow = Date.now();
        if (_tnow - cached.deleteWindowStart > _MUTATION_WINDOW_MS) {
          cached.deleteWindowStart = _tnow; cached.deleteCount = 0;
        }
        if (cached.deleteCount + 1 > _DELETE_CAP_PER_MIN) {
          logSecurity(_internalDb(env), 'mutation_budget', clientIp, '/api/_dokkebi/db', 'delete quota exceeded for session');
          return new Response(JSON.stringify({
            ok: false, code: 'MUTATION_BUDGET', error: '세션의 분당 삭제 한도를 초과했습니다.',
          }), { status: 429, headers });
        }
        cached.deleteCount += 1;
      }
    }

    // ── 7. DB 쿼리 실행 (유일한 블로킹 D1 호출) ─────────────
    // Phase B-3: D1 Sessions — SELECT 면 replica, 그 외 primary. 쿠키 우선.
    const _isReadOnly = _isReadOnlySelectSql(sql!);
    const _userSession = _withMaybeSession(_userDbForSql(env, sql!), request, _isReadOnly);
    const result = _userSession.using === 'off'
      ? await executeD1Query(env, sql!, params)
      : await (async () => {
          const stmt = _userSession.db.prepare(sql!);
          const bound = params.length > 0 ? stmt.bind(...params) : stmt;
          const r = await bound.all();
          return {
            rows: (r.results || []).map((x: any) => JSON.stringify(x)),
            affected: (r.meta as any)?.changes ?? 0,
            lastInsertId: (r.meta as any)?.last_row_id ?? 0,
          };
        })();
    if (_userSession.using !== 'off') {
      _appendBookmarkCookie(headers, _userSession.db, _userSession.bookmark);
    }
    ctx.waitUntil(logSecurity(_internalDb(env), 'db_audit', clientIp, '/api/_dokkebi/db',
      _summarizeDbAudit(sql!, queryId, params, result, Date.now() - reqStart)));
    ctx.waitUntil(logRequest(_internalDb(env), 'POST', '/api/_dokkebi/db', 200, Date.now() - reqStart, clientIp));
    const responsePayload = { ok: true, value: result };

    // ── 8. 응답 AES-GCM 암호화 (CPU only) ────────────────────
    const resIv = crypto.getRandomValues(new Uint8Array(12));
    const resPlain = new TextEncoder().encode(JSON.stringify(responsePayload));
    const resEncrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: resIv }, cached.encKey, resPlain);
    const encResponse = {
      _enc: true,
      enc: encBytesToB64(resEncrypted),
      iv: encBytesToB64(resIv),
    };

    ctx.waitUntil(cleanupExpired(_internalDb(env)));

    return new Response(JSON.stringify(encResponse), { headers });

  } catch (e: unknown) {
    return new Response(
      JSON.stringify({ ok: false, error: sanitizeError(e) }),
      { status: 200, headers }
    );
  }
};

/* __DOKKEBI_PH_D1_QUERY__ */
let _lastCleanup = 0;
async function cleanupExpired(db: D1Database) {
  const now = Date.now();
  if (now - _lastCleanup < 60_000) return;
  _lastCleanup = now;
  pruneSessionCache();
  prunePregateTmp();
  try {
    await db.batch([
      db.prepare(`DELETE FROM _dokkebi_nonces WHERE expires_at < ?`).bind(now),
      db.prepare(`DELETE FROM _dokkebi_sessions WHERE created_at < ?`).bind(now - SESSION_TTL_MS),
      db.prepare(`DELETE FROM _dokkebi_ephemeral_keys WHERE created_at < ?`).bind(now - 60_000),
    ]);
  } catch { /* ignore */ }
}
