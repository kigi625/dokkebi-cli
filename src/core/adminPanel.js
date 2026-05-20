/**
 * dokkebi 관제 어드민 패널
 *
 * 기능:
 *   - DOKKEBI_ADMIN_PASSWORD 기반 비밀번호 인증 (HMAC 서명 토큰)
 *   - 실시간 접속자 / 에러율 / 보안 이벤트 / API 통계 대시보드
 *   - _dokkebi_errors / _dokkebi_security / _dokkebi_requests 테이블 조회
 *   - 서버 모드 + 서버리스 모드 모두 지원
 *
 * 어드민 라우트:
 *   GET  /_dokkebi/_panel          → 대시보드 HTML
 *   POST /_dokkebi/_panel/auth     → 비밀번호 인증 → 토큰 발급
 *   GET  /_dokkebi/_panel/api/*    → 데이터 API (토큰 필수)
 */

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { renderTemplate } from './templateLoader.js';

// ─────────────────────────────────────────────────────────────
// /auth Rate Limiting — IP당 5분에 최대 10회, 초과 시 10분 잠금
// ─────────────────────────────────────────────────────────────
const _authAttempts = new Map(); // ip → { count, resetAt, lockedUntil }

function _checkAuthRateLimit(ip) {
    const now = Date.now();
    let entry = _authAttempts.get(ip);

    if (entry?.lockedUntil && now < entry.lockedUntil) {
        const remaining = Math.ceil((entry.lockedUntil - now) / 1000);
        return { allowed: false, reason: `너무 많은 로그인 시도. ${remaining}초 후 다시 시도하세요.` };
    }

    if (!entry || now > entry.resetAt) {
        entry = { count: 0, resetAt: now + 5 * 60 * 1000, lockedUntil: 0 };
    }

    entry.count += 1;
    _authAttempts.set(ip, entry);

    if (entry.count > 10) {
        entry.lockedUntil = now + 10 * 60 * 1000;
        return { allowed: false, reason: '로그인 시도 횟수 초과. 10분 후 다시 시도하세요.' };
    }

    return { allowed: true };
}

function _resetAuthRateLimit(ip) {
    _authAttempts.delete(ip);
}

function _requestIp(req) {
    return req.headers['cf-connecting-ip']
        || (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.socket?.remoteAddress
        || 'unknown';
}

function _normalizeIp(ip) {
    return String(ip || '').trim().replace(/^::ffff:/, '');
}

function _ipv4ToInt(ip) {
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

function _ipRuleMatch(ip, rule) {
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

function _panelIpAllowed(ip, allowedIps = '') {
    const raw = String(allowedIps || '').trim();
    if (!raw) return true;
    const rules = raw.split(',').map(s => s.trim()).filter(Boolean);
    return rules.some(rule => _ipRuleMatch(ip, rule));
}

// ─────────────────────────────────────────────────────────────
// 어드민 세션 관리 (메모리, serve/dev 모드용)
// ─────────────────────────────────────────────────────────────

const _adminSessions = new Map(); // token → expiry

setInterval(() => {
    const now = Date.now();
    for (const [tok, exp] of _adminSessions) {
        if (now > exp) _adminSessions.delete(tok);
    }
}, 60_000).unref();

export function createAdminToken(adminPassword) {
    const token  = randomBytes(32).toString('hex');
    const expiry = Date.now() + 4 * 3600_000; // 4시간
    const sig    = createHmac('sha256', adminPassword + ':admin').update(token).digest('hex');
    const full   = `${token}.${sig}`;
    _adminSessions.set(full, expiry);
    return { token: full, expires: expiry };
}

export function verifyAdminToken(token, adminPassword) {
    if (!token || typeof token !== 'string') return false;
    const [tok, sig] = token.split('.');
    if (!tok || !sig) return false;
    const expiry = _adminSessions.get(token);
    if (!expiry || Date.now() > expiry) { _adminSessions.delete(token); return false; }
    const expected = createHmac('sha256', adminPassword + ':admin').update(tok).digest('hex');
    try {
        return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'));
    } catch { return false; }
}

// ─────────────────────────────────────────────────────────────
// 보안 이벤트 DB 기록 헬퍼
// ─────────────────────────────────────────────────────────────

export async function logSecurityEvent(proxyDbQuery, dbType, dbConfig, { type, ip = '', path = '', detail = '' }) {
    try {
        const id = randomBytes(8).toString('hex') + Date.now().toString(36);
        await proxyDbQuery(dbType, dbConfig,
            `INSERT OR IGNORE INTO "_dokkebi_security" ("id","type","ip","path","detail") VALUES (?,?,?,?,?)`,
            [id, type, ip, path, detail.slice(0, 500)]
        );
    } catch { /* 보안 로그 실패 무시 */ }
}

export async function logRequest(proxyDbQuery, dbType, dbConfig, { method = 'POST', path = '', status = 200, durationMs = 0, ip = '' }) {
    try {
        const id = randomBytes(8).toString('hex') + Date.now().toString(36);
        await proxyDbQuery(dbType, dbConfig,
            `INSERT OR IGNORE INTO "_dokkebi_requests" ("id","method","path","status","duration_ms","ip") VALUES (?,?,?,?,?,?)`,
            [id, method, path, status, durationMs, ip]
        );
    } catch { /* 요청 로그 실패 무시 */ }
}

export async function logError(proxyDbQuery, dbType, dbConfig, { source = 'host', level = 'error', message = '', stack = '', path = '', method = '' }) {
    try {
        const id = randomBytes(8).toString('hex') + Date.now().toString(36);
        await proxyDbQuery(dbType, dbConfig,
            `INSERT OR IGNORE INTO "_dokkebi_errors" ("id","source","level","message","stack","path","method") VALUES (?,?,?,?,?,?,?)`,
            [id, source, level, message.slice(0, 1000), (stack || '').slice(0, 2000), path, method]
        );
    } catch { /* 에러 로그 실패 무시 */ }
}

// ─────────────────────────────────────────────────────────────
// 어드민 라우트 핸들러 (serve.js / dev.js에서 호출)
// ─────────────────────────────────────────────────────────────

// 어드민 라우트용 body 상한: 요청 종류별로 세분화
const _ADMIN_BODY_LIMITS = {
    auth:    2 * 1024,       // 비밀번호만
    default: 64 * 1024,      // 일반 API
};

function _readJson(req, maxBytes = _ADMIN_BODY_LIMITS.default) {
    return new Promise((resolve, reject) => {
        const contentLength = Number(req.headers['content-length']);
        if (Number.isFinite(contentLength) && contentLength > maxBytes) {
            const err = new Error('PAYLOAD_TOO_LARGE');
            err.code = 'PAYLOAD_TOO_LARGE';
            reject(err);
            req.resume?.();
            return;
        }
        const chunks = [];
        let received = 0;
        let aborted = false;
        req.on('data', (c) => {
            if (aborted) return;
            received += c.length;
            if (received > maxBytes) {
                aborted = true;
                const err = new Error('PAYLOAD_TOO_LARGE');
                err.code = 'PAYLOAD_TOO_LARGE';
                reject(err);
                try { req.destroy(); } catch { /* ignore */ }
                return;
            }
            chunks.push(c);
        });
        req.on('end', () => {
            if (aborted) return;
            try {
                const raw = Buffer.concat(chunks).toString('utf-8');
                resolve(raw.length === 0 ? {} : JSON.parse(raw));
            } catch (e) { reject(e); }
        });
        req.on('error', (e) => { if (!aborted) reject(e); });
    });
}

function _json(res, status, data) {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(data));
}

/**
 * @param {object} opts
 * @param {string}   opts.adminPassword     - DOKKEBI_ADMIN_PASSWORD 환경변수 값
 * @param {string}   opts.adminAllowedIps   - DOKKEBI_PANEL_ALLOWED_IPS 환경변수 값
 * @param {boolean}  opts.panelIpGuardEnabled - config security.panelIpGuard 활성 여부
 * @param {string}   opts.dbType            - 'd1' | 'supabase' | 'appwrite'
 * @param {object}   opts.dbConfig          - DB 자격증명
 * @param {Function} opts.proxyDbQuery      - serve.js의 proxyDbQuery
 * @param {number}   opts.activeConnections - 현재 SSE 연결 수 (serve 모드)
 * @param {string}   opts.projectName       - 프로젝트명
 * @param {string}   opts.mode              - 'serve' | 'dev'
 */
export async function handleAdminRoute(req, res, opts) {
    const { adminPassword, adminAllowedIps = '', panelIpGuardEnabled = false, dbType, dbConfig, proxyDbQuery, activeConnections = 0, projectName = 'dokkebi', mode = 'serve' } = opts;
    const rawPath = req.url?.split('?')[0] || '/';
    // /api/_dokkebi/_panel/... 와 /_dokkebi/_panel/... 모두 동일하게 처리
    const urlPath = rawPath.startsWith('/api/_dokkebi/_panel')
        ? rawPath.slice('/api'.length)
        : rawPath;
    const clientIp = _requestIp(req);

    if (panelIpGuardEnabled && !_panelIpAllowed(clientIp, adminAllowedIps)) {
        _json(res, 403, { error: '접근이 허용되지 않은 IP 입니다.' });
        return true;
    }

    // 어드민 비밀번호 미설정 시 안내
    if (!adminPassword) {
        res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"></head><body style="font-family:monospace;padding:40px;background:#0d1117;color:#e6edf3">
<h2>⚙️ 도깨비 관제 어드민</h2>
<p>관제 어드민을 활성화하려면 <code>.env</code>에 아래 항목을 추가하세요:</p>
<pre style="background:#161b22;padding:16px;border-radius:8px">DOKKEBI_ADMIN_PASSWORD=your_secure_password</pre>
<p>설정 후 서버를 재시작하세요.</p></body></html>`);
        return true;
    }

    // ── 어드민 HTML 서빙 ───────────────────────────────────────
    if ((urlPath === '/_dokkebi/_panel' || urlPath === '/_dokkebi/_panel/') && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(generateAdminHtml({ projectName, mode }));
        return true;
    }

    // ── 인증 엔드포인트 ───────────────────────────────────────
    if (urlPath === '/_dokkebi/_panel/auth' && req.method === 'POST') {
        // Rate Limit 검사
        const rl = _checkAuthRateLimit(clientIp);
        if (!rl.allowed) {
            _json(res, 429, { error: rl.reason });
            return true;
        }

        let body;
        try { body = await _readJson(req, _ADMIN_BODY_LIMITS.auth); }
        catch (e) {
            if (e?.code === 'PAYLOAD_TOO_LARGE') return _json(res, 413, { error: '요청 본문이 너무 큽니다.' }), true;
            return _json(res, 400, { error: '잘못된 요청' }), true;
        }

        const { password } = body || {};
        // 상수시간 비교:
        //  1) 비교 대상 길이를 항상 expected.length로 패딩 → 길이 기반 타이밍 채널 차단
        //  2) timingSafeEqual 은 같은 길이 버퍼에서만 안전하게 동작
        const expected = Buffer.from(adminPassword, 'utf-8');
        const providedRaw = Buffer.from(String(password || ''), 'utf-8');
        const provided = Buffer.alloc(expected.length);
        providedRaw.copy(provided, 0, 0, Math.min(expected.length, providedRaw.length));
        let match = false;
        try { match = timingSafeEqual(expected, provided); }
        catch { match = false; }
        // 길이가 다르면 내용이 같더라도 불일치 처리
        if (providedRaw.length !== expected.length) match = false;

        if (!match) {
            _json(res, 401, { error: '비밀번호가 올바르지 않습니다.' });
            return true;
        }

        // 로그인 성공 시 카운터 리셋
        _resetAuthRateLimit(clientIp);
        const { token, expires } = createAdminToken(adminPassword);
        _json(res, 200, { token, expires });
        return true;
    }

    // ── API 엔드포인트 (토큰 필수) ────────────────────────────
    if (urlPath.startsWith('/_dokkebi/_panel/api/')) {
        const authHeader = req.headers['authorization'] || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';

        if (!verifyAdminToken(token, adminPassword)) {
            _json(res, 401, { error: '인증이 필요합니다.' });
            return true;
        }

        const apiSub = urlPath.slice('/_dokkebi/_panel/api/'.length);
        const qs     = new URLSearchParams(req.url?.split('?')[1] || '');

        try {
            await _handleAdminApi(req, res, apiSub, qs, { dbType, dbConfig, proxyDbQuery, activeConnections, mode });
        } catch (e) {
            _json(res, 500, { error: e.message });
        }
        return true;
    }

    return false; // 어드민 라우트 아님
}

// proxyDbQuery가 rows를 JSON 문자열 배열로 반환하므로 파싱 필요
function _parseRows(result) {
    return (result?.rows || []).map(r => {
        if (typeof r === 'string') { try { return JSON.parse(r); } catch { return {}; } }
        return r ?? {};
    });
}
function _parseRow(result) {
    return _parseRows(result)[0] ?? {};
}

async function _handleAdminApi(req, res, sub, qs, { dbType, dbConfig, proxyDbQuery, activeConnections, mode }) {
    const limit  = Math.min(Number(qs.get('limit')  || 50), 200);
    const offset = Number(qs.get('offset') || 0);

    // ── 개요 ────────────────────────────────────────────────
    if (sub === 'overview') {
        const [errRes, secRes, reqRes, actRes] = await Promise.allSettled([
            proxyDbQuery(dbType, dbConfig,
                `SELECT COUNT(*) as cnt FROM "_dokkebi_errors" WHERE ts >= datetime('now','-24 hours')`, []),
            proxyDbQuery(dbType, dbConfig,
                `SELECT COUNT(*) as cnt FROM "_dokkebi_security" WHERE ts >= datetime('now','-24 hours')`, []),
            proxyDbQuery(dbType, dbConfig,
                `SELECT COUNT(*) as cnt FROM "_dokkebi_requests" WHERE ts >= datetime('now','-24 hours')`, []),
            proxyDbQuery(dbType, dbConfig,
                `SELECT COUNT(DISTINCT ip) as cnt FROM "_dokkebi_requests" WHERE ts >= datetime('now','-5 minutes')`, []),
        ]);

        const errCount = errRes.status === 'fulfilled'  ? (_parseRow(errRes.value).cnt  ?? 0) : 0;
        const secCount = secRes.status === 'fulfilled'  ? (_parseRow(secRes.value).cnt  ?? 0) : 0;
        const reqCount = reqRes.status === 'fulfilled'  ? (_parseRow(reqRes.value).cnt  ?? 0) : 0;
        const recentIp = actRes.status === 'fulfilled'  ? (_parseRow(actRes.value).cnt  ?? 0) : 0;

        // dev/serve 모드: SSE 연결 수 + 최근 5분 IP 수 중 큰 값 / 서버리스: 최근 5분 IP 수
        const active = (mode === 'serve' || mode === 'dev')
            ? Math.max(activeConnections, recentIp)
            : recentIp;

        // 최근 7일 요청 추이
        let trend = [];
        try {
            const tr = await proxyDbQuery(dbType, dbConfig,
                `SELECT date(ts) as day, COUNT(*) as cnt
                 FROM "_dokkebi_requests"
                 WHERE ts >= datetime('now','-7 days')
                 GROUP BY day ORDER BY day`, []);
            trend = _parseRows(tr);
        } catch { /* 없으면 빈 배열 */ }

        return _json(res, 200, {
            activeUsers: active,
            errors24h:   errCount,
            security24h: secCount,
            requests24h: reqCount,
            trend,
            mode,
        });
    }

    // ── 에러 로그 ────────────────────────────────────────────
    if (sub === 'errors') {
        const level = qs.get('level') || '';
        const where = level ? `WHERE level = ?` : '';
        const params = level ? [level] : [];
        const [rows, total] = await Promise.all([
            proxyDbQuery(dbType, dbConfig,
                `SELECT id, ts, source, level, message, stack, path, method
                 FROM "_dokkebi_errors" ${where}
                 ORDER BY ts DESC LIMIT ? OFFSET ?`,
                [...params, limit, offset]),
            proxyDbQuery(dbType, dbConfig,
                `SELECT COUNT(*) as cnt FROM "_dokkebi_errors" ${where}`, params),
        ]);
        return _json(res, 200, { rows: _parseRows(rows), total: _parseRow(total).cnt ?? 0 });
    }

    // ── 보안 이벤트 ──────────────────────────────────────────
    if (sub === 'security') {
        const [rows, total] = await Promise.all([
            proxyDbQuery(dbType, dbConfig,
                `SELECT id, ts, type, ip, path, detail FROM "_dokkebi_security"
                 ORDER BY ts DESC LIMIT ? OFFSET ?`, [limit, offset]),
            proxyDbQuery(dbType, dbConfig,
                `SELECT COUNT(*) as cnt FROM "_dokkebi_security"`, []),
        ]);
        return _json(res, 200, { rows: _parseRows(rows), total: _parseRow(total).cnt ?? 0 });
    }

    // ── 요청 로그 ────────────────────────────────────────────
    if (sub === 'requests') {
        const [rows, total] = await Promise.all([
            proxyDbQuery(dbType, dbConfig,
                `SELECT id, ts, method, path, status, duration_ms, ip FROM "_dokkebi_requests"
                 ORDER BY ts DESC LIMIT ? OFFSET ?`, [limit, offset]),
            proxyDbQuery(dbType, dbConfig,
                `SELECT COUNT(*) as cnt FROM "_dokkebi_requests"`, []),
        ]);
        return _json(res, 200, { rows: _parseRows(rows), total: _parseRow(total).cnt ?? 0 });
    }

    // ── 에러 상세 삭제 ────────────────────────────────────────
    if (sub === 'errors/clear' && req.method === 'POST') {
        await proxyDbQuery(dbType, dbConfig, `DELETE FROM "_dokkebi_errors"`, []);
        return _json(res, 200, { ok: true });
    }

    _json(res, 404, { error: '알 수 없는 API 경로' });
}

// ─────────────────────────────────────────────────────────────
// 어드민 HTML 생성
// ─────────────────────────────────────────────────────────────

export function generateAdminHtml({ projectName = 'dokkebi', mode = 'serve' } = {}) {
    return renderTemplate('adminPanel.html.tpl', [
        { find: '__DOKKEBI_PH_PROJECT_NAME__', replace: String(projectName) },
        { find: '__DOKKEBI_PH_MODE__',         replace: String(mode) },
    ]);
}
