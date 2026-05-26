/**
 * dokkebi serve 커맨드 (v3.1 — ECDH + HMAC 보안 강화)
 *
 * 역할:
 *   1. 정적 파일 서빙 (dist/)
 *   2. ECDH P-256 핸드셰이크
 *      GET  /api/_dokkebi/handshake → 서버 공개키 반환
 *      POST /api/_dokkebi/handshake → 클라이언트 공개키 수신, 세션키 HKDF 파생
 *   3. D1/Supabase/Appwrite DB 프록시 (AES-256-GCM + HMAC-SHA256 + nonce)
 *      POST /api/_dokkebi/db
 *   4. 백엔드 로그 수집
 *      POST /api/_dokkebi/log
 *
 * 보안 계층:
 *   - ECDH P-256 Ephemeral Key Exchange (Forward Secrecy)
 *   - HKDF-SHA256으로 encKey(암호화) / sigKey(서명) 별도 파생
 *   - AES-256-GCM 페이로드 암호화
 *   - HMAC-SHA256 요청 서명 (무결성)
 *   - Nonce 캐시 (재전송 공격 방어)
 *   - Timestamp ±30초 검증 (재전송 공격 방어)
 *   - timingSafeEqual (타이밍 공격 방어)
 *   - IP 기반 Rate Limiting (DoS/브루트포스 방어)
 *   - sessionStore 최대 크기 제한 (메모리 고갈 방어)
 *   - SQL 쿼리 기본 검증 레이어 (위험 구문 차단)
 *   - 에러 응답 내부 정보 마스킹 (정보 노출 방어)
 *   - 복호화 버퍼 즉시 제로화 (메모리 잔류 방어)
 */

import path from 'path';
import http from 'http';
import { frameSrcDirective, CSP_SCRIPT_SRC_LEMON_SQUEEZY } from '../core/cspFrameSrc.js';
import https from 'https';
import fs from 'fs/promises';
import { handleAdminRoute, logSecurityEvent, logRequest, logError } from '../core/adminPanel.js';
import { loadDokkebiConfigMerged } from '../core/dokkebiConfigLoad.js';
import { loadAllowlist, validateSqlAllowlist } from '../core/sqlAllowlist.js';
import {
    createECDH,
    createHmac,
    createCipheriv,
    createDecipheriv,
    timingSafeEqual,
    hkdfSync,
    randomBytes,
} from 'crypto';
import { runBuild } from './build.js';
import { loadWireRuntimeForLocalProxy, denormalizePayload, verifyAndStripPow } from '../core/payloadWireRuntime.js';
import { buildBundleBootPayload, injectBundleBootScript } from '../core/bundleBoot.js';
import { t } from '../i18n/index.js';

// ─────────────────────────────────────────────────────────────
// 서버 시작 시 ECDH P-256 키쌍 생성 (세션마다 새로 생성 = Ephemeral)
// ─────────────────────────────────────────────────────────────
const serverEcdh = createECDH('prime256v1');
serverEcdh.generateKeys();
// 브라우저 WebCrypto에서 importKey('raw') 가능한 비압축 포인트 형식
const SERVER_PUB_KEY_B64 = serverEcdh.getPublicKey('base64');

// sessionId → { encKey: Buffer, sigKey: Buffer, createdAt: number }
const sessionStore = new Map();

// nonce → expiry timestamp (재전송 공격 방어 캐시)
const nonceCache = new Map();

// ─────────────────────────────────────────────────────────────
// 보안 상수
// ─────────────────────────────────────────────────────────────
const MAX_SESSIONS     = 500;     // 동시 최대 세션 수 (메모리 고갈 방어)
const SQL_MAX_LENGTH   = 50_000;  // SQL 최대 길이 (50KB)
const RATE_WINDOW_MS   = 60_000;  // Rate Limit 윈도우 (1분)
const RATE_LIMITS = {
    handshake: 20,   // IP당 1분 20회 (ECDH CPU 비용 방어)
    db:        300,  // IP당 1분 300회 (적법 클라이언트 보호 — 세션 필요)
    log:       600,  // IP당 1분 600회 (WASM 로그 전송 보호)
};

// 요청 본문 최대 크기 (DoS 방어)
const BODY_LIMITS = {
    handshake:  8 * 1024,     // 8KB — clientPubKey + 필드
    db:         128 * 1024,   // 128KB — 암호문 + 여유
    log:        64 * 1024,    // 64KB — 로그 배치
    adminAuth:  2 * 1024,     // 2KB — password
    default:    16 * 1024,    // 16KB
};

// ─────────────────────────────────────────────────────────────
// Rate Limiter (IP 기반, 슬라이딩 윈도우)
// ─────────────────────────────────────────────────────────────
const rateLimitMap = new Map(); // `${ip}:${endpoint}` → { count, windowStart }

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
        || req.socket?.remoteAddress
        || 'unknown';
}

function checkRateLimit(ip, endpoint) {
    const key   = `${ip}:${endpoint}`;
    const limit = RATE_LIMITS[endpoint] || 100;
    const now   = Date.now();
    const entry = rateLimitMap.get(key);
    if (!entry || (now - entry.windowStart) > RATE_WINDOW_MS) {
        rateLimitMap.set(key, { count: 1, windowStart: now });
        return true;
    }
    entry.count++;
    return entry.count <= limit;
}

// ─────────────────────────────────────────────────────────────
// SQL 쿼리 기본 검증 레이어 (위험 구문 차단)
// ─────────────────────────────────────────────────────────────
const SQL_BLOCKED_PATTERNS = [
    /\bATTACH\s+DATABASE\b/i,
    /\bDETACH\s+DATABASE\b/i,
    /\bPRAGMA\s+(?:key|rekey|wal_autocheckpoint|secure_delete)\b/i,
    /\bLOAD_EXTENSION\b|\bLOAD\s+EXTENSION\b/i, // SQLite 함수형(load_extension()) + SQL 구문형 모두 차단
];

function validateSql(sql) {
    if (!sql || typeof sql !== 'string') {
        return { ok: false, reason: 'SQL이 비어 있습니다.' };
    }
    if (sql.length > SQL_MAX_LENGTH) {
        return { ok: false, reason: `SQL이 너무 깁니다. (최대 ${SQL_MAX_LENGTH}자)` };
    }
    for (const pattern of SQL_BLOCKED_PATTERNS) {
        if (pattern.test(sql)) {
            return { ok: false, reason: '허용되지 않는 SQL 구문입니다.' };
        }
    }
    return { ok: true };
}

// ─────────────────────────────────────────────────────────────
// 에러 메시지 마스킹 (내부 자격증명/경로 노출 방어)
// ─────────────────────────────────────────────────────────────
function sanitizeDbError(err) {
    const msg = err?.message || String(err);
    if (/Authorization|apiToken|Bearer|apikey|X-Appwrite/i.test(msg)) {
        return 'DB 연결 오류가 발생했습니다.';
    }
    const httpMatch = msg.match(/HTTP (\d{3}):/);
    if (httpMatch) return `DB 요청 실패 (HTTP ${httpMatch[1]})`;
    // 파일 경로 제거 후 최대 200자
    return msg.replace(/\/[^\s]+/g, '[경로]').slice(0, 200);
}

// 만료 nonce 정리 (60초 간격)
setInterval(() => {
    const now = Date.now();
    for (const [n, exp] of nonceCache) {
        if (now > exp) nonceCache.delete(n);
    }
}, 60_000).unref();

// 만료 세션 정리 (30분 간격, 8시간 지난 세션 삭제)
const SESSION_STORE_TTL_MS = 8 * 60 * 60_000; // 8시간
setInterval(() => {
    const cutoff = Date.now() - SESSION_STORE_TTL_MS;
    for (const [id, sess] of sessionStore) {
        if (sess.createdAt < cutoff) sessionStore.delete(id);
    }
}, 30 * 60_000).unref();

// 만료 Rate Limit 항목 정리 (5분 간격)
setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of rateLimitMap) {
        if (now - entry.windowStart > RATE_WINDOW_MS * 2) rateLimitMap.delete(key);
    }
}, 5 * 60_000).unref();

const MIME_TYPES = {
    '.html': 'text/html',
    '.js':   'application/javascript',
    '.mjs':  'application/javascript',
    '.json': 'application/json',
    '.css':  'text/css',
    '.wasm': 'application/wasm',
    '.ico':  'image/x-icon',
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.svg':  'image/svg+xml',
    '.woff': 'font/woff',
    '.woff2':'font/woff2',
    '.ttf':  'font/ttf',
    '.map':  'application/json',
};

const C = {
    reset:   '\x1b[0m',
    gray:    '\x1b[90m',
    green:   '\x1b[32m',
    yellow:  '\x1b[33m',
    red:     '\x1b[31m',
    cyan:    '\x1b[36m',
    blue:    '\x1b[34m',
    magenta: '\x1b[35m',
    bold:    '\x1b[1m',
};

function ts() {
    return C.gray + new Date().toLocaleTimeString('ko-KR') + C.reset;
}

// ─────────────────────────────────────────────────────────────
// 메인 서버
// ─────────────────────────────────────────────────────────────

export async function runServe(src, options = {}) {
    const sourceRoot = path.resolve(process.cwd(), src);
    const outputName = options.output || 'dist';

    // ── 서버리스 모드 감지 → 경고 출력 ──────────────────────
    await checkServerlessMode(sourceRoot);

    if (options.skipBuild !== true) {
        console.log(t('serve.buildBefore'));
        await runBuild(src, { ...options, output: outputName, skipMigration: true });
    }

    const distRoot = path.join(sourceRoot, outputName);
    try {
        await fs.access(distRoot);
    } catch {
        throw new Error(
            `[dokkebi] 빌드 결과 폴더가 없습니다: ${distRoot}\n먼저 'dokkebi build'를 실행하세요.`
        );
    }

    const envVars = await loadEnvFile(sourceRoot);

    // 포트 우선순위: CLI 옵션 > .env PORT > dokkebi.config.js serve.port > 기본값 5174
    const dokConfig = await _loadDokConfig(sourceRoot);
    const port = Number(options.port) || Number(envVars.PORT) || Number(process.env.PORT)
                 || Number(dokConfig?.serve?.port) || 5174;

    const dbType      = options.dbType || envVars.DOKKEBI_DB_TYPE || 'd1';
    const dbConfig    = resolveDbConfig(dbType, envVars);
    const adminPassword = envVars.DOKKEBI_ADMIN_PASSWORD || process.env.DOKKEBI_ADMIN_PASSWORD || '';
    const panelIpGuardEnabled = dokConfig?.security?.panelIpGuard === true
        || dokConfig?.security?.panelIpGuard?.enabled === true
        || dokConfig?.security?.adminPanel?.ipAllowlist === true
        || dokConfig?.security?.adminPanel?.ipAllowlist?.enabled === true;
    const adminAllowedIps = panelIpGuardEnabled
        ? (envVars.DOKKEBI_PANEL_ALLOWED_IPS || envVars.DOKKEBI_ADMIN_ALLOWED_IPS
            || process.env.DOKKEBI_PANEL_ALLOWED_IPS || process.env.DOKKEBI_ADMIN_ALLOWED_IPS || '')
        : '';
    const projectName   = dokConfig?.name || path.basename(sourceRoot);
    const proxyMode     = dokConfig?.proxyMode || 'server';

    // env-secrets.json 로드 (빌드 타임에 분리된 민감 환경변수)
    let envSecrets = {};
    try {
        const newSecretsPath = path.join(sourceRoot, '.dokkebi', 'env-secrets.json');
        const legacySecretsPath = path.join(distRoot, 'dokkebi', 'env-secrets.json');
        let secretsPath;
        try { await fs.access(newSecretsPath); secretsPath = newSecretsPath; } catch {
            secretsPath = legacySecretsPath;
        }
        const raw = JSON.parse(await fs.readFile(secretsPath, 'utf-8'));
        envSecrets = raw.secrets || {};
    } catch { /* 매니페스트 없으면 기존 방식 유지 */ }

    const handshakeSecretSource = { ...envVars, ...envSecrets };
    if (Object.keys(envSecrets).length > 0) {
        const clientSecretCount = Object.keys(pickClientHandshakeSecrets(handshakeSecretSource)).length;
        console.log(`[dokkebi] 🔐 민감 변수 ${Object.keys(envSecrets).length}개 로드, 클라이언트 허용 Secret ${clientSecretCount}개만 핸드셰이크 전달`);
    }

    // SQL Allowlist 로드 (빌드 타임에 생성된 허용목록)
    const allowlistPath = path.join(distRoot, 'dokkebi', 'sql-allowlist.json');
    const sqlAllowlist = await loadAllowlist(allowlistPath);
    if (sqlAllowlist && Array.isArray(sqlAllowlist.tables)) {
        const userTables = sqlAllowlist.tables.filter(t => !t.name.startsWith('_dokkebi_') && t.name !== 'sqlite_master');
        console.log(`[dokkebi] 🛡 SQL 허용목록 로드: ${userTables.length}개 테이블, raw SQL: ${sqlAllowlist.rawAllowed ? '허용' : '차단'}`);
    } else {
        console.warn('[dokkebi] ⚠ SQL 허용목록 없음 — 공통 방어(다중문장·위험토큰·주석 기반 우회)만 수행');
        console.warn('[dokkebi]   보안 강화를 위해 `dok build` 재실행으로 sql-allowlist.json 을 생성하세요.');
    }

    let bundleHash12Serve = '';
    try {
        const bh = await fs.readFile(path.join(distRoot, 'dokkebi', 'backend-bundle.sha256'), 'utf-8');
        bundleHash12Serve = String(bh).trim().slice(0, 12);
    } catch { /* */ }

    const bootSecretServe = String(
        handshakeSecretSource.DOKKEBI_BUNDLE_BOOT_SECRET
        || process.env.DOKKEBI_BUNDLE_BOOT_SECRET
        || '',
    ).trim();
    const bcKeyHexServe = String(handshakeSecretSource.__DOKKEBI_BC_KEY__ || '').replace(/\s/g, '');

    const server = http.createServer(async (req, res) => {
        const urlPath = req.url?.split('?')[0] || '/';
        const reqUrl = new URL(req.url || '/', 'http://dokkebi.serve');
        const page = reqUrl.searchParams.get('page');
        const allowEmbed = page === 'embed' || page === 'noto';

        // ── 보안 헤더 ────────────────────────────────────────
        setSecurityHeaders(res, 'serve', { allowEmbed });

        // ── CORS preflight ──────────────────────────────────
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Dokkebi-Session, Authorization');
        if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

        // ── 어드민 패널 (serve: /_dokkebi/_panel, serverless 호환: /api/_dokkebi/_panel) ──
        if (urlPath.startsWith('/_dokkebi/_panel') || urlPath.startsWith('/api/_dokkebi/_panel')) {
            await handleAdminRoute(req, res, {
                adminPassword, adminAllowedIps, panelIpGuardEnabled, dbType, dbConfig, proxyDbQuery,
                activeConnections: activeSockets.size,
                projectName, mode: 'serve',
            });
            return;
        }

        // ── 0. GET /api/_dokkebi/handshake — 서버 공개키 반환 ──
        if (urlPath === '/api/_dokkebi/handshake' && req.method === 'GET') {
            const ip = getClientIp(req);
            if (!checkRateLimit(ip, 'handshake')) {
                res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
                res.end(JSON.stringify({ error: '요청이 너무 많습니다. 잠시 후 다시 시도하세요.' }));
                console.warn(`${ts()} ${C.yellow}[Rate Limit]${C.reset} 핸드셰이크 초과 (ip: ${ip})`);
                return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
            res.end(JSON.stringify({ serverPubKey: SERVER_PUB_KEY_B64 }));
            console.log(`${ts()} ${C.cyan}[핸드셰이크]${C.reset} 서버 공개키 발급`);
            return;
        }

        // ── 1. POST /api/_dokkebi/handshake — 세션키 HKDF 파생 ──
        if (urlPath === '/api/_dokkebi/handshake' && req.method === 'POST') {
            const ip = getClientIp(req);
            if (!checkRateLimit(ip, 'handshake')) {
                res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
                res.end(JSON.stringify({ error: '요청이 너무 많습니다. 잠시 후 다시 시도하세요.' }));
                console.warn(`${ts()} ${C.yellow}[Rate Limit]${C.reset} 핸드셰이크 POST 초과 (ip: ${ip})`);
                logSecurityEvent(proxyDbQuery, dbType, dbConfig, { type: 'rate_limit', ip, path: urlPath, detail: 'handshake rate limit exceeded' });
                return;
            }
            return handleHandshake(req, res, handshakeSecretSource);
        }

        // ── (deprecated) GET /api/_dokkebi/session — 호환성 유지 ──
        if (urlPath === '/api/_dokkebi/session') {
            res.writeHead(410, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'ECDH 핸드셰이크를 사용하세요: /api/_dokkebi/handshake' }));
            return;
        }

        // ── 2. POST /api/_dokkebi/db — DB 프록시 ──────────────
        if (urlPath === '/api/_dokkebi/db' && req.method === 'POST') {
            const ip = getClientIp(req);
            if (!checkRateLimit(ip, 'db')) {
                res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
                res.end(JSON.stringify({ error: '요청이 너무 많습니다. 잠시 후 다시 시도하세요.' }));
                console.warn(`${ts()} ${C.yellow}[Rate Limit]${C.reset} DB 프록시 초과 (ip: ${ip})`);
                logSecurityEvent(proxyDbQuery, dbType, dbConfig, { type: 'rate_limit', ip, path: urlPath, detail: 'db rate limit exceeded' });
                return;
            }
            return handleDbProxy(req, res, dbType, dbConfig,
                (ev) => logSecurityEvent(proxyDbQuery, dbType, dbConfig, ev),
                sqlAllowlist, distRoot, proxyMode);
        }

        // ── 3. POST /api/_dokkebi/log — 로그 수집 ─────────────
        if (urlPath === '/api/_dokkebi/log' && req.method === 'POST') {
            const ip = getClientIp(req);
            if (!checkRateLimit(ip, 'log')) {
                res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
                res.end(JSON.stringify({ error: '로그 전송량이 너무 많습니다.' }));
                return;
            }
            return handleLogCollect(req, res, { proxyDbQuery, dbType, dbConfig, ip });
        }

        // ── 4. 정적 파일 서빙 ───────────────────────────────
        // env-secrets.json 직접 접근 차단 (서버 내부 전용)
        if (urlPath.includes('env-secrets.json')) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Forbidden' }));
            return;
        }

        // Path traversal 방어: ../, %2e%2e, 널바이트 등 모두 차단
        let filePath = safeStaticJoin(distRoot, urlPath);
        if (!filePath) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('Bad Request');
            return;
        }

        try {
            const stat = await fs.stat(filePath);
            if (stat.isDirectory()) {
                const indexPath = path.join(filePath, 'index.html');
                // 디렉토리 인덱스도 반드시 distRoot 하위여야 함
                const rootNormalized = path.resolve(distRoot);
                if (indexPath !== rootNormalized &&
                    !indexPath.startsWith(rootNormalized + path.sep)) {
                    res.writeHead(400, { 'Content-Type': 'text/plain' });
                    res.end('Bad Request');
                    return;
                }
                filePath = indexPath;
                await fs.access(filePath);
            }
        } catch {
            const hasExt = path.extname(urlPath) !== '';
            if (hasExt) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('Not Found');
                return;
            }
            // SPA fallback: index.html
            filePath = path.join(distRoot, 'index.html');
            try { await fs.access(filePath); }
            catch {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('Not Found');
                return;
            }
        }

        const ext = path.extname(filePath);
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';
        try {
            let data = await fs.readFile(filePath);
            const headers = {
                'Content-Type': contentType,
                'Cache-Control': ext === '.wasm' ? 'public, max-age=86400' : 'no-cache',
            };
            if (ext === '.html' && bootSecretServe && bcKeyHexServe.length >= 64 && bundleHash12Serve.length >= 12) {
                const bootPayload = buildBundleBootPayload(bootSecretServe, bcKeyHexServe, bundleHash12Serve);
                if (bootPayload) {
                    data = Buffer.from(
                        injectBundleBootScript(data.toString('utf-8'), bootPayload),
                        'utf-8',
                    );
                    headers['Cache-Control'] = 'private, no-store, no-cache, must-revalidate';
                    headers['Pragma'] = 'no-cache';
                }
            }
            res.writeHead(200, headers);
            res.end(data);
        } catch (e) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Internal Error');
            console.error(`${ts()} ${C.red}[STATIC]${C.reset} ${e.message}`);
        }
    });

    // 활성 소켓 추적 — keep-alive 등 열린 연결을 강제 종료하기 위해
    const activeSockets = new Set();
    server.on('connection', (socket) => {
        activeSockets.add(socket);
        socket.once('close', () => activeSockets.delete(socket));
    });

    server.listen(port, '0.0.0.0', () => {
        console.log(`
${C.bold}[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}
${C.bold}[dokkebi] 🖥  ${t('serve.starting', { port })}${C.reset}
[dokkebi] 정적 폴더  : ${distRoot}
[dokkebi] DB 타입    : ${dbType}
[dokkebi] 핸드셰이크 : /api/_dokkebi/handshake  ${C.cyan}(ECDH P-256)${C.reset}
[dokkebi] DB 프록시  : /api/_dokkebi/db          ${C.green}(AES-256-GCM + HMAC-SHA256)${C.reset}
[dokkebi] 로그 수집  : /api/_dokkebi/log
${C.bold}[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}
`);
    });

    process.once('SIGINT', () => {
        console.log('\n' + t('serve.shutdown'));

        for (const socket of activeSockets) {
            try { socket.destroy(); } catch { /* ignore */ }
        }

        server.close(() => {
            console.log('[dokkebi] ✅ ' + t('common.done'));
            process.exit(0);
        });

        setTimeout(() => process.exit(0), 3000).unref();
    });
}

// ─────────────────────────────────────────────────────────────
// ECDH 핸드셰이크 핸들러
// ─────────────────────────────────────────────────────────────

const CLIENT_HANDSHAKE_SECRET_KEYS = new Set(['__DOKKEBI_BC_KEY__', 'JWT_SECRET', 'DOKKEBI_JWT_SECRET']);

function pickClientHandshakeSecrets(envSecrets = {}) {
    const picked = {};
    for (const key of CLIENT_HANDSHAKE_SECRET_KEYS) {
        if (typeof envSecrets[key] === 'string' && envSecrets[key]) {
            picked[key] = envSecrets[key];
        }
    }
    return picked;
}

async function handleHandshake(req, res, _envSecrets = {}) {
    let body;
    try { body = await readJson(req, { maxBytes: BODY_LIMITS.handshake }); }
    catch (e) { handleReadJsonError(res, e); return; }

    const { clientPubKey } = body;
    if (!clientPubKey) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'clientPubKey 필드가 없습니다' }));
        return;
    }

    try {
        const clientPubBuf = Buffer.from(clientPubKey, 'base64');

        // ECDH 공유 비밀 계산
        const sharedSecret = serverEcdh.computeSecret(clientPubBuf);

        // HKDF-SHA256으로 두 개의 독립 키 파생
        const encKey = Buffer.from(hkdfSync(
            'sha256', sharedSecret,
            Buffer.alloc(0),
            Buffer.from('dokkebi-enc', 'utf-8'),
            32
        ));
        const sigKey = Buffer.from(hkdfSync(
            'sha256', sharedSecret,
            Buffer.alloc(0),
            Buffer.from('dokkebi-sig', 'utf-8'),
            32
        ));

        // sessionStore 최대 크기 초과 시 가장 오래된 세션 제거 (메모리 고갈 방어)
        if (sessionStore.size >= MAX_SESSIONS) {
            let oldestId = null, oldestTime = Infinity;
            for (const [id, sess] of sessionStore) {
                if (sess.createdAt < oldestTime) { oldestTime = sess.createdAt; oldestId = id; }
            }
            if (oldestId) {
                sessionStore.delete(oldestId);
                console.warn(`${ts()} ${C.yellow}[세션]${C.reset} 최대 세션 수 초과 — 오래된 세션 제거 (sid: ${oldestId.slice(0, 8)}...)`);
            }
        }

        const sessionId = randomBytes(16).toString('hex');
        sessionStore.set(sessionId, { encKey, sigKey, createdAt: Date.now() });

        // serve 모드에서도 클라이언트에는 암호화 번들 복호화 키만 전달한다.
        const responseData = { sessionId };
        const clientSecrets = pickClientHandshakeSecrets(_envSecrets);
        if (Object.keys(clientSecrets).length > 0) {
            const iv = randomBytes(12);
            const cipher = createCipheriv('aes-256-gcm', encKey, iv);
            const plain = Buffer.from(JSON.stringify(clientSecrets), 'utf-8');
            const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
            const authTag = cipher.getAuthTag();
            responseData.encSecrets = Buffer.concat([encrypted, authTag]).toString('base64');
            responseData.encSecretsIv = iv.toString('base64');
        }

        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify(responseData));

        const secretInfo = Object.keys(clientSecrets).length > 0
            ? ` + 🔐 클라이언트 허용 Secret ${Object.keys(clientSecrets).length}개 암호화 전달` : '';
        console.log(`${ts()} ${C.cyan}[핸드셰이크]${C.reset} 세션 키 파생 완료 (sid: ${sessionId.slice(0, 8)}...)${secretInfo}`);
    } catch (e) {
        console.error(`${ts()} ${C.red}[핸드셰이크 오류]${C.reset} ${e.message}`);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: '핸드셰이크 처리 중 오류가 발생했습니다.' }));
    }
}

// ─────────────────────────────────────────────────────────────
// DB 프록시 핸들러 (HMAC + nonce + timestamp 검증)
// ─────────────────────────────────────────────────────────────

async function handleDbProxy(req, res, dbType, dbConfig, _logSec, _allowlist, distRoot, proxyMode) {
    const _sec = _logSec || (() => {});
    let raw;
    try { raw = await readJson(req, { maxBytes: BODY_LIMITS.db }); }
    catch (e) { handleReadJsonError(res, e); return; }

    // ── 세션 조회 ──────────────────────────────────────────
    const sessionId = raw.sid || req.headers['x-dokkebi-session'];
    const session   = sessionId ? sessionStore.get(sessionId) : null;

    if (!session) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: '유효하지 않은 세션입니다. 페이지를 새로고침하세요.' }));
        return;
    }

    // ── 1. Timestamp 검증 (±30초) ─────────────────────────
    const now = Date.now();
    const reqTs = Number(raw.ts);
    if (!reqTs || Math.abs(now - reqTs) > 30_000) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `요청 시간이 유효하지 않습니다. (서버: ${now}, 요청: ${reqTs})` }));
        return;
    }

    // ── 2. Nonce 기본 검증 (재전송 공격 방어) ──────────────
    // 주의: 실제 nonceCache.set()은 HMAC 검증 통과 후에 수행한다.
    //       서명이 위조된 요청이 nonce 캐시를 오염시키지 못하도록 함.
    const nonce = raw.nonce;
    if (!nonce || typeof nonce !== 'string' || nonceCache.has(nonce)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: '재전송된 요청이거나 nonce가 없습니다.' }));
        return;
    }

    // ── 3. HMAC-SHA256 서명 검증 (타이밍 공격 방어) ─────────
    if (!raw.sig || !raw.enc || typeof raw.sig !== 'string' || typeof raw.enc !== 'string') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: '서명(sig) 또는 암호문(enc)이 없습니다.' }));
        return;
    }

    const sigInput  = Buffer.from(`${nonce}:${reqTs}:${raw.enc}`, 'utf-8');
    const expectedSig = createHmac('sha256', session.sigKey).update(sigInput).digest();

    let providedSigBuf;
    try { providedSigBuf = Buffer.from(raw.sig, 'base64'); }
    catch {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: '서명 형식 오류' }));
        return;
    }

    // 상수 시간 비교 (타이밍 공격 방어)
    // - 길이가 다르면 RangeError가 발생하므로 길이 체크를 먼저 (둘 다 32바이트 raw HMAC)
    // - 길이가 같더라도 timingSafeEqual이 예외를 던지는 경우를 try/catch로 포착
    let sigOk = false;
    try {
        if (providedSigBuf.length === expectedSig.length) {
            sigOk = timingSafeEqual(providedSigBuf, expectedSig);
        } else {
            // 길이 불일치에도 상수 시간 처리 흉내 — 더미 비교로 타이밍 평탄화
            const dummy = Buffer.alloc(expectedSig.length);
            try { timingSafeEqual(dummy, expectedSig); } catch { /* no-op */ }
            sigOk = false;
        }
    } catch {
        sigOk = false;
    }

    if (!sigOk) {
        const ip = getClientIp(req);
        console.warn(`${ts()} ${C.red}[DB ✗]${C.reset} HMAC 서명 불일치 (재전송 또는 변조 시도)`);
        _sec({ type: 'hmac_fail', ip, path: req.url, detail: 'HMAC-SHA256 mismatch' });
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: '서명이 유효하지 않습니다.' }));
        return;
    }

    // 서명 검증 통과 후에만 nonce 캐시에 기록 (캐시 오염 방어)
    // TTL을 요청 시간 유효 창보다 약간 길게 설정
    nonceCache.set(nonce, now + 35_000);

    // ── 4. AES-256-GCM 복호화 ──────────────────────────────
    let body;
    try {
        const combined = Buffer.from(raw.enc, 'base64');
        // WebCrypto AES-GCM 출력: 마지막 16바이트 = 인증 태그
        const cipherBuf = combined.slice(0, -16);
        const tagBuf    = combined.slice(-16);
        const ivBuf     = Buffer.from(raw.iv, 'base64');

        const decipher = createDecipheriv('aes-256-gcm', session.encKey, ivBuf);
        decipher.setAuthTag(tagBuf);
        const plain = Buffer.concat([decipher.update(cipherBuf), decipher.final()]);
        body = JSON.parse(plain.toString('utf-8'));
        plain.fill(0); // 복호화된 평문 버퍼 즉시 제로화 (메모리 잔류 방어)
    } catch (e) {
        console.error(`${ts()} ${C.red}[DB ✗]${C.reset} 복호화 실패: ${e.message}`);
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: '복호화 실패. 페이지를 새로고침하세요.' }));
        return;
    }

    const wire = await loadWireRuntimeForLocalProxy(distRoot, proxyMode);
    body = denormalizePayload(body, wire);
    const vr = verifyAndStripPow(body, String(sessionId || ''), wire);
    if (!vr.ok) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: vr.error, code: 'POW_INVALID' }));
        return;
    }
    body = vr.body;

    const { sql, params = [] } = body;

    // ── 4b. 세션 바인딩 명령 처리 (⚠ 보안 효과 없음) ────────
    // 주의: 이 명령은 클라이언트가 자가 선언하는 메타데이터일 뿐,
    //       프록시 레이어에서는 어떠한 인가 결정에도 사용되지 않는다.
    //       RLS/권한은 반드시 DB 레벨 정책(Supabase RLS, PG policy)이나
    //       별도 edge function 인가 레이어에서 강제해야 한다.
    //       자세한 내용은 SECURITY.md "인가 경계" 섹션 참조.
    if (sql === '__DOKKEBI_BIND_SESSION__') {
        const [userId, role] = params;
        if (userId && session) {
            // 메타데이터 저장 (로깅/디버깅 용도 한정)
            session.boundUserId = String(userId);
            session.boundRole = String(role || 'user');
            if (!session._bindWarned) {
                session._bindWarned = true;
                console.warn(`${ts()} ${C.yellow}[SECURITY]${C.reset} bindSession()은 보안 경계가 아닙니다. ` +
                    `실제 권한은 DB RLS 또는 별도 인가 레이어에서 강제하세요. ` +
                    `(userId=${userId}, sid: ${sessionId.slice(0, 8)}...)`);
            }
        }
        const encResp = encryptResponse(session, { ok: true, value: { rows: [], affected: 0, lastInsertId: 0 } });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(encResp));
        return;
    }

    // ── 5. SQL 쿼리 기본 검증 ─────────────────────────────
    const sqlCheck = validateSql(sql);
    if (!sqlCheck.ok) {
        const ip = getClientIp(req);
        console.warn(`${ts()} ${C.yellow}[DB ✗]${C.reset} SQL 검증 실패: ${sqlCheck.reason}`);
        _sec({ type: 'sql_inject', ip, path: req.url, detail: sqlCheck.reason + ' | ' + sql?.slice(0, 100) });
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: sqlCheck.reason }));
        return;
    }

    // ── 5b. SQL Allowlist 검증 ──────────────────────────
    // - allowlist 존재 → 등록 테이블·연산만 허용 (UNION/JOIN/서브쿼리 전수 검증)
    // - allowlist 부재 → 공통 방어(다중문장·위험토큰·주석 기반 우회)만 수행
    //                   *allowlist 미생성 경고는 서버 시작 시 출력됨*
    {
        const alCheck = validateSqlAllowlist(sql, _allowlist, { strict: false });
        if (!alCheck.allowed) {
            const ip = getClientIp(req);
            console.warn(`${ts()} ${C.red}[DB ✗]${C.reset} SQL 허용목록 거부: ${alCheck.reason}`);
            _sec({ type: 'sql_blocked', ip, path: req.url, detail: alCheck.reason + ' | ' + sql?.slice(0, 100) });
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: alCheck.reason }));
            return;
        }
    }

    console.log(`${ts()} ${C.blue}[DB]${C.reset} ${C.gray}${sql?.slice(0, 80)}${C.reset}`);

    let responsePayload;
    try {
        const result = await proxyDbQuery(dbType, dbConfig, sql, params);
        console.log(
            `${ts()} ${C.green}[DB ✓]${C.reset} rows=${result.rows?.length ?? 0} affected=${result.affected ?? 0}`
        );
        responsePayload = { ok: true, value: result };
    } catch (e) {
        console.error(`${ts()} ${C.red}[DB ✗]${C.reset} ${e.message}`);
        responsePayload = { ok: false, error: sanitizeDbError(e) };
    }

    const encResponse = encryptResponse(session, responsePayload);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(encResponse));
}

// ─────────────────────────────────────────────────────────────
// 응답 암호화 (AES-256-GCM) — 세션 encKey 사용
// 네트워크 탭에서 응답 본문이 암호문으로만 보임
// ─────────────────────────────────────────────────────────────
function encryptResponse(session, payload) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', session.encKey, iv);
    const plain = Buffer.from(JSON.stringify(payload), 'utf-8');
    const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
        _enc: true,
        enc: Buffer.concat([encrypted, tag]).toString('base64'),
        iv:  iv.toString('base64'),
    };
}

// ─────────────────────────────────────────────────────────────
// DB 프록시 쿼리 실행
// ─────────────────────────────────────────────────────────────

async function proxyDbQuery(dbType, config, sql, params) {
    // 자격증명이 없으면 빈 결과 반환 — DB 없이 샘플 데이터 폴백 허용
    const _empty = () => ({ rows: [], affected: 0, lastInsertId: 0 });

    switch (dbType) {
        case 'd1': {
            if (!config.accountId || !config.databaseId || !config.apiToken) return _empty();
            const url = `${config.apiBase}/accounts/${config.accountId}/d1/database/${config.databaseId}/query`;
            const data = await fetchJson(url, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${config.apiToken}`,
                    'Content-Type':  'application/json',
                },
                body: JSON.stringify({ sql, params }),
            });
            if (!data.success) throw new Error('D1 오류: ' + JSON.stringify(data.errors));
            const r = data.result?.[0] || {};
            return {
                rows:         (r.results || []).map(x => JSON.stringify(x)),
                affected:     r.meta?.changes       ?? 0,
                lastInsertId: r.meta?.last_row_id   ?? null,
            };
        }
        case 'supabase': {
            if (!config.supabaseUrl || !config.anonKey) return _empty();
            const url = `${config.supabaseUrl}/rest/v1/rpc/execute_sql`;
            const data = await fetchJson(url, {
                method: 'POST',
                headers: {
                    'apikey':        config.anonKey,
                    'Authorization': `Bearer ${config.serviceKey || config.anonKey}`,
                    'Content-Type':  'application/json',
                },
                body: JSON.stringify({ query: sql, params }),
            });
            const rows = Array.isArray(data) ? data : [data];
            return {
                rows:         rows.map(x => JSON.stringify(x)),
                affected:     rows.length,
                lastInsertId: null,
            };
        }
        case 'appwrite': {
            if (!config.endpoint || !config.projectId || !config.apiKey) return _empty();
            const url = `${config.endpoint}/v1/databases/${config.databaseId}/collections`;
            const data = await fetchJson(url, {
                method: 'GET',
                headers: {
                    'X-Appwrite-Project': config.projectId,
                    'X-Appwrite-Key':     config.apiKey,
                },
            });
            return {
                rows:         (data.documents || []).map(x => JSON.stringify(x)),
                affected:     data.total || 0,
                lastInsertId: null,
            };
        }
        default:
            throw new Error(`알 수 없는 DB 타입: ${dbType}`);
    }
}

// ─────────────────────────────────────────────────────────────
// 로그 수집 핸들러
// ─────────────────────────────────────────────────────────────

const LOG_LEVEL_COLOR = {
    log:   C.gray,
    info:  C.cyan,
    warn:  C.yellow,
    error: C.red,
    debug: C.blue,
};

const LOG_TAG_COLOR = {
    wasm:                C.magenta,
    host:                C.gray,
    backend:             C.blue,
    'uncaught':          C.red,
    'unhandled-promise': C.red,
};

// wasm 로그에서 요청 완료 패턴 파싱: "GET /api/path → 200 (42ms)"
const _REQ_LOG_RE = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+→\s+(\d{3})(?:\s+\((\d+)ms\))?$/;

async function handleLogCollect(req, res, ctx = {}) {
    let body;
    try { body = await readJson(req, { maxBytes: BODY_LIMITS.log }); }
    catch (e) { handleReadJsonError(res, e); return; }

    let { level = 'log', tag = 'backend', messages = [] } = body;
    if (tag === 'uncaught' || tag === 'unhandled-promise') level = 'error';

    const levelColor = LOG_LEVEL_COLOR[level] || C.gray;
    const tagColor   = LOG_TAG_COLOR[tag] || C.gray;
    const icon       = level === 'error' ? '✗' : level === 'warn' ? '⚠' : level === 'info' ? 'ℹ' : '▸';
    const prefix     = `${ts()} ${tagColor}[${tag}]${C.reset} ${levelColor}${icon}${C.reset}`;

    const formatted = messages
        .map(m => (typeof m === 'object' ? JSON.stringify(m) : String(m)))
        .join(' ');

    const lines = formatted.split('\n');
    const first = lines[0];
    const rest  = lines.slice(1).map(l => `       ${C.gray}${l}${C.reset}`).join('\n');
    const output = rest ? `${prefix} ${levelColor}${first}${C.reset}\n${rest}` : `${prefix} ${levelColor}${first}${C.reset}`;

    if (level === 'error') console.error(output);
    else if (level === 'warn') console.warn(output);
    else console.log(output);

    if (ctx.proxyDbQuery) {
        // wasm info 로그 → 실제 API 요청 완료 감지 → _dokkebi_requests
        if (tag === 'wasm' && level === 'info') {
            const m = _REQ_LOG_RE.exec(formatted.trim());
            if (m) {
                logRequest(ctx.proxyDbQuery, ctx.dbType, ctx.dbConfig, {
                    method: m[1], path: m[2], status: Number(m[3]),
                    durationMs: m[4] ? Number(m[4]) : 0, ip: ctx.ip || '',
                }).catch(() => {});
            }
        }

        // error/uncaught/unhandled-promise → _dokkebi_errors
        if (level === 'error' || tag === 'uncaught' || tag === 'unhandled-promise') {
            const [msgLine, ...stackLines] = formatted.split('\n');
            logError(ctx.proxyDbQuery, ctx.dbType, ctx.dbConfig, {
                source: tag === 'wasm' ? 'wasm' : 'host',
                level:  'error',
                message: msgLine.trim(),
                stack:   stackLines.join('\n').trim(),
            }).catch(() => {});
        }
    }

    res.writeHead(204); res.end();
}

// ─────────────────────────────────────────────────────────────
// 헬퍼
// ─────────────────────────────────────────────────────────────

/**
 * 요청 본문을 JSON으로 파싱 (최대 크기 제한 포함)
 *
 * @param {import('http').IncomingMessage} req
 * @param {object} [opts]
 * @param {number} [opts.maxBytes] - 바이트 단위 상한 (기본 16KB)
 * @returns {Promise<any>}
 * @throws {Error & { code: 'PAYLOAD_TOO_LARGE' | 'BAD_JSON' | 'REQ_ERROR' }}
 */
function readJson(req, opts = {}) {
    const maxBytes = Number.isFinite(opts.maxBytes) ? opts.maxBytes : BODY_LIMITS.default;
    return new Promise((resolve, reject) => {
        // Content-Length 선체크 — 과도한 바디 즉시 거부
        const contentLength = Number(req.headers['content-length']);
        if (Number.isFinite(contentLength) && contentLength > maxBytes) {
            const err = new Error(`요청 본문이 너무 큽니다 (max ${maxBytes} bytes)`);
            err.code = 'PAYLOAD_TOO_LARGE';
            reject(err);
            // 나머지 데이터 소비/폐기
            req.resume?.();
            return;
        }

        const chunks = [];
        let received = 0;
        let aborted = false;

        req.on('data', (chunk) => {
            if (aborted) return;
            received += chunk.length;
            if (received > maxBytes) {
                aborted = true;
                const err = new Error(`요청 본문이 너무 큽니다 (max ${maxBytes} bytes)`);
                err.code = 'PAYLOAD_TOO_LARGE';
                reject(err);
                // 스트림 중단
                try { req.destroy(); } catch { /* ignore */ }
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            if (aborted) return;
            try {
                const raw = Buffer.concat(chunks).toString('utf-8');
                resolve(raw.length === 0 ? {} : JSON.parse(raw));
            } catch (e) {
                const err = new Error('JSON 파싱 실패');
                err.code = 'BAD_JSON';
                reject(err);
            }
        });
        req.on('error', (e) => {
            if (aborted) return;
            const err = new Error('요청 수신 중 오류');
            err.code = 'REQ_ERROR';
            err.cause = e;
            reject(err);
        });
    });
}

/**
 * readJson 실패를 표준 응답으로 변환
 */
function handleReadJsonError(res, err) {
    if (err?.code === 'PAYLOAD_TOO_LARGE') {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: '요청 본문이 너무 큽니다.' }));
        return;
    }
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: '잘못된 요청 본문' }));
}

/**
 * 정적 파일 서빙 경로를 안전하게 해석 (path traversal 방어)
 *
 * - `..` 시퀀스나 절대경로 주입으로 distRoot 바깥을 가리키면 null 반환
 * - URL 디코딩 실패도 거부
 *
 * @param {string} distRoot - 정규화된 절대경로
 * @param {string} urlPath  - req.url에서 뽑은 경로 부분 (query 제거됨)
 * @returns {string|null}   - 안전하게 해석된 절대경로 또는 null
 */
function safeStaticJoin(distRoot, urlPath) {
    if (typeof urlPath !== 'string') return null;
    let decoded;
    try {
        decoded = decodeURIComponent(urlPath);
    } catch { return null; }
    // 널바이트·제어문자 차단
    if (/\0/.test(decoded)) return null;
    const rel = decoded === '/' ? 'index.html' : decoded.replace(/^\/+/, '');
    const resolved = path.resolve(distRoot, rel);
    const rootNormalized = path.resolve(distRoot);
    // distRoot 자체이거나 그 하위여야 함
    if (resolved !== rootNormalized &&
        !resolved.startsWith(rootNormalized + path.sep)) {
        return null;
    }
    return resolved;
}

function fetchJson(url, opts = {}) {
    return new Promise((resolve, reject) => {
        const parsed   = new URL(url);
        const protocol = parsed.protocol === 'https:' ? https : http;
        const body     = opts.body ? Buffer.from(opts.body, 'utf-8') : null;

        const reqOpts = {
            hostname: parsed.hostname,
            port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path:     parsed.pathname + parsed.search,
            method:   opts.method || 'GET',
            headers:  { ...(opts.headers || {}), ...(body ? { 'Content-Length': body.length } : {}) },
        };

        const r = protocol.request(reqOpts, (resp) => {
            let data = '';
            resp.on('data', c => (data += c));
            resp.on('end', () => {
                if (resp.statusCode >= 400) {
                    reject(new Error(`HTTP ${resp.statusCode}: ${data.slice(0, 200)}`));
                } else {
                    try { resolve(JSON.parse(data)); } catch { resolve(data); }
                }
            });
        });

        r.on('error', reject);
        if (body) r.write(body);
        r.end();
    });
}

async function loadEnvFile(sourceRoot) {
    const envPath = path.join(sourceRoot, '.env');
    try {
        const content = await fs.readFile(envPath, 'utf-8');
        const vars = {};
        for (const line of content.split('\n')) {
            const t = line.trim();
            if (!t || t.startsWith('#')) continue;
            const eq = t.indexOf('=');
            if (eq === -1) continue;
            vars[t.slice(0, eq).trim()] = t.slice(eq + 1).trim().replace(/^['"]|['"]$/g, '');
        }
        return vars;
    } catch { return {}; }
}

/**
 * proxyMode: 'serverless'인 프로젝트에서 dok serve 실행 시 경고 출력
 * - 서버리스 모드는 Cloudflare Pages Functions로 동작해야 함
 * - dok serve는 개발 편의용 fallback으로는 사용 가능
 */
async function checkServerlessMode(sourceRoot) {
    try {
        const configPath = path.join(sourceRoot, 'dokkebi.config.js');
        await fs.access(configPath);
        const content = await fs.readFile(configPath, 'utf-8');
        const match = content.match(/proxyMode:\s*['"](\w+)['"]/);
        if (match?.[1] === 'serverless') {
            console.log(`
${C.yellow}[dokkebi] ⚠  주의: 이 프로젝트는 서버리스 모드입니다 (proxyMode: 'serverless')${C.reset}
${C.yellow}[dokkebi]    dok serve 는 개발용 fallback 서버로 실행됩니다.${C.reset}
${C.yellow}[dokkebi]    프로덕션 배포 또는 Pages Functions 시뮬레이션:${C.reset}
${C.yellow}[dokkebi]      → 로컬 테스트: wrangler pages dev dist/${C.reset}
${C.yellow}[dokkebi]      → 프로덕션:    dok deploy${C.reset}
`);
        }
    } catch { /* config 없으면 무시 */ }
}

function resolveDbConfig(dbType, env) {
    const e = { ...env, ...process.env };
    switch (dbType) {
        case 'd1': return {
            accountId:  e.D1_ACCOUNT_ID  || '',
            databaseId: e.D1_DATABASE_ID || '',
            apiToken:   e.D1_API_TOKEN   || '',
            apiBase:    e.D1_API_BASE    || 'https://api.cloudflare.com/client/v4',
        };
        case 'supabase': return {
            supabaseUrl: e.SUPABASE_URL         || '',
            anonKey:     e.SUPABASE_ANON_KEY    || '',
            serviceKey:  e.SUPABASE_SERVICE_KEY || '',
        };
        case 'appwrite': return {
            endpoint:   e.APPWRITE_ENDPOINT    || '',
            projectId:  e.APPWRITE_PROJECT_ID  || '',
            apiKey:     e.APPWRITE_API_KEY      || '',
            databaseId: e.APPWRITE_DATABASE_ID || '',
        };
        default: return {};
    }
}

function hasDbCredentials(dbType, dbConfig) {
    switch (dbType) {
        case 'd1':       return !!(dbConfig.accountId && dbConfig.databaseId && dbConfig.apiToken);
        case 'supabase': return !!(dbConfig.supabaseUrl && dbConfig.anonKey);
        case 'appwrite': return !!(dbConfig.endpoint && dbConfig.projectId && dbConfig.apiKey);
        default:         return false;
    }
}

// ─────────────────────────────────────────────────────────────
// dokkebi.config.js 로드 헬퍼
// ─────────────────────────────────────────────────────────────
async function _loadDokConfig(sourceRoot) {
    return loadDokkebiConfigMerged(sourceRoot, { quiet: true });
}

// ─────────────────────────────────────────────────────────────
// Security Headers 헬퍼
// ─────────────────────────────────────────────────────────────

/**
 * 모든 HTTP 응답에 보안 헤더를 추가합니다.
 * CSP는 dokkebi 부트스트랩(인라인 스크립트 + QuickJS WASM)을 허용하도록 설계됩니다.
 * @param {import('http').ServerResponse} res
 * @param {'serve'|'dev'} mode  - dev 모드는 localhost 연결도 허용
 */
export function setSecurityHeaders(res, mode = 'serve', opts = {}) {
    const allowEmbed = opts.allowEmbed === true;
    // XSS / 스니핑 / 클릭재킹 방어
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    if (!allowEmbed) {
        res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    }

    // >>> dokkebi-coi-patch begin (mvpick-builder)
    // WebContainer SharedArrayBuffer 사용 위해 페이지를 crossOriginIsolated 로 강제.
    // credentialless: 외부 cross-origin 리소스(youtube/stackblitz 등)를 익명 로드로 허용.
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'credentialless');
    // <<< dokkebi-coi-patch end

    // 레퍼러 정책 — 크로스 도메인 요청 시 origin만 전송
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // 브라우저 기능 정책
    // camera / microphone / display-capture: 동일 오리진 앱(WebRTC 등)에만 허용
    // geolocation / payment: 완전 비활성화
    res.setHeader(
        'Permissions-Policy',
        'camera=(self), microphone=(self), display-capture=(self), geolocation=(), payment=()',
    );

    // dev 에서 COEP/COOP 를 붙이면 크로스 오리진 iframe(유튜브·NotoFly 등)이 브라우저에 의해
    // 차단되는 경우가 많음. SharedArrayBuffer 전용 격리는 블로그 앱에 필수가 아니므로 생략함.

    // CSP — 인라인 스크립트(부트스트랩)와 WASM 실행 허용
    // 'unsafe-inline': dokkebi 부트스트랩이 <script type="module"> 인라인으로 주입됨
    // 'wasm-unsafe-eval': QuickJS WASM VM 컴파일에 필요
    // 'unsafe-eval': iPadOS/Safari 계열은 WebAssembly 컴파일에 아직 이 토큰도 필요
    const connectSrc = mode === 'dev'
        ? `connect-src 'self' blob: ws: wss: http://localhost:* https:`
        : `connect-src 'self' blob: https:`;

    const frameSrc = frameSrcDirective(mode);

    // dev 모드에서는 esbuild-wasm 번들러(esm.sh), sql.js/@webcontainer(jsdelivr) 외부 스크립트 허용
    const scriptSrc = mode === 'dev'
        ? `script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' 'unsafe-eval' https://esm.sh https://cdn.jsdelivr.net ${CSP_SCRIPT_SRC_LEMON_SQUEEZY} blob:`
        : `script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' 'unsafe-eval' https://cdn.jsdelivr.net ${CSP_SCRIPT_SRC_LEMON_SQUEEZY} blob:`;

    const imgSrc = mode === 'dev'
        ? `img-src 'self' data: blob: https://picsum.photos https://*.picsum.photos https://placehold.co`
        : `img-src 'self' data: blob: https://picsum.photos https://*.picsum.photos`;

    res.setHeader('Content-Security-Policy', [
        `default-src 'self'`,
        `${scriptSrc}`,
        `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`,
        `${imgSrc}`,
        `media-src 'self' blob: data:`,
        `worker-src 'self' blob:`,
        `font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net`,
        `${connectSrc}`,
        `${frameSrc}`,
        `object-src 'none'`,
        `base-uri 'self'`,
        `form-action 'self'`,
        allowEmbed ? `frame-ancestors *` : `frame-ancestors 'self'`,
    ].join('; '));
}

// ─────────────────────────────────────────────────────────────
// dev.js에서 재사용 가능한 유틸리티 exports
// ─────────────────────────────────────────────────────────────
export { loadEnvFile, resolveDbConfig, hasDbCredentials, proxyDbQuery, encryptResponse, validateSql, fetchJson, readJson, handleReadJsonError, safeStaticJoin, BODY_LIMITS, getClientIp, sanitizeDbError, C, MIME_TYPES };
