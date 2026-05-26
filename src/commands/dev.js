/**
 * dokkebi dev 커맨드 (개발 서버 v1.0 — 핫 리로드 + 전체 로그)
 *
 * serve.js와 동일한 보안 레이어 위에 개발 편의 기능 추가:
 *   - 백엔드 파일 변경 감지 시 자동 재빌드 (esbuild only, 빠름)
 *   - SSE(/_dokkebi/sse)로 브라우저 자동 리로드
 *   - index.html 서빙 시 번들 무결성 해시 비활성화 (개발 중 변경에 무방)
 *   - 모든 WASM 백엔드 로그 터미널에 출력
 *   - 레이트 리밋 완화 (개발 편의)
 *
 * 사용법:
 *   dokkebi dev [src] [--port 5173] [--skip-build]
 */

import path                   from 'path';
import http                   from 'http';
import fs                     from 'fs/promises';
import { watch, existsSync }  from 'fs';
import { spawn }              from 'child_process';
import {
    createECDH,
    createHmac,
    createCipheriv,
    createDecipheriv,
    timingSafeEqual,
    hkdfSync,
    randomBytes,
} from 'crypto';
import { tryDevBlogMediaPost, tryDevBlogMediaGet } from '../core/devBlogMedia.js';
import {
    loadEnvFile,
    resolveDbConfig,
    hasDbCredentials,
    proxyDbQuery,
    encryptResponse,
    validateSql,
    readJson,
    handleReadJsonError,
    safeStaticJoin,
    BODY_LIMITS,
    getClientIp,
    sanitizeDbError,
    C,
    MIME_TYPES,
    setSecurityHeaders,
} from './serve.js';
import { handleAdminRoute, logSecurityEvent, logRequest, logError } from '../core/adminPanel.js';
import { loadAllowlist, validateSqlAllowlist } from '../core/sqlAllowlist.js';
import {
    QueryRegistry,
    loadRegistry,
    loadLearnedRegistry,
    writeLearnedRegistry,
} from '../core/queryRegistry.js';
import { bundleBackendForWasm, buildQuickJSBundle } from '../core/buildWasm.js';
import { runBuild }            from './build.js';
import { generateBootstrapScript } from '../core/opaqueHandle.js';
import { loadWireRuntimeForLocalProxy, denormalizePayload, verifyAndStripPow } from '../core/payloadWireRuntime.js';
import { loadPlugins, generatePluginBootstrapCode } from '../core/pluginLoader.js';
import { loadDokkebiConfigMerged } from '../core/dokkebiConfigLoad.js';
import { t } from '../i18n/index.js';

// ─────────────────────────────────────────────────────────────
// 개발 서버용 부트스트랩 캐시 (vite watch가 index.html 덮어쓸 때 재주입)
// ─────────────────────────────────────────────────────────────
let _devBootstrapHtml = '';

async function reinjectBootstrap(htmlPath) {
    if (!_devBootstrapHtml) return;
    try {
        let html = await fs.readFile(htmlPath, 'utf-8');
        if (html.includes('dokkebiInit')) return; // 이미 주입됨
        const tag = _devBootstrapHtml;
        if (html.includes('</head>')) {
            html = html.replace('</head>', tag + '\n</head>');
        } else {
            html += '\n' + tag;
        }
        await fs.writeFile(htmlPath, html, 'utf-8');
    } catch { /* index.html 없으면 무시 */ }
}

// ─────────────────────────────────────────────────────────────
// 개발 서버 전용 ECDH 세션 (서버 시작 시 1회 생성)
// ─────────────────────────────────────────────────────────────
const serverEcdh = createECDH('prime256v1');
serverEcdh.generateKeys();
const SERVER_PUB_KEY_B64 = serverEcdh.getPublicKey('base64');

const sessionStore  = new Map();
const nonceCache    = new Map();
const rateLimitMap  = new Map();

// ─────────────────────────────────────────────────────────────
// 개발용 보안 상수 (서버 모드보다 완화)
// ─────────────────────────────────────────────────────────────
const MAX_SESSIONS    = 200;
const SQL_MAX_LENGTH  = 50_000;
const RATE_WINDOW_MS  = 60_000;
const RATE_LIMITS = {
    handshake: 60,    // 개발 시 더 자주 허용
    db:        1000,  // 개발 시 더 자주 허용
};

function checkRateLimit(ip, endpoint) {
    const key   = `${ip}:${endpoint}`;
    const limit = RATE_LIMITS[endpoint] || 200;
    const now   = Date.now();
    const entry = rateLimitMap.get(key);
    if (!entry || (now - entry.windowStart) > RATE_WINDOW_MS) {
        rateLimitMap.set(key, { count: 1, windowStart: now });
        return true;
    }
    entry.count++;
    return entry.count <= limit;
}

function ts() {
    return C.gray + new Date().toLocaleTimeString('ko-KR') + C.reset;
}

// 만료 세션 정리 (30분 간격, 24시간 세션 유지)
setInterval(() => {
    const cutoff = Date.now() - 24 * 60 * 60_000;
    for (const [id, sess] of sessionStore) {
        if (sess.createdAt < cutoff) sessionStore.delete(id);
    }
}, 30 * 60_000).unref();

// nonce 정리 (60초 간격)
setInterval(() => {
    const now = Date.now();
    for (const [n, exp] of nonceCache) {
        if (now > exp) nonceCache.delete(n);
    }
}, 60_000).unref();

// 레이트 리밋 항목 정리
setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of rateLimitMap) {
        if (now - entry.windowStart > RATE_WINDOW_MS * 2) rateLimitMap.delete(key);
    }
}, 5 * 60_000).unref();

// ─────────────────────────────────────────────────────────────
// SSE (Server-Sent Events) — 브라우저 핫 리로드
// ─────────────────────────────────────────────────────────────
const sseClients = new Set();

function broadcastReload(reason = 'ok') {
    const msg = `event: reload\ndata: ${reason}\n\n`;
    for (const client of sseClients) {
        try { client.write(msg); } catch { sseClients.delete(client); }
    }
    console.log(`${ts()} ${C.cyan}[dev]${C.reset} 📡 브라우저 리로드 신호 전송 (클라이언트: ${sseClients.size}개)`);
}

// ─────────────────────────────────────────────────────────────
// 백엔드 자동 재빌드 (esbuild only — 빠름)
// ─────────────────────────────────────────────────────────────
async function findBackendEntry(sourceRoot) {
    const candidates = [
        path.join(sourceRoot, 'backend', 'controllers', 'index.ts'),
        path.join(sourceRoot, 'backend', 'index.ts'),
        path.join(sourceRoot, 'backend', 'controllers', 'index.js'),
        path.join(sourceRoot, 'backend', 'index.js'),
    ];
    for (const c of candidates) {
        try { await fs.access(c); return c; } catch { /* 다음 시도 */ }
    }
    return null;
}

function startBackendWatcher(sourceRoot, distRoot) {
    const backendDir = path.join(sourceRoot, 'backend');
    let debounceTimer  = null;
    let isRebuilding   = false;
    let pendingFile    = null; // 빌드 중 들어온 마지막 변경 (드롭 방지)

    let watcher;
    try {
        watcher = watch(backendDir, { recursive: true });
    } catch {
        console.warn(`${ts()} ${C.yellow}[dev]${C.reset} 백엔드 폴더를 찾을 수 없습니다: ${backendDir}`);
        return null;
    }

    const doRebuild = async (filename) => {
        isRebuilding = true;
        console.log(`\n${ts()} ${C.yellow}[dev]${C.reset} 📝 백엔드 변경: ${C.cyan}${filename || '파일'}${C.reset}`);
        console.log(`${ts()} ${C.yellow}[dev]${C.reset} ⚙  백엔드 재빌드 중 (esbuild)...`);

        try {
            const backendEntry = await findBackendEntry(sourceRoot);
            if (!backendEntry) {
                console.error(`${ts()} ${C.red}[dev]${C.reset} 백엔드 엔트리 파일을 찾을 수 없습니다.`);
            } else {
                const outFile = path.join(distRoot, 'dokkebi', 'backend-bundle.js');
                await bundleBackendForWasm({ backendEntry, outFile, backendDir, minify: false });
                console.log(`${ts()} ${C.green}[dev]${C.reset} ✅ 백엔드 재빌드 완료 → 브라우저 리로딩\n`);
                broadcastReload('backend-changed');
            }
        } catch (e) {
            console.error(`${ts()} ${C.red}[dev]${C.reset} ✗ 백엔드 재빌드 실패: ${e.message}\n`);
        } finally {
            isRebuilding = false;
            // 빌드 중 들어온 변경이 있으면 즉시 재처리
            if (pendingFile !== null) {
                const next = pendingFile;
                pendingFile = null;
                doRebuild(next);
            }
        }
    };

    const triggerRebuild = (filename) => {
        if (isRebuilding) {
            // 빌드 중이면 최신 파일명 저장 (완료 후 자동 실행)
            pendingFile = filename;
            return;
        }
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => doRebuild(filename), 200);
    };

    (async () => {
        try {
            for await (const event of watcher) {
                const { filename } = event;
                if (!filename) continue;
                if (!/\.(ts|js|json)$/.test(filename)) continue;
                if (filename.includes('node_modules')) continue;
                triggerRebuild(filename);
            }
        } catch { /* watcher 종료 */ }
    })();

    return watcher;
}

// ─────────────────────────────────────────────────────────────
// 프론트엔드 핫리로드 (vite build --watch)
// 파일 변경 시 Vite가 자동으로 dist/ 를 갱신하고 SSE로 브라우저 리로드
// ─────────────────────────────────────────────────────────────
function startFrontendWatch(sourceRoot, distRoot) {
    // 프론트엔드 디렉토리 탐색 (require 없이 existsSync 사용)
    const candidates = [
        path.join(sourceRoot, 'frontend'),
        sourceRoot,
    ];

    let frontendDir = null;
    for (const dir of candidates) {
        if (existsSync(path.join(dir, 'vite.config.ts')) ||
            existsSync(path.join(dir, 'vite.config.js')) ||
            existsSync(path.join(dir, 'vite.config.mts')) ||
            existsSync(path.join(dir, 'vite.config.mjs'))) {
            frontendDir = dir;
            break;
        }
    }

    if (!frontendDir) {
        console.log(`${ts()} ${C.gray}[dev]${C.reset} vite.config 파일을 찾을 수 없어 프론트엔드 감시를 건너뜁니다.`);
        return null;
    }

    console.log(`${ts()} ${C.cyan}[dev]${C.reset} 프론트엔드 감시 시작: ${frontendDir}`);

    const dokkebiOutDir = path.join(distRoot, 'dokkebi');
    let _wasmRestoring = false;

    async function ensureWasmFiles() {
        if (_wasmRestoring) return;
        const qjsPath = path.join(dokkebiOutDir, 'dokkebi-qjs.js');
        const bundlePath = path.join(dokkebiOutDir, 'backend-bundle.js');
        const qjsMissing = await fs.access(qjsPath).then(() => false).catch(() => true);
        const bundleMissing = await fs.access(bundlePath).then(() => false).catch(() => true);
        if (!qjsMissing && !bundleMissing) return;
        _wasmRestoring = true;
        try {
            if (qjsMissing) {
                console.log(`${ts()} ${C.yellow}[dev]${C.reset} ⚠ dokkebi-qjs.js 누락 감지 → WASM 번들 재생성 중...`);
                await buildQuickJSBundle(dokkebiOutDir, { minify: false });
                console.log(`${ts()} ${C.green}[dev]${C.reset} ✅ WASM 번들 복구 완료`);
            }
            if (bundleMissing) {
                const backendEntry = await findBackendEntry(sourceRoot);
                if (backendEntry) {
                    console.log(`${ts()} ${C.yellow}[dev]${C.reset} ⚠ backend-bundle.js 누락 감지 → 백엔드 번들 재생성 중...`);
                    const backendDir = path.join(sourceRoot, 'backend');
                    await bundleBackendForWasm({ backendEntry, outFile: bundlePath, backendDir, minify: false });
                    console.log(`${ts()} ${C.green}[dev]${C.reset} ✅ 백엔드 번들 복구 완료`);
                }
            }
        } catch (e) {
            console.warn(`${ts()} ${C.yellow}[dev]${C.reset} ⚠ WASM/번들 복구 실패: ${e.message}`);
        } finally {
            _wasmRestoring = false;
        }
    }

    let isShuttingDown = false;

    const spawnVite = () => {
        if (isShuttingDown) return null;

        const isWin = process.platform === 'win32';
        const proc  = spawn(isWin ? 'npx.cmd' : 'npx', ['vite', 'build', '--watch', '--logLevel', 'info'], {
            cwd:   frontendDir,
            stdio: 'pipe',
            shell: isWin,
        });

        let firstBuild  = true;
        let lineBuffer  = ''; // 청크가 분할될 경우를 대비한 라인 버퍼

        const processLine = (line) => {
            const t = line.trim();
            if (!t) return;
            const color = t.startsWith('✓') || t.includes('built in') ? C.green : C.gray;
            console.log(`${ts()} ${C.blue}[frontend]${C.reset} ${color}${t}${C.reset}`);

            // "built in Xms" 또는 "built in X.Xs" — Vite 빌드 완료 신호
            if (/built in \d/.test(t)) {
                if (firstBuild) {
                    firstBuild = false;
                    // 첫 빌드 후에도 부트스트랩 재주입 (vite가 index.html 덮어씀)
                    reinjectBootstrap(path.join(distRoot, 'index.html'));
                    ensureWasmFiles();
                    return;
                }
                // 파일 쓰기 완료 대기 후 부트스트랩 재주입 + 리로드
                setTimeout(async () => {
                    await reinjectBootstrap(path.join(distRoot, 'index.html'));
                    await ensureWasmFiles();
                    broadcastReload('frontend-changed');
                }, 200);
            }
        };

        const onData = (data) => {
            lineBuffer += data.toString();
            const lines = lineBuffer.split('\n');
            // 마지막 원소는 아직 완성되지 않은 줄일 수 있으므로 버퍼에 유지
            lineBuffer = lines.pop() ?? '';
            for (const line of lines) processLine(line);
        };

        proc.stdout.on('data', onData);
        proc.stderr.on('data', (data) => {
            const output = data.toString();
            for (const line of output.split('\n')) {
                const t = line.trim();
                if (t) console.error(`${ts()} ${C.yellow}[frontend]${C.reset} ${t}`);
            }
        });

        proc.on('error', (e) => {
            console.warn(`${ts()} ${C.yellow}[dev]${C.reset} 프론트엔드 빌드 프로세스 시작 실패: ${e.message}`);
        });

        proc.on('close', (code) => {
            if (isShuttingDown) return;
            if (code !== 0 && code !== null) {
                console.warn(`${ts()} ${C.yellow}[dev]${C.reset} 프론트엔드 빌드 프로세스 재시작 중... (종료 코드: ${code})`);
                setTimeout(spawnVite, 1000);
            }
        });

        proc._devShutdown = () => { isShuttingDown = true; proc.kill('SIGTERM'); };
        return proc;
    };

    return spawnVite();
}

// ─────────────────────────────────────────────────────────────
// 핸드셰이크 핸들러
// ─────────────────────────────────────────────────────────────
async function handleHandshake(req, res, _envSecrets = {}) {
    let body;
    try { body = await readJson(req, { maxBytes: BODY_LIMITS.handshake }); }
    catch (e) { handleReadJsonError(res, e); return; }

    const { clientPubKey } = body;
    if (!clientPubKey) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: 'clientPubKey 필드가 없습니다' }));
        return;
    }

    try {
        const clientPubBuf  = Buffer.from(clientPubKey, 'base64');
        const sharedSecret  = serverEcdh.computeSecret(clientPubBuf);
        const encKey = Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from('dokkebi-enc', 'utf-8'), 32));
        const sigKey = Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from('dokkebi-sig', 'utf-8'), 32));

        if (sessionStore.size >= MAX_SESSIONS) {
            let oldestId = null, oldestTime = Infinity;
            for (const [id, sess] of sessionStore) {
                if (sess.createdAt < oldestTime) { oldestTime = sess.createdAt; oldestId = id; }
            }
            if (oldestId) sessionStore.delete(oldestId);
        }

        const sessionId = randomBytes(16).toString('hex');
        sessionStore.set(sessionId, { encKey, sigKey, createdAt: Date.now() });

        const responseData = { sessionId };
        if (_envSecrets && Object.keys(_envSecrets).length > 0) {
            const iv = randomBytes(12);
            const cipher = createCipheriv('aes-256-gcm', encKey, iv);
            const plain = Buffer.from(JSON.stringify(_envSecrets), 'utf-8');
            const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
            const authTag = cipher.getAuthTag();
            responseData.encSecrets = Buffer.concat([encrypted, authTag]).toString('base64');
            responseData.encSecretsIv = iv.toString('base64');
        }

        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify(responseData));

        const secretInfo = Object.keys(_envSecrets).length > 0
            ? ` + 🔐 ${Object.keys(_envSecrets).length}개 시크릿 암호화 전달` : '';
        console.log(`${ts()} ${C.cyan}[핸드셰이크]${C.reset} 세션 생성 (sid: ${sessionId.slice(0, 8)}...)${secretInfo}`);
    } catch (e) {
        console.error(`${ts()} ${C.red}[핸드셰이크 오류]${C.reset} ${e.message}`);
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: '핸드셰이크 처리 중 오류가 발생했습니다.' }));
    }
}

// ─────────────────────────────────────────────────────────────
// DB 프록시 핸들러 (serve.js와 동일한 보안 레이어)
// ─────────────────────────────────────────────────────────────
async function handleDbProxy(req, res, dbType, dbConfig, _logSec, _allowlist, _queryRegistry, _onLearn, distRoot, proxyMode) {
    const ip = getClientIp(req);
    let raw;
    try { raw = await readJson(req, { maxBytes: BODY_LIMITS.db }); }
    catch (e) { handleReadJsonError(res, e); return; }

    const sessionId = raw.sid || req.headers['x-dokkebi-session'];
    const session   = sessionId ? sessionStore.get(sessionId) : null;

    if (!session) {
        res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: '유효하지 않은 세션입니다. 페이지를 새로고침하세요.' }));
        return;
    }

    // 타임스탬프 검증 (±30초)
    const now   = Date.now();
    const reqTs = Number(raw.ts);
    if (!reqTs || Math.abs(now - reqTs) > 30_000) {
        res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: `요청 시간이 유효하지 않습니다. (서버: ${now}, 요청: ${reqTs})` }));
        return;
    }

    // Nonce 기본 검증 — 실제 캐시 기록은 HMAC 통과 후 (캐시 오염 방어)
    const nonce = raw.nonce;
    if (!nonce || typeof nonce !== 'string' || nonceCache.has(nonce)) {
        res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: '재전송된 요청이거나 nonce가 없습니다.' }));
        return;
    }

    // HMAC-SHA256 서명 검증
    if (!raw.sig || !raw.enc || typeof raw.sig !== 'string' || typeof raw.enc !== 'string') {
        res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: '서명(sig) 또는 암호문(enc)이 없습니다.' }));
        return;
    }

    const sigInput    = Buffer.from(`${nonce}:${reqTs}:${raw.enc}`, 'utf-8');
    const expectedSig = createHmac('sha256', session.sigKey).update(sigInput).digest();

    let providedSigBuf;
    try { providedSigBuf = Buffer.from(raw.sig, 'base64'); }
    catch {
        res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: '서명 형식 오류' }));
        return;
    }

    let sigOk = false;
    try {
        if (providedSigBuf.length === expectedSig.length) {
            sigOk = timingSafeEqual(providedSigBuf, expectedSig);
        } else {
            const dummy = Buffer.alloc(expectedSig.length);
            try { timingSafeEqual(dummy, expectedSig); } catch { /* no-op */ }
            sigOk = false;
        }
    } catch {
        sigOk = false;
    }

    if (!sigOk) {
        console.warn(`${ts()} ${C.red}[DB ✗]${C.reset} HMAC 서명 불일치`);
        _logSec?.({ type: 'hmac_fail', ip, path: '/api/_dokkebi/db', detail: 'HMAC 서명 불일치' });
        res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: '서명이 유효하지 않습니다.' }));
        return;
    }

    // 서명 검증 통과 후 nonce 캐시에 기록
    nonceCache.set(nonce, now + 35_000);

    // AES-256-GCM 복호화
    let body;
    try {
        const combined  = Buffer.from(raw.enc, 'base64');
        const cipherBuf = combined.slice(0, -16);
        const tagBuf    = combined.slice(-16);
        const ivBuf     = Buffer.from(raw.iv, 'base64');

        const decipher = createDecipheriv('aes-256-gcm', session.encKey, ivBuf);
        decipher.setAuthTag(tagBuf);
        const plain = Buffer.concat([decipher.update(cipherBuf), decipher.final()]);
        body = JSON.parse(plain.toString('utf-8'));
        plain.fill(0);
    } catch (e) {
        console.error(`${ts()} ${C.red}[DB ✗]${C.reset} 복호화 실패: ${e.message}`);
        res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: '복호화 실패. 페이지를 새로고침하세요.' }));
        return;
    }

    const wire = await loadWireRuntimeForLocalProxy(distRoot, proxyMode);
    body = denormalizePayload(body, wire);
    const vr = verifyAndStripPow(body, String(sessionId || ''), wire);
    if (!vr.ok) {
        res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: vr.error, code: 'POW_INVALID' }));
        return;
    }
    body = vr.body;

    // Query Registry 분기 — { queryId, params, _debugSql } 또는 { sql, params }
    //   dev 모드는 기본 learn: queryId 가 없거나 미등록이면 _debugSql/sql 로
    //   폴백하며, 새 shape 는 .dokkebi/query-registry.learned.json 에 자동 기록.
    let sql;
    const params = Array.isArray(body.params) ? body.params : [];
    if (body.queryId && _queryRegistry) {
        const entry = _queryRegistry.get(body.queryId);
        if (entry) {
            sql = entry.sql;
        } else if (body._debugSql) {
            sql = body._debugSql;
            try {
                _queryRegistry.addSql(sql, { sources: [{ file: 'dev:learn', symbol: body.queryId }] });
                if (typeof _onLearn === 'function') await _onLearn(_queryRegistry);
                console.log(`${ts()} ${C.cyan}[Query]${C.reset} 새 쿼리 학습: ${body.queryId} (${sql.slice(0, 80)}...)`);
            } catch (e) {
                console.warn(`${ts()} ${C.yellow}[Query]${C.reset} 학습 기록 실패: ${e.message}`);
            }
        } else {
            console.warn(`${ts()} ${C.yellow}[Query ✗]${C.reset} 등록되지 않은 queryId: ${body.queryId}`);
            res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ error: '등록되지 않은 쿼리입니다. _debugSql 을 포함해 재시도하거나 dok build 하세요.' }));
            return;
        }
    } else if (body.queryId && !_queryRegistry && body._debugSql) {
        sql = body._debugSql;
    } else if (typeof body.sql === 'string') {
        sql = body.sql;
    } else {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: 'queryId 또는 sql 필드가 필요합니다.' }));
        return;
    }

    const sqlCheck = validateSql(sql);
    if (!sqlCheck.ok) {
        console.warn(`${ts()} ${C.yellow}[DB ✗]${C.reset} SQL 검증 실패: ${sqlCheck.reason}`);
        _logSec?.({ type: 'sql_inject', ip, path: '/api/_dokkebi/db', detail: (sqlCheck.reason || '') + ' | ' + sql?.slice(0, 100) });
        res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: sqlCheck.reason }));
        return;
    }

    // SQL Allowlist 검증 (dev 모드: 기본 strict=false, 경고만 출력)
    //   DOKKEBI_SQL_STRICT=true 이면 엄격 모드로 즉시 차단.
    if (_allowlist) {
        const strict = String(process.env.DOKKEBI_SQL_STRICT || 'false').toLowerCase() === 'true';
        const alCheck = validateSqlAllowlist(sql, _allowlist, { strict });
        if (!alCheck.allowed) {
            console.warn(`${ts()} ${C.yellow}[DB ⚠]${C.reset} SQL Allowlist 차단: ${alCheck.reason}`);
            _logSec?.({ type: 'sql_blocked', ip, path: '/api/_dokkebi/db', detail: (alCheck.reason || '') + ' | ' + sql?.slice(0, 100) });
            res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ error: alCheck.reason }));
            return;
        }
    }

    console.log(`${ts()} ${C.blue}[DB]${C.reset} ${C.gray}${sql?.slice(0, 100)}${C.reset}`);

    let responsePayload;
    try {
        const result = await proxyDbQuery(dbType, dbConfig, sql, params);
        console.log(`${ts()} ${C.green}[DB ✓]${C.reset} rows=${result.rows?.length ?? 0} affected=${result.affected ?? 0}`);
        responsePayload = { ok: true, value: result };
    } catch (e) {
        console.error(`${ts()} ${C.red}[DB ✗]${C.reset} ${e.message}`);
        responsePayload = { ok: false, error: sanitizeDbError(e) };
    }

    const encResp = encryptResponse(session, responsePayload);
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(encResp));
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

const TAG_COLOR = {
    wasm:              C.magenta,
    host:              C.gray,
    backend:           C.blue,
    'uncaught':        C.red,
    'unhandled-promise': C.red,
};

// wasm 로그에서 요청 완료 패턴 파싱: "GET /api/path → 200 (42ms)"
const _REQ_LOG_RE = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+→\s+(\d{3})(?:\s+\((\d+)ms\))?$/;

async function handleLogCollect(req, res, ctx = {}) {
    let body;
    try { body = await readJson(req, { maxBytes: BODY_LIMITS.log }); }
    catch (e) { handleReadJsonError(res, e); return; }

    // 배치 형식 { entries: [...] } 또는 단일 형식 { level, tag, messages } 모두 지원
    const entries = Array.isArray(body.entries) ? body.entries : [body];

    for (const entry of entries) {
        let { level = 'log', tag = 'backend', messages = [] } = entry;

        if (tag === 'uncaught' || tag === 'unhandled-promise') level = 'error';

        const levelColor = LOG_LEVEL_COLOR[level] || C.gray;
        const tagColor   = TAG_COLOR[tag] || C.gray;
        const icon       = level === 'error' ? '✗' : level === 'warn' ? '⚠' : level === 'info' ? 'ℹ' : '▸';
        const prefix     = `${ts()} ${tagColor}[${tag}]${C.reset} ${levelColor}${icon}${C.reset}`;

        const formatted = (Array.isArray(messages) ? messages : [messages])
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
            if (tag === 'wasm' && level === 'info') {
                const m = _REQ_LOG_RE.exec(formatted.trim());
                if (m) {
                    logRequest(ctx.proxyDbQuery, ctx.dbType, ctx.dbConfig, {
                        method: m[1], path: m[2], status: Number(m[3]),
                        durationMs: m[4] ? Number(m[4]) : 0, ip: ctx.ip || '',
                    }).catch(() => {});
                }
            }

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
    }

    res.writeHead(204); res.end();
}

// ─────────────────────────────────────────────────────────────
// dev 모드 index.html 처리
// (dokkebi 부트스트랩 재주입 + 번들 해시 비활성화 + SSE 리로드 스크립트 주입)
// ─────────────────────────────────────────────────────────────
async function serveDevHtml(filePath, res) {
    let html = await fs.readFile(filePath, 'utf-8');

    // vite watch가 dist/index.html을 덮어쓴 경우 부트스트랩 재주입
    if (_devBootstrapHtml && !html.includes('dokkebiInit')) {
        if (html.includes('</head>')) {
            html = html.replace('</head>', _devBootstrapHtml + '\n</head>');
        } else {
            html += '\n' + _devBootstrapHtml;
        }
    }

    // 번들 무결성 해시 비활성화 (개발 중 빌드 후 해시 불일치 방지)
    html = html.replace(
        /const _BUNDLE_EXPECTED_HASH\s*=\s*'[^']*';/,
        "const _BUNDLE_EXPECTED_HASH = ''; // dev mode: integrity check disabled"
    );

    // _isEncTextMode ↔ dist/dokkebi 실제 아티팩트 정합:
    // - 평문 backend-bundle.js 가 있으면 dev 는 워처 출력과 맞추기 위해 평문 모드(true→false).
    // - 평문이 없고 backend.bundle.enc 만 있으면(암호화 빌드 직후 등) 암호화 분기(false→true).
    const dokDir = path.join(path.dirname(filePath), 'dokkebi');
    const plainPath = path.join(dokDir, 'backend-bundle.js');
    const encPath = path.join(dokDir, 'backend.bundle.enc');
    const hasPlain = await fs.access(plainPath).then(() => true).catch(() => false);
    const hasEnc = await fs.access(encPath).then(() => true).catch(() => false);

    if (hasPlain) {
        html = html.replace(
            /var _isEncTextMode\s*=\s*true;/g,
            'var _isEncTextMode = false; /* dev: plaintext bundle (matches watcher output) */'
        );
    } else if (hasEnc) {
        html = html.replace(
            /var _isEncTextMode\s*=\s*false;/g,
            'var _isEncTextMode = true; /* dev: only .enc present, use encrypted bundle */'
        );
    }

    // SSE 핫 리로드 스크립트 주입
    const sseScript = `
<script>
(function(){
  var _sse = new EventSource('/_dokkebi/sse');
  _sse.addEventListener('reload', function() {
    console.log('[dokkebi:dev] 🔄 핫 리로드 중...');
    location.reload();
  });
  // onerror 시 page reload 하지 않음 — EventSource 자체 재연결 메커니즘에 위임
  var _sseErrTimer = null;
  _sse.onerror = function() {
    if (_sseErrTimer) return;
    _sseErrTimer = setTimeout(function() { _sseErrTimer = null; }, 10000);
    if (_sse.readyState !== 0) return; // CONNECTING 상태가 아니면 무시
    console.debug('[dokkebi:dev] SSE 재연결 중...');
  };
  window.__dokkebi_sse__ = _sse;
  console.log('[dokkebi:dev] 📡 핫 리로드 연결됨 (/_dokkebi/sse)');
})();
</script>`;

    if (html.includes('</body>')) {
        html = html.replace('</body>', sseScript + '\n</body>');
    } else {
        html += sseScript;
    }

    res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache, no-store' });
    res.end(html);
}

// ─────────────────────────────────────────────────────────────
// 메인 개발 서버
// ─────────────────────────────────────────────────────────────
export async function runDev(src, options = {}) {
    const sourceRoot = path.resolve(process.cwd(), src);
    const outputName = options.output || 'dist';
    const distRoot   = path.join(sourceRoot, outputName);

    // ── 자동 초기 빌드 ──────────────────────────────────────
    // dist/ 폴더가 없거나 --rebuild 플래그 시 자동으로 빌드 실행
    const distExists = await fs.access(distRoot).then(() => true).catch(() => false);
    if (!distExists || options.rebuild) {
        const reason = options.rebuild ? '--rebuild 옵션' : 'dist 폴더 없음';
        console.log(`\n${C.bold}[dokkebi:dev] 🔨 초기 빌드 시작 (${reason})...${C.reset}\n`);
        await runBuild(src, { output: outputName, skipMigration: true });
        console.log(`\n${C.bold}[dokkebi:dev] ✅ 초기 빌드 완료 → 개발 서버 시작${C.reset}\n`);
    } else {
        const dokkebiOutDir = path.join(distRoot, 'dokkebi');

        // dist/ 는 있지만 dokkebi-qjs.js 가 없는 경우 — WASM 번들만 단독으로 생성
        const qjsPath    = path.join(dokkebiOutDir, 'dokkebi-qjs.js');
        const qjsExists  = await fs.access(qjsPath).then(() => true).catch(() => false);
        if (!qjsExists) {
            console.log(`\n${C.bold}[dokkebi:dev] 🔨 QuickJS WASM 번들 생성 중 (dokkebi-qjs.js 없음)...${C.reset}`);
            try {
                await buildQuickJSBundle(dokkebiOutDir, { minify: false });
                console.log(`${C.bold}[dokkebi:dev] ✅ QuickJS WASM 번들 완료${C.reset}\n`);
            } catch (e) {
                console.warn(`${C.yellow}[dokkebi:dev] ⚠ WASM 번들 실패 (백엔드 없이 계속):${C.reset} ${e.message}\n`);
            }
        }

        // dist/ 는 있지만 backend-bundle.js 가 없는 경우 — 초기 백엔드 번들 단독 생성
        const bundlePath   = path.join(dokkebiOutDir, 'backend-bundle.js');
        const bundleExists = await fs.access(bundlePath).then(() => true).catch(() => false);
        if (!bundleExists) {
            const backendEntry = await findBackendEntry(src);
            if (backendEntry) {
                const backendDir = path.join(sourceRoot, 'backend');
                console.log(`${C.bold}[dokkebi:dev] ⚙  백엔드 초기 번들 생성 중...${C.reset}`);
                try {
                    await bundleBackendForWasm({ backendEntry, outFile: bundlePath, backendDir, minify: false });
                    console.log(`${C.bold}[dokkebi:dev] ✅ 백엔드 초기 번들 완료${C.reset}\n`);
                } catch (e) {
                    console.warn(`${C.yellow}[dokkebi:dev] ⚠ 백엔드 초기 번들 실패:${C.reset} ${e.message}\n`);
                }
            }
        }
    }

    const envVars  = await loadEnvFile(sourceRoot);

    // 포트 우선순위: CLI 옵션 > .env PORT > dokkebi.config.js dev.port > 기본값 5173
    const dokConfig = await _loadDevDokConfig(sourceRoot);
    const port = Number(options.port) || Number(envVars.PORT) || Number(process.env.PORT)
                 || Number(dokConfig?.dev?.port) || 5173;

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

    // ── 로컬 DB 모드 감지 (외부 DB 자격증명 미설정 시) ────────
    const localDbMode = !hasDbCredentials(dbType, dbConfig);
    let migrationSql = '';
    if (localDbMode) {
        try {
            const migrationsDir = path.join(sourceRoot, 'backend', 'db', 'migrations');
            const files = (await fs.readdir(migrationsDir))
                .filter(f => f.endsWith('.sql'))
                .sort(); // 파일명 오름차순으로 순서대로 적용
            const sqls = await Promise.all(
                files.map(f => fs.readFile(path.join(migrationsDir, f), 'utf-8')),
            );
            migrationSql = sqls.join('\n');
            console.log(`${C.cyan}[dokkebi] 📦 로컬 DB 모드 활성화${C.reset} — 외부 DB 자격증명 미설정`);
            console.log(`${C.gray}[dokkebi]    데이터: 브라우저 OPFS/IndexedDB (sql.js SQLite WASM)${C.reset}`);
            console.log(`${C.gray}[dokkebi]    마이그레이션: ${files.join(', ')}${C.reset}`);
        } catch {
            console.warn(`${C.yellow}[dokkebi] ⚠ 마이그레이션 SQL 파일을 찾을 수 없습니다${C.reset}`);
        }
    }

    // ── env-secrets.json 로드 (빌드 타임에 분리된 민감 환경변수) ──
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
        if (Object.keys(envSecrets).length > 0) {
            console.log(`[dokkebi:dev] 🔐 민감 변수 ${Object.keys(envSecrets).length}개 → 핸드셰이크 암호화 전달 활성`);
        }
    } catch { /* 매니페스트 없으면 무시 */ }

    // ── 플러그인 로딩 ────────────────────────────────────
    const plugins = await loadPlugins(sourceRoot);
    let pluginHostCode = '';
    let pluginVmBridge = '';
    if (plugins.length > 0) {
        console.log(`[dokkebi:dev] 플러그인 ${plugins.length}개 로드: ${plugins.map(p => p.name).join(', ')}`);
        const pluginCode = generatePluginBootstrapCode(plugins, envVars);
        pluginHostCode = pluginCode.hostImplementations;
        pluginVmBridge = pluginCode.vmBindings;
    }

    // ── 개발용 부트스트랩 생성 (vite 재빌드 후 index.html 재주입용) ──
    // bundleHash를 빈 문자열로 설정해 개발 모드에서 무결성 검사 비활성화
    _devBootstrapHtml = generateBootstrapScript({
        dbType,
        bundleHash: '',
        localDbMode,
        migrationSql,
        pluginHostCode,
        pluginVmBridge,
        queryLearn: true,
        logging: dokConfig?.logging,
    });

    // ── SQL Allowlist 로드 (dok build 단계에서 생성된 파일) ─────
    const allowlistPath = path.join(distRoot, 'dokkebi', 'sql-allowlist.json');
    let sqlAllowlist = await loadAllowlist(allowlistPath);
    if (sqlAllowlist && Array.isArray(sqlAllowlist.tables)) {
        const userTables = sqlAllowlist.tables.filter(t => !t.name.startsWith('_dokkebi_') && t.name !== 'sqlite_master');
        console.log(`${C.gray}[dokkebi] 🛡 SQL 허용목록 로드: ${userTables.length}개 테이블, raw SQL: ${sqlAllowlist.rawAllowed ? '허용' : '차단'}${C.reset}`);
    } else {
        if (sqlAllowlist && !Array.isArray(sqlAllowlist.tables)) {
            // 빌드 메타 비우기 단계가 sql-allowlist.json 을 {} 로 비운 경우 — dev 에서 학습으로 채움
            sqlAllowlist = null;
        }
        console.warn(`${C.yellow}[dokkebi] ⚠ SQL 허용목록 파일 없음: ${path.relative(sourceRoot, allowlistPath)}${C.reset}`);
        console.warn(`${C.gray}[dokkebi]   dev 모드는 경고만 출력합니다. 프로덕션 대응을 위해 dok build 를 먼저 실행하세요.${C.reset}`);
    }

    // ── Query Registry 로드 (dok build 산출물 + 학습 캐시 병합) ──
    //   dev 모드는 learn: 새 shape 가 들어오면 자동으로 학습 캐시에
    //   기록되어 다음 dok build 시 포함됩니다.
    const registryPath = path.join(distRoot, 'dokkebi', 'query-registry.json');
    const qrBuildPart = await loadRegistry(registryPath);
    const qrLearnedPart = await loadLearnedRegistry(sourceRoot);
    const devRegistry = new QueryRegistry();
    devRegistry.merge(qrBuildPart);
    devRegistry.merge(qrLearnedPart);
    console.log(`${C.gray}[dokkebi] 🧭 Query Registry: ${devRegistry.size()}개 쿼리 로드 (learn 모드 활성)${C.reset}`);
    // 학습 파일 디바운스 flush
    let _learnFlushTimer = null;
    const onLearn = async (reg) => {
        if (_learnFlushTimer) clearTimeout(_learnFlushTimer);
        _learnFlushTimer = setTimeout(async () => {
            try {
                await writeLearnedRegistry(sourceRoot, reg);
            } catch (e) {
                console.warn(`${C.yellow}[dokkebi] learn 캐시 저장 실패: ${e.message}${C.reset}`);
            }
        }, 500);
    };

    // ── 파일 워처 시작 ───────────────────────────────────────
    const watcher          = startBackendWatcher(sourceRoot, distRoot);
    const frontendProcess  = startFrontendWatch(sourceRoot, distRoot);

    const server = http.createServer(async (req, res) => {
        const urlPath = req.url?.split('?')[0] || '/';
        const reqUrl = new URL(req.url || '/', 'http://dokkebi.dev');
        const page = reqUrl.searchParams.get('page');
        const allowEmbed = page === 'embed' || page === 'noto';

        // ── 보안 헤더 ────────────────────────────────────────
        setSecurityHeaders(res, 'dev', { allowEmbed });

        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Dokkebi-Session, Authorization');
        if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

        // ── 어드민 패널 (dev: /_dokkebi/_panel, serverless 호환: /api/_dokkebi/_panel) ──
        if (urlPath.startsWith('/_dokkebi/_panel') || urlPath.startsWith('/api/_dokkebi/_panel')) {
            await handleAdminRoute(req, res, {
                adminPassword, adminAllowedIps, panelIpGuardEnabled, dbType, dbConfig, proxyDbQuery,
                activeConnections: sseClients.size,
                projectName, mode: 'dev',
            });
            return;
        }

        // ── SSE 핫 리로드 엔드포인트 ─────────────────────────
        if (urlPath === '/_dokkebi/sse' && req.method === 'GET') {
            // SSE는 장기 연결 → 소켓 타임아웃 비활성화
            req.socket?.setTimeout(0);
            req.socket?.setKeepAlive(true, 0);

            res.writeHead(200, {
                'Content-Type':      'text/event-stream',
                'Cache-Control':     'no-cache',
                'Connection':        'keep-alive',
                'X-Accel-Buffering': 'no',
                'Transfer-Encoding': 'identity',
            });
            res.write(':ok\n\n');
            sseClients.add(res);

            // SSE keepalive: 25초마다 주석 핑 전송 (연결 유지)
            const keepalive = setInterval(() => {
                try { res.write(':ping\n\n'); } catch { clearInterval(keepalive); }
            }, 25_000);

            const cleanup = () => { clearInterval(keepalive); sseClients.delete(res); };
            req.on('close', cleanup);
            req.on('error', cleanup);
            return;
        }

        // ── GET /api/_dokkebi/handshake ──────────────────────
        if (urlPath === '/api/_dokkebi/handshake' && req.method === 'GET') {
            const ip = getClientIp(req);
            if (!checkRateLimit(ip, 'handshake')) {
                res.writeHead(429, { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '60' });
                res.end(JSON.stringify({ error: '요청이 너무 많습니다.' }));
                return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
            res.end(JSON.stringify({ serverPubKey: SERVER_PUB_KEY_B64 }));
            return;
        }

        // ── POST /api/_dokkebi/handshake ─────────────────────
        if (urlPath === '/api/_dokkebi/handshake' && req.method === 'POST') {
            const ip = getClientIp(req);
            if (!checkRateLimit(ip, 'handshake')) {
                res.writeHead(429, { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '60' });
                res.end(JSON.stringify({ error: '요청이 너무 많습니다.' }));
                return;
            }
            return handleHandshake(req, res, envSecrets);
        }

        // ── POST /api/_dokkebi/db ────────────────────────────
        if (urlPath === '/api/_dokkebi/db' && req.method === 'POST') {
            const ip = getClientIp(req);
            if (!checkRateLimit(ip, 'db')) {
                logSecurityEvent(proxyDbQuery, dbType, dbConfig, { type: 'rate_limit', ip, path: '/api/_dokkebi/db', detail: 'db rate limit exceeded' });
                res.writeHead(429, { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '60' });
                res.end(JSON.stringify({ error: '요청이 너무 많습니다.' }));
                return;
            }
            return handleDbProxy(req, res, dbType, dbConfig,
                (ev) => logSecurityEvent(proxyDbQuery, dbType, dbConfig, ev),
                sqlAllowlist, devRegistry, onLearn, distRoot, proxyMode);
        }

        // ── POST /api/_dokkebi/log ───────────────────────────
        if (urlPath === '/api/_dokkebi/log' && req.method === 'POST') {
            return handleLogCollect(req, res, { proxyDbQuery, dbType, dbConfig, ip: getClientIp(req) });
        }

        // ── POST /_ipfs/pin (dev 모드: Pinata 없이 CID null 반환) ──
        // /api/ 접두사 없이 사용 → WASM 인터셉터 우회
        if (urlPath === '/_ipfs/pin' && req.method === 'POST') {
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ success: true, cid: null, dev: true }));
            return;
        }

        // ── POST /_dokkebi/blog-media · GET /media/* (dev: .dev-blog-media/ 디스크) ──
        const devMediaRoot = path.join(sourceRoot, '.dev-blog-media');
        // 브라우저 WASM: 핸드셰이크로 받은 env-secrets 가 kv 우선(.env는 서버 핸드셰이크에 안 실림)
        const devEnv = { ...envVars, ...process.env };
        const jwtForMedia =
            envSecrets.DOKKEBI_JWT_SECRET ||
            envSecrets.JWT_SECRET ||
            devEnv.DOKKEBI_JWT_SECRET ||
            devEnv.JWT_SECRET ||
            'change-this-in-production';
        if (await tryDevBlogMediaPost(req, res, { jwtSecret: jwtForMedia, mediaRoot: devMediaRoot })) return;
        if (await tryDevBlogMediaGet(req, res, urlPath, devMediaRoot)) return;

        // ── 정적 파일 서빙 (path traversal 방어) ─────────────
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
            filePath = path.join(distRoot, 'index.html');
            try { await fs.access(filePath); }
            catch {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('Not Found');
                return;
            }
        }

        const ext         = path.extname(filePath);
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';

        try {
            // index.html은 dev 모드 처리 (SSE 주입 + 해시 비활성화)
            if (filePath.endsWith('index.html')) {
                return serveDevHtml(filePath, res);
            }

            const data = await fs.readFile(filePath);
            res.writeHead(200, {
                'Content-Type':  contentType,
                'Cache-Control': ext === '.wasm' ? 'public, max-age=86400' : 'no-cache',
            });
            res.end(data);
        } catch (e) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Internal Error: ' + e.message);
        }
    });

    // 활성 소켓 추적 — server.close()가 즉시 완료되도록 강제 destroy에 사용
    const activeSockets = new Set();
    server.on('connection', (socket) => {
        activeSockets.add(socket);
        socket.once('close', () => activeSockets.delete(socket));
    });

    // SSE 장기 연결이 타임아웃으로 끊기지 않도록 서버 타임아웃 비활성화
    server.keepAliveTimeout = 0;
    server.headersTimeout   = 0;
    server.timeout          = 0;

    server.listen(port, '0.0.0.0', () => {
        const dbLine = localDbMode
            ? `[dokkebi] DB 모드   : ${C.cyan}📦 로컬 DB (sql.js + OPFS/IndexedDB)${C.reset}`
            : `[dokkebi] DB 타입    : ${dbType}`;
        const proxyLines = localDbMode
            ? `[dokkebi] 데이터 저장: ${C.cyan}브라우저 IndexedDB/OPFS (서버 DB 프록시 비활성)${C.reset}`
            : `[dokkebi] 핸드셰이크 : /api/_dokkebi/handshake  ${C.cyan}(ECDH P-256)${C.reset}
[dokkebi] DB 프록시  : /api/_dokkebi/db          ${C.green}(AES-256-GCM + HMAC)${C.reset}`;
        console.log(`
${C.bold}[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}
${C.bold}[dokkebi] 🔥 ${t('dev.starting', { port })}${C.reset}
[dokkebi] 정적 폴더  : ${distRoot}
${dbLine}
[dokkebi] 핫 리로드  : ${C.green}백엔드 (esbuild) + 프론트엔드 (vite --watch)${C.reset}
[dokkebi] SSE 엔드포인트: /_dokkebi/sse
${proxyLines}
${C.yellow}[dokkebi] ℹ  백엔드(.ts/.js) 변경 → esbuild 재빌드 → 브라우저 리로드${C.reset}
${C.yellow}[dokkebi] ℹ  프론트엔드(.vue/.tsx 등) 변경 → vite 재빌드 → 브라우저 리로드${C.reset}
${C.bold}[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}
`);
    });

    // process.once 로 SIGINT 핸들러를 한 번만 등록
    // server.close()는 신규 연결만 막으므로, SSE 등 장기 연결은 직접 종료해야 함
    process.once('SIGINT', () => {
        console.log('\n' + t('dev.stopping'));

        // 1. 백엔드 파일 워처 종료
        if (watcher) try { watcher.close(); } catch { /* ignore */ }

        // 2. 프론트엔드 빌드 프로세스 종료 (자동재시작 방지 후 종료)
        if (frontendProcess) {
            try {
                if (typeof frontendProcess._devShutdown === 'function') frontendProcess._devShutdown();
                else frontendProcess.kill('SIGTERM');
            } catch { /* ignore */ }
        }

        // 3. SSE 클라이언트 연결 강제 종료 (끊지 않으면 server.close()가 블록됨)
        for (const res of sseClients) {
            try { res.end(); } catch { /* ignore */ }
        }
        sseClients.clear();

        // 4. 남은 소켓 강제 destroy (keep-alive 등)
        for (const socket of activeSockets) {
            try { socket.destroy(); } catch { /* ignore */ }
        }

        // 5. 서버 종료 (이미 모든 연결을 닫았으므로 즉시 콜백 호출됨)
        server.close(() => {
            console.log('[dokkebi] ✅ 종료 완료');
            process.exit(0);
        });

        // 3초 내 종료 안 되면 강제 종료 (안전망)
        setTimeout(() => process.exit(0), 3000).unref();
    });
}

async function _loadDevDokConfig(sourceRoot) {
    return loadDokkebiConfigMerged(sourceRoot, { quiet: true });
}
