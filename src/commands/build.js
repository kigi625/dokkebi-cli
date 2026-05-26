/**
 * dokkebi build 커맨드 (v2)
 *
 * 빌드 파이프라인:
 *   1. 프로젝트 구조 스캔
 *   2. .env 파일 로드 → DB 자격증명 실제값 주입
 *   3. WIT 인터페이스 파일 생성
 *   4. 백엔드 TypeScript → esbuild ESM 번들
 *   5. 프론트엔드 vite build
 *   6. Opaque Handle 부트스트랩을 HTML에 주입 (실제 자격증명 포함)
 */

import path from 'path';
import fs from 'fs/promises';
import { createHash } from 'crypto';
import { execSync } from 'child_process';
import { createRequire } from 'module';
import { scanProject } from '../core/scanProject.js';
import { buildWasm, isBundleEncryptEnabled } from '../core/buildWasm.js';
import { injectBootstrapAll, normalizeAuthSessionForBootstrap } from '../core/opaqueHandle.js';
import { emitWitFiles } from '../core/witGenerate.js';
import { runFrontendBuild } from '../core/runFrontendBuild.js';
import { extractAllowlist } from '../core/sqlAllowlist.js';
import { buildRegistry, writeRegistry } from '../core/queryRegistry.js';
import { normalizePolicyConfig } from '../core/policyEngine.js';
import { normalizeAuthorizationConfig } from '../core/authorizationPolicy.js';
import { inferPolicyFromProject, mergeInferredIntoConfig } from '../core/policyInference.js';
import { scanPolicyAnnotations, mergeAnnotationsIntoInferred } from '../core/policyAnnotations.js';
import { workerDb, workerAdmin, workerAdminApi, workerHandshake, workerRootMiddleware } from '../core/projectGenerator.js';
import { loadPlugins, generatePluginBootstrapCode } from '../core/pluginLoader.js';
import { loadDokkebiConfigMerged, applySecurityPreset } from '../core/dokkebiConfigLoad.js';
import { getHardeningFlags } from '../core/hardeningFlags.js';
import { runSeoPipeline } from '../core/seo/index.js';
import { purgeBuildArtifactsFromDist } from '../core/buildArtifactPurge.js';
import { buildWireRuntimeJson, emitPayloadWireTs, disabledWireRuntimeJson, collectPreviousForwards } from '../core/payloadWireRuntime.js';
import { t } from '../i18n/index.js';

const DEFAULT_OUTPUT = 'dist';

// ── Phase 1-③ 빌드 메타데이터 수집 ──────────────────────────
// 공급망 공격 감지용 tripwire. 배포된 워커가 누구의 어떤 소스에서 빌드
// 됐는지 관리자가 시각적으로 확인할 수 있게 해준다.
async function collectBuildMeta(sourceRoot) {
    const meta = {
        built_at: new Date().toISOString(),
        scanner_version: '',
        source_sha: '',
        source_branch: '',
        source_dirty: false,
        controllers_hash: '',
        controller_count: 0,
    };

    // scanner_version: dokkebi-cli 자체의 package.json.
    try {
        const require = createRequire(import.meta.url);
        const selfPkgPath = require.resolve('../../package.json');
        const pkg = JSON.parse(await fs.readFile(selfPkgPath, 'utf-8'));
        meta.scanner_version = String(pkg.version || '');
    } catch { /* 무시 */ }

    // git 커밋 정보 (git 저장소가 아니면 비움)
    try {
        const sha = execSync('git rev-parse HEAD', { cwd: sourceRoot, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
        if (sha) meta.source_sha = sha;
        const branch = execSync('git rev-parse --abbrev-ref HEAD', { cwd: sourceRoot, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
        if (branch) meta.source_branch = branch;
        const status = execSync('git status --porcelain', { cwd: sourceRoot, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
        meta.source_dirty = status.length > 0;
    } catch { /* git 아님 — 무시 */ }

    // controllers_hash: backend/controllers 전체 파일의 정렬된 SHA-256 합.
    try {
        const controllersDir = path.join(sourceRoot, 'backend', 'controllers');
        const files = await _collectFilesRecursive(controllersDir, /\.(ts|js)$/);
        files.sort();
        const h = createHash('sha256');
        for (const f of files) {
            const rel = path.relative(sourceRoot, f).replace(/\\/g, '/');
            const buf = await fs.readFile(f);
            h.update(rel + '\0');
            h.update(buf);
            h.update('\0');
        }
        meta.controllers_hash = h.digest('hex');
        meta.controller_count = files.length;
    } catch { /* 무시 */ }

    return meta;
}

async function _collectFilesRecursive(dir, re) {
    const out = [];
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); }
    catch { return out; }
    for (const ent of entries) {
        const p = path.join(dir, ent.name);
        if (ent.isDirectory()) {
            out.push(...(await _collectFilesRecursive(p, re)));
        } else if (ent.isFile() && re.test(ent.name)) {
            out.push(p);
        }
    }
    return out;
}

/**
 * Caller Guard 용 frontend 청크 allowlist 수집.
 * dist 의 *.js / *.mjs 파일들을 web-root 절대경로(/assets/index-XXX.js 등)로 반환.
 * `/dokkebi/*` (도깨비 내부 자산) 은 frontend 호출 출처가 될 일이 없으므로 제외.
 */
async function collectCallerAllowedScripts(rootDir, currentDir = null, basePath = '') {
    const cur = currentDir || rootDir;
    const out = [];
    let entries;
    try { entries = await fs.readdir(cur, { withFileTypes: true }); }
    catch { return out; }
    for (const ent of entries) {
        const abs = path.join(cur, ent.name);
        const web = basePath + '/' + ent.name;
        if (ent.isDirectory()) {
            if (ent.name === 'dokkebi') continue;
            out.push(...(await collectCallerAllowedScripts(rootDir, abs, web)));
        } else if (/\.(m|c)?js$/i.test(ent.name)) {
            out.push(web);
        }
    }
    return out;
}

// ── Cost-Route Detection (build-time advisory) ──────────────
//   백엔드 컨트롤러를 가볍게 스캔해 "외부 비용/금전 행위" 가능성이 있는
//   라우트를 찾아낸다. 자동으로 capability 를 *추가* 하지는 않고, 선언이
//   누락된 후보를 사용자에게 안내한다(false positive 방지).
//
//   감지 신호 (간단한 정규식 — 정밀 파싱 X):
//     - 외부 결제/AI API 호출: api.openai.com, api.anthropic.com,
//                              api.lemonsqueezy.com, api.stripe.com,
//                              api.tosspayments.com 등
//     - 민감 secret 직접 사용: process.env.OPENAI_API_KEY,
//                            __dokkebi_env__('OPENAI_API_KEY') 류
//     - 명시적 비용 행위: points.deduct(, wallet.charge(, billing.charge(
//
//   각 신호는 라우터 선언 (router.{get,post,put,delete,patch} / app.method)
//   가까이 있을 때만 라우트 후보로 간주한다.
const _COST_HOST_PAT = /api\.(openai|anthropic|lemonsqueezy|stripe|tosspayments|paddle)\.com/i;
const _SENSITIVE_ENV_PAT = /(?:process\.env|__dokkebi_env__\s*\(\s*['"])\s*\.?\s*(OPENAI[A-Z_]*|ANTHROPIC[A-Z_]*|STRIPE[A-Z_]*|LEMON[A-Z_]*|PADDLE[A-Z_]*|TOSS[A-Z_]*|SUPABASE_SERVICE_KEY|GEMINI[A-Z_]*)/;
const _COST_BILLING_PAT = /\b(?:points|wallet|billing|credit)\s*\.\s*(?:deduct|charge|debit|spend)\s*\(/;
const _ROUTE_DECL_PAT = /\b(?:router|app|api|route)\s*\.\s*(get|post|put|delete|patch|use)\s*\(\s*['"`]([^'"`]+)['"`]/i;

async function _scanCostRoutes(backendDir) {
    const findings = [];
    const files = await _collectFilesRecursive(backendDir, /\.(ts|js)$/);
    for (const file of files) {
        let src;
        try { src = await fs.readFile(file, 'utf-8'); }
        catch { continue; }
        const lines = src.split(/\r?\n/);
        // 파일 단위로 라우트 선언 위치를 모은 뒤, 각 라우트의 +-200줄 윈도우에서 신호를 찾는다.
        const routes = [];
        for (let i = 0; i < lines.length; i++) {
            const m = _ROUTE_DECL_PAT.exec(lines[i]);
            if (m) routes.push({ line: i, method: m[1].toUpperCase(), path: m[2] });
        }
        for (const r of routes) {
            const start = r.line;
            const end = Math.min(lines.length, start + 200);
            const window = lines.slice(start, end).join('\n');
            const reasons = [];
            const m1 = _COST_HOST_PAT.exec(window);
            if (m1) reasons.push('external_api:' + m1[0]);
            const m2 = _SENSITIVE_ENV_PAT.exec(window);
            if (m2) reasons.push('sensitive_env:' + (m2[1] || ''));
            const m3 = _COST_BILLING_PAT.exec(window);
            if (m3) reasons.push('billing_call');
            if (reasons.length === 0) continue;
            findings.push({
                file: path.relative(path.dirname(backendDir), file),
                line: r.line + 1,
                method: r.method,
                path: r.path,
                signals: reasons,
            });
        }
    }
    return findings;
}

function _isRouteCovered(method, routePath, capabilityMeta) {
    if (!capabilityMeta?.enabled) return false;
    const norm = String(routePath || '').replace(/\/+$/, '') || '/';
    const upMethod = String(method || '').toUpperCase();
    for (const spec of Object.values(capabilityMeta.features || {})) {
        for (const route of spec.routes || []) {
            const m = /^([A-Z*]+)\s+(.+)$/.exec(String(route).trim());
            if (!m) continue;
            const rm = m[1].toUpperCase();
            const rp = m[2].replace(/\/+$/, '') || '/';
            if ((rm === '*' || rm === upMethod) && rp === norm) return true;
        }
    }
    return false;
}

function _integritySummary(meta) {
    const sha = meta.source_sha ? meta.source_sha.slice(0, 8) : '(no-git)';
    const dirty = meta.source_dirty ? ' [dirty]' : '';
    const cH = meta.controllers_hash ? meta.controllers_hash.slice(0, 12) : '(n/a)';
    return `src=${sha}${dirty} ctrl=${cH} files=${meta.controller_count}`;
}

// ── Phase 2-⑧ 보안 커버리지 스코어 ──────────────────────────
// 다양한 보안 기능이 얼마나 활성/설정돼 있는지 0~100 점수로 환산.
// 프레임워크 기본 방어 (Opaque Handle/ECDH/HMAC/Replay/Allowlist/Pregate/
// EnvelopeCap) 가 이미 70점을 차지하며, 추가로 opt-in 기능들이 가산된다.
function computeSecurityCoverage({
    policyMeta, authzMeta, webauthnMeta, replayMeta, buildMeta, strictCsp,
    adlMeta, capabilityMeta, attestationMeta, panelIpGuardMeta,
    bytecodeMode, bytecodeEncrypted, encryptedTextMode, zeroDowntimeReady,
}) {
    const weights = {
        opaqueHandle: 12,      // 항상 ON — Handshake/Opaque Handle
        replay:       12,      // 항상 ON — timestamp+nonce+HMAC+AES
        allowlist:    10,      // 항상 ON — SQL Allowlist + validateSql
        registry:     8,       // (queryRegistry 활성 — 이후 조회)
        pregate:      6,       // Per-session 토큰 버킷
        envelopeCap:  4,       // Envelope size cap (저렴한 기본값)
        counter:      4,       // Monotonic counter nonce
        codeProtect:  3,       // 바이트코드 보호 (난독화+컴파일)
        codeEncrypt:  3,       // 바이트코드 AES-256-GCM 암호화
        tenantPolicy: 15,      // opt-in — Tenant Policy 활성 여부
        authzPolicy:  15,      // opt-in — Authorization Policy 활성 여부
        webauthn:     8,       // opt-in — WebAuthn 서명
        integritySig: 6,       // buildMeta 존재 (git+controllers hash)
        strictCsp:    5,       // opt-in — Strict CSP (hash 기반, XSS 심층방어)
        activeDefense: 8,      // opt-in (Phase 3) — Lazy ADL
        capabilities: 7,       // opt-in — Signed Unlock Token capability gates
        capChain:     3,       // opt-in — Capability Chain (requires.prev)
        attestation:  5,       // opt-in — Bundle Attestation (chunk-hash 검증)
        panelIpGuard: 4,       // opt-in — 관제 패널 IP allowlist
        zeroDowntime: 3,       // 자동 — 무중단 배포 (BC_KEY_MAP + 해시 박힌 immutable 번들)
    };
    const capFeatures = capabilityMeta?.features || {};
    const capHasChain = Object.values(capFeatures).some((spec) => Array.isArray(spec?.requires?.prev) && spec.requires.prev.length > 0);
    const enabled = {
        opaqueHandle: true,
        replay: true,
        allowlist: true,
        registry: true,
        pregate: true,
        envelopeCap: !!replayMeta?.maxEnvelopeBytes,
        counter: true,
        codeProtect: !!bytecodeMode || !!encryptedTextMode,
        codeEncrypt: !!bytecodeEncrypted,
        tenantPolicy: !!(policyMeta?.enabled && policyMeta.mode && policyMeta.mode !== 'off'),
        authzPolicy:  !!(authzMeta?.enabled && authzMeta.mode !== 'off'),
        webauthn:     !!webauthnMeta?.enabled,
        integritySig: !!(buildMeta?.controllers_hash && buildMeta.controllers_hash.length > 0),
        strictCsp:    strictCsp === true,
        activeDefense: !!(adlMeta?.enabled),
        capabilities: !!(capabilityMeta?.enabled),
        capChain:     !!(capabilityMeta?.enabled && capHasChain),
        attestation:  !!(attestationMeta?.enabled),
        panelIpGuard: !!(panelIpGuardMeta?.enabled),
        zeroDowntime: zeroDowntimeReady !== false, // 기본 true (v6.x+ 자동 적용)
    };
    let score = 0;
    for (const k of Object.keys(weights)) if (enabled[k]) score += weights[k];
    const total = Object.values(weights).reduce((a, b) => a + b, 0);
    const normalized = Math.round((score / total) * 100);

    // 구체적 권고사항 (배너 용)
    const recommendations = [];
    if (!enabled.codeProtect)  recommendations.push('코드 보호 미활성 — JS 소스가 노출됩니다. 바이트코드 모드가 자동 적용되지 않았다면 빌드 환경을 확인하세요.');
    if (!enabled.tenantPolicy) recommendations.push('Tenant Policy 미활성 — 다중 사용자 앱이면 활성화 권장');
    if (!enabled.authzPolicy)  recommendations.push('Authorization Policy 미활성 — 연산별 권한 검사 활성화 권장');
    if (!enabled.webauthn)     recommendations.push('WebAuthn(Passkey) 미활성 — 금융/관리자 기능에 권장 (opt-in)');
    if (!enabled.strictCsp)    recommendations.push('Strict CSP 미활성 — security.strictCsp: true 로 인라인 XSS 심층방어 권장');
    if (!enabled.activeDefense) recommendations.push('능동 방어(ADL) 미활성 — security.activeDefense.enabled: true 로 행동 기반 차단 활성 권장');
    else if (adlMeta?.mode === 'monitor') recommendations.push('능동 방어가 monitor 모드입니다 — 운영 1주 후 mode: "enforce" 로 전환 권장');
    if (!enabled.capabilities) recommendations.push('Signed Unlock Token 미활성 — 유료/고비용 기능은 security.capabilities 로 실행 허가 토큰 적용 권장');
    if (enabled.capabilities && !enabled.attestation) recommendations.push('Bundle Attestation 미활성 — security.attestation.enabled: true 로 번들 변조 방지 권장 (capability 자동 연동)');
    if (enabled.capabilities && !enabled.capChain) recommendations.push('Capability Chain 미사용 — 다단계 비용 흐름은 features.<x>.requires.prev 로 순서 강제 권장');
    if (!enabled.panelIpGuard) recommendations.push('관제 패널 IP allowlist 미활성 — 운영 단계에서 security.panelIpGuard: true + DOKKEBI_PANEL_ALLOWED_IPS 설정 권장');
    if (buildMeta?.source_dirty) recommendations.push('git 워킹 트리 dirty — 프로덕션 배포 전 커밋 권장');
    if (!buildMeta?.source_sha)  recommendations.push('git 저장소 아님 — 빌드 SHA 트레이서빌리티 없음');

    return {
        score: normalized,
        weights,
        enabled,
        recommendations,
        level: normalized >= 85 ? 'excellent' : normalized >= 70 ? 'good' : normalized >= 55 ? 'warn' : 'danger',
    };
}


// ── Replay 방어 기본값 ─────────────────────────────────────
//   보안 필수 기능이므로 opt-out 없음. 값만 조정 가능.
//   - timestampWindowMs: [1s, 30s] — 너무 좁으면 모바일에서 거부 폭증,
//                        너무 넓으면 실시간 재생공격 가능성 증가.
//   - nonceTtlMs:        [windowMs + 여유, 5 min] — window 보다 반드시 커야 함.
const REPLAY_DEFAULT = Object.freeze({ timestampWindowMs: 5_000, nonceTtlMs: 35_000 });
const REPLAY_TIMESTAMP_MIN_MS = 1_000;
const REPLAY_TIMESTAMP_MAX_MS = 30_000;
const REPLAY_NONCE_TTL_MAX_MS = 300_000;

// ── WebAuthn (Passkey) 요청 서명 — 완전 opt-in (v5.5+) ─────
//   enabled: false (기본) → 런타임 SDK 주입 없음, 배너 출력 없음.
//   enabled: true         → 사용자가 회원가입/로그인에 직접 배선해야 함을
//                           dok build 마다 배너로 상기.
function normalizeWebAuthnConfig(rawSecurity) {
    const raw = rawSecurity && typeof rawSecurity === 'object' && rawSecurity.webauthn && typeof rawSecurity.webauthn === 'object'
        ? rawSecurity.webauthn
        : {};
    if (raw.enabled !== true) return { enabled: false };
    return {
        enabled: true,
        rpName: typeof raw.rpName === 'string' ? raw.rpName : null,
        rpId: typeof raw.rpId === 'string' ? raw.rpId : null,
        userVerification: ['required', 'preferred', 'discouraged'].includes(raw.userVerification) ? raw.userVerification : 'preferred',
        attestation: ['none', 'indirect', 'direct'].includes(raw.attestation) ? raw.attestation : 'none',
        timeoutMs: Number.isFinite(Number(raw.timeoutMs)) ? Math.floor(Number(raw.timeoutMs)) : 60_000,
        requireForOps: Array.isArray(raw.requireForOps) ? raw.requireForOps.slice() : null,
    };
}

function normalizeReplayConfig(rawSecurity) {
    const raw = rawSecurity && typeof rawSecurity === 'object' && rawSecurity.replay && typeof rawSecurity.replay === 'object'
        ? rawSecurity.replay
        : {};

    const warn = (msg) => console.warn(t('build.replayWarn', { msg }));

    let windowMs = Number.isFinite(Number(raw.timestampWindowMs))
        ? Math.floor(Number(raw.timestampWindowMs))
        : REPLAY_DEFAULT.timestampWindowMs;
    if (windowMs < REPLAY_TIMESTAMP_MIN_MS) {
        warn(`timestampWindowMs=${windowMs} 은(는) 최소값 ${REPLAY_TIMESTAMP_MIN_MS}ms 로 보정됩니다.`);
        windowMs = REPLAY_TIMESTAMP_MIN_MS;
    } else if (windowMs > REPLAY_TIMESTAMP_MAX_MS) {
        warn(`timestampWindowMs=${windowMs} 은(는) 최대값 ${REPLAY_TIMESTAMP_MAX_MS}ms 로 제한됩니다 (보안 권장).`);
        windowMs = REPLAY_TIMESTAMP_MAX_MS;
    }

    let nonceTtl = Number.isFinite(Number(raw.nonceTtlMs))
        ? Math.floor(Number(raw.nonceTtlMs))
        : REPLAY_DEFAULT.nonceTtlMs;
    const minNonceTtl = windowMs + 5_000;
    if (nonceTtl < minNonceTtl) {
        warn(`nonceTtlMs=${nonceTtl} 이 timestampWindowMs(${windowMs}) + 5s 보다 작아 ${minNonceTtl}ms 로 보정됩니다.`);
        nonceTtl = minNonceTtl;
    } else if (nonceTtl > REPLAY_NONCE_TTL_MAX_MS) {
        warn(`nonceTtlMs=${nonceTtl} 은(는) 최대값 ${REPLAY_NONCE_TTL_MAX_MS}ms 로 제한됩니다.`);
        nonceTtl = REPLAY_NONCE_TTL_MAX_MS;
    }

    if (raw.enabled === false) {
        warn('enabled: false 는 무시됩니다 — Replay 방어는 보안 필수 기능이며 비활성화할 수 없습니다.');
    }

    // Phase 1-② · Phase 2-⑤ · Phase 2-⑦ 추가 파라미터 (옵셔널)
    const rawSec = rawSecurity && typeof rawSecurity === 'object' ? rawSecurity : {};
    const rawPre = rawSec.preGate && typeof rawSec.preGate === 'object' ? rawSec.preGate : {};
    const rawMut = rawSec.mutationBudget && typeof rawSec.mutationBudget === 'object' ? rawSec.mutationBudget : {};

    const clampInt = (v, lo, hi, def) => {
        const n = Number(v);
        if (!Number.isFinite(n)) return def;
        return Math.max(lo, Math.min(hi, Math.floor(n)));
    };

    // envelope size cap: 4KB ~ 2MB. 기본 512KB (/api/_dokkebi/db 암호화 봉투 전체).
    // preGate → replay → security 순으로 오버라이드 (replay.maxEnvelopeBytes 가 dokkebi.config 표준).
    const maxEnvelopeBytes = clampInt(
        rawPre.maxEnvelopeBytes ?? raw.maxEnvelopeBytes ?? rawSec.maxEnvelopeBytes,
        4 * 1024,
        2 * 1024 * 1024,
        512 * 1024,
    );
    // per-session rpm: 10 ~ 6000. 기본 300.
    const pregateRpm = clampInt(rawPre.rpm, 10, 6000, 300);
    // mutation budget: writes/min 0 ~ 10000 (0 이면 off), deletes/min 0 ~ 10000.
    const writesPerMinute = clampInt(rawMut.writesPerMinute, 0, 10000, 120);
    const deletesPerMinute = clampInt(rawMut.deletesPerMinute, 0, 10000, 30);

    // 0 이면 사실상 무제한 — 캡을 매우 크게 잡아 동일 효과
    const _eff = (n) => (n === 0 ? 10_000_000 : n);

    return {
        timestampWindowMs: windowMs,
        nonceTtlMs: nonceTtl,
        maxEnvelopeBytes,
        pregate: { rpm: pregateRpm },
        mutationBudget: {
            writesPerMinute: _eff(writesPerMinute),
            deletesPerMinute: _eff(deletesPerMinute),
        },
    };
}

// ── Phase 3 — Active Defense Layer 설정 ─────────────────────
//   security.activeDefense 섹션. 기본 enabled: false (opt-in).
//   trigger 'lazy' (기본): Cron Trigger 없이 핫패스 ctx.waitUntil 로 동작 → 다수 사이트 무료 운영.
//   mode 'monitor' (기본): 차단 없이 감지+로그만. 운영 1주 후 'enforce' 전환 권장.
function normalizeActiveDefenseConfig(rawSecurity) {
    const raw = rawSecurity && typeof rawSecurity === 'object' && rawSecurity.activeDefense && typeof rawSecurity.activeDefense === 'object'
        ? rawSecurity.activeDefense
        : {};
    if (raw.enabled !== true) {
        return { enabled: false, version: 1 };
    }
    const mode = ['monitor', 'enforce'].includes(raw.mode) ? raw.mode : 'monitor';
    const trigger = ['lazy', 'cron'].includes(raw.trigger) ? raw.trigger : 'lazy';
    const sampleRate = Number.isFinite(Number(raw.sampleRate))
        ? Math.max(0, Math.min(1, Number(raw.sampleRate)))
        : 0.01;
    // interval 문자열 ('1m','5m','15m','1h') 또는 숫자(ms) 지원.
    let intervalMs = 5 * 60 * 1000;
    if (typeof raw.interval === 'number' && Number.isFinite(raw.interval)) {
        intervalMs = Math.max(60_000, Math.floor(raw.interval));
    } else if (typeof raw.interval === 'string') {
        const m = /^(\d+)\s*([smh])?$/i.exec(raw.interval.trim());
        if (m) {
            const n = Number(m[1]);
            const unit = (m[2] || 'm').toLowerCase();
            const mul = unit === 's' ? 1000 : unit === 'h' ? 3600_000 : 60_000;
            intervalMs = Math.max(60_000, n * mul);
        }
    }
    const riskBlockThreshold = Number.isFinite(Number(raw.riskBlockThreshold))
        ? Math.max(0, Math.min(1, Number(raw.riskBlockThreshold)))
        : 0.85;
    const useWorkersAI = raw.useWorkersAI === true;
    return {
        enabled: true,
        version: 1,
        mode,
        trigger,
        sampleRate,
        intervalMs,
        riskBlockThreshold,
        useWorkersAI,
    };
}

// ── Cryptographic Checkpoint — Signed Unlock Token 설정 ─────
//   security.capabilities 섹션. 기본 enabled: false (완전 opt-in).
//   민감 기능이 실행되기 전 Worker-only secret 으로 서명된 짧은 수명 토큰을 발급한다.
function normalizeCapabilitiesConfig(rawSecurity, annotations = null) {
    const raw = rawSecurity && typeof rawSecurity === 'object' && rawSecurity.capabilities && typeof rawSecurity.capabilities === 'object'
        ? rawSecurity.capabilities
        : {};
    if (raw.enabled !== true) {
        return { enabled: false, version: 1 };
    }
    const defaultTtlMs = Number.isFinite(Number(raw.defaultTtlMs))
        ? Math.max(1_000, Math.min(300_000, Math.floor(Number(raw.defaultTtlMs))))
        : 15_000;
    const secretEnv = typeof raw.secretEnv === 'string' && raw.secretEnv.trim()
        ? raw.secretEnv.trim()
        : 'DOKKEBI_CAPABILITY_SECRET';
    const claim = typeof raw.claim === 'string' && raw.claim.trim()
        ? raw.claim.trim()
        : 'role';
    const features = {};
    const mergeFeature = (featureName, spec) => {
        if (!featureName) return;
        const ttlMs = Number.isFinite(Number(spec.ttlMs))
            ? Math.max(1_000, Math.min(300_000, Math.floor(Number(spec.ttlMs))))
            : defaultTtlMs;
        const prev = features[featureName] || {};
        // requires.attest — true 면 capability 발급 전에 Bundle Attestation 통과 필요.
        // requires.prev   — 이 capability 를 받기 전에 먼저 발급/제출되어야 하는 다른 feature 토큰.
        //                   클라이언트는 unlock 호출 시 prevTokens: [{feature, token}] 로 동봉한다.
        const rawRequires = spec.requires && typeof spec.requires === 'object' ? spec.requires : {};
        const prevRequires = prev.requires || {};
        const requiresAttest = rawRequires.attest === true || prevRequires.attest === true;
        const requiresPrev = Array.from(new Set([
            ...(Array.isArray(prevRequires.prev) ? prevRequires.prev : []),
            ...(Array.isArray(rawRequires.prev) ? rawRequires.prev.map(String).filter(Boolean) : []),
        ]));
        features[featureName] = {
            public: spec.public === true || prev.public === true,
            auth: spec.auth === true || Array.isArray(spec.roles) || prev.auth === true,
            roles: Array.isArray(spec.roles) ? spec.roles.map(String).filter(Boolean) : (Array.isArray(prev.roles) ? prev.roles : null),
            deny: spec.deny === true || prev.deny === true,
            ttlMs,
            routes: Array.from(new Set([...(prev.routes || []), ...(Array.isArray(spec.routes) ? spec.routes.map(String) : [])])),
            requires: (requiresAttest || requiresPrev.length > 0)
                ? { attest: requiresAttest, prev: requiresPrev }
                : undefined,
        };
    };
    const rawFeatures = raw.features && typeof raw.features === 'object' ? raw.features : {};
    for (const [name, specRaw] of Object.entries(rawFeatures)) {
        const featureName = String(name || '').trim();
        if (!featureName) continue;
        const spec = specRaw && typeof specRaw === 'object' ? specRaw : {};
        mergeFeature(featureName, spec);
    }
    for (const [name, specRaw] of Object.entries(annotations?.capabilities || {})) {
        const featureName = String(name || '').trim();
        if (!featureName) continue;
        const spec = specRaw && typeof specRaw === 'object' ? specRaw : {};
        mergeFeature(featureName, spec);
    }
    return {
        enabled: true,
        version: 1,
        secretEnv,
        defaultTtlMs,
        claim,
        features,
    };
}

function capabilityRuntimeGuards(capabilityMeta) {
    if (!capabilityMeta?.enabled) return { enabled: false, routes: [], features: {} };
    const routes = [];
    // features 는 클라이언트가 prev 자동 동봉/재귀 unlock 을 수행할 때 필요한
    // 메타데이터(요구 prev, attest 필요 여부, ttlMs)를 담는다. roles/auth 같은
    // 정책 결정 자체는 워커가 수행하므로, 클라이언트로 내려가는 정보는 흐름
    // 자동화에 필요한 최소 항목으로 제한한다.
    const features = {};
    for (const [feature, spec] of Object.entries(capabilityMeta.features || {})) {
        for (const route of spec.routes || []) {
            const m = /^([A-Z*]+)\s+(.+)$/.exec(String(route).trim());
            if (!m) continue;
            routes.push({
                method: m[1],
                path: m[2],
                feature,
                ttlMs: spec.ttlMs,
            });
        }
        features[feature] = {
            ttlMs: Number(spec.ttlMs) || 0,
            requires: {
                prev: Array.isArray(spec.requires?.prev) ? spec.requires.prev.slice() : [],
                attest: spec.requires?.attest === true,
            },
        };
    }
    return { enabled: true, routes, features };
}

// Bundle Attestation — security.attestation 섹션을 정규화한다.
//   기본 동작: capabilities.enabled === true 면 자동 ON (사용자가 명시적으로 false 로 끌 때만 off).
//   capabilities 가 꺼져 있으면 attestation 만 켜는 건 의미가 작으므로 default off.
//   sampleSize 는 한 챌린지에서 검사할 청크 수 (기본 4, 최대 16).
//   ttlMs 는 attest 결과가 유효한 시간 (기본 5분, 최대 30분).
function normalizeAttestationConfig(rawSecurity, capabilityMeta = null) {
    const raw = rawSecurity && typeof rawSecurity === 'object' && rawSecurity.attestation && typeof rawSecurity.attestation === 'object'
        ? rawSecurity.attestation
        : {};
    // 자동 ON 규칙:
    //   1) raw.enabled === true              → 강제 ON
    //   2) raw.enabled === false             → 강제 OFF (사용자 명시 opt-out)
    //   3) raw.enabled 미설정                → capabilityMeta.enabled 를 따라간다
    let enabled;
    if (raw.enabled === true) enabled = true;
    else if (raw.enabled === false) enabled = false;
    else enabled = !!(capabilityMeta && capabilityMeta.enabled);
    if (!enabled) return { enabled: false, version: 1, autoFromCapabilities: false };
    const sampleSize = Number.isFinite(Number(raw.sampleSize))
        ? Math.max(1, Math.min(16, Math.floor(Number(raw.sampleSize))))
        : 4;
    const ttlMs = Number.isFinite(Number(raw.ttlMs))
        ? Math.max(30_000, Math.min(30 * 60_000, Math.floor(Number(raw.ttlMs))))
        : 5 * 60_000;
    return {
        enabled: true,
        version: 1,
        sampleSize,
        ttlMs,
        autoFromCapabilities: raw.enabled === undefined && !!(capabilityMeta && capabilityMeta.enabled),
    };
}

function normalizePanelIpGuardConfig(rawSecurity) {
    const direct = rawSecurity?.panelIpGuard;
    const adminPanel = rawSecurity?.adminPanel;
    const legacy = adminPanel?.ipAllowlist;
    return {
        enabled: direct === true || direct?.enabled === true || legacy === true || legacy?.enabled === true,
    };
}

// Phase 3-C — ADL 룰 시그니처 (공급망 무결성).
//   현재 ADL 룰은 Worker 템플릿 안에 인라인이라 _runActiveDefenseAnalysis
//   소스의 SHA-256 으로 룰셋 변조 감지. 룰 외부 모듈화 시 별도 파일로 이동.
function _adlRulesSignature() {
    // 정규화된 룰 식별자 — 룰 추가/변경 시마다 갱신.
    const ruleIds = [
        'ip-rate-zscore-5m@v1',
        'ip-fail-count-10m@v1',
        'session-risk-1h@v1',
        'blacklist-gc@v1',
    ];
    const sig = createHash('sha256').update(ruleIds.join('|')).digest('hex');
    return { sha256: sig, ruleIds };
}

export async function runBuild(src, options = {}) {
    const sourceRoot = path.resolve(process.cwd(), src);
    const outputName = options.output || DEFAULT_OUTPUT;
    const outDir = path.join(sourceRoot, outputName);

    console.log('\n[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('[dokkebi] ' + t('build.header'));
    console.log(t('build.sourceRoot'), sourceRoot);
    console.log('[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    // ── Step 0: dokkebi.config.js + .env 로드 ──────────────
    const _rawConfig = await loadDokkebiConfigMerged(sourceRoot);
    // ── 보안 프리셋 적용: security.level (basic | standard | strict) ─────
    //   사용자 명시값(예: policy.mode = 'inject') 은 항상 우선.
    //   level 미지정 시에는 프리셋을 적용하지 않음(기존 동작·호환).
    const dokkebiConfig = applySecurityPreset(_rawConfig);
    const envVars = await loadEnvFile(sourceRoot);

    const dbType = options.dbType || dokkebiConfig?.database?.type || 'd1';
    const proxyMode = dokkebiConfig?.proxyMode || 'server';

    let wireRuntimeJson = disabledWireRuntimeJson();
    let rotationPreviousState = null;
    try {
        const dokDir = path.join(sourceRoot, '.dokkebi');
        try {
            const hist = JSON.parse(await fs.readFile(path.join(dokDir, 'rotation-history.json'), 'utf-8'));
            const forwards = collectPreviousForwards(hist);
            if (forwards.length) rotationPreviousState = { previousForwards: forwards };
        } catch { /* no history */ }
        if (!rotationPreviousState) {
            rotationPreviousState = JSON.parse(await fs.readFile(path.join(dokDir, 'rotation-state.json'), 'utf-8'));
        }
    } catch { /* first build */ }

    // 실제 자격증명: .env 변수로 config의 ${VAR} 플레이스홀더 치환
    const dbConfig = resolveDbConfig(
        options.dbConfig || dokkebiConfig?.database || {},
        envVars
    );

    console.log(t('build.dbType'), dbType);
    const maskedKey = dbConfig.apiToken || dbConfig.anonKey || dbConfig.apiKey || '';
    if (maskedKey) {
        console.log(t('build.credentials', { prefix: maskedKey.slice(0, 6) }));
    } else {
        console.warn(t('build.noCredentials'));
    }

    // ── Step 1: 프로젝트 구조 스캔 ─────────────────────────
    console.log('\n' + t('build.step1'));
    const scan = await scanProject(sourceRoot, {
        backendHint: options.backend || 'backend',
        frontendHint: options.frontend,
    });

    const backendEntry =
        options.backendEntry ||
        (dokkebiConfig?.backend?.entry &&
            path.resolve(sourceRoot, dokkebiConfig.backend.entry)) ||
        scan.backendEntry;

    const backendDir = scan.backendDir || path.join(sourceRoot, 'backend');
    const frontendDir = scan.frontendDir || path.join(sourceRoot, 'frontend');

    if (!backendEntry) {
        throw new Error(
            '[dokkebi] 백엔드 진입점을 찾을 수 없습니다.\n' +
            'dokkebi.config.js에 backend.entry를 설정하거나 --backend 옵션을 사용하세요.'
        );
    }

    console.log(t('build.backendEntry'), backendEntry);
    console.log(t('build.frontend'), frontendDir);

    // ── Step 2: WIT 인터페이스 파일 생성 ───────────────────
    console.log('\n' + t('build.step2'));
    const witDir = path.join(backendDir, 'wit');
    const witFiles = await emitWitFiles(witDir, { dbType });
    console.log(t('build.witFile'), witFiles.wit);
    console.log(t('build.hostBindings'), witFiles.hostBindings);

    // ── Step 3: 프론트엔드 빌드 (먼저 실행 — emptyOutDir이 dist/ 초기화) ─
    if (options.skipFrontendBuild !== true) {
        console.log('\n' + t('build.step3'));
        await runFrontendBuild(frontendDir, scan.frontendBuildCommand);
        console.log(t('build.step3Done'));
    } else {
        console.log('\n' + t('build.step3Skip'));
    }

    // ── Step 4: 백엔드 번들 빌드 (프론트 빌드 이후) ────────
    const wasmOutDir = path.join(outDir, 'dokkebi');
    let bundleHash = null;
    let bundleAssetName = null;
    let chunkManifest = null;
    let bytecodeMode = false;
    let bytecodeEncrypted = false;
    let encryptedTextMode = false;

    let envSecrets = {};
    if (options.skipBackendBuild !== true) {
        console.log('\n' + t('build.step4'));
        const wasmResult = await buildWasm({
            backendEntry,
            backendDir,
            outDir: wasmOutDir,
            dbType,
            logCollectLevel: dokkebiConfig?.logging?.level,
            bundleEncrypt: dokkebiConfig?.security?.bundleEncrypt,
        });
        bundleHash = wasmResult.bundleHash || null;
        bundleAssetName = wasmResult.bundleAssetName || null;
        chunkManifest = wasmResult.chunkManifest || null;
        envSecrets = wasmResult.envSecrets || {};
        bytecodeMode = wasmResult.bytecodeMode || false;
        bytecodeEncrypted = wasmResult.bytecodeEncrypted || false;
        encryptedTextMode = wasmResult.encryptedTextMode || false;
        const workerOnlyEnvUsages = Array.from(new Set(wasmResult.sensitiveEnvUsages || []));
        if (workerOnlyEnvUsages.length > 0) {
            const message = `[dokkebi] ⚠ Worker 전용 Secret을 백엔드 WASM에서 직접 읽고 있습니다: ${workerOnlyEnvUsages.join(', ')}\n`
                + '[dokkebi]   이 값들은 클라이언트로 전달되지 않습니다. Worker-side operation/proxy로 옮겨 결과만 응답하세요.';
            const strict = String(dokkebiConfig?.security?.level || '').toLowerCase() === 'strict';
            // strict 만 차단. dok deploy 는 말미 안내용 경고만 (배포 진행).
            if (strict) {
                throw new Error(
                    message
                    + '\n[dokkebi]   배포 차단: security.level: strict 에서는 Worker 전용 Secret 의 WASM 직접 사용을 허용하지 않습니다.',
                );
            }
            if (options.forDeploy) {
                console.warn(
                    message
                    + '\n[dokkebi]   배포는 계속됩니다. Worker-side(worker/api/…) 로 옮기는 것을 권장합니다.',
                );
            } else {
                console.warn(message);
            }
        }
        console.log(t('build.buildComplete', { mode: wasmResult.mode }));

        // 민감 환경변수를 프로젝트 루트의 .dokkebi/ 에 저장 (dist/ 밖 — 공개 서빙 방지)
        if (Object.keys(envSecrets).length > 0) {
            const dokkebiDir = path.join(sourceRoot, '.dokkebi');
            await fs.mkdir(dokkebiDir, { recursive: true });
            const secretsPath = path.join(dokkebiDir, 'env-secrets.json');

            // 무중단 배포(zero-downtime) — __DOKKEBI_BC_KEY_MAP__ 누적/GC
            //   배포 직후 옛 HTML 을 들고 있던 사용자(=옛 bundleHash 로 핸드셰이크 요청)
            //   에게도 정확한 복호화 키를 응답하기 위해 최근 N개 빌드의 키를 함께
            //   유지한다. 한 번에 하나의 워커-only Secret(JSON map) 으로 등록한다.
            //   - 키: bundleHash 의 앞 12자
            //   - 값: AES-256-GCM 키(hex 64자)
            //   - GC: 최신 5개만 유지 (오래된 빌드의 옛 번들은 자연 만료)
            try {
                if (envSecrets.__DOKKEBI_BC_KEY__ && bundleHash) {
                    const newHash12 = String(bundleHash).slice(0, 12);
                    const newKey = String(envSecrets.__DOKKEBI_BC_KEY__);
                    envSecrets.__DOKKEBI_BC_HASH__ = newHash12;
                    let prevMap = {};
                    try {
                        const raw = JSON.parse(await fs.readFile(secretsPath, 'utf-8'));
                        const prevMapRaw = raw?.secrets?.__DOKKEBI_BC_KEY_MAP__;
                        if (typeof prevMapRaw === 'string') {
                            try { prevMap = JSON.parse(prevMapRaw) || {}; } catch { prevMap = {}; }
                        } else if (prevMapRaw && typeof prevMapRaw === 'object') {
                            prevMap = { ...prevMapRaw };
                        }
                        // 직전 빌드 키도 별도 저장돼 있다면 보존(혹시 누락된 경우)
                        const prevKey = raw?.secrets?.__DOKKEBI_BC_KEY__;
                        const prevHash = raw?.bundleHash || raw?.lastBundleHash;
                        if (typeof prevKey === 'string' && typeof prevHash === 'string') {
                            const ph12 = prevHash.slice(0, 12);
                            if (ph12 && !prevMap[ph12]) prevMap[ph12] = prevKey;
                        }
                    } catch { /* env-secrets.json 없음 → 빈 맵 시작 */ }
                    if (!Object.prototype.hasOwnProperty.call(prevMap, newHash12)) {
                        prevMap[newHash12] = newKey;
                    } else {
                        // 동일 해시 재빌드(deterministic 아님) — 최신 키로 덮어쓰기
                        prevMap[newHash12] = newKey;
                    }
                    // 최근 5개만 유지 (FIFO by insertion order — Object key order 보장됨)
                    const MAX_KEEP = 5;
                    const entries = Object.entries(prevMap);
                    if (entries.length > MAX_KEEP) {
                        // 새 키가 항상 마지막에 오도록 재정렬
                        const trimmed = entries
                            .filter(([k]) => k !== newHash12)
                            .slice(-(MAX_KEEP - 1));
                        trimmed.push([newHash12, prevMap[newHash12]]);
                        prevMap = Object.fromEntries(trimmed);
                    }
                    envSecrets.__DOKKEBI_BC_KEY_MAP__ = JSON.stringify(prevMap);
                    console.log(`[dokkebi]   🔁 BC_KEY_MAP: ${Object.keys(prevMap).length}개 빌드 키 유지 (무중단 배포)`);
                }
            } catch (e) {
                console.warn('[dokkebi] ⚠ BC_KEY_MAP 누적 실패 (단일 키만 사용됩니다):', e?.message || e);
            }

            await fs.writeFile(
                secretsPath,
                JSON.stringify({ secrets: envSecrets, bundleHash, generatedAt: new Date().toISOString() }),
                'utf-8',
            );
            console.log(t('build.envSecretsManifest', { count: Object.keys(envSecrets).length }));

            // dist/ 내 구버전 파일이 남아있으면 더미로 덮어쓰기 (CDN 캐시 무효화)
            const legacySecretsPath = path.join(wasmOutDir, 'env-secrets.json');
            try {
                await fs.access(legacySecretsPath);
                await fs.writeFile(legacySecretsPath, '{}', 'utf-8');
            } catch { /* 없으면 무시 */ }

            // .gitignore에 .dokkebi/ 추가
            try {
                const gitignorePath = path.join(sourceRoot, '.gitignore');
                let content = '';
                try { content = await fs.readFile(gitignorePath, 'utf-8'); } catch {}
                if (!content.includes('.dokkebi/')) {
                    await fs.appendFile(gitignorePath, '\n.dokkebi/\n');
                }
            } catch { /* 무시 */ }
        }
    } else {
        console.log('\n' + t('build.step4Skip'));
        const encryptSkip = isBundleEncryptEnabled(dokkebiConfig?.security?.bundleEncrypt, process.env);
        if (encryptSkip) {
            const encDir = await fs.readdir(wasmOutDir).catch(() => []);
            const hasEnc = encDir.some(
                (n) => n === 'backend.bundle.enc' || /^backend\.bundle\.[a-f0-9]{12}\.enc$/i.test(n),
            );
            if (!hasEnc) {
                throw new Error(
                    '[dokkebi] 암호화 번들(.enc)이 dist/dokkebi 에 없습니다. --skip-backend-build 없이 빌드하거나 dok build 로 번들을 생성하세요.',
                );
            }
            const plainStale = await fs
                .access(path.join(wasmOutDir, 'backend-bundle.js'))
                .then(() => true)
                .catch(() => false);
            if (plainStale) {
                throw new Error(
                    '[dokkebi] security.bundleEncrypt 가 켜져 있는데 dist/dokkebi/backend-bundle.js 가 남아 있습니다. dok build 로 정리하세요.',
                );
            }
        } else {
            const bundleExists = await fs
                .access(path.join(wasmOutDir, 'backend-bundle.js'))
                .then(() => true)
                .catch(() => false);
            if (!bundleExists) {
                throw new Error(
                    '[dokkebi] 기존 번들이 없습니다. --skip-backend-build 없이 빌드를 먼저 실행하세요.',
                );
            }
        }
        // 기존 해시 파일에서 읽기 (--skip-backend-build 시 재사용)
        try {
            bundleHash = (await fs.readFile(path.join(wasmOutDir, 'backend-bundle.sha256'), 'utf-8')).trim();
            if (bundleHash) bundleAssetName = `backend.bundle.${bundleHash.slice(0, 12)}.enc`;
        } catch { /* 해시 파일 없으면 무결성 검증 생략 */ }
        try {
            const chunksJson = await fs.readFile(path.join(wasmOutDir, 'backend-bundle.chunks.json'), 'utf-8');
            const parsed = JSON.parse(chunksJson);
            if (parsed && Array.isArray(parsed.hashes)) chunkManifest = parsed;
        } catch { /* 청크 매니페스트 없으면 attestation 비활성 */ }
        if (encryptSkip) {
            encryptedTextMode = true;
            bytecodeEncrypted = true;
        }
    }

    // ── Step 4b1: Query Registry 생성 (Stage 3) ─────────────
    //   1. @dokkebi-query 주석 (명시 선언)
    //   2. 정적 스캐너 (backend/**/*.{ts,js} 의 SQL 문자열 리터럴 자동 추출)
    //   3. .dokkebi/query-registry.learned.json (dev 런타임 학습)
    //   문서: docs/design/QUERY_REGISTRY.md
    //
    //   scan 결과의 opTableStats 는 뒤이은 policyInference 에 입력으로 전달됩니다.
    console.log('\n' + t('build.queryRegistryStep'));
    const queryRegistryEnabled = dokkebiConfig?.queryRegistry?.enabled !== false;
    const queryScanEnabled = dokkebiConfig?.queryRegistry?.scan !== false;
    const queryScanRoots = dokkebiConfig?.queryRegistry?.scanRoots;
    const queryScanVerbose = !!dokkebiConfig?.queryRegistry?.scanVerbose;
    let queryRegistry = null;
    let scanOpTableStats = null;
    if (queryRegistryEnabled) {
        const { registry, sources, opTableStats } = await buildRegistry(sourceRoot, {
            includeLearned: true,
            includeScan: queryScanEnabled,
            buildHash: bundleHash,
            scanRoots: queryScanRoots,
            verbose: queryScanVerbose,
        });
        scanOpTableStats = opTableStats;
        const registryJsonPath = path.join(wasmOutDir, 'query-registry.json');
        await writeRegistry(registry, registryJsonPath, { buildHash: bundleHash });
        const stats = registry.stats();
        const byOpStr = Object.entries(stats.byOp).map(([k, v]) => k + ':' + v).join(', ') || t('build.queryRegistryNone');
        console.log(t('build.queryRegistryStats', { total: stats.total, byOp: byOpStr }));
        console.log(t('build.queryRegistryDeclarative', { count: sources.declarative }));
        console.log(t('build.queryRegistryScanned', { count: sources.scanned, suffix: queryScanEnabled ? '' : t('build.queryRegistryScanDisabled') }));
        console.log(t('build.queryRegistryLearned', { count: sources.learned }));
        if (sources.dynamicSamples && sources.dynamicSamples.length > 0) {
            console.log(t('build.queryRegistryDynamic', { samples: sources.dynamicSamples.slice(0, 3).join(', ') }));
        }
        if (stats.total === 0) {
            console.warn(t('build.queryRegistryEmpty1'));
            console.warn(t('build.queryRegistryEmpty2'));
            console.warn(t('build.queryRegistryEmpty3'));
            console.warn(t('build.queryRegistryEmpty4'));
        }
        queryRegistry = registry.toJSON({ buildHash: bundleHash });
    } else {
        console.log(t('build.queryRegistryDisabled'));
    }

    // ── Step 4b2: Policy 자동 추론 (convention + SQL 스캔) ──
    //   dokkebi.config.js 의 policy / authorization 섹션이 비어있거나 일부만
    //   정의되어도, 모델 DSL (table(...)) + 컨트롤러 SQL 로부터 자동으로
    //   기본 규칙을 생성한다. 사용자 명시값은 **항상 우선** (override).
    //   문서: docs/design/POLICY_INFERENCE.md
    console.log('\n' + t('build.policyStep'));
    const policyAutoDisabled = dokkebiConfig?.policy?.infer === false
                            || dokkebiConfig?.authorization?.infer === false;
    let effectiveConfig = dokkebiConfig;
    let capabilityAnnotations = { capabilities: {} };
    capabilityAnnotations = await scanPolicyAnnotations(sourceRoot, { verbose: queryScanVerbose });
    if (policyAutoDisabled) {
        console.log(t('build.policyInferDisabled'));
    } else {
        const inferredRaw = await inferPolicyFromProject(sourceRoot, {
            opTableStats: scanOpTableStats,
            verbose: queryScanVerbose,
        });

        // ── JSDoc 어노테이션 (@dokkebi-policy / @dokkebi-tenant) 추출 후 병합 ──
        // DSL 옵션과 마찬가지로 사용자 명시 의도를 우선 적용. inferredRaw 의
        // convention 추론 결과를 덮어쓴다.
        const annotations = capabilityAnnotations;
        const inferred = mergeAnnotationsIntoInferred(inferredRaw, annotations);

        const detected = inferred.detectedTables.length;
        const shared = (inferred.sharedTables || []).length;
        const undetected = inferred.undetectedTables.length;
        console.log(t('build.policyScanResult', { scanned: inferred.scannedModelFiles, detected, shared, undetected }));
        if (annotations.scannedFiles > 0) {
            const ruleCount = Object.keys(annotations.rules || {}).length;
            const tenantCount = Object.keys(annotations.tenants || {}).length;
            const capCount = Object.keys(annotations.capabilities || {}).length;
            console.log(`[dokkebi]   ↳ JSDoc 어노테이션: ${annotations.scannedFiles}개 파일, 규칙 ${ruleCount}개 / 테넌트 ${tenantCount}개 / capability ${capCount}개`);
        }
        if (detected > 0) {
            console.log(t('build.policyTenantList', { tables: inferred.detectedTables.join(', ') }));
        }
        if (shared > 0) {
            console.log(t('build.policySharedList', { tables: inferred.sharedTables.join(', ') }));
        }
        for (const warn of inferred.warnings) console.warn(t('build.policyWarn', { msg: warn }));

        const merge = mergeInferredIntoConfig(dokkebiConfig || {}, inferred);
        effectiveConfig = merge.merged;

        if (merge.policyAdds.length > 0) {
            console.log(t('build.policyAutoApply', {
                count: merge.policyAdds.length,
                preview: merge.policyAdds.slice(0, 5).join(', '),
                ellipsis: merge.policyAdds.length > 5 ? '…' : '',
            }));
        } else if (merge.policyAutoSuggestions.length > 0) {
            console.log(t('build.policySuggestions', {
                count: merge.policyAutoSuggestions.length,
                preview: merge.policyAutoSuggestions.slice(0, 5).join(', '),
                ellipsis: merge.policyAutoSuggestions.length > 5 ? '…' : '',
            }));
            console.log(t('build.policyApplyHint'));
        }
        if (merge.authzAdds.length > 0) {
            console.log(t('build.authzAutoApply', { count: merge.authzAdds.length }));
        } else if (merge.authzAutoSuggestions.length > 0) {
            console.log(t('build.authzSuggestions', { count: merge.authzAutoSuggestions.length }));
            console.log(t('build.authzApplyHint'));
        }
        if (merge.policyAutoSuggestions.length === 0 && merge.authzAutoSuggestions.length === 0) {
            console.log(t('build.policyNoChange'));
        }
    }

    // ── Step 4b3: SQL Allowlist 자동 생성 ───────────────────
    //   dokkebi.config.js 의 policy 섹션이 있으면 v2 스키마로 자동 출력.
    //   문서: docs/design/TENANT_POLICY.md
    console.log('\n' + t('build.allowlistStep'));
    const policyMeta = normalizePolicyConfig(effectiveConfig?.policy);

    // ── Phase B-4: 샤딩 ↔ 정책 정합성 검증 ─────────────────────────
    //   샤딩 모드일 때 strategy.key 와 policy.tables[*].sessionClaim 이
    //   일치하는지 점검. 단일 D1 모드에서는 no-op.
    try {
        const { normalizeDatabaseConfig, verifyShardConsistency } = await import('../core/shardConfig.js');
        const _dbn = normalizeDatabaseConfig(effectiveConfig?.database);
        const { warnings: _shardWarn, errors: _shardErr } = verifyShardConsistency(
            _dbn,
            effectiveConfig?.policy,
            { strict: effectiveConfig?.policy?.strict === true }
        );
        for (const w of _shardWarn) console.warn(`[dokkebi] ⚠ shard-consistency: ${w}`);
        if (_shardErr.length) {
            for (const e of _shardErr) console.error(`[dokkebi] ✖ shard-consistency: ${e}`);
            throw new Error('shard consistency check failed (policy.strict=true)');
        }
    } catch (e) {
        if (e && /shard consistency check failed/.test(String(e.message || ''))) throw e;
    }

    const authzMeta = normalizeAuthorizationConfig(effectiveConfig?.authorization);
    const replayMeta = normalizeReplayConfig(effectiveConfig?.security);
    const webauthnMeta = normalizeWebAuthnConfig(effectiveConfig?.security);
    const adlMeta = normalizeActiveDefenseConfig(effectiveConfig?.security);
    const capabilityMeta = normalizeCapabilitiesConfig(effectiveConfig?.security, capabilityAnnotations);
    const panelIpGuardMeta = normalizePanelIpGuardConfig(effectiveConfig?.security);
    const allowlist = await extractAllowlist(sourceRoot, { policy: policyMeta });

    // ── Cost-Route Advisory ────────────────────────────────────
    //   외부 결제/AI 호출 같은 "비용 발생 라우트" 가 capability 미선언이면
    //   경고만 출력한다(자동 추가 금지). false positive 가능성이 있으므로
    //   `dokkebi.config.js` 의 `security.advisor.disable: true` 로 끌 수 있다.
    if (effectiveConfig?.security?.advisor?.disable !== true) {
        try {
            const findings = await _scanCostRoutes(backendDir);
            const uncovered = findings.filter(f => !_isRouteCovered(f.method, f.path, capabilityMeta));
            if (uncovered.length > 0) {
                console.warn('\n[dokkebi] ⚠ 비용/금전 행위가 감지된 라우트에 capability 가 선언되어 있지 않습니다');
                console.warn('[dokkebi]   (자동 추가하지 않습니다 — 운영 사고 방지를 위해 사용자가 직접 선언해야 합니다)');
                for (const f of uncovered.slice(0, 10)) {
                    console.warn(`[dokkebi]   • ${f.method} ${f.path}  (${f.file}:${f.line})  signals=[${f.signals.join(', ')}]`);
                }
                if (uncovered.length > 10) {
                    console.warn(`[dokkebi]   …외 ${uncovered.length - 10}건`);
                }
                console.warn('[dokkebi]   해결: dokkebi.config.js 의 security.capabilities.features 또는');
                console.warn('[dokkebi]         컨트롤러 위 @dokkebi-capability JSDoc 으로 feature/route 를 선언하세요.');
                console.warn('[dokkebi]   비활성화: security.advisor.disable: true\n');
            }
        } catch (e) {
            // advisor 실패는 빌드를 막지 않음.
        }
    }

    // Phase 1-③ — 빌드 메타데이터 수집 (git SHA, controllers hash, scanner version).
    // 공급망 공격 탐지용 tripwire. 관리자 패널에서 현재 배포된 번들이 어느
    // 소스 상태에서 빌드됐는지 확인 가능.
    const buildMeta = await collectBuildMeta(sourceRoot);
    // Phase 3-C — ADL 활성 시 룰셋 시그니처 추가 (공급망 tripwire 와 결합).
    if (adlMeta.enabled) {
        const sig = _adlRulesSignature();
        buildMeta.adlVersion = adlMeta.version;
        buildMeta.adlMode = adlMeta.mode;
        buildMeta.adlTrigger = adlMeta.trigger;
        buildMeta.adlRules = sig;
    }
    if (capabilityMeta.enabled) {
        buildMeta.capabilitiesVersion = capabilityMeta.version;
        buildMeta.capabilitiesFeatures = Object.keys(capabilityMeta.features || {}).sort();
    }
    if (panelIpGuardMeta.enabled) {
        buildMeta.panelIpGuard = true;
    }
    // Bundle Attestation — chunkManifest 가 있으면 buildMeta 에 첨부해 워커 임베드 흐름을 탄다.
    // attestation 사용 여부는 security.attestation.enabled 로 결정되며, 매니페스트 자체는
    // 항상 빌드되어 디스크에 남는다(추후 활성화 시 재빌드 없이 켤 수 있도록).
    // 자동 ON: capabilities 가 켜져 있고 attestation.enabled 를 명시 opt-out 하지 않았다면 자동 활성.
    const attestationMeta = normalizeAttestationConfig(effectiveConfig?.security, capabilityMeta);
    if (attestationMeta.enabled && attestationMeta.autoFromCapabilities) {
        console.log('[dokkebi] 🛡 Bundle Attestation: capabilities 활성에 따라 자동 ON (security.attestation.enabled: false 로 끌 수 있음)');
    }
    if (chunkManifest && attestationMeta.enabled) {
        buildMeta.attestation = {
            version: 1,
            chunkSize: chunkManifest.chunkSize,
            count: chunkManifest.count,
            totalBytes: chunkManifest.totalBytes,
            salt: chunkManifest.salt,
            // hashes 는 Worker 측 검증에서만 필요하므로 클라이언트로는 노출하지 않는다.
            hashes: chunkManifest.hashes,
            sampleSize: attestationMeta.sampleSize,
            ttlMs: attestationMeta.ttlMs,
        };
    }
    allowlist.buildMeta = buildMeta;
    if (queryRegistry) queryRegistry.buildMeta = buildMeta;

    const allowlistPath = path.join(wasmOutDir, 'sql-allowlist.json');
    await fs.writeFile(allowlistPath, JSON.stringify(allowlist, null, 2), 'utf-8');
    if (queryRegistry) {
        // buildMeta 가 추가됐으니 registry 도 다시 flush
        await fs.writeFile(path.join(wasmOutDir, 'query-registry.json'), JSON.stringify(queryRegistry, null, 2), 'utf-8');
    }
    console.log(t('build.buildSignature', { summary: _integritySummary(buildMeta) }));
    if (buildMeta.source_dirty) {
        console.warn(t('build.gitDirtyWarn'));
    }
    {
        const tableCount = allowlist.tables.filter(tbl => !tbl.name.startsWith('_dokkebi_') && tbl.name !== 'sqlite_master').length;
        console.log(t('build.allowlistTables', { count: tableCount, raw: allowlist.rawAllowed ? t('build.rawAllow') : t('build.rawDeny') }));
    }
    if (policyMeta?.enabled) {
        const declared = Object.keys(policyMeta.tables || {}).length;
        console.log(t('build.tenantPolicyOn', {
            mode: policyMeta.mode,
            count: declared,
            claim: policyMeta.claim,
            strict: policyMeta.strict ? t('build.switchOn') : t('build.switchOff'),
        }));
    } else {
        console.log(t('build.tenantPolicyOff'));
    }
    if (authzMeta?.enabled) {
        const specifics = authzMeta.rules.filter(r => r.op !== '*' || r.table !== '*').length;
        const wildcard = authzMeta.rules.find(r => r.op === '*' && r.table === '*');
        console.log(t('build.authzOn', {
            mode: authzMeta.mode,
            count: authzMeta.rules.length,
            specifics,
            defaultLabel: wildcard ? t('build.authzDefaultDefined') : t('build.authzDefaultNone'),
            claim: authzMeta.claim,
        }));
        if (!wildcard && authzMeta.mode === 'warn') {
            console.warn(t('build.authzWarnDefault1'));
            console.warn(t('build.authzWarnDefault2'));
        }
        if (authzMeta.mode === 'strict' && !wildcard) {
            console.warn(t('build.authzStrictDefault'));
        }
    } else {
        console.log(t('build.authzOff'));
    }

    if (adlMeta?.enabled) {
        const intMin = Math.round(adlMeta.intervalMs / 60000);
        console.log(t('build.adlOn', {
            mode: adlMeta.mode,
            trigger: adlMeta.trigger,
            interval: intMin,
            sample: (adlMeta.sampleRate * 100).toFixed(2),
        }));
        if (adlMeta.mode === 'monitor') {
            console.log(t('build.adlMonitor'));
        } else {
            console.log(t('build.adlEnforce', { threshold: adlMeta.riskBlockThreshold }));
        }
    } else {
        console.log(t('build.adlOff'));
    }

    if (capabilityMeta?.enabled) {
        const featureCount = Object.keys(capabilityMeta.features || {}).length;
        const routeCount = capabilityRuntimeGuards(capabilityMeta).routes.length;
        const secretName = capabilityMeta.secretEnv || 'DOKKEBI_CAPABILITY_SECRET';
        console.log(`[dokkebi]   Signed Unlock Token: on (${featureCount}개 feature, autoGuard ${routeCount}개 route, secret=${secretName})`);
        if (!envVars[secretName]) {
            const msg = `[dokkebi]   ${secretName} 환경변수가 없습니다. 배포 전 Pages Secret 또는 .env에 32바이트 이상 랜덤 값을 설정하세요.`;
            if (String(effectiveConfig?.security?.level || '').toLowerCase() === 'strict') {
                throw new Error(msg + '\n[dokkebi]   security.level: strict 에서는 capability secret 누락을 허용하지 않습니다.');
            }
            console.warn(msg);
        } else if (String(envVars[secretName]).length < 32) {
            console.warn(`[dokkebi]   ${secretName} 값이 짧습니다 (32자 이상 권장).`);
        }
    } else {
        console.log('[dokkebi]   Signed Unlock Token: off');
    }

    if (panelIpGuardMeta.enabled) {
        const panelIps = envVars.DOKKEBI_PANEL_ALLOWED_IPS || envVars.DOKKEBI_ADMIN_ALLOWED_IPS || process.env.DOKKEBI_PANEL_ALLOWED_IPS || process.env.DOKKEBI_ADMIN_ALLOWED_IPS || '';
        console.log('[dokkebi]   Panel IP Guard: on');
        if (!String(panelIps).trim()) {
            console.warn('[dokkebi]   security.panelIpGuard=true 이지만 DOKKEBI_PANEL_ALLOWED_IPS 가 비어 있습니다. 패널 IP 차단이 실질적으로 적용되지 않습니다.');
        }
    } else {
        console.log('[dokkebi]   Panel IP Guard: off');
    }

    if (webauthnMeta?.enabled) {
        console.log('\n[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log(t('build.webauthnHeader'));
        console.log('[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log(t('build.webauthnLine1'));
        console.log(t('build.webauthnLine2'));
        console.log(t('build.webauthnLine3'));
        console.log(t('build.webauthnLine4'));
        console.log(t('build.webauthnLine5'));
        const opts = [];
        if (webauthnMeta.rpName) opts.push(`rpName=${webauthnMeta.rpName}`);
        if (webauthnMeta.rpId) opts.push(`rpId=${webauthnMeta.rpId}`);
        opts.push(`uv=${webauthnMeta.userVerification}`);
        if (webauthnMeta.requireForOps) opts.push(`requireForOps=[${webauthnMeta.requireForOps.join(',')}]`);
        console.log(t('build.webauthnConfig', { opts: opts.join(', ') }));
        console.log('[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    }

    // ── Step 4c: (serverless) Pages Function 에 allowlist + registry 임베드 ──
    //   worker/api/_dokkebi/db.ts 를 방금 생성된 allowlist + registry 를
    //   포함한 버전으로 재생성해 프로덕션 검증 로직이 빌드 산출물과
    //   동일한 수명주기를 갖도록 보장합니다.
    if (proxyMode === 'serverless') {
        const flags = getHardeningFlags({ ...process.env, ...envVars });
        const bid = (bundleHash && String(bundleHash).slice(0, 16)) || '0000000000000000';
        wireRuntimeJson = buildWireRuntimeJson(flags, rotationPreviousState, bid);

        const wireTsPath = path.join(sourceRoot, 'worker', 'api', '_dokkebi', '_payloadWire.ts');
        try {
            await fs.mkdir(path.dirname(wireTsPath), { recursive: true });
            await fs.writeFile(wireTsPath, emitPayloadWireTs(wireRuntimeJson), 'utf-8');
        } catch (e) {
            console.warn('[dokkebi] ⚠ _payloadWire.ts write failed:', e?.message || e);
        }

        try {
            await fs.mkdir(wasmOutDir, { recursive: true });
            await fs.writeFile(path.join(wasmOutDir, 'wire-runtime.json'), JSON.stringify(wireRuntimeJson), 'utf-8');
        } catch (e) {
            console.warn('[dokkebi] ⚠ wire-runtime.json write failed:', e?.message || e);
        }

        try {
            const dokDir = path.join(sourceRoot, '.dokkebi');
            await fs.mkdir(dokDir, { recursive: true });
            if (wireRuntimeJson.rotation?.enabled) {
                const stateSnap = {
                    enabled: true,
                    activeForward: wireRuntimeJson.rotation.activeForward,
                    buildId: wireRuntimeJson.rotation.buildId,
                };
                await fs.writeFile(path.join(dokDir, 'rotation-state.json'), JSON.stringify(stateSnap), 'utf-8');
                let hist = [];
                try {
                    const raw = JSON.parse(await fs.readFile(path.join(dokDir, 'rotation-history.json'), 'utf-8'));
                    if (Array.isArray(raw.forwards)) hist = raw.forwards;
                } catch { /* empty */ }
                hist.push({ ...stateSnap, savedAt: new Date().toISOString() });
                const seen = new Set();
                hist = hist.filter((e) => {
                    const k = JSON.stringify(e.activeForward || {});
                    if (seen.has(k)) return false;
                    seen.add(k);
                    return true;
                }).slice(-5);
                await fs.writeFile(path.join(dokDir, 'rotation-history.json'), JSON.stringify({ forwards: hist }, null, 2), 'utf-8');
            } else {
                await fs.writeFile(path.join(dokDir, 'rotation-state.json'), JSON.stringify({ enabled: false }), 'utf-8');
            }
        } catch { /* ignore */ }

        console.log(`[dokkebi]   payload wire: rotation=${wireRuntimeJson.rotation?.enabled ? 'on' : 'off'}, pow=${wireRuntimeJson.pow?.enabled ? 'on' : 'off'}`);

        const workerDbPath = path.join(sourceRoot, 'worker', 'api', '_dokkebi', 'db.ts');
        try {
            await fs.access(workerDbPath);
            // Phase B-3: D1 Sessions opt-in (database.sessions: true | { mode })
            const _rawSess = dokkebiConfig?.database?.sessions;
            const sessionsMeta =
                _rawSess === true
                    ? { enabled: true, mode: 'first-unconstrained' }
                    : (_rawSess && typeof _rawSess === 'object'
                        ? { enabled: _rawSess.enabled !== false, mode: _rawSess.mode === 'first-primary' ? 'first-primary' : 'first-unconstrained' }
                        : { enabled: false, mode: 'first-unconstrained' });
            const nextSource = workerDb(dbType, allowlist, queryRegistry, policyMeta, authzMeta, replayMeta, buildMeta, adlMeta, capabilityMeta, sessionsMeta);
            await fs.writeFile(workerDbPath, nextSource, 'utf-8');
            const parts = ['allowlist'];
            if (queryRegistry) parts.push('query-registry');
            if (policyMeta?.enabled) parts.push('tenant-policy');
            if (authzMeta?.enabled) parts.push('authorization');
            if (capabilityMeta?.enabled) parts.push('capabilities');
            parts.push(`replay(window=${replayMeta.timestampWindowMs}ms, nonce=${replayMeta.nonceTtlMs}ms)`);
            if (adlMeta?.enabled) parts.push(`adl(${adlMeta.mode}, ${adlMeta.trigger}, ${Math.round(adlMeta.intervalMs/60000)}m)`);
            console.log(t('build.workerDbEmbed', { parts: parts.join(' + ') }));
        } catch {
            console.warn(t('build.workerDbMissing1'));
            console.warn(t('build.workerDbMissing2'));
        }

        const workerHsPath = path.join(sourceRoot, 'worker', 'api', '_dokkebi', 'handshake.ts');
        try {
            await fs.access(workerHsPath);
            await fs.writeFile(workerHsPath, workerHandshake(), 'utf-8');
            console.log('[dokkebi] handshake.ts 재생성 완료');
        } catch { /* handshake.ts 미존재 → 무시 */ }

        const rootMwPath = path.join(sourceRoot, 'worker', '_middleware.ts');
        try {
            await fs.writeFile(rootMwPath, workerRootMiddleware(dbType), 'utf-8');
            console.log('[dokkebi] _middleware.ts (루트 ADL 차단) 생성 완료');
        } catch { /* 루트 미들웨어 생성 실패 → 무시 */ }

        // Phase 2-⑧ · Phase 3-C — 관제 어드민 워커에도 보안 커버리지 요약 embed
        const _strictCspCfg = dokkebiConfig?.security?.strictCsp === true;
        const coverage = computeSecurityCoverage({
            policyMeta, authzMeta, webauthnMeta, replayMeta, buildMeta,
            strictCsp: _strictCspCfg, adlMeta, capabilityMeta,
            attestationMeta, panelIpGuardMeta,
            bytecodeMode, bytecodeEncrypted, encryptedTextMode,
            zeroDowntimeReady: !!bundleAssetName, // 해시 박힌 번들 + BC_KEY_MAP 적용 시 자동 ON
        });
        const securitySummary = {
            coverage,
            buildMeta,
            replay: replayMeta,
            strictCsp: _strictCspCfg,
            policy: policyMeta?.enabled ? { enabled: true, mode: policyMeta.mode, strict: !!policyMeta.strict, tables: Object.keys(policyMeta.tables || {}).length } : { enabled: false },
            authorization: authzMeta?.enabled ? { enabled: true, mode: authzMeta.mode, rules: (authzMeta.rules || []).length } : { enabled: false },
            webauthn: webauthnMeta?.enabled ? { enabled: true, userVerification: webauthnMeta.userVerification } : { enabled: false },
            panelIpGuard: panelIpGuardMeta.enabled ? { enabled: true } : { enabled: false },
            attestation: attestationMeta?.enabled ? {
                enabled: true,
                sampleSize: attestationMeta.sampleSize,
                ttlMs: attestationMeta.ttlMs,
                autoFromCapabilities: !!attestationMeta.autoFromCapabilities,
            } : { enabled: false },
            zeroDowntime: bundleAssetName ? {
                enabled: true,
                bundleAssetName,
                bcKeyMapKeys: (() => {
                    try {
                        const map = envSecrets?.__DOKKEBI_BC_KEY_MAP__;
                        if (typeof map === 'string' && map) return Object.keys(JSON.parse(map)).length;
                    } catch { /* ignore */ }
                    return 1;
                })(),
            } : { enabled: false },
            capabilities: capabilityMeta?.enabled ? {
                enabled: true,
                features: Object.keys(capabilityMeta.features || {}).length,
                defaultTtlMs: capabilityMeta.defaultTtlMs,
                secretEnv: capabilityMeta.secretEnv,
                hasChain: Object.values(capabilityMeta.features || {}).some((s) => Array.isArray(s?.requires?.prev) && s.requires.prev.length > 0),
            } : { enabled: false },
            activeDefense: adlMeta?.enabled ? {
                enabled: true,
                mode: adlMeta.mode,
                trigger: adlMeta.trigger,
                intervalMs: adlMeta.intervalMs,
                sampleRate: adlMeta.sampleRate,
                riskBlockThreshold: adlMeta.riskBlockThreshold,
                useWorkersAI: !!adlMeta.useWorkersAI,
                rules: buildMeta.adlRules || null,
            } : { enabled: false },
        };
        const adminPanelPath = path.join(sourceRoot, 'worker', 'api', '_dokkebi', '_panel.ts');
        const adminApiPath = path.join(sourceRoot, 'worker', 'api', '_dokkebi', '_panel', '[[path]].ts');
        try {
            await fs.access(adminPanelPath);
            await fs.writeFile(adminPanelPath, workerAdmin(path.basename(sourceRoot), securitySummary, panelIpGuardMeta), 'utf-8');
        } catch { /* 관제 미설정 */ }
        try {
            await fs.access(adminApiPath);
            await fs.writeFile(adminApiPath, workerAdminApi(path.basename(sourceRoot), securitySummary, panelIpGuardMeta), 'utf-8');
        } catch { /* 관제 미설정 */ }
        console.log(t('build.securityCoverage', {
            score: coverage.score,
            level: coverage.level,
            enabled: Object.entries(coverage.enabled).filter(([, v]) => v).length,
            total: Object.keys(coverage.enabled).length,
        }));
        if (coverage.recommendations.length > 0) {
            for (const r of coverage.recommendations.slice(0, 3)) {
                console.log(t('build.securityRecommend', { msg: r }));
            }
        }
    }

    // ── 로컬 DB 모드 감지 ──────────────────────────────────
    const _hasCreds = !!(
        (dbType === 'd1' && dbConfig.accountId && dbConfig.databaseId && dbConfig.apiToken) ||
        (dbType === 'supabase' && dbConfig.supabaseUrl && dbConfig.anonKey) ||
        (dbType === 'appwrite' && dbConfig.endpoint && dbConfig.projectId && dbConfig.apiKey)
    );
    const localDbMode = !_hasCreds;
    let migrationSql = '';
    if (localDbMode) {
        try {
            const migrationPath = path.join(sourceRoot, 'backend', 'db', 'migrations', '001_initial.sql');
            migrationSql = await fs.readFile(migrationPath, 'utf-8');
            console.log(t('build.localDbMode'));
        } catch {
            console.warn(t('build.noMigrationFiles'));
        }
    }

    // ── 빌드 버전 생성 (프론트엔드 업데이트 감지용) ─────────
    const buildVer = createHash('sha256')
        .update(Date.now().toString() + Math.random().toString() + (bundleHash || ''))
        .digest('hex')
        .slice(0, 12);

    // ── 플러그인 로딩 ────────────────────────────────────
    const plugins = await loadPlugins(sourceRoot);
    let pluginHostCode = '';
    let pluginVmBridge = '';
    if (plugins.length > 0) {
        console.log('\n' + t('build.pluginsLoaded', { count: plugins.length, names: plugins.map(p => p.name).join(', ') }));
        const pluginCode = generatePluginBootstrapCode(plugins, envVars);
        pluginHostCode = pluginCode.hostImplementations;
        pluginVmBridge = pluginCode.vmBindings;
    }

    // ── Step 5: Opaque Handle 부트스트랩 HTML 주입 ─────────
    //   queryLearn:
    //     - 기본(auto 모드): true — 클라이언트가 queryId + _debugSql 모두 전송.
    //       서버는 queryId 로 매칭되면 우선 사용, 미등록이면 _debugSql 로 fallback.
    //       → 학습 누락/shape 차이에도 첫 요청이 성공하며 불필요한 403 제거.
    //     - strict 모드(opt-in): false — _debugSql 제외. 서버는 미등록 쿼리 차단.
    //       SQL 문자열이 네트워크에 노출되지 않음 (암호화 채널 안이지만 방어 깊이↑).
    //       활성화: dokkebi.config.js 에 queryRegistry.strict: true
    const queryStrict = !!(dokkebiConfig?.queryRegistry?.strict);
    const queryLearnClient = !queryStrict;
    if (queryStrict) {
        console.log(t('build.queryRegistryStrict'));
    } else {
        console.log(t('build.queryRegistryAuto'));
    }

    // ── Step 4d: SEO 자동 파이프라인 (zero-config) ─────────
    //   라우터 AST 스캔 → 페이지 메타 추론 → 정적 prerender → sitemap/robots → 리포트.
    //   동적 라우트 D1 enumerate 와 Edge SEO Renderer 는 후속 PR 에서 추가.
    //   실패는 빌드를 막지 않는다(경고만) — SEO 는 부가기능이므로 안전 우선.
    try {
        const seoResult = await runSeoPipeline({
            sourceRoot,
            frontendDir,
            outDir,
            dokkebiConfig: effectiveConfig,
            dbConfig,        // PR2: D1 enumerate 자격
            authzMeta,       // PR2: authorization policy 존중
            verbose: !!options.verbose,
        });
        if (seoResult && seoResult.enabled) {
            const s = seoResult.summary || {};
            const routerOk = seoResult.scanned?.sourceFiles?.length > 0;
            if ((s.routes || 0) === 0) {
                console.log(`\n[dokkebi] 🔍 SEO: 라우터를 감지하지 못했습니다 (스캔 파일 ${seoResult.scanned?.scannedFiles || 0}개)`);
                console.log(`[dokkebi]   react-router-dom 미사용이거나 동적 path 패턴이면, dokkebi.config.js 의 seo.routes 에 페이지를 직접 선언하세요.`);
                if (seoResult.reportPath) {
                    console.log(`[dokkebi]   ↳ 가이드: ${path.relative(sourceRoot, seoResult.reportPath)}`);
                }
            } else {
                const dynPart = s.dynamicSourceRoutes
                    ? `, dynamic ${s.dynamicExpanded || 0}/${s.dynamicSourceRoutes} 라우트 enumerate` +
                      (s.d1Available ? '' : ' (D1 자격 없음 — 스킵)')
                    : '';
                console.log(`\n[dokkebi] 🔍 SEO: routes=${s.routes || 0}, prerender=${s.prerendered || 0}, sitemap=${s.sitemapUrls || 0}URL` +
                    dynPart +
                    (s.lowConfidence ? `, ⚠ 확인필요=${s.lowConfidence}` : ''));
                if (s.edgeRendererEmitted > 0) {
                    console.log(`[dokkebi]   ↳ Edge SEO Renderer: functions/_middleware.js + functions/_dokkebi-seo.js (봇 UA → D1 lookup → KV 캐시)`);
                    console.log(`[dokkebi]      ⚠ Cloudflare Pages 설정 필요: env.DB (D1 binding) ${seoResult.edgeRenderer?.skipped ? '' : '· env.SEO_CACHE (KV binding, 선택)'}`);
                } else if (seoResult.edgeRenderer?.skipped) {
                    console.log(`[dokkebi]   ↳ Edge SEO Renderer: skipped (${seoResult.edgeRenderer.reason})`);
                }
                if (seoResult.reportPath) {
                    console.log(`[dokkebi]   ↳ 리포트: ${path.relative(sourceRoot, seoResult.reportPath)}`);
                }
            }
        } else if (seoResult && seoResult.enabled === false) {
            console.log('[dokkebi] 🔍 SEO: 비활성화됨 (seo.enabled: false)');
        }
    } catch (e) {
        console.warn('[dokkebi] ⚠ SEO 파이프라인 실패 (빌드는 계속):', e?.message || e);
    }

    console.log('\n' + t('build.step5'));
    // Caller Guard: dist 의 frontend 청크들을 allowlist 로 수집
    const callerCheckMode = dokkebiConfig?.security?.callerCheck || 'off';
    let callerAllowedScripts = [];
    if (callerCheckMode !== 'off') {
        try {
            callerAllowedScripts = await collectCallerAllowedScripts(outDir);
            console.log(`[dokkebi]   🛡 Caller Guard: ${callerCheckMode} 모드 — 허용 청크 ${callerAllowedScripts.length}개`);
        } catch (e) {
            console.warn('[dokkebi]   Caller Guard allowlist 수집 실패:', e.message);
        }
    }
    const htmlCount = await injectBootstrapAll(outDir, {
        dbType,
        dbConfig,
        bundleHash,
        bundleAssetName,
        localDbMode,
        migrationSql,
        buildVer,
        pluginHostCode,
        pluginVmBridge,
        queryLearn: queryLearnClient,
        capabilityGuards: capabilityRuntimeGuards(capabilityMeta),
        bytecodeMode: bytecodeMode || false,
        bytecodeEncrypted: bytecodeEncrypted || false,
        encryptedTextMode: encryptedTextMode || false,
        logging: dokkebiConfig?.logging,
        authSession: normalizeAuthSessionForBootstrap(dokkebiConfig?.security?.authSession),
        callerCheck: callerCheckMode,
        allowedScripts: callerAllowedScripts,
        callerCheckAuditUrl: dokkebiConfig?.security?.callerCheckAuditUrl,
        ...(proxyMode === 'serverless' ? { payloadWireClient: wireRuntimeJson } : {}),
    }).catch((e) => {
        console.warn(t('build.htmlInjectWarn'), e.message);
        return 0;
    });

    console.log(t('build.htmlInjected', { count: htmlCount }));

    // build-version.json 출력
    await fs.writeFile(
        path.join(outDir, 'build-version.json'),
        JSON.stringify({ v: buildVer, t: new Date().toISOString() }),
    );
    console.log(t('build.buildVersion', { ver: buildVer }));

    // ── Step 5b: 서버리스 모드 — Worker 함수 번들 + .dev.vars 생성 ──
    let functionsDir = null;
    if (proxyMode === 'serverless') {
        console.log('\n' + t('build.step6Functions'));
        const workerDir = path.join(sourceRoot, 'worker');
        functionsDir = path.join(sourceRoot, 'functions');
        const workerBuilt = await buildWorkerFunctions(workerDir, functionsDir);
        if (workerBuilt) {
            console.log(t('build.step6FunctionsDone'), functionsDir);
        } else {
            console.warn(t('build.step6FunctionsNoWorker'));
        }

        await ensureDevVars(sourceRoot);
    }

    const canRunMigrations =
        dbType === 'd1'
            ? !!(dbConfig.accountId && dbConfig.databaseId && dbConfig.apiToken)
            : false;

    if (!options.skipMigration) {
        if (canRunMigrations) {
            console.log('\n' + t('build.migrationStart'));
            await runMigrations(backendDir, dbType, dbConfig);
        } else {
            console.log(t('build.migrationSkip'));
        }
    }

    console.log('\n[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    // ── 빌드 메타 외부 노출 차단 — dist/dokkebi/*.json 비우기 ───────────────
    // worker/db.ts 안에 SQL/policy/wire 메타가 모두 인라인 임베드되어 클라이언트는
    // *.json 을 fetch 하지 않는다. 그러나 Cloudflare Pages 정적 자산 fallback 으로
    // 누구나 GET 가능했으므로 (SQL 평문/컬럼명/번들 chunk 메타 노출), `{}` 로 비운다.
    // 통과: backend.bundle.*.enc · *.wasm · dokkebi-webcontainer-bootstrap.js.
    try {
        const r = await purgeBuildArtifactsFromDist(outDir);
        if (r.purged.length > 0) {
            console.log(`[dokkebi]   🧹 빌드 메타 비우기: ${r.purged.length}개 파일 (${r.purged.slice(0, 3).join(', ')}${r.purged.length > 3 ? '…' : ''})`);
        }
    } catch (e) {
        console.warn('[dokkebi] ⚠ 빌드 메타 비우기 실패:', e?.message || e);
    }

    // ── 시크릿 누출 스캔 (dok deploy / strict 일 때만 실행, 실패 대신 말미 경고) ──
    // .env 값이 dist/ 정적 자산 또는 백엔드 평문 번들에 포함된 것으로 보이면 안내한다.
    let secretLeakWarning = '';
    try {
        const enforceLeakScan =
            options.forDeploy === true
            || String(dokkebiConfig?.security?.level || '').toLowerCase() === 'strict';
        if (enforceLeakScan && envSecrets && Object.keys(envSecrets).length > 0) {
            const userSkipRaw = envSecrets.DOKKEBI_SECRET_SCAN_SKIP || process.env.DOKKEBI_SECRET_SCAN_SKIP || '';
            const userSkipKeys = new Set(
                String(userSkipRaw).split(',').map((s) => s.trim()).filter(Boolean),
            );
            const leaks = await scanForSecretLeaks(outDir, envSecrets, wasmOutDir, userSkipKeys);
            if (leaks.length > 0) {
                const lines = leaks.map(
                    (l) => `   • ${l.key}  →  ${path.relative(sourceRoot, l.file)}${l.snippet ? `  (…${l.snippet}…)` : ''}`,
                );
                secretLeakWarning =
                    '[dokkebi] ⚠ 시크릿 누출 가능: .env 값이 빌드 산출물에 평문으로 들어간 것으로 감지되었습니다. (배포는 계속됩니다)\n'
                    + lines.join('\n')
                    + '\n[dokkebi]   해당 값들을 백엔드 WASM 의 process.env.X 로 직접 사용하지 말고 Worker-side(worker/api/...) 로 옮기거나,\n'
                    + '[dokkebi]   프론트엔드에서 사용 중이라면 .env 가 아닌 일반 빌드 변수로 분리하세요.';
            } else {
                console.log('[dokkebi]   🛡  시크릿 누출 스캔 통과 (dist + WASM).');
            }
        }
    } catch (e) {
        console.warn('[dokkebi] ⚠ 시크릿 누출 스캐너 오류:', e?.message || e);
    }

    console.log(t('build.complete'));
    console.log(t('build.outDir', { outDir }));
    if (proxyMode === 'serverless') {
        console.log(t('build.completeFunctions', { dir: functionsDir }));
        console.log(t('build.completeDeployHint'));
        console.log(t('build.completeLocalHint'));
    } else {
        console.log(t('build.completeServeHint'));
    }
    if (secretLeakWarning) {
        console.warn('\n' + secretLeakWarning + '\n');
    }
    console.log('[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    return { outDir, wasmOutDir, dbType, htmlCount, proxyMode, functionsDir };
}

// ─────────────────────────────────────────────────────────────
// 헬퍼
// ─────────────────────────────────────────────────────────────

/**
 * 빌드 산출물에 .env Secret 값이 평문 포함되어 있는지 스캔한다.
 *
 *  - dist/ 아래의 텍스트 자산(.js / .mjs / .cjs / .css / .html / .map / .json / .txt) 검사
 *  - wasmOutDir 아래의 백엔드 번들(backend-bundle.js / .bundle.enc 가 아닌 평문)도 검사
 *  - .dokkebi/env-secrets.json 처럼 의도된 보관 파일은 dist 밖이라 자동 제외
 *
 * 검사 대상에서 자동 제외(low-entropy 값 — 공개되도 무해):
 *  - 길이 < 12
 *  - true/false/숫자/단순 식별자 (영문 소문자/숫자/하이픈만, 예: "admin", "dokkebi-blog", "ko")
 *  - URL 경로 (`/admin`)
 *  - Shannon entropy < 3.0 (영문 단어 수준)
 *
 * 사용자가 강제로 검사에서 빼고 싶은 키는 .env 에 `DOKKEBI_SECRET_SCAN_SKIP="KEY1,KEY2"` 로 지정 가능.
 *
 *  반환: [{ key, file, snippet }]  ← 발견된 모든 누출 항목
 */
function shannonEntropy(s) {
    if (!s) return 0;
    const freq = new Map();
    for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
    let h = 0;
    for (const c of freq.values()) {
        const p = c / s.length;
        h -= p * Math.log2(p);
    }
    return h;
}

/**
 * 키 이름에 PASSWORD / TOKEN / KEY / SECRET / PRIVATE / CREDENTIAL 이 포함되면
 * 절대 휴리스틱으로 우회하지 않고 무조건 검사한다. (값이 짧거나 단순 식별자라도)
 */
function isAlwaysSensitiveKey(key) {
    return /SECRET|TOKEN|PASSWORD|PRIVATE|CREDENTIAL|API[_-]?KEY|ACCESS[_-]?KEY|AUTH/i.test(key);
}

function isLowEntropyOrCommon(val) {
    // 매우 짧은 값(8자 미만) — 패스워드/토큰으로는 너무 짧음
    if (val.length < 8) return true;
    if (/^(true|false|null|undefined|\d+)$/i.test(val)) return true;
    // 짧은 단순 식별자(영문 소문자/숫자/-_/만, 18자 이내): "admin", "dokkebi-blog", "ko" 등 공개 식별자
    if (val.length <= 18 && /^[a-z0-9_\-/]+$/i.test(val)) return true;
    // 짧은 IP 주소 (xxx.xxx.xxx.xxx) 단일 IP — 공개적으로 광고되는 값이라 누출 의미 약함
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(val)) return true;
    // 엔트로피가 매우 낮음 (한 글자만 반복 등)
    if (shannonEntropy(val) < 2.0) return true;
    return false;
}

async function scanForSecretLeaks(distDir, envSecrets, wasmOutDir, userSkipKeys = new Set()) {
    const TEXT_EXTS = new Set(['.js', '.mjs', '.cjs', '.css', '.html', '.htm', '.map', '.json', '.txt', '.svg', '.xml']);
    const MAX_BYTES = 20 * 1024 * 1024; // 20MB 초과 파일은 스킵 (성능)
    const leaks = [];

    // 검사할 값들 — false-positive 방지 휴리스틱
    const targets = [];
    const skippedLowEntropy = [];
    for (const [key, rawVal] of Object.entries(envSecrets || {})) {
        const val = String(rawVal ?? '').trim();
        if (!val) continue;
        // dokkebi 내부 키(번들 복호화 키 등)는 의도적으로 클라이언트에 핸드셰이크로 전달되므로 검사 제외.
        if (key.startsWith('__DOKKEBI_')) continue;
        if (userSkipKeys.has(key)) continue;
        // 키 이름이 PASSWORD/TOKEN/KEY/SECRET 등 명백한 비밀이면 휴리스틱 우회 금지.
        if (!isAlwaysSensitiveKey(key) && isLowEntropyOrCommon(val)) {
            skippedLowEntropy.push(key);
            continue;
        }
        // JWT_SECRET 류는 핸드셰이크 화이트리스트라 클라이언트(WASM)에 전달되지만, dist 정적 자산에는 절대
        // 들어가면 안 된다 — 그대로 검사한다.
        targets.push({ key, val });
    }
    if (skippedLowEntropy.length > 0) {
        console.log(`[dokkebi]   ℹ 스캔 제외(low-entropy/식별자): ${skippedLowEntropy.join(', ')}`);
    }
    if (targets.length === 0) return leaks;

    async function* walk(root) {
        let entries = [];
        try {
            entries = await fs.readdir(root, { withFileTypes: true });
        } catch {
            return;
        }
        for (const ent of entries) {
            const full = path.join(root, ent.name);
            if (ent.isDirectory()) {
                yield* walk(full);
            } else if (ent.isFile()) {
                yield full;
            }
        }
    }

    async function scanFile(file) {
        const ext = path.extname(file).toLowerCase();
        // 백엔드 암호화 번들(.enc) / wasm 바이너리 / 이미지 등은 텍스트 검사 의미 없음.
        if (!TEXT_EXTS.has(ext)) return;
        let stat;
        try { stat = await fs.stat(file); } catch { return; }
        if (stat.size > MAX_BYTES) return;
        let content;
        try { content = await fs.readFile(file, 'utf-8'); } catch { return; }
        for (const { key, val } of targets) {
            const idx = content.indexOf(val);
            if (idx >= 0) {
                const start = Math.max(0, idx - 12);
                const end = Math.min(content.length, idx + val.length + 12);
                const snippet = content.slice(start, end).replace(/\s+/g, ' ');
                leaks.push({ key, file, snippet });
            }
        }
    }

    const roots = [];
    if (distDir) roots.push(distDir);
    if (wasmOutDir && wasmOutDir !== distDir) roots.push(wasmOutDir);
    for (const root of roots) {
        for await (const f of walk(root)) {
            await scanFile(f);
            if (leaks.length > 50) return leaks; // 안전 차단
        }
    }
    return leaks;
}

/** .env 파일 파싱 — KEY=VALUE 형식 */
async function loadEnvFile(sourceRoot) {
    const envPath = path.join(sourceRoot, '.env');
    try {
        const content = await fs.readFile(envPath, 'utf-8');
        const vars = {};
        for (const line of content.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            const eqIdx = trimmed.indexOf('=');
            if (eqIdx === -1) continue;
            const key = trimmed.slice(0, eqIdx).trim();
            const val = trimmed.slice(eqIdx + 1).trim().replace(/^['"]|['"]$/g, '');
            vars[key] = val;
        }
        return vars;
    } catch {
        return {};
    }
}

/**
 * DB 설정값의 ${ENV_VAR} 플레이스홀더를 실제 환경변수 값으로 치환
 * 우선순위: process.env > .env 파일 > 설정 파일 값
 */
function resolveDbConfig(config, envVars) {
    const env = { ...envVars, ...process.env };

    function resolve(val) {
        if (typeof val !== 'string') return val;
        // ${VAR} 또는 process.env.VAR || '' 형태 처리
        return val.replace(/\$\{([^}]+)\}/g, (_, k) => env[k] || '');
    }

    const resolved = {};
    for (const [k, v] of Object.entries(config)) {
        resolved[k] = resolve(v);
    }

    // D1 shortcut: env 변수에서 직접 읽기
    if (config.type === 'd1') {
        resolved.accountId  = resolved.accountId  || env.D1_ACCOUNT_ID  || '';
        resolved.databaseId = resolved.databaseId || env.D1_DATABASE_ID || '';
        resolved.apiToken   = resolved.apiToken   || env.D1_API_TOKEN   || '';
        resolved.apiBase    = resolved.apiBase    || 'https://api.cloudflare.com/client/v4';
    }
    if (config.type === 'supabase') {
        resolved.supabaseUrl = resolved.supabaseUrl || env.SUPABASE_URL      || '';
        resolved.anonKey     = resolved.anonKey     || env.SUPABASE_ANON_KEY || '';
        resolved.serviceKey  = resolved.serviceKey  || env.SUPABASE_SERVICE_KEY || '';
    }
    if (config.type === 'appwrite') {
        resolved.endpoint   = resolved.endpoint   || env.APPWRITE_ENDPOINT   || '';
        resolved.projectId  = resolved.projectId  || env.APPWRITE_PROJECT_ID || '';
        resolved.apiKey     = resolved.apiKey     || env.APPWRITE_API_KEY    || '';
        resolved.databaseId = resolved.databaseId || env.APPWRITE_DATABASE_ID || '';
    }

    return resolved;
}

/**
 * wrangler pages dev 로컬 테스트를 위한 .dev.vars 자동 생성
 * DOKKEBI_SERVER_JWK, DOKKEBI_SESSION_SECRET + .env 의 모든 변수를 포함합니다.
 * VITE_* 접두사는 빌드 시 인라인되므로 제외합니다.
 * .dev.vars 는 .gitignore에 자동 추가됩니다.
 */
async function ensureDevVars(sourceRoot) {
    const devVarsPath = path.join(sourceRoot, '.dev.vars');
    const secretsPath = path.join(sourceRoot, '.dokkebi-secrets.json');

    let secrets;

    // .dokkebi-secrets.json이 있으면 재사용
    try {
        secrets = JSON.parse(await fs.readFile(secretsPath, 'utf-8'));
    } catch {
        console.log(t('build.secretCreating'));
        const { webcrypto } = await import('crypto');
        const { subtle } = webcrypto;

        const keyPair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );
        const privateJwk = await subtle.exportKey('jwk', keyPair.privateKey);
        const sessionSecretBytes = webcrypto.getRandomValues(new Uint8Array(32));

        secrets = {
            DOKKEBI_SERVER_JWK: JSON.stringify(privateJwk),
            DOKKEBI_SESSION_SECRET: Buffer.from(sessionSecretBytes).toString('hex'),
        };

        await fs.writeFile(secretsPath, JSON.stringify(secrets, null, 2), 'utf-8');
    }

    // .env 변수 로드 후 VITE_* 제외, secrets와 병합
    const envVars = await loadEnvFile(sourceRoot).catch(() => ({}));
    const SKIP_PREFIXES = ['VITE_'];
    const envForWorker = {};
    for (const [k, v] of Object.entries(envVars)) {
        if (v && !SKIP_PREFIXES.some(p => k.startsWith(p))) {
            envForWorker[k] = v;
        }
    }

    const merged = { ...envForWorker, ...secrets };

    // .dev.vars 작성 (매 빌드마다 .env 변경사항 반영)
    const devVarsContent = Object.entries(merged)
        .map(([k, v]) => `${k}=${v}`)
        .join('\n') + '\n';
    await fs.writeFile(devVarsPath, devVarsContent, 'utf-8');

    const envCount = Object.keys(envForWorker).length;
    console.log(t('build.devVarsCreated', { count: envCount }));

    // .gitignore에 추가
    try {
        const gitignorePath = path.join(sourceRoot, '.gitignore');
        let content = '';
        try { content = await fs.readFile(gitignorePath, 'utf-8'); } catch {}
        const toAdd = ['.dev.vars', '.dokkebi-secrets.json'].filter(e => !content.includes(e));
        if (toAdd.length > 0) {
            await fs.appendFile(gitignorePath, '\n' + toAdd.join('\n') + '\n');
        }
    } catch { /* 무시 */ }
}

/**
 * worker/ 디렉토리의 TypeScript 파일을 esbuild로 컴파일 → functions/ 출력
 * Cloudflare Pages가 functions/ 디렉토리를 자동으로 인식합니다.
 */
async function buildWorkerFunctions(workerDir, functionsDir) {
    try {
        await fs.access(workerDir);
    } catch {
        return false;
    }

    // worker/ 내 모든 .ts 파일 수집
    const tsFiles = await findTsFiles(workerDir);
    if (tsFiles.length === 0) return false;

    const { build } = await import('esbuild');
    await build({
        entryPoints: tsFiles,
        bundle: true,
        format: 'esm',
        outbase: workerDir,
        outdir: functionsDir,
        target: 'es2022',
        platform: 'neutral',
        charset: 'utf8',
        // D1Database 등 Cloudflare 타입은 런타임이 제공하므로 external 처리 불필요
        // TypeScript 타입만이므로 esbuild가 알아서 제거합니다
        // 주의: template literal 내 regex에서 \/ 는 esbuild가 / 로 정규화하므로
        //       worker TS 소스에서는 /[/]+$/ 형태로 작성해야 합니다
    });
    return true;
}

async function findTsFiles(dir) {
    const results = [];
    let entries;
    try {
        entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
        return results;
    }
    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            results.push(...await findTsFiles(fullPath));
        } else if (entry.name.endsWith('.ts')) {
            results.push(fullPath);
        }
    }
    return results;
}

async function runMigrations(backendDir, dbType, dbConfig) {
    if (dbType !== 'd1') {
        console.log(t('build.migrationOnlyD1'));
        return;
    }
    const migrationsDir = path.join(backendDir, 'db', 'migrations');
    try {
        await fs.access(migrationsDir);
    } catch {
        console.log(t('build.migrationNoFolder'), migrationsDir);
        return;
    }
    const { applyMigrationsToD1 } = await import('../core/d1Integration.js');
    const result = await applyMigrationsToD1(dbConfig, migrationsDir);
    console.log(t('build.migrationApplied', { applied: result.applied, files: result.files?.length || 0 }));
}
