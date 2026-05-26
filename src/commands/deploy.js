/**
 * dokkebi deploy 커맨드 v2
 *
 * 프론트엔드 배포 대상:
 *   - cloudflare-pages  (기본) — 백엔드와 함께 Cloudflare Pages에 배포
 *   - cloudflare-r2            — Cloudflare R2 오브젝트 스토리지 업로드
 *   - s3                       — AWS S3 업로드 (+ CloudFront 캐시 무효화)
 *
 * 도메인 자동화 (domain 설정 시):
 *   - Cloudflare 관리 도메인이면 DNS 레코드 자동 추가/갱신
 *   - Cloudflare Pages 커스텀 도메인 자동 연결
 *   - R2 커스텀 도메인 자동 연결
 *
 * 필요한 환경변수 (.env):
 *   D1_API_TOKEN / CLOUDFLARE_API_TOKEN   — Cloudflare API 토큰
 *   D1_ACCOUNT_ID / CLOUDFLARE_ACCOUNT_ID — Cloudflare 계정 ID
 */

import path from 'path';
import fs from 'fs/promises';
import https from 'https';
import { execFileSync } from 'child_process';
import { createHmac, createHash } from 'crypto';
import { runBuild } from './build.js';
import { loadDokkebiConfigMerged } from '../core/dokkebiConfigLoad.js';
import { CSP_FRAME_SRC_ALLOWLIST, CSP_SCRIPT_SRC_LEMON_SQUEEZY } from '../core/cspFrameSrc.js';
import { isBundleEncryptEnabled } from '../core/buildWasm.js';
import { purgeBuildArtifactsFromDist } from '../core/buildArtifactPurge.js';
import { t } from '../i18n/index.js';

export async function runDeploy(src, options = {}) {
    const sourceRoot = path.resolve(process.cwd(), src);

    // ── 0. config + env 로드 ────────────────────────────────
    const dokkebiConfig = await loadDokkebiConfigMerged(sourceRoot);
    const envVars       = await loadEnvFile(sourceRoot);
    const env           = { ...envVars, ...process.env };

    const deployConfig   = dokkebiConfig?.deploy || {};
    const frontendTarget = options.frontendTarget || deployConfig.frontend || 'cloudflare-pages';
    const frontendOnly   = options.frontendOnly === true;
    const backendOnly    = options.backendOnly   === true;

    const cfApiToken  = env.D1_API_TOKEN || env.CLOUDFLARE_API_TOKEN || '';
    const cfAccountId = env.D1_ACCOUNT_ID || env.CLOUDFLARE_ACCOUNT_ID || '';
    const distDir     = path.join(sourceRoot, options.output || 'dist');
    const projectName = options.projectName || dokkebiConfig?.name || path.basename(sourceRoot);
    let pendingDokkebiEnvSecrets = [];

    // Secret-first 배포의 핵심: 초기 secret put 시점에도 wrangler 가 인증 정보를
    // 볼 수 있어야 한다. 기존에는 _deployToCloudflarePages() 안에서야 env 를 세팅해
    // 새 정적 자산이 먼저 올라간 뒤 secret retry 가 도는 race window 가 생겼다.
    if (cfApiToken) process.env.CLOUDFLARE_API_TOKEN = cfApiToken;
    if (cfAccountId) process.env.CLOUDFLARE_ACCOUNT_ID = cfAccountId;

    // 배포 결과 수집 (최종 요약 출력용)
    const result = {
        backend:  null,  // { url, type }
        frontend: null,  // { url, type, bucket? }
        domains:  [],    // [{ domain, target, status, record }]
    };

    // ── 타이틀 ──────────────────────────────────────────────
    const targets = [];
    if (!frontendOnly && dokkebiConfig?.proxyMode === 'serverless') targets.push(t('deploy.targetCfPagesBackend'));
    if (!backendOnly) {
        if (frontendTarget === 'cloudflare-r2') targets.push(t('deploy.targetCfR2Frontend'));
        else if (frontendTarget === 's3')        targets.push(t('deploy.targetS3Frontend'));
        else                                     targets.push(t('deploy.targetCfPagesFull'));
    }
    console.log('\n[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(t('deploy.header') + ': ' + targets.join(' + '));
    console.log('[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    if (!options.skipBuild) {
        console.log(t('deploy.buildStart'));
        await runBuild(src, { output: options.output || 'dist', skipMigration: options.skipMigration, forDeploy: true });
    } else {
        console.log(t('deploy.skipBuildNote'));
    }

    if (options.preflight !== false) {
        const strict = options.preflight === 'strict' || options.preflightStrict === true;
        const pre = await runPreflight(sourceRoot, dokkebiConfig, { strict });
        if (!pre.ok && strict) {
            console.error(t('deploy.preflightStrictBlock'));
            process.exit(1);
        }
    } else {
        console.log(t('deploy.preflightSkip'));
    }

    // ── 1b. Query Registry 검증 (Stage 3) ────────────────────
    //   기본 정책 (auto):
    //     - 레지스트리 비어도 배포는 진행 (legacy 호환 — 기존 v4 수준 방어 유지)
    //     - 경고만 출력하고 dev 학습 가이드 안내
    //   strict 정책 (opt-in):
    //     - dokkebi.config.js 의 queryRegistry.strict: true 이거나
    //       --strict-registry 플래그 사용 시 활성화
    //     - 레지스트리가 비었으면 배포 중단 (fail-closed)
    const qrEnabled = dokkebiConfig?.queryRegistry?.enabled !== false;
    const qrStrictConfig = dokkebiConfig?.queryRegistry?.strict === true;
    const qrStrictFlag = options.strictRegistry === true;
    const qrStrict = qrStrictConfig || qrStrictFlag;
    if (qrEnabled && dokkebiConfig?.proxyMode === 'serverless') {
        const registryPath = path.join(distDir, 'dokkebi', 'query-registry.json');
        let count = 0;
        let missing = false;
        try {
            const raw = await fs.readFile(registryPath, 'utf-8');
            const json = JSON.parse(raw);
            count = json?.queries ? Object.keys(json.queries).length : 0;
        } catch (e) {
            if (e.code === 'ENOENT') missing = true;
            else throw e;
        }

        if (count === 0) {
            console.warn(t('deploy.registryEmpty', { state: missing ? t('deploy.registryStateMissing') : t('deploy.registryStateEmpty') }));
            console.warn(t('deploy.registryMode', { mode: qrStrict ? t('deploy.registryModeStrict') : t('deploy.registryModeAuto') }));
            console.warn(t('deploy.registryPath'));
            console.warn(t('deploy.registryPath1'));
            console.warn(t('deploy.registryPath2'));
            console.warn(t('deploy.registryPath3'));
            console.warn(t('deploy.registryPath4'));
            if (qrStrict) {
                throw new Error('strict 모드에서 Query Registry 가 비어있어 배포를 중단합니다. (config.queryRegistry.strict: false 또는 --strict-registry 제거로 통과 가능)');
            }
        } else {
            console.log(t('deploy.registryEmbedded', { count, mode: qrStrict ? 'strict' : 'auto' }));
        }
    }

    // ── 1b. dist/ 내 민감 파일 퍼지 (CDN 캐시 무효화용 더미 덮어쓰기) ──
    await _purgeSecretsFromDist(distDir);
    await _enforceEncryptedBundleArtifacts(distDir, dokkebiConfig);

    // ── 1c. .dokkebi/env-secrets.json → Pages Secret 동기화 ──
    // 개별 키 등록 + DOKKEBI_ENV_SECRETS JSON 통합 등록
    // Cloudflare Pages Secret은 non-enumerable이므로 Object.entries(env)로 열거 불가.
    // handshake Worker가 모든 민감 변수를 한 번에 읽을 수 있도록 JSON blob도 함께 등록.
    //
    // 무중단 배포 — Secret 을 먼저 등록하고, 정적 자산 푸시 전에 짧은 전파 슬립을 둔다.
    //   wrangler pages secret put 는 Cloudflare API 가 200 을 반환해도 모든 엣지로
    //   전파되기까지 수 초가 걸린다. 이 사이에 정적 자산이 먼저 배포되면 새 번들+옛 키
    //   조합으로 핸드셰이크 실패가 발생한다 (BC_KEY_MAP 으로 1차 방어되지만, 첫 배포
    //   직후의 사용자에게 안전 마진을 추가한다).
    pendingDokkebiEnvSecrets = await _registerDokkebiEnvSecrets(sourceRoot, projectName);
    if (pendingDokkebiEnvSecrets.length === 0) {
        const propagationMs = Number(process.env.DOKKEBI_SECRET_PROPAGATION_MS || 15000);
        if (propagationMs > 0) {
            console.log(`[dokkebi] ⏳ Worker Secret 전파 안정화 대기 (${propagationMs}ms)...`);
            await new Promise((r) => setTimeout(r, propagationMs));
        }
    }

    // ── 2. Cloudflare Pages 배포 (서버리스 백엔드) ──────────
    if (!frontendOnly && !backendOnly && frontendTarget === 'cloudflare-pages') {
        // 기본 모드: CF Pages에 프론트+백엔드 함께 배포
        if (dokkebiConfig?.proxyMode !== 'serverless') {
            console.error(t('deploy.notServerless'));
            process.exitCode = 1; return;
        }
        result.backend  = await _deployToCloudflarePages(sourceRoot, distDir, projectName, cfApiToken, cfAccountId, {
            strictCsp: dokkebiConfig?.security?.strictCsp === true,
            dokkebiConfig,
        });
        result.frontend = { url: result.backend.url, type: 'cloudflare-pages' };

        if (pendingDokkebiEnvSecrets.length > 0) {
            console.log('\n' + t('deploy.secretRetry'));
            const registered = await _retryRegisterSecrets(pendingDokkebiEnvSecrets, projectName, sourceRoot);
            if (registered > 0) {
                // 무중단 배포 — 방금 등록된 Secret 이 모든 엣지에 전파될 때까지 대기.
                //   첫 deploy 시 secret put 이 정적 푸시 후에야 가능하므로,
                //   그 사이 들어온 사용자가 BC_KEY_MAP 미반영 핸드셰이크를 받지 않도록
                //   재배포 직전에 슬립을 둔다.
                const propagationMs = Number(process.env.DOKKEBI_SECRET_PROPAGATION_MS || 15000);
                if (propagationMs > 0) {
                    console.log(`[dokkebi] ⏳ Secret 전파 대기 후 재배포 (${propagationMs}ms)...`);
                    await new Promise((r) => setTimeout(r, propagationMs));
                }
                await _redeployCloudflarePagesDist(sourceRoot, distDir, projectName, dokkebiConfig);
            }
        }

        // CF Pages 커스텀 도메인 설정
        const pagesDomain = deployConfig.cloudflarePages?.domain || deployConfig.domain;
        if (pagesDomain && cfApiToken) {
            await _setupCloudflarePagesDomain(pagesDomain, projectName, cfAccountId, cfApiToken, result);
        }
    } else if (!frontendOnly) {
        // 백엔드와 프론트엔드 배포 대상이 분리된 경우
        if (dokkebiConfig?.proxyMode === 'serverless' && !backendOnly) {
            result.backend = await _deployToCloudflarePages(sourceRoot, distDir, projectName, cfApiToken, cfAccountId, {
                strictCsp: dokkebiConfig?.security?.strictCsp === true,
                dokkebiConfig,
            });
            if (pendingDokkebiEnvSecrets.length > 0) {
                console.log('\n' + t('deploy.secretRetry'));
                const registered = await _retryRegisterSecrets(pendingDokkebiEnvSecrets, projectName, sourceRoot);
                if (registered > 0) {
                    const propagationMs = Number(process.env.DOKKEBI_SECRET_PROPAGATION_MS || 15000);
                    if (propagationMs > 0) {
                        console.log(`[dokkebi] ⏳ Secret 전파 대기 후 재배포 (${propagationMs}ms)...`);
                        await new Promise((r) => setTimeout(r, propagationMs));
                    }
                    await _redeployCloudflarePagesDist(sourceRoot, distDir, projectName, dokkebiConfig);
                }
            }
        }

        // ── 3. 프론트엔드 배포 (R2 | S3) ──────────────────
        if (!backendOnly) {
            if (frontendTarget === 'cloudflare-r2') {
                result.frontend = await _deployFrontendToR2(distDir, deployConfig.r2 || {}, env, cfApiToken, cfAccountId);

                // R2 도메인 설정
                const r2Domain = deployConfig.r2?.domain;
                if (r2Domain && cfApiToken && cfAccountId) {
                    const bucket = deployConfig.r2?.bucket || env.R2_BUCKET;
                    await _setupR2Domain(r2Domain, bucket, cfAccountId, cfApiToken, result);
                }
            } else if (frontendTarget === 's3') {
                result.frontend = await _deployFrontendToS3(distDir, deployConfig.s3 || {}, env);
            }
        }
    } else {
        // --frontend-only
        if (frontendTarget === 'cloudflare-r2') {
            result.frontend = await _deployFrontendToR2(distDir, deployConfig.r2 || {}, env, cfApiToken, cfAccountId);
            const r2Domain = deployConfig.r2?.domain;
            if (r2Domain && cfApiToken && cfAccountId) {
                await _setupR2Domain(r2Domain, deployConfig.r2?.bucket || env.R2_BUCKET, cfAccountId, cfApiToken, result);
            }
        } else if (frontendTarget === 's3') {
            result.frontend = await _deployFrontendToS3(distDir, deployConfig.s3 || {}, env);
        } else {
            console.error(t('deploy.frontendOnlyBlocked'));
            process.exitCode = 1; return;
        }
    }

    // ── 4. 최종 배포 요약 출력 ─────────────────────────────
    printDeploySummary(result);
}

// ─────────────────────────────────────────────────────────────
// 암호화 번들 모드 — 평문 backend-bundle.js / backend-source.js 는 배포에 포함되지 않음
// ─────────────────────────────────────────────────────────────

async function _enforceEncryptedBundleArtifacts(distDir, dokkebiConfig) {
    if (!isBundleEncryptEnabled(dokkebiConfig?.security?.bundleEncrypt, process.env)) return;

    const wasmDir = path.join(distDir, 'dokkebi');
    for (const name of ['backend-bundle.js', 'backend-source.js']) {
        const p = path.join(wasmDir, name);
        try {
            await fs.unlink(p);
            console.log(`[dokkebi]   암호화 모드: dokkebi/${name} 제거 (배포 업로드 제외)`);
        } catch (e) {
            if (e.code !== 'ENOENT') throw e;
        }
    }

    let entries;
    try {
        entries = await fs.readdir(wasmDir);
    } catch (e) {
        if (e.code === 'ENOENT') {
            throw new Error('[dokkebi] dist/dokkebi 가 없습니다. dok build 를 먼저 실행하세요.');
        }
        throw e;
    }

    const hasEnc = entries.some(
        (n) => n === 'backend.bundle.enc' || /^backend\.bundle\.[a-f0-9]{12}\.enc$/i.test(n),
    );
    if (!hasEnc) {
        throw new Error(
            '[dokkebi] security.bundleEncrypt 가 켜져 있는데 암호화 번들(.enc)이 dist/dokkebi 에 없습니다. dok build 를 실행하세요.',
        );
    }

    try {
        await fs.access(path.join(wasmDir, 'backend-bundle.sha256'));
    } catch {
        throw new Error('[dokkebi] backend-bundle.sha256 이 없습니다. dok build 를 실행하세요.');
    }
}

// ─────────────────────────────────────────────────────────────
// 민감 파일 퍼지 — CDN 캐시 무효화를 위해 `{}` 더미로 덮어쓰기
// 삭제(unlink)만 하면 CDN이 이전 캐시를 유지하므로 덮어쓰기 필수
// ─────────────────────────────────────────────────────────────

async function _purgeSecretsFromDist(distDir) {
    const { purged } = await purgeBuildArtifactsFromDist(distDir);
    for (const rel of purged) {
        console.log(t('deploy.dummyOverwrite', { file: rel }));
    }
    console.log(t('deploy.purgeDone'));
}

// ─────────────────────────────────────────────────────────────
// Cloudflare Pages _headers 보안 헤더 파일 생성
// ─────────────────────────────────────────────────────────────

async function _writeSecurityHeaders(distDir, { strictCsp = false } = {}) {
    // Phase 2-⑥ — Strict CSP (hash 방식)
    //   strictCsp=true 이면 index.html 의 인라인 <script>/<style> 콘텐츠를 SHA-256
    //   으로 해시해 script-src/style-src 에 'sha256-...' 를 추가하고 'unsafe-inline'
    //   을 제거한다. 인라인 블록이 전혀 없으면 더 엄격한 디폴트가 적용된다.
    // Safari/iPadOS Safari still gates WebAssembly compilation behind 'unsafe-eval'
    // even when 'wasm-unsafe-eval' is present. QuickJS WASM cannot boot without it.
    let scriptSrc = `'self' 'unsafe-inline' 'wasm-unsafe-eval' 'unsafe-eval' blob: https://cdn.jsdelivr.net https://static.cloudflareinsights.com ${CSP_SCRIPT_SRC_LEMON_SQUEEZY}`;
    let styleSrc  = `'self' 'unsafe-inline' https://fonts.googleapis.com`;

    if (strictCsp) {
        try {
            const indexPath = path.join(distDir, 'index.html');
            const html = await fs.readFile(indexPath, 'utf-8');
            const { scriptHashes, styleHashes, inlineEventCount } = _collectInlineHashes(html);
            const scriptTok = scriptHashes.map(h => `'sha256-${h}'`).join(' ');
            const styleTok  = styleHashes.map(h => `'sha256-${h}'`).join(' ');
            scriptSrc = [`'self'`, `'wasm-unsafe-eval'`, `'unsafe-eval'`, scriptTok, `https://cdn.jsdelivr.net`, `https://static.cloudflareinsights.com`, CSP_SCRIPT_SRC_LEMON_SQUEEZY].filter(Boolean).join(' ').trim();
            // 스타일은 인라인 속성 (style="...") 까지 잡기 어렵기 때문에 hash + 'unsafe-hashes' 조합 안내
            styleSrc  = [`'self'`, styleTok, `https://fonts.googleapis.com`].filter(Boolean).join(' ').trim();
            if (inlineEventCount > 0) {
                console.warn(t('deploy.cspInlineWarn', { count: inlineEventCount }));
            }
            console.log(t('deploy.cspActive', { scripts: scriptHashes.length, styles: styleHashes.length }));
        } catch (e) {
            console.warn(t('deploy.cspScanFail'), e.message);
        }
    }

    // iframe: YouTube + NotoFly + Toonify (serve.js · cspFrameSrc.js 와 동일하게 유지)
    const frameSrc = CSP_FRAME_SRC_ALLOWLIST;
    const csp = `default-src 'self'; script-src ${scriptSrc}; style-src ${styleSrc}; img-src 'self' data: blob:; media-src 'self' blob:; worker-src 'self' blob:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' blob: https: wss: https://cloudflareinsights.com; frame-src ${frameSrc}; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'`;

    const content = `# dokkebi 보안 헤더 (자동 생성)
# https://developers.cloudflare.com/pages/configuration/headers/

/*
  X-Content-Type-Options: nosniff
  X-XSS-Protection: 1; mode=block
  X-Frame-Options: SAMEORIGIN
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(self), microphone=(self), display-capture=(self), geolocation=(), payment=()
  Content-Security-Policy: ${csp}

# index.html — 배포마다 최신 버전 강제 수신 (무결성 해시 캐시 방지)
/index.html
  Cache-Control: no-cache, no-store, must-revalidate
  Pragma: no-cache
  Expires: 0

# Service Worker — 항상 최신 버전 유지
/sw.js
  Cache-Control: no-cache, no-store, must-revalidate
  Pragma: no-cache
  Expires: 0

# Vite 빌드 정적 자산 — 파일명에 해시 포함되므로 영구 캐시 허용
/assets/*
  Cache-Control: public, max-age=31536000, immutable

# 해시 박힌 암호화 번들 — 콘텐츠 변경 시 파일명도 바뀌므로 영구 캐시 안전 (무중단 배포)
# (반드시 /dokkebi/* 보다 먼저 와야 우선 매칭됨)
/dokkebi/backend.bundle.*.enc
  Cache-Control: public, max-age=31536000, immutable

# dokkebi WASM 번들 — 해시 기반 무결성 검증 대상이므로 캐시 금지
/dokkebi/*
  Cache-Control: no-cache, no-store, must-revalidate

# WASM 바이너리 Content-Type 명시
/dokkebi/*.wasm
  Content-Type: application/wasm

# 민감 JSON 파일 접근 차단 (env-secrets.json 등 빌드 아티팩트 잔존 방어)
/dokkebi/*.json
  X-Robots-Tag: noindex
  X-Content-Type-Options: nosniff
  Cache-Control: no-store
`;
    try {
        await fs.mkdir(distDir, { recursive: true });
        await fs.writeFile(path.join(distDir, '_headers'), content, 'utf-8');
        console.log(t('deploy.headersCreated'));
    } catch (e) {
        console.warn(t('deploy.headersFailed'), e.message);
    }

}

// Phase 2-⑥ — 인라인 <script>/<style> 블록을 찾아 SHA-256 해시를 base64 로 반환.
function _collectInlineHashes(html) {
    const scriptHashes = [];
    const styleHashes = [];
    let inlineEventCount = 0;

    const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
    let m;
    while ((m = scriptRe.exec(html)) !== null) {
        const attrs = m[1] || '';
        const body = m[2] || '';
        // src= 가 있으면 외부 스크립트라 hash 불필요
        if (/\bsrc\s*=/.test(attrs)) continue;
        if (!body.trim()) continue;
        const h = createHash('sha256').update(body, 'utf-8').digest('base64');
        scriptHashes.push(h);
    }

    const styleRe = /<style\b[^>]*>([\s\S]*?)<\/style>/gi;
    while ((m = styleRe.exec(html)) !== null) {
        const body = m[1] || '';
        if (!body.trim()) continue;
        const h = createHash('sha256').update(body, 'utf-8').digest('base64');
        styleHashes.push(h);
    }

    // on* 이벤트 핸들러 카운트 (정확한 파싱은 비용이 크므로 경고용 heuristic)
    const evRe = /\son[a-z]+\s*=/gi;
    inlineEventCount = (html.match(evRe) || []).length;

    return { scriptHashes, styleHashes, inlineEventCount };
}

// ─────────────────────────────────────────────────────────────
// Cloudflare Pages 배포 (내부)
// ─────────────────────────────────────────────────────────────

async function _deployToCloudflarePages(sourceRoot, distDir, projectName, apiToken, accountId, opts = {}) {
    console.log('\n' + t('deploy.deployStart'));

    const wranglerOk = await ensureWrangler(sourceRoot);
    if (!wranglerOk) throw new Error('wrangler를 설치할 수 없습니다. npm install -g wrangler 를 실행하세요.');

    if (!apiToken) throw new Error('Cloudflare API Token이 없습니다. .env의 D1_API_TOKEN을 설정하세요.');
    process.env.CLOUDFLARE_API_TOKEN = apiToken;
    if (accountId) process.env.CLOUDFLARE_ACCOUNT_ID = accountId;

    // Cloudflare Pages _headers 파일 자동 생성 (보안 헤더 + 선택적 strict CSP)
    await _writeSecurityHeaders(distDir, { strictCsp: opts.strictCsp === true });

    // 배포 전 Secret 등록 시도 (프로젝트가 이미 존재하는 경우 성공)
    const pendingSecrets = await ensureWorkerSecrets(sourceRoot, projectName);

    // 배포 직전 최종 퍼지 — dist/ 내 민감 파일이 절대 업로드되지 않도록 보장
    await _purgeSecretsFromDist(distDir);
    await _enforceEncryptedBundleArtifacts(distDir, opts.dokkebiConfig);

    try {
        execFileSync('wrangler', ['pages', 'deploy', distDir, '--project-name', projectName], {
            cwd: sourceRoot, stdio: 'inherit',
        });
    } catch (e) {
        throw new Error(`Cloudflare Pages 배포 실패: ${e.message}\n직접 실행: wrangler pages deploy dist/`);
    }

    // 첫 배포로 프로젝트가 새로 생성된 경우 — 배포 후 Secret 재등록
    if (pendingSecrets && pendingSecrets.length > 0) {
        console.log('\n' + t('deploy.secretRetry'));
        const registered = await _retryRegisterSecrets(pendingSecrets, projectName, sourceRoot);
        if (registered > 0) {
            const propagationMs = Number(process.env.DOKKEBI_SECRET_PROPAGATION_MS || 15000);
            if (propagationMs > 0) {
                console.log(`[dokkebi] ⏳ Secret 전파 대기 후 재배포 (${propagationMs}ms)...`);
                await new Promise((r) => setTimeout(r, propagationMs));
            }
            await _redeployCloudflarePagesDist(sourceRoot, distDir, projectName, opts.dokkebiConfig);
        }
    }

    // .env의 변수를 Cloudflare Pages Secret으로 동기화 (OPENAI_API_KEY, DOKKEBI_JWT_SECRET 등).
    // 신규 프로젝트는 위 첫 deploy 로 프로젝트가 생긴 뒤에야 secret put 이 가능하다.
    // 이전 구현은 여기서만 put 하고 재배포가 없어, 사용자가 수동으로 두 번째 배포해야 키가
    // 적용된 것처럼 보이는 경우가 많았다 → 변경분이 있으면 전파 대기 후 동일 dist 로 재배포.
    const envSecretsUpdated = await _syncEnvVarsToPages(sourceRoot, projectName, apiToken, accountId);
    if (envSecretsUpdated > 0) {
        const propagationMs = Number(process.env.DOKKEBI_SECRET_PROPAGATION_MS || 15000);
        if (propagationMs > 0) {
            console.log(`[dokkebi] ⏳ .env Pages Secret 반영 전파 대기 (${propagationMs}ms) 후 재배포…`);
            await new Promise((r) => setTimeout(r, propagationMs));
        }
        console.log('[dokkebi] Pages Secret(.env) 갱신을 반영하기 위해 동일 산출물로 재배포합니다.');
        await _redeployCloudflarePagesDist(sourceRoot, distDir, projectName, opts.dokkebiConfig);
    }

    const url = `https://${projectName}.pages.dev`;
    console.log(t('deploy.deployedUrl', { url }));
    return { url, type: 'cloudflare-pages', projectName };
}

// ─────────────────────────────────────────────────────────────
// R2 프론트엔드 배포 (내부)
// ─────────────────────────────────────────────────────────────

async function _deployFrontendToR2(distRoot, r2Config, env, cfApiToken, cfAccountId) {
    const accountId = r2Config.accountId || cfAccountId || env.CF_ACCOUNT_ID || '';
    const bucket    = r2Config.bucket    || env.R2_BUCKET    || '';
    const prefix    = (r2Config.prefix   || env.R2_PREFIX    || '').replace(/\/+$/, '');
    const keyId     = r2Config.accessKeyId     || env.R2_ACCESS_KEY_ID     || '';
    const secret    = r2Config.secretAccessKey || env.R2_SECRET_ACCESS_KEY || '';

    if (!accountId) throw new Error('Cloudflare 계정 ID가 없습니다. .env의 D1_ACCOUNT_ID 또는 R2 설정을 확인하세요.');
    if (!bucket)    throw new Error('R2 버킷 이름이 없습니다. dokkebi.config.js의 deploy.r2.bucket을 설정하세요.');
    if (!keyId || !secret) throw new Error('R2 자격증명이 없습니다. .env의 R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY를 설정하세요.');

    await _purgeSecretsFromDist(distRoot);
    const files = await walkDir(distRoot);
    console.log('\n' + t('deploy.r2Upload', { bucket, prefix: prefix ? prefix + '/' : '', count: files.length }));

    let uploaded = 0;
    const hostname = `${accountId}.r2.cloudflarestorage.com`;
    const concurrency = 5;

    for (let i = 0; i < files.length; i += concurrency) {
        const batch = files.slice(i, i + concurrency);
        await Promise.all(batch.map(async (filePath) => {
            const rel          = path.relative(distRoot, filePath).replace(/\\/g, '/');
            const r2Key        = prefix ? `${prefix}/${rel}` : rel;
            const contentType  = getContentType(rel);
            const cacheControl = rel === 'index.html' || rel.endsWith('/index.html')
                ? 'no-cache, no-store, must-revalidate'
                : 'public, max-age=31536000, immutable';

            const body    = await fs.readFile(filePath);
            // R2는 path-style: hostname/{bucket}/{key}, region=auto
            const urlPath = `/${bucket}/${r2Key.split('/').map(encodeURIComponent).join('/')}`;
            await _objectPut({ hostname, urlPath, region: 'auto', body, contentType, cacheControl, keyId, secret });
            uploaded++;
            process.stdout.write(`\r[dokkebi]   업로드 중... ${uploaded}/${files.length}  `);
        }));
    }
    process.stdout.write('\n');

    // r2.dev 공개 URL 활성화 (cfApiToken으로 관리 API 호출)
    let publicUrl = `https://${bucket}.${accountId}.r2.dev`;
    if (cfApiToken) {
        const res = await cfApiRequest(`/accounts/${accountId}/r2/buckets/${bucket}/domains/managed`, 'PUT',
            { enabled: true }, cfApiToken);
        if (res.status < 300) {
            console.log(t('deploy.r2Done', { url: publicUrl }));
        } else {
            console.log(t('deploy.r2DoneNoUrl'));
        }
    } else {
        console.log(t('deploy.r2DoneSimple'));
    }

    return { url: publicUrl, type: 'cloudflare-r2', bucket, accountId };
}

// ─────────────────────────────────────────────────────────────
// S3 프론트엔드 배포 (내부)
// ─────────────────────────────────────────────────────────────

async function _deployFrontendToS3(distRoot, s3Config, env) {
    const bucket  = s3Config.bucket || env.AWS_S3_BUCKET || '';
    const region  = s3Config.region || env.AWS_REGION    || 'us-east-1';
    const prefix  = (s3Config.prefix || env.AWS_S3_PREFIX || '').replace(/\/+$/, '');
    const cfId    = s3Config.cloudfrontDistributionId || env.AWS_CLOUDFRONT_DISTRIBUTION_ID || '';
    const keyId   = env.AWS_ACCESS_KEY_ID     || '';
    const secret  = env.AWS_SECRET_ACCESS_KEY || '';

    if (!bucket) throw new Error('S3 버킷 이름이 없습니다. deploy.s3.bucket 또는 AWS_S3_BUCKET을 설정하세요.');
    if (!keyId || !secret) throw new Error('AWS 자격증명이 없습니다. AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY를 설정하세요.');

    await _purgeSecretsFromDist(distRoot);
    const files = await walkDir(distRoot);
    console.log('\n' + t('deploy.s3Upload', { bucket, prefix: prefix ? prefix + '/' : '', count: files.length }));

    let uploaded = 0;
    const hostname  = `${bucket}.s3.${region}.amazonaws.com`;
    const concurrency = 5;

    for (let i = 0; i < files.length; i += concurrency) {
        const batch = files.slice(i, i + concurrency);
        await Promise.all(batch.map(async (filePath) => {
            const rel          = path.relative(distRoot, filePath).replace(/\\/g, '/');
            const s3Key        = prefix ? `${prefix}/${rel}` : rel;
            const contentType  = getContentType(rel);
            const cacheControl = rel === 'index.html' || rel.endsWith('/index.html')
                ? 'no-cache, no-store, must-revalidate'
                : 'public, max-age=31536000, immutable';
            const urlPath = '/' + s3Key.split('/').map(encodeURIComponent).join('/');
            const body    = await fs.readFile(filePath);
            await _objectPut({ hostname, urlPath, region, body, contentType, cacheControl, keyId, secret });
            uploaded++;
            process.stdout.write(`\r[dokkebi]   업로드 중... ${uploaded}/${files.length}  `);
        }));
    }
    process.stdout.write('\n');

    let publicUrl = `https://${bucket}.s3.${region}.amazonaws.com`;
    if (cfId) {
        console.log(t('deploy.s3Invalidating', { id: cfId }));
        await _cloudfrontInvalidate(cfId, keyId, secret);
        publicUrl = `https://${cfId}.cloudfront.net`;
        console.log(t('deploy.s3DoneCloudFront'));
    } else {
        console.log(t('deploy.s3DoneUrl', { url: publicUrl }));
    }

    return { url: publicUrl, type: 's3', bucket, region };
}

// ─────────────────────────────────────────────────────────────
// Worker Secrets 자동 생성 + 등록
// ─────────────────────────────────────────────────────────────

async function _registerDokkebiEnvSecrets(sourceRoot, projectName) {
    const dokkebiSecretsPath = path.join(sourceRoot, '.dokkebi', 'env-secrets.json');
    const pending = [];
    try {
        const raw = JSON.parse(await fs.readFile(dokkebiSecretsPath, 'utf-8'));
        const envSecretsObj = raw.secrets || {};
        if (Object.keys(envSecretsObj).length > 0) {
            console.log(t('deploy.envSecretsRegistering', { count: Object.keys(envSecretsObj).length }));
            for (const [key, value] of Object.entries(envSecretsObj)) {
                const ok = _registerSecret(key, value, projectName, sourceRoot);
                if (!ok) pending.push({ key, value });
            }
            const blobOk = _registerSecret('DOKKEBI_ENV_SECRETS', JSON.stringify(envSecretsObj), projectName, sourceRoot);
            if (!blobOk) pending.push({ key: 'DOKKEBI_ENV_SECRETS', value: JSON.stringify(envSecretsObj) });
        }
    } catch { /* .dokkebi/env-secrets.json 없으면 무시 */ }
    return pending;
}

// ─────────────────────────────────────────────────────────────
// .env 변수 → Cloudflare Pages 환경변수 동기화
// Pages Function(send.js 등)에서 env.XXX 로 접근하는 변수들을 자동 등록
// ─────────────────────────────────────────────────────────────

// .env 파일의 모든 변수를 Pages secret으로 동기화
// VITE_* 접두사는 빌드 시 인라인되므로 제외
const PAGES_ENV_SKIP_PREFIXES = ['VITE_'];
const PAGES_SECRET_HASH_MANIFEST = path.join('.dokkebi', 'pages-secret-hashes.json');

/**
 * .env → wrangler pages secret put. 성공적으로 갱신된 키 개수를 반환한다.
 * @returns {Promise<number>}
 */
async function _syncEnvVarsToPages(sourceRoot, projectName, apiToken, accountId) {
    void apiToken;
    void accountId;
    const envVars = await loadEnvFile(sourceRoot).catch(() => ({}));

    const toSync = Object.entries(envVars)
        .filter(([k, v]) => v && !PAGES_ENV_SKIP_PREFIXES.some((p) => k.startsWith(p)))
        .map(([k, v]) => ({ key: k, value: v, hash: _hashPageSecretValue(k, v) }));
    if (toSync.length === 0) return 0;

    const previousHashes = await _loadPageSecretHashes(sourceRoot);
    const changed = toSync.filter(({ key, hash }) => previousHashes[key] !== hash);
    const skipped = toSync.length - changed.length;

    /** 이전 매니페스트 + 동일 값인 키는 현재 해시로 확정 */
    const nextHashes = { ...previousHashes };
    for (const { key, hash } of toSync) {
        if (!changed.some((c) => c.key === key)) {
            nextHashes[key] = hash;
        }
    }

    if (changed.length === 0) {
        console.log(`\n[dokkebi] Pages Secret 동기화: 변경 없음 (${skipped}개 키 스킵)`);
        await _savePageSecretHashes(sourceRoot, nextHashes);
        return 0;
    }

    console.log('\n' + t('deploy.envSyncStart', { count: changed.length }));
    if (skipped > 0) {
        console.log(`[dokkebi] Pages Secret: 변경 없는 ${skipped}개 키 스킵`);
    }

    let updated = 0;
    for (const { key, value, hash } of changed) {
        try {
            execFileSync(
                'wrangler',
                ['pages', 'secret', 'put', key, '--project-name', projectName],
                {
                    input: value,
                    cwd: sourceRoot,
                    stdio: ['pipe', 'pipe', 'pipe'],
                    env: { ...process.env },
                }
            );
            console.log(t('deploy.envSyncOk', { key }));
            nextHashes[key] = hash;
            updated++;
        } catch {
            console.warn(t('deploy.envSyncFail', { key }));
        }
    }

    await _savePageSecretHashes(sourceRoot, nextHashes);
    return updated;
}

function _hashPageSecretValue(key, value) {
    return createHash('sha256').update(key).update('\0').update(String(value)).digest('hex');
}

async function _loadPageSecretHashes(sourceRoot) {
    const manifestPath = path.join(sourceRoot, PAGES_SECRET_HASH_MANIFEST);
    try {
        const raw = JSON.parse(await fs.readFile(manifestPath, 'utf-8'));
        return raw?.secrets && typeof raw.secrets === 'object' ? raw.secrets : {};
    } catch {
        return {};
    }
}

async function _savePageSecretHashes(sourceRoot, hashes) {
    const manifestPath = path.join(sourceRoot, PAGES_SECRET_HASH_MANIFEST);
    const filtered = {};
    for (const [key, hash] of Object.entries(hashes)) {
        if (typeof hash === 'string' && hash) filtered[key] = hash;
    }

    try {
        await fs.mkdir(path.dirname(manifestPath), { recursive: true });
        await fs.writeFile(
            manifestPath,
            JSON.stringify({ version: 1, generatedAt: new Date().toISOString(), secrets: filtered }, null, 2),
            { encoding: 'utf-8', mode: 0o600 }
        );
        await fs.chmod(manifestPath, 0o600).catch(() => {});
        await appendToGitignore(sourceRoot, '.dokkebi/');
    } catch { /* 해시 매니페스트 저장 실패는 다음 배포에서 전체 동기화로 복구 */ }
}

// ensureWorkerSecrets — Secret 생성/로드 후 등록 시도
// 반환값: 등록 실패한 [{ key, value }] 배열 (첫 배포 시 프로젝트 없어서 실패한 항목)
async function ensureWorkerSecrets(sourceRoot, projectName) {
    const secretsFile = path.join(sourceRoot, '.dokkebi-secrets.json');
    let secrets;

    try {
        secrets = JSON.parse(await fs.readFile(secretsFile, 'utf-8'));
        console.log(t('deploy.secretsLoaded', { file: secretsFile }));
    } catch {
        console.log(t('deploy.secretsCreating'));

        const { webcrypto } = await import('crypto');
        const { subtle } = webcrypto;

        // ECDH P-256 키 쌍 생성
        const keyPair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );
        const privateJwk = await subtle.exportKey('jwk', keyPair.privateKey);

        // 세션 서명키: 32바이트 랜덤 Hex
        const sessionSecretBytes = webcrypto.getRandomValues(new Uint8Array(32));
        const sessionSecret = Buffer.from(sessionSecretBytes).toString('hex');

        secrets = {
            DOKKEBI_SERVER_JWK: JSON.stringify(privateJwk),
            DOKKEBI_SESSION_SECRET: sessionSecret,
        };

        // .dokkebi-secrets.json 저장 (gitignore에 자동 추가)
        await fs.writeFile(secretsFile, JSON.stringify(secrets, null, 2), 'utf-8');
        console.log(t('deploy.secretsCreated', { file: secretsFile }));

        // .gitignore에 추가
        await appendToGitignore(sourceRoot, '.dokkebi-secrets.json');
    }

    // wrangler pages secret put 으로 각 secret 등록
    const pending = []; // 등록 실패 항목 (프로젝트 미존재 등)
    for (const [key, value] of Object.entries(secrets)) {
        const ok = _registerSecret(key, value, projectName, sourceRoot);
        if (!ok) pending.push({ key, value });
    }
    return pending; // 빈 배열이면 모두 성공
}

// Secret 단건 등록 — 성공 true / 실패 false
function _registerSecret(key, value, projectName, sourceRoot) {
    try {
        execFileSync(
            'wrangler',
            ['pages', 'secret', 'put', key, '--project-name', projectName],
            {
                input: value,
                cwd: sourceRoot,
                stdio: ['pipe', 'pipe', 'pipe'],
                env: { ...process.env },
            }
        );
        console.log(t('deploy.secretRegistered', { key }));
        return true;
    } catch {
        console.warn(t('deploy.secretWaiting', { key }));
        return false;
    }
}

// 배포 후 미등록 Secret 재시도 (최대 3회)
async function _retryRegisterSecrets(pending, projectName, sourceRoot) {
    const MAX_RETRY = 3;
    const RETRY_DELAY_MS = 2000;
    let registeredCount = 0;

    for (const { key, value } of pending) {
        let registered = false;
        for (let attempt = 1; attempt <= MAX_RETRY; attempt++) {
            if (attempt > 1) {
                await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
                console.log(t('deploy.secretRetryAttempt', { attempt, max: MAX_RETRY, key }));
            }
            registered = _registerSecret(key, value, projectName, sourceRoot);
            if (registered) break;
        }
        if (!registered) {
            console.error(t('deploy.secretFailed', { key }));
            console.error(t('deploy.secretFailedHint', { key, projectName }));
        } else {
            registeredCount++;
        }
    }
    return registeredCount;
}

async function _redeployCloudflarePagesDist(sourceRoot, distDir, projectName, dokkebiConfig) {
    await _enforceEncryptedBundleArtifacts(distDir, dokkebiConfig);
    console.log('\n[dokkebi]   Secret 반영을 위해 동일 산출물을 재배포합니다...');
    try {
        execFileSync('wrangler', ['pages', 'deploy', distDir, '--project-name', projectName], {
            cwd: sourceRoot,
            stdio: 'inherit',
            env: { ...process.env },
        });
    } catch (e) {
        throw new Error(`Cloudflare Pages 재배포 실패: ${e.message}\n직접 실행: wrangler pages deploy dist/`);
    }
}

// ─────────────────────────────────────────────────────────────
// wrangler 설치 확인
// ─────────────────────────────────────────────────────────────

async function ensureWrangler(sourceRoot) {
    try {
        execFileSync('wrangler', ['--version'], { stdio: 'pipe' });
        const version = execFileSync('wrangler', ['--version'], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
        console.log(t('deploy.wranglerDetected', { version }));
        return true;
    } catch {
        console.log(t('deploy.wranglerInstalling'));
        try {
            execFileSync('npm', ['install', '-g', 'wrangler'], { stdio: 'inherit', cwd: sourceRoot });
            return true;
        } catch {
            // 로컬 설치 시도
            try {
                execFileSync('npm', ['install', 'wrangler', '--save-dev'], { stdio: 'inherit', cwd: sourceRoot });
                return true;
            } catch {
                return false;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
// 헬퍼
// ─────────────────────────────────────────────────────────────

async function appendToGitignore(sourceRoot, entry) {
    try {
        const gitignorePath = path.join(sourceRoot, '.gitignore');
        let content = '';
        try {
            content = await fs.readFile(gitignorePath, 'utf-8');
        } catch { /* .gitignore 없음 */ }
        if (!content.includes(entry)) {
            await fs.appendFile(gitignorePath, `\n${entry}\n`);
            console.log(t('deploy.gitignoreAdd', { entry }));
        }
    } catch { /* 무시 */ }
}

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

// ─────────────────────────────────────────────────────────────
// 도메인 자동화 — Cloudflare Pages
// ─────────────────────────────────────────────────────────────

async function _setupCloudflarePagesDomain(domain, projectName, accountId, apiToken, result) {
    console.log('\n' + t('deploy.domainPagesStart', { domain }));
    try {
        const res = await cfApiRequest(
            `/accounts/${accountId}/pages/projects/${projectName}/domains`,
            'POST', { name: domain }, apiToken
        );
        if (res.status >= 400 && res.status !== 409) {
            console.warn(t('deploy.domainPagesFail', { status: res.status, errors: JSON.stringify(res.body?.errors) }));
        } else {
            console.log(t('deploy.domainPagesOk', { domain }));
        }

        const dnsStatus = await _autoAddCFDns(domain, `${projectName}.pages.dev`, apiToken, 'CNAME');
        result.domains.push({ domain, target: `${projectName}.pages.dev`, type: 'CNAME', dnsStatus });
    } catch (e) {
        console.warn(t('deploy.domainAutoFail', { msg: e.message }));
        result.domains.push({ domain, target: `${projectName}.pages.dev`, type: 'CNAME', dnsStatus: 'manual' });
    }
}

// ─────────────────────────────────────────────────────────────
// 도메인 자동화 — Cloudflare R2
// ─────────────────────────────────────────────────────────────

async function _setupR2Domain(domain, bucket, accountId, apiToken, result) {
    console.log('\n' + t('deploy.domainR2Start', { domain, bucket }));
    try {
        const apexDomain = _getApexDomain(domain);
        const res = await cfApiRequest(
            `/accounts/${accountId}/r2/buckets/${bucket}/domains/custom`,
            'POST',
            { domain, zoneName: apexDomain, enabled: true },
            apiToken
        );

        if (res.status >= 400) {
            const res2 = await cfApiRequest(
                `/accounts/${accountId}/r2/buckets/${bucket}/domains/custom/${domain}`,
                'PUT', { enabled: true }, apiToken
            );
            if (res2.status < 300 || res2.status === 409) {
                console.log(t('deploy.domainR2Ok', { domain }));
            } else {
                console.warn(t('deploy.domainR2Fail', { errors: JSON.stringify(res2.body?.errors) }));
            }
        } else {
            console.log(t('deploy.domainR2Ok', { domain }));
        }

        const r2DevHost = `${bucket}.${accountId}.r2.dev`;
        const dnsStatus = await _autoAddCFDns(domain, r2DevHost, apiToken, 'CNAME');
        result.domains.push({ domain, target: r2DevHost, type: 'CNAME', dnsStatus });

        if (result.frontend) result.frontend.url = `https://${domain}`;
    } catch (e) {
        console.warn(t('deploy.domainAutoFail', { msg: e.message }));
        result.domains.push({ domain, dnsStatus: 'manual' });
    }
}

// ─────────────────────────────────────────────────────────────
// Cloudflare DNS 자동 추가/갱신
// ─────────────────────────────────────────────────────────────

async function _autoAddCFDns(fqdn, target, apiToken, type = 'CNAME') {
    const apexDomain = _getApexDomain(fqdn);
    const subdomain  = fqdn === apexDomain ? '@' : fqdn.slice(0, fqdn.length - apexDomain.length - 1);

    // 1. zone 조회
    const zoneRes = await cfApiRequest(`/zones?name=${apexDomain}`, 'GET', null, apiToken);
    const zone    = zoneRes.body?.result?.[0];
    if (!zone) {
        console.log(t('deploy.dnsManual', { apex: apexDomain }));
        console.log(t('deploy.dnsManualLine', { type, fqdn, target }));
        return 'manual';
    }

    const zoneId  = zone.id;
    const recName = fqdn; // fqdn을 name으로 사용

    // 2. 기존 레코드 확인
    const existingRes = await cfApiRequest(
        `/zones/${zoneId}/dns_records?type=${type}&name=${recName}`, 'GET', null, apiToken
    );
    const existing = existingRes.body?.result?.[0];

    const recordBody = { type, name: recName, content: target, proxied: true, ttl: 1 };

    if (existing) {
        // 업데이트
        const upRes = await cfApiRequest(
            `/zones/${zoneId}/dns_records/${existing.id}`, 'PATCH', recordBody, apiToken
        );
        if (upRes.status < 300) {
            console.log(t('deploy.dnsUpdated', { name: recName, target }));
            return 'updated';
        }
    } else {
        const addRes = await cfApiRequest(`/zones/${zoneId}/dns_records`, 'POST', recordBody, apiToken);
        if (addRes.status < 300) {
            console.log(t('deploy.dnsAdded', { name: recName, target }));
            return 'created';
        }
    }

    console.warn(t('deploy.dnsFailed', { type, fqdn, target }));
    return 'failed';
}

function _getApexDomain(fqdn) {
    const parts = fqdn.split('.');
    return parts.length >= 2 ? parts.slice(-2).join('.') : fqdn;
}

// ─────────────────────────────────────────────────────────────
// Cloudflare API 공통 요청 헬퍼
// ─────────────────────────────────────────────────────────────

function cfApiRequest(apiPath, method, body, apiToken) {
    const hostname = 'api.cloudflare.com';
    const urlPath  = '/client/v4' + apiPath;
    const bodyStr  = body ? JSON.stringify(body) : null;
    const headers  = {
        'Authorization': `Bearer ${apiToken}`,
        'Content-Type':  'application/json',
        ...(bodyStr ? { 'Content-Length': String(Buffer.byteLength(bodyStr)) } : {}),
    };

    return new Promise((resolve, reject) => {
        const req = https.request({ hostname, path: urlPath, method, headers }, (res) => {
            let data = '';
            res.on('data', c => (data += c));
            res.on('end', () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
                catch { resolve({ status: res.statusCode, body: data }); }
            });
        });
        req.on('error', reject);
        if (bodyStr) req.write(bodyStr);
        req.end();
    });
}

// ─────────────────────────────────────────────────────────────
// 배포 결과 요약 출력
// ─────────────────────────────────────────────────────────────

function printDeploySummary(result) {
    const line = '━'.repeat(48);
    console.log(`\n[dokkebi] ${line}`);
    console.log('[dokkebi] 🎉  ' + t('deploy.complete'));
    console.log(`[dokkebi] ${line}`);

    if (result.backend) {
        const icon = result.backend.type === 'cloudflare-pages' ? '☁ ' : '🖥';
        console.log(t('deploy.summaryBackend', { icon, url: result.backend.url }));
    }
    if (result.frontend) {
        const icons = { 'cloudflare-pages': '☁ ', 'cloudflare-r2': '🪣', 's3': '🗃' };
        const icon  = icons[result.frontend.type] || '🌐';
        console.log(t('deploy.summaryFrontend', { icon, url: result.frontend.url }));
    }

    if (result.domains.length > 0) {
        console.log(`[dokkebi]   ${'─'.repeat(44)}`);
        for (const d of result.domains) {
            if (d.dnsStatus === 'manual') {
                console.log(t('deploy.summaryDomainManual', { domain: d.domain }));
                console.log(t('deploy.summaryDomainHint1', { type: d.type || 'CNAME' }));
                if (d.target) console.log(t('deploy.summaryDomainHint2', { target: d.target }));
            } else {
                const statusIcon = d.dnsStatus === 'created' ? '✅' : d.dnsStatus === 'updated' ? '🔄' : '✅';
                console.log(t('deploy.summaryDomain', { icon: statusIcon, domain: d.domain }));
            }
        }
    }

    console.log(`[dokkebi] ${line}\n`);
}

// ─────────────────────────────────────────────────────────────
// 오브젝트 스토리지 PUT (S3 Signature V4 — S3 & R2 공통)
// hostname 과 urlPath 를 외부에서 결정하므로 virtual-hosted / path-style 모두 지원
// ─────────────────────────────────────────────────────────────

async function _objectPut({ hostname, urlPath, region, body, contentType, cacheControl, keyId, secret }) {
    const datetime = new Date().toISOString().replace(/[:-]/g, '').replace(/\.\d{3}/, '');
    const date     = datetime.slice(0, 8);
    const bodyHash = _awsHash(body);

    const headers = {
        'cache-control':        cacheControl,
        'content-length':       String(body.length),
        'content-type':         contentType,
        'host':                 hostname,
        'x-amz-content-sha256': bodyHash,
        'x-amz-date':           datetime,
    };

    const sortedKeys       = Object.keys(headers).sort();
    const canonicalHeaders = sortedKeys.map(k => `${k}:${headers[k]}`).join('\n') + '\n';
    const signedHeaders    = sortedKeys.join(';');
    const canonicalReq     = ['PUT', urlPath, '', canonicalHeaders, signedHeaders, bodyHash].join('\n');
    const scope            = `${date}/${region}/s3/aws4_request`;
    const stringToSign     = ['AWS4-HMAC-SHA256', datetime, scope, _awsHash(canonicalReq)].join('\n');

    const signingKey = _awsHmac(
        _awsHmac(_awsHmac(_awsHmac(`AWS4${secret}`, date), region), 's3'),
        'aws4_request'
    );
    const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');
    const Authorization = `AWS4-HMAC-SHA256 Credential=${keyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const reqHeaders = Object.fromEntries(sortedKeys.map(k => [k, headers[k]]));
    reqHeaders['Authorization'] = Authorization;
    delete reqHeaders['host'];

    return new Promise((resolve, reject) => {
        const req = https.request(
            { hostname, path: urlPath, method: 'PUT', headers: reqHeaders },
            (res) => {
                let data = '';
                res.on('data', c => (data += c));
                res.on('end', () => {
                    if (res.statusCode >= 400) reject(new Error(`업로드 실패 (${res.statusCode}): ${data.slice(0, 300)}`));
                    else resolve(res.statusCode);
                });
            }
        );
        req.on('error', reject);
        req.write(body);
        req.end();
    });
}

async function _cloudfrontInvalidate(distributionId, keyId, secret) {
    const datetime = new Date().toISOString().replace(/[:-]/g, '').replace(/\.\d{3}/, '');
    const date     = datetime.slice(0, 8);
    const hostname = 'cloudfront.amazonaws.com';
    const urlPath  = `/2020-05-31/distribution/${distributionId}/invalidation`;
    const xmlBody  = `<?xml version="1.0" encoding="UTF-8"?><InvalidationBatch><Paths><Quantity>1</Quantity><Items><Path>/*</Path></Items></Paths><CallerReference>${Date.now()}</CallerReference></InvalidationBatch>`;
    const bodyHash = _awsHash(xmlBody);

    const headers = {
        'content-length': String(Buffer.byteLength(xmlBody)),
        'content-type':   'application/xml',
        'host':           hostname,
        'x-amz-content-sha256': bodyHash,
        'x-amz-date':    datetime,
    };

    const sortedKeys       = Object.keys(headers).sort();
    const canonicalHeaders = sortedKeys.map(k => `${k}:${headers[k]}`).join('\n') + '\n';
    const signedHeaders    = sortedKeys.join(';');
    const canonicalReq     = ['POST', urlPath, '', canonicalHeaders, signedHeaders, bodyHash].join('\n');
    const scope            = `${date}/us-east-1/cloudfront/aws4_request`;
    const stringToSign     = ['AWS4-HMAC-SHA256', datetime, scope, _awsHash(canonicalReq)].join('\n');
    const signingKey       = _awsHmac(_awsHmac(_awsHmac(_awsHmac(`AWS4${secret}`, date), 'us-east-1'), 'cloudfront'), 'aws4_request');
    const signature        = createHmac('sha256', signingKey).update(stringToSign).digest('hex');

    const reqHeaders = Object.fromEntries(sortedKeys.map(k => [k, headers[k]]));
    reqHeaders['Authorization'] = `AWS4-HMAC-SHA256 Credential=${keyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    delete reqHeaders['host'];

    return new Promise((resolve) => {
        const req = https.request({ hostname, path: urlPath, method: 'POST', headers: reqHeaders }, (res) => {
            let data = '';
            res.on('data', c => (data += c));
            res.on('end', () => {
                if (res.statusCode >= 400) console.warn(t('deploy.cloudfrontFail', { status: res.statusCode }));
                else console.log(t('deploy.cloudfrontOk'));
                resolve(null);
            });
        });
        req.on('error', () => resolve(null));
        req.write(xmlBody);
        req.end();
    });
}

function _awsHmac(key, data) { return createHmac('sha256', key).update(data, 'utf8').digest(); }
function _awsHash(data) { return createHash('sha256').update(data).digest('hex'); }

// ─── 파일 유틸리티 ───────────────────────────────────────────

async function walkDir(dir) {
    const results = [];
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            results.push(...(await walkDir(fullPath)));
        } else {
            results.push(fullPath);
        }
    }
    return results;
}

const MIME = {
    '.html':  'text/html; charset=utf-8',
    '.css':   'text/css; charset=utf-8',
    '.js':    'application/javascript; charset=utf-8',
    '.mjs':   'application/javascript; charset=utf-8',
    '.json':  'application/json; charset=utf-8',
    '.wasm':  'application/wasm',
    '.png':   'image/png',
    '.jpg':   'image/jpeg',
    '.jpeg':  'image/jpeg',
    '.gif':   'image/gif',
    '.webp':  'image/webp',
    '.svg':   'image/svg+xml',
    '.ico':   'image/x-icon',
    '.woff':  'font/woff',
    '.woff2': 'font/woff2',
    '.ttf':   'font/ttf',
    '.txt':   'text/plain',
    '.xml':   'application/xml',
    '.pdf':   'application/pdf',
    '.map':   'application/json',
};

function getContentType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return MIME[ext] || 'application/octet-stream';
}

// ── Phase 1-④ Preflight 보안 점검 ────────────────────────────
// dokkebi.config.js + 빌드 산출물을 기반으로 배포 전 보안 취약 구성을 자동
// 점검. 실패를 강제 차단하지는 않으며(기본) 경고를 수집해 출력. --strict
// 로 실행 시 경고가 하나라도 있으면 배포 중단한다.
async function runPreflight(sourceRoot, dokkebiConfig, { strict = false } = {}) {
    console.log('\n[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(t('deploy.preflightTitle'));
    console.log('[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

    const warnings = [];
    const errors = [];
    const ok = [];

    const distDir = path.join(sourceRoot, 'dist');
    const wasmOutDir = path.join(distDir, 'dokkebi');

    try {
        await fs.access(path.join(wasmOutDir, 'sql-allowlist.json'));
        ok.push(t('deploy.pfOkBuildArtifact'));
    } catch {
        errors.push(t('deploy.pfErrNoAllowlist'));
    }

    let allowlist = null;
    try {
        allowlist = JSON.parse(await fs.readFile(path.join(wasmOutDir, 'sql-allowlist.json'), 'utf-8'));
    } catch { /* 위에서 에러 누적됨 */ }

    if (allowlist) {
        const userTables = (allowlist.tables || []).filter(tbl => !tbl.name.startsWith('_dokkebi_') && tbl.name !== 'sqlite_master');
        if (userTables.length === 0) {
            warnings.push(t('deploy.pfWarnNoUserTables'));
        } else {
            ok.push(t('deploy.pfOkAllowlist', { count: userTables.length }));
        }
        if (allowlist.rawAllowed === true) {
            warnings.push(t('deploy.pfWarnRawSql'));
        }
        if (!allowlist.buildMeta?.source_sha) {
            warnings.push(t('deploy.pfWarnNoBuildSig'));
        } else if (allowlist.buildMeta.source_dirty) {
            warnings.push(t('deploy.pfWarnGitDirty'));
        } else {
            ok.push(t('deploy.pfOkBuildSig', {
                sha: allowlist.buildMeta.source_sha.slice(0, 10),
                branch: allowlist.buildMeta.source_branch || 'n/a',
            }));
        }
    }

    const policyCfg = dokkebiConfig?.policy;
    const policyEnabled = policyCfg?.enabled === true || !!(policyCfg?.tables && Object.keys(policyCfg.tables).length > 0);
    if (!policyEnabled) {
        warnings.push(t('deploy.pfWarnNoTenantPolicy'));
    } else {
        const mode = policyCfg?.mode || 'verify';
        if (mode === 'off') {
            warnings.push(t('deploy.pfWarnPolicyOff'));
        } else if (policyCfg?.strict === false) {
            warnings.push(t('deploy.pfWarnPolicyStrictOff'));
        } else {
            ok.push(t('deploy.pfOkTenantPolicy', { mode }));
        }
    }

    const authzCfg = dokkebiConfig?.authorization;
    const authzEnabled = authzCfg?.enabled === true || !!(authzCfg?.rules && Object.keys(authzCfg.rules).length > 0);
    if (!authzEnabled) {
        warnings.push(t('deploy.pfWarnNoAuthz'));
    } else {
        const mode = authzCfg?.mode || 'warn';
        const rules = authzCfg?.rules || {};
        const hasWildcard = !!(rules['*:*'] || rules['*'] || rules['default']);
        if (mode === 'warn' && !hasWildcard) {
            warnings.push(t('deploy.pfWarnAuthzWarnNoDefault'));
        } else if (mode === 'strict' && !hasWildcard) {
            warnings.push(t('deploy.pfWarnAuthzStrictNoDefault'));
        } else {
            ok.push(t('deploy.pfOkAuthz', { mode, count: Object.keys(rules).length }));
        }
    }

    const rep = dokkebiConfig?.security?.replay || {};
    const winMs = Number(rep.timestampWindowMs);
    if (Number.isFinite(winMs) && winMs > 15_000) {
        warnings.push(t('deploy.pfWarnReplayWindow', { ms: winMs }));
    }
    if (rep.enabled === false) {
        warnings.push(t('deploy.pfWarnReplayDisabled'));
    }
    if (rep.maxEnvelopeBytes && Number(rep.maxEnvelopeBytes) > 512 * 1024) {
        warnings.push(t('deploy.pfWarnEnvelopeBig', { bytes: rep.maxEnvelopeBytes }));
    }

    const waCfg = dokkebiConfig?.security?.webauthn;
    if (waCfg?.enabled === true) {
        console.log(t('deploy.preflightWebAuthnNote'));
        ok.push(t('deploy.pfOkWebAuthn'));
    }

    if (dokkebiConfig?.security?.strictCsp === true) {
        ok.push(t('deploy.pfOkStrictCsp'));
    } else {
        warnings.push(t('deploy.pfWarnNoStrictCsp'));
    }

    // 7) 관리자 비밀번호
    const envPath = path.join(sourceRoot, '.env');
    try {
        const envText = await fs.readFile(envPath, 'utf-8');
        const m = /DOKKEBI_ADMIN_PASSWORD\s*=\s*(.+)/.exec(envText);
        if (m && m[1] && m[1].trim() && m[1].trim().length < 12) {
            warnings.push(t('deploy.pfWarnAdminPasswordShort'));
        }
    } catch { /* 무시 */ }

    // 8) Query Registry 비어있으면 경고 (build.js 에서 이미 경고 — preflight 중복 방지 위해 간결히)
    try {
        const reg = JSON.parse(await fs.readFile(path.join(wasmOutDir, 'query-registry.json'), 'utf-8'));
        const cnt = reg?.queries ? Object.keys(reg.queries).length : 0;
        if (cnt === 0) warnings.push(t('deploy.pfWarnEmptyRegistry'));
        else ok.push(t('deploy.pfOkQueryRegistry', { count: cnt }));
    } catch { /* query registry 없음 — 이미 build 에서 안내 */ }

    // 9) CORS 기본값(*) 운영 노출 — security.cors.allowedOrigins 미설정 시 경고.
    //    SECURITY.md §4.7 / §7 체크리스트의 "실제 프론트 오리진으로 제한" 강제용.
    try {
        const corsCfg = dokkebiConfig?.security?.cors;
        const origins = Array.isArray(corsCfg?.allowedOrigins) ? corsCfg.allowedOrigins.filter(Boolean) : null;
        const widePattern = !origins || origins.length === 0 || origins.includes('*');
        if (widePattern) {
            warnings.push('CORS Access-Control-Allow-Origin 이 `*` 으로 노출됩니다 — security.cors.allowedOrigins 에 실제 프론트 오리진을 명시하세요. (SECURITY.md §4.7)');
        } else {
            ok.push(`CORS allowed origins: ${origins.length}개 명시`);
        }
    } catch { /* 무시 */ }

    // ── Phase B-5: 샤딩 preflight ─────────────────────────────
    //   샤딩 모드일 때 strategy.key ↔ policy 정합성, sessions 권장,
    //   그리고 wrangler.toml 에 모든 샤드 D1 binding 이 선언되어 있는지 확인.
    try {
        const { normalizeDatabaseConfig, verifyShardConsistency, summarizeShardConfig } =
            await import('../core/shardConfig.js');
        const _dbn = normalizeDatabaseConfig(dokkebiConfig?.database);
        if (_dbn.sharded) {
            ok.push(`샤딩 구성 감지: ${summarizeShardConfig(_dbn)}`);
            const { warnings: _sw, errors: _se } = verifyShardConsistency(
                _dbn,
                dokkebiConfig?.policy,
                { strict: dokkebiConfig?.policy?.strict === true }
            );
            for (const w of _sw) warnings.push(`shard: ${w}`);
            for (const e of _se) errors.push(`shard: ${e}`);

            // wrangler.toml 에서 expected binding 이 모두 선언되어 있는지 점검
            try {
                const wrText = await fs.readFile(path.join(sourceRoot, 'wrangler.toml'), 'utf-8');
                const expected = [
                    _dbn.internalBinding || 'DB_INTERNAL',
                    ..._dbn.shards.map((s) => s.binding),
                ];
                const missing = expected.filter(
                    (b) => !new RegExp(`binding\\s*=\\s*"${b.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}"`).test(wrText)
                );
                if (missing.length) {
                    errors.push(
                        `wrangler.toml 에 누락된 D1 binding: ${missing.join(', ')} — \`dok db:provision\` 으로 자동 추가하거나 수동 등록 필요.`
                    );
                } else {
                    ok.push(`wrangler.toml 에 ${expected.length}개 D1 binding 모두 선언됨`);
                }
            } catch {
                warnings.push('wrangler.toml 을 읽을 수 없습니다 — 샤딩 binding 점검을 건너뜁니다.');
            }
        }

        // sessions opt-in 상태 안내 (단일/샤딩 공통)
        const _rawSess = dokkebiConfig?.database?.sessions;
        const _sessOn = _rawSess === true || (_rawSess && typeof _rawSess === 'object' && _rawSess.enabled !== false);
        if (_sessOn) ok.push('D1 Sessions API 활성 (read replica + bookmark)');
    } catch (e) {
        warnings.push(`shard preflight 점검 중 예외: ${String(e?.message || e)}`);
    }

    // ── 결과 출력 ────────────────────────────────────────────
    for (const o of ok) console.log(t('deploy.preflightOkItem', { msg: o }));
    for (const w of warnings) console.warn(t('deploy.preflightWarnItem', { msg: w }));
    for (const e of errors) console.error(t('deploy.preflightErrItem', { msg: e }));

    console.log('[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    const hasProblems = errors.length > 0 || (strict && warnings.length > 0);
    return { ok: !hasProblems, warnings, errors, passed: ok };
}
