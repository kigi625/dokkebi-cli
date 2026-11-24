/**
 * 보안 감사 (dok security --audit)
 *
 * 목적: "지금 설정이 실제로 어떤 보안 수준인지"를 한 번에 점검하고,
 *       한 줄 프리셋(`security.preset: 'production'`)으로 올리는 방법을 제시한다.
 *
 * 이 모듈은 부작용이 없다(파일 수정/배포 없음). 빌드/서브/보안 명령에서 공유한다.
 */

import path from 'path';
import fs from 'fs/promises';
import { loadDokkebiConfigMerged, applySecurityPreset } from './dokkebiConfigLoad.js';
import { normalizePolicyConfig } from './policyEngine.js';
import {
    normalizeAuthorizationConfig,
    resolveJwtSecret,
} from './authorizationPolicy.js';

function _parseEnv(text) {
    const out = {};
    for (const line of String(text || '').split('\n')) {
        const t = line.trim();
        if (!t || t.startsWith('#')) continue;
        const i = t.indexOf('=');
        if (i < 1) continue;
        out[t.slice(0, i).trim()] = t.slice(i + 1).trim().replace(/^["']|["']$/g, '');
    }
    return out;
}

async function _readText(p) {
    try { return await fs.readFile(p, 'utf-8'); } catch { return ''; }
}

async function _exists(p) {
    try { await fs.access(p); return true; } catch { return false; }
}

/**
 * security.preset: 'production' 빌드 프리플라이트.
 * 누락된 필수 값이 있으면 build/deploy 를 중단시켜 "반쯤 켜진 보안" 배포를 막는다.
 *
 * @returns {{ issues: string[], warnings: string[] }}
 */
export function checkProductionPreflight({
    security,
    policyMeta,
    authzMeta,
    panelIpGuardEnabled,
    env,
}) {
    const issues = [];
    const warnings = [];
    const e = env && typeof env === 'object' ? env : {};
    if (authzMeta?.enabled) {
        if (!resolveJwtSecret(e, authzMeta).secret) {
            issues.push('JWT 시크릿이 없습니다 — JWT_SECRET 또는 DOKKEBI_JWT_SECRET 를 설정하세요.');
        }
        if (authzMeta.mode !== 'strict') {
            issues.push('authorization.mode 가 strict 가 아닙니다 (production preset 은 strict 를 요구).');
        }
    }
    if (panelIpGuardEnabled) {
        const ips = String(e.DOKKEBI_PANEL_ALLOWED_IPS || e.DOKKEBI_ADMIN_ALLOWED_IPS || '').trim();
        if (!ips) issues.push('security.panelIpGuard 가 켜져 있는데 DOKKEBI_PANEL_ALLOWED_IPS 가 비어 있습니다.');
        const pw = String(e.DOKKEBI_ADMIN_PASSWORD || '');
        if (!pw) warnings.push('DOKKEBI_ADMIN_PASSWORD 미설정 — 관제 패널이 503 으로 비활성화됩니다.');
        else if (pw.length < 20) warnings.push('DOKKEBI_ADMIN_PASSWORD 길이가 20자 미만입니다.');
    }
    const origins = Array.isArray(security?.cors?.allowedOrigins)
        ? security.cors.allowedOrigins.filter(Boolean)
        : [];
    if (origins.length === 0 || origins.includes('*')) {
        issues.push('security.cors.allowedOrigins 에 실제 프론트 오리진을 지정하세요 (현재 비어있거나 `*`).');
    }
    if (policyMeta?.enabled && Object.keys(policyMeta.tables || {}).length === 0) {
        warnings.push('Tenant Policy 가 켜져 있지만 policy.tables 가 비어 있습니다 — 테이블별 tenantColumn 을 지정하세요.');
    }
    return { issues, warnings };
}

/**
 * @param {string} sourceRoot
 * @returns {Promise<{
 *   sourceRoot: string,
 *   findings: Array<{ severity: 'error'|'warn'|'info', id: string, title: string, fix?: string }>,
 *   counts: { error: number, warn: number, info: number },
 *   envNames: { jwt: string|null },
 * }>}
 */
export async function collectSecurityAudit(sourceRoot) {
    const root = path.resolve(sourceRoot);
    const findings = [];
    const add = (severity, id, title, fix) => findings.push({ severity, id, title, fix });

    const raw = await loadDokkebiConfigMerged(root, { quiet: true });
    if (!raw || Object.keys(raw).length === 0) {
        add('error', 'config.missing', 'dokkebi.config.js 를 찾을 수 없습니다.', '프로젝트 루트에서 실행하거나 설정 파일을 생성하세요.');
        return _finalize(root, findings, { jwt: null });
    }

    const envFile = _parseEnv(await _readText(path.join(root, '.env')));
    const env = { ...process.env, ...envFile };
    const eff = applySecurityPreset(raw, { quiet: true });
    const sec = eff.security && typeof eff.security === 'object' ? eff.security : {};
    const preset = String(sec.preset || '').toLowerCase();
    const level = String(sec.level || '').toLowerCase();

    // policy/authz normalize (build 와 동일 옵션)
    const policyMeta = normalizePolicyConfig(eff.policy, {
        authorizationEnabled: !!eff.authorization?.enabled,
        authLoginEnabled: !!eff.auth?.login?.enabled,
    });
    const authzMeta = normalizeAuthorizationConfig(eff.authorization);
    const policyAuto = eff.policy?.autoApply === true;
    const authzAuto = eff.authorization?.autoApply === true;
    const jwt = resolveJwtSecret(env, authzMeta);
    const claim = String(policyMeta?.claim || sec.policy?.claim || 'user_id');

    // ── 레벨/프리셋 ─────────────────────────────────────────
    if (preset === 'production') {
        add('info', 'preset.production', 'security.preset: production 이 적용되어 있습니다.');
    } else if (!level) {
        add('warn', 'level.unset', 'security.level / security.preset 이 설정되지 않았습니다.',
            "security: { preset: 'production' } 한 줄을 권장합니다.");
    } else if (level !== 'strict') {
        add('warn', 'level.notStrict', `security.level 이 '${level}' 입니다.`,
            "운영 환경은 security.level: 'strict' 또는 preset: 'production' 을 권장합니다.");
    } else {
        add('info', 'level.strict', "security.level: 'strict' 가 적용되어 있습니다.");
    }

    // ── Tenant Policy ───────────────────────────────────────
    if (policyMeta?.enabled && policyMeta.mode !== 'off') {
        const tables = policyMeta.tables || {};
        const names = Object.keys(tables);
        if (names.length === 0) {
            if (policyAuto) {
                add('info', 'policy.autoApply', 'policy.tables 가 비어 있지만 autoApply 로 빌드 시 자동 추론됩니다.');
            } else {
                add('warn', 'policy.noTables', 'Tenant Policy 가 켜져 있지만 policy.tables 가 비어 있습니다.', '테이블별 tenantColumn 을 지정하세요.');
            }
        }
        const ambiguous = names.filter((n) => {
            const tp = tables[n];
            if (!tp?.tenantColumn) return false;
            if (tp.sessionClaim) return false;
            return String(tp.tenantColumn).toLowerCase() !== claim.toLowerCase();
        });
        if (ambiguous.length > 0) {
            add('warn', 'policy.ambiguousTables',
                `테넌트 매핑이 모호한 테이블: ${ambiguous.join(', ')} (tenantColumn ≠ claim, sessionClaim 없음)`,
                '각 테이블에 sessionClaim 을 명시하거나 tenantColumn 을 claim 과 맞추세요. (optional 모드는 공개로 동작)');
        }
        if (String(policyMeta.mode).toLowerCase() === 'verify') {
            add('info', 'policy.verify', 'Tenant Policy verify 모드 — 필터 누락만 거부하고 자동 주입은 하지 않습니다.');
        }
    } else {
        add('warn', 'policy.off', 'Tenant Policy 가 비활성입니다.', '다중 사용자 데이터가 있으면 policy.enabled: true + mode: inject 를 권장합니다.');
    }

    // ── Authorization ───────────────────────────────────────
    if (authzMeta?.enabled) {
        if (authzMeta.mode !== 'strict') {
            add('warn', 'authz.warnMode', 'Authorization 이 warn 모드입니다 — 규칙 미매칭 요청이 통과합니다.',
                "mode: 'strict' 로 전환하고 '*': { auth: true } 기본 규칙을 추가하세요.");
        }
        if ((authzMeta.rules || []).length === 0) {
            if (authzAuto) {
                add('info', 'authz.autoApply', 'authorization.rules 가 비어 있지만 autoApply 로 빌드 시 추론됩니다.');
            } else {
                add(authzMeta.mode === 'strict' ? 'error' : 'warn', 'authz.noRules',
                    'Authorization 규칙이 하나도 없습니다.',
                    "예: rules: { '*': { auth: true }, 'DELETE:*': { roles: ['admin'] } }");
            }
        } else if (authzMeta.mode === 'strict' && !authzAuto
            && !authzMeta.rules.some((r) => r.op === '*' && r.table === '*')) {
            add('warn', 'authz.noWildcard', "Authorization strict 인데 '*' 기본 규칙이 없습니다.",
                "'*': { auth: true } 또는 공개 테이블별 public 규칙을 추가하세요.");
        }
        if (!jwt.secret) {
            add('error', 'jwt.missing', 'Authorization 이 켜져 있는데 JWT 시크릿이 없습니다.',
                'JWT_SECRET 또는 DOKKEBI_JWT_SECRET (32+ bytes) 을 설정하세요.');
        }
    } else {
        add('warn', 'authz.off', 'Authorization Policy 가 비활성입니다.', "authorization.enabled: true + mode: 'strict' 를 권장합니다.");
    }

    // ── JWT 다중 시크릿 ─────────────────────────────────────
    const j = env.JWT_SECRET, d = env.DOKKEBI_JWT_SECRET;
    if (j && d && j !== d) {
        add('warn', 'jwt.multiple', 'JWT_SECRET 과 DOKKEBI_JWT_SECRET 값이 다릅니다.',
            `검증은 ${jwt.source || '한 개'} 만 사용합니다. 하나로 통일하세요.`);
    }
    if (authzMeta?.jwtSecretEnvExplicit && !env[authzMeta.jwtSecretEnv]
        && jwt.secret && jwt.source !== authzMeta.jwtSecretEnv) {
        add('warn', 'jwt.explicitMissing', `authorization.jwtSecretEnv(${authzMeta.jwtSecretEnv}) 값이 없습니다.`,
            '해당 바인딩을 설정하거나 jwtSecretEnv 를 제거하세요.');
    }

    // ── Capabilities / Attestation ──────────────────────────
    const cap = sec.capabilities && typeof sec.capabilities === 'object' ? sec.capabilities : {};
    const features = cap.features && typeof cap.features === 'object' ? Object.keys(cap.features) : [];
    if (cap.enabled === true) {
        const secretName = String(cap.secretEnv || 'DOKKEBI_CAPABILITY_SECRET');
        const secret = env[secretName];
        if (!secret) {
            add('error', 'cap.missingSecret', `Signed Unlock Token 이 켜져 있는데 ${secretName} 이 없습니다.`,
                '32+ bytes 랜덤 값을 .env/Pages Secret 으로 설정하세요.');
        } else if (String(secret).length < 32) {
            add('warn', 'cap.weakSecret', `${secretName} 길이가 32자 미만입니다.`, '32+ bytes 랜덤 값을 사용하세요.');
        }
        if (features.length === 0) {
            add('warn', 'cap.noFeatures', 'capabilities.enabled=true 이지만 features 가 없습니다.', '보호할 고비용/관리 route 를 features 에 선언하세요.');
        }
        if (sec.attestation?.enabled !== true) {
            add('warn', 'cap.attestationOff', 'Capability 가 켜져 있는데 Bundle Attestation 이 꺼져 있습니다.',
                'security.attestation.enabled: true (또는 requires.attest) 를 권장합니다.');
        }
    } else if (features.length > 0) {
        add('warn', 'cap.disabled', 'features 가 선언되어 있지만 capabilities.enabled 가 아닙니다.');
    }

    // ── ADL / CSP / panel ───────────────────────────────────
    const adl = sec.activeDefense && typeof sec.activeDefense === 'object' ? sec.activeDefense : {};
    if (adl.enabled === true) {
        if (String(adl.mode || 'monitor') !== 'enforce') {
            add('warn', 'adl.monitor', 'Active Defense 가 monitor 모드입니다.', "운영 1주 후 mode: 'enforce' 로 전환하세요.");
        }
    } else {
        add('warn', 'adl.off', 'Active Defense 가 비활성입니다.', "security.activeDefense: { enabled: true, mode: 'enforce' } 를 권장합니다.");
    }
    if (sec.strictCsp !== true) {
        add('warn', 'csp.off', 'Strict CSP 가 비활성입니다.', 'security.strictCsp: true 로 인라인 XSS 심층방어를 켜세요.');
    }

    const panelEnabled = sec.panelIpGuard === true || sec.panelIpGuard?.enabled === true;
    if (!panelEnabled) {
        add('warn', 'panel.off', '관제 패널 IP allowlist 가 비활성입니다.', 'security.panelIpGuard: true + DOKKEBI_PANEL_ALLOWED_IPS 를 설정하세요.');
    } else {
        const ips = String(env.DOKKEBI_PANEL_ALLOWED_IPS || env.DOKKEBI_ADMIN_ALLOWED_IPS || '').trim();
        if (!ips) add('error', 'panel.noIps', 'panelIpGuard 가 켜져 있는데 DOKKEBI_PANEL_ALLOWED_IPS 가 비어 있습니다.');
        const pw = String(env.DOKKEBI_ADMIN_PASSWORD || '');
        if (!pw) add('warn', 'panel.noPassword', 'DOKKEBI_ADMIN_PASSWORD 가 없어 관제 패널이 비활성(503)입니다.');
        else if (pw.length < 20) add('warn', 'panel.weakPassword', 'DOKKEBI_ADMIN_PASSWORD 길이가 20자 미만입니다.');
    }

    // ── CORS ────────────────────────────────────────────────
    const origins = Array.isArray(sec.cors?.allowedOrigins) ? sec.cors.allowedOrigins.filter(Boolean) : [];
    if (origins.length === 0 || origins.includes('*')) {
        add(preset === 'production' ? 'error' : 'warn', 'cors.wildcard',
            'CORS allowedOrigins 가 비어 있거나 `*` 입니다.',
            '실제 프론트 오리진만 나열하세요 (예: allowedOrigins: ["https://app.example.com"]).');
    }

    // ── .gitignore ──────────────────────────────────────────
    const gi = await _readText(path.join(root, '.gitignore'));
    for (const entry of ['.env', '.dokkebi/', '.dev.vars', '.dokkebi-secrets.json']) {
        if (!gi.split('\n').map((l) => l.trim()).includes(entry)) {
            add('warn', 'gitignore.' + entry.replace(/[^a-z0-9]/gi, '_'), `.gitignore 에 ${entry} 가 없습니다.`, '시크릿/빌드 산출물이 커밋되지 않도록 추가하세요.');
        }
    }

    // ── Worker 템플릿 최신 여부 ─────────────────────────────
    const proxyMode = String(eff.proxyMode || 'server');
    if (proxyMode === 'serverless') {
        const dbTs = await _readText(path.join(root, 'worker', 'api', '_dokkebi', 'db.ts'));
        if (!dbTs) {
            add('warn', 'worker.missing', 'worker/api/_dokkebi/db.ts 가 없습니다.', 'dok build 로 워커를 생성하세요.');
        } else if (!dbTs.includes('findInternalTableRef') || !dbTs.includes('_az_checkSql')) {
            add('warn', 'worker.stale', '워커가 최신 보안 템플릿이 아닙니다.', '최신 dokkebi-cli 로 dok build 를 다시 실행하세요.');
        }
    }

    // ── WebAuthn ────────────────────────────────────────────
    if (sec.webauthn?.enabled === true) {
        add('info', 'webauthn.preview', "WebAuthn 은 아직 서버측 강제가 구현되지 않았습니다 — 인가/테넌트 정책으로 대체하세요.");
    }

    return _finalize(root, findings, { jwt: jwt.source });
}

function _finalize(sourceRoot, findings, extra) {
    const counts = { error: 0, warn: 0, info: 0 };
    for (const f of findings) counts[f.severity] += 1;
    return { sourceRoot, findings, counts, envNames: { jwt: extra?.jwt ?? null } };
}

const ICON = { error: '❌', warn: '⚠️ ', info: 'ℹ️ ' };

/**
 * @param {Awaited<ReturnType<typeof collectSecurityAudit>>} report
 */
export function formatSecurityAudit(report) {
    const lines = [];
    lines.push('');
    lines.push('[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    lines.push('[dokkebi] 🔎 Security audit — ' + report.sourceRoot);
    lines.push('[dokkebi] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    for (const f of report.findings) {
        lines.push(`  ${ICON[f.severity] || '•'} [${f.id}] ${f.title}`);
        if (f.fix) lines.push(`       → ${f.fix}`);
    }
    lines.push('');
    lines.push(`Summary: ${report.counts.error} error(s), ${report.counts.warn} warning(s), ${report.counts.info} info`);
    const showPreset = report.findings.some((f) => f.severity === 'error' || f.id === 'level.unset' || f.id === 'level.notStrict');
    if (showPreset) {
        lines.push('');
        lines.push("Recommended one-liner (dokkebi.config.js):");
        lines.push("  security: { preset: 'production' }");
        lines.push("Required .env / Pages Secrets:");
        lines.push('  JWT_SECRET=<32+ bytes>                     # authorization');
        lines.push('  DOKKEBI_ADMIN_PASSWORD=<20+ chars>         # ops panel');
        lines.push('  DOKKEBI_PANEL_ALLOWED_IPS=<ip,cidr,...>    # panel IP allowlist');
        lines.push('  DOKKEBI_CAPABILITY_SECRET=<32+ bytes>      # if capabilities enabled');
        lines.push('  security.cors.allowedOrigins: ["https://your-frontend"]');
    }
    lines.push('');
    return lines.join('\n');
}
