/**
 * dok update — 기존 프로젝트에 dokkebi 최신 버전 적용
 *
 * 업데이트 대상:
 *   1. worker/api/_dokkebi/*.ts (서버리스 모드 전용)
 *      - handshake.ts / db.ts / log.ts — 보안/기능 개선 반영
 *      - admin.ts                      — 신규 파일 (없을 경우 추가)
 *   2. backend/db/migrations/XXX_dokkebi_system_tables.sql
 *      - _dokkebi_requests, _dokkebi_security 등 누락된 시스템 테이블 추가
 *   3. .env.example — 누락된 환경변수 항목 append
 *   4. dokkebi.config.js — 신규 설정 기본값 추가 (security.panelIpGuard, logging.level 등)
 *
 * 사용자 코드(backend/, frontend/, .env)는 절대 수정하지 않습니다.
 */

import path from 'path';
import fs   from 'fs/promises';
import { existsSync, readFileSync } from 'fs';
import { createReadStream } from 'fs';
import readline from 'readline';
import { pathToFileURL } from 'url';

import { workerHandshake, workerDb, workerLog, workerAdmin, workerAdminApi, systemTableSql } from '../core/projectGenerator.js';
import { emitPayloadWireTs, disabledWireRuntimeJson } from '../core/payloadWireRuntime.js';
import { applyDokkebiConfigAliases } from '../core/dokkebiConfigLoad.js';
import { dokkebiClientTsSource } from '../../packages/dokkebi-vite-plugin/src/index.js';
import { C } from './serve.js';
import { t } from '../i18n/index.js';
import { ensureCliUpdatedBeforeProject } from '../core/cliSelfUpdate.js';

// C.gray 는 serve.js 에 있으나 C.muted 는 없음 — gray 로 대체
C.muted = C.gray;

// ─────────────────────────────────────────────────────────────
// 도깨비 managed 파일 정의
// ─────────────────────────────────────────────────────────────

/**
 * 각 파일의 현재 최신 버전.
 * 파일 상단에 `// @dokkebi-version: N` 헤더로 설치된 버전을 추적합니다.
 * 템플릿을 수정할 때는 해당 파일의 version 을 올리고
 * projectGenerator.js 의 템플릿 문자열 맨 위 `@dokkebi-version` 숫자도 함께 올리세요.
 */
const WORKER_FILES = [
    {
        rel:      'worker/api/_dokkebi/handshake.ts',
        generate: () => workerHandshake(),
        version:  3,
        desc:     'ECDH 핸드셰이크 Worker',
    },
    {
        rel:      'worker/api/_dokkebi/_payloadWire.ts',
        generate: () => emitPayloadWireTs(disabledWireRuntimeJson()),
        version:  2,
        desc:     '암호화 페이로드 wire (회전 + PoW) — dok build 시 최신으로 덮어씀',
    },
    {
        rel:      'worker/api/_dokkebi/db.ts',
        // allowlist / query-registry / tenant-policy / authorization / ADL 은 dok build
        // 단계에서 임베드됩니다. update 직후에는 모두 null 자리 표시자 상태이며
        // 반드시 `dok build` 재실행 필요. Tenant Policy / Authorization / ADL 은 opt-in.
        generate: (cfg) => workerDb(cfg.database?.type || 'd1', null, null, null, null, null, null, null, null, null),
        version:  10,
        desc:     'DB 프록시 Worker (Allowlist + Query Registry + Tenant Policy + Authorization + Active Defense)',
        requiresRebuild: true,
    },
    {
        rel:      'worker/api/_dokkebi/log.ts',
        generate: () => workerLog(),
        version:  3,
        desc:     '로그 수집 Worker',
    },
    {
        rel:      'worker/api/_dokkebi/_panel.ts',
        generate: (cfg) => workerAdmin(cfg._name || 'dokkebi', null, { enabled: panelIpGuardConfigEnabled(cfg) }),
        version:  4,
        desc:     '관제 어드민 HTML Worker (능동방어 탭 추가)',
    },
    {
        rel:      'worker/api/_dokkebi/_panel/[[path]].ts',
        generate: (cfg) => workerAdminApi(cfg._name || 'dokkebi', null, { enabled: panelIpGuardConfigEnabled(cfg) }),
        version:  4,
        desc:     '관제 어드민 API Worker (능동방어 엔드포인트 추가)',
    },
];

const ENV_ADDITIONS = `
# ── 관제 어드민 (선택) ───────────────────────────────────────
# 설정 시 /_dokkebi/_panel 경로로 관제 대시보드 접속 가능
# DOKKEBI_ADMIN_PASSWORD=your_admin_password
# security.panelIpGuard=true 일 때 사용. 쉼표 구분 IP/CIDR allowlist.
# 예: 203.0.113.10,198.51.100.0/24
# DOKKEBI_PANEL_ALLOWED_IPS=
`;

const CONFIG_PANEL_IP_GUARD_SNIPPET = `  security: {
    // 관제 어드민 IP allowlist. true면 DOKKEBI_PANEL_ALLOWED_IPS 필요.
    panelIpGuard: false,
  },
`;

/** 원격 로그 수집 최소 레벨 — dok build / 부트스트랩과 동일 의미 (생략 시 error 와 동등) */
const CONFIG_LOGGING_SNIPPET = `  logging: {
    /** 원격 로그 수집 최소 레벨 — 생략 시 CLI 기본은 error (Spring root level 과 유사) */
    level: 'error', // 'debug' | 'log' | 'info' | 'warn' | 'error'
  },
`;

/**
 * SEO 자동화 — zero-config 가 기본이지만, 동적 라우트 중 자동 매칭이 어려운 경우는
 * dynamic[] 에 SQL 을 명시해야 합니다. 빈 dynamic 으로 시작하고, dok build 후
 * dist/.dokkebi/seo-report.md 의 "동적 라우트 스킵" 섹션을 참고해 채우세요.
 *
 * ⚠ 보안: dynamic[].query 의 SELECT 결과는 prerender HTML 에 그대로 노출됩니다.
 *           이메일/비밀번호 해시/내부 ID 등 민감 컬럼은 절대 SELECT 하지 마세요.
 */
const CONFIG_SEO_SNIPPET = `  seo: {
    // enabled: true,  // 기본값 — 끄려면 false
    // baseUrl: 'https://www.example.com',  // 미지정 시 deploy.cloudflarePages.domain 자동 추론
    // siteName: 'My Site',                  // 미지정 시 package.json#name 자동 추론
    // image: '/og-default.png',             // public/og-default.png 가 있으면 자동 사용

    // 동적 라우트 SEO — dok build 가 D1 을 enumerate 해서 정적 HTML/sitemap 생성.
    // dist/.dokkebi/seo-report.md 의 "동적 라우트 스킵" 항목을 보고 필요한 만큼 추가하세요.
    // 예시:
    //   { path: '/posts/:slug', table: 'posts' }                        // 자동 매칭 (가장 단순)
    //   { path: '/:lang/:user/post/:slug', query: 'SELECT ...' }        // JOIN 필요 시 SQL 명시
    dynamic: [],
  },
`;

// ─────────────────────────────────────────────────────────────
// 유틸
// ─────────────────────────────────────────────────────────────

function ts() {
    return `[${new Date().toLocaleTimeString('ko-KR')}]`;
}

async function readFileSafe(filePath) {
    try { return await fs.readFile(filePath, 'utf-8'); }
    catch { return null; }
}

/** 파일 상단의 `// @dokkebi-version: N` 헤더에서 버전 숫자를 읽음. 없으면 0 반환 */
function readInstalledVersion(content) {
    if (!content) return 0;
    const m = content.match(/^\/\/\s*@dokkebi-version:\s*(\d+)/m);
    return m ? parseInt(m[1], 10) : 0;
}

async function loadDokConfig(sourceRoot) {
    const cfgPath = path.join(sourceRoot, 'dokkebi.config.js');
    if (!existsSync(cfgPath)) return null;
    try {
        const mod = await import(pathToFileURL(cfgPath).href + '?t=' + Date.now());
        const raw = mod.default || mod;
        return applyDokkebiConfigAliases(raw, { quiet: false });
    } catch { return null; }
}

function configHasPanelIpGuard(content) {
    if (!content) return false;
    return /\bpanelIpGuard\s*:/.test(content)
        || /\badminPanel\s*:\s*\{[\s\S]*?\bipAllowlist\s*:/.test(content);
}

/** 최상위에 \`logging:\` 속성이 있으면 true (주석 줄 제외) */
function configHasLogging(content) {
    if (!content) return false;
    const lines = content.split(/\r?\n/);
    for (const line of lines) {
        if (/^\s*\/\//.test(line)) continue;
        if (/^\s*logging\s*:/.test(line)) return true;
    }
    return false;
}

/**
 * \`frontend: { ... },\` 블록 직후에 logging 블록 삽입. frontend 없으면 마지막 \`\n};\` 앞에 추가.
 */
function findInsertAfterFrontendBlock(content) {
    const re = /^(\s*)frontend\s*:\s*\{/m;
    const m = content.match(re);
    if (!m || m.index === undefined) return -1;
    const braceOpen = content.indexOf('{', m.index);
    if (braceOpen < 0) return -1;
    let depth = 0;
    const n = content.length;
    for (let i = braceOpen; i < n; i++) {
        const c = content[i];
        if (c === '{') depth++;
        else if (c === '}') {
            depth--;
            if (depth === 0) {
                let j = i + 1;
                while (j < n && /\s/.test(content[j])) j++;
                if (content[j] === ',') j++;
                while (j < n && /\s/.test(content[j])) j++;
                if (j < n && content[j] === '\r') j++;
                if (j < n && content[j] === '\n') return j + 1;
                return j;
            }
        }
    }
    return -1;
}

function addLoggingToConfig(content) {
    if (!content || configHasLogging(content)) return content;
    const insertAt = findInsertAfterFrontendBlock(content);
    if (insertAt >= 0) {
        return content.slice(0, insertAt) + CONFIG_LOGGING_SNIPPET + '\n' + content.slice(insertAt);
    }
    const idx = content.lastIndexOf('\n};');
    if (idx >= 0) {
        return content.slice(0, idx) + '\n' + CONFIG_LOGGING_SNIPPET + content.slice(idx);
    }
    return content.trimEnd() + '\n\n' + CONFIG_LOGGING_SNIPPET;
}

/** 최상위에 \`seo:\` 속성이 있으면 true (주석 줄 제외) */
function configHasSeo(content) {
    if (!content) return false;
    const lines = content.split(/\r?\n/);
    for (const line of lines) {
        if (/^\s*\/\//.test(line)) continue;
        if (/^\s*seo\s*:/.test(line)) return true;
    }
    return false;
}

function addSeoToConfig(content) {
    if (!content || configHasSeo(content)) return content;
    // 가능하면 deploy 블록 직후, 없으면 마지막 `\n};` 직전.
    const re = /^(\s*)deploy\s*:\s*\{/m;
    const m = content.match(re);
    if (m && m.index !== undefined) {
        const braceOpen = content.indexOf('{', m.index);
        if (braceOpen >= 0) {
            let depth = 0;
            const n = content.length;
            for (let i = braceOpen; i < n; i++) {
                const c = content[i];
                if (c === '{') depth++;
                else if (c === '}') {
                    depth--;
                    if (depth === 0) {
                        let j = i + 1;
                        while (j < n && /\s/.test(content[j])) j++;
                        if (content[j] === ',') j++;
                        while (j < n && /\s/.test(content[j])) j++;
                        if (j < n && content[j] === '\r') j++;
                        if (j < n && content[j] === '\n') j++;
                        return content.slice(0, j) + '\n' + CONFIG_SEO_SNIPPET + content.slice(j);
                    }
                }
            }
        }
    }
    const idx = content.lastIndexOf('\n};');
    if (idx >= 0) {
        return content.slice(0, idx) + '\n' + CONFIG_SEO_SNIPPET + content.slice(idx);
    }
    return content.trimEnd() + '\n\n' + CONFIG_SEO_SNIPPET;
}

function addPanelIpGuardToConfig(content) {
    if (!content || configHasPanelIpGuard(content)) return content;
    const lines = content.split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*\/\//.test(line)) continue;
        const m = /^(\s*)security\s*:\s*\{/.exec(line);
        if (!m) continue;
        const indent = m[1] + '  ';
        lines.splice(
            i + 1,
            0,
            `${indent}// 관제 어드민 IP allowlist. true면 DOKKEBI_PANEL_ALLOWED_IPS 필요.`,
            `${indent}panelIpGuard: false,`,
        );
        return lines.join('\n');
    }

    const insert = '\n' + CONFIG_PANEL_IP_GUARD_SNIPPET;
    const idx = content.lastIndexOf('\n};');
    if (idx >= 0) {
        return content.slice(0, idx) + insert + content.slice(idx);
    }
    return content.trimEnd() + '\n\n' + CONFIG_PANEL_IP_GUARD_SNIPPET;
}

function panelIpGuardConfigEnabled(cfg) {
    return cfg?.security?.panelIpGuard === true
        || cfg?.security?.panelIpGuard?.enabled === true
        || cfg?.security?.adminPanel?.ipAllowlist === true
        || cfg?.security?.adminPanel?.ipAllowlist?.enabled === true;
}

async function findMigrationDir(sourceRoot) {
    const candidates = [
        path.join(sourceRoot, 'backend', 'db', 'migrations'),
        path.join(sourceRoot, 'db', 'migrations'),
        path.join(sourceRoot, 'migrations'),
    ];
    for (const d of candidates) {
        if (existsSync(d)) return d;
    }
    return null;
}

/** 마이그레이션 디렉토리에서 이미 정의된 테이블 이름 수집 */
async function getDefinedTables(migrationsDir) {
    const defined = new Set();
    if (!migrationsDir) return defined;
    const files = (await fs.readdir(migrationsDir)).filter(f => f.endsWith('.sql')).sort();
    for (const file of files) {
        const content = await fs.readFile(path.join(migrationsDir, file), 'utf-8');
        for (const m of content.matchAll(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?"?([^"\s(]+)"?/gi)) {
            defined.add(m[1]);
        }
    }
    return defined;
}

/** 다음 마이그레이션 파일명 생성 (003_xxx.sql 형태) */
async function nextMigrationName(migrationsDir) {
    const files = (await fs.readdir(migrationsDir)).filter(f => f.endsWith('.sql')).sort();
    const maxNum = files.reduce((max, f) => {
        const m = f.match(/^(\d+)/);
        return m ? Math.max(max, parseInt(m[1], 10)) : max;
    }, 0);
    const nextNum = String(maxNum + 1).padStart(3, '0');
    return `${nextNum}_dokkebi_system_tables.sql`;
}

// ─────────────────────────────────────────────────────────────
// Frontend 마이그레이션 — window.dokkebi → ./lib/dokkebi (실제 파일 import)
// ─────────────────────────────────────────────────────────────
//
// dokkebi v6.x+ 부터 `window.dokkebi` 전역 노출이 제거되었습니다 (XSS 표면 축소).
// 대신 frontend/src/lib/dokkebi.ts 실제 파일을 자동 emit 하고,
// 사용자 코드는 `import { dokkebi } from '<상대경로>/lib/dokkebi'` 형태로 가져옵니다.
// vite-plugin 등록이나 vite.config 수정 없이 작동합니다.

const FRONTEND_EXTS = new Set(['.ts', '.tsx', '.js', '.jsx', '.vue']);

/** frontend 소스 루트 후보들 (사용자 프로젝트마다 구조 다름) */
function frontendSrcCandidates(sourceRoot) {
    return [
        path.join(sourceRoot, 'frontend', 'src'),
        path.join(sourceRoot, 'src'),
        path.join(sourceRoot, 'app'),
        path.join(sourceRoot, 'web', 'src'),
    ];
}

/** 프로젝트의 frontend src 디렉토리 발견 (첫 번째 존재하는 후보) */
async function findFrontendSrcDir(sourceRoot) {
    for (const cand of frontendSrcCandidates(sourceRoot)) {
        if (existsSync(cand)) {
            try {
                const stat = await fs.stat(cand);
                if (stat.isDirectory()) return cand;
            } catch { /* noop */ }
        }
    }
    return null;
}

/** 디렉토리 재귀 스캔 (node_modules / dist / build / .* 제외) */
async function walkFrontendFiles(dir, acc = []) {
    let entries = [];
    try { entries = await fs.readdir(dir, { withFileTypes: true }); }
    catch { return acc; }
    for (const ent of entries) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) {
            if (ent.name.startsWith('.')) continue;
            if (ent.name === 'node_modules' || ent.name === 'dist' || ent.name === 'build') continue;
            await walkFrontendFiles(full, acc);
        } else if (ent.isFile()) {
            const ext = path.extname(ent.name).toLowerCase();
            if (FRONTEND_EXTS.has(ext)) acc.push(full);
        }
    }
    return acc;
}

/** 파일이 window.dokkebi 또는 dokkebiReady 또는 잘못된 dokkebi:client import 패턴을 갖고 있는지 */
function frontendNeedsMigration(content) {
    if (!content) return false;
    return /\bwindow\.dokkebi\b/.test(content)
        || /\(window as any\)\.dokkebi\b/.test(content)
        || /\bwindow\.dokkebiReady\b/.test(content)
        || /from\s+['"]dokkebi:client['"]/.test(content);
}

/** 정규식 메타 문자 이스케이프 */
function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** 파일이 이미 importPath 에서 dokkebi 를 가져오고 있는지 (정확한 path 매칭) */
function alreadyImportsDokkebi(content, importPath) {
    if (!importPath) {
        // 일반 매칭 (dokkebi:client, 또는 어떤 경로든 끝이 dokkebi 인 import)
        return /import\s*\{\s*[^}]*\bdokkebi\b[^}]*\}\s*from\s*['"][^'"]*(?:dokkebi:client|\/dokkebi)['"]/.test(content);
    }
    const escaped = escapeRegex(importPath);
    const re = new RegExp(`import\\s*\\{\\s*[^}]*\\bdokkebi\\b[^}]*\\}\\s*from\\s*['"]${escaped}['"]`);
    return re.test(content);
}

/**
 * filePath 파일에서 frontendSrcDir/lib/dokkebi.ts 로 가는 상대 경로를 계산.
 * 예: frontend/src/lib/api.ts → './dokkebi'
 *     frontend/src/composables/useDokkebi.ts → '../lib/dokkebi'
 *     frontend/src/views/foo/bar.tsx → '../../lib/dokkebi'
 */
function relativeImportPath(filePath, frontendSrcDir) {
    const fileDir = path.dirname(filePath);
    const target = path.join(frontendSrcDir, 'lib', 'dokkebi');
    let rel = path.relative(fileDir, target);
    // 상대 경로는 항상 ./ 또는 ../ 로 시작해야 ES module import 로 인식됨
    if (!rel.startsWith('.')) rel = './' + rel;
    // OS path separator 를 / 로 정규화 (윈도우 호환)
    rel = rel.split(path.sep).join('/');
    return rel;
}

/**
 * frontend 파일 내용을 마이그레이션.
 *
 * 변환 규칙:
 *   1) (window as any).dokkebi.X          → dokkebi.X
 *   2) window.dokkebi.X                   → dokkebi.X        (.dokkebiReady 는 보호)
 *   3) window.dokkebi?.X                  → dokkebi.X        (optional chaining)
 *   4) await window.dokkebiReady          → await dokkebi.ready()
 *   5) typeof window.dokkebi              → 의미 보존 시 'undefined' 비교를 제거하기 어려움 → 그대로 두고 안내
 *   6) from 'dokkebi:client'              → from '<상대경로>/lib/dokkebi'
 *   7) 변환이 1회 이상 발생했고 import 가 없으면 자동 추가
 *
 * @param {string} content 원본
 * @param {string} filePath 절대 경로
 * @param {string} frontendSrcDir frontend src 절대 경로 (lib/dokkebi.ts 가 있을 위치 기준)
 * @returns {{ next: string, changed: boolean, summary: string[] }}
 */
function migrateFrontendContent(content, filePath, frontendSrcDir) {
    const summary = [];
    let next = content;
    const importPath = relativeImportPath(filePath, frontendSrcDir);

    const wasAnyDok        = /\(window as any\)\.dokkebi\b/.test(next);
    const wasWinDok        = /\bwindow\.dokkebi(?=\.[A-Za-z_$])/.test(next);
    const wasWinDokOpt     = /\bwindow\.dokkebi\?\.[A-Za-z_$]/.test(next);
    const wasReady         = /\bawait\s+window\.dokkebiReady\b/.test(next);
    const wasVirtualImport = /from\s+['"]dokkebi:client['"]/.test(next);

    // 1) (window as any).dokkebi.X  →  dokkebi.X
    next = next.replace(/\(window as any\)\.dokkebi\b/g, 'dokkebi');

    // 2) window.dokkebi.X  →  dokkebi.X
    next = next.replace(/\bwindow\.dokkebi(?=\.[A-Za-z_$])/g, 'dokkebi');

    // 3) window.dokkebi?.X  →  dokkebi.X   (optional chaining 제거)
    next = next.replace(/\bwindow\.dokkebi\?\.([A-Za-z_$])/g, 'dokkebi.$1');

    // 4) await window.dokkebiReady  →  await dokkebi.ready()
    next = next.replace(/\bawait\s+window\.dokkebiReady\b/g, 'await dokkebi.ready()');

    // 5) typeof window.dokkebi?.X === 'function'  →  typeof dokkebi.X === 'function'
    //    (사용자가 호환 가드를 작성했을 때 - safe 한 변환)
    next = next.replace(/\btypeof\s+window\.dokkebi\?\.([A-Za-z_$]+)\b/g, 'typeof dokkebi.$1');
    next = next.replace(/\btypeof\s+window\.dokkebi\.([A-Za-z_$]+)\b/g, 'typeof dokkebi.$1');

    // 6) from 'dokkebi:client'  →  from '<상대경로>/lib/dokkebi'
    next = next.replace(/from\s+(['"])dokkebi:client\1/g, `from '${importPath}'`);

    const changed = next !== content;

    // 7) import 자동 추가 (필요하고 아직 없을 때만)
    if (changed && !alreadyImportsDokkebi(next, importPath)) {
        const ext = path.extname(filePath).toLowerCase();
        const importLine = `import { dokkebi } from '${importPath}';`;

        if (ext === '.vue') {
            const scriptOpen = next.match(/<script\b[^>]*>\r?\n?/);
            if (scriptOpen) {
                const insertAt = scriptOpen.index + scriptOpen[0].length;
                const after = next.slice(insertAt);
                const lastImportMatch = after.match(/^(?:import\s[^;]+;\s*\n)+/);
                if (lastImportMatch) {
                    const afterImports = insertAt + lastImportMatch[0].length;
                    next = next.slice(0, afterImports) + importLine + '\n' + next.slice(afterImports);
                } else {
                    next = next.slice(0, insertAt) + importLine + '\n' + next.slice(insertAt);
                }
            }
        } else {
            const headerImportMatch = next.match(/^(?:(?:[^\n]*\n)*?)(?:import\s[^;\n]+;[^\n]*\n)+/);
            if (headerImportMatch) {
                const insertAt = headerImportMatch[0].length;
                next = next.slice(0, insertAt) + importLine + '\n' + next.slice(insertAt);
            } else {
                next = importLine + '\n' + next;
            }
        }
        summary.push(`import { dokkebi } from '${importPath}' 추가`);
    }

    if (wasVirtualImport) summary.push(`from 'dokkebi:client' → from '${importPath}'`);
    if (wasAnyDok)        summary.push('(window as any).dokkebi → dokkebi');
    if (wasWinDok)        summary.push('window.dokkebi → dokkebi');
    if (wasWinDokOpt)     summary.push('window.dokkebi?.X → dokkebi.X');
    if (wasReady)         summary.push('await window.dokkebiReady → await dokkebi.ready()');

    return { next, changed, summary };
}

/**
 * frontend src 디렉토리를 발견하고, 그 안의 파일 중 마이그레이션 필요한 항목 목록을 반환.
 * @returns {Promise<{ frontendSrcDir: string|null, targets: Array<{path:string, summary:string[]}> }>}
 */
async function scanFrontendForMigration(sourceRoot) {
    const frontendSrcDir = await findFrontendSrcDir(sourceRoot);
    if (!frontendSrcDir) return { frontendSrcDir: null, targets: [] };

    const files = [];
    await walkFrontendFiles(frontendSrcDir, files);

    const targets = [];
    for (const f of files) {
        // 우리가 emit 한 dokkebi.ts 자체는 마이그레이션 대상이 아님
        if (path.relative(frontendSrcDir, f).split(path.sep).join('/') === 'lib/dokkebi.ts') continue;
        const content = await readFileSafe(f);
        if (!content) continue;
        if (!frontendNeedsMigration(content)) continue;
        const { changed, summary } = migrateFrontendContent(content, f, frontendSrcDir);
        if (changed) targets.push({ path: f, summary });
    }
    return { frontendSrcDir, targets };
}

// ─────────────────────────────────────────────────────────────
// 메인 업데이트 로직
// ─────────────────────────────────────────────────────────────

export async function runUpdate(src, options = {}) {
    const dryRun = options.dryRun || options['dry-run'] || false;
    const force  = options.force || false;
    const normalizedOptions = {
        dryRun,
        force,
        skipCliUpdate: options.skipCliUpdate || options['skip-cli-update'] || false,
    };

    await ensureCliUpdatedBeforeProject(src, normalizedOptions, { askConfirm });

    const sourceRoot = src ? path.resolve(src) : process.cwd();

    console.log(`\n${C.bold}${t('update.header')}${C.reset} ${C.cyan}${sourceRoot}${C.reset}\n`);

    const cfg = await loadDokConfig(sourceRoot);
    if (!cfg) {
        console.error(`${C.red}${t('update.noConfig')}${C.reset}`);
        console.error(t('update.noConfigHint'));
        process.exit(1);
    }

    const projectName = path.basename(sourceRoot);
    cfg._name = projectName;
    const proxyMode = cfg.proxyMode || 'server';
    const dbType    = cfg.database?.type || 'd1';

    console.log(t('update.project', { name: `${C.bold}${projectName}${C.reset}` }));
    console.log(t('update.mode', { mode: `${proxyMode === 'serverless' ? C.cyan + 'serverless' : C.yellow + 'server'}${C.reset}` }));
    console.log(t('update.dbType', { db: dbType }) + '\n');

    const changes = []; // { type: 'new'|'update'|'skip', desc, path }

    const configPath = path.join(sourceRoot, 'dokkebi.config.js');
    let configNeedsPanelIpGuard = false;
    let configNeedsLogging = false;
    let configNeedsSeo = false;
    if (existsSync(configPath)) {
        const configContent = await readFileSafe(configPath);
        if (configContent) {
            configNeedsPanelIpGuard = !configHasPanelIpGuard(configContent);
            configNeedsLogging = !configHasLogging(configContent);
            configNeedsSeo = !configHasSeo(configContent);
        }
        if (configNeedsPanelIpGuard || configNeedsLogging || configNeedsSeo) {
            const bits = [];
            if (configNeedsLogging) bits.push('logging');
            if (configNeedsPanelIpGuard) bits.push('security.panelIpGuard');
            if (configNeedsSeo) bits.push('seo');
            changes.push({
                type: 'update',
                desc: `dokkebi.config.js (${bits.join(' · ')})`,
                path: 'dokkebi.config.js',
            });
        } else {
            changes.push({
                type: 'skip',
                desc: 'dokkebi.config.js',
                path: 'dokkebi.config.js',
                reason: 'logging · panelIpGuard · seo 이미 반영',
            });
        }
    }

    // ── 1. Worker 파일 (서버리스 모드만) ──────────────────────
    if (proxyMode === 'serverless') {
        for (const wf of WORKER_FILES) {
            const absPath = path.join(sourceRoot, wf.rel);
            const exists  = existsSync(absPath);

            if (!exists) {
                changes.push({ type: 'new', desc: wf.desc, path: wf.rel, wf });
                continue;
            }

            // 설치된 버전과 템플릿 버전 비교
            const current          = await readFileSafe(absPath);
            const installedVersion = readInstalledVersion(current);

            if (installedVersion < wf.version) {
                changes.push({
                    type: 'update', desc: wf.desc, path: wf.rel, wf,
                    reason: `v${installedVersion} → v${wf.version}`,
                });
            } else {
                changes.push({ type: 'skip', desc: wf.desc, path: wf.rel, reason: `v${installedVersion} (최신)` });
            }
        }
    }

    // ── 2. 마이그레이션 — 누락된 시스템 테이블 ───────────────
    const migrationsDir = await findMigrationDir(sourceRoot);
    const sqlMap        = systemTableSql();
    let newMigrationNeeded = false;
    const missingTables    = [];

    if (migrationsDir) {
        const defined = await getDefinedTables(migrationsDir);
        for (const tbl of Object.keys(sqlMap)) {
            if (!defined.has(tbl)) {
                missingTables.push(tbl);
                newMigrationNeeded = true;
            }
        }
        if (newMigrationNeeded) {
            const migName = await nextMigrationName(migrationsDir);
            changes.push({ type: 'new', desc: t('update.missingTablesDesc', { tables: missingTables.join(', ') }), path: path.join(path.relative(sourceRoot, migrationsDir), migName) });
        } else {
            changes.push({ type: 'skip', desc: t('update.sysTablesSkip'), path: '<all exist>', reason: t('update.sysTablesExist') });
        }
    } else {
        changes.push({ type: 'skip', desc: t('update.noMigrationDir'), path: '—', reason: t('update.noMigrationDirReason') });
    }

    const envExamplePath = path.join(sourceRoot, '.env.example');
    let envExampleNeedsUpdate = false;
    let envExampleAddition = '';
    if (existsSync(envExamplePath)) {
        const envContent = await readFileSafe(envExamplePath);
        if (envContent && (!envContent.includes('DOKKEBI_ADMIN_PASSWORD') || !envContent.includes('DOKKEBI_PANEL_ALLOWED_IPS'))) {
            envExampleNeedsUpdate = true;
            envExampleAddition = !envContent.includes('DOKKEBI_ADMIN_PASSWORD')
                ? ENV_ADDITIONS
                : `\n# 관제 어드민 IP allowlist (선택)\n# security.panelIpGuard=true 일 때 사용. 쉼표 구분 IP/CIDR allowlist.\n# 예: 203.0.113.10,198.51.100.0/24\n# DOKKEBI_PANEL_ALLOWED_IPS=\n`;
            changes.push({ type: 'update', desc: t('update.envExampleAdd'), path: '.env.example' });
        } else {
            changes.push({ type: 'skip', desc: t('update.envExampleSkip'), path: '.env.example', reason: t('update.envExampleSkipReason') });
        }
    }

    // ── 3. Frontend 코드 — window.dokkebi → ./lib/dokkebi 자동 변환 ──
    const frontendScan = await scanFrontendForMigration(sourceRoot);
    const frontendMigrationTargets = frontendScan.targets;
    const frontendSrcDir = frontendScan.frontendSrcDir;

    if (frontendMigrationTargets.length > 0) {
        for (const tgt of frontendMigrationTargets) {
            changes.push({
                type: 'update',
                desc: `Frontend: ${tgt.summary.join(' · ')}`,
                path: path.relative(sourceRoot, tgt.path),
                frontendTarget: tgt,
            });
        }
    } else {
        changes.push({
            type: 'skip',
            desc: 'Frontend (window.dokkebi 마이그레이션)',
            path: '—',
            reason: frontendSrcDir
                ? 'window.dokkebi 사용처 없음 또는 이미 마이그레이션 완료'
                : 'frontend/src 디렉토리를 찾지 못함',
        });
    }

    // ── 4. Frontend 실제 클라이언트 파일 (frontend/src/lib/dokkebi.ts) ──
    //    가상 모듈이 아닌 실제 .ts 파일로 emit → vite-plugin 등록 불필요.
    let frontendClientFileTarget = null;
    let frontendClientFileNeedsUpdate = false;
    if (frontendSrcDir) {
        frontendClientFileTarget = path.join(frontendSrcDir, 'lib', 'dokkebi.ts');
        if (!existsSync(frontendClientFileTarget)) {
            changes.push({
                type: 'new',
                desc: 'dokkebi 클라이언트 파일 (frontend/src/lib/dokkebi.ts)',
                path: path.relative(sourceRoot, frontendClientFileTarget),
            });
        } else {
            // 내용 비교 — 다르면 업데이트
            const current = await readFileSafe(frontendClientFileTarget);
            const expected = dokkebiClientTsSource();
            if (current !== expected) {
                frontendClientFileNeedsUpdate = true;
                changes.push({
                    type: 'update',
                    desc: 'dokkebi 클라이언트 파일 (frontend/src/lib/dokkebi.ts)',
                    path: path.relative(sourceRoot, frontendClientFileTarget),
                });
            } else {
                changes.push({
                    type: 'skip',
                    desc: 'dokkebi 클라이언트 파일 (frontend/src/lib/dokkebi.ts)',
                    path: path.relative(sourceRoot, frontendClientFileTarget),
                    reason: '이미 최신',
                });
            }
        }
    }

    // ── 4-b. 레거시 frontend/src/dokkebi-client.d.ts 정리 (있으면 삭제) ──
    let legacyDtsToDelete = null;
    if (frontendSrcDir) {
        const legacyDts = path.join(frontendSrcDir, 'dokkebi-client.d.ts');
        if (existsSync(legacyDts)) {
            legacyDtsToDelete = legacyDts;
            changes.push({
                type: 'update',
                desc: '레거시 dokkebi-client.d.ts 제거 (실제 .ts 파일로 대체됨)',
                path: path.relative(sourceRoot, legacyDts),
            });
        }
    }

    console.log(`${C.bold}${t('update.planTitle')}${C.reset}\n`);

    const typeLabel = {
        new:    `${C.green}${t('update.labelNew')}${C.reset}`,
        update: `${C.yellow}${t('update.labelUpdate')}${C.reset}`,
        skip:   `${C.cyan}${t('update.labelSkip')}${C.reset}`,
    };

    let hasChanges = false;
    for (const ch of changes) {
        const icon = typeLabel[ch.type];
        const note = ch.reason ? `  ${C.gray}(${ch.reason})${C.reset}` : '';
        console.log(`  ${icon} ${ch.desc}${note}`);
        if (ch.type !== 'skip') hasChanges = true;
    }

    if (!hasChanges) {
        console.log(`\n${C.green}${t('update.alreadyLatest')}${C.reset}\n`);
        return;
    }

    if (dryRun) {
        console.log(`\n${C.yellow}${t('update.dryRunNote')}${C.reset}\n`);
        return;
    }

    if (!force) {
        const answer = await askConfirm(`\n${t('update.confirm')}`);
        if (!answer) {
            console.log(`\n${C.yellow}${t('update.cancelled')}${C.reset}\n`);
            return;
        }
    }

    console.log('');

    // ── 6. 적용 ───────────────────────────────────────────────

    // 6-0. dokkebi.config.js — 신규 기본값 (logging → panelIpGuard → seo 순으로 삽입)
    if (configNeedsPanelIpGuard || configNeedsLogging || configNeedsSeo) {
        const configContent = await fs.readFile(configPath, 'utf-8');
        let nextConfig = configContent;
        if (configNeedsLogging) nextConfig = addLoggingToConfig(nextConfig);
        if (configNeedsPanelIpGuard) nextConfig = addPanelIpGuardToConfig(nextConfig);
        if (configNeedsSeo) nextConfig = addSeoToConfig(nextConfig);
        if (nextConfig !== configContent) {
            const bakPath = configPath + `.bak.${Date.now()}`;
            await fs.copyFile(configPath, bakPath);
            console.log(`  ${C.gray}${t('update.backup', { path: path.relative(sourceRoot, bakPath) })}${C.reset}`);
            await fs.writeFile(configPath, nextConfig, 'utf-8');
            console.log(`  ${C.yellow}↑${C.reset} dokkebi.config.js`);
        }
    }

    // 6-a. Worker 파일
    if (proxyMode === 'serverless') {
        // 구버전 admin.ts / admin/ 잔재 정리
        const legacyFiles = [
            'worker/api/_dokkebi/admin.ts',
            'worker/api/_dokkebi/admin/[[path]].ts',
        ];
        for (const rel of legacyFiles) {
            const absPath = path.join(sourceRoot, rel);
            if (existsSync(absPath)) {
                await fs.unlink(absPath);
                console.log(`  ${C.gray}${t('update.legacyDeleted', { path: rel })}${C.reset}`);
                // 빈 디렉토리면 같이 정리
                try { await fs.rmdir(path.dirname(absPath)); } catch { /* 비어있지 않으면 무시 */ }
            }
        }

        for (const wf of WORKER_FILES) {
            const ch = changes.find(c => c.path === wf.rel);
            if (!ch || ch.type === 'skip') continue;

            const absPath = path.join(sourceRoot, wf.rel);
            const content = wf.generate(cfg);

            if (ch.type === 'update') {
                // 기존 파일 백업
                const bakPath = absPath + `.bak.${Date.now()}`;
                await fs.copyFile(absPath, bakPath);
                console.log(`  ${C.gray}${t('update.backup', { path: path.relative(sourceRoot, bakPath) })}${C.reset}`);
            }

            await fs.mkdir(path.dirname(absPath), { recursive: true });
            await fs.writeFile(absPath, content, 'utf-8');
            console.log(`  ${ch.type === 'new' ? C.green + '✚' : C.yellow + '↑'}${C.reset} ${wf.rel}`);
        }
    }

    // 6-b. 마이그레이션
    if (newMigrationNeeded && migrationsDir) {
        const migName    = await nextMigrationName(migrationsDir);
        const migPath    = path.join(migrationsDir, migName);
        const sqlParts   = missingTables.map(t => sqlMap[t]).join('\n\n');
        const migContent = `-- dokkebi 시스템 테이블 업데이트
-- dok update 명령으로 자동 생성됨

${sqlParts}
`;
        await fs.writeFile(migPath, migContent, 'utf-8');
        console.log(`  ${C.green}✚${C.reset} ${path.relative(sourceRoot, migPath)}`);
    }

    // 6-c. .env.example
    if (envExampleNeedsUpdate) {
        await fs.appendFile(envExamplePath, envExampleAddition || ENV_ADDITIONS, 'utf-8');
        console.log(`  ${C.yellow}↑${C.reset} .env.example`);
    }

    // 6-d. Frontend 실제 클라이언트 파일 emit (먼저 emit 해야 이후 import 가 valid)
    if (frontendClientFileTarget && (!existsSync(frontendClientFileTarget) || frontendClientFileNeedsUpdate)) {
        if (existsSync(frontendClientFileTarget)) {
            const bakPath = frontendClientFileTarget + `.bak.${Date.now()}`;
            await fs.copyFile(frontendClientFileTarget, bakPath);
            console.log(`  ${C.gray}${t('update.backup', { path: path.relative(sourceRoot, bakPath) })}${C.reset}`);
        }
        await fs.mkdir(path.dirname(frontendClientFileTarget), { recursive: true });
        await fs.writeFile(frontendClientFileTarget, dokkebiClientTsSource(), 'utf-8');
        console.log(`  ${frontendClientFileNeedsUpdate ? C.yellow + '↑' : C.green + '✚'}${C.reset} ${path.relative(sourceRoot, frontendClientFileTarget)}`);
    }

    // 6-e. 레거시 dokkebi-client.d.ts 삭제
    if (legacyDtsToDelete) {
        try { await fs.unlink(legacyDtsToDelete); } catch { /* noop */ }
        console.log(`  ${C.gray}${t('update.legacyDeleted', { path: path.relative(sourceRoot, legacyDtsToDelete) })}${C.reset}`);
    }

    // 6-f. Frontend — 사용자 코드 자동 변환 (window.dokkebi → dokkebi, 'dokkebi:client' → 상대경로)
    if (frontendMigrationTargets.length > 0 && frontendSrcDir) {
        for (const target of frontendMigrationTargets) {
            const original = await readFileSafe(target.path);
            if (!original) continue;
            const { next, changed } = migrateFrontendContent(original, target.path, frontendSrcDir);
            if (!changed) continue;

            const bakPath = target.path + `.bak.${Date.now()}`;
            await fs.copyFile(target.path, bakPath);
            await fs.writeFile(target.path, next, 'utf-8');
            console.log(`  ${C.yellow}↑${C.reset} ${path.relative(sourceRoot, target.path)} ${C.gray}(${target.summary.join(', ')})${C.reset}`);
        }
    }

    console.log(`\n${C.green}${C.bold}${t('update.complete')}${C.reset}\n`);

    const dbTsTouched = changes.some(c => c.type !== 'skip' && c.path === 'worker/api/_dokkebi/db.ts');
    if (proxyMode === 'serverless' && changes.some(c => c.type !== 'skip' && c.path.includes('worker'))) {
        console.log(t('update.nextSteps'));
        if (dbTsTouched) {
            console.log(`  ${C.yellow}${t('update.dbTsNote1')}${C.reset}`);
            console.log(`      ${t('update.dbTsNote2', { cmd: `${C.bold}dok build${C.reset}` })}`);
            console.log(`      ${C.gray}${t('update.dbTsNote3')}${C.reset}`);
            console.log(`      ${C.gray}${t('update.dbTsNote4')}${C.reset}`);
            console.log(`      ${C.gray}${t('update.dbTsNote5')}${C.reset}`);
            console.log(`      ${C.gray}${t('update.dbTsNote6')}${C.reset}\n`);
        }
        console.log(`  ${C.cyan}${t('update.step1')}${C.reset}`);
        console.log(`  ${C.cyan}${t('update.step2')}${C.reset}`);
        console.log(`       ${C.bold}dok migrate${C.reset}`);
        console.log(`  ${C.cyan}${t('update.step3')}${C.reset}`);
        console.log(`       ${C.bold}dok build && dok deploy${C.reset}\n`);
    } else if (newMigrationNeeded) {
        console.log(t('update.nextSteps'));
        console.log(`  ${C.cyan}${t('update.stepMigrate')}${C.reset}`);
        console.log(`       ${C.bold}dok migrate${C.reset}\n`);
    }
}

// ─────────────────────────────────────────────────────────────
// 확인 프롬프트 (readline)
// ─────────────────────────────────────────────────────────────

function askConfirm(question) {
    return new Promise(resolve => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        rl.question(question, answer => {
            rl.close();
            resolve(answer.trim().toLowerCase() === 'y');
        });
    });
}
