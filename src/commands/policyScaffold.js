/**
 * dok policy:scaffold
 *
 * 역할:
 *   현 프로젝트의 모델 DSL(table(...)) 과 컨트롤러 SQL 리터럴을 정적 분석해
 *   Tenant Policy / Authorization Policy 초기 설정을 dokkebi.config.js 에
 *   **직접 삽입** 하거나 갱신한다.
 *
 * 동작:
 *   1) inferPolicyFromProject → { tables, rules, warnings }
 *   2) dokkebi.config.js 을 읽어 AUTOGEN 마커 영역을 탐지
 *        - 마커 있음: 마커 사이 내용을 교체
 *        - 마커 없음: export default { ... } 의 닫는 중괄호 직전에 삽입
 *   3) 기존 사용자 명시값(policy.tables.* / authorization.rules.*) 은 보존하기 위해
 *      **자동 생성 블록과 기존 블록을 물리적으로 분리** 한다.
 *        - autogen 블록은 `...autogen` 식의 spread 대상으로 export 에 병합되도록
 *          별도 상수를 선언한다.
 *
 * 생성 스키마 (config 상단에 상수, export 내부는 spread):
 *
 *   // ╭─ DOKKEBI AUTOGEN:POLICY START ───────────────────────────────
 *   // │ `dok policy:scaffold` 로 재생성됩니다. 이 블록은 직접 수정해도
 *   // │ 다음 scaffold 실행 시 덮어씁니다. 커스텀 오버라이드는 export
 *   // │ 객체 안의 policy / authorization 블록에 직접 작성하세요.
 *   // ╰──────────────────────────────────────────────────────────────
 *   const __dokkebi_autogen_policy = { ... };
 *   const __dokkebi_autogen_authz  = { ... };
 *   // ╰─ DOKKEBI AUTOGEN:POLICY END ───────────────────────────────
 *
 *   export default {
 *     // ...
 *     policy: {
 *       ...__dokkebi_autogen_policy,
 *       // 여기에 사용자 오버라이드 (tables 를 포함) 를 추가하세요.
 *       // 같은 key 는 나중에 선언한 값이 우선합니다.
 *     },
 *     authorization: {
 *       ...__dokkebi_autogen_authz,
 *     },
 *   };
 */

import fs from 'fs/promises';
import path from 'path';
import { buildRegistry } from '../core/queryRegistry.js';
import { inferPolicyFromProject } from '../core/policyInference.js';
import { t } from '../i18n/index.js';

const START_MARKER = '// ╭─ DOKKEBI AUTOGEN:POLICY START';
const END_MARKER = '// ╰─ DOKKEBI AUTOGEN:POLICY END';

export async function runPolicyScaffold(src = '.', options = {}) {
    const sourceRoot = path.resolve(process.cwd(), src);
    const configPath = path.join(sourceRoot, 'dokkebi.config.js');
    let existing;
    try {
        existing = await fs.readFile(configPath, 'utf-8');
    } catch {
        throw new Error(`[policy:scaffold] dokkebi.config.js 를 찾을 수 없습니다: ${configPath}`);
    }

    console.log('\n' + t('policy.scanning'));

    // 1) opTableStats 를 위해 query registry scan 을 실행
    const { opTableStats } = await buildRegistry(sourceRoot, {
        includeLearned: false,
        includeScan: true,
        verbose: false,
    });

    // 2) 모델 기반 tenant + SQL 기반 authz 추론
    const inferred = await inferPolicyFromProject(sourceRoot, { opTableStats });

    console.log(`[policy:scaffold]   모델 파일 ${inferred.scannedModelFiles}개 스캔`);
    console.log(`[policy:scaffold]   tenant 감지: ${inferred.detectedTables.length}개 (${inferred.detectedTables.join(', ') || '없음'})`);
    if ((inferred.sharedTables || []).length > 0) {
        console.log(`[policy:scaffold]   shared 테이블: ${inferred.sharedTables.length}개 (${inferred.sharedTables.join(', ')})`);
    }
    if (inferred.undetectedTables.length > 0) {
        console.log(`[policy:scaffold]   tenant 미감지: ${inferred.undetectedTables.length}개 (${inferred.undetectedTables.join(', ')})`);
    }
    console.log(`[policy:scaffold]   authz 규칙 추론: ${Object.keys(inferred.rules).length}개`);
    for (const w of inferred.warnings) console.warn(`[policy:scaffold]   ⚠ ${w}`);

    // 3) autogen 블록 렌더링
    const autogenBlock = renderAutogenBlock(inferred);

    // 4) 기존 파일에 마커 있는지 확인
    const hasStart = existing.includes(START_MARKER);
    const hasEnd = existing.includes(END_MARKER);
    let nextContent;
    if (hasStart && hasEnd) {
        // 마커 사이만 교체
        const startIdx = existing.indexOf(START_MARKER);
        const endIdx = existing.indexOf(END_MARKER);
        const endLineIdx = existing.indexOf('\n', endIdx);
        const before = existing.slice(0, startIdx);
        const after = existing.slice(endLineIdx + 1);
        nextContent = before + autogenBlock + '\n' + after;
    } else if (hasStart || hasEnd) {
        throw new Error('[policy:scaffold] AUTOGEN 마커가 깨져있습니다 (start/end 중 하나만 존재). 수동 정리 후 다시 실행하세요.');
    } else {
        // 마커 없음 — 파일 최상단에 autogen 블록 삽입 + export 객체에 spread 삽입 제안
        nextContent = autogenBlock + '\n\n' + existing;

        // export default 객체 안에 policy/authorization 블록이 없으면 spread 자동 삽입
        nextContent = injectSpreadsIntoExport(nextContent);
    }

    if (options.dryRun) {
        console.log('\n' + t('policy.dryRun'));
        console.log('─'.repeat(60));
        console.log(nextContent.split('\n').slice(0, 40).join('\n'));
        console.log('─'.repeat(60));
        return;
    }

    // 5) .bak 백업 + 쓰기
    const bakPath = configPath + '.bak';
    await fs.writeFile(bakPath, existing, 'utf-8');
    await fs.writeFile(configPath, nextContent, 'utf-8');
    console.log('\n' + t('policy.complete'));
    console.log(`[policy:scaffold]    백업: ${path.relative(sourceRoot, bakPath)}`);
    console.log(`[policy:scaffold]    다음 빌드부터 자동 정책이 적용됩니다 (dok build).`);
}

// ─────────────────────────────────────────────────────────────
// 렌더링 유틸
// ─────────────────────────────────────────────────────────────

function renderAutogenBlock(inferred) {
    const ts = new Date().toISOString();
    const lines = [];
    lines.push(START_MARKER + ' ─────────────────────────────');
    lines.push(`// │ 생성 시각: ${ts}`);
    lines.push(`// │ 감지: tenant=${inferred.detectedTables.length}, shared=${(inferred.sharedTables || []).length}, rules=${Object.keys(inferred.rules).length}, scannedModels=${inferred.scannedModelFiles}`);
    lines.push(`// │`);
    lines.push(`// │ ⚠ 기본 enabled: false 로 생성됩니다. 활성화하려면:`);
    lines.push(`// │   1) Tenant Policy (row-level 격리):`);
    lines.push(`// │      • 엔진은 테이블별 sessionClaim 을 지원 — JWT 없이도 동작.`);
    lines.push(`// │        세션에 어떤 "식별값"이든 넣기만 하면 되고, 테이블마다 다른 클레임을`);
    lines.push(`// │        쓰는 프로젝트 (예: creator_token / sender_token / token / user_id)도 OK.`);
    lines.push(`// │      • 식별되는 시점에 (로그인이 없어도) 한 번 호출:`);
    lines.push(`// │          await ctx.setSessionTenant({`);
    lines.push(`// │              creator_token: localStorage.getItem('creator_token') || undefined,`);
    lines.push(`// │              sender_token:  localStorage.getItem('sender_token')  || undefined,`);
    lines.push(`// │              user_id:       authState?.userId                   || undefined,`);
    lines.push(`// │          });`);
    lines.push(`// │        각 테이블은 자기 sessionClaim 에 해당하는 값을 자동으로 사용.`);
    lines.push(`// │      • 첫 활성 시 mode:'verify' + strict:false 로 시작 → 로그 안정 후 'inject' 로 승격.`);
    lines.push(`// │      • strict:false 이면 클레임이 "없는" 요청은 통과 (공개 쿼리로 취급). 완전 차단은 strict:true.`);
    lines.push(`// │   2) Authorization Policy (연산-레벨 권한):`);
    lines.push(`// │      • JWT/role 기반. 익명 토큰만 쓰는 사이트는 이 블록 enabled:false 유지 가능.`);
    lines.push(`// │      • DOKKEBI_JWT_SECRET 환경변수 설정 + Authorization: Bearer <jwt> 헤더.`);
    lines.push(`// │      • mode:'warn' 으로 시작 → 규칙 누락 케이스 로그 확인 후 'strict'.`);
    lines.push(`// │`);
    lines.push(`// │ 이 블록은 \`dok policy:scaffold\` 재실행 시 덮어써집니다.`);
    lines.push(`// │ 커스텀 오버라이드는 아래 export default 안의 policy / authorization 블록에서.`);
    lines.push(`// ╰──────────────────────────────────────────────────────────────`);
    lines.push(`const __dokkebi_autogen_policy = ${jsLiteral(buildPolicyObject(inferred), 0)};`);
    lines.push('');
    lines.push(`const __dokkebi_autogen_authz = ${jsLiteral(buildAuthzObject(inferred), 0)};`);
    lines.push(END_MARKER + ' ─────────────────────────────');
    return lines.join('\n');
}

function buildPolicyObject(inferred) {
    // 추론 결과에서 '공개로 간주' 된 테이블은 주석으로만 남기고 실제 enforce 테이블만 포함.
    // v5.4+ 부터는 **테이블별 sessionClaim** 을 엔진이 지원하므로,
    // 추론된 값을 그대로 옮겨 놓는다 (notofly 처럼 creator_token / sender_token / token / id 가
    // 테이블마다 다른 케이스에서 바로 작동).
    const enforcedTables = {};
    for (const [tname, cfg] of Object.entries(inferred.tables)) {
        if (cfg.mode === 'enforce' && cfg.tenantColumn) {
            enforcedTables[tname] = {
                tenantColumn: cfg.tenantColumn,
                mode: 'enforce',
                // 테이블별 명시 클레임 — 없으면 엔진이 tenantColumn 이름으로 fallback.
                sessionClaim: cfg.sessionClaim || cfg.tenantColumn,
            };
        }
    }
    if (Object.keys(enforcedTables).length === 0) {
        return { enabled: false, _autogen: true, _note: '추론된 tenant 테이블 없음 — 필요 시 수동으로 tables 선언 후 enabled:true 로 변경' };
    }
    // 🔴 SAFE DEFAULTS — scaffold 는 기존 프로젝트의 런타임을 깨지 않는 값으로 생성.
    //   - enabled: false → 사용자가 세션 주입 코드를 준비한 뒤 true 로 전환
    //   - mode: 'verify' → 경고 로그만 (자동 주입 X). 안정되면 'inject' 로 승격
    //   - strict: false → 세션에 클레임이 없는 요청도 통과 (점진 롤아웃)
    //
    // 전역 sessionClaim 은 '가장 많이 쓰인' 컬럼을 기본값으로 잡되, 테이블별
    // sessionClaim 이 우선하므로 혼합 프로젝트에서도 정확히 동작한다.
    const sessionClaim = _pickCommonClaim(inferred.tables) || 'user_id';
    return {
        enabled: false,
        mode: 'verify',
        sessionClaim,
        strict: false,
        tables: enforcedTables,
        _autogen: true,
        _note: "활성화 전 확인: (1) 식별 단계에서 ctx.setSessionTenant({ [각 테이블의 sessionClaim]: 값 }) 호출 (2) mode:'verify',strict:false 로 먼저 시작 (3) 로그 안정 후 strict:true → mode:'inject' 순 승격",
    };
}

/**
 * 추론된 테이블 중 **가장 흔한 tenantColumn** 을 전역 sessionClaim 기본값으로 선택.
 * 동률이면 알파벳 순. 테이블별 sessionClaim 이 우선하므로 이 값은 fallback 가이드.
 */
function _pickCommonClaim(tables) {
    const counts = new Map();
    for (const cfg of Object.values(tables || {})) {
        if (!cfg.tenantColumn) continue;
        counts.set(cfg.tenantColumn, (counts.get(cfg.tenantColumn) || 0) + 1);
    }
    if (counts.size === 0) return null;
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    return sorted[0][0];
}

function buildAuthzObject(inferred) {
    if (Object.keys(inferred.rules).length === 0) {
        return { enabled: false, _autogen: true };
    }
    const rules = {};
    for (const [key, spec] of Object.entries(inferred.rules)) {
        const { _inferred, ...pure } = spec;
        rules[key] = pure;
    }
    if (rules['*'] === undefined) rules['*'] = { public: true };
    // 🟡 SAFE DEFAULT — enabled: false 로 생성. 사용자가 JWT/role 전송을 준비한 뒤
    //    true 로 전환. mode:'warn' 은 규칙 미정의 연산을 "경고 + 통과" 로 처리.
    return {
        enabled: false,
        mode: 'warn',
        jwtSecretEnv: 'DOKKEBI_JWT_SECRET',
        claim: 'role',
        rules,
        _autogen: true,
        _note: "활성화 전 확인: (1) DOKKEBI_JWT_SECRET 환경변수 설정 (2) 프론트가 요청에 Authorization 헤더 포함 (3) mode:'warn' 으로 먼저 시작하여 로그 확인 후 'strict' 로 승격",
    };
}

function jsLiteral(obj, indent) {
    const pad = '    '.repeat(indent);
    const nextPad = '    '.repeat(indent + 1);
    if (obj === null) return 'null';
    if (typeof obj === 'string') return JSON.stringify(obj);
    if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);
    if (Array.isArray(obj)) {
        if (obj.length === 0) return '[]';
        const items = obj.map((v) => nextPad + jsLiteral(v, indent + 1));
        return '[\n' + items.join(',\n') + '\n' + pad + ']';
    }
    if (typeof obj === 'object') {
        const keys = Object.keys(obj);
        if (keys.length === 0) return '{}';
        const lines = keys.map((k) => {
            const kStr = /^[A-Za-z_$][\w$]*$/.test(k) ? k : JSON.stringify(k);
            return nextPad + kStr + ': ' + jsLiteral(obj[k], indent + 1);
        });
        return '{\n' + lines.join(',\n') + ',\n' + pad + '}';
    }
    return 'undefined';
}

// ─────────────────────────────────────────────────────────────
// export default {...} 에 policy/authorization spread 가 없으면 삽입
// ─────────────────────────────────────────────────────────────

function injectSpreadsIntoExport(source) {
    // 이미 policy 또는 authorization 키가 export 객체에 있는지 거친 검사
    const hasPolicyKey = /\n\s*policy\s*:/.test(source);
    const hasAuthzKey = /\n\s*authorization\s*:/.test(source);

    const needPolicy = !hasPolicyKey;
    const needAuthz = !hasAuthzKey;
    if (!needPolicy && !needAuthz) return source;

    // export default { ... }; 의 닫는 중괄호 찾기
    const exportRe = /export\s+default\s+\{/;
    const m = exportRe.exec(source);
    if (!m) return source; // non-standard — 사용자 수동 처리 유도

    const openIdx = m.index + m[0].length - 1;
    const closeIdx = findMatchingClose(source, openIdx);
    if (closeIdx < 0) return source;

    const before = source.slice(0, closeIdx);
    const after = source.slice(closeIdx);

    const insertions = [];
    if (needPolicy) {
        insertions.push('');
        insertions.push('    // 자동 추론된 Tenant Policy (dok policy:scaffold 생성)');
        insertions.push('    policy: {');
        insertions.push('        ...__dokkebi_autogen_policy,');
        insertions.push('        // 여기에 수동 오버라이드 추가 (예: tables.notos.tenantColumn 강제)');
        insertions.push('    },');
    }
    if (needAuthz) {
        insertions.push('');
        insertions.push('    // 자동 추론된 Authorization Policy (dok policy:scaffold 생성)');
        insertions.push('    authorization: {');
        insertions.push('        ...__dokkebi_autogen_authz,');
        insertions.push('        // 여기에 수동 규칙 오버라이드 추가');
        insertions.push('        // 예: rules: { ...__dokkebi_autogen_authz.rules, "DELETE:notos": { roles: ["admin"] } }');
        insertions.push('    },');
    }

    // 마지막이 콤마로 끝나지 않으면 콤마 추가
    const beforeTrim = before.replace(/\s*$/, '');
    const needsComma = !/[,{]\s*$/.test(beforeTrim);
    return beforeTrim + (needsComma ? ',' : '') + '\n' + insertions.join('\n') + '\n' + after;
}

function findMatchingClose(src, openIdx) {
    let depth = 0;
    const n = src.length;
    for (let i = openIdx; i < n; i++) {
        const ch = src[i];
        if (ch === "'" || ch === '"' || ch === '`') {
            const quote = ch;
            i++;
            while (i < n) {
                const c = src[i];
                if (c === '\\') { i += 2; continue; }
                if (c === quote) break;
                if (c === '$' && quote === '`' && src[i + 1] === '{') {
                    // 템플릿 interpolation — 빠르게 닫기
                    let d = 1; i += 2;
                    while (i < n && d > 0) { if (src[i] === '{') d++; else if (src[i] === '}') d--; i++; }
                    continue;
                }
                i++;
            }
            continue;
        }
        if (ch === '{') depth++;
        else if (ch === '}') { depth--; if (depth === 0) return i; }
    }
    return -1;
}
