/**
 * dokkebi 클라이언트 & frontend 마이그레이션 스모크 테스트
 *
 * 1) vite-plugin 의 dokkebiClientTsSource() 결과가 유효한 TS 인지 (간접 syntax)
 * 2) bootstrap.js.tpl 에서 window.dokkebi 가 사라졌고 Symbol handoff 가 설치되는지
 * 3) update.js 의 migrateFrontendContent() 가 다양한 입력을 올바르게 변환하는지
 *    - window.dokkebi.X / (window as any).dokkebi.X / window.dokkebi?.X
 *    - await window.dokkebiReady
 *    - from 'dokkebi:client' → 상대 경로
 *    - 중복 import 방지 (idempotent)
 *    - Vue SFC 지원
 *
 * 실행: node tests/dokkebiClient.smoke.mjs
 */

import fs from 'fs/promises';
import path from 'path';
import vm from 'vm';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const FAILED = [];
function ok(name, cond, detail = '') {
    if (cond) {
        console.log(`  ${'\u2713'} ${name}`);
    } else {
        console.log(`  ${'\u2717'} ${name}${detail ? '  — ' + detail : ''}`);
        FAILED.push(name);
    }
}

// ─────────────────────────────────────────────────────────────
// 1) vite-plugin export 검증
// ─────────────────────────────────────────────────────────────
console.log('\n[1] vite-plugin: dokkebiClientTsSource() & 가상 모듈');

const pluginMod = await import(path.join(ROOT, 'packages/dokkebi-vite-plugin/src/index.js'));
ok('dokkebiClientSource export', typeof pluginMod.dokkebiClientSource === 'function');
ok('dokkebiClientTsSource export', typeof pluginMod.dokkebiClientTsSource === 'function');

const tsSrc = pluginMod.dokkebiClientTsSource();
ok('TS 소스가 export const dokkebi 포함', /export const dokkebi: DokkebiClient/.test(tsSrc));
ok('TS 소스가 export default dokkebi 포함', /export default dokkebi/.test(tsSrc));
ok('Symbol.for(dokkebi.client.handoff) 사용', /Symbol\.for\(['"]dokkebi\.client\.handoff['"]\)/.test(tsSrc));
ok('handoff 소비 후 window 에서 제거', /delete\s+\(window as any\)\[_HANDOFF\]/.test(tsSrc));
ok('ready() 메서드 정의', /async\s+ready\(\)/.test(tsSrc));
ok('DokkebiClient interface 정의', /export interface DokkebiClient/.test(tsSrc));

// 가상 모듈도 syntax 검증 (JS 형태)
const plugin = pluginMod.default();
if (plugin && typeof plugin.load === 'function') {
    const virtualCode = plugin.load('\0dokkebi:client');
    ok('가상 모듈 load() 결과 존재', typeof virtualCode === 'string' && virtualCode.length > 100);
    try {
        const dataUrl = 'data:text/javascript;base64,' + Buffer.from(virtualCode).toString('base64');
        const mod = await import(dataUrl);
        ok('가상 모듈 ESM import 가능', mod && typeof mod.dokkebi === 'object');
        ok('dokkebi.request 메서드 존재', typeof mod.dokkebi?.request === 'function');
        ok('dokkebi.ready 메서드 존재', typeof mod.dokkebi?.ready === 'function');
    } catch (e) {
        ok('가상 모듈 ESM import 가능', false, e.message);
    }
}

// ─────────────────────────────────────────────────────────────
// 2) bootstrap.js.tpl 검증
// ─────────────────────────────────────────────────────────────
console.log('\n[2] bootstrap.js.tpl: window.dokkebi 제거 & handoff 설치');

const bootstrapSrc = await fs.readFile(
    path.join(ROOT, 'src/templates/bootstrap.js.tpl'),
    'utf-8',
);

ok('window.dokkebi = { ... } 할당이 없다',
    !/^\s*window\.dokkebi\s*=\s*\{/m.test(bootstrapSrc));
ok('_dokClient 클로저 객체 도입', /\bconst\s+_dokClient\s*=\s*\{/.test(bootstrapSrc));
ok('Symbol.for("dokkebi.client.handoff") 설치',
    /Symbol\.for\(['"]dokkebi\.client\.handoff['"]\)/.test(bootstrapSrc));
ok('handoff 함수가 _dokClient 반환', /return\s+_dokClient\s*;/.test(bootstrapSrc));
ok('_resolveReady(_dokClient) 로 변경', /_resolveReady\(_dokClient\)/.test(bootstrapSrc));
ok('내부 get/post/put/delete 가 _dokClient.request 참조',
    /_dokClient\.request\(['"]GET['"]/.test(bootstrapSrc));
ok('fetch override 가 await window.dokkebiReady 결과 사용',
    /const\s+_client\s*=\s*await\s+window\.dokkebiReady/.test(bootstrapSrc));
ok('window.dokkebi.request 직접 호출이 없다 (fetch override)',
    !/await\s+window\.dokkebi\.request/.test(bootstrapSrc));

// ⚠ 인라인 <script> 안의 텍스트로 들어가므로, 본문 어디에도 script-종료 태그
// (대소문자 무시) 가 등장해선 안 된다 — 등장하면 HTML 파서가 부트스트랩을 조기
// 종료해서 SyntaxError + 스크립트 내용 노출이 발생한다.
{
    const closingTags = bootstrapSrc.match(/<\s*\/\s*script\s*>/gi) || [];
    ok('부트스트랩 본문에 </script> 종료 태그가 정확히 1개 (마지막 닫음만)',
        closingTags.length === 1,
        `발견된 종료 태그 수: ${closingTags.length}`);
}

// ─────────────────────────────────────────────────────────────
// 3) Frontend 마이그레이션 (update.js)
// ─────────────────────────────────────────────────────────────
console.log('\n[3] update.js: migrateFrontendContent() — 다양한 패턴');

const updateSrc = await fs.readFile(path.join(ROOT, 'src/commands/update.js'), 'utf-8');

ok('migrateFrontendContent 함수 정의됨', /function\s+migrateFrontendContent\s*\(/.test(updateSrc));
ok('scanFrontendForMigration 함수 정의됨', /async\s+function\s+scanFrontendForMigration\s*\(/.test(updateSrc));
ok('relativeImportPath 함수 정의됨', /function\s+relativeImportPath\s*\(/.test(updateSrc));

// migrateFrontendContent 와 그 헬퍼들을 sandbox 에서 평가
const fnBlocks = [
    updateSrc.match(/function\s+escapeRegex[\s\S]+?\n\}\s*\n/),
    updateSrc.match(/function\s+alreadyImportsDokkebi[\s\S]+?\n\}\s*\n/),
    updateSrc.match(/function\s+relativeImportPath[\s\S]+?\n\}\s*\n/),
    updateSrc.match(/function\s+migrateFrontendContent[\s\S]+?\n\}\s*\n/),
];
ok('마이그레이션 헬퍼 함수 4개 추출 성공', fnBlocks.every(Boolean));

if (fnBlocks.every(Boolean)) {
    const helperSrc = `
        const path = require('path');
        ${fnBlocks.map(m => m[0]).join('\n')}
        module.exports = { migrateFrontendContent, relativeImportPath, alreadyImportsDokkebi };
    `;
    const ctx = { module: { exports: {} }, require: (await import('module')).createRequire(import.meta.url) };
    vm.createContext(ctx);
    try {
        new vm.Script(helperSrc).runInContext(ctx);
        const { migrateFrontendContent, relativeImportPath } = ctx.module.exports;

        // 상대 경로 헬퍼 검증
        ok('상대 경로: src/lib/api.ts → ./dokkebi',
            relativeImportPath('/p/frontend/src/lib/api.ts', '/p/frontend/src') === './dokkebi');
        ok('상대 경로: src/composables/useDokkebi.ts → ../lib/dokkebi',
            relativeImportPath('/p/frontend/src/composables/useDokkebi.ts', '/p/frontend/src') === '../lib/dokkebi');
        ok('상대 경로: src/views/foo/bar.tsx → ../../lib/dokkebi',
            relativeImportPath('/p/frontend/src/views/foo/bar.tsx', '/p/frontend/src') === '../../lib/dokkebi');
        ok('상대 경로: src/App.tsx → ./lib/dokkebi',
            relativeImportPath('/p/frontend/src/App.tsx', '/p/frontend/src') === './lib/dokkebi');

        const SRC = '/p/frontend/src';

        // 케이스 1: (window as any).dokkebi.request
        {
            const r = migrateFrontendContent(
                `const x = await (window as any).dokkebi.request({ method: 'GET' });`,
                '/p/frontend/src/lib/api.ts',
                SRC,
            );
            ok('case1: (window as any).dokkebi → dokkebi + import 추가',
                /\bdokkebi\.request\(/.test(r.next)
                && !/\(window as any\)\.dokkebi/.test(r.next)
                && /import\s*\{\s*dokkebi\s*\}\s*from\s*['"]\.\/dokkebi['"]/.test(r.next));
        }

        // 케이스 2: window.dokkebi.get (composables 깊이)
        {
            const r = migrateFrontendContent(
                `import { foo } from 'bar';\nconst y = await window.dokkebi.get('/api/users');`,
                '/p/frontend/src/composables/useDokkebi.ts',
                SRC,
            );
            ok('case2: composables → ../lib/dokkebi 상대 경로',
                /import\s*\{\s*dokkebi\s*\}\s*from\s*['"]\.\.\/lib\/dokkebi['"]/.test(r.next)
                && !/window\.dokkebi\.get/.test(r.next));
        }

        // 케이스 3: window.dokkebi?.X (optional chaining)
        {
            const r = migrateFrontendContent(
                `if (typeof window.dokkebi?.request === 'function') { /* ok */ }`,
                '/p/frontend/src/lib/api.ts',
                SRC,
            );
            ok('case3: window.dokkebi?.X → dokkebi.X',
                /typeof\s+dokkebi\.request\s*===\s*['"]function['"]/.test(r.next));
        }

        // 케이스 4: from 'dokkebi:client' 가상 모듈 → 상대 경로
        {
            const r = migrateFrontendContent(
                `import { dokkebi } from 'dokkebi:client';\nawait dokkebi.get('/');`,
                '/p/frontend/src/lib/api.ts',
                SRC,
            );
            ok('case4: from "dokkebi:client" → from "./dokkebi"',
                /import\s*\{\s*dokkebi\s*\}\s*from\s*['"]\.\/dokkebi['"]/.test(r.next)
                && !/dokkebi:client/.test(r.next));
        }

        // 케이스 5: idempotent — 이미 변환된 파일은 변경 없음
        {
            const r = migrateFrontendContent(
                `import { dokkebi } from './dokkebi';\nawait dokkebi.get('/');`,
                '/p/frontend/src/lib/api.ts',
                SRC,
            );
            ok('case5: 이미 마이그레이션된 파일은 변경 없음', !r.changed);
        }

        // 케이스 6: 중복 import 방지 — from 'dokkebi:client' 가 이미 있는 파일에 추가 변환 시 import 중복 X
        {
            const r = migrateFrontendContent(
                `import { dokkebi } from 'dokkebi:client';\nif (typeof window.dokkebi?.request === 'function') {}`,
                '/p/frontend/src/lib/api.ts',
                SRC,
            );
            const importCount = (r.next.match(/import\s*\{\s*dokkebi\s*\}\s*from/g) || []).length;
            ok('case6: 중복 import 발생 X', importCount === 1);
        }

        // 케이스 7: await window.dokkebiReady
        {
            const r = migrateFrontendContent(
                `await window.dokkebiReady;\nconst z = await window.dokkebi.post('/api/x', {});`,
                '/p/frontend/src/lib/api.ts',
                SRC,
            );
            ok('case7: await window.dokkebiReady → await dokkebi.ready()',
                /await\s+dokkebi\.ready\(\)/.test(r.next));
        }

        // 케이스 8: Vue SFC
        {
            const input = `<script setup lang="ts">
import { ref } from 'vue';

async function api(path: string) {
  return (window as any).dokkebi.request({ method: 'GET', path });
}
</script>

<template><div /></template>`;
            const r = migrateFrontendContent(input, '/p/frontend/src/App.vue', SRC);
            const scriptEnd = r.next.indexOf('</script>');
            const dokkebiImportIdx = r.next.indexOf("from './lib/dokkebi'");
            ok('case8: Vue SFC <script setup> 안에 상대 import 추가',
                dokkebiImportIdx > 0 && dokkebiImportIdx < scriptEnd
                && /import\s*\{\s*ref\s*\}\s*from\s*['"]vue['"]/.test(r.next));
        }
    } catch (e) {
        ok('migrateFrontendContent 평가', false, e.message + '\n' + (e.stack || ''));
    }
}

// ─────────────────────────────────────────────────────────────
// 4) Caller Guard (XSS / DevTools 방어 레이어)
// ─────────────────────────────────────────────────────────────
console.log('\n[4] Caller Guard: opaqueHandle placeholder 치환 + 부트스트랩 로직');

const opaqueMod = await import(path.join(ROOT, 'src/core/opaqueHandle.js'));
ok('generateBootstrapScript export', typeof opaqueMod.generateBootstrapScript === 'function');

// 4-1) 기본 'off' 모드 — placeholder 가 안전한 기본값으로 치환
{
    const html = opaqueMod.generateBootstrapScript({
        dbType: 'd1', dbConfig: {}, buildVer: 'test',
    });
    ok('default mode = "off"', /var mode = "off";/.test(html));
    ok('default allowedArr = []', /var allowedArr = \[\];/.test(html));
    ok('default auditUrl = "" (endpoint 미설정 시 sendBeacon 스킵)',
        /var auditUrl = "";/.test(html));
    ok('placeholder __DOKKEBI_PH_CALLER_CHECK__ 잔존 없음',
        !html.includes('__DOKKEBI_PH_CALLER_CHECK__'));
    ok('placeholder __DOKKEBI_PH_ALLOWED_SCRIPTS__ 잔존 없음',
        !html.includes('__DOKKEBI_PH_ALLOWED_SCRIPTS__'));
    ok('attribution seal placeholders 치환됨 (__DOKKEBI_PH_ATTR_* 잔존 없음)',
        !html.includes('__DOKKEBI_PH_ATTR_'));
    ok('콘솔 배너 Contact 문자열 존재', /Contact:/.test(html));
    ok('콘솔 배너 License ELv2', /License ELv2/.test(html));
}

// 4-2) audit 모드 + 청크 allowlist
{
    const html = opaqueMod.generateBootstrapScript({
        dbType: 'd1', dbConfig: {}, buildVer: 'test',
        callerCheck: 'audit',
        allowedScripts: ['/assets/index-abc.js', 'assets/vendor-def.js'],
        callerCheckAuditUrl: '/my/quarantine',
    });
    ok('mode = "audit" 치환', /var mode = "audit";/.test(html));
    ok('allowedArr 가 / 로 시작하도록 정규화',
        /var allowedArr = \["\/assets\/index-abc\.js","\/assets\/vendor-def\.js"\];/.test(html));
    ok('auditUrl 커스텀 치환', /var auditUrl = "\/my\/quarantine";/.test(html));
}

// 4-3) 잘못된 모드 값은 'off' 로 폴백
{
    const html = opaqueMod.generateBootstrapScript({
        dbType: 'd1', dbConfig: {}, buildVer: 'test',
        callerCheck: 'unknown-mode',
        allowedScripts: ['/x.js'],
    });
    ok('unknown 모드 → "off" 폴백', /var mode = "off";/.test(html));
}

// 4-4) 부트스트랩에 caller guard 핵심 구조가 들어있음
{
    const html = opaqueMod.generateBootstrapScript({
        dbType: 'd1', dbConfig: {}, buildVer: 'test',
        callerCheck: 'block', allowedScripts: ['/assets/x.js'],
    });
    ok('__DOKKEBI_CALLER_GUARD__ 객체 정의',
        /const\s+__DOKKEBI_CALLER_GUARD__\s*=/.test(html));
    ok('isInternal 함수 정의', /\bfunction\s+_isInternalCall/.test(html));
    ok('audit 함수 정의', /\bfunction\s+_audit/.test(html));
    ok('MutationObserver 등록', /\bnew\s+MutationObserver\b/.test(html));
    ok('_dokClient.request 래핑',
        /_dokClient\[name\]\s*=\s*function/.test(html));
    ok('window.fetch 인터셉터에 caller check 확장',
        /__DOKKEBI_CALLER_GUARD__\.isInternal\(window\.fetch\)/.test(html));
    ok('block 모드 caller-mismatch reject',
        /Promise\.reject\(new Error\(['"]\[dokkebi\] 허용되지 않은 호출 출처/.test(html));
    ok('XMLHttpRequest.send 인터셉터 설치',
        /XMLHttpRequest\.prototype\.send\s*=\s*function/.test(html)
        && /api:\s*['"]xhr['"]/.test(html));
    ok('navigator.sendBeacon 인터셉터 설치',
        /navigator\.sendBeacon\s*=\s*function/.test(html)
        && /api:\s*['"]sendBeacon['"]/.test(html));
    ok('EventSource Proxy 생성자 인터셉터',
        /window\.EventSource\s*=\s*new Proxy/.test(html)
        && /api:\s*['"]EventSource['"]/.test(html));
    ok('WebSocket Proxy 생성자 인터셉터',
        /window\.WebSocket\s*=\s*new Proxy/.test(html)
        && /api:\s*['"]WebSocket['"]/.test(html));
    ok('가드 적용 경로 함수 (/api/* 만, /_dokkebi/* 제외)',
        /_shouldGuardPath/.test(html) && /'\/_dokkebi\/'/.test(html));
}

// 4-5) caller guard 의 핵심 구현 디테일 정규식 검증
{
    const html = opaqueMod.generateBootstrapScript({
        dbType: 'd1', dbConfig: {}, buildVer: 'test',
        callerCheck: 'audit', allowedScripts: ['/assets/index-abc.js'],
    });
    ok('Error.prototype 을 freeze 하지 않음 (extends Error 호환)',
        !/Object\.freeze\(\s*_Error\.prototype\s*\)/.test(html));
    ok('stack 게터를 closure 에 캡처 (위조 방어)',
        /_stkGet\.call\(e\)/.test(html));
    ok('script URL 추출 정규식 존재 (.js / .mjs / .cjs)',
        /\b_jsExtRe\b/.test(html) && html.includes('\\.(m|c)?js$'));
    ok('sendBeacon 사용 (audit fire-and-forget)',
        /navigator\.sendBeacon\(auditUrl/.test(html));
    ok('auditUrl 미설정 시 sendBeacon 스킵 (콘솔만)',
        /if\s*\(\s*auditUrl\s*&&\s*typeof\s+auditUrl/.test(html));
    ok('MutationObserver: 빌드 시 박힌 allowedScripts 도 화이트리스트',
        /_initialSet\.add\(/.test(html) && /\bvar\s+_alw\s*=\s*"__DOKKEBI_PH_ALLOWED_SCRIPTS__"/.test(html) === false
        && /Array\.isArray\(_alw\)/.test(html));
    ok('MutationObserver: dokkebi 내부 자산 경로 인정 (/dokkebi/*, /_dokkebi/*)',
        /_isDokkebiInternalPath/.test(html) && /\/dokkebi-qjs/.test(html));
    ok('MutationObserver: 브라우저 확장 URL (chrome-extension:// 등) 무시',
        /chrome-extension:/.test(html) && /moz-extension:/.test(html)
        && /_isBrowserExtensionUrl/.test(html));
    ok('audit 반복 보고 억제 (페이지당 종류별 최대 5건)',
        /_auditedKinds\[key\]\s*>\s*5/.test(html));
    ok('cross-origin URL 은 external 로 간주',
        /seenExternal\s*=\s*true/.test(html));
    ok('seenInternal && !seenExternal 가 허용 분기 조건',
        /if\s*\(\s*seenInternal\s*&&\s*!seenExternal\s*\)/.test(html));
    ok('placeholder 가 비었으면 off 로 폴백',
        /!Array\.isArray\(allowedArr\)\s*\|\|\s*allowedArr\.length\s*===\s*0/.test(html));
}

// 4-6) build.js 의 collectCallerAllowedScripts 가 /dokkebi/* 를 제외하는지
{
    const buildSrc = await fs.readFile(path.join(ROOT, 'src/commands/build.js'), 'utf-8');
    ok('build.js: collectCallerAllowedScripts 정의',
        /async\s+function\s+collectCallerAllowedScripts/.test(buildSrc));
    ok('build.js: dokkebi 폴더 제외 로직',
        /ent\.name\s*===\s*['"]dokkebi['"]/.test(buildSrc));
    ok('build.js: injectBootstrapAll 호출에 callerCheck/allowedScripts 전달',
        /callerCheck:\s*callerCheckMode/.test(buildSrc)
        && /allowedScripts:\s*callerAllowedScripts/.test(buildSrc));
}

// ─────────────────────────────────────────────────────────────
// 결과
// ─────────────────────────────────────────────────────────────
console.log('');
if (FAILED.length === 0) {
    console.log('\u2705 모든 테스트 통과');
    process.exit(0);
} else {
    console.log(`\u274C ${FAILED.length} 개 실패:`);
    FAILED.forEach(f => console.log('   - ' + f));
    process.exit(1);
}
