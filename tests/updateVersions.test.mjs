/**
 * `dok update` managed worker 버전과 템플릿 헤더 버전이 일치하는지 검사한다.
 *
 * 배경: 템플릿 내용만 바꾸고 WORKER_FILES[].version 을 올리지 않으면
 * `dok update` 가 "이미 최신"으로 판단해 보안 패치를 건너뛴다.
 *
 * 실행: node --test tests/updateVersions.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const MANAGED = [
    ['worker/api/_dokkebi/db.ts', 'src/templates/worker/db.ts.tpl'],
    ['worker/api/_dokkebi/handshake.ts', 'src/templates/worker/handshake.ts.tpl'],
    ['worker/api/_dokkebi/log.ts', 'src/templates/worker/log.ts.tpl'],
    ['worker/api/_dokkebi/_panel.ts', 'src/templates/worker/admin.ts.tpl'],
    ['worker/api/_dokkebi/_panel/[[path]].ts', 'src/templates/worker/admin-api.ts.tpl'],
];

test('dok update: WORKER_FILES 버전과 템플릿 @dokkebi-version 이 일치', async () => {
    const updateSrc = await fs.readFile(path.join(ROOT, 'src/commands/update.js'), 'utf-8');

    for (const [rel, tplRel] of MANAGED) {
        const at = updateSrc.indexOf(`'${rel}'`);
        assert.ok(at >= 0, `WORKER_FILES 에 ${rel} 이 없습니다`);

        const segment = updateSrc.slice(at, at + 1500);
        const vm = /version:\s*(\d+)/.exec(segment);
        assert.ok(vm, `${rel} 의 version 을 찾지 못했습니다`);
        const managedVersion = Number(vm[1]);

        const tpl = await fs.readFile(path.join(ROOT, tplRel), 'utf-8');
        const hm = /^\/\/ @dokkebi-version:\s*(\d+)/m.exec(tpl);
        assert.ok(hm, `${tplRel} 에 @dokkebi-version 헤더가 없습니다`);
        const templateVersion = Number(hm[1]);

        assert.equal(
            managedVersion,
            templateVersion,
            `${rel}: WORKER_FILES=${managedVersion}, 템플릿=${templateVersion} — 버전을 함께 올리세요`,
        );
    }
});
