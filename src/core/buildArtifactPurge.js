/**
 * Dokkebi — 빌드 메타 외부 노출 차단 (SENSITIVE_FILENAMES 비우기)
 *
 * dist/dokkebi/*.json 의 빌드 메타들은 모두 빌드 타임에 worker/db.ts 안에
 * 인라인 임베드된다. 클라이언트 부트스트랩은 *.json 을 fetch 하지 않는다.
 * 따라서 dist/ 의 메타 JSON 은 외부 노출되어선 안 되며, 배포되는 정적 자산에서는
 * 빈 `{}` 로 비워야 한다.
 *
 * Cloudflare Pages `_redirects` 의 force(`!`) 는 404 status 를 지원하지 않아
 * 차단 규칙이 무시된다. 따라서 "비우기" 가 유일하게 신뢰할 수 있는 방법.
 *
 * 통과시켜야 하는 것 (절대 비우면 안 됨):
 *   - backend.bundle.*.enc            — 클라가 부트스트랩에서 fetch (암호화된 백엔드 번들)
 *   - *.wasm                          — QuickJS 바이너리
 *   - dokkebi-webcontainer-bootstrap.js — 부트스트랩 스크립트
 *
 * 비우기 대상:
 *   - dist/dokkebi/secrets.json
 *   - dist/dokkebi/env-secrets.json
 *   - dist/dokkebi/env-secrets.js          (legacy)
 *   - dist/dokkebi/sql-allowlist.json      — SQL/policy 메타 (인라인 임베드됨)
 *   - dist/dokkebi/query-registry.json     — SQL 평문/컬럼명 (인라인 임베드됨)
 *   - dist/dokkebi/wire-runtime.json       — wire 회전 메타 (인라인 임베드됨)
 *   - dist/dokkebi/backend-bundle.chunks.json — chunk hash/salt (워커에 임베드됨)
 *   - dist/dokkebi/backend-bundle.sha256   — 번들 해시 (파일명에 이미 포함되어 중복)
 *
 * Idempotent — 이미 비어있으면 noop. 파일이 없으면 무시.
 */

import path from 'path';
import fs from 'fs/promises';

export const SENSITIVE_FILENAMES = new Set([
    'env-secrets.json',
    'env-secrets.js',
    'secrets.json',
    'query-registry.json',
    'sql-allowlist.json',
    'wire-runtime.json',
    'backend-bundle.chunks.json',
    'backend-bundle.sha256',
]);

/**
 * dist/dokkebi/ 와 dist 전체를 재귀 스캔해 SENSITIVE_FILENAMES 매칭 파일을
 * `{}` 로 덮어쓴다.
 *
 * @param {string} distDir - 빌드 산출물 루트 (dist)
 * @returns {Promise<{ purged: string[] }>}
 */
export async function purgeBuildArtifactsFromDist(distDir) {
    const purged = [];
    const dokkebiDir = path.join(distDir, 'dokkebi');
    try { await fs.mkdir(dokkebiDir, { recursive: true }); } catch { /* ignore */ }

    for (const file of SENSITIVE_FILENAMES) {
        const p = path.join(dokkebiDir, file);
        try {
            await fs.access(p);
            await fs.writeFile(p, '{}', 'utf-8');
            purged.push(path.relative(distDir, p));
        } catch { /* 없으면 skip */ }
    }

    await scanAndPurge(distDir, distDir, purged);
    return { purged };
}

async function scanAndPurge(rootDir, dir, purged) {
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            await scanAndPurge(rootDir, full, purged);
        } else if (SENSITIVE_FILENAMES.has(entry.name)) {
            const rel = path.relative(rootDir, full);
            // 이미 dokkebi/ 직속에서 처리한 파일은 건너뛴다.
            if (purged.includes(rel)) continue;
            try {
                await fs.writeFile(full, '{}', 'utf-8');
                purged.push(rel);
            } catch { /* ignore */ }
        }
    }
}
