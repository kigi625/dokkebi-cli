/**
 * 로컬 DB(sql.js) 에셋을 빌드 산출물로 복사한다.
 *
 * 배경: `localDbMode`(DB 자격증명 없음) 앱은 부트스트랩에서 sql.js 를 CDN 에서
 * 로드했다. CDN/패키지 변조 시 origin 코드 실행으로 이어질 수 있어,
 * 빌드 시 sql.js 를 `dist/dokkebi/` 로 복사하고 same-origin 에서 로드한다.
 * (CDN 은 파일이 없을 때만 SRI 와 함께 fallback)
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const CLI_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** sql.js dist 디렉터리 경로 (패키지 exports 우회 포함) */
export function resolveSqlJsDistDir() {
    try {
        const pkg = require.resolve('sql.js/package.json');
        return path.join(path.dirname(pkg), 'dist');
    } catch {
        return path.join(CLI_ROOT, 'node_modules', 'sql.js', 'dist');
    }
}

/**
 * @param {string} destDir - 예: dist/dokkebi
 * @returns {Promise<boolean>} 복사 성공 여부
 */
export async function copySqlJsAssets(destDir) {
    const src = resolveSqlJsDistDir();
    const files = ['sql-wasm.js', 'sql-wasm.wasm'];
    for (const f of files) {
        await fs.access(path.join(src, f));
    }
    await fs.mkdir(destDir, { recursive: true });
    for (const f of files) {
        await fs.copyFile(path.join(src, f), path.join(destDir, f));
    }
    return true;
}
