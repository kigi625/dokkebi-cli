import { spawn } from 'child_process';

/**
 * 프론트엔드 디렉터리에서 빌드 커맨드 실행
 * @param {string} frontendDir   - 프론트엔드 루트 경로
 * @param {string|null} buildCommand - 빌드 커맨드 (null/undefined 시 'npm run build' 사용)
 */
export function runFrontendBuild(frontendDir, buildCommand) {
    // null / undefined 모두 기본값으로 처리
    const fullCmd = buildCommand || 'npm run build';
    const parts   = fullCmd.trim().split(/\s+/);
    const bin     = parts[0];        // 'npm' | 'vite' | ...
    const args    = parts.slice(1);  // ['run', 'build'] | ['build'] | ...

    return new Promise((resolve, reject) => {
        const child = spawn(bin, args, {
            cwd: frontendDir,
            stdio: 'inherit',
            shell: true,
        });
        child.on('error', reject);
        child.on('exit', (code) => {
            if (code === 0) resolve();
            else reject(new Error(`프론트엔드 빌드 종료 코드: ${code}`));
        });
    });
}
