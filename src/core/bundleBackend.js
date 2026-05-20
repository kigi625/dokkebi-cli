import * as esbuild from 'esbuild';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const ENV_LOADER_BANNER = `
(function(){
var path=require('path');var fs=require('fs');
var envPath=path.join(__dirname,'env.json');
if(fs.existsSync(envPath)){
  try{
    var env=JSON.parse(fs.readFileSync(envPath,'utf8'));
    for(var k in env) if(env[k]!=null) process.env[k]=String(env[k]);
  }catch(e){ console.error('[dokkebi] env.json load failed:',e.message); }
}
})();
`;

/**
 * Express 백엔드를 WebContainer에서 npm install 없이 실행하기 위해
 * 단일 번들로 묶습니다. 번들 상단에서 env.json을 읽어 process.env에 주입합니다.
 */
export async function bundleBackend({ backendDir, backendEntry, outDir }) {
    await fs.mkdir(outDir, { recursive: true });

    const outFile = path.join(outDir, 'server.bundle.cjs');
    const result = await esbuild.build({
        entryPoints: [backendEntry],
        bundle: true,
        platform: 'node',
        target: 'node18',
        format: 'cjs',
        outfile: outFile,
        absWorkingDir: backendDir,
        banner: { js: ENV_LOADER_BANNER },
        external: [
            'better-sqlite3',
            'mysql2',
            'pg',
            'pg-native',
            'sqlite3',
            'tedious',
        ],
        sourcemap: false,
        minify: false,
        metafile: true,
    });

    const size = (await fs.stat(outFile)).size;
    return {
        outFile,
        size,
        metafile: result.metafile,
        warnings: result.warnings,
    };
}
