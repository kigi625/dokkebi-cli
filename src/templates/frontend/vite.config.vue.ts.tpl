import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import path from 'path';
import fs from 'fs';

/**
 * dist/ 정리 시 dist/dokkebi/ 는 보존하는 플러그인
 * (dok build/dev 가 생성한 WASM 아티팩트 보호)
 */
function preserveDokkebiPlugin() {
  const distDir = path.resolve(import.meta.dirname, '../dist');
  return {
    name: 'preserve-dokkebi-wasm',
    apply: 'build',
    buildStart() {
      if (!fs.existsSync(distDir)) return;
      const entries = fs.readdirSync(distDir);
      let cleaned = 0;
      for (const entry of entries) {
        if (entry === 'dokkebi') continue;
        fs.rmSync(path.join(distDir, entry), { recursive: true, force: true });
        cleaned++;
      }
      if (cleaned > 0) {
        console.log('[preserve-dokkebi] dist/ 정리 완료 (dokkebi/ 보존, ' + cleaned + '개 삭제)');
      }
    },
  };
}

export default defineConfig({
  plugins: [vue(), preserveDokkebiPlugin()],
  build: {
    outDir: '../dist',
    emptyOutDir: false,
  },
  server: {
    port: 5173,
  },
});
