import fs from 'fs/promises';
import path from 'path';

const DOKKEBI_FOLDER = 'dokkebi';
const BOOTSTRAP_SCRIPT_NAME = 'dokkebi-webcontainer-bootstrap.js';

/**
 * 빌드된 프론트엔드를 dokkebi 폴더로 복사하고,
 * WebContainer 부트스트랩 스크립트를 주입하여 프론트만 열어도 백엔드가 브라우저에서 기동되도록 함
 */
export async function emitDokkebi({
    sourceRoot,
    frontendDistDir,
    frontendDir,
    backendBundlePath,
    envJson,
    outputDirName = DOKKEBI_FOLDER,
}) {
    const dokkebiRoot = path.resolve(sourceRoot, outputDirName);
    await fs.mkdir(dokkebiRoot, { recursive: true });

    const frontendDistFull = path.join(frontendDir, frontendDistDir);
    const distExists = await fs.access(frontendDistFull).then(() => true).catch(() => false);
    if (!distExists) {
        throw new Error(`프론트엔드 빌드 결과가 없습니다: ${frontendDistFull}. 먼저 프론트엔드 빌드를 실행하세요.`);
    }

    // 프론트 빌드 결과물 복사 (원본 수정 없이 복사만)
    await copyRecursive(frontendDistFull, dokkebiRoot);

    // 백엔드 번들/설정을 dokkebi/backend/ 에 넣어서 브라우저에서 fetch로 불러와 마운트
    const backendDir = path.join(dokkebiRoot, 'backend');
    await fs.mkdir(backendDir, { recursive: true });
    const bundleContent = await fs.readFile(backendBundlePath, 'utf8');
    await fs.writeFile(path.join(backendDir, 'server.bundle.cjs'), bundleContent, 'utf8');
    await fs.writeFile(path.join(backendDir, 'env.json'), typeof envJson === 'string' ? envJson : JSON.stringify(envJson, null, 2), 'utf8');
    await fs.writeFile(
        path.join(backendDir, 'package.json'),
        JSON.stringify({ name: 'dokkebi-backend', type: 'commonjs' }, null, 2),
        'utf8'
    );

    // WebContainer 부트스트랩 스크립트 생성 (백엔드 URL 설정 + fetch 프록시)
    const bootstrapCode = getBootstrapScript();
    await fs.writeFile(path.join(dokkebiRoot, BOOTSTRAP_SCRIPT_NAME), bootstrapCode, 'utf8');

    // index.html 등 HTML에 부트스트랩 스크립트 주입
    const patched = await injectBootstrapIntoHtmlFiles(dokkebiRoot, BOOTSTRAP_SCRIPT_NAME);
    return {
        dokkebiRoot,
        backendDir,
        patchedHtmlCount: patched.length,
        patchedHtmlFiles: patched,
    };
}

async function copyRecursive(src, dest) {
    await fs.mkdir(dest, { recursive: true });
    const entries = await fs.readdir(src, { withFileTypes: true });
    for (const entry of entries) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        if (entry.isDirectory()) {
            await copyRecursive(srcPath, destPath);
        } else {
            await fs.copyFile(srcPath, destPath);
        }
    }
}

async function findHtmlFiles(dir) {
    const out = [];
    const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const e of entries) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
            out.push(...(await findHtmlFiles(full)));
        } else if (e.name.toLowerCase().endsWith('.html')) {
            out.push(full);
        }
    }
    return out;
}

async function injectBootstrapIntoHtmlFiles(dokkebiRoot, scriptName) {
    const htmlFiles = await findHtmlFiles(dokkebiRoot);
    const patched = [];
    const tag = `<script src="/${scriptName}" defer></script>`;
    for (const htmlPath of htmlFiles) {
        let html = await fs.readFile(htmlPath, 'utf8');
        if (html.includes(scriptName)) continue;
        if (/<\/head>/i.test(html)) {
            html = html.replace(/<\/head>/i, `${tag}\n</head>`);
        } else if (/<\/body>/i.test(html)) {
            html = html.replace(/<\/body>/i, `${tag}\n</body>`);
        } else {
            html = html + '\n' + tag;
        }
        await fs.writeFile(htmlPath, html, 'utf8');
        patched.push(htmlPath);
    }
    return patched;
}

function getBootstrapScript() {
    return `
(function() {
  'use strict';
  window.__DOKKEBI_BACKEND_URL__ = '';
  window.__DOKKEBI_READY__ = null;
  window.dokkebiReady = function() {
    if (window.__DOKKEBI_BACKEND_URL__) return Promise.resolve();
    if (!window.__DOKKEBI_READY__) window.__DOKKEBI_READY__ = new Promise(function(resolve, reject) {
      window.__DOKKEBI_READY_RESOLVE__ = resolve;
      window.__DOKKEBI_READY_REJECT__ = reject;
    });
    return window.__DOKKEBI_READY__;
  };

  var originalFetch = window.fetch;
  window.fetch = function(input, init) {
    var url = typeof input === 'string' ? input : (input && input.url);
    if (url && window.__DOKKEBI_BACKEND_URL__ && (url.startsWith('/') || url.startsWith('./'))) {
      var path = url.replace(/^\\.\\//, '/');
      if (path.startsWith('/api') || path.startsWith('/api/') || path === '/') {
        input = window.__DOKKEBI_BACKEND_URL__.replace(/\\/$/, '') + path;
      }
    }
    return originalFetch.call(this, input, init);
  };

  (async function boot() {
    try {
      console.log('[dokkebi] Loading WebContainer API...');
      var script = document.createElement('script');
      script.src = 'https://cdn.jsdelivr.net/npm/@webcontainer/api@1.1.14/dist/webcontainer.umd.js';
      script.crossOrigin = 'anonymous';
      await new Promise(function(res, rej) {
        script.onload = res;
        script.onerror = function() { rej(new Error('WebContainer script load failed (check COEP/network)')); };
        document.head.appendChild(script);
      });
      var WebContainer = window.WebContainer || (window.webcontainer && window.webcontainer.WebContainer);
      if (!WebContainer) {
        throw new Error('WebContainer API not found');
      }
      console.log('[dokkebi] Booting WebContainer...');
      var wc = await WebContainer.boot();
      console.log('[dokkebi] Fetching backend bundle...');
      var bundleRes = await fetch('/backend/server.bundle.cjs');
      if (!bundleRes.ok) throw new Error('Backend bundle fetch failed: ' + bundleRes.status);
      var envRes = await fetch('/backend/env.json').catch(function() { return null; });
      var envJson = envRes && envRes.ok ? await envRes.text() : '{}';
      var pkg = '{"name":"dokkebi-backend","type":"commonjs"}';
      await wc.mount({
        'server.bundle.cjs': { file: { contents: await bundleRes.text() } },
        'env.json': { file: { contents: envJson } },
        'package.json': { file: { contents: pkg } }
      });
      function setBackendReady(url) {
        if (!url || window.__DOKKEBI_BACKEND_URL__) return;
        console.log('[dokkebi] Backend ready:', url);
        window.__DOKKEBI_BACKEND_URL__ = url;
        if (window.__DOKKEBI_READY_RESOLVE__) {
          window.__DOKKEBI_READY_RESOLVE__();
          window.__DOKKEBI_READY_RESOLVE__ = null;
        }
        window.dispatchEvent(new Event('dokkebi-backend-ready'));
      }
      wc.on('server-ready', function(port, url) { setBackendReady(url); });
      wc.on('port', function(port, type, url) {
        if (type === 'open' && url) setBackendReady(url);
      });
      wc.on('error', function(err) {
        console.error('[dokkebi] WebContainer error:', err);
      });
      console.log('[dokkebi] Spawning node server.bundle.cjs...');
      var proc = await wc.spawn('node', ['server.bundle.cjs']);
      var decoder = new TextDecoder();
      proc.output.pipeTo(new WritableStream({
        write: function(chunk) {
          var text = chunk && chunk.length ? decoder.decode(chunk) : '';
          if (text && text.trim()) console.log('[dokkebi backend]', text.trim());
        }
      })).catch(function() {});
      await new Promise(function(resolve) {
        var t = setTimeout(function() {
          console.warn('[dokkebi] server-ready timeout 15s');
          resolve();
        }, 15000);
        if (window.__DOKKEBI_BACKEND_URL__) {
          clearTimeout(t);
          resolve();
        } else {
          wc.once('server-ready', function() { clearTimeout(t); resolve(); });
        }
      });
    } catch (e) {
      console.error('[dokkebi] WebContainer boot failed:', e);
      if (window.__DOKKEBI_READY_REJECT__) window.__DOKKEBI_READY_REJECT__(e);
    }
  })();
})();
`.trim();
}
