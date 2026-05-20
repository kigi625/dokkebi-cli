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
      var path = url.replace(/^\.\//, '/');
      if (path.startsWith('/api') || path.startsWith('/api/') || path === '/') {
        input = window.__DOKKEBI_BACKEND_URL__.replace(/\/$/, '') + path;
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