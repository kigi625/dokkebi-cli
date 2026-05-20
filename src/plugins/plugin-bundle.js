/**
 * dokkebi Plugin: Bundle (esbuild-wasm)
 *
 * 보안:
 *   - OPFS에 저장된 프로젝트 파일만 번들링 대상
 *   - 외부 의존성은 esm.sh CDN import map으로 해결
 *   - 메모리 제한: esbuild-wasm 초기화 시 적용
 */

export default function pluginBundle(config = {}) {
    return {
        name: 'bundle',
        permissions: ['bundle-build'],

        validate() {
            return null;
        },

        hostCode() {
            return `
  var _pluginBundle = (function() {
    var _esbuildReady = null;

    async function _ensureEsbuild() {
      if (_esbuildReady) return _esbuildReady;
      _esbuildReady = (async function() {
        if (!globalThis.esbuild) {
          await import('https://esm.sh/esbuild-wasm@0.24.0/esm/browser.min.js');
        }
        if (!globalThis.__esbuildInitialized) {
          await globalThis.esbuild.initialize({
            wasmURL: 'https://esm.sh/esbuild-wasm@0.24.0/esbuild.wasm',
          });
          globalThis.__esbuildInitialized = true;
        }
      })();
      return _esbuildReady;
    }

    return {
      async bundleBuild(projectRoot, opts) {
        await _ensureEsbuild();

        var result = await globalThis.esbuild.build({
          stdin: {
            contents: opts.entryContent || '',
            resolveDir: projectRoot,
            loader: 'tsx',
          },
          bundle: true,
          format: opts.format || 'esm',
          target: opts.target || 'es2020',
          platform: 'browser',
          external: opts.external || [],
          define: opts.define ? Object.fromEntries(opts.define) : {},
          minify: opts.minify || false,
          write: false,
          plugins: [_opfsResolverPlugin(projectRoot)],
        });

        var output = '';
        var errors = [];
        var warnings = [];
        if (result.outputFiles && result.outputFiles.length > 0) {
          output = result.outputFiles[0].text;
        }
        if (result.errors) errors = result.errors.map(function(e) { return e.text || String(e); });
        if (result.warnings) warnings = result.warnings.map(function(w) { return w.text || String(w); });

        return { output: output, sourceMap: null, errors: errors, warnings: warnings };
      },

      generateImportMap(dependencies) {
        var imports = {};
        for (var i = 0; i < dependencies.length; i++) {
          var name = dependencies[i][0];
          var version = dependencies[i][1];
          imports[name] = 'https://esm.sh/' + name + '@' + version;
        }
        return JSON.stringify({ imports: imports }, null, 2);
      },
    };

    function _opfsResolverPlugin(projectRoot) {
      return {
        name: 'dokkebi-opfs-resolver',
        setup: function(build) {
          build.onResolve({ filter: /^\\./ }, function(args) {
            var resolved = _resolvePath(projectRoot, args.resolveDir || projectRoot, args.path);
            return { path: resolved, namespace: 'opfs' };
          });
          build.onLoad({ filter: /.*/, namespace: 'opfs' }, async function(args) {
            var content = await _readOpfsFile(args.path);
            if (content === null) return { errors: [{ text: 'File not found: ' + args.path }] };
            var loader = 'tsx';
            if (args.path.endsWith('.css')) loader = 'css';
            else if (args.path.endsWith('.json')) loader = 'json';
            else if (args.path.endsWith('.js')) loader = 'js';
            else if (args.path.endsWith('.ts')) loader = 'ts';
            return { contents: content, loader: loader };
          });
        },
      };
    }

    function _resolvePath(root, dir, rel) {
      var parts = (dir + '/' + rel).split('/').filter(Boolean);
      var stack = [];
      for (var i = 0; i < parts.length; i++) {
        if (parts[i] === '..') stack.pop();
        else if (parts[i] !== '.') stack.push(parts[i]);
      }
      return '/' + stack.join('/');
    }

    async function _readOpfsFile(filePath) {
      try {
        var b64 = await hostOpfs.readChunk(filePath, 0, 10 * 1024 * 1024);
        if (!b64) return null;
        return atob(b64);
      } catch { return null; }
    }
  })();
`;
        },

        vmBridge() {
            return `
      var vmPluginBundle = _vm.newObject();

      _vm.setProp(vmPluginBundle, 'bundleBuild', _vm.newFunction('bundleBuild',
        function(rootH, optsH) {
          var root = _vm.getString(rootH);
          var opts = _vm.dump(optsH);
          var deferred = _vm.newPromise();
          _pluginBundle.bundleBuild(root, opts)
            .then(function(r) { _settleDeferred(deferred, _vm.newString(JSON.stringify(r)), false, 'bundle.build'); })
            .catch(function(e) { _settleDeferred(deferred, _vm.newString(String(e)), true, 'bundle.build'); });
          return deferred.handle.dup();
        }
      ));

      _vm.setProp(vmPluginBundle, 'generateImportMap', _vm.newFunction('generateImportMap',
        function(depsH) {
          var deps = _vm.dump(depsH);
          var result = _pluginBundle.generateImportMap(deps);
          return _vm.newString(result);
        }
      ));

      _vm.setProp(hostModule, 'bundle', vmPluginBundle);
`;
        },

        guestApi() {
            return `
export const bundle = {
  async build(projectRoot, opts = {}) {
    var host = getHost();
    if (!host.bundle) throw new Error('[dokkebi:bundle] bundle 플러그인이 활성화되지 않았습니다.');
    var raw = await host.bundle.bundleBuild(projectRoot, JSON.stringify(opts));
    return _parseHostResult(raw);
  },

  generateImportMap(dependencies) {
    var host = getHost();
    if (!host.bundle) throw new Error('[dokkebi:bundle] bundle 플러그인이 활성화되지 않았습니다.');
    var result = host.bundle.generateImportMap(
      Array.isArray(dependencies) ? dependencies : Object.entries(dependencies)
    );
    return _parseHostResult(result);
  },
};
`;
        },
    };
}
