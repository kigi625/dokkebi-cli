/**
 * dokkebi Plugin: Fetch (도메인 제한 HTTP)
 *
 * 보안:
 *   - allowedDomains 화이트리스트로 WASM에서 접근 가능한 도메인을 제한
 *   - 미설정 시 모든 요청 차단
 *   - maxConcurrent: 동시 요청 수 제한 (기본 5)
 *   - timeoutMs: 요청 타임아웃 (기본 30초)
 *   - CORS 제한은 브라우저가 자체적으로 적용
 */

export default function pluginFetch(config = {}) {
    const allowedDomains = config.allowedDomains || [];
    const maxConcurrent = config.maxConcurrent || 5;
    const timeoutMs = config.timeoutMs || 30000;

    return {
        name: 'fetch',
        permissions: ['http-fetch'],

        validate(cfg) {
            if (!cfg.allowedDomains || cfg.allowedDomains.length === 0) {
                return 'allowedDomains가 비어있습니다. 최소 1개 도메인을 설정하세요.';
            }
            return null;
        },

        hostCode(cfg) {
            const domains = JSON.stringify(cfg.allowedDomains || []);
            return `
  var _pluginFetch = (function() {
    var _allowedDomains = ${domains};
    var _maxConcurrent = ${maxConcurrent};
    var _timeoutMs = ${timeoutMs};
    var _activeFetches = 0;

    function _isDomainAllowed(url) {
      try {
        var parsed = new URL(url);
        // 스킴 제한: http / https 만 허용 (file://, data:, javascript: 차단)
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
        var hostname = parsed.hostname.toLowerCase();
        for (var i = 0; i < _allowedDomains.length; i++) {
          var d = String(_allowedDomains[i] || '').toLowerCase().replace(/^\\./, '');
          // TLD 단독(점 없음) 화이트리스트 거부 — 'com' 같은 과도한 허용 방지
          if (d.indexOf('.') === -1) continue;
          if (hostname === d || hostname.endsWith('.' + d)) return true;
        }
      } catch(e) { /* invalid URL */ }
      return false;
    }

    return {
      async httpFetch(url, opts) {
        if (!_isDomainAllowed(url)) {
          throw new Error('[plugin:fetch] 차단된 도메인: ' + url + ' (허용: ' + _allowedDomains.join(', ') + ')');
        }
        if (_activeFetches >= _maxConcurrent) {
          throw new Error('[plugin:fetch] 동시 요청 한도 초과 (' + _maxConcurrent + ')');
        }

        _activeFetches++;
        try {
          var fetchOpts = {
            method: opts.method || 'GET',
            headers: {},
          };
          if (opts.headers) {
            for (var i = 0; i < opts.headers.length; i++) {
              fetchOpts.headers[opts.headers[i][0]] = opts.headers[i][1];
            }
          }
          if (opts.body) fetchOpts.body = opts.body;

          var ctrl = new AbortController();
          fetchOpts.signal = ctrl.signal;
          var timer = setTimeout(function() { ctrl.abort(); }, opts.timeoutMs || _timeoutMs);

          var resp = await _fetch(url, fetchOpts);
          clearTimeout(timer);

          var body = await resp.text();
          var respHeaders = [];
          resp.headers.forEach(function(v, k) { respHeaders.push([k, v]); });

          return { status: resp.status, body: body, headers: respHeaders };
        } finally {
          _activeFetches--;
        }
      },
    };
  })();
`;
        },

        vmBridge() {
            return `
      var vmPluginFetch = _vm.newObject();
      _vm.setProp(vmPluginFetch, 'httpFetch', _vm.newFunction('httpFetch',
        function(urlH, optsH) {
          var url = _vm.getString(urlH);
          var opts = _vm.dump(optsH);
          var deferred = _vm.newPromise();
          _pluginFetch.httpFetch(url, opts)
            .then(function(r) { _settleDeferred(deferred, _vm.newString(JSON.stringify(r)), false, 'fetch'); })
            .catch(function(e) { _settleDeferred(deferred, _vm.newString(String(e)), true, 'fetch: ' + url); });
          return deferred.handle.dup();
        }
      ));
      _vm.setProp(hostModule, 'fetch', vmPluginFetch);
`;
        },

        guestApi() {
            return `
export const httpFetch = {
  async request(url, opts = {}) {
    var host = getHost();
    if (!host.fetch) throw new Error('[dokkebi:fetch] fetch 플러그인이 활성화되지 않았습니다.');
    var raw = await host.fetch.httpFetch(url, JSON.stringify({
      method: opts.method || 'GET',
      headers: opts.headers ? Object.entries(opts.headers) : [],
      body: opts.body || null,
      timeoutMs: opts.timeoutMs || null,
    }));
    return _parseHostResult(raw);
  },

  async get(url, headers) {
    return this.request(url, { method: 'GET', headers: headers });
  },

  async post(url, body, headers) {
    return this.request(url, {
      method: 'POST',
      body: typeof body === 'string' ? body : JSON.stringify(body),
      headers: { 'Content-Type': 'application/json', ...(headers || {}) },
    });
  },
};
`;
        },
    };
}
