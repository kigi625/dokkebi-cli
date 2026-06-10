
<!-- dokkebi v3 Bootstrap (자동 생성됨) -->
<script type="module">
// ═══════════════════════════════════════════════════════════
// dokkebi v3 Bootstrap
//   보안: ECDH P-256 + HKDF + AES-256-GCM + HMAC-SHA256
//   WASM: QuickJS Async VM (로컬 번들, CDN 없음)
// ═══════════════════════════════════════════════════════════
window.__DOKKEBI_BUILD_VER__ = '__DOKKEBI_PH_BUILD_VER__';
// Query Registry 모드 힌트 (dev/learn 전용 — 서버에 _debugSql 포함)
window.__DOKKEBI_QUERY_LEARN__ = __DOKKEBI_PH_BOOL_QUERY_LEARN__;
window.__DOKKEBI_CAPABILITY_GUARDS__ = "__DOKKEBI_PH_CAPABILITY_GUARDS__";

// ═══════════════════════════════════════════════════════════
//  Caller Guard (XSS / DevTools 방어 레이어)
//
//  - 빌드 시 frontend 청크 경로(allowedScripts)가 박혀 들어옴
//  - 부트스트랩이 가장 먼저 실행되므로, user code 가 prototype 을 더럽히기
//    전에 Error / Set / RegExp 등 native 들을 closure 에 캡처해 둠
//  - 매 dokkebi.request() / fetch /api/* 호출 시 stack 의 source URL 을
//    파싱해 allowedScripts 에 있는지 검증
//  - 'audit' 모드: 의심 호출 sendBeacon 으로 보고 후 통과
//  - 'block' 모드: 의심 호출 차단 + 보고
// ═══════════════════════════════════════════════════════════
const __DOKKEBI_CALLER_GUARD__ = (function _setupCallerGuard() {
  var mode = "__DOKKEBI_PH_CALLER_CHECK__"; // 'off' | 'audit' | 'block'
  var allowedArr = "__DOKKEBI_PH_ALLOWED_SCRIPTS__";
  var auditUrl = "__DOKKEBI_PH_CALLER_AUDIT_URL__";

  // placeholder 치환이 안 됐거나(레거시 빌드) allowlist 가 비었으면 off 로 안전 폴백
  if (mode !== 'audit' && mode !== 'block') mode = 'off';
  if (!Array.isArray(allowedArr) || allowedArr.length === 0) mode = 'off';

  if (mode === 'off') {
    return {
      mode: 'off',
      isInternal: function () { return true; },
      audit: function () { /* noop */ },
    };
  }

  // ── native API capture (user code 이전에 잡아둠) ──
  var _Error = Error;
  var _capStk = _Error.captureStackTrace;
  var _stkDesc = Object.getOwnPropertyDescriptor(_Error.prototype, 'stack');
  var _stkGet = _stkDesc && _stkDesc.get ? _stkDesc.get : null;
  var _Set = Set;
  var _setHas = _Set.prototype.has;
  var _splitFn = String.prototype.split;
  var _strSliceFn = String.prototype.slice;
  var _strStartsWithFn = String.prototype.startsWith;
  var _strIndexOfFn = String.prototype.indexOf;
  var _matchFn = String.prototype.match;
  var _jsExtRe = /\.(m|c)?js$/i;
  // stack frame 내 URL 매칭 — .js 확장자 제한을 없애서 HTML(inline 부트스트랩) URL 도 잡는다.
  //   V8 :  "    at fn (https://host/path/file.js:NN:CC)" / 또는 "...host/page/:NN:CC"
  //   WebKit: "fn@https://host/path/file.js:NN:CC" / "@https://host/page/:NN:CC"
  // 공통적으로 끝에 `:line:col` 이 붙는 점을 기준으로 잡는다.
  var _FRAME_URL_RE = /\bhttps?:\/\/[^\s)'"]+?(?=:\d+:\d+)/g;
  // 엔진 판별 — Safari 16.4+ 도 Error.captureStackTrace 를 호환 도입했기 때문에
  //   기능 존재만으로는 V8/WebKit 을 구분할 수 없다.
  //   → 실제 stack 문자열 포맷으로 판별: V8 은 "Error\n    at ..." 로 시작, WebKit 은 바로 frame.
  var _isV8Engine = (function _detectV8() {
    try {
      var e = new _Error('_dok_probe');
      var s = _stkGet ? _stkGet.call(e) : e.stack;
      if (typeof s !== 'string' || s.length === 0) return false;
      return s.indexOf('Error') === 0; // V8 첫 줄 "Error" / WebKit 은 frame
    } catch (_) {
      return false;
    }
  })();
  // 주의: Error 와 Error.prototype 은 freeze 하지 않는다.
  //   class X extends Error 패턴(React/router 등의 custom 에러)이 prototype 의
  //   constructor 재할당을 필요로 하므로 freeze 시 TypeError 가 난다.
  //   stack 위조 방어는 위에서 closure 에 capture 한 _stkGet / _capStk 만 사용하는 것으로 충분.
  //   _stkGet.call(e) 로 native slot 을 직접 읽기 때문에 attacker 가 prototype 의
  //   stack getter 를 덮어써도 우리 호출은 영향받지 않는다.

  var allowed;
  try {
    allowed = new _Set(Array.isArray(allowedArr) ? allowedArr : []);
  } catch (_) {
    allowed = new _Set();
  }
  var pageOrigin = (function () {
    try { return location.origin; } catch (_) { return ''; }
  })();

  function _captureStack(hereFn) {
    try {
      var e = new _Error();
      if (_capStk) {
        try { _capStk.call(_Error, e, hereFn); } catch (_) { /* V8 only */ }
      }
      var s = _stkGet ? _stkGet.call(e) : e.stack;
      return typeof s === 'string' ? s : '';
    } catch (_) {
      return '';
    }
  }

  function _extractCallerUrls(stack) {
    if (!stack) return [];
    var lines = _splitFn.call(stack, '\n');
    var urls = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      _FRAME_URL_RE.lastIndex = 0;
      var m;
      while ((m = _FRAME_URL_RE.exec(line)) !== null) {
        urls.push(m[0]);
      }
    }
    return urls;
  }

  // 마지막 판정 진단 (audit 콘솔 로그에 노출)
  var _lastDecision = null;

  function _isInternalCall(hereFn) {
    var stack = _captureStack(hereFn || _isInternalCall);
    var urls = _extractCallerUrls(stack);

    var seenInternal = false;   // .js 가 allowlist 안에 있음
    var seenExternal = false;   // 의심스러운 .js (allowlist 밖) 또는 cross-origin
    var seenInline = false;     // same-origin 의 비-JS URL — 우리가 발행한 HTML 안의 inline script
    var externals = [];
    var internals = [];
    var inlines = [];

    for (var i = 0; i < urls.length; i++) {
      var u = urls[i];
      // ?query / #hash 제거
      var q = _strIndexOfFn.call(u, '?');
      if (q >= 0) u = _strSliceFn.call(u, 0, q);
      var h = _strIndexOfFn.call(u, '#');
      if (h >= 0) u = _strSliceFn.call(u, 0, h);

      if (pageOrigin && _strStartsWithFn.call(u, pageOrigin)) {
        var pathOnly = _strSliceFn.call(u, pageOrigin.length);
        if (_jsExtRe.test(pathOnly)) {
          // same-origin .js — allowlist 검사
          if (_setHas.call(allowed, pathOnly)) {
            seenInternal = true;
            internals.push(pathOnly);
          } else {
            seenExternal = true;
            externals.push(pathOnly);
          }
        } else {
          // same-origin 비-JS URL = inline 부트스트랩 모듈이 박힌 HTML 페이지 URL.
          //   부트스트랩은 빌드가 발행한 우리 HTML 의 일부이므로 그 자체로 신뢰 가능.
          //   (단, V8 의 경우 사용자 번들 .js frame 도 stack 에 함께 잡히므로
          //   inline 단독 판정에 매달리지 않는다 — 아래 decision 로직 참조.)
          seenInline = true;
          inlines.push(pathOnly);
        }
      } else {
        // cross-origin URL — 신뢰 불가
        seenExternal = true;
        externals.push(u);
      }
    }

    var decision;
    if (seenInternal && !seenExternal) {
      // 명시적으로 allowlist 안의 사용자 번들이 stack 에 있고 외부는 없음 → 통과
      decision = true;
    } else if (seenExternal && !seenInternal) {
      // 명시적으로 외부 URL 만 stack 에 있고 내부는 전무 → 차단
      decision = false;
    } else if (seenExternal && seenInternal) {
      // mixed: 내부 + 외부 같이 있음 → 의심. (XSS 가 자사 번들과 자기 스크립트 섞어서 호출하는 케이스)
      decision = false;
    } else {
      // seenInternal=false, seenExternal=false:
      //   - urls.length === 0 (stack 자체가 빔) — 콘솔/eval 또는 WebKit async 손실
      //   - 또는 seenInline 만 true (전부 inline 부트스트랩 frame) — WebKit 의 정상 케이스
      // 인라인 frame 만으로 신뢰할지를 결정.
      //   V8: 정상 호출이면 .js frame 이 반드시 한 줄은 잡혀야 한다. → 의심으로 처리(block).
      //   WebKit: async 손실로 .js 가 안 잡히는 정상 케이스가 흔함 → inline frame 이 있으면 통과.
      //   (XSS 인라인 주입 같은 위협은 handshake nonce / JWT / SQL allowlist 등 다른 레이어가 책임.)
      if (_isV8Engine) {
        decision = false;
      } else {
        decision = true;
      }
    }

    _lastDecision = {
      engine: _isV8Engine ? 'v8' : 'webkit',
      decision: decision,
      urlCount: urls.length,
      seenInternal: seenInternal,
      seenExternal: seenExternal,
      seenInline: seenInline,
      internals: internals,
      externals: externals,
      inlines: inlines,
      stackHead: _strSliceFn.call(stack || '', 0, 600),
    };
    return decision;
  }

  var _auditedKinds = Object.create(null); // 동일 종류 반복 보고 억제
  function _audit(kind, info) {
    try {
      var key = kind + '|' + (info && info.path ? info.path : '');
      _auditedKinds[key] = (_auditedKinds[key] || 0) + 1;
      if (_auditedKinds[key] > 5) return; // 한 페이지 lifetime 동안 종류당 최대 5건
      var stack = _captureStack(_audit);
      var payload = JSON.stringify({
        kind: kind,
        info: info || null,
        stack: _strSliceFn.call(stack, 0, 2000),
        ua: typeof navigator !== 'undefined' ? navigator.userAgent : '',
        build: window.__DOKKEBI_BUILD_VER__ || '',
        mode: mode,
        decision: _lastDecision,
        ts: Date.now(),
      });
      // auditUrl 이 빈 문자열이면 네트워크 보고를 보내지 않는다 (콘솔 로깅만).
      // dokkebi.config.js 의 security.callerCheckAuditUrl 로 endpoint 지정 시에만 전송.
      if (auditUrl && typeof auditUrl === 'string') {
        try {
          if (typeof navigator !== 'undefined' && typeof navigator.sendBeacon === 'function') {
            var blob = new Blob([payload], { type: 'application/json' });
            navigator.sendBeacon(auditUrl, blob);
          }
        } catch (_) { /* sendBeacon 실패 무시 */ }
      }
      try { console.warn('[dokkebi:caller-guard] ' + kind, info, _lastDecision); } catch (_) { /* noop */ }
    } catch (_) { /* audit 자체 실패는 무시 */ }
  }

  return {
    mode: mode,
    isInternal: _isInternalCall,
    audit: _audit,
  };
})();

// dokkebiVersionCheck() 에서 실제 구현으로 교체됨 — 초기에는 무해한 no-op
window.__dokkebi_checkVersion = function () {};

function _dokkebiPathFromFetchUrl(url) {
  if (url == null) return '';
  var s = String(url);
  try {
    if (/^https?:\/\//i.test(s)) {
      var u = new URL(s);
      if (u.origin !== location.origin) return '';
      return (u.pathname || '').split('?')[0] || '';
    }
  } catch (_) { /* noop */ }
  var qi = s.indexOf('?');
  return (qi >= 0 ? s.slice(0, qi) : s) || '';
}

/** /api/* 또는 내부 DB 프록시 응답 후 build-version.json 비교(30s 스로틀은 _check 내부) */
function _dokkebiScheduleVersionProbeForPath(path) {
  try {
    var p = String(path || '');
    if (p.indexOf('/api/') !== 0 && p.indexOf('./api/') !== 0) return;
    if (p.indexOf('/api/_dokkebi/log') === 0) return;
    queueMicrotask(function () {
      try {
        if (typeof window.__dokkebi_checkVersion === 'function') {
          window.__dokkebi_checkVersion();
        }
      } catch (_) { /* noop */ }
    });
  } catch (_) { /* noop */ }
}

(async function dokkebiInit() {
  'use strict';
  // index.html 에 부트스트랩이 두 번 주입되거나 모듈이 이중 로드되면 첫 실행이 OPFS 세션을
  // 저장한 뒤 __DOKKEBI_BC_KEY__ 만 메모리에서 지우고, 두 번째 실행이 "세션 복원 성공 +
  // 복호화 키 없음"으로 불필요한 재핸드셰이크가 난다 → 단일 실행 강제.
  if (globalThis.__DOKKEBI_BOOTSTRAP__) {
    console.warn('[dokkebi] 부트스트랩 중복 실행 무시 (동일 탭에 dok 스크립트가 2회 이상 있습니다)');
    return;
  }
  globalThis.__DOKKEBI_BOOTSTRAP__ = true;

  const _LOG_COLLECT_MIN = "__DOKKEBI_PH_LOG_MIN__";
  function _shouldSendRemoteLog(lv) {
    var order = ['debug', 'log', 'info', 'warn', 'error'];
    var mi = order.indexOf(String(_LOG_COLLECT_MIN).toLowerCase());
    var ei = order.indexOf(String(lv || '').toLowerCase());
    if (mi < 0) mi = order.indexOf('error');
    if (ei < 0) return false;
    return ei >= mi;
  }
  const _PAYLOAD_WIRE = "__DOKKEBI_PH_PAYLOAD_WIRE__";

  // ── 개발자 콘솔 배너 ─────────────────────────────────────
  console.log(
    '%c' + __DOKKEBI_PH_ATTR_BRAND_L__ + '%c' + __DOKKEBI_PH_ATTR_BRAND_R__,
    'background:#6e40c9;color:#fff;font-weight:700;font-size:13px;padding:4px 8px;border-radius:4px 0 0 4px;',
    'background:#1a1a2e;color:#a78bfa;font-size:13px;padding:4px 8px;border-radius:0 4px 4px 0;'
  );
  console.log(
    '%c' + __DOKKEBI_PH_ATTR_SUBTITLE__,
    'color:#6b7280;font-size:11px;'
  );
  console.log(
    '%c' + __DOKKEBI_PH_ATTR_CREATOR__,
    'color:#a78bfa;font-size:11px;font-weight:600;'
  );
  console.log(
    '%c' + __DOKKEBI_PH_ATTR_CONTACT_L__ + '%c' + __DOKKEBI_PH_ATTR_CONTACT_URL__,
    'color:#6b7280;font-size:11px;',
    'color:#60a5fa;font-size:11px;text-decoration:underline;'
  );
  console.log(
    '%c' + __DOKKEBI_PH_ATTR_LICENSE__,
    'color:#6b7280;font-size:11px;'
  );
  // ─────────────────────────────────────────────────────────

  // ── 로컬 DB 모드 설정 ──────────────────────────────────
  const _LOCAL_DB_MODE = __DOKKEBI_PH_BOOL_LOCAL_DB__;
  const _MIGRATION_SQL = "__DOKKEBI_PH_MIGRATION_SQL__";

  const _origFetchInner = window.fetch.bind(window);
  const _fetch = async function (input, opts) {
    var res = await _origFetchInner(input, opts);
    try {
      var u = typeof input === 'string' ? input : (input && input.url);
      _dokkebiScheduleVersionProbeForPath(_dokkebiPathFromFetchUrl(u));
    } catch (_) { /* noop */ }
    return res;
  };

  // ────────────────────────────────────────────────────────
  // OPFS 캐시 레이어 (세션 영속화 + 번들 캐싱 + 오프라인 쿼리)
  // ────────────────────────────────────────────────────────
  const _OPFS_ROOT = 'dokkebi-cache';
  const _LOCAL_DB_FILE = 'local-db-' + '__DOKKEBI_PH_BUILD_VER__'.slice(0, 12) + '.sqlite';
  const _SESSION_TTL = 8 * 60 * 60 * 1000;
  let _opfsDir = null;

  async function _opfsInit() {
    try {
      var root = await navigator.storage.getDirectory();
      _opfsDir = await root.getDirectoryHandle(_OPFS_ROOT, { create: true });
      return true;
    } catch { return false; }
  }

  async function _opfsWrite(name, data) {
    if (!_opfsDir) return false;
    try {
      var fh = await _opfsDir.getFileHandle(name, { create: true });
      var w = await fh.createWritable();
      await w.write(data);
      await w.close();
      return true;
    } catch { return false; }
  }

  async function _opfsReadText(name) {
    if (!_opfsDir) return null;
    try {
      var fh = await _opfsDir.getFileHandle(name);
      var f = await fh.getFile();
      return f.size > 0 ? await f.text() : null;
    } catch { return null; }
  }

  async function _opfsDelete(name) {
    if (!_opfsDir) return;
    try { await _opfsDir.removeEntry(name); } catch {}
  }

  // ── OPFS 세션 암호화 레이어 ────────────────────────────
  // origin + userAgent 기반 PBKDF2 파생 키로 세션 데이터를 AES-GCM 래핑
  // XSS로 OPFS 파일을 읽어도 다른 origin/환경에서는 복호화 불가
  async function _deriveStorageKey() {
    var material = location.origin + '|' + navigator.userAgent + '|dokkebi-opfs-wrap';
    var raw = new TextEncoder().encode(material);
    var keyMaterial = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: new TextEncoder().encode('dokkebi-session-salt'), iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  // overrideSecrets 가 주어지면 _envSecretMap snapshot 보다 그것을 우선 사용.
  // 핸드셰이크 본문에서 encSecrets 를 푼 직후 그 평문을 그대로 넘겨, 메인 흐름의
  // _forgetClientSecret('__DOKKEBI_BC_KEY__') 와의 마이크로태스크 경합을 차단한다.
  async function _saveSessionToOPFS(sharedB64, sid, overrideSecrets) {
    try {
      var wrapKey = await _deriveStorageKey();
      var iv = crypto.getRandomValues(new Uint8Array(12));
      var sessionData = { shared: sharedB64, sid: sid, ts: Date.now(), bh: '__DOKKEBI_PH_BUNDLE_HASH__' };
      var safeSecrets;
      if (overrideSecrets && typeof overrideSecrets === 'object') {
        safeSecrets = {};
        for (var k in _CLIENT_SECRET_KEYS) {
          if (Object.prototype.hasOwnProperty.call(overrideSecrets, k) && overrideSecrets[k]) {
            safeSecrets[k] = overrideSecrets[k];
          }
        }
      } else {
        safeSecrets = _clientSecretsForStorage();
      }
      if (Object.keys(safeSecrets).length > 0) sessionData.secrets = safeSecrets;
      var plain = new TextEncoder().encode(JSON.stringify(sessionData));
      var enc = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, wrapKey, plain));
      var payload = JSON.stringify({ iv: btoa(String.fromCharCode.apply(null, iv)), enc: btoa(String.fromCharCode.apply(null, enc)), v: 2 });
      await _opfsWrite('ecdh-session.json', payload);
    } catch { /* 암호화 저장 실패 시 무시 — 다음 로드에서 재핸드셰이크 */ }
  }

  async function _restoreSessionFromOPFS() {
    var raw = await _opfsReadText('ecdh-session.json');
    if (!raw) {
      console.debug('[dokkebi] OPFS 세션 복원 생략: ecdh-session.json 없음');
      return false;
    }
    try {
      var stored = JSON.parse(raw);
      var d;
      if (stored.v === 2) {
        var wrapKey = await _deriveStorageKey();
        var iv = Uint8Array.from(atob(stored.iv), function(c) { return c.charCodeAt(0); });
        var encBytes = Uint8Array.from(atob(stored.enc), function(c) { return c.charCodeAt(0); });
        var plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, wrapKey, encBytes);
        d = JSON.parse(new TextDecoder().decode(plainBuf));
      } else {
        d = stored;
      }
      if (Date.now() - d.ts > _SESSION_TTL) {
        console.debug('[dokkebi] OPFS 세션 복원 실패: TTL 초과(8h), ecdh-session.json 삭제 후 재핸드셰이크');
        await _opfsDelete('ecdh-session.json');
        return false;
      }
      if (d.bh !== '__DOKKEBI_PH_BUNDLE_HASH__') {
        console.debug('[dokkebi] OPFS 세션 복원 실패: bundle 해시 불일치', d.bh || '(없음)', 'vs', '__DOKKEBI_PH_BUNDLE_HASH__');
        await _opfsDelete('ecdh-session.json');
        return false;
      }
      var sharedBuf = Uint8Array.from(atob(d.shared), function(c) { return c.charCodeAt(0); }).buffer;
      var hkdfKey = await crypto.subtle.importKey('raw', sharedBuf, 'HKDF', false, ['deriveKey', 'deriveBits']);
      _encKey = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('dokkebi-enc') },
        hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
      );
      var sBits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('dokkebi-sig') },
        hkdfKey, 256
      );
      _sigKey = await crypto.subtle.importKey('raw', sBits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      _sessionId = d.sid;
      // Phase 1-① — OPFS 복원 시 counter 를 timestamp(ms) 기반 큰 값으로 시작.
      // 0 으로 리셋하면 서버 메모리에 살아있는 같은 sid 의 lastCounter(>0) 보다
      // 작아 REPLAY_DETECTED 가 발생한다 (페이지 새로고침 후 재현).
      // Date.now() 는 항상 이전 요청의 순차 카운터보다 훨씬 크므로
      // 서버의 어떤 lastCounter 도 초과한다.
      try { _reqCounter = Date.now(); } catch {}
      // OPFS에 저장된 클라이언트 허용 Secret만 복원
      if (d.secrets) {
        _storeClientSecrets(d.secrets);
      }
      return true;
    } catch (e) {
      console.debug('[dokkebi] OPFS 세션 복원 실패: 복호화/파싱 예외', e && e.message ? e.message : e);
      await _opfsDelete('ecdh-session.json');
      return false;
    }
  }

  async function _clearSessionOPFS() { await _opfsDelete('ecdh-session.json'); }
  async function _clearBundleOPFS() {
    await _opfsDelete('bundle-hash.txt');
    await _opfsDelete('backend.bundle.enc');
    await _opfsDelete('backend.bytecode');
    await _opfsDelete('backend-bundle.js');
  }

  async function _loadCachedBundle(hash) {
    if (!hash || !_opfsDir) return null;
    var stored = await _opfsReadText('bundle-hash.txt');
    if (stored !== hash) return null;
    var _bcMode = __DOKKEBI_PH_BOOL_BYTECODE_MODE__;
    var _etMode = __DOKKEBI_PH_BOOL_ENCRYPTED_TEXT__;
    if (_bcMode || _etMode) {
      try {
        var _cacheFile = _etMode ? 'backend.bundle.enc' : 'backend.bytecode';
        var fh = await _opfsDir.getFileHandle(_cacheFile, { create: false });
        var f = await fh.getFile();
        return new Uint8Array(await f.arrayBuffer());
      } catch { return null; }
    }
    return _opfsReadText('backend-bundle.js');
  }

  async function _saveCachedBundle(hash, data) {
    if (!hash) return;
    var _bcMode = __DOKKEBI_PH_BOOL_BYTECODE_MODE__;
    var _etMode = __DOKKEBI_PH_BOOL_ENCRYPTED_TEXT__;
    if ((_bcMode || _etMode) && data instanceof Uint8Array) {
      var _cacheFile = _etMode ? 'backend.bundle.enc' : 'backend.bytecode';
      var fh = await _opfsDir.getFileHandle(_cacheFile, { create: true });
      var wr = await fh.createWritable();
      await wr.write(data);
      await wr.close();
    } else if (typeof data === 'string') {
      await _opfsWrite('backend-bundle.js', data);
    }
    await _opfsWrite('bundle-hash.txt', hash);
  }

  async function _queryHash(sql, params) {
    var buf = await crypto.subtle.digest('SHA-256',
      new TextEncoder().encode(sql + JSON.stringify(params || []))
    );
    return Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2,'0'); }).join('').slice(0,16);
  }

  async function _sha256HexString(input) {
    var text = typeof input === 'string' ? input : JSON.stringify(input ?? null);
    var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2,'0'); }).join('');
  }

  // HTML 주입 __DOKKEBI_BOOT__ — BC_KEY 래핑 언랩 (Worker 와 동일 HKDF/GCM)
  function _b64urlToBytes(s) {
    if (!s || typeof s !== 'string') return null;
    var pad = s.length % 4;
    var b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    if (pad === 2) b64 += '==';
    else if (pad === 3) b64 += '=';
    else if (pad !== 0) return null;
    try {
      var bin = atob(b64);
      var out = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    } catch { return null; }
  }
  async function _deriveBundleKekFromBoot(nonceB64, tokenB64) {
    var nonceBytes = _b64urlToBytes(nonceB64);
    var tokenBytes = _b64urlToBytes(tokenB64);
    if (!nonceBytes || !tokenBytes || nonceBytes.length === 0 || tokenBytes.length === 0) {
      throw new Error('invalid boot nonce/token');
    }
    var h12 = ('__DOKKEBI_PH_BUNDLE_HASH__' || '').slice(0, 12);
    var ikmKey = await crypto.subtle.importKey('raw', tokenBytes, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: nonceBytes, info: new TextEncoder().encode('dokkebi-bc-wrap-v1|' + h12) },
      ikmKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }
  async function _unwrapBcKeyHexFromBoot(boot) {
    if (!boot || typeof boot !== 'object' || Number(boot.v) !== 1 || !boot.w || !boot.n || !boot.t) return null;
    try {
      var kek = await _deriveBundleKekFromBoot(String(boot.n), String(boot.t));
      var wrapRaw = _b64urlToBytes(String(boot.w));
      if (!wrapRaw || wrapRaw.length < 28) return null;
      var iv = wrapRaw.slice(0, 12);
      var ct = wrapRaw.slice(12);
      var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, kek, ct);
      var arr = new Uint8Array(pt);
      var hex = '';
      for (var j = 0; j < arr.length; j++) hex += arr[j].toString(16).padStart(2, '0');
      return hex;
    } catch (e) {
      console.warn('[dokkebi] __DOKKEBI_BOOT__ 언랩 실패 — 핸드셰이크 BC_KEY 폴백:', e && e.message ? e.message : e);
      return null;
    }
  }

  // ──────────────────────────────────────────────────────────
  // Query Registry (Stage 3)
  //   DSL 이 만든 SQL 을 canonical form 으로 정규화한 뒤 해시해
  //   queryId 로 변환합니다. 서버는 이 queryId 로 빌드 타임
  //   레지스트리를 조회해 실제 SQL 을 실행합니다.
  //   빌드 도구의 src/core/queryRegistry.js 와 동일 규칙이어야 합니다.
  // ──────────────────────────────────────────────────────────
  var _QR_KEYWORDS_RE = /\b(SELECT|FROM|WHERE|INSERT|INTO|VALUES|UPDATE|SET|DELETE|ORDER|GROUP|HAVING|LIMIT|OFFSET|JOIN|LEFT|RIGHT|INNER|OUTER|CROSS|ON|AND|OR|NOT|NULL|IS|IN|BETWEEN|LIKE|AS|ASC|DESC|CREATE|TABLE|IF|EXISTS|PRIMARY|KEY|UNIQUE|FOREIGN|REFERENCES|RETURNING|WITH|RECURSIVE|UNION|ALL|DISTINCT)\b/gi;

  function _qrStripStringsAndComments(sql) {
    var out = '';
    var i = 0;
    var n = sql.length;
    while (i < n) {
      var ch = sql[i];
      var next = sql[i + 1];
      if (ch === '-' && next === '-') {
        while (i < n && sql[i] !== '\n') i++;
        out += ' ';
        continue;
      }
      if (ch === '/' && next === '*') {
        i += 2;
        while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i++;
        i += 2;
        out += ' ';
        continue;
      }
      if (ch === "'") {
        out += '?';
        i++;
        while (i < n) {
          if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; }
          if (sql[i] === "'") { i++; break; }
          i++;
        }
        continue;
      }
      if (ch === '"') {
        out += '"';
        i++;
        while (i < n) {
          if (sql[i] === '"' && sql[i + 1] === '"') { out += '""'; i += 2; continue; }
          if (sql[i] === '"') { out += '"'; i++; break; }
          out += sql[i];
          i++;
        }
        continue;
      }
      if (ch === '`') {
        out += '`';
        i++;
        while (i < n) {
          if (sql[i] === '`') { out += '`'; i++; break; }
          out += sql[i];
          i++;
        }
        continue;
      }
      out += ch;
      i++;
    }
    return out;
  }

  function _canonicalizeSql(sql) {
    if (typeof sql !== 'string') return '';
    var s = _qrStripStringsAndComments(sql);
    s = s.replace(/\s+/g, ' ').trim();
    s = s.replace(_QR_KEYWORDS_RE, function(m) { return m.toUpperCase(); });
    s = s.replace(/\s*,\s*/g, ', ');
    s = s.replace(/\s*\(\s*/g, ' (').replace(/\s*\)\s*/g, ') ');
    s = s.replace(/\s+/g, ' ').trim();
    s = s.replace(/\bIN \(\?(?:, \?)*\)/g, 'IN (?)');
    return s;
  }

  async function _computeQueryId(sql) {
    var canonical = _canonicalizeSql(sql);
    var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
    var hex = Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2,'0'); }).join('');
    return 'q_' + hex.slice(0, 16);
  }

  async function _cacheQueryResult(hash, result) {
    if (!_opfsDir) return;
    try {
      var dir = await _opfsDir.getDirectoryHandle('qcache', { create: true });
      var fh = await dir.getFileHandle(hash + '.json', { create: true });
      var w = await fh.createWritable();
      await w.write(JSON.stringify({ ts: Date.now(), d: result }));
      await w.close();
    } catch {}
  }

  async function _getCachedQuery(hash) {
    if (!_opfsDir) return null;
    try {
      var dir = await _opfsDir.getDirectoryHandle('qcache');
      var fh = await dir.getFileHandle(hash + '.json');
      var f = await fh.getFile();
      var data = JSON.parse(await f.text());
      if (Date.now() - data.ts > 5 * 60 * 1000) return null;
      return data.d;
    } catch { return null; }
  }

  // ────────────────────────────────────────────────────────
  // sql.js 로컬 DB 레이어 (IndexedDB/OPFS 영속화)
  // _LOCAL_DB_MODE === true 일 때만 활성화
  // ────────────────────────────────────────────────────────
  let _localSqlDb = null;
  let _localDbDirty = false;
  let _localDbSaveTimer = null;

  async function _opfsReadBytes(name) {
    if (!_opfsDir) return null;
    try {
      var fh = await _opfsDir.getFileHandle(name);
      var f = await fh.getFile();
      return f.size > 0 ? new Uint8Array(await f.arrayBuffer()) : null;
    } catch { return null; }
  }

  async function _opfsWriteBytes(name, uint8) {
    if (!_opfsDir) return false;
    try {
      var fh = await _opfsDir.getFileHandle(name, { create: true });
      var w = await fh.createWritable();
      await w.write(uint8);
      await w.close();
      return true;
    } catch { return false; }
  }

  function _idbSave(data) {
    return new Promise(function(resolve, reject) {
      var req = indexedDB.open('dokkebi-localdb', 1);
      req.onupgradeneeded = function() { req.result.createObjectStore('db'); };
      req.onsuccess = function() {
        var tx = req.result.transaction('db', 'readwrite');
        tx.objectStore('db').put(data, 'sqlite');
        tx.oncomplete = function() { req.result.close(); resolve(); };
        tx.onerror = function() { req.result.close(); reject(tx.error); };
      };
      req.onerror = function() { reject(req.error); };
    });
  }

  function _idbLoad() {
    return new Promise(function(resolve, reject) {
      var req = indexedDB.open('dokkebi-localdb', 1);
      req.onupgradeneeded = function() { req.result.createObjectStore('db'); };
      req.onsuccess = function() {
        var tx = req.result.transaction('db', 'readonly');
        var getReq = tx.objectStore('db').get('sqlite');
        getReq.onsuccess = function() { req.result.close(); resolve(getReq.result || null); };
        getReq.onerror = function() { req.result.close(); resolve(null); };
      };
      req.onerror = function() { resolve(null); };
    });
  }

  async function _persistLocalDb() {
    if (!_localSqlDb) return;
    var data = _localSqlDb.export();
    var saved = await _opfsWriteBytes(_LOCAL_DB_FILE, data);
    if (!saved) {
      try { await _idbSave(data); } catch {}
    }
  }

  function _scheduleLocalDbSave() {
    _localDbDirty = true;
    if (_localDbSaveTimer) return;
    _localDbSaveTimer = setTimeout(function() {
      _localDbSaveTimer = null;
      if (_localDbDirty) {
        _localDbDirty = false;
        _persistLocalDb().catch(function() {});
      }
    }, 500);
  }

  async function _loadLocalDbData() {
    var data = await _opfsReadBytes(_LOCAL_DB_FILE);
    if (data) return data;
    return await _idbLoad();
  }

  async function _initLocalSqlDb() {
    var script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/sql.js@1.11.0/dist/sql-wasm.js';
    await new Promise(function(resolve, reject) {
      script.onload = resolve;
      script.onerror = function() { reject(new Error('sql.js CDN 로드 실패')); };
      document.head.appendChild(script);
    });

    var SQL = await initSqlJs({
      locateFile: function(file) { return 'https://cdn.jsdelivr.net/npm/sql.js@1.11.0/dist/' + file; }
    });

    var existing = await _loadLocalDbData();
    _localSqlDb = existing ? new SQL.Database(existing) : new SQL.Database();

    if (_MIGRATION_SQL) {
      try {
        _localSqlDb.exec(_MIGRATION_SQL);
      } catch (e) {
        console.warn('[dokkebi:localDb] 마이그레이션 실행 중 일부 오류:', e.message);
      }
      await _persistLocalDb();
      console.log('[dokkebi] 📦 로컬 DB 마이그레이션 완료');
    } else {
      console.log('[dokkebi] 📦 로컬 DB 복원 완료 (OPFS/IndexedDB)');
    }

    window.addEventListener('beforeunload', function() {
      if (_localDbDirty) _persistLocalDb().catch(function() {});
    });
  }

  function _localDbExec(sql, params) {
    if (!_localSqlDb) return { ok: false, error: '로컬 DB가 초기화되지 않았습니다.' };
    try {
      var trimmed = sql.trimStart();
      var upper = trimmed.substring(0, 7).toUpperCase();
      var isReturning = sql.toUpperCase().indexOf('RETURNING') !== -1;
      var isSelect = upper.startsWith('SELECT');

      if (isSelect || isReturning) {
        var stmt = _localSqlDb.prepare(sql);
        if (params && params.length > 0) stmt.bind(params);
        var rows = [];
        while (stmt.step()) {
          rows.push(JSON.stringify(stmt.getAsObject()));
        }
        stmt.free();
        if (!isSelect) _scheduleLocalDbSave();
        return { ok: true, value: { rows: rows, affected: rows.length, lastInsertId: 0 } };
      } else {
        _localSqlDb.run(sql, params || []);
        var affected = _localSqlDb.getRowsModified();
        _scheduleLocalDbSave();
        return { ok: true, value: { rows: [], affected: affected, lastInsertId: 0 } };
      }
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  // ────────────────────────────────────────────────────────
  // ECDH P-256 + HKDF 핸드셰이크
  // ────────────────────────────────────────────────────────
  let _encKey    = null;  // AES-256-GCM 암호화 키 (CryptoKey)
  let _sigKey    = null;  // HMAC-SHA256 서명 키 (CryptoKey)
  let _sessionId = null;  // 서버에서 발급받은 세션 ID
  /** 온라인 모드에서 Step 1b 가 백그라운드 핸드셰이크 Promise 로 교체됨 — /db 암호화 전 await */
  var _handshakeBgP = Promise.resolve();
  const _envSecretMap = {};  // 클라이언트 허용 Secret만 보관 (번들 복호화 키 전용)
  // ── C-1 방어: JWT 서명 시크릿은 더 이상 클라이언트로 전달/보관하지 않는다. ──
  //   로그인은 ctx.login()/__DOKKEBI_LOGIN__ → 워커 _login 이 서버측에서 검증·서명한다.
  const _CLIENT_SECRET_KEYS = { __DOKKEBI_BC_KEY__: true };

  function _storeClientSecrets(source) {
    if (!source) return 0;
    var count = 0;
    for (var key in _CLIENT_SECRET_KEYS) {
      if (Object.prototype.hasOwnProperty.call(source, key) && source[key] !== undefined) {
        _envSecretMap[key] = source[key];
        count++;
      }
    }
    return count;
  }

  function _clientSecretsForStorage() {
    var out = {};
    for (var key in _CLIENT_SECRET_KEYS) {
      // OPFS v2 블롭 전체가 origin+UA 기반 wrapKey 로 암호화됨. JWT 등과 동일하게 BC_KEY 도
      // 세션 TTL(8h) 안에서는 새로고침 시 번들 복호화 재사용 — 없으면 세션만 복원되고 키는
      // 비어 매번 재핸드셰이크가 난다.
      if (Object.prototype.hasOwnProperty.call(_envSecretMap, key)) out[key] = _envSecretMap[key];
    }
    return out;
  }

  function _forgetClientSecret(key) {
    if (!key) return;
    try { _envSecretMap[key] = ''; } catch {}
    try { delete _envSecretMap[key]; } catch {}
  }

  // 동시에 두 갈래(백그라운드 Step 1b ↔ 번들 복호화 경로의 _performHandshake)가 돌면
  // _encKey 가 중간에 덮여 POST 응답 encSecrets 복호화가 실패한다 → 직렬화 필수.
  var _handshakeMutexPrev = Promise.resolve();
  async function _performHandshakeCore() {
    // 1. 클라이언트 ECDH 키쌍 생성
    const clientKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );

    // 2. 서버 공개키 가져오기 (비압축 포인트 형식)
    const _hsData = await _fetch('/api/_dokkebi/handshake').then(r => r.json());
    const serverPubB64 = _hsData.serverPubKey;
    const _ephKeyId = _hsData.keyId || null;

    const serverPubRaw = Uint8Array.from(atob(serverPubB64), c => c.charCodeAt(0));
    const serverPubImported = await crypto.subtle.importKey(
      'raw', serverPubRaw,
      { name: 'ECDH', namedCurve: 'P-256' },
      false, []
    );

    // 3. ECDH 공유 비밀 계산 (256 bits)
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: serverPubImported },
      clientKeyPair.privateKey,
      256
    );
    const _sharedB64 = btoa(String.fromCharCode(...new Uint8Array(sharedBits)));
    const sharedKey = await crypto.subtle.importKey(
      'raw', sharedBits, 'HKDF', false, ['deriveKey', 'deriveBits']
    );

    // 4. HKDF-SHA256: encKey 파생 (AES-256-GCM용)
    _encKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF', hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: new TextEncoder().encode('dokkebi-enc'),
      },
      sharedKey,
      { name: 'AES-GCM', length: 256 },
      false, ['encrypt', 'decrypt']
    );

    // 5. HKDF-SHA256: sigKey 파생 (HMAC-SHA256용)
    const sigBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF', hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: new TextEncoder().encode('dokkebi-sig'),
      },
      sharedKey,
      256
    );
    _sigKey = await crypto.subtle.importKey(
      'raw', sigBits,
      { name: 'HMAC', hash: 'SHA-256' },
      false, ['sign']
    );

    // 6. 클라이언트 공개키 서버에 전송 → sessionId 수신
    const clientPubRaw = await crypto.subtle.exportKey('raw', clientKeyPair.publicKey);
    const clientPubB64 = btoa(String.fromCharCode(...new Uint8Array(clientPubRaw)));

    const _hsPostBody = { clientPubKey: clientPubB64 };
    if (_ephKeyId) _hsPostBody.keyId = _ephKeyId;
    // 무중단 배포 — 현재 HTML 에 박힌 bundleHash 앞 12자를 함께 보낸다.
    // 서버는 __DOKKEBI_BC_KEY_MAP__ 에서 이 해시에 매칭되는 키를 응답.
    var _hsBh = ('__DOKKEBI_PH_BUNDLE_HASH__' || '').slice(0, 12);
    if (_hsBh) _hsPostBody.bh = _hsBh;
    const _hsPostRaw = await _fetch('/api/_dokkebi/handshake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify(_hsPostBody),
    });
    var _hsPostRes = await _hsPostRaw.json();
    // 200 + { pending:true, code:'prop_pending' } — 무중단 배포 전파가 진행 중.
    // HTTP 503 을 쓰면 브라우저 콘솔에 빨간 네트워크 에러가 노출되므로, 사용자 경험을
    // 위해 정상 HTTP 응답 안에서 내부 pending 상태로 처리한다.
    if (_hsPostRes && _hsPostRes.pending) {
      var _propErr = new Error('[dokkebi] handshake_propagation_pending');
      _propErr.code = _hsPostRes.code || 'prop_pending';
      _propErr.retryAfterMs = (function() {
        var bodyMs = Number(_hsPostRes.retryAfterMs || 0);
        if (Number.isFinite(bodyMs) && bodyMs > 0) return bodyMs;
        var ra = Number(_hsPostRaw.headers && _hsPostRaw.headers.get && _hsPostRaw.headers.get('Retry-After'));
        return Number.isFinite(ra) && ra > 0 ? ra * 1000 : 5000;
      })();
      throw _propErr;
    }

    _sessionId = _hsPostRes.sessionId;

    // 서버가 전달한 암호화된 클라이언트 허용 Secret 복호화 → Host 클로저에만 저장
    var _secSnapshot = null;
    if (_hsPostRes.encSecrets && _hsPostRes.encSecretsIv) {
      try {
        var _secIv = Uint8Array.from(atob(_hsPostRes.encSecretsIv), function(c) { return c.charCodeAt(0); });
        var _secEnc = Uint8Array.from(atob(_hsPostRes.encSecrets), function(c) { return c.charCodeAt(0); });
        var _secPlain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: _secIv }, _encKey, _secEnc);
        var _secData = JSON.parse(new TextDecoder().decode(_secPlain));
        var _storedSecretCount = _storeClientSecrets(_secData);
        // OPFS 저장용 스냅샷 — 메인 흐름의 _forgetClientSecret 가 _envSecretMap 을 비우기 전에
        // 이 값을 그대로 _saveSessionToOPFS 에 넘긴다.
        _secSnapshot = {};
        for (var _sk in _CLIENT_SECRET_KEYS) {
          if (Object.prototype.hasOwnProperty.call(_secData, _sk) && _secData[_sk]) {
            _secSnapshot[_sk] = _secData[_sk];
          }
        }
        try { new Uint8Array(_secPlain).fill(0); } catch {}
        console.log('[dokkebi] 🔐 클라이언트 허용 Secret ' + _storedSecretCount + '개 → Opaque Handle 보호 적용');
      } catch (e) {
        var _secFail = (e && (e.message || e.name)) ? (e.message || e.name) : String(e);
        console.warn('[dokkebi] ⚠ 클라이언트 Secret 복호화 실패:', _secFail);
        // 삼켜 버리면 ECDH 만 OPFS 에 저장되어 다음 로드마다 "복호화 키 미보유 → 재핸드셰이크" 가 반복된다.
        var _esErr = new Error('[dokkebi] encSecrets 복호화 실패: ' + _secFail);
        _esErr.code = 'enc_secrets_decrypt';
        throw _esErr;
      }
    }

    // 암호화 번들 모드인데 BC_KEY 가 handshake 로도 BOOT 로도 없으면 세션을 저장하지 않는다.
    var _bundleNeedsBcKey = __DOKKEBI_PH_BOOL_ENCRYPTED_TEXT___OR___DOKKEBI_PH_BOOL_BYTECODE_ENC__;
    if (_bundleNeedsBcKey && !(_secSnapshot && _secSnapshot.__DOKKEBI_BC_KEY__) && !_envSecretMap['__DOKKEBI_BC_KEY__']) {
      var _gbCk = typeof window !== 'undefined' ? window : null;
      var _bootCk = _gbCk && _gbCk.__DOKKEBI_BOOT__;
      var _hasBootCk = _bootCk && Number(_bootCk.v) === 1 && _bootCk.w && _bootCk.n && _bootCk.t;
      if (!_hasBootCk) {
        var _bcMiss = new Error('[dokkebi] 암호화 번들 모드인데 번들 복호화 키가 없습니다. Worker handshake(encSecrets·__DOKKEBI_BC_KEY__) 또는 HTML __DOKKEBI_BOOT__ 를 확인하세요.');
        _bcMiss.code = 'bc_key_missing_after_handshake';
        throw _bcMiss;
      }
    }

    // OPFS 저장은 await — 메인 흐름의 _forgetClientSecret 가 일어나기 전에 디스크에 박히도록.
    await _saveSessionToOPFS(_sharedB64, _sessionId, _secSnapshot);
    _secSnapshot = null;
    try { _resetReqCounter(); } catch {}
    console.log('[dokkebi] 🔐 ECDH 핸드셰이크 완료 (Forward Secrecy 활성)');
  }

  async function _performHandshake() {
    var _prev = _handshakeMutexPrev;
    var _unlock;
    _handshakeMutexPrev = new Promise(function(resolve) { _unlock = resolve; });
    await _prev;
    try {
      return await _performHandshakeCore();
    } finally {
      try { _unlock(); } catch (_) {}
    }
  }

  // 무중단 배포 전파 인지 핸드셰이크 — pending 응답을 받으면 백오프 재시도.
  // _performHandshake 자체에서 prop_pending 을 던져도 부드럽게 회복.
  async function _performHandshakeResilient() {
    var _delays = [500, 1500, 3500, 6000, 10000, 15000];
    var _lastErr = null;
    try {
      await _performHandshake();
      return;
    } catch (e) {
      _lastErr = e;
      if (!e || e.code !== 'prop_pending') throw e;
      console.debug('[dokkebi] ⏳ 배포 업데이트 반영 중 — 자동 재시도');
    }
    // 최대 약 5분간 조용히 대기한다. 일반 사용자는 로딩 상태만 보며,
    // 콘솔에도 warning/error 를 남기지 않는다. 그 이상이면 자동 새로고침으로
    // 최신 HTML/Worker 조합을 다시 잡는다.
    var _maxAttempts = 30;
    for (var _i = 0; _i < _maxAttempts; _i++) {
      var _wait = _delays[Math.min(_i, _delays.length - 1)];
      if (_lastErr && _lastErr.code === 'prop_pending' && Number(_lastErr.retryAfterMs) > 0 && _i === 0) {
        _wait = Number(_lastErr.retryAfterMs);
      }
      await new Promise(function(r) { setTimeout(r, _wait); });
      try {
        await _performHandshake();
        console.debug('[dokkebi] ✅ 핸드셰이크 재시도 성공 (' + (_i + 1) + '/' + _maxAttempts + ')');
        return;
      } catch (e) {
        _lastErr = e;
        if (e && e.code === 'prop_pending') {
          console.debug('[dokkebi] ⏳ 배포 업데이트 반영 대기 (' + (_i + 1) + '/' + _maxAttempts + ')');
        } else {
          throw e;
        }
      }
    }
    setTimeout(function() { window.location.reload(); }, 500);
    await new Promise(function() {});
  }

  // ────────────────────────────────────────────────────────
  // 클라이언트 시계 자동 보정 (Replay 방어 보조)
  //   서버가 응답 헤더 Date 또는 에러 바디의 server_ts 를 제공함.
  //   여기서 얻은 서버 기준시각과 로컬 시각의 차이를 EWMA 로 학습하여
  //   TIMESTAMP_SKEW (±5초 초과) 거부를 예방.
  //   음(-): 클라가 미래를, 양(+): 클라가 과거를 가리키는 경우.
  // ────────────────────────────────────────────────────────
  var _clockOffsetMs = 0;
  function _updateClockOffset(serverTs, roundTripMs) {
    if (!Number.isFinite(serverTs)) return;
    // Round-trip 의 절반이 편도 지연이라고 가정하고 보정.
    var rtt = Math.max(0, Number(roundTripMs) || 0);
    var localNow = Date.now();
    var estimated = Number(serverTs) + Math.round(rtt / 2) - localNow;
    // 1차 측정은 그대로, 이후 EWMA α=0.3
    _clockOffsetMs = _clockOffsetMs === 0 ? estimated : Math.round(_clockOffsetMs * 0.7 + estimated * 0.3);
  }
  function _serverNow() { return Date.now() + _clockOffsetMs; }
  function _learnFromResponse(resp, json, sentAt) {
    try {
      var dateHdr = resp && resp.headers ? resp.headers.get('Date') : null;
      var serverTs = (json && Number.isFinite(Number(json.server_ts))) ? Number(json.server_ts) : null;
      if (!serverTs && dateHdr) {
        var d = Date.parse(dateHdr);
        if (Number.isFinite(d)) serverTs = d;
      }
      if (serverTs) _updateClockOffset(serverTs, Date.now() - sentAt);
    } catch {}
  }

  // ────────────────────────────────────────────────────────
  // AES-256-GCM 암호화 + HMAC-SHA256 서명
  // ────────────────────────────────────────────────────────
  // Phase 1-① — Monotonic request counter (per-session).
  // nonce 에 "{sid}:{counter}:{rand}" 를 embed 하여 세션별 순서를
  // 서버가 enforce 할 수 있게 한다. 카운터는 핸드셰이크 때 리셋.
  var _reqCounter = 0;
  function _resetReqCounter() { _reqCounter = 0; }

  // ── DB 요청 직렬화 큐 ──────────────────────────────────
  // _encryptPayload 에서 카운터를 할당하고 HMAC 서명까지 포함한 요청이
  // (쓰기·WITH·특수 페이로드 등) 여러 개 동시에 in-flight 하면 네트워크 지연으로
  // 서버 도달 순서가 역전되어 monotonic counter 검증 실패가 날 수 있다.
  // 이 큐는 그런 경로만 직렬화한다.
  // ⚠ 순수 SELECT (문자열이 SELECT 로 시작) 는 _proxyQuery 가 큐를 건너뛴다.
  //    parallelReads() 없이도 a.exec(); b.exec(); await Promise.all([a,b]) 처럼
  //    동시에 여러 읽기 요청을 날릴 수 있다 (서버는 SELECT 에 대해 카운터 역행 검사 생략).
  var _dbReqQueue = Promise.resolve();
  function _dbRequest(fn) {
    var prev = _dbReqQueue;
    // 이전 요청 성공/실패 무관하게 항상 다음 요청 실행 (큐 절대 막히지 않음)
    var current = prev.then(fn, fn);
    // 에러를 전파하지 않고 큐 상태만 업데이트
    _dbReqQueue = current.then(function() {}, function() {});
    return current;
  }

  function _leadingZeroBitsHex_client(hex) {
    var clean = hex.length % 2 === 1 ? '0' + hex : hex;
    var pairs = clean.match(/.{2}/g);
    if (!pairs) return 0;
    var bits = 0;
    for (var i = 0; i < pairs.length; i++) {
      var b = parseInt(pairs[i], 16);
      if (b === 0) { bits += 8; continue; }
      for (var j = 7; j >= 0; j--) {
        if ((b >> j) & 1) return bits;
        bits++;
      }
      return bits;
    }
    return bits;
  }

  async function _minePowWeb(stamp, bits) {
    var enc = new TextEncoder();
    var want = Math.max(8, Math.min(22, Math.floor(Number(bits) || 14)));
    var c = 0;
    var max = 8000000;
    while (c < max) {
      var digest = await crypto.subtle.digest('SHA-256', enc.encode(stamp + ':' + String(c)));
      var hex = Array.from(new Uint8Array(digest)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
      if (_leadingZeroBitsHex_client(hex) >= want) return c;
      c++;
    }
    throw new Error('[dokkebi] PoW mine failed');
  }

  function _payloadCanonToAlias(obj) {
    var r = _PAYLOAD_WIRE && _PAYLOAD_WIRE.rotation;
    if (!r || !r.enabled || !r.activeForward) return obj;
    var m = r.activeForward;
    var out = {};
    for (var k in obj) {
      if (!Object.prototype.hasOwnProperty.call(obj, k)) continue;
      var nk = m[k] || k;
      out[nk] = obj[k];
    }
    return out;
  }

  async function _maybeAttachPow(data) {
    var pow = _PAYLOAD_WIRE && _PAYLOAD_WIRE.pow;
    if (!pow || !pow.enabled) return data;
    var need = (data._capabilityUnlock !== undefined)
      || (data._attest && typeof data._attest === 'object' && data._attest.request === true);
    if (!need) return data;
    if (data._pow) return data;
    var bits = Math.max(8, Math.min(22, Math.floor(Number(pow.bits) || 14)));
    var stamp = _sessionId + ':' + Math.floor(_serverNow() / 60000);
    var counter = await _minePowWeb(stamp, bits);
    var next = {};
    for (var k in data) { if (Object.prototype.hasOwnProperty.call(data, k)) next[k] = data[k]; }
    next._pow = { stamp: stamp, bits: bits, counter: counter };
    return next;
  }

  async function _encryptPayload(data, opts) {
    if (!_LOCAL_DB_MODE) await _handshakeBgP;
    if (!_encKey || !_sigKey || !_sessionId) {
      throw new Error('[dokkebi] 보안 핸드셰이크가 완료되지 않았습니다.');
    }

    _reqCounter++;
    var _randBytes = crypto.getRandomValues(new Uint8Array(8));
    var _randHex = '';
    for (var _bi = 0; _bi < _randBytes.length; _bi++) {
      _randHex += _randBytes[_bi].toString(16).padStart(2, '0');
    }
    const nonce = _sessionId + ':' + _reqCounter + ':' + _randHex;
    const ts    = _serverNow();
    const iv    = crypto.getRandomValues(new Uint8Array(12));

    // AES-256-GCM 암호화 (출력: ciphertext + 16바이트 auth tag)
    const wired = await _maybeAttachPow(data);
    // skipWire: 배포 직후 구버전 클라 → 서버가 이전 회전 매핑을 못 읽을 때 정규 키로 1회 재시도
    const dataOut = (opts && opts.skipWire) ? wired : _payloadCanonToAlias(wired);
    const plain     = new TextEncoder().encode(JSON.stringify(dataOut));
    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, _encKey, plain)
    );
    const enc = btoa(String.fromCharCode(...encrypted));
    const ivB64 = btoa(String.fromCharCode(...iv));

    // HMAC-SHA256 서명: nonce + ":" + ts + ":" + enc
    const sigInput = new TextEncoder().encode(nonce + ':' + ts + ':' + enc);
    const sigBuf   = await crypto.subtle.sign('HMAC', _sigKey, sigInput);
    const sig      = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));

    return JSON.stringify({ enc, iv: ivB64, nonce, ts, sig, sid: _sessionId });
  }

  // ────────────────────────────────────────────────────────
  // 로그 전송 — 요청 스코프 배치 (요청 완료 시 일괄 전송)
  // ────────────────────────────────────────────────────────
  let _logQueue  = [];
  let _logTimer  = null;
  let _logRequestScope = false;

  function _flushLogs() {
    _logTimer = null;
    if (_logQueue.length === 0) return;
    var entries = _logQueue.splice(0);
    _fetch('/api/_dokkebi/log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ entries: entries }),
    }).catch(function() {});
  }

  function _beginLogScope() { _logRequestScope = true; }
  function _endLogScope() {
    _logRequestScope = false;
    if (_logQueue.length > 0) {
      clearTimeout(_logTimer);
      _flushLogs();
    }
  }

  function _sendLog(level, tag, messages) {
    if (!_shouldSendRemoteLog(level)) return Promise.resolve();
    _logQueue.push({ level: level, tag: tag, messages: messages });
    if (_logRequestScope) return Promise.resolve();
    if (_logQueue.length >= 50) {
      clearTimeout(_logTimer);
      _flushLogs();
    } else if (!_logTimer) {
      _logTimer = setTimeout(_flushLogs, 2000);
    }
    return Promise.resolve();
  }

  // ────────────────────────────────────────────────────────
  // Opaque Handle 스토어 (Host 전용)
  // ────────────────────────────────────────────────────────
  const _store = new Map();
  let _seq = 100;
  const _sessionNonce = crypto.randomUUID();

  function _registerHandle(creds) {
    const id = ++_seq;
    _store.set(id, Object.freeze({ ...creds, _nonce: _sessionNonce }));
    return id;
  }

  function _resolveHandle(id) {
    const entry = _store.get(id);
    if (!entry) throw new Error('[dokkebi] 유효하지 않은 핸들: ' + id);
    if (entry._nonce !== _sessionNonce) throw new Error('[dokkebi] 세션 만료 핸들: ' + id);
    return entry;
  }

  const DB_HANDLE = _registerHandle({ type: '__DOKKEBI_PH_DB_TYPE__' });

  // ────────────────────────────────────────────────────────
  // host-db (로컬 DB 모드: sql.js / 온라인 모드: /api/_dokkebi/db 프록시)
  // ────────────────────────────────────────────────────────
  const hostDb = _LOCAL_DB_MODE ? {
    async dbExecute(handleId, sql, params) {
      return _localDbExec(sql, params);
    },
    async dbTransaction(handleId, statements) {
      var count = 0;
      for (var i = 0; i < statements.length; i++) {
        _localDbExec(statements[i][0], statements[i][1] || []);
        count++;
      }
      _scheduleLocalDbSave();
      return { ok: true, value: count };
    },
    async dbTableExists(handleId, tableName) {
      try {
        var res = _localDbExec(
          "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
          [tableName]
        );
        return (res.value?.rows?.length ?? 0) > 0;
      } catch { return false; }
    },
  } : {
    async dbExecute(handleId, sql, params) {
      return _proxyQuery(sql, params);
    },
    async dbTransaction(handleId, statements) {
      let count = 0;
      for (const [sql, params] of statements) {
        await _proxyQuery(sql, params);
        count++;
      }
      return { ok: true, value: count };
    },
    async dbTableExists(handleId, tableName) {
      try {
        const res = await _proxyQuery(
          "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
          [tableName]
        );
        return (res.value?.rows?.length ?? 0) > 0;
      } catch { return false; }
    },
    // Tenant Policy (Stage 1/2) — 세션 클레임 설정.
    // DSL 업데이트 후 ctx.setSessionTenant({user_id}) 로 호출될 예정.
    async dbSetSessionTenant(handleId, tenantObj) {
      return _proxySetTenant(tenantObj);
    },
  };

  async function _decryptResponse(encData) {
    if (!_LOCAL_DB_MODE) await _handshakeBgP;
    if (!_encKey) throw new Error('[dokkebi] 복호화 키가 없습니다.');

    const combined = Uint8Array.from(atob(encData.enc), c => c.charCodeAt(0));
    const iv       = Uint8Array.from(atob(encData.iv),  c => c.charCodeAt(0));

    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      _encKey,
      combined
    );
    return JSON.parse(new TextDecoder().decode(plainBuf));
  }

  // Worker 테넌트/인가: /api/_dokkebi/db 는 Authorization 헤더가 없으므로
  // 암호화 페이로드에 JWT 를 실어 보냄. 앱에서 window.__DOKKEBI_DB_JWT__ = () => token;
  function _getJwtForDbChannel() {
    try {
      var g = typeof window !== 'undefined' ? window : null;
      if (!g) return '';
      var v = g.__DOKKEBI_DB_JWT__;
      if (typeof v === 'function') v = v();
      return (typeof v === 'string' && v) ? v : '';
    } catch (e) {
      return '';
    }
  }

  async function _buildDbPayload(sql, params) {
    // Query Registry 모드: { queryId, params, [_debugSql], [_jwt] }
    //   - queryId 만 서버로 전송 (SQL 문자열 노출 없음)
    //   - learn 모드(dev) 에서는 _debugSql 동봉 → 서버 자동 학습 허용
    //   - strict 모드(deploy) 에서는 _debugSql 없이 매칭 실패하면 403
    var jwtDb = _getJwtForDbChannel();
    var payload = { params: params };
    try {
      payload.queryId = await _computeQueryId(sql);
    } catch {
      // crypto 실패 등 예외 상황 — legacy 경로로 폴백 (서버가 어쨌든 sql 필요시 해독)
      payload.sql = sql;
      if (jwtDb) payload._jwt = jwtDb;
      return payload;
    }
    // IN 절 정규화로 queryId 가 파라미터 수와 무관해졌으므로,
    // 실제 SQL 을 항상 동봉하여 서버가 정확한 파라미터 수의 SQL 을 실행할 수 있게 한다.
    // (AES-GCM 암호화 채널 내부이므로 평문 노출 없음)
    payload._debugSql = sql;
    if (jwtDb) payload._jwt = jwtDb;
    return payload;
  }

  // ────────────────────────────────────────────────────────
  // 세션 테넌트 설정 (Tenant Policy 용)
  //   backend 로그인 성공 후 호출:
  //     await window.__DOKKEBI_SET_TENANT__({ user_id: user.id })
  //   서버는 이 세션의 tenant_json 을 업데이트하고,
  //   이후 모든 db 요청이 verifyTenantPolicy / injectTenantPolicy 에서
  //   이 값을 기준으로 검증됩니다.
  //   null 을 넘기면 로그아웃(클리어).
  //   ⚠ 자기 자신의 세션만 변경 가능 — 다른 세션 탈취가 전제되지 않는 한
  //     공격 벡터가 되지 않습니다. 문서: docs/design/TENANT_POLICY.md
  // ────────────────────────────────────────────────────────
  // DB 요청과 동일 _dbRequest 큐에 넣어 counter(nonce) 순서가 역행하지 않게 함.
  // 큐 밖에서 호출 시 loadProjects 등과 병렬 → 서버 counter regression + replay_attempt 로그.
  async function _proxySetTenant(tenantObj) {
    return _dbRequest(async function() {
      try {
        const payload = { _setTenant: tenantObj === undefined ? null : tenantObj };
        const body = await _encryptPayload(payload);
        const resp = await _fetch('/api/_dokkebi/db', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json; charset=utf-8' },
          body,
        });
        const json = await resp.json();
        if (resp.status === 403 && json.error) {
          _clearSessionOPFS();
          await _performHandshake();
          const body2 = await _encryptPayload(payload);
          const resp2 = await _fetch('/api/_dokkebi/db', {
            method: 'POST', headers: { 'Content-Type': 'application/json; charset=utf-8' }, body: body2,
          });
          const json2 = await resp2.json();
          return json2._enc ? await _decryptResponse(json2) : json2;
        }
        return json._enc ? await _decryptResponse(json) : json;
      } catch (e) {
        return { ok: false, error: e.message };
      }
    });
  }
  try { window.__DOKKEBI_SET_TENANT__ = _proxySetTenant; } catch {}

  // ── C-1: 워커측 로그인 ──────────────────────────────────────
  //   비밀번호 검증과 JWT 서명은 전적으로 워커에서 수행된다(클라이언트는 시크릿 미보유).
  //     const { ok, value } = await window.__DOKKEBI_LOGIN__({ identifier, password })
  //     value.token  → 이후 db 요청의 _jwt / Authorization 으로 사용
  //   서버 설정: dokkebi.config.js 의 auth.login (enabled+query). 미설정 시 LOGIN_DISABLED.
  async function _proxyLogin(identifier, password) {
    return _dbRequest(async function() {
      try {
        const payload = { _login: { identifier: String(identifier == null ? '' : identifier), password: String(password == null ? '' : password) } };
        const body = await _encryptPayload(payload);
        const resp = await _fetch('/api/_dokkebi/db', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json; charset=utf-8' },
          body,
        });
        const json = await resp.json();
        return json._enc ? await _decryptResponse(json) : json;
      } catch (e) {
        return { ok: false, error: e.message };
      }
    });
  }
  try { window.__DOKKEBI_LOGIN__ = _proxyLogin; } catch {}

  // Bundle Attestation — 서버가 발급한 청크 인덱스를 메모리 내 암호화 번들 바이트로
  // 슬라이싱해 SHA-256 응답을 만든다. 번들이 변조됐다면 응답 해시가 어긋난다.
  async function _proxyAttestRun() {
    if (_LOCAL_DB_MODE) return { ok: false, code: 'ATTEST_LOCAL_DB', error: '로컬 DB 모드에서는 attest 를 수행할 수 없습니다.' };
    // Step A — 챌린지 발급
    var reqBody = await _encryptPayload({ _attest: { request: true } });
    var rA = await _fetch('/api/_dokkebi/db', { method: 'POST', headers: { 'Content-Type': 'application/json; charset=utf-8' }, body: reqBody });
    var jA = await rA.json();
    var dec = jA._enc ? await _decryptResponse(jA) : jA;
    if (!dec || dec.ok !== true || !dec.attest || !Array.isArray(dec.attest.indices)) {
      return dec || { ok: false, code: 'ATTEST_REQUEST_FAILED' };
    }
    // Step B — 메모리 바이트로 청크 해시 계산
    var bundleHashKey = (window.__DOKKEBI_ATTEST_LATEST__ || '');
    var bytesMap = window.__DOKKEBI_ATTEST_BYTES__ || {};
    var bytes = bundleHashKey ? bytesMap[bundleHashKey] : null;
    if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) {
      return { ok: false, code: 'ATTEST_BYTES_MISSING', error: '브라우저에 보관된 번들 바이트를 찾을 수 없습니다.' };
    }
    var chunkSize = Number(dec.attest.chunkSize || 0);
    var total = bytes.byteLength;
    if (chunkSize <= 0) return { ok: false, code: 'ATTEST_CHUNK_INVALID' };
    var hashes = [];
    for (var i = 0; i < dec.attest.indices.length; i++) {
      var idx = dec.attest.indices[i] | 0;
      var start = idx * chunkSize;
      var end = Math.min(total, start + chunkSize);
      if (start >= end) return { ok: false, code: 'ATTEST_INDEX_OUT_OF_RANGE', error: 'idx=' + idx };
      var slice = bytes.subarray(start, end);
      var dig = await crypto.subtle.digest('SHA-256', slice);
      var arr = new Uint8Array(dig);
      var hex = '';
      for (var j = 0; j < arr.length; j++) { var s = arr[j].toString(16); hex += s.length === 1 ? ('0' + s) : s; }
      hashes.push(hex);
    }
    // Step C — 응답 검증
    var reqBody2 = await _encryptPayload({ _attest: { nonce: dec.attest.nonce, hashes: hashes } });
    var rB = await _fetch('/api/_dokkebi/db', { method: 'POST', headers: { 'Content-Type': 'application/json; charset=utf-8' }, body: reqBody2 });
    var jB = await rB.json();
    return jB._enc ? await _decryptResponse(jB) : jB;
  }

  // ── Capability 토큰 캐시 (메모리 only) ────────────────────────
  //   feature → { token, exp, jwtKey, fetchedAt }
  //   exp - 1s 까지만 신뢰. jwt 가 바뀌면 다른 캐시 슬롯으로 분리.
  //   sessionStorage/localStorage 에 적지 않는다 — XSS 가 토큰을 가져가지 못하게.
  var _capTokenCache = (typeof window !== 'undefined' && window.__DOKKEBI_CAP_CACHE__)
    ? window.__DOKKEBI_CAP_CACHE__
    : Object.create(null);
  try { window.__DOKKEBI_CAP_CACHE__ = _capTokenCache; } catch {}
  function _capCacheKey(feature, jwt) {
    return String(feature) + '|' + (typeof jwt === 'string' && jwt ? jwt.slice(-12) : '');
  }
  function _capCacheGetValid(feature, jwt) {
    var key = _capCacheKey(feature, jwt);
    var hit = _capTokenCache[key];
    if (!hit) return null;
    if (typeof hit.exp !== 'number' || hit.exp - 1000 <= Date.now()) {
      delete _capTokenCache[key];
      return null;
    }
    return hit;
  }
  function _capCachePut(feature, jwt, token, exp) {
    if (!token || typeof exp !== 'number') return;
    _capTokenCache[_capCacheKey(feature, jwt)] = { token: String(token), exp: exp, fetchedAt: Date.now() };
  }

  // ── JWT 무효(401 invalid token 등) 시 공통 클라이언트 정리 (dok build → 부트스트랩에 박힘) ──
  const _AUTH_SESSION_CFG = "__DOKKEBI_PH_AUTH_SESSION__";
  function _dokkebiNormAuthErr(s) {
    return String(s == null ? '' : s).trim().toLowerCase();
  }
  function _dokkebiIsInvalidAuthTokenMsg(msg) {
    var e = _dokkebiNormAuthErr(msg);
    if (!e) return false;
    if (e === 'invalid token' || e === 'invalid token payload' || e === 'invalid token signature' || e === 'token expired') return true;
    if (e.indexOf('invalid token') >= 0) return true;
    if (e.indexOf('token expired') >= 0) return true;
    return false;
  }
  var _dokkebiAuthInvalidLastEmit = 0;
  function _dokkebiClearCapabilityCacheOnly() {
    try {
      for (var k in _capTokenCache) {
        if (Object.prototype.hasOwnProperty.call(_capTokenCache, k)) delete _capTokenCache[k];
      }
    } catch {}
  }
  function _dokkebiRunAuthInvalidCleanup(status, body) {
    if (!_AUTH_SESSION_CFG || _AUTH_SESSION_CFG.enabled === false) return;
    var b = body && typeof body === 'object' ? body : {};
    var err = b.error;
    var st = Number(status) || 0;
    if (!_dokkebiIsInvalidAuthTokenMsg(err)) return;
    if (!(st === 401 || (st === 200 && b.ok === false))) return;
    _dokkebiClearCapabilityCacheOnly();
    try {
      var keys = _AUTH_SESSION_CFG.clearLocalStorageKeys || [];
      for (var i = 0; i < keys.length; i++) {
        try { localStorage.removeItem(String(keys[i])); } catch {}
      }
    } catch {}
    try {
      var stFn = window.__DOKKEBI_SET_TENANT__;
      if (typeof stFn === 'function') void stFn(null);
    } catch {}
    try {
      var hook = window.__DOKKEBI_ON_AUTH_INVALID__;
      if (typeof hook === 'function') hook({ status: st, error: err, body: b });
    } catch {}
    var nowEm = Date.now();
    var deb = Math.max(300, Number(_AUTH_SESSION_CFG.debounceMs) || 2000);
    if (nowEm - _dokkebiAuthInvalidLastEmit < deb) return;
    _dokkebiAuthInvalidLastEmit = nowEm;
    try {
      window.dispatchEvent(new CustomEvent('dokkebi:auth-invalid', { detail: { status: st, error: err } }));
      window.dispatchEvent(new CustomEvent('dokkebi:session-invalid', { detail: { status: st, error: err } }));
    } catch {}
  }

  // 빌드 시 워커가 알려준 feature 메타(클라용 최소 항목): { ttlMs, requires: { prev, attest } }
  function _capFeatureMeta(feature) {
    var guards = (typeof window !== 'undefined' && window.__DOKKEBI_CAPABILITY_GUARDS__) || null;
    if (!guards || !guards.features) return null;
    var spec = guards.features[String(feature || '')];
    return spec && typeof spec === 'object' ? spec : null;
  }

  // requires.prev 가 선언된 경우, 캐시에 있는 prev 토큰을 모으고 부족하면 재귀 unlock.
  // 사이클 방지를 위해 visited set 을 함께 넘긴다.
  async function _capResolvePrevTokens(feature, opts, visited) {
    var meta = _capFeatureMeta(feature);
    var declared = meta && meta.requires && Array.isArray(meta.requires.prev) ? meta.requires.prev : [];
    if (declared.length === 0) return [];
    var supplied = new Map();
    var fromOpts = Array.isArray(opts.prevTokens) ? opts.prevTokens : (Array.isArray(opts.prev) ? opts.prev : []);
    for (var i = 0; i < fromOpts.length; i++) {
      var p = fromOpts[i];
      if (p && typeof p === 'object' && typeof p.feature === 'string' && typeof p.token === 'string') {
        supplied.set(p.feature, p.token);
      }
    }
    var result = [];
    for (var j = 0; j < declared.length; j++) {
      var need = declared[j];
      // 1) opts 가 직접 줬으면 그대로 사용
      if (supplied.has(need)) { result.push({ feature: need, token: supplied.get(need) }); continue; }
      // 2) 캐시에서 유효 토큰 사용
      var hit = _capCacheGetValid(need, opts.jwt);
      if (hit) { result.push({ feature: need, token: hit.token }); continue; }
      // 3) 재귀 unlock. 사이클이면 중단(서버가 어차피 PREV_MISSING 으로 거절).
      if (visited.has(need)) continue;
      visited.add(need);
      var sub = await _proxyCapabilityUnlockCore(need, { jwt: opts.jwt, _autoPrev: true, _visited: visited });
      if (sub && sub.ok === true && sub.capability && typeof sub.capability.token === 'string') {
        _capCachePut(need, opts.jwt, sub.capability.token, Number(sub.capability.exp) || 0);
        result.push({ feature: need, token: sub.capability.token });
      }
    }
    return result;
  }

  async function _proxyCapabilityUnlockCore(feature, opts) {
    opts = opts || {};
    // 0) 캐시 단축 — 동일 feature 의 유효 토큰이 있으면 그대로 반환.
    //    단, 호출자가 stateHash/state/context 같은 입력 binding 을 준 경우는
    //    "지금 입력에 묶인 새 토큰" 이 필요하므로 캐시를 건너뛴다.
    var hasInputBinding = (typeof opts.stateHash === 'string') || (opts.state !== undefined)
      || (typeof opts.contextHash === 'string') || (opts.context !== undefined);
    if (!hasInputBinding && opts._retried !== true) {
      var cached = _capCacheGetValid(feature, opts.jwt);
      if (cached) {
        return { ok: true, capability: { token: cached.token, exp: cached.exp, feature: String(feature) } };
      }
    }
    var stateHash = typeof opts.stateHash === 'string'
      ? opts.stateHash
      : (opts.state !== undefined ? await _sha256HexString(opts.state) : undefined);
    var contextHash = typeof opts.contextHash === 'string'
      ? opts.contextHash
      : (opts.context !== undefined ? await _sha256HexString(opts.context) : undefined);
    // prevTokens — opts.prev: [{feature, token}] 또는 opts.prevTokens 그대로 허용.
    //   호출자가 명시한 게 있으면 그걸 우선 쓰고, 없으면 메타 기반 자동 해결.
    var explicitPrev = Array.isArray(opts.prevTokens) ? opts.prevTokens
      : (Array.isArray(opts.prev) ? opts.prev : null);
    var prevTokens;
    if (explicitPrev) {
      prevTokens = explicitPrev;
    } else {
      var visited = (opts._visited instanceof Set) ? opts._visited : new Set();
      visited.add(String(feature));
      var auto = await _capResolvePrevTokens(feature, opts, visited);
      prevTokens = auto.length > 0 ? auto : undefined;
    }
    var payload = {
      _capabilityUnlock: {
        feature: String(feature || ''),
        stateHash: stateHash,
        contextHash: contextHash,
        jwt: typeof opts.jwt === 'string' ? opts.jwt : undefined,
        prevTokens: prevTokens,
      },
    };
    if (typeof opts.jwt === 'string' && opts.jwt) payload._jwt = opts.jwt;
    const body = await _encryptPayload(payload);
    var sentAt = Date.now();
    const resp = await _fetch('/api/_dokkebi/db', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body,
    });
    const json = await resp.json();
    _learnFromResponse(resp, json, sentAt);
    var decoded = json._enc ? await _decryptResponse(json) : json;
    // attest 가 요구되지만 미통과 → 한 번 attest 후 재시도.
    if (decoded && decoded.ok === false && decoded.code === 'CAPABILITY_ATTEST_REQUIRED' && opts._retried !== true) {
      var att = await _proxyAttestRun();
      if (att && att.ok === true) {
        return _proxyCapabilityUnlockCore(feature, Object.assign({}, opts, { _retried: true }));
      }
      return att && att.code ? att : decoded;
    }
    // 성공 시 캐시 (input binding 이 없는 호출만 — state 묶인 토큰은 일회성).
    if (decoded && decoded.ok === true && decoded.capability && typeof decoded.capability.token === 'string' && !hasInputBinding) {
      _capCachePut(feature, opts.jwt, decoded.capability.token, Number(decoded.capability.exp) || 0);
    }
    _dokkebiRunAuthInvalidCleanup(resp.status, decoded);
    return decoded;
  }
  try { window.__DOKKEBI_ATTEST__ = _proxyAttestRun; } catch {}

  function _proxyCapabilityUnlock(feature, opts) {
    if (_LOCAL_DB_MODE) {
      return Promise.resolve({ ok: false, code: 'CAPABILITY_LOCAL_DB', error: '로컬 DB 모드에서는 Signed Unlock Token을 발급할 수 없습니다.' });
    }
    return _dbRequest(function() { return _proxyCapabilityUnlockCore(feature, opts); });
  }
  try { window.__DOKKEBI_CAPABILITY_UNLOCK__ = _proxyCapabilityUnlock; } catch {}

  async function _proxyQueryCore(sql, params) {
    var _isSelect = sql.trimStart().substring(0, 6).toUpperCase() === 'SELECT';
    var _qHash = _isSelect ? await _queryHash(sql, params) : null;
    try {
      const payload = await _buildDbPayload(sql, params);
      const body = await _encryptPayload(payload);
      var sentAt = Date.now();
      const resp = await _fetch('/api/_dokkebi/db', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        body,
      });
      const json = await resp.json();
      _learnFromResponse(resp, json, sentAt);

      // 403 원인별 분기:
      //   (a) code: TIMESTAMP_SKEW → 서버가 server_ts 제공. offset 보정 후 1회 재시도.
      //   (b) "등록되지 않은 쿼리" → _debugSql 포함해 재시도 (세션 유지)
      //   (c) code: REPLAY_DETECTED → 새 nonce 로 1회 재시도 (매우 드문 collision)
      //   (e) 정책/권한 에러 코드 → 재핸드셰이크 없이 그대로 반환 (세션은 유효함)
      //   (d) 그 외 서명/세션 오류 → OPFS 세션 삭제 후 재핸드셰이크
      if (resp.status === 403 && (json.error || json.code)) {
        var errMsg = String(json.error || '');
        var errCode = String(json.code || '');
        var isUnregisteredQuery = errMsg.indexOf('등록되지 않은 쿼리') >= 0;

        // (e) 정책/권한 에러 — 세션 자체는 유효하므로 재핸드셰이크 불필요.
        //     그대로 반환해 백엔드 코드가 오류를 처리하도록 위임.
        var _POLICY_CODES = ['TENANT_MISSING', 'TENANT_MISMATCH', 'NO_TENANT_FILTER', 'NO_WHERE',
          'LOOSE_OR', 'INSERT_MISSING_TENANT_COL', 'INSERT_NO_COLUMNS', 'INJECT_FAILED',
          'INJECT_INCOMPLETE', 'AUTH_REQUIRED', 'ROLE_MISSING', 'ROLE_FORBIDDEN',
          'RULE_DENY', 'NO_RULE', 'sql_blocked', 'UNSUPPORTED_OP', 'UNSUPPORTED_INSERT_SUBQUERY'];
        if (_POLICY_CODES.indexOf(errCode) >= 0) {
          console.warn('[dokkebi] 🚫 정책/권한 거부 (' + errCode + ') — 세션 유지:', errMsg);
          _sendLog('error', 'wasm', ['DB 정책 위반 ' + errCode, errMsg, json.table ? 'table=' + json.table : '']).catch(function() {});
          return json;
        }

        if (errCode === 'TIMESTAMP_SKEW') {
          // 서버 바디에서 명시 server_ts 를 얻었으므로 offset 이 이미 학습됨.
          // 새 payload 로 1회만 재시도 (루프 방지).
          console.warn('[dokkebi] ⏱ 시계 오차 감지 — offset ' + _clockOffsetMs + 'ms 보정 후 재시도');
          const payloadR = await _buildDbPayload(sql, params);
          const bodyR = await _encryptPayload(payloadR);
          const respR = await _fetch('/api/_dokkebi/db', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: bodyR,
          });
          const jsonR = await respR.json();
          _learnFromResponse(respR, jsonR, Date.now());
          var resultR2 = jsonR._enc ? await _decryptResponse(jsonR) : jsonR;
          if (_qHash && resultR2 && resultR2.ok !== false) _cacheQueryResult(_qHash, resultR2);
          return resultR2;
        }

        if (errCode === 'REPLAY_DETECTED') {
          // 동일 nonce 가 이미 관측됨 → 새 nonce 로 1회 재시도.
          console.warn('[dokkebi] 🔁 nonce 충돌 — 새 nonce 로 재시도');
          const payloadR = await _buildDbPayload(sql, params);
          const bodyR = await _encryptPayload(payloadR);
          const respR = await _fetch('/api/_dokkebi/db', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: bodyR,
          });
          const jsonR = await respR.json();
          _learnFromResponse(respR, jsonR, Date.now());
          var resultR3 = jsonR._enc ? await _decryptResponse(jsonR) : jsonR;
          if (_qHash && resultR3 && resultR3.ok !== false) _cacheQueryResult(_qHash, resultR3);
          return resultR3;
        }

        if (isUnregisteredQuery && !payload._debugSql) {
          // (a) 미등록 queryId — auto 모드 fallback 용 _debugSql 포함 재시도
          console.warn('[dokkebi] 🔍 미등록 쿼리 → _debugSql 포함 재시도 (auto 모드 fallback)');
          const payloadR = { queryId: payload.queryId, params: payload.params, _debugSql: sql };
          const bodyR = await _encryptPayload(payloadR);
          const respR = await _fetch('/api/_dokkebi/db', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: bodyR,
          });
          const jsonR = await respR.json();
          var resultR = jsonR._enc ? await _decryptResponse(jsonR) : jsonR;
          if (_qHash && resultR && resultR.ok !== false) _cacheQueryResult(_qHash, resultR);
          return resultR;
        }

        // (b2) 배포 직후 wire 회전 불일치 — 세션 유지, 정규 필드명으로 1회 재시도
        if (!payload._canonWireRetry) {
          console.warn('[dokkebi] 🔁 배포 호환 — 정규 필드명으로 DB 재시도 (새로고침 없이)');
          const payloadR = await _buildDbPayload(sql, params);
          payloadR._canonWireRetry = true;
          const bodyR = await _encryptPayload(payloadR, { skipWire: true });
          const respR = await _fetch('/api/_dokkebi/db', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
            body: bodyR,
          });
          const jsonR = await respR.json();
          _learnFromResponse(respR, jsonR, Date.now());
          var resultCanon = jsonR._enc ? await _decryptResponse(jsonR) : jsonR;
          // HTTP 200 일 때만 성공 처리. 403/500 은 ok 필드가 없어 ok!==false 가 true 가 되며
          // 실패 응답을 성공처럼 캐시·반환해 (d) 재핸드셰이크 분기를 막던 버그 수정.
          if (respR.status >= 200 && respR.status < 300 && resultCanon && resultCanon.ok !== false) {
            if (_qHash) _cacheQueryResult(_qHash, resultCanon);
            return resultCanon;
          }
        }

        // (d) 세션 만료 또는 서명 오류 → 재핸드셰이크
        console.warn('[dokkebi] 🔄 세션 갱신 중... (재핸드셰이크)');
        _clearSessionOPFS();
        await _performHandshake();
        const payload2 = await _buildDbPayload(sql, params);
        const body2 = await _encryptPayload(payload2);
        var sentAt2 = Date.now();
        const resp2 = await _fetch('/api/_dokkebi/db', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json; charset=utf-8' },
          body: body2,
        });
        const json2 = await resp2.json();
        _learnFromResponse(resp2, json2, sentAt2);
        if (json2._enc) return _decryptResponse(json2);
        return json2;
      }

      var result = json._enc ? await _decryptResponse(json) : json;
      _dokkebiRunAuthInvalidCleanup(resp.status, result);
      if (_qHash && result.ok !== false) _cacheQueryResult(_qHash, result);
      return result;
    } catch (e) {
      if (_qHash) {
        var cached = await _getCachedQuery(_qHash);
        if (cached) {
          console.warn('[dokkebi] 📴 오프라인 — 캐시된 쿼리 결과 반환');
          return cached;
        }
      }
      return { ok: false, error: e.message };
    }
  }

  // _proxyQuery: 쓰기/비표준 요청은 직렬 큐로 카운터 순서 보장.
  // SELECT 로 시작하는 읽기는 짧은 윈도우 안 요청을 모아 한 번의 /db 왕복으로 묶음
  // (Worker D1.batch). 2건 이상이면 즉시 flush, 1건은 타이머(기본 50ms) 후 단건 경로.
  function _isParallelSafeSelectSql(sql) {
    var t = String(sql || '').replace(/^﻿/, '').trimStart();
    return t.toUpperCase().startsWith('SELECT');
  }

  var _readBatchMs = (function() {
    try {
      var w = typeof window !== 'undefined' ? window : null;
      var n = w && w.__DOKKEBI_DB_READ_BATCH_MS__;
      if (typeof n === 'number' && n >= 0) return Math.min(500, n);
      if (typeof n === 'string' && n !== '') {
        var p = parseInt(n, 10);
        if (!isNaN(p) && p >= 0) return Math.min(500, p);
      }
    } catch (_) {}
    return 50;
  })();
  var _readBatchQueue = [];
  var _readBatchTimer = null;
  var _readBatchFlushing = false;

  function _scheduleReadBatchFlush() {
    if (_readBatchTimer !== null) return;
    _readBatchTimer = setTimeout(function() {
      _readBatchTimer = null;
      _flushReadBatchChain();
    }, _readBatchMs);
  }

  function _flushReadBatchChain() {
    if (_readBatchFlushing || _readBatchQueue.length === 0) return;
    _readBatchFlushing = true;
    var batch = _readBatchQueue.splice(0, _readBatchQueue.length);
    Promise.resolve()
      .then(function() { return _flushReadBatchNow(batch); })
      .then(function() {
        _readBatchFlushing = false;
        if (_readBatchQueue.length > 0) _flushReadBatchChain();
      })
      .catch(function(e) {
        _readBatchFlushing = false;
        for (var i = 0; i < batch.length; i++) {
          try { batch[i].reject(e); } catch (_) {}
        }
        if (_readBatchQueue.length > 0) _flushReadBatchChain();
      });
  }

  async function _flushReadBatchNow(batch) {
    if (batch.length === 1) {
      try {
        var r0 = await _proxyQueryCore(batch[0].sql, batch[0].params);
        batch[0].resolve(r0);
      } catch (e) { batch[0].reject(e); }
      return;
    }
    try {
      var subs = [];
      for (var i = 0; i < batch.length; i++) {
        subs.push(await _buildDbPayload(batch[i].sql, batch[i].params));
      }
      var outerJwt = '';
      for (var j = 0; j < subs.length; j++) {
        if (subs[j]._jwt) { outerJwt = subs[j]._jwt; break; }
      }
      for (var k = 0; k < subs.length; k++) {
        if (subs[k]._jwt !== undefined) delete subs[k]._jwt;
      }
      var batchPayload = { _batchRead: subs };
      if (outerJwt) batchPayload._jwt = outerJwt;
      var sentAt = Date.now();
      var body = await _encryptPayload(batchPayload);
      var resp = await _fetch('/api/_dokkebi/db', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        body,
      });
      var json = await resp.json();
      _learnFromResponse(resp, json, sentAt);
      var decoded = json._enc ? await _decryptResponse(json) : json;
      var okBatch = decoded && decoded.ok === true && Array.isArray(decoded.results)
        && decoded.results.length === batch.length;
      if (!okBatch) {
        var rows = await Promise.all(batch.map(function(b) {
          return _proxyQueryCore(b.sql, b.params);
        }));
        for (var r = 0; r < rows.length; r++) batch[r].resolve(rows[r]);
        return;
      }
      for (var x = 0; x < batch.length; x++) {
        var item = batch[x];
        var one = decoded.results[x];
        var isSel = item.sql.trimStart().substring(0, 6).toUpperCase() === 'SELECT';
        var qh = isSel ? await _queryHash(item.sql, item.params) : null;
        if (qh && one && one.ok !== false) _cacheQueryResult(qh, one);
        item.resolve(one);
      }
    } catch (e) {
      try {
        var rows2 = await Promise.all(batch.map(function(b) {
          return _proxyQueryCore(b.sql, b.params);
        }));
        for (var z = 0; z < rows2.length; z++) batch[z].resolve(rows2[z]);
      } catch (e2) {
        for (var z2 = 0; z2 < batch.length; z2++) batch[z2].reject(e2);
      }
    }
  }

  function _enqueueReadBatch(sql, params) {
    return new Promise(function(resolve, reject) {
      _readBatchQueue.push({ sql: sql, params: params, resolve: resolve, reject: reject });
      if (_readBatchQueue.length >= 2) {
        if (_readBatchTimer !== null) {
          clearTimeout(_readBatchTimer);
          _readBatchTimer = null;
        }
        _flushReadBatchChain();
      } else {
        _scheduleReadBatchFlush();
      }
    });
  }

  function _proxyQuery(sql, params) {
    if (!_LOCAL_DB_MODE && _isParallelSafeSelectSql(sql)) {
      return _enqueueReadBatch(sql, params);
    }
    return _dbRequest(function() { return _proxyQueryCore(sql, params); });
  }

  // ────────────────────────────────────────────────────────
  // host-crypto
  // ────────────────────────────────────────────────────────
  const hostCrypto = {
    randomBytes: (len) => Array.from(crypto.getRandomValues(new Uint8Array(len))),
    hashSha256: async (data) => {
      const buf = await crypto.subtle.digest('SHA-256', new Uint8Array(data));
      return Array.from(new Uint8Array(buf));
    },
    hmacSign: async (key, data) => {
      const k = await crypto.subtle.importKey(
        'raw', new Uint8Array(key),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
      );
      const sig = await crypto.subtle.sign('HMAC', k, new Uint8Array(data));
      return Array.from(new Uint8Array(sig));
    },
    nowMillis: () => Date.now(),
  };

  // ────────────────────────────────────────────────────────
  // host-kv (세션 스토리지 기반)
  // ────────────────────────────────────────────────────────
  const hostKv = {
    kvGet: (key) => {
      const raw = sessionStorage.getItem('dk:' + key);
      if (!raw) {
        // sessionStorage에 없으면 Opaque Handle (민감 환경변수)에서 폴백 조회
        // 시크릿을 sessionStorage에 노출하지 않으면서 kv.kvGet 패턴 호환
        if (Object.prototype.hasOwnProperty.call(_envSecretMap, key)) {
          return _envSecretMap[key];
        }
        return undefined;
      }
      try {
        const p = JSON.parse(raw);
        if (p.exp && Date.now() > p.exp) {
          sessionStorage.removeItem('dk:' + key);
          return undefined;
        }
        return p.v !== undefined ? p.v : raw;
      } catch { return raw; }
    },
    kvSet: (key, value, ttlSecs) => {
      const entry = ttlSecs
        ? JSON.stringify({ v: value, exp: Date.now() + ttlSecs * 1000 })
        : value;
      sessionStorage.setItem('dk:' + key, entry);
    },
    kvDelete: (key) => sessionStorage.removeItem('dk:' + key),
  };

  // ────────────────────────────────────────────────────────
  // host-opfs (OPFS 데이터 파이프라인 — 청크 기반 대용량 데이터 처리)
  // 대용량 데이터를 RAM에 올리지 않고 OPFS를 경유해 청크 단위로 스트리밍 처리
  // ────────────────────────────────────────────────────────
  const _OPFS_DATA_ROOT = 'dokkebi-data';
  let _opfsDataDir = null;
  let _opfsAvailable = null;
  const _memFallback = new Map();

  async function _opfsDataInit() {
    if (_opfsDataDir) return true;
    if (_opfsAvailable === false) return false;
    try {
      var root = await navigator.storage.getDirectory();
      _opfsDataDir = await root.getDirectoryHandle(_OPFS_DATA_ROOT, { create: true });
      _opfsAvailable = true;
      return true;
    } catch { _opfsAvailable = false; return false; }
  }

  function _bytesToBase64(bytes) {
    var parts = [];
    for (var i = 0; i < bytes.length; i += 8192) {
      parts.push(String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 8192, bytes.length))));
    }
    return btoa(parts.join(''));
  }

  function _base64ToBytes(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  async function _opfsResolvePath(filePath, create) {
    if (!(await _opfsDataInit())) return null;
    var parts = filePath.replace(/^\/+/, '').split('/').filter(Boolean);
    if (parts.length === 0) throw new Error('Empty OPFS path');
    var dir = _opfsDataDir;
    for (var i = 0; i < parts.length - 1; i++) {
      dir = await dir.getDirectoryHandle(parts[i], { create: !!create });
    }
    return { dir: dir, name: parts[parts.length - 1] };
  }

  const hostOpfs = {
    async writeChunk(filePath, offset, base64Data) {
      var bytes = _base64ToBytes(base64Data);
      var resolved = await _opfsResolvePath(filePath, true);
      if (resolved) {
        var fh = await resolved.dir.getFileHandle(resolved.name, { create: true });
        var writable = await fh.createWritable({ keepExistingData: true });
        await writable.write({ type: 'write', position: offset, data: bytes });
        await writable.close();
      } else {
        var existing = _memFallback.get(filePath) || new Uint8Array(0);
        var needed = offset + bytes.length;
        if (existing.length < needed) {
          var grown = new Uint8Array(needed);
          grown.set(existing);
          existing = grown;
        }
        existing.set(bytes, offset);
        _memFallback.set(filePath, existing);
      }
    },
    async readChunk(filePath, offset, length) {
      var resolved = await _opfsResolvePath(filePath, false);
      if (resolved) {
        try {
          var fh = await resolved.dir.getFileHandle(resolved.name);
          var file = await fh.getFile();
          if (offset >= file.size) return '';
          var end = Math.min(offset + length, file.size);
          var slice = file.slice(offset, end);
          var buf = await slice.arrayBuffer();
          return _bytesToBase64(new Uint8Array(buf));
        } catch { return ''; }
      }
      var data = _memFallback.get(filePath);
      if (!data || offset >= data.length) return '';
      var end = Math.min(offset + length, data.length);
      return _bytesToBase64(data.subarray(offset, end));
    },
    async stat(filePath) {
      var resolved = await _opfsResolvePath(filePath, false);
      if (resolved) {
        try {
          var fh = await resolved.dir.getFileHandle(resolved.name);
          var file = await fh.getFile();
          return { size: file.size, lastModified: file.lastModified };
        } catch { return null; }
      }
      var data = _memFallback.get(filePath);
      return data ? { size: data.length, lastModified: Date.now() } : null;
    },
    async remove(filePath) {
      var resolved = await _opfsResolvePath(filePath, false);
      if (resolved) {
        try { await resolved.dir.removeEntry(resolved.name); } catch {}
      }
      _memFallback.delete(filePath);
    },
    async removeDir(dirPath) {
      if (await _opfsDataInit()) {
        try {
          var parts = dirPath.replace(/^\/+/, '').split('/').filter(Boolean);
          var dir = _opfsDataDir;
          for (var i = 0; i < parts.length - 1; i++) dir = await dir.getDirectoryHandle(parts[i]);
          await dir.removeEntry(parts[parts.length - 1], { recursive: true });
        } catch {}
      }
      for (var key of _memFallback.keys()) {
        if (key.startsWith(dirPath)) _memFallback.delete(key);
      }
    },
    async list(dirPath) {
      if (await _opfsDataInit()) {
        try {
          var dir = _opfsDataDir;
          if (dirPath) {
            var parts = dirPath.replace(/^\/+/, '').split('/').filter(Boolean);
            for (var i = 0; i < parts.length; i++) dir = await dir.getDirectoryHandle(parts[i]);
          }
          var entries = [];
          for await (var entry of dir.values()) entries.push(entry.name);
          return entries;
        } catch { return []; }
      }
      var prefix = dirPath ? dirPath.replace(/^\/+/, '').replace(/\/$/, '') + '/' : '';
      var names = new Set();
      for (var key of _memFallback.keys()) {
        if (key.startsWith(prefix)) {
          var rest = key.slice(prefix.length).split('/')[0];
          if (rest) names.add(rest);
        }
      }
      return Array.from(names);
    },
  };

  // ────────────────────────────────────────────────────────
  // 플러그인 Host 구현 (dokkebi.config.js 설정에 따라 동적 주입)
  // ────────────────────────────────────────────────────────
  /* __DOKKEBI_PH_PLUGIN_HOST__ */

  const hostCapability = {
    async unlock(feature, options) {
      return _proxyCapabilityUnlock(feature, options || {});
    },
  };

  // ────────────────────────────────────────────────────────
  // console 인터셉터 — 호스트(브라우저) 로그를 CLI 터미널로 전송
  // ────────────────────────────────────────────────────────
  const _origConsole = {};
  ['log', 'warn', 'error', 'info'].forEach(function(l) {
    try { _origConsole[l] = Function.prototype.bind.call(console[l], console); }
    catch(e) { _origConsole[l] = function() {}; }
  });

  let _consoleReentrant = false;

  function _serializeArg(a) {
    if (a === null) return 'null';
    if (a === undefined) return 'undefined';
    if (typeof a === 'string') return a;
    if (a instanceof Error) return a.stack || a.message || String(a);
    try { return JSON.stringify(a); } catch { return String(a); }
  }

  function _patchConsole(level) {
    var orig = _origConsole[level];
    console[level] = function() {
      if (_consoleReentrant) { orig.apply(console, arguments); return; }
      _consoleReentrant = true;
      try { orig.apply(console, arguments); } catch(e) { /* swallow TDZ / React internals errors */ }
      _consoleReentrant = false;
      var args = Array.prototype.slice.call(arguments);
      var firstStr = typeof args[0] === 'string' ? args[0] : '';
      if (firstStr.startsWith('[vite]') || firstStr.startsWith('[HMR]')) return;
      _sendLog(level, 'host', args.map(_serializeArg)).catch(function() {});
    };
  }
  _patchConsole('log');
  _patchConsole('warn');
  _patchConsole('error');
  _patchConsole('info');

  // 미처리 예외 + 프로미스 거부도 CLI로 전송
  window.addEventListener('error', (e) => {
    const msg = e.error ? (e.error.stack || e.error.message || String(e.error)) : e.message;
    _sendLog('error', 'uncaught', [msg]).catch(() => {});
  });
  window.addEventListener('unhandledrejection', (e) => {
    const msg = e.reason instanceof Error
      ? (e.reason.stack || e.reason.message)
      : String(e.reason);
    _sendLog('error', 'unhandled-promise', [msg]).catch(() => {});
  });

  // ────────────────────────────────────────────────────────
  // QuickJS Async VM 초기화 + 백엔드 실행
  // ────────────────────────────────────────────────────────
  globalThis.__dokkebi_host__ = { db: hostDb, crypto: hostCrypto, kv: hostKv, opfs: hostOpfs, capability: hostCapability };

  let _resolveReady, _rejectReady;
  window.dokkebiReady = new Promise((res, rej) => {
    _resolveReady = res;
    _rejectReady  = rej;
  });

  (async () => {
    try {
      // Step 1: OPFS 초기화
      await _opfsInit();
      await _opfsDataInit();
      if (_opfsDataDir) {
        try {
          for await (var _entry of _opfsDataDir.values()) {
            if (_entry.name.startsWith('_tmp') && _entry.kind === 'directory') {
              _opfsDataDir.removeEntry(_entry.name, { recursive: true }).catch(function() {});
            }
          }
        } catch {}
      }

      // Step 1b: 로컬 DB → sql.js / 온라인 → D1 핸드셰이크는 백그라운드 (트랙 분리: 번들 복호는 __DOKKEBI_BOOT__ 로 병렬)
      if (_LOCAL_DB_MODE) {
        await _initLocalSqlDb();
      } else {
        _handshakeBgP = (async function _handshakeBackground() {
          try {
            if (!(await _restoreSessionFromOPFS())) {
              await _performHandshakeResilient();
            } else if (__DOKKEBI_PH_BOOL_ENCRYPTED_TEXT___OR___DOKKEBI_PH_BOOL_BYTECODE_ENC__ && !_envSecretMap['__DOKKEBI_BC_KEY__']) {
              var _hasBoot = false;
              try {
                var _gb = typeof window !== 'undefined' ? window : null;
                var _b = _gb && _gb.__DOKKEBI_BOOT__;
                _hasBoot = _b && Number(_b.v) === 1 && _b.w && _b.n && _b.t;
              } catch (_) {}
              if (!_hasBoot) {
                console.log('[dokkebi] 🔄 복호화 키 미보유 — 재핸드셰이크 진행');
                await _clearSessionOPFS();
                await _performHandshakeResilient();
              } else {
                console.log('[dokkebi] 🔐 OPFS 세션 복원 — 번들 키는 HTML BOOT 경로 사용');
              }
            } else {
              console.log('[dokkebi] 🔐 OPFS 캐시에서 세션 복원 (핸드셰이크 생략)');
            }
          } catch (e) {
            console.error('[dokkebi] ⛔ 백그라운드 핸드셰이크 실패:', e && e.message ? e.message : e);
            throw e;
          }
        })();
      }

      // Step 2: QuickJS Sync VM 로드 (로컬 번들, CDN 없음)
      // 커스텀 WebAssembly.Memory: QuickJS WASM 기본 maximum=2GB → 모바일 32MB / PC 256MB
      // iOS Safari에서 2GB 가상 주소 예약이 OOM 크래시를 유발하므로 제한 필수
      const _v = '__DOKKEBI_PH_BUNDLE_HASH__'.slice(0, 12) || Date.now();
      const { getQuickJS } = await import('/dokkebi/dokkebi-qjs.js?v=' + _v);
      const _isMob = /iPhone|iPad|iPod|Android|Mobile/i.test(navigator.userAgent);
      const _wasmMem = new WebAssembly.Memory({
        initial: 256,                      // 16MB (QuickJS WASM 모듈 최소 요구량)
        maximum: _isMob ? 3200 : 20480,   // 200MB(모바일) / 1280MB(PC) — VM 한도 + 런타임 여유 포함
      });
      const QuickJS = await getQuickJS({ wasmMemory: _wasmMem });
      const _vm = QuickJS.newContext();

      try { _vm.runtime.setMemoryLimit(_isMob ? 100 * 1024 * 1024 : 1024 * 1024 * 1024); } catch {}
      try { _vm.runtime.setMaxStackSize(512 * 1024); } catch {}

      // Step 3: Host 함수를 VM에 주입 (WIT import 구현)
      const hostModule = _vm.newObject();

      // host-db / host-crypto 공통 헬퍼
      // deferred.resolve/reject + executePendingJobs 를 반드시 비동기(queueMicrotask)로 실행
      // 호스트 함수 내부에서 동기적으로 resolve 하면 executePendingJobs 가 재진입(re-entrant)되어
      // QJS 이벤트 루프가 교착상태에 빠집니다.
      function _settleDeferred(deferred, valueH, isReject, ctx) {
        queueMicrotask(() => {
          if (!_vm.alive) return;
          if (isReject) {
            try {
              const errMsg = _vm.getString(valueH);
              // opfs.stat NotFoundError 는 파일 존재 여부 확인의 정상 케이스 — 로그 스킵
              const isStatNotFound = ctx === 'opfs.stat' && errMsg.includes('NotFoundError');
              if (!isStatNotFound) {
                _sendLog('error', 'wasm', [ctx || 'host-fn', errMsg]);
              }
            } catch {}
            deferred.reject(valueH);
          } else {
            deferred.resolve(valueH);
          }
          valueH.dispose();
          deferred.dispose();
          _vm.runtime.executePendingJobs(-1);
        });
      }

      const vmHostDb = _vm.newObject();
      _vm.setProp(vmHostDb, 'dbExecute', _vm.newFunction('dbExecute',
        (handleIdH, sqlH, paramsH) => {
          const sql    = _vm.getString(sqlH);
          const params = _vm.dump(paramsH);
          const deferred = _vm.newPromise();
          hostDb.dbExecute(null, sql, Array.isArray(params) ? params : [])
            .then(result => _settleDeferred(deferred, _vm.newString(JSON.stringify(result)), false, 'dbExecute'))
            .catch(err   => _settleDeferred(deferred, _vm.newString(String(err)), true, 'dbExecute: ' + sql));
          return deferred.handle.dup();
        }
      ));
      _vm.setProp(vmHostDb, 'dbTransaction', _vm.newFunction('dbTransaction',
        (handleIdH, statementsH) => {
          const statements = _vm.dump(statementsH);
          const deferred = _vm.newPromise();
          hostDb.dbTransaction(null, statements)
            .then(result => _settleDeferred(deferred, _vm.newString(JSON.stringify(result)), false, 'dbTransaction'))
            .catch(err   => _settleDeferred(deferred, _vm.newString(String(err)), true, 'dbTransaction'));
          return deferred.handle.dup();
        }
      ));
      _vm.setProp(hostModule, 'db', vmHostDb);

      // host-crypto
      const vmHostCrypto = _vm.newObject();
      _vm.setProp(vmHostCrypto, 'randomBytes', _vm.newFunction('randomBytes', (lenH) => {
        const len = _vm.getNumber(lenH);
        return _vm.newString(JSON.stringify(hostCrypto.randomBytes(len)));
      }));
      _vm.setProp(vmHostCrypto, 'nowMillis', _vm.newFunction('nowMillis', () => {
        return _vm.newString(String(hostCrypto.nowMillis()));
      }));
      _vm.setProp(vmHostCrypto, 'hashSha256', _vm.newFunction('hashSha256', (dataH) => {
        const data = _vm.dump(dataH);
        const deferred = _vm.newPromise();
        hostCrypto.hashSha256(data)
          .then(result => _settleDeferred(deferred, _vm.newString(JSON.stringify(result)), false, 'hashSha256'))
          .catch(err   => _settleDeferred(deferred, _vm.newString(String(err)), true, 'hashSha256'));
        return deferred.handle.dup();
      }));
      _vm.setProp(vmHostCrypto, 'hmacSign', _vm.newFunction('hmacSign', (keyH, dataH) => {
        const key  = _vm.dump(keyH);
        const data = _vm.dump(dataH);
        const deferred = _vm.newPromise();
        hostCrypto.hmacSign(key, data)
          .then(result => _settleDeferred(deferred, _vm.newString(JSON.stringify(result)), false, 'hmacSign'))
          .catch(err   => _settleDeferred(deferred, _vm.newString(String(err)), true, 'hmacSign'));
        return deferred.handle.dup();
      }));
      _vm.setProp(hostModule, 'crypto', vmHostCrypto);

      // host-kv
      const vmHostKv = _vm.newObject();
      _vm.setProp(vmHostKv, 'kvGet', _vm.newFunction('kvGet', (keyH) => {
        const key = _vm.getString(keyH);
        const val = hostKv.kvGet(key);
        return val !== undefined ? _vm.newString(val) : _vm.undefined;
      }));
      _vm.setProp(vmHostKv, 'kvSet', _vm.newFunction('kvSet', (keyH, valueH, ttlH) => {
        hostKv.kvSet(
          _vm.getString(keyH),
          _vm.getString(valueH),
          ttlH !== _vm.undefined ? _vm.getNumber(ttlH) : undefined
        );
        return _vm.undefined;
      }));
      _vm.setProp(hostModule, 'kv', vmHostKv);

      // host-opfs (데이터 파이프라인 — 청크 기반 대용량 I/O)
      const vmHostOpfs = _vm.newObject();
      _vm.setProp(vmHostOpfs, 'writeChunk', _vm.newFunction('writeChunk', (pathH, offsetH, dataH) => {
        const filePath = _vm.getString(pathH);
        const offset   = _vm.getNumber(offsetH);
        const data     = _vm.getString(dataH);
        const deferred = _vm.newPromise();
        hostOpfs.writeChunk(filePath, offset, data)
          .then(() => _settleDeferred(deferred, _vm.newString('ok'), false, 'opfs.writeChunk'))
          .catch(err => _settleDeferred(deferred, _vm.newString(String(err)), true, 'opfs.writeChunk'));
        return deferred.handle.dup();
      }));
      _vm.setProp(vmHostOpfs, 'readChunk', _vm.newFunction('readChunk', (pathH, offsetH, lenH) => {
        const filePath = _vm.getString(pathH);
        const offset   = _vm.getNumber(offsetH);
        const len      = _vm.getNumber(lenH);
        const deferred = _vm.newPromise();
        hostOpfs.readChunk(filePath, offset, len)
          .then(b64 => _settleDeferred(deferred, _vm.newString(b64), false, 'opfs.readChunk'))
          .catch(err => _settleDeferred(deferred, _vm.newString(String(err)), true, 'opfs.readChunk'));
        return deferred.handle.dup();
      }));
      _vm.setProp(vmHostOpfs, 'stat', _vm.newFunction('stat', (pathH) => {
        const filePath = _vm.getString(pathH);
        const deferred = _vm.newPromise();
        hostOpfs.stat(filePath)
          .then(info => _settleDeferred(deferred, _vm.newString(JSON.stringify(info)), false, 'opfs.stat'))
          .catch(err => _settleDeferred(deferred, _vm.newString(String(err)), true, 'opfs.stat'));
        return deferred.handle.dup();
      }));
      _vm.setProp(vmHostOpfs, 'remove', _vm.newFunction('remove', (pathH) => {
        const filePath = _vm.getString(pathH);
        const deferred = _vm.newPromise();
        hostOpfs.remove(filePath)
          .then(() => _settleDeferred(deferred, _vm.newString('ok'), false, 'opfs.remove'))
          .catch(err => _settleDeferred(deferred, _vm.newString(String(err)), true, 'opfs.remove'));
        return deferred.handle.dup();
      }));
      _vm.setProp(vmHostOpfs, 'removeDir', _vm.newFunction('removeDir', (pathH) => {
        const dirPath = _vm.getString(pathH);
        const deferred = _vm.newPromise();
        hostOpfs.removeDir(dirPath)
          .then(() => _settleDeferred(deferred, _vm.newString('ok'), false, 'opfs.removeDir'))
          .catch(err => _settleDeferred(deferred, _vm.newString(String(err)), true, 'opfs.removeDir'));
        return deferred.handle.dup();
      }));
      _vm.setProp(vmHostOpfs, 'list', _vm.newFunction('list', (pathH) => {
        const dirPath = _vm.getString(pathH);
        const deferred = _vm.newPromise();
        hostOpfs.list(dirPath)
          .then(entries => _settleDeferred(deferred, _vm.newString(JSON.stringify(entries)), false, 'opfs.list'))
          .catch(err => _settleDeferred(deferred, _vm.newString(String(err)), true, 'opfs.list'));
        return deferred.handle.dup();
      }));
      _vm.setProp(hostModule, 'opfs', vmHostOpfs);

      const vmHostCapability = _vm.newObject();
      _vm.setProp(vmHostCapability, 'unlock', _vm.newFunction('unlock', (featureH, optsH) => {
        const feature = _vm.getString(featureH);
        let opts = {};
        try {
          opts = optsH && optsH.type !== 'undefined' ? _vm.dump(optsH) : {};
        } catch { opts = {}; }
        const deferred = _vm.newPromise();
        hostCapability.unlock(feature, opts && typeof opts === 'object' ? opts : {})
          .then(result => _settleDeferred(deferred, _vm.newString(JSON.stringify(result)), false, 'capability.unlock'))
          .catch(err => _settleDeferred(deferred, _vm.newString(String(err)), true, 'capability.unlock'));
        return deferred.handle.dup();
      }));
      _vm.setProp(hostModule, 'capability', vmHostCapability);

      // ── 플러그인 VM 브릿지 (dokkebi.config.js 설정에 따라 동적 주입) ──
      /* __DOKKEBI_PH_PLUGIN_VM_BRIDGE__ */

      _vm.setProp(_vm.global, '__dokkebi_host__', hostModule);

      // Step 3a-env: 민감 환경변수 Opaque Handle 호스트 함수 등록
      // WASM 번들 내 __dokkebi_env__("KEY") 호출 시 Host 클로저의 실제 값을 반환
      // 실제 시크릿 값은 WASM 메모리에 평문으로 존재하지 않고 Host JS 스코프에만 존재
      _vm.setProp(_vm.global, '__dokkebi_env__', _vm.newFunction('__dokkebi_env__', (keyH) => {
        const key = _vm.getString(keyH);
        const val = _envSecretMap[key];
        return _vm.newString(val !== undefined ? val : '');
      }));

      // Step 3a-timer: setTimeout/clearTimeout 호스트 딜레이 함수
      _vm.setProp(_vm.global, '__host_delay__', _vm.newFunction('__host_delay__', (msH) => {
        const ms = _vm.getNumber(msH);
        const deferred = _vm.newPromise();
        setTimeout(() => { deferred.resolve(_vm.undefined); }, Math.max(0, ms));
        deferred.settled.then(_vm.runtime.executePendingJobs);
        return deferred.handle.dup();
      }));

      // Step 3b: QuickJS VM 에 Web API 폴리필 주입
      // QuickJS 는 순수 ECMAScript 엔진이므로 TextEncoder/btoa/atob/console 등이 없습니다.
      const polyfillCode = `
        // ── TextEncoder / TextDecoder 폴리필 ──
        if (typeof globalThis.TextEncoder === 'undefined') {
          globalThis.TextEncoder = class TextEncoder {
            encode(str) {
              const arr = [];
              for (let i = 0; i < str.length; i++) {
                let c = str.charCodeAt(i);
                if (c < 0x80) { arr.push(c); }
                else if (c < 0x800) { arr.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
                else if (c >= 0xd800 && c <= 0xdbff) {
                  const hi = c, lo = str.charCodeAt(++i);
                  c = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
                  arr.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f),
                           0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
                } else {
                  arr.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
                }
              }
              return new Uint8Array(arr);
            }
          };
        }
        if (typeof globalThis.TextDecoder === 'undefined') {
          globalThis.TextDecoder = class TextDecoder {
            decode(buf) {
              const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
              let str = '', i = 0;
              while (i < bytes.length) {
                let c = bytes[i++];
                if (c < 0x80) { str += String.fromCharCode(c); }
                else if ((c & 0xe0) === 0xc0) {
                  str += String.fromCharCode(((c & 0x1f) << 6) | (bytes[i++] & 0x3f));
                } else if ((c & 0xf0) === 0xe0) {
                  str += String.fromCharCode(((c & 0x0f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f));
                } else {
                  const cp = ((c & 0x07) << 18) | ((bytes[i++] & 0x3f) << 12) |
                             ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f);
                  str += String.fromCodePoint(cp);
                }
              }
              return str;
            }
          };
        }

        // ── btoa / atob 폴리필 ──
        if (typeof globalThis.btoa === 'undefined') {
          const _chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
          globalThis.btoa = function(str) {
            let out = '', i = 0;
            while (i < str.length) {
              const a = str.charCodeAt(i++), b = i < str.length ? str.charCodeAt(i++) : NaN,
                    c = i < str.length ? str.charCodeAt(i++) : NaN;
              const n = (a << 16) | ((isNaN(b) ? 0 : b) << 8) | (isNaN(c) ? 0 : c);
              out += _chars[(n >> 18) & 63] + _chars[(n >> 12) & 63]
                   + (isNaN(b) ? '=' : _chars[(n >> 6) & 63])
                   + (isNaN(c) ? '=' : _chars[n & 63]);
            }
            return out;
          };
        }
        if (typeof globalThis.atob === 'undefined') {
          const _inv = {};
          'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.split('').forEach((c, i) => _inv[c] = i);
          globalThis.atob = function(b64) {
            b64 = b64.replace(/=+$/, '');
            let out = '', i = 0;
            while (i < b64.length) {
              const a = _inv[b64[i++]] || 0, b = _inv[b64[i++]] || 0,
                    c = _inv[b64[i++]], d = _inv[b64[i++]];
              out += String.fromCharCode((a << 2) | (b >> 4));
              if (c !== undefined) out += String.fromCharCode(((b & 15) << 4) | (c >> 2));
              if (d !== undefined) out += String.fromCharCode(((c & 3) << 6) | d);
            }
            return out;
          };
        }

        // ── setTimeout / clearTimeout 폴리필 ──
        if (typeof globalThis.setTimeout === 'undefined') {
          const _timers = new Map();
          let _timerSeq = 1;
          globalThis.setTimeout = function(fn, ms) {
            const id = _timerSeq++;
            _timers.set(id, fn);
            __host_delay__(ms || 0).then(function() {
              const cb = _timers.get(id);
              if (cb) { _timers.delete(id); if (typeof cb === 'function') cb(); }
            });
            return id;
          };
          globalThis.clearTimeout = function(id) { _timers.delete(id); };
          globalThis.setInterval = function(fn, ms) {
            const id = _timerSeq++;
            function tick() {
              _timers.set(id, fn);
              __host_delay__(ms || 0).then(function() {
                const cb = _timers.get(id);
                if (cb) { if (typeof cb === 'function') cb(); tick(); }
              });
            }
            tick();
            return id;
          };
          globalThis.clearInterval = function(id) { _timers.delete(id); };
        }

        // console 은 호스트 함수로 별도 주입 (폴리필 아래 참조)
        if (typeof globalThis.console === 'undefined') {
          globalThis.console = {
            log:   (...args) => {},
            warn:  (...args) => {},
            error: (...args) => {},
            info:  (...args) => {},
            debug: (...args) => {},
          };
        }
      `;
      const polyfillResult = _vm.evalCode(polyfillCode, 'dokkebi-polyfills.js');
      if (polyfillResult.error) {
        const err = _vm.dump(polyfillResult.error);
        polyfillResult.error.dispose();
        throw new Error('[dokkebi] 폴리필 주입 실패: ' + JSON.stringify(err));
      }
      polyfillResult.value.dispose();

      // Step 3c: VM console → dok dev/serve 터미널로 전달
      // QuickJS 내부 console.log/error/warn 호출 시 /api/_dokkebi/log 전송
      function _vmDumpHandle(h) {
        try {
          const t = _vm.typeof(h);
          if (t === 'undefined') return 'undefined';
          if (t === 'null')      return 'null';
          if (t === 'string')    return _vm.getString(h);
          if (t === 'number' || t === 'boolean') return String(_vm.dump(h));
          // Error 객체 — message/stack은 non-enumerable이라 _vm.dump()로는 {}가 됨
          // getProp으로 직접 읽어야 함
          const msgH   = _vm.getProp(h, 'message');
          const stackH = _vm.getProp(h, 'stack');
          const msg    = msgH   && _vm.typeof(msgH)   === 'string' ? _vm.getString(msgH)   : null;
          const stack  = stackH && _vm.typeof(stackH) === 'string' ? _vm.getString(stackH) : null;
          if (msgH)   msgH.dispose();
          if (stackH) stackH.dispose();
          if (msg) return stack ? (stack.startsWith(msg) ? stack : msg + '\n' + stack) : msg;
          // 일반 객체 — JSON 직렬화
          return JSON.stringify(_vm.dump(h));
        } catch { return '[dump error]'; }
      }

      function _vmLog(level, argsHandles) {
        const messages = argsHandles.map(_vmDumpHandle);
        _sendLog(level, 'wasm', messages);
      }

      const vmConsole = _vm.newObject();
      ['log', 'info', 'warn', 'error', 'debug'].forEach(level => {
        _vm.setProp(vmConsole, level, _vm.newFunction('console.' + level, (...args) => {
          _vmLog(level, args);
          return _vm.undefined;
        }));
      });
      _vm.setProp(_vm.global, 'console', vmConsole);

      // WASM VM 에러 → dok serve 터미널 전송 헬퍼
      function _wasmLog(level, ...msgs) {
        _sendLog(level, 'wasm', msgs);
      }

      // Step 4: 백엔드 번들 로드 (OPFS 캐시 → 네트워크 폴백) + SHA-256 무결성 검증
      var _cachedBundle = await _loadCachedBundle('__DOKKEBI_PH_BUNDLE_HASH__');
      var _isBytecodeMode = __DOKKEBI_PH_BOOL_BYTECODE_MODE__;
      var _isBytecodeEnc  = __DOKKEBI_PH_BOOL_BYTECODE_ENC__;
      var _isEncTextMode  = __DOKKEBI_PH_BOOL_ENCRYPTED_TEXT__;
      var _bundleRaw;

      if (_isEncTextMode) {
        // 1차: 해시 박힌 파일명 (현재 빌드의 immutable 자산) → 무중단 배포 안전
        // 2차: 비-해시 호환 파일명 (구 클라이언트/엣지 캐시 race 폴백)
        async function _fetchEncBundleBytes() {
          var _primaryUrl = '/dokkebi/__DOKKEBI_PH_ENC_ASSET__';
          try {
            var r1 = await fetch(_primaryUrl);
            if (r1 && r1.ok) return new Uint8Array(await r1.arrayBuffer());
          } catch (e) { /* 네트워크 실패 → 폴백 */ }
          var r2 = await fetch('/dokkebi/backend.bundle.enc?v=' + _v);
          return new Uint8Array(await r2.arrayBuffer());
        }
        _bundleRaw = _cachedBundle instanceof Uint8Array
          ? _cachedBundle
          : await _fetchEncBundleBytes();
      } else if (_isBytecodeMode) {
        var _bcFileName = _isBytecodeEnc ? 'backend.bytecode.enc' : 'backend.bytecode';
        _bundleRaw = _cachedBundle instanceof Uint8Array
          ? _cachedBundle
          : new Uint8Array(await fetch('/dokkebi/' + _bcFileName + '?v=' + _v).then(function(r) { return r.arrayBuffer(); }));
      } else {
        _bundleRaw = (typeof _cachedBundle === 'string' && _cachedBundle)
          ? _cachedBundle
          : await fetch('/dokkebi/backend-bundle.js?v=' + _v).then(function(r) { return r.text(); });
      }

      // Bundle Attestation 용 — 메인 스레드의 attest 함수가 이 바이트를 청크 슬라이싱해 응답한다.
      // 키는 bundleHash 로 격리되며, 단일 페이지에 여러 도깨비 인스턴스가 떠도 충돌하지 않는다.
      try {
        var _attestBytes = _bundleRaw instanceof Uint8Array
          ? _bundleRaw
          : new TextEncoder().encode(String(_bundleRaw || ''));
        window.__DOKKEBI_ATTEST_BYTES__ = window.__DOKKEBI_ATTEST_BYTES__ || {};
        window.__DOKKEBI_ATTEST_BYTES__['__DOKKEBI_PH_BUNDLE_HASH__'] = _attestBytes;
        window.__DOKKEBI_ATTEST_LATEST__ = '__DOKKEBI_PH_BUNDLE_HASH__';
      } catch (e) { /* attest bytes 노출 실패해도 정상 부팅에는 영향 없음 */ }

      // 빌드 타임에 생성된 해시로 번들 무결성 검증 (변조/중간자 공격 탐지)
      const _BUNDLE_EXPECTED_HASH = '__DOKKEBI_PH_BUNDLE_HASH__';
      if (_BUNDLE_EXPECTED_HASH) {
        const _isBinaryBundle = _isBytecodeMode || _isEncTextMode;
        const _hashInput = _isBinaryBundle ? _bundleRaw : new TextEncoder().encode(_bundleRaw);
        const _hashBuf   = await crypto.subtle.digest('SHA-256', _hashInput);
        const _hashHex   = Array.from(new Uint8Array(_hashBuf))
          .map(b => b.toString(16).padStart(2, '0')).join('');
        if (_hashHex !== _BUNDLE_EXPECTED_HASH) {
          var _fname = _isEncTextMode ? 'backend.bundle.enc' : (_isBytecodeEnc ? 'backend.bytecode.enc' : (_isBytecodeMode ? 'backend.bytecode' : 'backend-bundle.js'));
          var integrityMsg = '[dokkebi] ⛔ ' + _fname + ' 무결성 검증 실패! 빌드를 다시 실행하세요.';
          _wasmLog('error', integrityMsg);
          throw new Error(integrityMsg);
        }
        var _srcLabel = _isEncTextMode ? 'backend.bundle.enc' : (_isBytecodeEnc ? 'backend.bytecode.enc' : (_isBytecodeMode ? 'backend.bytecode' : 'backend-bundle.js'));
        console.log('[dokkebi] ✅ ' + _srcLabel + ' 무결성 검증 통과' + (_cachedBundle ? ' (OPFS 캐시)' : ''));
        if (!_cachedBundle) _saveCachedBundle('__DOKKEBI_PH_BUNDLE_HASH__', _bundleRaw);
      }

      // AES-256-GCM 복호화 (암호화가 활성된 경우)
      var _bytecodeData = _bundleRaw;
      if (_isBytecodeEnc && (_isBytecodeMode || _isEncTextMode)) {
        var _bcIv = _bundleRaw.slice(0, 12);
        var _bcPayload = _bundleRaw.slice(12);

        async function _decryptBackendBundle(forceHandshake) {
          if (forceHandshake) {
            await _clearSessionOPFS();
            _forgetClientSecret('__DOKKEBI_BC_KEY__');
            console.log('[dokkebi] 🔄 복호화 키 갱신을 위해 핸드셰이크 재시도');
            await _performHandshake();
          }
          var _bcKeyHex = null;
          try {
            var _g2 = typeof window !== 'undefined' ? window : null;
            var _boot2 = _g2 && _g2.__DOKKEBI_BOOT__;
            _bcKeyHex = await _unwrapBcKeyHexFromBoot(_boot2);
            if (_bcKeyHex) {
              console.log('[dokkebi] ⚡ 번들 복호화 키: HTML 주입 (__DOKKEBI_BOOT__) — D1 핸드셰이크와 분리');
              try { delete _g2.__DOKKEBI_BOOT__; } catch (_) { try { _g2.__DOKKEBI_BOOT__ = undefined; } catch (__) {} }
            }
          } catch (_) {}
          // Step 1b 백그라운드 핸드셰이크와 번들 복호화가 동시에 돌면 이전에는 _encKey 레이스로
          // encSecrets 복호화 실패가 났다. 뮤텍스로 직렬화했어도, 여기서 BG 완료를 먼저 기다리면
          // BC_KEY 가 이미 채워진 경우 불필요한 두 번째 핸드셰이크를 피한다.
          if (!_LOCAL_DB_MODE && !forceHandshake) {
            try { await _handshakeBgP; } catch (_) { /* 실패 시 아래에서 핸드셰이크 */ }
          }
          if (!_bcKeyHex) {
            _bcKeyHex = _envSecretMap['__DOKKEBI_BC_KEY__'];
          }
          if (!_bcKeyHex) {
            console.log('[dokkebi] 🔄 복호화 키 조회를 위해 핸드셰이크 재시도');
            await _performHandshake();
            _bcKeyHex = _envSecretMap['__DOKKEBI_BC_KEY__'];
          }
          if (!_bcKeyHex) {
            var _keyErr = '[dokkebi] ⛔ 복호화 키를 찾을 수 없습니다. 서버 설정을 확인하세요.';
            _wasmLog('error', _keyErr);
            throw new Error(_keyErr);
          }
          var _bcKeyBytes = new Uint8Array(_bcKeyHex.match(/.{2}/g).map(function(b) { return parseInt(b, 16); }));
          var _aesKey = await crypto.subtle.importKey('raw', _bcKeyBytes, 'AES-GCM', false, ['decrypt']);
          _bcKeyBytes.fill(0);
          _bcKeyHex = '';
          _forgetClientSecret('__DOKKEBI_BC_KEY__');
          try {
            return await crypto.subtle.decrypt({ name: 'AES-GCM', iv: _bcIv }, _aesKey, _bcPayload);
          } finally {
            _aesKey = null;
          }
        }

        var _decrypted;
        try {
          _decrypted = await _decryptBackendBundle(false);
        } catch (_decErr) {
          // Cloudflare Pages 배포 직후에는 새 HTML/새 encrypted bundle 과
          // Worker Secret(__DOKKEBI_BC_KEY__) 전파가 몇 초 ~ 수십 초 어긋날 수 있다.
          // 이때 이전 키로 새 번들을 복호화하면 OperationError 가 발생하거나
          // 서버가 pending 응답을 보낸다. 두 경우 모두 같은 백오프
          // 스케줄(누적 ~36s)로 재시도하고, 그래도 안 풀리면 1회 reload 후
          // 60초 가드 만료 시 자동으로 다시 재시도한다.
          var _isPropPending = _decErr && _decErr.code === 'prop_pending';
          if (_isPropPending) {
            console.debug('[dokkebi] ⏳ 배포 업데이트 반영 중 — 자동 재시도');
          } else {
            console.warn('[dokkebi] ⚠ 번들 복호화 실패 — 배포 전파 안정화를 기다리며 재시도합니다.', _decErr?.name || _decErr?.message || _decErr);
          }
          var _retryDecErr = _decErr;
          // 누적 ~36.5s. 첫 재시도는 서버가 보낸 Retry-After 가 있으면 그 값 사용.
          var _retryDelays = [500, 1500, 3500, 6000, 10000, 15000];
          if (_isPropPending && Number(_decErr.retryAfterMs) > 0) {
            _retryDelays = [Number(_decErr.retryAfterMs), 1500, 3500, 6000, 10000, 15000];
          }
          await _clearSessionOPFS();
          await _clearBundleOPFS();
          for (var _ri = 0; _ri < _retryDelays.length; _ri++) {
            await new Promise(function(resolve) { setTimeout(resolve, _retryDelays[_ri]); });
            try {
              _decrypted = await _decryptBackendBundle(true);
              _retryDecErr = null;
              console.log('[dokkebi] ✅ 번들 복호화 재시도 성공 (' + (_ri + 1) + '/' + _retryDelays.length + ')');
              break;
            } catch (e) {
              _retryDecErr = e;
              if (e && e.code === 'prop_pending') {
                console.debug('[dokkebi] ⏳ 배포 업데이트 반영 대기 (' + (_ri + 1) + '/' + _retryDelays.length + ')');
              } else {
                console.warn('[dokkebi] ⚠ 번들 복호화 재시도 실패 (' + (_ri + 1) + '/' + _retryDelays.length + ')', e?.name || e?.message || e);
              }
              await _clearSessionOPFS();
            }
          }
          if (_retryDecErr) {
            // 자동 새로고침 없음 — 이미 열린 탭은 세션·WASM 으로 DB 계속 가능. 첫 로드만 실패 시 배너 Reload 유도.
            var _kindMsg = (_retryDecErr && _retryDecErr.code === 'prop_pending')
              ? '배포 전파 중입니다. 잠시 후 다시 시도하거나, 하단 «Reload»로 새로고침하세요.'
              : '새 배포가 있습니다. 하단 «Reload»로 새로고침하면 최신 번들을 받습니다. (이미 로드된 탭은 DB가 계속 동작할 수 있습니다)';
            console.warn('[dokkebi] ⏳ ' + _kindMsg, _retryDecErr?.name || _retryDecErr?.message || _retryDecErr);
            throw _retryDecErr;
          }
        }
        _bytecodeData = new Uint8Array(_decrypted);
        console.log('[dokkebi] 🔓 AES-256-GCM 복호화 완료 (' + (_bytecodeData.byteLength / 1024).toFixed(1) + ' KB)');
      }

      const capabilityGuardResult = _vm.evalCode(
        'globalThis.__dokkebi_capability_guards__ = ' + JSON.stringify(window.__DOKKEBI_CAPABILITY_GUARDS__ || { enabled: false, routes: [] }) + ';',
        'dokkebi-capability-guards.js'
      );
      if (capabilityGuardResult.error) {
        const err = _vm.dump(capabilityGuardResult.error);
        capabilityGuardResult.error.dispose();
        throw new Error('[dokkebi] Capability guard 주입 실패: ' + JSON.stringify(err));
      }
      capabilityGuardResult.value.dispose();

      // 트랙 2: 번들은 이미 복호됨 — VM 백엔드 eval 전에 D1 ECDH 세션 완료를 보장 (DB/API 사용)
      if (!_LOCAL_DB_MODE) {
        await _handshakeBgP;
      }

      var evalResult;
      if (_isEncTextMode) {
        var _decryptedText = new TextDecoder().decode(_bytecodeData);
        evalResult = _vm.evalCode(_decryptedText, 'backend-bundle.js');
        _decryptedText = '';
        console.log('[dokkebi] ✅ 암호화 텍스트 모드 백엔드 로드 완료');
      } else if (_isBytecodeMode) {
        var _bufH = _vm.newArrayBuffer(_bytecodeData.buffer || _bytecodeData);
        var _compiledH = _vm.decodeBinaryJSON(_bufH);
        _bufH.dispose();
        evalResult = _vm.callFunction(_compiledH, _vm.undefined);
        _compiledH.dispose();
        console.log('[dokkebi] ✅ 바이트코드 모드 백엔드 로드 완료');
      } else {
        evalResult = _vm.evalCode(_bundleRaw, 'backend-bundle.js');
      }
      if (evalResult.error) {
        const err = _vm.dump(evalResult.error);
        evalResult.error.dispose();
        const msg = '[dokkebi] 백엔드 초기화 실패: ' + JSON.stringify(err);
        _wasmLog('error', msg);
        throw new Error(msg);
      }
      evalResult.value.dispose();
      if (_isBytecodeEnc && _bytecodeData instanceof Uint8Array) {
        try { _bytecodeData.fill(0); } catch {}
      }

      // Step 4b: 런타임 초기화 (__dokkebi_init__ 호출 — DB 핸들 등록)
      // 이 단계가 누락되면 _db 가 null 상태로 모든 DB 쿼리가 실패합니다.
      const initFnH = _vm.getProp(_vm.global, '__dokkebi_init__');
      if (initFnH && initFnH.type !== 'undefined') {
        const handleIdH  = _vm.newNumber(DB_HANDLE);
        const dbTypeH    = _vm.newString('__DOKKEBI_PH_DB_TYPE__');
        // __dokkebi_init__ 는 동기 함수 — callFunction 이 직접 값을 반환
        const callResult = _vm.callFunction(initFnH, _vm.undefined, [handleIdH, dbTypeH]);
        handleIdH.dispose();
        dbTypeH.dispose();
        initFnH.dispose();
        if (callResult.error) {
          const err = _vm.dump(callResult.error);
          callResult.error.dispose();
          throw new Error('[dokkebi] DB 핸들 등록 실패: ' + JSON.stringify(err));
        }
        let initVal = callResult.value;
        if (_vm.typeof(initVal) === 'object') {
          _vm.runtime.executePendingJobs(-1);
          let iState = _vm.getPromiseState(initVal);
          while (iState.type === 'pending') {
            await new Promise(r => setTimeout(r, 1));
            _vm.runtime.executePendingJobs(-1);
            iState = _vm.getPromiseState(initVal);
          }
          initVal.dispose();
          if (iState.type === 'rejected') {
            const err = _vm.dump(iState.error); iState.error.dispose();
            throw new Error('[dokkebi] DB 핸들 등록 실패(async): ' + JSON.stringify(err));
          }
          iState.value?.dispose();
        } else {
          initVal.dispose();
        }
        console.log('[dokkebi] ✅ DB 핸들 등록 완료 (handle:', DB_HANDLE, ')');
      }

      // Step 5: VM에서 handle_request 함수 추출
      const _vmHandleRequest = _vm.getProp(_vm.global, '__dokkebi_handle_request__');
      if (!_vmHandleRequest || _vmHandleRequest.type === 'undefined') {
        throw new Error('__dokkebi_handle_request__ 가 VM에서 등록되지 않았습니다.');
      }

      // ── dokkebi 클라이언트 (클로저, window 비노출) ───────
      // window.dokkebi 로 전역 노출하지 않고 dokkebi:client 가상 모듈에서만
      // 일회성 Symbol handoff 로 가져갈 수 있게 합니다.
      // → 페이지 로드 후 실행되는 XSS 코드가 dokkebi 객체에 접근하기 어렵게 함.
      const _dokClient = {
        /**
         * API 요청 — 두 가지 호출 형식 지원:
         *   1. dokkebi.request('GET', '/api/products')
         *   2. dokkebi.request({ method: 'GET', path: '/api/products' })
         */
        async request(methodOrOpts, urlPath, body = null, headers = {}) {
          let _method, _path, _body, _headers;

          if (typeof methodOrOpts === 'object' && methodOrOpts !== null) {
            _method  = methodOrOpts.method;
            _path    = methodOrOpts.path || methodOrOpts.url || '/';
            _body    = methodOrOpts.body ?? null;
            _headers = methodOrOpts.headers ?? {};
          } else {
            _method  = methodOrOpts;
            _path    = urlPath;
            _body    = body;
            _headers = headers;
          }

          const req = {
            method:  _method.toUpperCase(),
            path:    _path?.split('?')[0] || '/',
            query:   _path?.includes('?') ? _path.split('?')[1] : '',
            body:    _body !== null
              ? (typeof _body === 'string' ? _body : JSON.stringify(_body))
              : '',
            headers: Object.entries({ 'Content-Type': 'application/json; charset=utf-8', ..._headers }),
          };

          _beginLogScope();
          var _parsed;
          try {
            const reqStr    = _vm.newString(JSON.stringify(req));
            const callResult = _vm.callFunction(_vmHandleRequest, _vm.undefined, [reqStr]);
            reqStr.dispose();

            if (callResult.error) {
              const errStr = _vmDumpHandle(callResult.error);
              callResult.error.dispose();
              const msg = '[dokkebi] 호출 오류: ' + errStr;
              _wasmLog('error', _method + ' ' + _path, msg);
              throw new Error(msg);
            }

            const promiseHandle = callResult.value;
            let pState = _vm.getPromiseState(promiseHandle);
            _vm.runtime.executePendingJobs(-1);
            pState = _vm.getPromiseState(promiseHandle);

            while (pState.type === 'pending') {
              await new Promise(r => setTimeout(r, 1));
              _vm.runtime.executePendingJobs(-1);
              pState = _vm.getPromiseState(promiseHandle);
            }
            promiseHandle.dispose();

            if (pState.type === 'rejected') {
              const errStr = _vmDumpHandle(pState.error);
              pState.error.dispose();
              const msg = '[dokkebi] 요청 처리 오류: ' + errStr;
              _wasmLog('error', _method + ' ' + _path, msg);
              throw new Error(msg);
            }

            const rawStr  = _vm.getString(pState.value);
            pState.value.dispose();
            _parsed  = JSON.parse(rawStr);
          } finally {
            _endLogScope();
          }
          const parsed = _parsed;

          // 오류(4xx/5xx)만 로깅 — 성공 요청은 로그 스킵
          const _status = parsed.status || (parsed.ok ? 200 : 500);
          if (_status >= 400) {
            _sendLog('warn', 'wasm', [_method + ' ' + _path, '→', _status]);
          }

          if (parsed.ok !== undefined) {
            _dokkebiRunAuthInvalidCleanup(_status, parsed);
            _dokkebiScheduleVersionProbeForPath(req.path);
            return parsed;
          }
          const jsonBody = (() => {
            try { return parsed.body ? JSON.parse(parsed.body) : null; }
            catch { return parsed.body || null; }
          })();
          _dokkebiRunAuthInvalidCleanup(parsed.status, jsonBody);
          _dokkebiScheduleVersionProbeForPath(req.path);
          return {
            ok:      parsed.status >= 200 && parsed.status < 300,
            status:  parsed.status,
            json:    jsonBody,
            error:   parsed.status >= 400
              ? (jsonBody?.error || `HTTP ${parsed.status}`)
              : null,
            headers: parsed.headers || [],
            body:    parsed.body,
          };
        },

        get:    (p, h)    => _dokClient.request('GET',    p, null, h),
        post:   (p, b, h) => _dokClient.request('POST',   p, b,    h),
        put:    (p, b, h) => _dokClient.request('PUT',    p, b,    h),
        delete: (p, h)    => _dokClient.request('DELETE', p, null, h),

        capability: {
          unlock: _proxyCapabilityUnlock,
        },

        /**
         * 대용량 파일 업로드 — QuickJS VM을 거치지 않고 OPFS에 직접 스트리밍
         * @param {File|Blob} file - 업로드할 파일
         * @param {string} [targetPath] - OPFS 내 저장 경로 (생략 시 자동 생성)
         * @returns {{ opfsRef: string, size: number }}
         */
        async upload(file, targetPath) {
          var tp = targetPath || (Date.now().toString(36) + '_' + (file.name || 'file'));
          var resolved = await _opfsResolvePath(tp, true);
          if (resolved) {
            var fh = await resolved.dir.getFileHandle(resolved.name, { create: true });
            var writable = await fh.createWritable();
            if (file.stream) {
              await file.stream().pipeTo(writable);
            } else {
              await writable.write(file);
              await writable.close();
            }
          } else {
            var buf = await file.arrayBuffer();
            _memFallback.set(tp, new Uint8Array(buf));
          }
          return { opfsRef: tp, size: file.size };
        },

        /**
         * OPFS 파일을 Blob URL로 변환 (다운로드/표시용)
         * @param {string} opfsRef - OPFS 파일 경로
         * @returns {string} blob: URL
         */
        async download(opfsRef) {
          var resolved = await _opfsResolvePath(opfsRef, false);
          if (resolved) {
            var fh = await resolved.dir.getFileHandle(resolved.name);
            var file = await fh.getFile();
            return URL.createObjectURL(file);
          }
          var data = _memFallback.get(opfsRef);
          if (!data) throw new Error('File not found: ' + opfsRef);
          return URL.createObjectURL(new Blob([data]));
        },

        /**
         * OPFS 데이터 파일/디렉토리 삭제
         */
        async removeData(opfsRef) { return hostOpfs.remove(opfsRef); },
        async removeDataDir(dirPath) { return hostOpfs.removeDir(dirPath); },

        /** OPFS 데이터 파이프라인 사용 가능 여부 */
        get opfsAvailable() { return _opfsAvailable === true; },
      };

      // ── Caller Guard wrapping ────────────────────────────────
      // _dokClient 의 외부 진입 함수들을 caller-guard 로 감싸서
      // frontend 번들 외부(콘솔/inline handler/eval/cross-origin)에서의 호출을 차단/감사.
      if (__DOKKEBI_CALLER_GUARD__.mode !== 'off') {
        var _guardMode = __DOKKEBI_CALLER_GUARD__.mode;
        var _wrapMethod = function (name) {
          var orig = _dokClient[name];
          if (typeof orig !== 'function') return;
          _dokClient[name] = function () {
            if (!__DOKKEBI_CALLER_GUARD__.isInternal(_dokClient[name])) {
              __DOKKEBI_CALLER_GUARD__.audit('caller-mismatch', {
                api: name,
                path: arguments[0] && (arguments[0].path || arguments[0].url) || (typeof arguments[1] === 'string' ? arguments[1] : ''),
              });
              if (_guardMode === 'block') {
                return Promise.reject(new Error('[dokkebi] 허용되지 않은 호출 출처 (caller guard)'));
              }
            }
            return orig.apply(this, arguments);
          };
        };
        ['request', 'get', 'post', 'put', 'delete', 'upload', 'download', 'removeData', 'removeDataDir'].forEach(_wrapMethod);
        if (_dokClient.capability && typeof _dokClient.capability.unlock === 'function') {
          var _origUnlock = _dokClient.capability.unlock;
          _dokClient.capability.unlock = function () {
            if (!__DOKKEBI_CALLER_GUARD__.isInternal(_dokClient.capability.unlock)) {
              __DOKKEBI_CALLER_GUARD__.audit('caller-mismatch', { api: 'capability.unlock', path: arguments[0] || '' });
              if (_guardMode === 'block') {
                return Promise.reject(new Error('[dokkebi] 허용되지 않은 호출 출처 (caller guard)'));
              }
            }
            return _origUnlock.apply(this, arguments);
          };
        }
        console.log('[dokkebi] caller guard 활성:', _guardMode);
      }

      // ── 일회성 handoff: dokkebi:client 가상 모듈이 첫 import 시 소비 ──
      // frontend 번들이 dokkebi:client 를 import 하면 그 모듈이 _HANDOFF 를 호출하고
      // 즉시 window 에서 제거합니다. 페이지 로드 후 실행되는 XSS 는 접근 불가.
      try {
        var _HANDOFF = Symbol.for('dokkebi.client.handoff');
        var _handoffConsumed = false;
        Object.defineProperty(window, _HANDOFF, {
          value: function () {
            if (_handoffConsumed) {
              throw new Error('[dokkebi] client handoff already consumed');
            }
            _handoffConsumed = true;
            return _dokClient;
          },
          configurable: true,
          enumerable: false,
          writable: false,
        });
      } catch (_handoffErr) {
        console.warn('[dokkebi] client handoff 설치 실패:', _handoffErr && _handoffErr.message);
      }

      console.log('[dokkebi] ✅ QuickJS WASM 백엔드 초기화 완료 (DB Handle:', DB_HANDLE, _LOCAL_DB_MODE ? ', 📦 로컬 DB' : '', ')');
      _resolveReady(_dokClient);
    } catch (e) {
      const errMsg = e instanceof Error ? e.message + (e.stack ? '\n' + e.stack : '') : String(e);
      const userMsg = '빌드에 문제가 있거나 네트워크 속도가 불안정 합니다.';
      console.error('[dokkebi] ❌ ' + userMsg, '\n상세 오류:', errMsg);
      _sendLog('error', 'bootstrap', [userMsg, errMsg]);

      // ── 상단 에러 배너 (DOM) ──────────────────────────────
      (function _showErrBanner() {
        try {
          if (document.getElementById('_dokkebi_err_banner')) return;
          var _eb = document.createElement('div');
          _eb.id = '_dokkebi_err_banner';
          _eb.setAttribute('style',
            'position:fixed;top:0;left:0;right:0;z-index:2147483647;' +
            'background:#1a0505;border-bottom:2px solid #ef4444;' +
            'padding:12px 20px;display:flex;align-items:center;gap:12px;' +
            'font-family:system-ui,-apple-system,sans-serif;font-size:13px;' +
            'line-height:1.5;color:#fca5a5;box-shadow:0 2px 16px rgba(0,0,0,.5);'
          );
          var _firstLine = (errMsg || '').split('\n')[0].slice(0, 200);
          var _icon = document.createElement('span');
          _icon.textContent = '\u26a0\ufe0f';
          _icon.setAttribute('style', 'font-size:1.4rem;flex-shrink:0;line-height:1');
          var _bd = document.createElement('div');
          _bd.setAttribute('style', 'flex:1;min-width:0');
          var _tt = document.createElement('b');
          _tt.setAttribute('style', 'color:#f87171;display:block;margin-bottom:3px;font-size:13px');
          _tt.textContent = '[dokkebi] ' + userMsg;
          var _dt = document.createElement('span');
          _dt.setAttribute('style', 'color:#fca5a5;opacity:.75;font-size:11px;word-break:break-all;display:block');
          _dt.textContent = _firstLine;
          _bd.appendChild(_tt);
          _bd.appendChild(_dt);
          var _cl = document.createElement('button');
          _cl.setAttribute('style',
            'background:none;border:none;color:#f87171;cursor:pointer;' +
            'font-size:1.2rem;line-height:1;padding:4px 6px;flex-shrink:0;opacity:.8'
          );
          _cl.title = '\ub2eb\uae30';
          _cl.textContent = '\u2715';
          _cl.onclick = function() {
            var _b = document.getElementById('_dokkebi_err_banner');
            if (_b) _b.remove();
          };
          _eb.appendChild(_icon);
          _eb.appendChild(_bd);
          _eb.appendChild(_cl);
          var _root = document.body || document.documentElement;
          if (_root && _root.prepend) _root.prepend(_eb);
        } catch (_be) { /* DOM 배너 실패 무시 */ }
      })();

      _rejectReady(new Error(userMsg + ' (' + errMsg + ')'));
    }
  })();

  // ── fetch 인터셉터 (/api/* → dokkebi.request로 자동 라우팅) ─
  //
  // 동작 규칙:
  //   1) 내부 dokkebi API (/_dokkebi/*) 는 항상 그대로 네트워크로 보낸다.
  //   2) 사용자 /api/* 요청은 먼저 WASM 백엔드 라우터로 보낸다.
  //   3) WASM 백엔드가 "라우트 없음(X-Dokkebi-Route: miss)" 을 돌려주면
  //      Cloudflare Pages Functions 등 외부 엔드포인트로 폴스루한다.
  //   4) body 가 JSON 이 아닐 수도 있으므로(FormData, text 등) 안전하게 파싱한다.
  const _origFetch = window.fetch.bind(window);
  window.fetch = async function(input, init = {}) {
    const url = typeof input === 'string' ? input : (input?.url || '');
    if (url.includes('/_dokkebi/')) return _origFetch(input, init);
    if (url.startsWith('/api/') || url.startsWith('./api/')) {
      // Caller Guard: window.fetch('/api/...') 호출 출처도 검증
      if (__DOKKEBI_CALLER_GUARD__.mode !== 'off' &&
          !__DOKKEBI_CALLER_GUARD__.isInternal(window.fetch)) {
        __DOKKEBI_CALLER_GUARD__.audit('caller-mismatch', { api: 'fetch', path: url });
        if (__DOKKEBI_CALLER_GUARD__.mode === 'block') {
          return new Response(JSON.stringify({ error: 'caller guard: 허용되지 않은 호출 출처' }), {
            status: 403, headers: { 'Content-Type': 'application/json; charset=utf-8' },
          });
        }
      }
      // window.dokkebiReady 는 _dokClient 로 resolve 됩니다 (window.dokkebi 가 사라진 후의 호환 진입점).
      const _client = await window.dokkebiReady;
      const method  = init.method || 'GET';
      let reqBody = null;
      if (init.body != null) {
        if (typeof init.body === 'string') {
          try { reqBody = JSON.parse(init.body); } catch { reqBody = init.body; }
        } else {
          reqBody = init.body;
        }
      }
      const reqHeaders = init.headers ? Object.fromEntries(Object.entries(init.headers)) : {};
      const res = await _client.request(method, url, reqBody, reqHeaders);

      // 라우트 매칭 실패 마커 감지 → 네트워크 폴스루
      const routeMiss = (res.headers || []).some(
        (h) => Array.isArray(h) && String(h[0]).toLowerCase() === 'x-dokkebi-route' && String(h[1]).toLowerCase() === 'miss'
      );
      if (routeMiss) {
        var _fall = await _origFetch(input, init);
        _dokkebiScheduleVersionProbeForPath(_dokkebiPathFromFetchUrl(url));
        return _fall;
      }

      _dokkebiScheduleVersionProbeForPath(_dokkebiPathFromFetchUrl(url));
      return new Response(
        res.body || JSON.stringify(res.json),
        {
          status:  res.status || 200,
          headers: Object.fromEntries(res.headers || [['Content-Type', 'application/json; charset=utf-8']]),
        }
      );
    }
    return _origFetch(input, init);
  };

  // ── Caller Guard: XMLHttpRequest / sendBeacon / EventSource 차단 ────────
  // fetch 인터셉터만으론 XHR/Beacon/EventSource 우회 (DevTools 콘솔, XSS payload)
  // 를 막을 수 없으므로 동일한 caller-check 를 적용한다.
  //
  // 검사 대상은 same-origin 의 /api/* (도깨비 내부 /_dokkebi/* 제외).
  // 그 외 (외부 origin / 정적 자산 / 사용자 자체 endpoint 가 /api/* 가 아닌 경우)
  // 는 그대로 통과시켜 정상 동작을 유지한다.
  if (__DOKKEBI_CALLER_GUARD__.mode !== 'off') {
    var _shouldGuardPath = function (urlStr) {
      var u = String(urlStr || '');
      if (!u) return false;
      if (u.indexOf('/_dokkebi/') >= 0) return false;
      return u.indexOf('/api/') === 0 || u.indexOf('./api/') === 0;
    };

    // 1) XMLHttpRequest
    try {
      if (typeof XMLHttpRequest !== 'undefined') {
        var _XHR_open = XMLHttpRequest.prototype.open;
        var _XHR_send = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.open = function (method, url) {
          try { this.__dokkebi_url__ = url; this.__dokkebi_method__ = method; } catch (_) {}
          return _XHR_open.apply(this, arguments);
        };
        XMLHttpRequest.prototype.send = function (body) {
          var u = '';
          try { u = String(this.__dokkebi_url__ || ''); } catch (_) {}
          if (_shouldGuardPath(u)
              && !__DOKKEBI_CALLER_GUARD__.isInternal(XMLHttpRequest.prototype.send)) {
            __DOKKEBI_CALLER_GUARD__.audit('caller-mismatch', { api: 'xhr', path: u });
            if (__DOKKEBI_CALLER_GUARD__.mode === 'block') {
              throw new Error('[dokkebi] 허용되지 않은 호출 출처 (caller guard, XHR)');
            }
          }
          return _XHR_send.apply(this, arguments);
        };
      }
    } catch (_xhrErr) {
      console.warn('[dokkebi] XHR 인터셉터 설치 실패:', _xhrErr && _xhrErr.message);
    }

    // 2) navigator.sendBeacon
    try {
      if (typeof navigator !== 'undefined' && typeof navigator.sendBeacon === 'function') {
        var _origBeacon = navigator.sendBeacon.bind(navigator);
        navigator.sendBeacon = function (url, data) {
          var u = String(url || '');
          if (_shouldGuardPath(u)
              && !__DOKKEBI_CALLER_GUARD__.isInternal(navigator.sendBeacon)) {
            __DOKKEBI_CALLER_GUARD__.audit('caller-mismatch', { api: 'sendBeacon', path: u });
            if (__DOKKEBI_CALLER_GUARD__.mode === 'block') return false;
          }
          return _origBeacon(url, data);
        };
      }
    } catch (_beaconErr) {
      console.warn('[dokkebi] sendBeacon 인터셉터 설치 실패:', _beaconErr && _beaconErr.message);
    }

    // 3) EventSource (Server-Sent Events) — Proxy 로 생성자 인터셉트
    try {
      if (typeof EventSource !== 'undefined' && typeof Proxy !== 'undefined') {
        var _OrigES = EventSource;
        window.EventSource = new Proxy(_OrigES, {
          construct: function (target, args) {
            var u = String((args && args[0]) || '');
            if (_shouldGuardPath(u)
                && !__DOKKEBI_CALLER_GUARD__.isInternal(window.EventSource)) {
              __DOKKEBI_CALLER_GUARD__.audit('caller-mismatch', { api: 'EventSource', path: u });
              if (__DOKKEBI_CALLER_GUARD__.mode === 'block') {
                throw new Error('[dokkebi] 허용되지 않은 호출 출처 (caller guard, EventSource)');
              }
            }
            return Reflect.construct(target, args, target);
          },
        });
      }
    } catch (_esErr) {
      console.warn('[dokkebi] EventSource 인터셉터 설치 실패:', _esErr && _esErr.message);
    }

    // 4) WebSocket — 보통 사용자가 직접 쓰지만, /api/ws 류 경로만 검사 (audit 만)
    //    same-origin 이면서 path 가 /api/ 로 시작할 때만. 외부 WS endpoint 는 무관.
    try {
      if (typeof WebSocket !== 'undefined' && typeof Proxy !== 'undefined') {
        var _OrigWS = WebSocket;
        window.WebSocket = new Proxy(_OrigWS, {
          construct: function (target, args) {
            var raw = String((args && args[0]) || '');
            var pathPart = raw;
            try {
              var wsUrl = new URL(raw, location.href);
              if (wsUrl.origin === location.origin.replace(/^http/, 'ws')
                  || wsUrl.host === location.host) {
                pathPart = wsUrl.pathname;
              } else {
                pathPart = ''; // cross-origin WS 는 검사하지 않음
              }
            } catch (_) {}
            if (_shouldGuardPath(pathPart)
                && !__DOKKEBI_CALLER_GUARD__.isInternal(window.WebSocket)) {
              __DOKKEBI_CALLER_GUARD__.audit('caller-mismatch', { api: 'WebSocket', path: raw });
              if (__DOKKEBI_CALLER_GUARD__.mode === 'block') {
                throw new Error('[dokkebi] 허용되지 않은 호출 출처 (caller guard, WebSocket)');
              }
            }
            return Reflect.construct(target, args, target);
          },
        });
      }
    } catch (_wsErr) {
      console.warn('[dokkebi] WebSocket 인터셉터 설치 실패:', _wsErr && _wsErr.message);
    }
  }

  // ── Caller Guard: MutationObserver — 외부 script 동적 주입 차단 ──
  // XSS 가 새로운 script 태그(외부 src 또는 inline body)를 DOM 에 끼워넣는
  // 시도를 즉시 제거하고 감사 로그를 남긴다.
  // (HTML 파서가 inline 부트스트랩을 조기 종료하지 않도록 이 주석에는
  //  실제 script-종료 태그 문자열을 적지 않습니다.)
  if (__DOKKEBI_CALLER_GUARD__.mode !== 'off') {
    try {
      // 페이지 로드 시점의 <script src> 들 + 빌드 시 박힌 allowedScripts
      // + dokkebi 내부 자산( /dokkebi/*, /_dokkebi/* )을 모두 정당 화이트리스트로 인정.
      var _initialSet = new Set();
      var _initScripts = document.querySelectorAll('script');
      for (var _si = 0; _si < _initScripts.length; _si++) {
        var _ss = _initScripts[_si];
        if (_ss && _ss.src) {
          try { _initialSet.add(new URL(_ss.src).pathname); } catch (_) { /* noop */ }
        }
      }
      // build 시 captured allowlist (caller guard 와 동일 셋)
      try {
        var _alw = "__DOKKEBI_PH_ALLOWED_SCRIPTS__";
        if (Array.isArray(_alw)) {
          for (var _ai = 0; _ai < _alw.length; _ai++) {
            var _ap = String(_alw[_ai] || '');
            if (_ap) _initialSet.add(_ap.startsWith('/') ? _ap : '/' + _ap);
          }
        }
      } catch (_) { /* noop */ }
      function _isDokkebiInternalPath(p) {
        return typeof p === 'string'
          && (p.indexOf('/dokkebi/') === 0
              || p.indexOf('/_dokkebi/') === 0
              || /\/dokkebi-qjs(\.|-)/.test(p));
      }
      // 사용자 측 브라우저 확장(Wappalyzer, React/Vue DevTools, Grammarly, 1Password, uBlock …)
      // 은 보통 chrome-extension://, moz-extension://, safari-web-extension:// 등의
      // 비-http 스킴으로 script 를 주입한다. 보안 위협이 아니라 사용자 환경 도구이고,
      // 'block' 모드에서 강제 제거하면 사용자 환경이 깨지므로 무시한다.
      function _isBrowserExtensionUrl(protocol) {
        return protocol === 'chrome-extension:'
          || protocol === 'moz-extension:'
          || protocol === 'safari-web-extension:'
          || protocol === 'safari-extension:'
          || protocol === 'webkit-masked-url:'
          || protocol === 'edge-extension:';
      }
      var _mo = new MutationObserver(function (records) {
        for (var i = 0; i < records.length; i++) {
          var nodes = records[i].addedNodes;
          for (var j = 0; j < nodes.length; j++) {
            var n = nodes[j];
            if (!n || n.nodeType !== 1 || String(n.tagName).toLowerCase() !== 'script') continue;
            var src = n.src || '';
            var ok = false;
            if (src) {
              try {
                var u = new URL(src);
                if (_isBrowserExtensionUrl(u.protocol)) {
                  ok = true; // 브라우저 확장 자산은 사용자 환경 → 무시
                } else if (u.origin === location.origin) {
                  if (_initialSet.has(u.pathname) || _isDokkebiInternalPath(u.pathname)) {
                    ok = true;
                  }
                }
              } catch (_) { /* noop */ }
            }
            if (!ok) {
              __DOKKEBI_CALLER_GUARD__.audit('script-injected', {
                src: src || '(inline)',
                snippet: !src && n.textContent ? String(n.textContent).slice(0, 200) : '',
              });
              if (__DOKKEBI_CALLER_GUARD__.mode === 'block') {
                try { n.remove(); } catch (_) { /* noop */ }
              }
            }
          }
        }
      });
      _mo.observe(document.documentElement || document, { childList: true, subtree: true });
    } catch (_moErr) {
      console.warn('[dokkebi] MutationObserver 설치 실패:', _moErr && _moErr.message);
    }
  }

  console.log('[dokkebi] 부트스트랩 로드 (DB Handle:', DB_HANDLE, _LOCAL_DB_MODE ? '/ 로컬 DB' : '', ')— QuickJS VM 초기화 중...');

  // ── 빌드 버전 체크 (이벤트 + API/DB 왕복 — 폴링 없음) ───
  // 탭 복귀·포커스 / Same-Origin /api/*·/api/_dokkebi/db 응답 후 build-version.json 비교 → 배너
  (function dokkebiVersionCheck() {
    let _lastCheck = 0;
    let _updateShown = false;
    const _MIN_GAP = 30000;

    async function _check() {
      const now = Date.now();
      if (now - _lastCheck < _MIN_GAP) return;
      _lastCheck = now;
      try {
        const r = await _origFetch('/build-version.json', { cache: 'no-store' });
        if (!r.ok) return;
        const d = await r.json();
        if (!d.v) return;
        const cur = document.querySelector('meta[name="dokkebi-build-ver"]');
        const curVer = cur ? cur.content : (window.__DOKKEBI_BUILD_VER__ || '');
        if (!curVer || d.v === curVer) return;
        if (!_updateShown) {
          _updateShown = true;
          _showBanner();
        }
      } catch {}
    }

    function _showBanner() {
      if (document.getElementById('dokkebi-update-banner')) return;
      const w = document.createElement('div');
      w.id = 'dokkebi-update-banner';
      w.style.cssText = 'position:fixed;bottom:5.5rem;left:0;right:0;z-index:99999;display:flex;justify-content:center;pointer-events:none;';
      const b = document.createElement('div');
      b.style.cssText = 'background:#1e293b;color:#fff;border-radius:12px;padding:0.75rem 1.25rem;display:flex;align-items:center;justify-content:center;gap:0.75rem;box-shadow:0 8px 32px rgba(0,0,0,0.4);border:1px solid rgba(99,102,241,0.4);pointer-events:auto;animation:dokSlideUp .3s ease-out;';
      b.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>'
        + '<span style="font-size:0.88rem">A new version is available — you can keep using this tab; reload when convenient</span>';
      const btn = document.createElement('button');
      btn.textContent = 'Reload';
      btn.style.cssText = 'padding:0.35rem 0.9rem;border-radius:8px;background:linear-gradient(135deg,#6366f1,#7c3aed);color:#fff;border:none;cursor:pointer;font-weight:700;font-size:0.82rem;';
      btn.onclick = function() { sessionStorage.setItem('dokkebi_just_updated','1'); window.location.reload(); };
      const x = document.createElement('button');
      x.innerHTML = '✕';
      x.style.cssText = 'background:none;border:none;color:rgba(255,255,255,0.5);cursor:pointer;padding:0;font-size:0.8rem;';
      x.onclick = function() { w.remove(); };
      b.appendChild(btn);
      b.appendChild(x);
      w.appendChild(b);
      document.body.appendChild(w);
      if (!document.getElementById('dokkebi-update-style')) {
        const s = document.createElement('style');
        s.id = 'dokkebi-update-style';
        s.textContent = '@keyframes dokSlideUp{from{transform:translateY(80px);opacity:0}to{transform:translateY(0);opacity:1}}';
        document.head.appendChild(s);
      }
    }

    // 업데이트 완료 토스트
    if (sessionStorage.getItem('dokkebi_just_updated') === '1') {
      sessionStorage.removeItem('dokkebi_just_updated');
      requestAnimationFrame(function() {
        const w = document.createElement('div');
        w.style.cssText = 'position:fixed;bottom:5.5rem;left:0;right:0;z-index:99999;display:flex;justify-content:center;pointer-events:none;';
        const t = document.createElement('div');
        t.style.cssText = 'background:#0f172a;color:#fff;border-radius:12px;padding:0.7rem 1.25rem;display:flex;align-items:center;justify-content:center;gap:0.6rem;box-shadow:0 8px 32px rgba(0,0,0,0.35);border:1px solid rgba(99,102,241,0.35);pointer-events:auto;animation:dokSlideUp .3s ease-out;';
        t.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
          + '<span style="font-size:0.88rem;font-weight:500">You\'re on the latest version.</span>';
        w.appendChild(t);
        document.body.appendChild(w);
        setTimeout(function() { w.remove(); }, 4000);
      });
    }

    document.addEventListener('visibilitychange', function() { if (document.visibilityState === 'visible') _check(); });
    window.addEventListener('focus', _check);
    window.__dokkebi_checkVersion = _check;
  })();

})();
</script>