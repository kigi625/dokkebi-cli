/**
 * dokkebi Plugin: AI (Anthropic API) — ⚠ OPTIONAL EXAMPLE PLUGIN
 *
 * 이 플러그인은 dokkebi 코어의 기본 기능이 아니며,
 * 사용자가 `dokkebi.config.js` 에서 명시적으로 추가할 때만 번들에 포함됩니다.
 *
 * ─────────────────────────────────────────────────────────────
 * ⚠ 중요한 보안 경고
 * ─────────────────────────────────────────────────────────────
 *
 * 이 플러그인은 **브라우저에서 직접 Anthropic API를 호출**합니다.
 * 그 결과:
 *
 *   1) `ANTHROPIC_API_KEY` 는 Host JS 클로저에 존재하지만,
 *      브라우저 네트워크 탭/DevTools에서 `x-api-key` 요청 헤더로
 *      **반드시 관찰 가능**합니다. 즉 이는 진정한 "Zero Key in Browser"가 아닙니다.
 *
 *   2) XSS 취약점이 발생한 경우 공격자는 `fetch('https://api.anthropic.com/...')`
 *      를 직접 호출하거나 네트워크 요청을 스니핑하여 키를 탈취할 수 있습니다.
 *
 *   3) 이 플러그인은 다음 경우에만 사용하세요:
 *        a) 개인/내부 프로젝트 — 키 유출이 허용 가능한 경우
 *        b) 단기/로테이션 가능한 프로젝트별 API 키
 *        c) 데모 또는 오프라인 도구
 *
 *   4) 프로덕션에서는 반드시 Cloudflare Pages Function(또는 동등한 서버리스 엔드포인트)을
 *      통해 키를 보관하고, 클라이언트는 해당 엔드포인트를 호출하도록 설계하세요.
 *      → examples/safe-ai-proxy 디렉토리 참조
 *
 * ─────────────────────────────────────────────────────────────
 * 구현 방어층:
 *   - 분당 Rate limit (config.rateLimit, 기본 30)
 *   - 호출당 max_tokens 한도 (config.maxTokens, 기본 16384)
 *   - localStorage 폴백 제거 — 키는 서버에서 주입된 env secret에서만 로드
 * ─────────────────────────────────────────────────────────────
 */

export default function pluginAi(config = {}) {
    const maxRequestsPerMin = config.rateLimit || 30;
    const maxTokensPerCall = config.maxTokens || 16384;

    return {
        name: 'ai',
        permissions: ['ai-complete', 'ai-stream'],

        validate(cfg) {
            return null;
        },

        /**
         * Host-side 구현 (브라우저 부트스트랩에 주입)
         *
         * 키 로드 정책(개정):
         *   - `_envSecretMap['ANTHROPIC_API_KEY']` 에서만 읽는다 (서버 전달분)
         *   - `localStorage` 폴백 **제거** (XSS 키 유출 차단)
         *   - 키가 없으면 명시적으로 실패 — 프록시 서버 사용을 권고하는 에러 메시지 반환
         */
        hostCode(cfg) {
            return `
  const _pluginAi = (function() {
    const _AI_RATE_LIMIT = ${maxRequestsPerMin};
    const _AI_MAX_TOKENS = ${maxTokensPerCall};
    let _aiReqCount = 0;
    let _aiRateWindow = Date.now();
    const _activeStreams = new Map();
    let _streamSeq = 0;

    // 최초 호출 시 1회 경고 출력 — 개발자가 보안 함의를 인지하도록
    var _aiKeyWarned = false;

    function _getAiApiKey() {
      // localStorage 폴백 제거: 브라우저에 저장된 키는 XSS에 취약하므로 원천 차단
      var k = (typeof _envSecretMap !== 'undefined' && _envSecretMap)
        ? (_envSecretMap['ANTHROPIC_API_KEY'] || '')
        : '';
      if (!k) {
        throw new Error(
          '[plugin:ai] ANTHROPIC_API_KEY 가 설정되지 않았습니다. ' +
          '.env 에 ANTHROPIC_API_KEY 를 추가하거나, ' +
          '프로덕션에서는 Pages Function 등 서버 측 프록시를 사용하세요.'
        );
      }
      if (!_aiKeyWarned) {
        _aiKeyWarned = true;
        try {
          console.warn(
            '[plugin:ai] ⚠ 브라우저에서 직접 Anthropic API를 호출합니다. ' +
            'x-api-key 는 네트워크 탭에서 관찰 가능하며 XSS 시 유출될 수 있습니다. ' +
            '프로덕션에서는 서버 프록시 사용을 권장합니다.'
          );
        } catch { /* ignore */ }
      }
      return k;
    }

    function _checkRateLimit() {
      var now = Date.now();
      if (now - _aiRateWindow > 60000) { _aiReqCount = 0; _aiRateWindow = now; }
      if (++_aiReqCount > _AI_RATE_LIMIT) throw new Error('[plugin:ai] Rate limit: ' + _AI_RATE_LIMIT + '/분 초과');
    }

    return {
      async aiComplete(model, system, messages, maxTokens, temperature) {
        _checkRateLimit();
        var apiKey = _getAiApiKey();
        var effectiveMaxTokens = Math.min(maxTokens || 4096, _AI_MAX_TOKENS);
        var msgArr = typeof messages === 'string' ? JSON.parse(messages) : messages;

        var resp = await _fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
            'anthropic-dangerous-direct-browser-access': 'true',
          },
          body: JSON.stringify({
            model: model || 'claude-sonnet-4-20250514',
            max_tokens: effectiveMaxTokens,
            temperature: temperature ?? 0.7,
            system: system || '',
            messages: msgArr.map(function(m) { return { role: m.role, content: m.content }; }),
          }),
        });

        if (!resp.ok) {
          var errText = await resp.text().catch(function() { return ''; });
          throw new Error('[plugin:ai] API error ' + resp.status + ': ' + errText.slice(0, 200));
        }

        var data = await resp.json();
        var text = '';
        if (data.content) {
          for (var i = 0; i < data.content.length; i++) {
            if (data.content[i].type === 'text') text += data.content[i].text;
          }
        }

        return {
          content: text,
          inputTokens: data.usage?.input_tokens || 0,
          outputTokens: data.usage?.output_tokens || 0,
          stopReason: data.stop_reason || 'end_turn',
        };
      },

      aiStreamStart(model, system, messages, maxTokens, temperature, thinkingBudget) {
        _checkRateLimit();
        var apiKey = _getAiApiKey();
        var effectiveMaxTokens = Math.min(maxTokens || 4096, _AI_MAX_TOKENS);
        var streamId = 'stream_' + (++_streamSeq) + '_' + Date.now().toString(36);
        var msgArr = typeof messages === 'string' ? JSON.parse(messages) : messages;

        // Extended thinking requires temperature=1
        var effectiveTemp = (thinkingBudget && thinkingBudget > 0) ? 1 : (temperature ?? 0.7);

        var bodyObj = {
          model: model || 'claude-sonnet-4-20250514',
          max_tokens: effectiveMaxTokens,
          temperature: effectiveTemp,
          system: system || '',
          messages: msgArr.map(function(m) { return { role: m.role, content: m.content }; }),
          stream: true,
        };

        if (thinkingBudget && thinkingBudget > 0) {
          bodyObj.thinking = { type: 'enabled', budget_tokens: thinkingBudget };
        }

        var ctrl = new AbortController();
        var queue = [];
        var done = false;

        _fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
            'anthropic-dangerous-direct-browser-access': 'true',
          },
          body: JSON.stringify(bodyObj),
          signal: ctrl.signal,
        }).then(function(resp) {
          if (!resp.ok) {
            resp.text().then(function(t) {
              queue.push({ eventType: 'error', text: 'API ' + resp.status + ': ' + t.slice(0, 200) });
              done = true;
            });
            return;
          }
          var reader = resp.body.getReader();
          var decoder = new TextDecoder();
          var buffer = '';

          function pump() {
            reader.read().then(function(result) {
              if (result.done) { done = true; return; }
              buffer += decoder.decode(result.value, { stream: true });
              var lines = buffer.split('\\n');
              buffer = lines.pop() || '';
              for (var i = 0; i < lines.length; i++) {
                var line = lines[i].trim();
                if (line.startsWith('data: ')) {
                  try {
                    var evt = JSON.parse(line.slice(6));
                    if (evt.type === 'content_block_delta') {
                      if (evt.delta?.type === 'text_delta') {
                        queue.push({ eventType: 'text', text: evt.delta.text });
                      } else if (evt.delta?.type === 'thinking_delta') {
                        queue.push({ eventType: 'thinking', thinking: evt.delta.thinking });
                      }
                    } else if (evt.type === 'message_start') {
                      queue.push({ eventType: 'start', inputTokens: evt.message?.usage?.input_tokens || 0 });
                    } else if (evt.type === 'message_delta') {
                      queue.push({
                        eventType: 'delta',
                        outputTokens: evt.usage?.output_tokens || 0,
                        stopReason: evt.delta?.stop_reason || '',
                      });
                    } else if (evt.type === 'message_stop') {
                      queue.push({ eventType: 'stop' });
                      done = true;
                    }
                  } catch(e) { /* SSE parse error */ }
                }
              }
              if (!done) pump();
            }).catch(function(e) {
              if (e.name !== 'AbortError') queue.push({ eventType: 'error', text: e.message });
              done = true;
            });
          }
          pump();
        }).catch(function(e) {
          if (e.name !== 'AbortError') queue.push({ eventType: 'error', text: e.message });
          done = true;
        });

        _activeStreams.set(streamId, { queue: queue, done: function() { return done; }, abort: ctrl });
        return streamId;
      },

      aiStreamPoll(streamId) {
        var s = _activeStreams.get(streamId);
        if (!s) throw new Error('[plugin:ai] Unknown stream: ' + streamId);
        var events = s.queue.splice(0);
        if (s.done() && s.queue.length === 0) _activeStreams.delete(streamId);
        return events;
      },

      aiStreamCancel(streamId) {
        var s = _activeStreams.get(streamId);
        if (s) { s.abort.abort(); _activeStreams.delete(streamId); }
      },
    };
  })();
`;
        },

        /**
         * QuickJS VM ↔ Host 브릿지 코드
         */
        vmBridge() {
            return `
      var vmPluginAi = _vm.newObject();

      _vm.setProp(vmPluginAi, 'aiComplete', _vm.newFunction('aiComplete',
        function(modelH, systemH, msgsH, maxTokH, tempH) {
          var model = _vm.getString(modelH);
          var system = _vm.getString(systemH);
          var msgs = _vm.dump(msgsH);
          var maxTok = _vm.getNumber(maxTokH);
          var temp = _vm.getNumber(tempH);
          var deferred = _vm.newPromise();
          _pluginAi.aiComplete(model, system, msgs, maxTok, temp)
            .then(function(r) { _settleDeferred(deferred, _vm.newString(JSON.stringify(r)), false, 'ai.complete'); })
            .catch(function(e) { _settleDeferred(deferred, _vm.newString(String(e)), true, 'ai.complete'); });
          return deferred.handle.dup();
        }
      ));

      _vm.setProp(vmPluginAi, 'aiStreamStart', _vm.newFunction('aiStreamStart',
        function(modelH, systemH, msgsH, maxTokH, tempH, budgetH) {
          var model = _vm.getString(modelH);
          var system = _vm.getString(systemH);
          var msgs = _vm.dump(msgsH);
          var maxTok = _vm.getNumber(maxTokH);
          var temp = _vm.getNumber(tempH);
          var budget = _vm.getNumber(budgetH);
          try {
            var id = _pluginAi.aiStreamStart(model, system, msgs, maxTok, temp, budget);
            return _vm.newString(JSON.stringify({ ok: true, value: id }));
          } catch(e) {
            return _vm.newString(JSON.stringify({ ok: false, error: String(e) }));
          }
        }
      ));

      _vm.setProp(vmPluginAi, 'aiStreamPoll', _vm.newFunction('aiStreamPoll',
        function(idH) {
          var id = _vm.getString(idH);
          try {
            var events = _pluginAi.aiStreamPoll(id);
            return _vm.newString(JSON.stringify({ ok: true, value: events }));
          } catch(e) {
            return _vm.newString(JSON.stringify({ ok: false, error: String(e) }));
          }
        }
      ));

      _vm.setProp(vmPluginAi, 'aiStreamCancel', _vm.newFunction('aiStreamCancel',
        function(idH) {
          _pluginAi.aiStreamCancel(_vm.getString(idH));
          return _vm.undefined;
        }
      ));

      _vm.setProp(hostModule, 'ai', vmPluginAi);
`;
        },

        /**
         * Guest (dokkebi-runtime) 측 API
         */
        guestApi() {
            return `
export const ai = {
  async complete(opts) {
    var host = getHost();
    if (!host.ai) throw new Error('[dokkebi:ai] ai 플러그인이 활성화되지 않았습니다.');
    var raw = await host.ai.aiComplete(
      opts.model || 'claude-sonnet-4-20250514',
      opts.system || '',
      JSON.stringify(opts.messages || []),
      opts.maxTokens || 4096,
      opts.temperature ?? 0.7
    );
    return _parseHostResult(raw);
  },

  streamStart(opts) {
    var host = getHost();
    if (!host.ai) throw new Error('[dokkebi:ai] ai 플러그인이 활성화되지 않았습니다.');
    var raw = host.ai.aiStreamStart(
      opts.model || 'claude-sonnet-4-20250514',
      opts.system || '',
      JSON.stringify(opts.messages || []),
      opts.maxTokens || 4096,
      opts.temperature ?? 0.7,
      opts.thinkingBudget || 0
    );
    var parsed = _parseHostResult(raw);
    if (!parsed.ok) throw new Error(parsed.error);
    return parsed.value;
  },

  streamPoll(streamId) {
    var host = getHost();
    if (!host.ai) throw new Error('[dokkebi:ai] ai 플러그인이 활성화되지 않았습니다.');
    var raw = host.ai.aiStreamPoll(streamId);
    var parsed = _parseHostResult(raw);
    if (!parsed.ok) throw new Error(parsed.error);
    return parsed.value;
  },

  streamCancel(streamId) {
    var host = getHost();
    if (!host.ai) return;
    host.ai.aiStreamCancel(streamId);
  },
};
`;
        },
    };
}
