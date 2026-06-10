# Refactoring — Template Extraction (in progress)

`core/projectGenerator.js` (7257 lines) 와 `core/opaqueHandle.js` (3136 lines) 같은 거대 파일은
실제로는 **함수가 큰 게 아니라 다른 파일의 소스 텍스트를 큰 template literal 로 들고 있는 컨테이너**다.
이를 외부 `.tpl` 파일로 추출하면:

- 파일 줄 수가 5–10배 줄어든다
- IDE/lint/formatter 가 제대로 동작한다 (현재는 string 안이라 안 됨)
- Phase B (예: `env.DB` → 다중 바인딩 변환) 같은 후속 작업이 **진짜 코드 편집**이 된다

## 추출 절차 (검증된 방식)

1. 원본 함수의 `return \`...\`` 블록을 **시작·끝 줄로 정확히** 잡는다.
2. 외부 보간(`${var}`)이 있다면 **placeholder 식별자**로 대체해 eval (`__DOKKEBI_PLACEHOLDER_<NAME>__`).
3. 평가 결과를 `templates/<group>/<name>.<ext>.tpl` 로 저장한다.
4. 원본 함수를 `renderTemplate()` 호출로 교체한다.
5. **여러 입력값 케이스로 동등성 검증** — 변경 전 출력과 byte 단위 동일해야 한다.

## 진행 상황

| 함수 | 원본 줄수 | .tpl 파일 | 검증 | 비고 |
|---|---|---|---|---|
| `workerHandshake()` | ~248 | `templates/worker/handshake.ts.tpl` | ✅ byte-equal | 외부 보간 0개 |
| `workerAdmin()` | ~795 | `templates/worker/admin.ts.tpl` | ✅ 4 cases byte-equal | placeholder 3개 (summary, project, panelGuard) |
| `generateBootstrapScript()` (`opaqueHandle.js`) | ~2960 | `templates/bootstrap.js.tpl` | ✅ 5 cases byte-equal | placeholder 17개 (string + ternary). `opaqueHandle.js` 3136→197 줄 |
| `generateAdminHtml()` (`adminPanel.js`) | ~420 | `templates/adminPanel.html.tpl` | ✅ 3 cases byte-equal | placeholder 2개 (projectName, mode). `adminPanel.js` 864→448 줄 |
| `workerDb()` | ~2326 | `templates/worker/db.ts.tpl` | ✅ 5 cases byte-equal | placeholder 9개 (replay/buildMeta/capability/adl/allowlist/registry/policy/authz/d1Query). `projectGenerator.js` 6244→3929 줄 |
| `workerAdminApi()` | ~757 | `templates/worker/admin-api.ts.tpl` | ✅ 5 cases byte-equal | placeholder 3개 (summary/panelGuard/project). `projectGenerator.js` 3929→3178 줄 |
| `reactApp()` | ~289 | `templates/frontend/react-app.tsx.tpl` | ✅ E2E generateProject byte-equal | 외부 보간 0개 (정적 SFC) |
| `vueApp()` | ~535 | `templates/frontend/vue-app.vue.tpl` | ✅ E2E generateProject byte-equal | 외부 보간 0개 (정적 SFC) |
| **R-7 정적 템플릿 16개 일괄** | ~777 합계 | `templates/{project,backend,worker,frontend}/...` | ✅ 12 E2E byte-equal | `dokkebiTypeDeclarations`, `witFile`, `modelsIndex`, `productController`, `orderController`, `workerLog`, `workerMiddleware`, `workerLemonSqueezyWebhookTemplate`, `viteConfigReact/Vue`, `reactMain/Login/Dashboard`, `vueMain/Login/Dashboard`. 모두 외부 보간 0개. `projectGenerator.js` 2353→1575 줄 |
| inline `ADMIN_HTML` (admin.ts.tpl 안) | ~430 | (미수행) | — | 다음 PR |

### R-7 에서 발견한 dead code (별도 정리 권장)

`buildFileTree` 가 호출하지 않지만 export 도 안 된 함수: `reactLogin`, `reactDashboard`, `vueLogin`, `vueDashboard`. 본문은 추출되어 `templates/frontend/{react,vue}/{Login,Dashboard}.{tsx,vue}.tpl` 에 보존됨. 안전하게 제거 가능하나 사용자가 향후 멀티페이지 확장에 쓸 가능성이 있어 함수 시그니처는 그대로 둠.

## 새 모듈

- `src/core/templateLoader.js` — `renderTemplate(relPath, replacements[])`
  - `find: string | RegExp` + `replace: string` 기반 안전 치환
  - 패턴 미매칭 시 throw (template 정합성 보장)
- `src/templates/worker/*.ts.tpl` — 추출된 TypeScript 템플릿. 표준 `.ts` 문법이라 IDE 가 lint/format 가능

## 동등성 검증 방법 (PR 머지 기준)

```js
import crypto from 'crypto';
import { workerHandshake, workerAdmin } from './src/core/projectGenerator.js';

// 변경 전: 각 호출 결과 sha256 을 미리 기록 (예: handshake → baaab5846ff5)
// 변경 후: 같은 호출이 같은 sha 를 반환해야 머지
```

다음 함수 추출 시에도 동일 절차로 **변경 전/후 sha 비교 → 동일 시 머지**.

## 다음 단계 (R-2, R-3 + workerDb)

순서 권장:

1. **R-2 (`opaqueHandle.js`)** — 외부 보간 적고 위험 가장 낮음. ~3000줄 → ~50줄.
2. **R-3 (`adminPanel.js` HTML)** — 비슷한 패턴, 효과 중간.
3. **`workerDb` + `ADMIN_HTML` + `workerAdminApi`** — 외부 보간 다수 + Phase B 와 직접 연관 → Phase B 시작 시점에 함께.
4. **`commands/build.js` 의 `runBuild` 단계 분해** — 텍스트 추출이 아닌 **함수 분해** 라 별도 위험 평가 필요.

## 회귀 테스트 (각 PR 머지 전)

```bash
# 1. node 로 generateProject 직접 호출해 임시 디렉터리 생성
node -e "
import('./src/core/projectGenerator.js').then(({ generateProject }) =>
  generateProject({ name: 'test', targetDir: '/tmp/dok-test', frontend: 'react', database: 'd1', withAuth: true, proxyMode: 'serverless' })
);
"

# 2. 변경 전/후 dist 비교
diff -r /tmp/dok-test-before /tmp/dok-test-after  # → 빈 출력이어야 함
```

## 안전장치

- `renderTemplate()` 는 패턴 미매칭 시 **즉시 throw** — 변수 이름이 바뀌어도 빌드가 조용히 깨지지 않음.
- 모든 `.tpl` 파일은 표준 TypeScript 로 작성되어 `tsc --noEmit` 에서 syntax error 가 검출된다.
- Placeholder 토큰(`__DOKKEBI_PLACEHOLDER_*__`)은 식별자 형태라 IDE 가 unresolved symbol 로 잡아준다.
