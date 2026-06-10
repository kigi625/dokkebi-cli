# Dokkebi SEO — Zero-Config Auto SEO

> **목표**: 개발자가 아무 것도 안 적어도, `dok build` 만 하면 라우터 기반으로 SEO 메타·OG·sitemap·JSON-LD·robots 가 자동 생성되고, 동적 페이지(예: `/projects/:id`, `/:lang/:username/post/:slug`)는 빌드 타임 D1 enumerate + 런타임 Edge SEO Renderer 로 모두 크롤링 가능해야 한다. 사용자는 **"확인만 하면 끝"**.

---

## 0. 비-목표 (왜 SSR 안 가는지)

- WASM 백엔드(SPIN/CF Pages Function) 환경에서 React/Vue 렌더링 = 별도 Node 레이어 필요 → 도깨비 단일 배포 모델 파괴
- 검색엔진·메신저 OG 카드 요구사항은 "정확한 메타 + 크롤 가능한 정적 HTML 스냅샷" 뿐 → SSR 불필요
- A(빌드 타임 prerender) + B(Edge SEO Renderer) 조합은 SSR 의 SEO 효과를 100% 가져오면서 런타임 비용은 0 에 수렴

---

## 1. 아키텍처 개요

```
┌──────────────────────────────────────────────────────────────────┐
│                       dok build (CLI)                             │
│                                                                   │
│  ┌────────────────┐   ┌────────────────┐   ┌──────────────────┐  │
│  │ 1. 라우터 스캔 │ → │ 2. 콘텐츠 추론 │ → │ 3. D1 enumerate  │  │
│  │  (App.tsx etc) │   │ (page 컴포넌트) │   │  (동적 라우트)   │  │
│  └────────────────┘   └────────────────┘   └──────────────────┘  │
│            │                   │                    │            │
│            └───────────────────┼────────────────────┘            │
│                                ▼                                  │
│                    ┌─────────────────────┐                        │
│                    │  SEO Manifest (JSON) │                       │
│                    │  routes[].{path,     │                       │
│                    │    title, desc, og,  │                       │
│                    │    jsonLd, dynamic}  │                       │
│                    └─────────────────────┘                        │
│                                │                                  │
│         ┌──────────────────────┼─────────────────────────┐        │
│         ▼                      ▼                         ▼        │
│  ┌──────────────┐    ┌──────────────────┐    ┌─────────────────┐ │
│  │ HTML 복제·   │    │ sitemap.xml /    │    │ Edge SEO        │ │
│  │ 메타 주입    │    │ robots.txt       │    │ Renderer 함수   │ │
│  │ (정적 라우트)│    │                  │    │ 자동 생성       │ │
│  └──────────────┘    └──────────────────┘    └─────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                  dist/  (CF Pages 배포 산출물)
```

**핵심**: 사용자는 `dokkebi.config.js` 의 `seo` 블록을 **건드리지 않아도** 빌드가 라우터/페이지 컴포넌트/D1 스키마를 스캔해서 합리적 기본값을 채워넣는다. 빌드 끝에 `dist/.dokkebi/seo-manifest.json` + 사람이 읽기 쉬운 `seo-report.md` 가 출력 → 사용자는 "확인만" 한다.

---

## 2. Zero-Config 자동 추론 파이프라인

### 2.1 라우터 스캔 (`src/core/seo/scanRouter.js`)

**입력**: `frontend/src/**/*.{tsx,jsx,ts,js}`
**방법**: AST 파서 (`@babel/parser` + `@babel/traverse` — 이미 의존성에 있음).

탐지 패턴:
1. `react-router-dom` 의 `<Route path="..." element={<X/>}>` JSX
2. `createBrowserRouter([{path, element}])` 객체 리터럴
3. 라우트 path 의 동적 세그먼트 (`:id`, `:slug`, `*`)

**산출**:
```ts
type ScannedRoute = {
  path: string;                     // '/projects/:id'
  componentName: string;            // 'BlogPostPage'
  componentFile: string;            // 'src/pages/BlogPostPage.tsx'
  isDynamic: boolean;
  params: string[];                 // ['id']
  protected: boolean;               // ProtectedRoute 래핑 여부
  redirect: boolean;                // <Navigate> 만 있는지
};
```

`protected: true` 또는 `redirect: true` 인 라우트는 **자동 noindex** (로그인/관리 페이지가 검색에 노출되지 않도록).

### 2.2 페이지 컴포넌트 콘텐츠 추론 (`src/core/seo/inferPageMeta.js`)

각 라우트의 컴포넌트 파일을 AST 로 분석해서 **메타 후보**를 뽑는다. 우선순위:

1. **명시적 hint**: 컴포넌트 파일 상단의 magic comment
   ```tsx
   /** @dokkebi-seo
    *  title: 블로그 글 보기
    *  description: 도깨비 블로그의 개별 글 페이지
    *  image: /og/blog-post.png
    */
   ```
2. **`dokkebi.seo.set(...)` 호출** (런타임 SDK) — 인자가 정적 리터럴이면 빌드 타임에도 추출
3. **JSX 휴리스틱**:
   - 첫 `<h1>{...}</h1>` 의 정적 텍스트 → title 후보
   - 첫 `<p>` / `<meta name="description">` → description 후보
   - 첫 `<img src="...">` 정적 경로 → og:image 후보
4. **컴포넌트명 → 한글/영문 라벨 매핑 휴리스틱** (`BlogPostPage` → "블로그 글", `LoginPage` → "로그인", `PricingPage` → "요금제"…)
   - i18n locales (`src/i18n/locales/*.json`) 키와 fuzzy 매칭으로 더 정확하게
5. **fallback**: `seo.defaults` (config) → 프로젝트명 + 페이지경로

각 단계는 **점수**(confidence)를 매겨 manifest 에 함께 저장 → 리포트에서 "title: '블로그 글 보기' (h1 추출, 신뢰도 0.8)" 식으로 사용자가 한눈에 검토 가능.

### 2.3 D1 enumerate (`src/core/seo/enumerateDynamic.js`)

동적 라우트(`:id`, `:slug`)는 D1 스키마를 스캔해 후보 테이블을 자동 매칭:

| 라우트 패턴 | 자동 매칭 규칙 |
|---|---|
| `/projects/:id` | `projects` 또는 `*_projects` 테이블의 `id` PK |
| `/posts/:slug` | `posts` 테이블의 `slug` 컬럼 |
| `/:lang/:username/post/:slug` | `posts` + `users.username` JOIN |
| `/users/:userId` | `users.id` |

매칭 로직:
1. 라우트의 마지막 동적 세그먼트 이름(`id`, `slug`, `username`) 과 컬럼명 일치
2. 라우트 정적 prefix (`/posts/`) 와 테이블명 단수/복수 일치
3. 컬럼 후보 자동 선택:
   - **title 컬럼**: `title`, `name`, `subject`, `headline` 중 첫 매칭
   - **description**: `description`, `summary`, `excerpt`, `content` (앞 160자 strip)
   - **image**: `thumbnail`, `cover_image`, `og_image`, `image`
   - **updatedAt**: `updated_at`, `modified_at` (sitemap `<lastmod>`)
4. **공개 필터 자동 추론**: `public`, `is_published`, `status='published'` 컬럼 발견 시 자동 WHERE

**Authorization Policy 존중**: `authorization.rules['SELECT:posts']` 가 `public:true` 가 아닌 테이블은 **enumerate 스킵 + 경고** ("이 라우트는 인증 필요 테이블을 사용 → 빌드 타임 prerender 불가, Edge SEO Renderer 로만 처리").

매칭 결과가 모호하면(>1 후보 또는 0 후보) 빌드 리포트에 명시 → 사용자가 `seo.dynamic[].query` 로 1줄 오버라이드.

### 2.4 JSON-LD 자동 추론

테이블 의미에서 schema.org 타입 매핑:

| 테이블 패턴 | JSON-LD `@type` |
|---|---|
| `posts`, `articles`, `blog_*` | `BlogPosting` |
| `products`, `items` | `Product` |
| `users`, `profiles` | `Person` / `ProfilePage` |
| `events` | `Event` |
| `*_projects` (animation_projects) | `CreativeWork` |
| 그 외 | `WebPage` |

홈/카테고리는 자동 `BreadcrumbList` + `WebSite` (with `SearchAction` if `/search` 라우트 존재).

### 2.5 Hreflang 자동 (i18n 통합)

`/:lang/:username/post/:slug` 처럼 `:lang` 세그먼트가 있고 `src/i18n/locales/*.json` 이 존재하면, 동일 라우트의 다른 lang 변형을 `<link rel="alternate" hreflang="...">` 로 자동 주입.

---

## 3. 빌드 산출물

```
dist/
├── index.html                          # 정적 prerender (홈)
├── pricing/index.html                  # title=요금제, OG 주입
├── login/index.html                    # noindex (자동)
├── projects/123/index.html             # D1 enumerate prerender
├── projects/124/index.html
├── ko/alice/post/hello/index.html      # i18n + dynamic
├── en/alice/post/hello/index.html
├── sitemap.xml                         # 모든 정적 + enumerate 결과
├── robots.txt                          # noindex 라우트 자동 반영
├── _routes.json                        # CF Pages: 봇 UA 만 Edge Renderer 통과
└── .dokkebi/
    ├── seo-manifest.json               # 머신용 (재빌드 캐시)
    └── seo-report.md                   # 사람용 (사용자 확인용)
```

**`seo-report.md` 예시** (사용자가 보는 것):

```markdown
# Dokkebi SEO 빌드 리포트

빌드: 2026-05-09 21:30:14 · 라우트 18개 · prerender 2,341 페이지

## 정적 라우트 (8)

| 경로       | title (출처)                | description (출처)        | indexable |
|-----------|------------------------------|---------------------------|-----------|
| /         | 도깨비 애니메이트 (h1, 0.9) | AI 애니메이션 생성 (p, 0.7) | ✅ |
| /pricing  | 요금제 (i18n, 1.0)           | (없음 — 채우세요)            | ✅ |
| /login    | 로그인 (휴리스틱, 0.8)       | —                         | ❌ noindex |
| /manage   | (Protected → 자동 제외)     | —                         | ❌ noindex |

## 동적 라우트 (3)

### /projects/:id → animation_projects
- 매칭: id=id, title=title, desc=description, image=thumbnail
- 공개 필터: WHERE public=1 (자동 감지)
- enumerate: 142 페이지
- JSON-LD: CreativeWork

### /:lang/:username/post/:slug → posts JOIN users
- ⚠ 인증 필요 (SELECT:posts auth=true) → 빌드 prerender 스킵
- → Edge SEO Renderer 로 위임됨

## ⚠ 확인 필요 (3)

1. `/about` — title/description 추론 실패. `dokkebi.config.js` 또는 페이지 상단에 @dokkebi-seo 주석 추가 권장.
2. `/products/:sku` — 매칭 테이블 모호 (products / shop_products 둘 다 후보). seo.dynamic 으로 명시.
3. og:image 미설정 라우트 4개 — `/og-default.png` 사용 중.
```

---

## 4. config 스키마 (모두 선택, 0줄도 OK)

```js
// dokkebi.config.js
seo: {
  // 전부 생략 가능 — 자동 추론 모드
  enabled: true,                    // 기본 true
  baseUrl: 'https://ani.dokkebi.net', // 미지정 시 deploy.cloudflarePages.domain 에서 자동
  defaults: {
    siteName: 'Dokkebi Animate',    // package.json name 에서 자동
    locale: 'ko',                   // i18n 기본 locale
    image: '/og-default.png',       // public/og-default.png 자동 감지
    twitterCard: 'summary_large_image',
  },

  // 자동 추론을 끄거나 보정만 하고 싶을 때
  routes: {
    '/pricing': { description: '도깨비 요금제 — 무료부터 엔터프라이즈까지' },
    '/secret':  { noindex: true },
  },

  // 자동 D1 enumerate 가 실패한 라우트만 명시
  dynamic: [
    {
      pattern: '/products/:sku',
      table: 'shop_products',         // 또는 query: 'SELECT ...'
      // map 생략 가능 — 컬럼 자동 매칭
    },
  ],

  // 끄고 싶을 때
  prerender: { enabled: true, concurrency: 8, maxPages: 50_000 },
  sitemap:   { enabled: true, splitAt: 50_000 },
  robots:    { enabled: true },
  edgeRenderer: { enabled: true, cacheTtlSec: 300 },
  jsonLd:    { enabled: true },
  hreflang:  { enabled: true },

  // 추론 신뢰도 임계값 — 이하인 라우트는 리포트에 ⚠ 표시
  inferenceMinConfidence: 0.5,
},
```

---

## 5. Edge SEO Renderer (CF Pages Function)

자동 생성 위치: `worker/_seo-renderer.ts` (도깨비가 emit, gitignore 권장)

`dist/_routes.json`:
```json
{
  "version": 1,
  "include": ["/*"],
  "exclude": ["/assets/*", "/api/*"]
}
```

함수 흐름:
```ts
export const onRequest: PagesFunction = async ({ request, env, next }) => {
  const ua = request.headers.get('user-agent') || '';
  if (!isCrawler(ua)) return next();          // 사람 → 정적 SPA

  const url = new URL(request.url);
  const cacheKey = `seo:${url.pathname}`;
  const cached = await env.SEO_CACHE.get(cacheKey);
  if (cached) return new Response(cached, { headers: { 'content-type': 'text/html' } });

  // 1) manifest 에서 라우트 매칭
  const meta = await resolveMeta(url.pathname, env);  // D1 조회 (런타임 동적)
  // 2) index.html 템플릿에 주입
  const html = injectMeta(await env.ASSETS.fetch(new URL('/index.html', url)).then(r=>r.text()), meta);
  await env.SEO_CACHE.put(cacheKey, html, { expirationTtl: 300 });
  return new Response(html, { headers: { 'content-type': 'text/html' } });
};
```

봇 판정 화이트리스트 (CLI 내장, 업데이트 가능):
- Googlebot, bingbot, Yeti(NAVER), Daumoa(Daum), Baiduspider, YandexBot, DuckDuckBot
- Twitterbot, facebookexternalhit, LinkedInBot, Slackbot, Discordbot, KakaoTalk-scrap, TelegramBot
- Applebot, ChatGPT-User, GPTBot, ClaudeBot, PerplexityBot

봇이지만 prerender 가 이미 dist 에 있는 경로는 정적 파일이 우선이므로 함수 자체가 호출되지 않음 → 동적/long-tail 만 함수가 처리.

`?_dokkebi_seo=1` 쿼리로 사람도 강제 SEO HTML 보기 (디버깅).

---

## 6. 클라이언트 SDK (런타임 보조)

`packages/dokkebi-runtime/src/seo.ts`:

```ts
export const seo = {
  set({ title, description, image, jsonLd }) {
    if (title) document.title = title;
    upsertMeta('description', description);
    upsertMeta('og:title', title, 'property');
    upsertMeta('og:description', description, 'property');
    upsertMeta('og:image', image, 'property');
    if (jsonLd) upsertJsonLd(jsonLd);
  },
};
```

라우터 전환 시 사용자 직접 호출 또는 자동 훅:
```tsx
// dokkebi 가 vite-plugin 으로 자동 주입 가능
useDokkebiSeo();   // 현재 path 의 manifest meta 자동 반영
```

이건 사람 UX 보조 (브라우저 탭 제목, 공유 시 재계산) — SEO 본질은 정적 HTML + Edge Renderer 가 담당.

---

## 7. CLI 변경 포인트

| 작업 | 위치 | 신규/수정 |
|---|---|---|
| config 스키마 + 검증 | `src/core/dokkebiConfigLoad.js` | 수정 |
| 라우터 스캔 | `src/core/seo/scanRouter.js` | **신규** |
| 페이지 메타 추론 | `src/core/seo/inferPageMeta.js` | **신규** |
| D1 enumerate | `src/core/seo/enumerateDynamic.js` | **신규** (`d1Integration.js` 재사용) |
| HTML 메타 주입 + prerender | `src/core/seo/emitPrerender.js` | **신규** |
| sitemap/robots | `src/core/seo/emitSitemap.js` | **신규** |
| Edge Renderer emit | `src/core/seo/emitEdgeRenderer.js` | **신규** |
| 빌드 파이프라인 hook | `src/commands/build.js` (`runFrontendBuild` 직후) | 수정 |
| 리포트 출력 | `src/core/seo/emitReport.js` | **신규** |
| init 템플릿 (주석/og-default.png) | `src/core/projectGenerator.js` | 수정 |
| 런타임 SDK | `packages/dokkebi-runtime/src/seo.ts` | **신규** |
| Vite 플러그인 자동 훅 | `packages/dokkebi-vite-plugin/src/index.js` | 수정 |
| i18n 로케일 | `src/i18n/locales/*.json` (seo.* 키) | 수정 |
| 디자인 문서 | `docs/design/SEO.md` (이 문서) | **신규** |

---

## 8. 빌드 파이프라인 통합 (commands/build.js)

```
dok build
  ├─ 1. config load
  ├─ 2. wasm/backend bundle  (기존)
  ├─ 3. runFrontendBuild      (기존, vite build)
  ├─ 4. [신규] SEO pipeline
  │     ├─ scanRouter()              → routes[]
  │     ├─ inferPageMeta(routes)     → meta 후보
  │     ├─ enumerateDynamic(routes)  → D1 prerender 대상
  │     ├─ emitPrerender()           → dist/<route>/index.html * N
  │     ├─ emitSitemap()             → dist/sitemap.xml
  │     ├─ emitRobots()              → dist/robots.txt
  │     ├─ emitEdgeRenderer()        → worker/_seo-renderer.ts + _routes.json
  │     ├─ writeManifest()           → dist/.dokkebi/seo-manifest.json
  │     └─ emitReport()              → dist/.dokkebi/seo-report.md (콘솔에도 요약)
  └─ 5. deploy (선택)
```

증분 빌드: D1 데이터 변경 분만 재 prerender (manifest 의 `updatedAt` diff). 50,000 페이지 미만은 풀 빌드도 수 초.

---

## 9. 보안·성능 고려

- **Authorization Policy 위반 방지**: enumerate 단계에서 `SELECT:<table>` 규칙이 `auth:true` 면 prerender 스킵, 리포트에 경고 (실수로 비공개 글 sitemap 노출 차단).
- **Tenant Policy**: 빌드 타임 enumerate 는 시스템 컨텍스트 → `tenant.mode='enforce'` 테이블은 `--seo-enumerate-bypass-tenant` 플래그가 있어야 통과. 기본은 차단.
- **prerender 페이지 최대치**: `seo.prerender.maxPages` (기본 50,000). 초과 시 long-tail 은 Edge Renderer 로 자동 위임.
- **KV 캐시**: Edge Renderer 는 5분 TTL (config). 콘텐츠 변경은 백엔드 mutation 시 `dokkebi.seo.invalidate(path)` 로 즉시 무효화.
- **로그**: Edge Renderer 호출량/캐시 히트율은 도깨비 logging 파이프라인으로 자동 수집.

---

## 10. 마이그레이션·하위호환

- 기존 프로젝트는 `dok build` 가 자동으로 SEO 산출물 생성 (opt-out: `seo.enabled:false`).
- 기존 `index.html` 의 사용자 정의 `<meta>` 는 보존 (도깨비 주입 메타에 `data-dokkebi-seo` 속성 부여 후 재빌드 시 같은 속성만 교체).
- v6 부터 default ON, v5 에서는 `seo.enabled:true` 로 opt-in.

---