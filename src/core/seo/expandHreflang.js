/**
 * Dokkebi SEO — i18n :lang 세그먼트 확장 + hreflang alternates (PR2)
 *
 * enumerate 단계에서 슬러그 등 데이터 컬럼은 모두 치환됐지만 :lang 같은
 * 정적 i18n 세그먼트는 남아있을 수 있다. 이 모듈은:
 *   1) item.path 에 남은 :lang 을 frontend i18n locale 마다 한 번씩 치환
 *   2) 같은 데이터 row 에서 파생된 모든 lang variant 를 서로의 hreflang
 *      alternate 로 묶는다 (검색엔진이 lang 별 동일 콘텐츠를 인식)
 *   3) :lang 외에 남은 :param 이 또 있으면 skip (지원 불가)
 *
 * 라우트의 `:lang` 위치가 어디든 (path 앞쪽 또는 안쪽) 동일하게 동작.
 *
 * 입력 locales 가 비어있으면 원본 그대로 통과 (i18n 미사용 프로젝트).
 */

const LANG_PARAM_NAMES = new Set(['lang', 'locale', 'language']);

/**
 * @param {Array<object>} items - enumerate 결과 (paramRemaining 포함)
 * @param {object} opts
 * @param {Array<string>} opts.locales - ['ko','en',...]
 * @param {boolean} opts.enabled - hreflang alternates 추가 여부
 * @returns {{ items: Array<object>, skipped: Array<{path, reason}> }}
 */
export function expandHreflangForItems(items, opts) {
    const locales = Array.isArray(opts?.locales) ? opts.locales.filter(Boolean) : [];
    const enableAlts = opts?.enabled !== false;
    const out = [];
    const skipped = [];

    for (const item of items) {
        const remaining = Array.isArray(item.paramRemaining) ? item.paramRemaining : [];
        // :param 이 없으면 그대로 통과
        if (remaining.length === 0) { out.push(item); continue; }

        // :lang 또는 :locale 만 남았는지 확인
        const langParams = remaining.filter(p => LANG_PARAM_NAMES.has(p.replace(/^:/, '').toLowerCase()));
        const otherParams = remaining.filter(p => !LANG_PARAM_NAMES.has(p.replace(/^:/, '').toLowerCase()));

        if (otherParams.length > 0) {
            // :lang 외에 다른 :param 도 남았다 → enumerate 가 처리 못한 영역
            skipped.push({ path: item.path, reason: `unresolved-params:${otherParams.join(',')}` });
            continue;
        }

        if (langParams.length === 0) {
            // 도달 불가
            out.push(item);
            continue;
        }

        if (locales.length === 0) {
            // 프로젝트가 i18n locale 을 노출하지 않음 → :lang 채울 후보 없음
            skipped.push({ path: item.path, reason: 'no-locales-detected' });
            continue;
        }

        // langParams 에 들어있는 모든 패턴을 locales 곱집합으로 펼친다.
        // (대부분 단일 :lang 한 개. 안전하게 다중 처리.)
        const variants = [];
        const expandOne = (currentPath, idx) => {
            if (idx >= langParams.length) { variants.push(currentPath); return; }
            for (const lang of locales) {
                const next = currentPath.replace(new RegExp(langParams[idx] + '\\b'), lang);
                expandOne(next, idx + 1);
            }
        };
        expandOne(item.path, 0);

        // alternates 묶기 — 같은 데이터 row 에서 파생된 lang 별 path
        const alternates = enableAlts && langParams.length === 1
            ? locales.map(lang => ({ lang, path: item.path.replace(new RegExp(langParams[0] + '\\b'), lang) }))
            : null;

        for (const v of variants) {
            // 어떤 lang 으로 펼친 결과인지 추출
            let detectedLang = null;
            if (langParams.length === 1) {
                for (const lang of locales) {
                    if (v.includes('/' + lang + '/') || v.endsWith('/' + lang) || v === '/' + lang) {
                        detectedLang = lang; break;
                    }
                }
            }
            out.push({
                ...item,
                path: v,
                paramRemaining: [],
                lang: detectedLang,
                alternates: alternates ? alternates.slice() : null,
            });
        }
    }
    return { items: out, skipped };
}
