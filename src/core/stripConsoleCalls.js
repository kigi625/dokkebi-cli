/**
 * 프로덕션 번들에서 지정한 console.METHOD(…) 호출을 `void 0` 로 치환.
 * 문자열/템플릿/주석/정규식 리터럴 내부의 괄호는 무시한다.
 *
 * @param {string} source
 * @param {ReadonlySet<string>|string[]} methods
 * @returns {string}
 */
export function replaceConsoleCallsWithVoid(source, methods) {
    const strip = methods instanceof Set ? methods : new Set(methods);
    if (strip.size === 0) return source;

    const n = source.length;
    let out = '';
    let i = 0;

    while (i < n) {
        const hit = source.indexOf('console.', i);
        if (hit < 0) {
            out += source.slice(i);
            break;
        }
        // 이전 글자가 식별자면 `myconsole.` 등 — 건너뜀
        if (hit > 0 && /[$\w]/.test(source[hit - 1])) {
            out += source.slice(i, hit + 8);
            i = hit + 8;
            continue;
        }

        let j = hit + 8; // after 'console.'
        let name = '';
        while (j < n && /[a-zA-Z]/.test(source[j])) {
            name += source[j];
            j++;
        }
        if (!strip.has(name)) {
            out += source.slice(i, j);
            i = j;
            continue;
        }

        let k = j;
        while (k < n && /\s/.test(source[k])) k++;
        if (k + 1 < n && source[k] === '?' && source[k + 1] === '.') {
            k += 2;
            while (k < n && /\s/.test(source[k])) k++;
        }
        if (k >= n || source[k] !== '(') {
            out += source.slice(i, j);
            i = j;
            continue;
        }

        const close = findClosingParen(source, k);
        if (close < 0) {
            out += source.slice(i, j);
            i = j;
            continue;
        }

        out += source.slice(i, hit);
        out += 'void 0';
        i = close + 1;
    }

    return out;
}

/**
 * @param {string} s
 * @param {number} openIdx — '(' 위치
 * @returns {number} 닫는 ')' 인덱스, 또는 -1
 */
function findClosingParen(s, openIdx) {
    let depth = 0;
    let i = openIdx;
    const n = s.length;
    let state = /** @type {'code'|'sq'|'dq'|'tm'|'line'|'block'|'regex'} */ ('code');
    let templateDepth = 0;

    while (i < n) {
        const c = s[i];
        const next = i + 1 < n ? s[i + 1] : '';

        if (state === 'line') {
            if (c === '\n' || c === '\r') state = 'code';
            i++;
            continue;
        }
        if (state === 'block') {
            if (c === '*' && next === '/') {
                state = 'code';
                i += 2;
                continue;
            }
            i++;
            continue;
        }
        if (state === 'sq') {
            if (c === '\\' && i + 1 < n) {
                i += 2;
                continue;
            }
            if (c === "'") state = 'code';
            i++;
            continue;
        }
        if (state === 'dq') {
            if (c === '\\' && i + 1 < n) {
                i += 2;
                continue;
            }
            if (c === '"') state = 'code';
            i++;
            continue;
        }
        if (state === 'tm') {
            if (c === '\\' && i + 1 < n) {
                i += 2;
                continue;
            }
            if (c === '`') {
                templateDepth = 0;
                state = 'code';
                i++;
                continue;
            }
            if (c === '$' && next === '{') {
                templateDepth++;
                i += 2;
                continue;
            }
            if (c === '}' && templateDepth > 0) {
                templateDepth--;
                i++;
                continue;
            }
            i++;
            continue;
        }
        if (state === 'regex') {
            if (c === '\\' && i + 1 < n) {
                i += 2;
                continue;
            }
            if (c === '/') {
                while (i + 1 < n && /[gimsuy]/.test(s[i + 1])) i++;
                state = 'code';
                i++;
                continue;
            }
            if (c === '[') {
                i++;
                while (i < n && s[i] !== ']') {
                    if (s[i] === '\\') i++;
                    i++;
                }
                i++;
                continue;
            }
            i++;
            continue;
        }

        // code
        if (c === '/' && next === '/') {
            state = 'line';
            i += 2;
            continue;
        }
        if (c === '/' && next === '*') {
            state = 'block';
            i += 2;
            continue;
        }
        if (c === "'") {
            state = 'sq';
            i++;
            continue;
        }
        if (c === '"') {
            state = 'dq';
            i++;
            continue;
        }
        if (c === '`') {
            state = 'tm';
            templateDepth = 0;
            i++;
            continue;
        }

        // regex heuristic: / after operator-start position
        if (c === '/') {
            const prev = i > 0 ? s[i - 1] : '';
            if (/[\n\r([=:;,+!*&|^%~<>?-]/.test(prev) || i === openIdx + 1) {
                state = 'regex';
                i++;
                continue;
            }
        }

        if (c === '(') depth++;
        else if (c === ')') {
            depth--;
            if (depth === 0) return i;
        }
        i++;
    }
    return -1;
}
