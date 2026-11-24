/**
 * SQL 형태(shape) 판별 공용 헬퍼
 *
 * 목적:
 *   - `WITH ... DELETE/UPDATE/INSERT` 처럼 CTE 뒤에 DML 이 오는 문장을
 *     "SELECT" 로 오판하지 않도록 **괄호 밖(depth 0)의 실제 문장 키워드**를 찾는다.
 *   - 주 연산 대상 테이블도 CTE 본문이 아니라 **바깥 문장**에서 추출한다.
 *
 * 입력은 `stripStringsAndComments()` 를 통과한 뒤 공백 정규화 + 대문자화된 문자열을
 * 가정한다. (문자열 리터럴은 `''` 로 치환되어 있음)
 */

const DML_OPS = new Set(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE']);

function _isWordChar(ch) {
    return /[A-Z0-9_]/.test(ch);
}

/**
 * 괄호 밖에서 첫 문장 키워드를 찾는다.
 *
 * @param {string} normalizedUpper
 * @returns {{ op: string|null, index: number }}
 *   op: 'SELECT'|'INSERT'|'UPDATE'|'DELETE'|'CREATE'|null, index: 키워드 시작 위치
 */
export function detectOuterOp(normalizedUpper) {
    const s = String(normalizedUpper || '');
    const n = s.length;
    let depth = 0;
    let firstWord = true;

    for (let i = 0; i < n; i++) {
        const ch = s[i];
        if (ch === '"' || ch === '`') {
            const q = ch;
            i++;
            while (i < n) {
                if (s[i] === q) {
                    if (s[i + 1] === q) { i += 2; continue; }
                    break;
                }
                i++;
            }
            continue;
        }
        if (ch === '(') { depth++; continue; }
        if (ch === ')') { if (depth > 0) depth--; continue; }
        if (depth !== 0) continue;
        if (!/[A-Z_]/.test(ch)) continue;

        let j = i;
        while (j < n && _isWordChar(s[j])) j++;
        const word = s.slice(i, j);
        const wordStart = i;
        i = j - 1;

        if (firstWord) {
            firstWord = false;
            if (word === 'WITH') continue; // CTE 헤더 — 바깥 문장 키워드를 계속 찾는다
            if (DML_OPS.has(word)) return { op: word, index: wordStart };
            if (word === 'REPLACE') return { op: 'INSERT', index: wordStart };
            // EXPLAIN/PRAGMA/VALUES 등 — 지원하지 않는 문장
            return { op: null, index: -1 };
        }

        // WITH 이후: CTE 이름/AS/MATERIALIZED 같은 토큰은 건너뛰고 바깥 DML 을 찾는다.
        if (DML_OPS.has(word)) return { op: word, index: wordStart };
        if (word === 'REPLACE') return { op: 'INSERT', index: wordStart };
    }
    return { op: null, index: -1 };
}

/**
 * 바깥 문장(DML 키워드부터 끝까지)만 잘라낸다.
 * `WITH x AS (SELECT 1) DELETE FROM posts` → `DELETE FROM POSTS`
 */
export function outerStatement(normalizedUpper) {
    const { index } = detectOuterOp(normalizedUpper);
    if (index < 0) return String(normalizedUpper || '');
    return String(normalizedUpper).slice(index);
}

/**
 * 바깥 문장에서 주 연산 대상 테이블을 추출한다.
 * (기존 detectPrimaryTable 과 동일 규칙이지만 CTE 본문을 배제)
 *
 * @param {string} outerUpper - outerStatement() 결과
 * @param {string} op
 * @returns {string|null}
 */
export function detectPrimaryTableOf(outerUpper, op) {
    const ident = '["\'`]?([A-Z_][\\w]*(?:\\.[A-Z_][\\w]*)?)["\'`]?';
    const patterns = {
        SELECT: new RegExp('\\bFROM\\s+' + ident),
        INSERT: new RegExp('\\bINTO\\s+' + ident),
        // `UPDATE OR REPLACE|ROLLBACK|ABORT|FAIL|IGNORE <table>` 의 conflict 절을 건너뛴다.
        UPDATE: new RegExp('\\bUPDATE\\s+(?:OR\\s+(?:REPLACE|ROLLBACK|ABORT|FAIL|IGNORE)\\s+)?' + ident),
        DELETE: new RegExp('\\bFROM\\s+' + ident),
    };
    const p = patterns[String(op || '').toUpperCase()];
    if (!p) return null;
    const m = String(outerUpper || '').match(p);
    if (!m) return null;
    const parts = m[1].split('.');
    return parts[parts.length - 1];
}

/**
 * SQL 이 참조하는 테이블(FROM/JOIN/INTO/UPDATE) + 별칭을 추출한다.
 *
 * 문자열/주석이 제거된 정규화 SQL 을 받는다. 다음을 모두 처리한다:
 *  - `FROM a, b` 콤마 조인 (기존 FROM/JOIN 정규식이 첫 테이블만 잡던 우회)
 *  - `"schema"."table"`, `` `table` ``, `[table]` 따옴표 식별자
 *  - 서브쿼리 내부 FROM (전체 스캔)
 *
 * @param {string} normalized - 주석/문자열 제거 + 원본 대소문자 유지
 * @returns {Array<{name: string, alias: string|null, offset: number, keyword: string}>}
 */
/**
 * 따옴표로 감싼 "문자열/비식별자" 영역을 공백으로 마스킹한다.
 *
 * SQLite 는 double-quoted 토큰이 컬럼명으로 해석되지 않으면 문자열 리터럴로
 * 취급(DQS)한다. 정책 검사가 그 내부의 `user_id = ?` 같은 텍스트를 실제
 * 조건으로 오인하지 않도록, 단순 식별자(`"user_id"`)만 남기고 나머지
 * quoted 영역은 같은 길이의 공백으로 바꾼다. (오프셋 유지)
 *
 * @param {string} text
 * @returns {string}
 */
export function maskQuotedNonIdentifiers(text) {
    const s = String(text || '');
    const n = s.length;
    let out = '';
    for (let i = 0; i < n; i++) {
        const ch = s[i];
        if (ch !== '"' && ch !== '`' && ch !== '[') { out += ch; continue; }
        const close = ch === '[' ? ']' : ch;
        let j = i + 1;
        let content = '';
        while (j < n) {
            if (s[j] === close) {
                if (ch !== '[' && s[j + 1] === close) { content += close; j += 2; continue; }
                break;
            }
            content += s[j];
            j++;
        }
        const end = Math.min(j + 1, n);
        const isIdent = /^[A-Za-z_][A-Za-z0-9_]*$/.test(content);
        out += isIdent ? s.slice(i, end) : ' '.repeat(end - i);
        i = j;
    }
    return out;
}

/**
 * 위치 기반(`?`) 이외의 파라미터 표기를 감지한다.
 *
 * SQLite 는 `?NNN`, `:name`, `@name`, `$name` 을 지원하는데, `?NNN` 의 경우
 * 정책 엔진이 `?` 개수로 파라미터 인덱스를 계산하면 실제 바인딩과 어긋난다.
 * (예: `user_id = ?2` 가 `params[1]` 을 참조) → 혼동을 원천 차단한다.
 *
 * 따옴표 문자열/식별자와 주석 내부는 제외한다.
 *
 * @param {string} sql
 * @returns {boolean}
 */
export function hasNonPositionalParameters(sql) {
    const masked = maskQuotedNonIdentifiers(String(sql || ''));
    let plain = '';
    for (let i = 0; i < masked.length; i++) {
        const ch = masked[i];
        if (ch === "'") {
            i++;
            while (i < masked.length) {
                if (masked[i] === "'" && masked[i + 1] === "'") { i += 2; continue; }
                if (masked[i] === "'") break;
                i++;
            }
            plain += ' ';
            continue;
        }
        if (ch === '-' && masked[i + 1] === '-') {
            while (i < masked.length && masked[i] !== '\n') i++;
            plain += ' ';
            continue;
        }
        if (ch === '/' && masked[i + 1] === '*') {
            i += 2;
            while (i < masked.length && !(masked[i] === '*' && masked[i + 1] === '/')) i++;
            i++;
            plain += ' ';
            continue;
        }
        plain += ch;
    }
    if (/\?\d/.test(plain)) return true;
    if (/(^|[^A-Za-z0-9_$])(?::|@|\$)[A-Za-z_][A-Za-z0-9_]*/.test(plain)) return true;
    return false;
}

export function extractTableRefs(normalized) {
    const s = String(normalized || '');
    const n = s.length;
    const out = [];
    const TABLE_KW = new Set(['FROM', 'JOIN', 'INTO', 'UPDATE']);
    const RESERVED = new Set([
        'WHERE', 'SET', 'VALUES', 'ON', 'GROUP', 'ORDER', 'LIMIT', 'HAVING',
        'UNION', 'INTERSECT', 'EXCEPT', 'RETURNING', 'WINDOW', 'INNER', 'LEFT',
        'RIGHT', 'FULL', 'CROSS', 'OUTER', 'NATURAL', 'JOIN', 'USING', 'AS',
        'AND', 'OR', 'FROM', 'INTO', 'UPDATE', 'SELECT', 'INSERT', 'DELETE',
        'INDEXED', 'NOT', 'BY', 'WITH', 'RECURSIVE',
    ]);

    function readIdent(i, limit = n) {
        if (i >= limit) return null;
        const ch = s[i];
        if (ch === '"' || ch === '`') {
            let j = i + 1;
            let value = '';
            while (j < limit) {
                if (s[j] === ch) {
                    if (s[j + 1] === ch) { value += ch; j += 2; continue; }
                    j++;
                    break;
                }
                value += s[j];
                j++;
            }
            return { value, end: j, quoted: true };
        }
        if (ch === '[') {
            let j = i + 1;
            let value = '';
            while (j < limit && s[j] !== ']') { value += s[j]; j++; }
            if (j < limit) j++;
            return { value, end: j, quoted: true };
        }
        if (!/[A-Za-z_]/.test(ch)) return null;
        let j = i;
        while (j < limit && /[A-Za-z0-9_$]/.test(s[j])) j++;
        return { value: s.slice(i, j), end: j, quoted: false };
    }

    function skipWs(i, limit = n) {
        while (i < limit && /\s/.test(s[i])) i++;
        return i;
    }

    function matchParen(i, limit = n) {
        // i 는 '(' 위치. 따옴표 식별자를 건너뛰며 짝이 맞는 ')' 위치를 찾는다.
        let depth = 0;
        for (let j = i; j < limit; j++) {
            const ch = s[j];
            if (ch === '"' || ch === '`' || ch === '[') {
                const t = readIdent(j, limit);
                j = (t ? t.end : j + 1) - 1;
                continue;
            }
            if (ch === "'") {
                let k = j + 1;
                while (k < limit) {
                    if (s[k] === "'" && s[k + 1] === "'") { k += 2; continue; }
                    if (s[k] === "'") { k++; break; }
                    k++;
                }
                j = k - 1;
                continue;
            }
            if (ch === '(') depth++;
            else if (ch === ')') {
                depth--;
                if (depth === 0) return j;
            }
        }
        return -1;
    }

    function hasQueryKeyword(text) {
        for (let i = 0; i < text.length; i++) {
            const ch = text[i];
            if (ch === '"' || ch === '`' || ch === '[') {
                const t = readIdent(i);
                i = (t ? t.end : i + 1) - 1;
                continue;
            }
            if (!/[A-Za-z_]/.test(ch)) continue;
            let j = i;
            while (j < text.length && /[A-Za-z0-9_]/.test(text[j])) j++;
            const w = text.slice(i, j).toUpperCase();
            if (w === 'SELECT' || w === 'VALUES' || w === 'WITH') return true;
            i = j - 1;
        }
        return false;
    }

    function wordAt(i, limit = n) {
        if (i < 0 || i >= limit || !/[A-Za-z_]/.test(s[i] || '')) return null;
        let j = i;
        while (j < limit && /[A-Za-z0-9_]/.test(s[j])) j++;
        return { value: s.slice(i, j), end: j };
    }

    function isWordAt(i, word, limit = n) {
        const w = wordAt(i, limit);
        return !!w && w.value.toUpperCase() === word;
    }

    // `JOIN ... ON <expr>` 의 식을 건너뛰고 top-level 콤마 또는 FROM 절 종료 지점을 반환.
    // (ON 식 안의 함수 호출/서브쿼리 콤마를 테이블 구분자로 오인하지 않도록)
    function skipJoinOn(i, limit = n) {
        const END_KW = new Set([
            'WHERE', 'GROUP', 'ORDER', 'LIMIT', 'HAVING', 'UNION', 'INTERSECT',
            'EXCEPT', 'RETURNING', 'WINDOW', 'JOIN', 'INNER', 'LEFT', 'RIGHT',
            'FULL', 'CROSS', 'NATURAL', 'OUTER', 'ON', 'USING',
        ]);
        let depth = 0;
        for (let j = i; j < limit; j++) {
            const ch = s[j];
            if (ch === '"' || ch === '`' || ch === '[') {
                const t = readIdent(j, limit);
                j = (t ? t.end : j + 1) - 1;
                continue;
            }
            if (ch === "'") {
                let k = j + 1;
                while (k < limit) {
                    if (s[k] === "'" && s[k + 1] === "'") { k += 2; continue; }
                    if (s[k] === "'") { k++; break; }
                    k++;
                }
                j = k - 1;
                continue;
            }
            if (ch === '(') { depth++; continue; }
            if (ch === ')') {
                if (depth > 0) { depth--; continue; }
                return j;
            }
            if (depth !== 0) continue;
            if (ch === ',' || ch === ';') return j;
            if (/[A-Za-z_]/.test(ch)) {
                const w = wordAt(j, limit);
                if (w && END_KW.has(w.value.toUpperCase())) return j;
                if (w) j = w.end - 1;
            }
        }
        return limit;
    }

    function readRef(i, limit = n) {
        const first = readIdent(i, limit);
        if (!first) return null;
        if (!first.quoted && RESERVED.has(first.value.toUpperCase())) return null;
        let name = first.value;
        let end = first.end;
        // schema-qualified: a.b.c (따옴표 혼용 허용)
        for (;;) {
            let k = skipWs(end, limit);
            if (s[k] !== '.') break;
            k = skipWs(k + 1, limit);
            const seg = readIdent(k, limit);
            if (!seg) break;
            name = seg.value;
            end = seg.end;
        }
        // alias: `AS x` 또는 `x` (예약어 제외)
        let alias = null;
        let k = skipWs(end, limit);
        if (/^AS\b/i.test(s.slice(k, k + 3)) && !/[A-Za-z0-9_]/.test(s[k + 2] || '')) {
            k = skipWs(k + 2, limit);
            const a = readIdent(k, limit);
            if (a) { alias = a.value; end = a.end; }
        } else {
            const a = readIdent(k, limit);
            if (a && !(!a.quoted && RESERVED.has(a.value.toUpperCase()))) {
                alias = a.value;
                end = a.end;
            }
        }
        return { name, alias, offset: i, end };
    }

    // 콤마로 나열된 테이블 참조 목록. `(table)` / `(a, b)` / `(SELECT ...)` 처리.
    function readList(start, limit = n) {
        const refs = [];
        let pos = start;
        for (;;) {
            pos = skipWs(pos, limit);
            if (pos >= limit) break;
            if (s[pos] === '(') {
                const close = matchParen(pos, limit);
                if (close < 0) break;
                const inner = s.slice(pos + 1, close);
                if (!hasQueryKeyword(inner)) {
                    const sub = readList(pos + 1, close);
                    for (const r of sub.refs) refs.push(r);
                }
                pos = close + 1;
                // `(posts) p` / `(posts) AS p` — 괄호 뒤 별칭은 건너뛴다.
                let k = skipWs(pos, limit);
                if (/^AS\b/i.test(s.slice(k, k + 3)) && !/[A-Za-z0-9_]/.test(s[k + 2] || '')) {
                    k = skipWs(k + 2, limit);
                    const a = readIdent(k, limit);
                    if (a) pos = a.end;
                } else {
                    const a = readIdent(k, limit);
                    if (a && !(!a.quoted && RESERVED.has(a.value.toUpperCase()))) pos = a.end;
                }
            } else {
                const r = readRef(pos, limit);
                if (!r) break;
                refs.push({ name: r.name, alias: r.alias, offset: r.offset });
                pos = r.end;
            }
            // JOIN 제약(INDEXED BY / NOT INDEXED / ON ... / USING (...))를 건너뛰고
            // 뒤따르는 콤마 조인을 계속 수집한다.
            //   `FROM posts INDEXED BY idx, secrets`
            //   `FROM posts JOIN users ON ..., secrets`
            //   `FROM posts JOIN users USING(id), secrets`
            for (;;) {
                const k = skipWs(pos, limit);
                if (isWordAt(k, 'INDEXED', limit)) {
                    let p = skipWs(k + 7, limit);
                    if (!isWordAt(p, 'BY', limit)) break;
                    p = skipWs(p + 2, limit);
                    const idx = readIdent(p, limit);
                    if (!idx) break;
                    pos = idx.end;
                    continue;
                }
                if (isWordAt(k, 'NOT', limit)) {
                    const p = skipWs(k + 3, limit);
                    if (!isWordAt(p, 'INDEXED', limit)) break;
                    pos = p + 7;
                    continue;
                }
                if (isWordAt(k, 'ON', limit)) {
                    pos = skipJoinOn(k + 2, limit);
                    continue;
                }
                if (isWordAt(k, 'USING', limit)) {
                    let p = skipWs(k + 5, limit);
                    if (s[p] !== '(') break;
                    const close = matchParen(p, limit);
                    if (close < 0) break;
                    pos = close + 1;
                    continue;
                }
                break;
            }
            let next = skipWs(pos, limit);
            if (next >= limit || s[next] !== ',') break;
            pos = next + 1;
        }
        return { refs, end: pos };
    }

    for (let i = 0; i < n; i++) {
        const ch = s[i];
        if (ch === '"' || ch === '`' || ch === '[') {
            const t = readIdent(i);
            i = (t ? t.end : i + 1) - 1;
            continue;
        }
        if (ch === "'") {
            let j = i + 1;
            while (j < n) {
                if (s[j] === "'" && s[j + 1] === "'") { j += 2; continue; }
                if (s[j] === "'") { j++; break; }
                j++;
            }
            i = j - 1;
            continue;
        }
        if (!/[A-Za-z_]/.test(ch)) continue;
        let j = i;
        while (j < n && /[A-Za-z0-9_]/.test(s[j])) j++;
        const kw = s.slice(i, j).toUpperCase();
        if (!TABLE_KW.has(kw)) { i = j - 1; continue; }
        let start = skipWs(j);
        // `UPDATE OR REPLACE|ROLLBACK|ABORT|FAIL|IGNORE <table>` — 충돌 절을 건너뛰고
        // 대상 테이블을 읽는다. (건너뛰지 않으면 대상 테이블이 추출되지 않아
        //  allowlist/tenant/authz 가 모두 우회된다)
        if (kw === 'UPDATE' && isWordAt(start, 'OR')) {
            const conflict = wordAt(skipWs(start + 2));
            if (conflict && ['REPLACE', 'ROLLBACK', 'ABORT', 'FAIL', 'IGNORE'].includes(conflict.value.toUpperCase())) {
                start = skipWs(conflict.end);
            }
        }
        const list = readList(start);
        if (list.refs.length === 0) { i = j - 1; continue; }
        for (const r of list.refs) {
            out.push({ name: r.name, alias: r.alias, offset: r.offset, keyword: kw });
        }
        i = j - 1;
    }
    return out;
}

/**
 * 외부 연산(op) 외에 **추가 쓰기 효과**를 일으키는 SQL 형태를 감지한다.
 * (Authorization / Allowlist 가 INSERT 하나만 보고 통과시키는 우회 방지)
 *
 * - `INSERT ... ON CONFLICT ... DO UPDATE` → UPDATE
 * - `INSERT OR REPLACE`, `REPLACE INTO`    → DELETE (충돌 행 삭제 후 삽입)
 * - `UPDATE OR REPLACE`                    → DELETE (충돌 행 삭제)
 *
 * @param {string} normalized - 주석/문자열 제거된 SQL
 * @param {string|null} op - 바깥 문장 연산
 * @returns {string[]} 추가로 요구되는 연산 목록
 */
export function detectSecondaryWriteOps(normalized, op) {
    const s = maskQuotedNonIdentifiers(String(normalized || '')).replace(/\s+/g, ' ');
    const u = s.toUpperCase();
    const out = new Set();
    if (!op) return [];
    if (op === 'INSERT') {
        if (/\bINSERT\s+OR\s+REPLACE\b/.test(u) || /\bREPLACE\s+INTO\b/.test(u)) out.add('DELETE');
        if (/\bON\s+CONFLICT\b[\s\S]*\bDO\s+UPDATE\b/.test(u)) out.add('UPDATE');
    }
    if (op === 'UPDATE' && /\bUPDATE\s+OR\s+REPLACE\b/.test(u)) out.add('DELETE');
    return [...out];
}
