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
        UPDATE: new RegExp('\\bUPDATE\\s+' + ident),
        DELETE: new RegExp('\\bFROM\\s+' + ident),
    };
    const p = patterns[String(op || '').toUpperCase()];
    if (!p) return null;
    const m = String(outerUpper || '').match(p);
    if (!m) return null;
    const parts = m[1].split('.');
    return parts[parts.length - 1];
}
