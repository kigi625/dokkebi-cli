/**
 * SQL 바인딩 파라미터 정규화 — 값의 타입을 보존하여 SQL NULL / 숫자 / 문자열 / Date 를 올바르게 전달.
 * 기존 `String(value)` 방식은 null→'null', undefined→'undefined' 문자열로 변환해
 * SQLite WHERE ... IS NULL 비교 등이 깨지는 심각한 버그를 유발했음.
 */
function normalizeBind(value) {
    if (value === null || value === undefined) return null;
    if (value instanceof Date) return value.toISOString();
    if (typeof value === 'boolean') return value ? 1 : 0;
    if (typeof value === 'number' || typeof value === 'bigint') return value;
    if (typeof value === 'string') return value;
    // object / array 등은 JSON 직렬화 — 기존 동작과 호환
    try { return JSON.stringify(value); } catch { return String(value); }
}

// UUID v4 생성 — 브라우저(crypto.randomUUID) / QuickJS(Math.random 폴백) 모두 지원
function _uuid() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    // QuickJS 폴백 (crypto.randomUUID 없는 환경)
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
}

/**
 * dokkebi Type-safe Query DSL
 *
 * Drizzle ORM 스타일의 쿼리 빌더입니다.
 * QuickJS WASM 내에서 실행되며, 실제 DB 호출은
 * WIT 인터페이스를 통해 Host(브라우저)에 위임합니다.
 *
 * 사용 예:
 *   const users = table('users', {
 *     id:    col('id',    t.uuid().primaryKey()),
 *     name:  col('name',  t.text().notNull()),
 *     email: col('email', t.text().unique()),
 *   });
 *
 *   const result = await db
 *     .select(users, ['id', 'name'])
 *     .where(eq(users.email, 'test@test.com'))
 *     .limit(1)
 *     .exec();
 */

// ─────────────────────────────────────────────────────────────
// 타입 빌더 (t.xxx())
// ─────────────────────────────────────────────────────────────

class ColumnType {
    constructor(sqlType) {
        this._sqlType = sqlType;
        this._nullable = true;
        this._isPk = false;
        this._isUnique = false;
        this._default = undefined;
        this._references = null;
    }

    notNull() {
        this._nullable = false;
        return this;
    }

    primaryKey() {
        this._isPk = true;
        this._nullable = false;
        return this;
    }

    unique() {
        this._isUnique = true;
        return this;
    }

    default(value) {
        this._default = value;
        return this;
    }

    references(tableName, columnName = 'id') {
        this._references = { table: tableName, column: columnName };
        return this;
    }

    /** SQL 타입 정의 문자열 생성 */
    toSqlDef() {
        let def = this._sqlType;
        if (!this._nullable) def += ' NOT NULL';
        if (this._isPk) def += ' PRIMARY KEY';
        if (this._isUnique) def += ' UNIQUE';
        if (this._default !== undefined) {
            if (this._default === 'random') {
                // UUID 기본값 (SQLite의 경우 트리거 또는 앱에서 생성)
                def += ` DEFAULT (lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))),2) || '-' || substr('89ab',abs(random()) % 4 + 1, 1) || substr(lower(hex(randomblob(2))),2) || '-' || lower(hex(randomblob(6))))`;
            } else if (this._default === 'now') {
                def += ` DEFAULT CURRENT_TIMESTAMP`;
            } else if (typeof this._default === 'string') {
                def += ` DEFAULT '${this._default}'`;
            } else {
                def += ` DEFAULT ${this._default}`;
            }
        }
        return def;
    }
}

/** 타입 팩토리 */
export const t = {
    text:      () => new ColumnType('TEXT'),
    integer:   () => new ColumnType('INTEGER'),
    real:      () => new ColumnType('REAL'),
    blob:      () => new ColumnType('BLOB'),
    boolean:   () => new ColumnType('INTEGER'),  // SQLite: 0/1
    uuid:      () => new ColumnType('TEXT'),
    timestamp: () => new ColumnType('TEXT'),
    json:      () => new ColumnType('TEXT'),
    /** 열거형 (SQLite는 CHECK 제약으로 구현) */
    enum(values) {
        const type = new ColumnType('TEXT');
        type._enumValues = values;
        return type;
    },
    /** 자동 증가 정수 (SQLite AUTOINCREMENT) */
    serial() {
        const type = new ColumnType('INTEGER');
        type._isPk = true;
        type._serial = true;
        return type;
    },
};

// ─────────────────────────────────────────────────────────────
// 컬럼 + 테이블 정의
// ─────────────────────────────────────────────────────────────

/**
 * 컬럼 정의 헬퍼
 * @param {string} name       - DB 컬럼명
 * @param {ColumnType} type   - t.xxx() 타입
 */
export function col(name, type) {
    return { _colName: name, _type: type };
}

/**
 * 테이블 정의
 * @param {string} tableName  - DB 테이블명
 * @param {object} columns    - { fieldName: col(...) } 맵
 * @param {object} [options]  - 보안 메타데이터 (선택)
 * @param {object} [options.tenant]  - 테넌트 격리 설정
 *   - string: tenant 컬럼명 (e.g. 'user_id')
 *   - { column: string, claim?: string, mode?: 'enforce' | 'none' }: 상세 설정
 * @param {object} [options.access] - 연산별 권한 설정 (정적 메타 — dok build 가 읽음)
 *   - { read?: spec, write?: spec, delete?: spec, all?: spec }
 *   - spec: { public: true } | { auth: true } | { roles: string[] } | { deny: true }
 *
 * 사용 예:
 *   const premiumContents = table('premium_contents', {
 *     id:      col('id', t.uuid().primaryKey()),
 *     content: col('content', t.text()),
 *     userId:  col('user_id', t.text()),
 *   }, {
 *     tenant: 'user_id',
 *     access: {
 *       read:  { roles: ['premium', 'admin'] },
 *       write: { roles: ['admin'] },
 *     },
 *   });
 *
 * 위 메타데이터는 `dok build` 가 정적 추출해 Tenant Policy + Authorization
 * Policy 의 입력으로 사용합니다. dokkebi.config.js 의 명시값이 항상 우선.
 */
export function table(tableName, columns, options) {
    const meta = {
        _tableName: tableName,
        _columns: columns,
        // 보안 메타 (옵션) — 런타임에는 사용되지 않으며, dok build 의 정적
        // 추출용. SQL 실행에는 영향 없음 (사용자 코드 호환성 보존).
        _tenant: options && options.tenant ? options.tenant : null,
        _access: options && options.access ? options.access : null,
    };
    const proxy = new Proxy(
        meta,
        {
            get(target, prop) {
                if (prop in target) return target[prop];
                if (prop in columns) {
                    // users.name → 컬럼 참조 객체 반환 (where 절 등에 사용)
                    return { _ref: true, _table: tableName, _col: columns[prop]._colName };
                }
                return undefined;
            },
        }
    );
    return proxy;
}

// ─────────────────────────────────────────────────────────────
// SQL 표현식 빌더 (where 절용)
// ─────────────────────────────────────────────────────────────

/** col = value */
export function eq(colRef, value) {
    return { op: '=', col: colRef._col, value, table: colRef._table };
}

/** col != value */
export function neq(colRef, value) {
    return { op: '!=', col: colRef._col, value, table: colRef._table };
}

/** col > value */
export function gt(colRef, value) {
    return { op: '>', col: colRef._col, value, table: colRef._table };
}

/** col >= value */
export function gte(colRef, value) {
    return { op: '>=', col: colRef._col, value, table: colRef._table };
}

/** col < value */
export function lt(colRef, value) {
    return { op: '<', col: colRef._col, value, table: colRef._table };
}

/** col <= value */
export function lte(colRef, value) {
    return { op: '<=', col: colRef._col, value, table: colRef._table };
}

/** col LIKE pattern */
export function like(colRef, pattern) {
    return { op: 'LIKE', col: colRef._col, value: pattern, table: colRef._table };
}

/** col IS NULL */
export function isNull(colRef) {
    return { op: 'IS NULL', col: colRef._col, value: null, table: colRef._table };
}

/** col IS NOT NULL */
export function isNotNull(colRef) {
    return { op: 'IS NOT NULL', col: colRef._col, value: null, table: colRef._table };
}

/** col IN (values) */
export function inList(colRef, values) {
    return { op: 'IN', col: colRef._col, value: values, table: colRef._table };
}

/** cond1 AND cond2 */
export function and(...conditions) {
    return { op: 'AND', conditions };
}

/** cond1 OR cond2 */
export function or(...conditions) {
    return { op: 'OR', conditions };
}

// ─────────────────────────────────────────────────────────────
// SQL 생성기
// ─────────────────────────────────────────────────────────────

/**
 * 조건식을 SQL WHERE 절 문자열로 변환
 * @param {object} cond - eq/neq/gt/and/or 등
 * @param {Array}  params - 파라미터 수집 배열 (변이)
 * @returns {string} SQL 조각
 */
function condToSql(cond, params) {
    if (cond.op === 'AND') {
        return cond.conditions
            .map((c) => {
                const inner = condToSql(c, params);
                return c.op === 'OR' || c.op === 'AND' ? `(${inner})` : inner;
            })
            .join(' AND ');
    }
    if (cond.op === 'OR') {
        return cond.conditions
            .map((c) => {
                const inner = condToSql(c, params);
                return c.op === 'OR' || c.op === 'AND' ? `(${inner})` : inner;
            })
            .join(' OR ');
    }
    if (cond.op === 'IS NULL' || cond.op === 'IS NOT NULL') {
        return `"${cond.col}" ${cond.op}`;
    }
    if (cond.op === 'IN') {
        const values = Array.isArray(cond.value) ? cond.value : [];
        if (values.length === 0) {
            // IN () 은 SQL 문법 오류. 항상 거짓인 조건으로 대체.
            return '1 = 0';
        }
        const placeholders = [];
        for (const v of values) {
            params.push(normalizeBind(v));
            placeholders.push('?');
        }
        return `"${cond.col}" IN (${placeholders.join(', ')})`;
    }
    params.push(normalizeBind(cond.value));
    return `"${cond.col}" ${cond.op} ?`;
}

// ─────────────────────────────────────────────────────────────
// 쿼리 빌더
// ─────────────────────────────────────────────────────────────

class QueryBuilder {
    constructor(runtime) {
        this._runtime = runtime; // dokkebi-runtime 주입
        this._type = null;
        this._table = null;
        this._columns = null;
        this._where = null;
        this._orderBy = [];
        this._limit = null;
        this._offset = null;
        this._values = null;
        this._returning = false;
    }

    // ── SELECT ───────────────────────────────────────────────

    select(tableDef, columns = null) {
        this._type = 'SELECT';
        this._table = tableDef._tableName;
        this._columns = columns
            ? columns.map((c) =>
                  // JS 프로퍼티명(camelCase) → 실제 컬럼명(snake_case) 자동 매핑
                  typeof c === 'string'
                      ? (tableDef._columns[c]?._colName ?? c)
                      : tableDef._columns[c]._colName
              )
            : Object.values(tableDef._columns).map((c) => c._colName);
        // exec() 시 row 의 snake_case 컬럼을 camelCase JS 키로 역변환하기 위한 사전.
        // tableDef._columns 는 { camelKey: { _colName: 'snake_name', ... } } 형태.
        this._colNameToJsKey = Object.create(null);
        for (const [jsKey, def] of Object.entries(tableDef._columns)) {
            const dbName = def._colName;
            if (dbName && dbName !== jsKey) this._colNameToJsKey[dbName] = jsKey;
        }
        return this;
    }

    where(condition) {
        this._where = condition;
        return this;
    }

    orderBy(colRef, dir = 'asc') {
        this._orderBy.push({
            col: typeof colRef === 'string' ? colRef : colRef._col,
            dir: dir.toUpperCase(),
        });
        return this;
    }

    limit(n) {
        this._limit = n;
        return this;
    }

    offset(n) {
        this._offset = n;
        return this;
    }

    // ── INSERT ───────────────────────────────────────────────

    insert(tableDef, values) {
        this._type = 'INSERT';
        this._table = tableDef._tableName;
        this._tableDef = tableDef;

        // JS 키 → 실제 컬럼명 매핑 + default 자동 채우기
        const mapped = {};

        // 1) 전달된 values를 컬럼명으로 변환
        for (const [k, v] of Object.entries(values || {})) {
            const colName = tableDef._columns[k]?._colName ?? k;
            mapped[colName] = v;
        }

        // 2) 테이블 컬럼을 순회하며 미제공 default 자동 채우기
        for (const colDef of Object.values(tableDef._columns)) {
            const col = colDef._colName;
            if (col in mapped) continue;          // 이미 있으면 건너뜀
            const def = colDef._type?._default;
            if (def === 'random') {
                // UUID v4 자동 생성
                mapped[col] = _uuid();
            } else if (def === 'now') {
                // 현재 시각
                mapped[col] = new Date().toISOString().slice(0, 19).replace('T', ' ');
            }
            // 그 외 default 값은 DB가 처리 (SQL DEFAULT 절)
        }

        this._values = mapped;
        return this;
    }

    returning() {
        this._returning = true;
        return this;
    }

    // ── UPDATE ───────────────────────────────────────────────

    update(tableDef, values) {
        this._type = 'UPDATE';
        this._table = tableDef._tableName;
        this._tableDef = tableDef;

        // JS 키(camelCase) → 실제 컬럼명(snake_case) 매핑 — INSERT 와 동일 규칙
        const mapped = {};
        for (const [k, v] of Object.entries(values || {})) {
            const colName = tableDef._columns[k]?._colName ?? k;
            mapped[colName] = v;
        }
        this._values = mapped;
        return this;
    }

    // ── DELETE ───────────────────────────────────────────────

    delete(tableDef) {
        this._type = 'DELETE';
        this._table = tableDef._tableName;
        this._tableDef = tableDef;
        return this;
    }

    // ── SQL 컴파일 ───────────────────────────────────────────

    _compile() {
        const params = [];
        let sql = '';

        switch (this._type) {
            case 'SELECT': {
                const cols =
                    this._columns.length > 0
                        ? this._columns.map((c) => `"${c}"`).join(', ')
                        : '*';
                sql = `SELECT ${cols} FROM "${this._table}"`;
                if (this._where) {
                    sql += ` WHERE ${condToSql(this._where, params)}`;
                }
                if (this._orderBy.length > 0) {
                    sql +=
                        ' ORDER BY ' +
                        this._orderBy.map((o) => `"${o.col}" ${o.dir}`).join(', ');
                }
                if (this._limit !== null) sql += ` LIMIT ${Number(this._limit)}`;
                if (this._offset !== null) sql += ` OFFSET ${Number(this._offset)}`;
                break;
            }
            case 'INSERT': {
                const cols = Object.keys(this._values);
                const placeholders = cols.map(() => '?').join(', ');
                cols.forEach((c) => params.push(normalizeBind(this._values[c])));
                sql = `INSERT INTO "${this._table}" (${cols.map((c) => `"${c}"`).join(', ')}) VALUES (${placeholders})`;
                if (this._returning) sql += ' RETURNING *';
                break;
            }
            case 'UPDATE': {
                const sets = Object.keys(this._values)
                    .map((c) => {
                        params.push(normalizeBind(this._values[c]));
                        return `"${c}" = ?`;
                    })
                    .join(', ');
                sql = `UPDATE "${this._table}" SET ${sets}`;
                if (this._where) {
                    sql += ` WHERE ${condToSql(this._where, params)}`;
                }
                break;
            }
            case 'DELETE': {
                sql = `DELETE FROM "${this._table}"`;
                if (this._where) {
                    sql += ` WHERE ${condToSql(this._where, params)}`;
                }
                break;
            }
            default:
                throw new Error('[dokkebi:dsl] 알 수 없는 쿼리 타입: ' + this._type);
        }

        return { sql, params };
    }

    // ── 실행 ─────────────────────────────────────────────────

    /**
     * 쿼리 실행. 브라우저 + dokkebi-cli 부트스트랩에서는 `SELECT` 로 시작하는 읽기가
     * 네트워크 직렬 큐를 타지 않아, `Promise.all([q1.exec(), q2.exec()])` 또는
     * `parallelReads([...])` 없이도 여러 exec 를 동시에 시작하면 병렬 전송됩니다.
     * `INSERT`/`UPDATE`/`DELETE`, `WITH` 로 시작하는 SQL 은 직렬입니다.
     */
    async exec() {
        const { sql, params } = this._compile();
        const result = await this._runtime._execSql(sql, params);

        if (!result.ok) {
            throw new Error(`[dokkebi:dsl] 쿼리 실패: ${result.error}\nSQL: ${sql}`);
        }

        // SELECT 는 select() 시 만든 사전, INSERT/UPDATE returning 은 _tableDef 로 즉시 생성.
        let dbToJsKey = this._colNameToJsKey;
        if (!dbToJsKey && this._tableDef) {
            dbToJsKey = Object.create(null);
            for (const [jsKey, def] of Object.entries(this._tableDef._columns)) {
                const dbName = def._colName;
                if (dbName && dbName !== jsKey) dbToJsKey[dbName] = jsKey;
            }
        }

        // 호환 모드:
        //   - 새 코드:  row.camelCase  (DSL 모델의 JS 키)
        //   - 기존 코드: row.snake_case (DB 컬럼명, 예: user.password_hash)
        //   둘 다 채운다. 같은 값이라 메모리 비용은 컬럼 수만큼만 추가.
        //   사용자가 양쪽 키 모두 사용 중인 코드베이스에서도 100% 호환.
        const remapKeys = (obj) => {
            if (!obj || typeof obj !== 'object') return obj;
            if (!dbToJsKey) return obj;
            const out = {};
            for (const [k, v] of Object.entries(obj)) {
                const jsKey = dbToJsKey[k];
                if (jsKey && jsKey !== k) {
                    out[jsKey] = v;   // camelCase
                    out[k] = v;       // snake_case (호환)
                } else {
                    out[k] = v;
                }
            }
            return out;
        };

        const rows = (result.value?.rows || []).map((r) => {
            let parsed;
            try { parsed = JSON.parse(r); }
            catch { parsed = r; }
            return remapKeys(parsed);
        });

        return {
            rows,
            affected: result.value?.affected ?? 0,
            lastInsertId: result.value?.lastInsertId ?? null,
        };
    }
}

// ─────────────────────────────────────────────────────────────
// DDL 생성 (마이그레이션)
// ─────────────────────────────────────────────────────────────

/**
 * 테이블 정의로부터 CREATE TABLE SQL 생성
 * @param {object} tableDef - table() 반환값
 * @returns {string} CREATE TABLE SQL
 */
export function createTableSql(tableDef) {
    const { _tableName: name, _columns: cols } = tableDef;
    const colDefs = Object.values(cols).map((c) => {
        const base = `  "${c._colName}" ${c._type.toSqlDef()}`;
        if (c._type._enumValues) {
            const checks = c._type._enumValues.map((v) => `'${v}'`).join(', ');
            return base + ` CHECK("${c._colName}" IN (${checks}))`;
        }
        if (c._type._serial) {
            return `  "${c._colName}" INTEGER PRIMARY KEY AUTOINCREMENT`;
        }
        return base;
    });

    const fkDefs = Object.values(cols)
        .filter((c) => c._type._references)
        .map((c) => {
            const ref = c._type._references;
            return `  FOREIGN KEY ("${c._colName}") REFERENCES "${ref.table}"("${ref.column}")`;
        });

    return `CREATE TABLE IF NOT EXISTS "${name}" (\n${[...colDefs, ...fkDefs].join(',\n')}\n);`;
}

// ─────────────────────────────────────────────────────────────
// DB 팩토리 (런타임 주입)
// ─────────────────────────────────────────────────────────────

/**
 * 런타임과 연결된 DB 쿼리 빌더 인스턴스 생성
 * dokkebi-runtime에서 주입 받아 사용합니다.
 *
 * @param {object} runtime - { _execSql(sql, params) }
 * @returns {object} db 빌더 인스턴스
 */
export function createDb(runtime) {
    const builder = {
        _rawBlocked: false,

        select(tableDef, columns) {
            return new QueryBuilder(runtime).select(tableDef, columns);
        },
        insert(tableDef, values) {
            return new QueryBuilder(runtime).insert(tableDef, values);
        },
        update(tableDef, values) {
            return new QueryBuilder(runtime).update(tableDef, values);
        },
        delete(tableDef) {
            return new QueryBuilder(runtime).delete(tableDef);
        },
        /**
         * 원시 SQL 직접 실행
         * security.blockRaw 설정 시 차단됩니다.
         */
        async raw(sql, params = []) {
            if (builder._rawBlocked) {
                throw new Error('[dokkebi:dsl] db.raw()가 보안 정책에 의해 차단되었습니다. DSL 쿼리 빌더를 사용하세요.');
            }
            const result = await runtime._execSql(sql, params.map(String));
            if (!result.ok) throw new Error('[dokkebi:dsl] raw SQL 실패: ' + result.error);
            return (result.value?.rows || []).map((r) => {
                try { return JSON.parse(r); } catch { return r; }
            });
        },
    };
    return builder;
}
