/**
 * Cloudflare D1 HTTPS API를 사용한 마이그레이션 및 데이터 복사
 * CLI에서 입력받은 accountId, databaseId, apiToken으로 D1에 스키마/데이터 적용
 */

const D1_API_BASE = 'https://api.cloudflare.com/client/v4';

function quoteSqliteIdentifier(value) {
    return '"' + String(value || '').replace(/"/g, '""') + '"';
}

function normalizeD1Param(value) {
    if (value === null || value === undefined) return null;
    if (value instanceof Date) return value.toISOString().slice(0, 19).replace('T', ' ');
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value).toString('base64');
    if (typeof value === 'bigint') return value.toString();
    return value;
}

function d1Url(targetConfig, action) {
    return [
        String(targetConfig.apiBase || D1_API_BASE).replace(/\/+$/, ''),
        'accounts',
        encodeURIComponent(String(targetConfig.accountId || '').trim()),
        'd1',
        'database',
        encodeURIComponent(String(targetConfig.databaseId || '').trim()),
        action,
    ].join('/');
}

async function d1Json(targetConfig, action, body) {
    const response = await fetch(d1Url(targetConfig, action), {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${targetConfig.apiToken}`,
        },
        body: JSON.stringify(body),
    });
    const text = await response.text();
    let parsed = null;
    try {
        parsed = JSON.parse(text);
    } catch {
        parsed = { success: false, errors: [{ message: text || 'D1_PARSE_FAILED' }] };
    }
    if (!response.ok || parsed.success === false) {
        const errorMessage =
            Array.isArray(parsed.errors) && parsed.errors.length > 0
                ? String(parsed.errors[0].message || parsed.errors[0].code || 'D1_EXECUTION_FAILED')
                : `D1_HTTP_${response.status}`;
        throw new Error(errorMessage);
    }
    return parsed;
}

/**
 * D1 REST API로 SQL 실행. CREATE TRIGGER 처럼 본문에 ; 가 있는 문은 d1ImportSql 을 쓴다.
 */
export async function d1Execute(targetConfig, sql, params = []) {
    const parsed = await d1Json(targetConfig, 'query', {
        sql: String(sql || ''),
        params: Array.isArray(params) ? params.map((v) => normalizeD1Param(v)) : [],
    });
    const resultEntry = Array.isArray(parsed.result) ? parsed.result[0] : parsed.result;
    return resultEntry || {};
}

async function sleep(ms) {
    await new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * D1 import API로 SQL 스크립트 전체를 적용한다. /query 는 트리거 본문의 ; 에서 incomplete input 이 난다.
 */
export async function d1ImportSql(targetConfig, sql) {
    const { createHash } = await import('crypto');
    const buf = Buffer.from(String(sql || ''), 'utf8');
    if (!buf.length) return {};
    const etag = createHash('md5').update(buf).digest('hex');
    const initParsed = await d1Json(targetConfig, 'import', { action: 'init', etag });
    const init = initParsed.result || {};
    let poll = init;
    if (init.upload_url && init.filename) {
        const put = await fetch(init.upload_url, {
            method: 'PUT',
            headers: { 'Content-Length': String(buf.length) },
            body: buf,
        });
        if (!put.ok) throw new Error(`D1 SQL 업로드 실패 (${put.status})`);
        const remoteEtag = String(put.headers.get('etag') || '').replace(/^"|"$/g, '');
        if (remoteEtag && remoteEtag !== etag) throw new Error('D1 SQL 업로드 검증에 실패했습니다.');
        const ingestParsed = await d1Json(targetConfig, 'import', {
            action: 'ingest',
            etag,
            filename: init.filename,
        });
        poll = ingestParsed.result || ingestParsed;
    }
    for (let i = 0; i < 90; i++) {
        const status = poll.status;
        const errorText = Array.isArray(poll.errors) ? poll.errors.filter(Boolean).join('\n') : String(poll.error || '');
        if (status === 'error') throw new Error(errorText || 'D1 import error');
        if (status === 'complete') return poll;
        if (errorText === 'Not currently importing anything.') return poll;
        await sleep(400);
        const polled = await d1Json(targetConfig, 'import', {
            action: 'poll',
            current_bookmark: poll.at_bookmark || '',
        });
        poll = polled.result || polled;
    }
    throw new Error('D1 마이그레이션 import가 시간 초과되었습니다.');
}

/**
 * MySQL CREATE TABLE을 SQLite(D1) 호환으로 변환
 */
function mysqlCreateToSqlite(createSql, tableName) {
    const safeTable = quoteSqliteIdentifier(tableName);
    let raw = String(createSql || '').trim();
    if (!raw) return `CREATE TABLE IF NOT EXISTS ${safeTable} (id INTEGER PRIMARY KEY AUTOINCREMENT);`;
    let sql = raw
        .replace(/`/g, '"')
        .replace(/\/\*![\s\S]*?\*\//g, '')
        .replace(/AUTO_INCREMENT=\d+/gi, '')
        .replace(/DEFAULT CHARSET=[^ ]+/gi, '')
        .replace(/COLLATE=[^ ]+/gi, '')
        .replace(/\s+CHARACTER SET\s+[a-z0-9_]+/gi, '')
        .replace(/\s+COLLATE\s+[a-z0-9_]+/gi, '')
        .replace(/ROW_FORMAT=[^ ]+/gi, '')
        .replace(/ENGINE=[^ ]+/gi, '')
        .replace(/UNSIGNED/gi, '')
        .replace(/\bTINYINT\(\d+\)/gi, 'INTEGER')
        .replace(/\bSMALLINT\(\d+\)/gi, 'INTEGER')
        .replace(/\bMEDIUMINT\(\d+\)/gi, 'INTEGER')
        .replace(/\bINT\(\d+\)/gi, 'INTEGER')
        .replace(/\bBIGINT\(\d+\)/gi, 'INTEGER')
        .replace(/\bVARCHAR\(\d+\)/gi, 'TEXT')
        .replace(/\bCHAR\(\d+\)/gi, 'TEXT')
        .replace(/\bLONGTEXT\b/gi, 'TEXT')
        .replace(/\bMEDIUMTEXT\b/gi, 'TEXT')
        .replace(/\bTEXT\b/gi, 'TEXT')
        .replace(/\bJSON\b/gi, 'TEXT')
        .replace(/\bDECIMAL\([^)]+\)/gi, 'REAL')
        .replace(/\bDOUBLE\b/gi, 'REAL')
        .replace(/\bFLOAT\b/gi, 'REAL')
        .replace(/\bDATETIME\b/gi, 'TEXT')
        .replace(/\bTIMESTAMP\b/gi, 'TEXT')
        .replace(/\bDATE\b/gi, 'TEXT')
        .replace(/\bENUM\([^)]+\)/gi, 'TEXT')
        .replace(/\bAUTO_INCREMENT\b/gi, 'AUTOINCREMENT');
    const lines = sql.split(/\r?\n/g).filter((line) => {
        const t = line.trim();
        if (!t) return false;
        if (/^(KEY|INDEX|UNIQUE KEY|FULLTEXT|SPATIAL)\s+/i.test(t)) return false;
        return true;
    });
    let rebuilt = lines.join('\n').replace(/,\s*\)/g, '\n)');
    if (!rebuilt.endsWith(';')) rebuilt += ';';
    rebuilt = rebuilt.replace(/^CREATE TABLE\s+"[^"]+"/i, `CREATE TABLE IF NOT EXISTS ${safeTable}`);
    return rebuilt;
}

function isSqlIdentChar(ch) {
    return Boolean(ch) && /[A-Za-z0-9_]/.test(ch);
}

function sqlWithoutComments(text) {
    return String(text || '')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/--.*$/gm, '')
        .trim();
}

/**
 * SQLite 문을 세미콜론으로 나누되, 트리거 BEGIN…END와 문자열/주석 안의 ; 는 유지한다.
 * 줄 끝 ; 만 자르면 CREATE TRIGGER 본문의 END; 에서 incomplete input 이 난다.
 */
export function splitSqlStatements(sql) {
    const src = String(sql || '');
    const statements = [];
    let buf = '';
    let i = 0;
    let quote = null;
    let lineComment = false;
    let blockComment = false;
    let beginDepth = 0;
    let caseDepth = 0;

    const matchKeyword = (word) => {
        if (i > 0 && isSqlIdentChar(src[i - 1])) return false;
        if (src.slice(i, i + word.length).toUpperCase() !== word) return false;
        return !isSqlIdentChar(src[i + word.length]);
    };

    while (i < src.length) {
        const c = src[i];
        const n = src[i + 1];

        if (lineComment) {
            buf += c;
            if (c === '\n') lineComment = false;
            i += 1;
            continue;
        }
        if (blockComment) {
            buf += c;
            if (c === '*' && n === '/') {
                buf += n;
                i += 2;
                blockComment = false;
                continue;
            }
            i += 1;
            continue;
        }
        if (quote) {
            buf += c;
            if (c === quote) {
                if (quote === "'" && n === "'") {
                    buf += n;
                    i += 2;
                    continue;
                }
                quote = null;
            }
            i += 1;
            continue;
        }

        if (c === '-' && n === '-') {
            lineComment = true;
            buf += c;
            i += 1;
            continue;
        }
        if (c === '/' && n === '*') {
            blockComment = true;
            buf += c;
            i += 1;
            continue;
        }
        if (c === "'" || c === '"' || c === '`') {
            quote = c;
            buf += c;
            i += 1;
            continue;
        }

        if (matchKeyword('CASE')) {
            caseDepth += 1;
            buf += src.slice(i, i + 4);
            i += 4;
            continue;
        }
        if (matchKeyword('BEGIN')) {
            const txn = /^\s+(TRANSACTION|IMMEDIATE|DEFERRED|EXCLUSIVE)\b/i.test(src.slice(i + 5));
            buf += src.slice(i, i + 5);
            i += 5;
            if (!txn) beginDepth += 1;
            continue;
        }
        if (matchKeyword('END')) {
            buf += src.slice(i, i + 3);
            i += 3;
            if (caseDepth > 0) caseDepth -= 1;
            else if (beginDepth > 0) beginDepth -= 1;
            continue;
        }

        if (c === ';' && beginDepth === 0) {
            if (sqlWithoutComments(buf)) statements.push(buf.trim());
            buf = '';
            i += 1;
            continue;
        }

        buf += c;
        i += 1;
    }
    if (sqlWithoutComments(buf)) statements.push(buf.trim());
    return statements;
}
export async function applyMigrationsToD1(targetConfig, migrationsDir) {
    const { readdir, readFile } = await import('fs/promises');
    const { join } = await import('path');
    let entries = [];
    try {
        entries = await readdir(migrationsDir, { withFileTypes: true });
    } catch {
        return { applied: 0, files: [], skippedFiles: [], sqlFileCount: 0 };
    }
    const sqlFiles = entries
        .filter((e) => e.isFile() && e.name.endsWith('.sql'))
        .map((e) => e.name)
        .sort();

    // ── 마이그레이션 이력 테이블 생성 (최초 1회) ────────────────
    await d1Execute(targetConfig,
        `CREATE TABLE IF NOT EXISTS "_dokkebi_migrations" (
           "name"       TEXT NOT NULL PRIMARY KEY,
           "applied_at" TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
         )`
    );

    // ── 이미 적용된 마이그레이션 목록 조회 ──────────────────────
    // D1 REST API는 결과 행을 { results: [...] } 형태로 반환
    const appliedResult = await d1Execute(targetConfig,
        'SELECT name FROM "_dokkebi_migrations"'
    );
    const appliedRows = appliedResult.results || appliedResult.rows || [];
    const applied_set = new Set(appliedRows.map((r) => r.name));

    let applied = 0;
    const appliedFiles = [];
    const skippedFiles = [];
    for (const name of sqlFiles) {
        if (applied_set.has(name)) {
            skippedFiles.push(name);
            continue; // 이미 적용됨 → 건너뜀
        }

        const content = await readFile(join(migrationsDir, name), 'utf8');
        if (/CREATE\s+TRIGGER\b/i.test(content)) {
            await d1ImportSql(targetConfig, content);
            applied++;
        } else {
            const statements = splitSqlStatements(content);
            for (const sql of statements) {
                await d1Execute(targetConfig, sql);
                applied++;
            }
        }
        // 적용 완료 기록
        await d1Execute(targetConfig,
            `INSERT OR IGNORE INTO "_dokkebi_migrations" ("name") VALUES ('${name.replace(/'/g, "''")}')`
        );
        appliedFiles.push(name);
    }
    return { applied, files: appliedFiles, skippedFiles, sqlFileCount: sqlFiles.length };
}

/**
 * MySQL 소스에서 스냅샷 추출 후 D1에 적용 (스키마 변환 + 데이터 복사)
 */
export async function migrateFromMysqlToD1(sourceMysqlConfig, targetD1Config) {
    const mysql2 = await import('mysql2/promise').catch(() => null);
    if (!mysql2) throw new Error('MySQL 소스 사용 시 mysql2 패키지가 필요합니다: npm i mysql2');

    const connection = await mysql2.default.createConnection({
        host: sourceMysqlConfig.host || '127.0.0.1',
        port: Number(sourceMysqlConfig.port) || 3306,
        user: sourceMysqlConfig.user || 'root',
        password: sourceMysqlConfig.password || '',
        database: sourceMysqlConfig.database || '',
    });

    const quote = (v) => '`' + String(v).replace(/`/g, '``') + '`';
    const [tableRows] = await connection.query('SHOW FULL TABLES WHERE Table_type = "BASE TABLE"');
    const tableNames = tableRows.map((r) => Object.values(r)[0]).filter(Boolean);

    const tables = [];
    for (const tableName of tableNames) {
        const [createRows] = await connection.query(`SHOW CREATE TABLE ${quote(tableName)}`);
        const createKey = Object.keys(createRows[0] || {}).find((k) => /create table/i.test(k)) || 'Create Table';
        const createSql = String(createRows[0][createKey] || '').trim();
        const [columnRows] = await connection.query(`SHOW COLUMNS FROM ${quote(tableName)}`);
        const columns = columnRows.map((r) => r.Field).filter(Boolean);
        const [rows] = await connection.query(`SELECT * FROM ${quote(tableName)}`);
        tables.push({ tableName, columns, createSql, rows: Array.isArray(rows) ? rows : [] });
    }
    await connection.end();

    const report = { tableCount: tables.length, insertedRows: 0, tableSummaries: [] };
    for (const table of tables) {
        const safeTable = quoteSqliteIdentifier(table.tableName);
        const createSql = mysqlCreateToSqlite(table.createSql, table.tableName);
        await d1Execute(targetD1Config, createSql);
        await d1Execute(targetD1Config, `DELETE FROM ${safeTable}`).catch(() => {});
        let inserted = 0;
        if (table.rows.length > 0 && table.columns.length > 0) {
            const cols = table.columns.map((c) => quoteSqliteIdentifier(c)).join(', ');
            const marks = table.columns.map(() => '?').join(', ');
            const sql = `INSERT INTO ${safeTable} (${cols}) VALUES (${marks})`;
            for (const row of table.rows) {
                const params = table.columns.map((c) => row[c]);
                await d1Execute(targetD1Config, sql, params);
                inserted++;
            }
        }
        report.insertedRows += inserted;
        report.tableSummaries.push({ table: table.tableName, rows: inserted });
    }
    return report;
}

export function validateD1Config(config) {
    const accountId = String(config.accountId || '').trim();
    const databaseId = String(config.databaseId || '').trim();
    const apiToken = String(config.apiToken || '').trim();
    if (!accountId) return { ok: false, error: 'CLOUDFLARE_ACCOUNT_ID 필요' };
    if (!databaseId) return { ok: false, error: 'CLOUDFLARE_D1_DATABASE_ID 필요' };
    if (!apiToken) return { ok: false, error: 'CLOUDFLARE_API_TOKEN 필요' };
    return {
        ok: true,
        config: {
            accountId,
            databaseId,
            apiToken,
            apiBase: String(config.apiBase || D1_API_BASE).trim(),
        },
    };
}
