import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { splitSqlStatements } from '../src/core/d1Integration.js';

test('splitSqlStatements keeps CREATE TRIGGER bodies intact', () => {
  const sql = `CREATE TABLE IF NOT EXISTS t (id TEXT);
CREATE TRIGGER IF NOT EXISTS t_quota BEFORE INSERT ON t BEGIN
  SELECT CASE WHEN 1 THEN RAISE(ABORT,'SCAN_QUOTA_EXCEEDED') END;
  SELECT CASE WHEN 0 THEN RAISE(ABORT,'NO') END;
END;
INSERT INTO t(id) VALUES ('a');
`;
  const stmts = splitSqlStatements(sql);
  assert.equal(stmts.length, 3);
  assert.match(stmts[0], /CREATE TABLE IF NOT EXISTS t/);
  assert.match(stmts[1], /CREATE TRIGGER[\s\S]*BEGIN[\s\S]*END$/);
  assert.equal(stmts[1].includes("RAISE(ABORT,'SCAN_QUOTA_EXCEEDED')"), true);
  assert.match(stmts[2], /INSERT INTO t/);
});

test('splitSqlStatements ignores semicolons in strings and comments', () => {
  const stmts = splitSqlStatements(`
    -- comment; not a split
    INSERT INTO t(id) VALUES ('a;b');
    /* block; comment */
    UPDATE t SET id = 'x';
  `);
  assert.equal(stmts.length, 2);
  assert.match(stmts[0], /'a;b'/);
  assert.match(stmts[1], /UPDATE t/);
});

test('003_trusted_scans.sql splits into complete statements', () => {
  const file = join(dirname(fileURLToPath(import.meta.url)), '../../dokkebi-security/backend/db/migrations/003_trusted_scans.sql');
  let sql;
  try { sql = readFileSync(file, 'utf8'); }
  catch { sql = ''; }
  if (!sql) return;
  const stmts = splitSqlStatements(sql);
  const triggers = stmts.filter((s) => /CREATE TRIGGER/i.test(s));
  assert.equal(triggers.length, 3);
  for (const t of triggers) {
    assert.match(t, /BEGIN[\s\S]*\bEND$/i);
    assert.doesNotMatch(t, /^CREATE TRIGGER[\s\S]*BEGIN\s*$/i);
  }
});
