/**
 * 키스토어 테이블 사용자 SQL 차단 (C1)
 *
 * 실행: node tests/sqlAllowlist.keystore.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
    findKeystoreTableRef,
    KEYSTORE_TABLES,
    validateSqlAllowlist,
} from '../src/core/sqlAllowlist.js';

const allowlistWithKeystore = {
    tables: [
        { name: 'users', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] },
        { name: '_dokkebi_sessions', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE'] },
        { name: '_dokkebi_ephemeral_keys', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE'] },
        { name: '_dokkebi_nonces', ops: ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE'] },
        { name: '_dokkebi_errors', ops: ['SELECT', 'INSERT'] },
        { name: 'sqlite_master', ops: ['SELECT'] },
    ],
};

test('KEYSTORE_TABLES 는 세션/ephemeral/nonce 세 개', () => {
    assert.deepEqual([...KEYSTORE_TABLES], [
        '_dokkebi_sessions',
        '_dokkebi_ephemeral_keys',
        '_dokkebi_nonces',
    ]);
});

test('findKeystoreTableRef: 직접 SELECT', () => {
    assert.equal(findKeystoreTableRef('SELECT enc_key FROM _dokkebi_sessions'), '_dokkebi_sessions');
    assert.equal(findKeystoreTableRef('SELECT * FROM "_dokkebi_ephemeral_keys"'), '_dokkebi_ephemeral_keys');
    assert.equal(findKeystoreTableRef('DELETE FROM `_dokkebi_nonces`'), '_dokkebi_nonces');
});

test('findKeystoreTableRef: 로그 테이블은 매칭 안 함', () => {
    assert.equal(findKeystoreTableRef('INSERT INTO _dokkebi_errors (id) VALUES (?)'), null);
    assert.equal(findKeystoreTableRef('SELECT name FROM sqlite_master'), null);
});

test('구버전 allowlist 에 키가 있어도 SELECT 거부', () => {
    const r = validateSqlAllowlist(
        'SELECT enc_key, sig_key FROM _dokkebi_sessions',
        allowlistWithKeystore,
        { strict: true },
    );
    assert.equal(r.allowed, false);
    assert.match(r.reason, /_dokkebi_sessions/);
});

test('UNION 으로 키스토어를 붙여도 거부', () => {
    const r = validateSqlAllowlist(
        'SELECT id FROM users UNION SELECT enc_key FROM _dokkebi_sessions',
        allowlistWithKeystore,
        { strict: false },
    );
    assert.equal(r.allowed, false);
    assert.match(r.reason, /_dokkebi_sessions/);
});

test('서브쿼리 / JOIN 거부', () => {
    const sub = validateSqlAllowlist(
        'SELECT * FROM users WHERE id IN (SELECT session_id FROM _dokkebi_sessions)',
        allowlistWithKeystore,
    );
    assert.equal(sub.allowed, false);

    const join = validateSqlAllowlist(
        'SELECT u.id FROM users u JOIN _dokkebi_nonces n ON u.id = n.nonce',
        allowlistWithKeystore,
    );
    assert.equal(join.allowed, false);
});

test('allowlist 없어도 (strict=false) 키스토어는 거부', () => {
    const r = validateSqlAllowlist(
        'SELECT * FROM _dokkebi_ephemeral_keys',
        null,
        { strict: false },
    );
    assert.equal(r.allowed, false);
    assert.match(r.reason, /_dokkebi_ephemeral_keys/);
});

test('CREATE TABLE 키스토어 / CREATE AS SELECT 거부', () => {
    const create = validateSqlAllowlist(
        'CREATE TABLE IF NOT EXISTS _dokkebi_sessions (session_id TEXT)',
        allowlistWithKeystore,
    );
    assert.equal(create.allowed, false);

    const ctas = validateSqlAllowlist(
        'CREATE TABLE leaked AS SELECT enc_key FROM _dokkebi_sessions',
        allowlistWithKeystore,
    );
    assert.equal(ctas.allowed, false);
});

test('앱 테이블은 허용, 내부 로그/스키마 테이블은 거부', () => {
    const users = validateSqlAllowlist(
        'SELECT id FROM users WHERE id = ?',
        allowlistWithKeystore,
    );
    assert.equal(users.allowed, true);

    // v7+ 보안 강화: _dokkebi_* (로그 포함) 및 sqlite_* 는 클라이언트 SQL 에서 차단.
    // 로그 조회/조작은 관제 패널(Worker env.DB 직접 접근)만 수행한다.
    const logs = validateSqlAllowlist(
        'INSERT INTO _dokkebi_errors (id, source, level, message, stack) VALUES (?,?,?,?,?)',
        allowlistWithKeystore,
    );
    assert.equal(logs.allowed, false);
    assert.match(logs.reason, /_dokkebi_errors/);

    const master = validateSqlAllowlist(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        allowlistWithKeystore,
    );
    assert.equal(master.allowed, false);
    assert.match(master.reason, /sqlite_master/);
});
