/**
 * Policy Extensions 단위 테스트
 *
 *   1. DSL table() 의 access / tenant 옵션 정적 추출
 *   2. 컨트롤러 JSDoc @dokkebi-policy / @dokkebi-tenant 어노테이션 파싱
 *   3. security.level 프리셋 적용 동작
 *
 * 실행: node tests/policyExtensions.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { extractTableDefinitions, inferPolicyFromProject } from '../src/core/policyInference.js';
import { extractAnnotations, mergeAnnotationsIntoInferred } from '../src/core/policyAnnotations.js';

// ─────────────────────────────────────────────────────────────
// 1. DSL table() 의 access / tenant 옵션 추출
// ─────────────────────────────────────────────────────────────

test('extractTableDefinitions: tenant 문자열 옵션 추출', () => {
    const src = `
        export const posts = table('posts', {
            id:     col('id',      t.uuid().primaryKey()),
            userId: col('user_id', t.uuid()),
        }, {
            tenant: 'user_id',
        });
    `;
    const defs = extractTableDefinitions(src);
    assert.equal(defs.length, 1);
    assert.equal(defs[0].name, 'posts');
    assert.deepEqual(defs[0].options?.tenant, { column: 'user_id', mode: 'enforce' });
});

test('extractTableDefinitions: tenant 객체 옵션 (column + claim + mode)', () => {
    const src = `
        export const notes = table('notes', {
            id: col('id', t.uuid().primaryKey()),
        }, {
            tenant: { column: 'creator_token', claim: 'token', mode: 'enforce' },
        });
    `;
    const defs = extractTableDefinitions(src);
    assert.deepEqual(defs[0].options?.tenant, {
        column: 'creator_token',
        claim: 'token',
        mode: 'enforce',
    });
});

test('extractTableDefinitions: access (read/write/delete) 옵션 추출', () => {
    const src = `
        export const premiumContents = table('premium_contents', {
            id: col('id', t.uuid().primaryKey()),
        }, {
            tenant: 'user_id',
            access: {
                read:   { roles: ['premium', 'admin'] },
                write:  { roles: ['admin'] },
                delete: { deny: true },
            },
        });
    `;
    const defs = extractTableDefinitions(src);
    const access = defs[0].options?.access;
    assert.deepEqual(access?.read,   { roles: ['premium', 'admin'] });
    assert.deepEqual(access?.write,  { roles: ['admin'] });
    assert.deepEqual(access?.delete, { deny: true });
});

test('extractTableDefinitions: access.public:true / access.auth:true', () => {
    const src = `
        export const blog = table('blog', {
            id: col('id', t.uuid().primaryKey()),
        }, {
            access: {
                read: { public: true },
                write: { auth: true },
            },
        });
    `;
    const defs = extractTableDefinitions(src);
    const access = defs[0].options?.access;
    assert.deepEqual(access?.read,  { public: true });
    assert.deepEqual(access?.write, { auth: true });
});

test('extractTableDefinitions: 옵션이 없으면 options 필드 없음 (호환성)', () => {
    const src = `
        export const foo = table('foo', {
            id: col('id', t.uuid().primaryKey()),
        });
    `;
    const defs = extractTableDefinitions(src);
    assert.equal(defs[0].name, 'foo');
    assert.equal(defs[0].options, undefined);
});

// ─────────────────────────────────────────────────────────────
// 2. JSDoc 어노테이션 파싱
// ─────────────────────────────────────────────────────────────

test('extractAnnotations: @dokkebi-policy 단일 (read/roles)', () => {
    const src = `
        /**
         * @dokkebi-policy table:premium_contents access:read roles:['premium','admin']
         */
        router.get('/api/premium', async () => {});
    `;
    const { policies } = extractAnnotations(src);
    assert.equal(policies.length, 1);
    assert.equal(policies[0].op, 'SELECT');
    assert.equal(policies[0].table, 'premium_contents');
    assert.deepEqual(policies[0].spec, { roles: ['premium', 'admin'] });
});

test('extractAnnotations: @dokkebi-policy access:write → INSERT/UPDATE 두 개로 확장', () => {
    const src = `
        /**
         * @dokkebi-policy table:payments access:write roles:['admin']
         */
    `;
    const { policies } = extractAnnotations(src);
    assert.equal(policies.length, 2);
    const ops = policies.map((p) => p.op).sort();
    assert.deepEqual(ops, ['INSERT', 'UPDATE']);
    for (const p of policies) {
        assert.equal(p.table, 'payments');
        assert.deepEqual(p.spec, { roles: ['admin'] });
    }
});

test('extractAnnotations: @dokkebi-policy public:true', () => {
    const src = `
        // @dokkebi-policy table:public_blog access:read public:true
    `;
    const { policies } = extractAnnotations(src);
    assert.equal(policies.length, 1);
    assert.deepEqual(policies[0].spec, { public: true });
});

test('extractAnnotations: @dokkebi-policy deny:true (명시적 차단)', () => {
    const src = `
        /** @dokkebi-policy table:secret access:all deny:true */
    `;
    const { policies } = extractAnnotations(src);
    assert.equal(policies.length, 4); // SELECT/INSERT/UPDATE/DELETE 4개
    for (const p of policies) {
        assert.deepEqual(p.spec, { deny: true });
    }
});

test('extractAnnotations: @dokkebi-tenant table+column+claim', () => {
    const src = `
        /**
         * @dokkebi-tenant table:notes column:creator_token claim:token
         */
    `;
    const { tenants } = extractAnnotations(src);
    assert.equal(tenants.length, 1);
    assert.equal(tenants[0].table, 'notes');
    assert.equal(tenants[0].column, 'creator_token');
    assert.equal(tenants[0].claim, 'token');
});

test('extractAnnotations: 어노테이션이 없으면 빈 결과', () => {
    const src = `
        /**
         * 일반 JSDoc — 도깨비 어노테이션 없음.
         */
        function foo() {}
    `;
    const { policies, tenants } = extractAnnotations(src);
    assert.equal(policies.length, 0);
    assert.equal(tenants.length, 0);
});

// ─────────────────────────────────────────────────────────────
// 3. mergeAnnotationsIntoInferred — 어노테이션이 convention 을 덮어씀
// ─────────────────────────────────────────────────────────────

test('mergeAnnotationsIntoInferred: 어노테이션 규칙이 convention 추론보다 우선', () => {
    const inferred = {
        tables: {},
        rules: {
            'SELECT:premium_contents': { public: true, _inferred: true },
        },
        detectedTables: [],
        warnings: [],
    };
    const annotations = {
        rules: {
            'SELECT:premium_contents': { roles: ['premium'] },
        },
        tenants: {},
    };
    const out = mergeAnnotationsIntoInferred(inferred, annotations);
    assert.deepEqual(out.rules['SELECT:premium_contents'].roles, ['premium']);
    assert.equal(out.rules['SELECT:premium_contents']._explicit, true);
});

test('mergeAnnotationsIntoInferred: 어노테이션 tenant 가 convention 을 덮어씀', () => {
    const inferred = {
        tables: {
            notes: { tenantColumn: 'user_id', mode: 'enforce', _inferred: true },
        },
        rules: {},
        detectedTables: ['notes'],
        warnings: [],
    };
    const annotations = {
        rules: {},
        tenants: {
            notes: { tenantColumn: 'creator_token', sessionClaim: 'token', mode: 'enforce' },
        },
    };
    const out = mergeAnnotationsIntoInferred(inferred, annotations);
    assert.equal(out.tables.notes.tenantColumn, 'creator_token');
    assert.equal(out.tables.notes.sessionClaim, 'token');
    assert.equal(out.tables.notes._explicit, true);
});

// ─────────────────────────────────────────────────────────────
// 4. inferPolicyFromProject — DSL access 옵션이 규칙으로 변환되는지
// ─────────────────────────────────────────────────────────────

import os from 'node:os';
import fs from 'node:fs/promises';
import path from 'node:path';

async function tmpProject() {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'dokkebi-policy-ext-'));
    const modelDir = path.join(dir, 'backend', 'models');
    await fs.mkdir(modelDir, { recursive: true });
    return { dir, modelDir };
}

test('inferPolicyFromProject: DSL access 옵션이 인가 규칙으로 자동 등록', async () => {
    const { dir, modelDir } = await tmpProject();
    try {
        await fs.writeFile(path.join(modelDir, 'index.ts'), `
            import { table, col, t } from 'dokkebi-dsl';
            export const premium = table('premium_contents', {
                id:     col('id',      t.uuid().primaryKey()),
                userId: col('user_id', t.uuid()),
            }, {
                tenant: 'user_id',
                access: {
                    read:  { roles: ['premium', 'admin'] },
                    write: { roles: ['admin'] },
                },
            });
        `, 'utf-8');

        const inferred = await inferPolicyFromProject(dir);
        // tenant 자동 등록
        assert.equal(inferred.tables.premium_contents.tenantColumn, 'user_id');
        // access → 인가 규칙으로 확장
        assert.deepEqual(inferred.rules['SELECT:premium_contents'].roles, ['premium', 'admin']);
        assert.deepEqual(inferred.rules['INSERT:premium_contents'].roles, ['admin']);
        assert.deepEqual(inferred.rules['UPDATE:premium_contents'].roles, ['admin']);
        // _explicit 플래그
        assert.equal(inferred.rules['SELECT:premium_contents']._explicit, true);
    } finally {
        await fs.rm(dir, { recursive: true, force: true });
    }
});

test('inferPolicyFromProject: DSL tenant 명시가 convention 추론보다 우선', async () => {
    const { dir, modelDir } = await tmpProject();
    try {
        // user_id 컬럼이 있어 convention 으로는 user_id 가 잡히지만
        // DSL 명시 옵션으로 다른 컬럼을 강제.
        await fs.writeFile(path.join(modelDir, 'index.ts'), `
            export const docs = table('docs', {
                id:           col('id',           t.uuid().primaryKey()),
                userId:       col('user_id',      t.uuid()),
                creatorToken: col('creator_token', t.text()),
            }, {
                tenant: { column: 'creator_token', claim: 'token' },
            });
        `, 'utf-8');

        const inferred = await inferPolicyFromProject(dir);
        assert.equal(inferred.tables.docs.tenantColumn, 'creator_token');
        assert.equal(inferred.tables.docs.sessionClaim, 'token');
        assert.equal(inferred.tables.docs._reason, 'dsl-explicit-tenant');
    } finally {
        await fs.rm(dir, { recursive: true, force: true });
    }
});
