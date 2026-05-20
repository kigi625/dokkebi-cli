/**
 * Policy Inference 단위 테스트
 *
 * 실행: node --test tests/policyInference.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import fs from 'node:fs/promises';
import path from 'node:path';

import {
    extractTableDefinitions,
    inferTenantColumn,
    defaultAuthzSpec,
    inferPolicyFromProject,
    mergeInferredIntoConfig,
    _inferSessionClaim,
} from '../src/core/policyInference.js';
import {
    verifyTenantPolicy,
    injectTenantPolicy,
    normalizePolicyConfig,
    _resolveTenantClaim,
} from '../src/core/policyEngine.js';

// ─────────────────────────────────────────────────────────────
// 1. extractTableDefinitions — 모델 DSL 파싱
// ─────────────────────────────────────────────────────────────

test('extractTableDefinitions: 단일 table() 호출', () => {
    const src = `
        import { table, col, t } from 'dokkebi-dsl';
        export const posts = table('posts', {
            id:      col('id',       t.uuid().primaryKey()),
            userId:  col('user_id',  t.uuid().notNull()),
            title:   col('title',    t.text()),
        });
    `;
    const defs = extractTableDefinitions(src);
    assert.equal(defs.length, 1);
    assert.equal(defs[0].name, 'posts');
    assert.deepEqual(defs[0].columns, ['id', 'user_id', 'title']);
});

test('extractTableDefinitions: 여러 테이블 + 중첩 객체 + 주석 무시', () => {
    const src = `
        // 주석 안의 table('fake', { col('x', ...) }) 는 무시되어야 함
        export const posts = table('posts', {
            id:   col('id',   t.uuid().primaryKey()),
            meta: col('meta', t.text().default('{}')),
        });
        /* 블록 주석
           export const ghost = table('ghost', { ... });
        */
        export const comments = table('comments', {
            id:      col('id',       t.uuid()),
            postId:  col('post_id',  t.uuid().notNull()),
            body:    col('body',     t.text()),
        });
    `;
    const defs = extractTableDefinitions(src);
    assert.equal(defs.length, 2);
    assert.equal(defs[0].name, 'posts');
    assert.equal(defs[1].name, 'comments');
    assert.deepEqual(defs[1].columns, ['id', 'post_id', 'body']);
});

test('extractTableDefinitions: 문자열 내부의 table() 은 무시', () => {
    const src = `
        const doc = "예시: table('bad', { col('x', t.text()) })";
        export const real = table('real', { id: col('id', t.uuid()) });
    `;
    const defs = extractTableDefinitions(src);
    assert.equal(defs.length, 1);
    assert.equal(defs[0].name, 'real');
});

// ─────────────────────────────────────────────────────────────
// 2. inferTenantColumn — tenant 컬럼 휴리스틱
// ─────────────────────────────────────────────────────────────

test('inferTenantColumn: user_id 를 최우선으로 채택', () => {
    const out = inferTenantColumn({ name: 'posts', columns: ['id', 'user_id', 'title'] });
    assert.deepEqual(out, { tenantColumn: 'user_id', reason: 'convention' });
});

test('inferTenantColumn: owner_id 도 후보', () => {
    const out = inferTenantColumn({ name: 'files', columns: ['id', 'owner_id'] });
    assert.equal(out.tenantColumn, 'owner_id');
});

test('inferTenantColumn: users 테이블은 self-tenant(id)', () => {
    const out = inferTenantColumn({ name: 'users', columns: ['id', 'email'] });
    assert.deepEqual(out, { tenantColumn: 'id', reason: 'self-tenant(users)' });
});

test('inferTenantColumn: 후보 없으면 null', () => {
    const out = inferTenantColumn({ name: 'templates', columns: ['id', 'name', 'description'] });
    assert.equal(out, null);
});

test('inferTenantColumn: sender_token / author_token 도 기본 후보로 감지', () => {
    const out1 = inferTenantColumn({ name: 'messages', columns: ['id', 'sender_token', 'body'] });
    assert.equal(out1?.tenantColumn, 'sender_token');
    const out2 = inferTenantColumn({ name: 'replies', columns: ['id', 'author_token'] });
    assert.equal(out2?.tenantColumn, 'author_token');
});

test('inferTenantColumn: *_token 일반 패턴 (editor_token 등 정확 후보에 없는 것도) 자동 감지', () => {
    // editor_token 은 정확 매칭 후보(TENANT_COLUMN_CANDIDATES)에 없음 → token-pattern fallback 으로 잡혀야 함
    const out = inferTenantColumn({
        name: 'doc_editors',
        columns: ['id', 'doc_id', 'editor_token', 'added_at'],
    });
    assert.equal(out?.tenantColumn, 'editor_token');
    assert.ok(out.reason.startsWith('token-pattern'));
});

test('inferTenantColumn: password_token / access_token 은 tenant 로 간주하지 않음', () => {
    const out = inferTenantColumn({
        name: 'credentials',
        columns: ['id', 'password_token', 'access_token', 'refresh_token'],
    });
    assert.equal(out, null, '인증 토큰류는 tenant 가 아니어야 함');
});

test('inferTenantColumn: *_subscriptions + 단일 token 컬럼 → token 을 tenant 로', () => {
    const out = inferTenantColumn({
        name: 'push_subscriptions',
        columns: ['id', 'subscriber_type', 'token', 'endpoint'],
    });
    assert.equal(out?.tenantColumn, 'token');
    assert.ok(out.reason.includes('token-owned-table'));
});

test('isSharedTable: 관례 이름 (templates, categories) 은 shared', async () => {
    const { isSharedTable } = await import('../src/core/policyInference.js');
    assert.equal(isSharedTable({ name: 'templates', columns: ['id', 'name'] }), true);
    assert.equal(isSharedTable({ name: 'categories', columns: ['id', 'label'] }), true);
});

test('isSharedTable: FK 도 tenant 도 없는 순수 참조 테이블은 shared', async () => {
    const { isSharedTable } = await import('../src/core/policyInference.js');
    assert.equal(isSharedTable({ name: 'colors', columns: ['id', 'hex', 'name'] }), true);
});

test('isSharedTable: FK 가 있으면 shared 가 아님 (소속 데이터일 가능성)', async () => {
    const { isSharedTable } = await import('../src/core/policyInference.js');
    assert.equal(isSharedTable({ name: 'messages', columns: ['id', 'noto_id', 'data'] }), false);
});

// ─────────────────────────────────────────────────────────────
// 3. defaultAuthzSpec — 기본 프리셋
// ─────────────────────────────────────────────────────────────

test('defaultAuthzSpec: SELECT → public', () => {
    assert.deepEqual(defaultAuthzSpec('SELECT', 'posts'), { public: true });
});

test('defaultAuthzSpec: INSERT → auth', () => {
    assert.deepEqual(defaultAuthzSpec('INSERT', 'posts'), { auth: true });
});

test('defaultAuthzSpec: UPDATE/DELETE on users → admin', () => {
    assert.deepEqual(defaultAuthzSpec('DELETE', 'users'), { roles: ['admin'] });
    assert.deepEqual(defaultAuthzSpec('UPDATE', 'users'), { roles: ['admin'] });
});

test('defaultAuthzSpec: UPDATE on posts → auth', () => {
    assert.deepEqual(defaultAuthzSpec('UPDATE', 'posts'), { auth: true });
});

test('defaultAuthzSpec: _dokkebi_* → null (allowlist 전담)', () => {
    assert.equal(defaultAuthzSpec('SELECT', '_dokkebi_sessions'), null);
});

test('defaultAuthzSpec: CREATE → null', () => {
    assert.equal(defaultAuthzSpec('CREATE', 'anything'), null);
});

// ─────────────────────────────────────────────────────────────
// 4. inferPolicyFromProject — 가상 프로젝트 디렉터리
// ─────────────────────────────────────────────────────────────

async function makeFixture() {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'dokkebi-inf-'));
    const modelsDir = path.join(dir, 'backend', 'models');
    await fs.mkdir(modelsDir, { recursive: true });
    await fs.writeFile(path.join(modelsDir, 'index.ts'), `
        import { table, col, t } from 'dokkebi-dsl';
        export const posts = table('posts', {
            id:      col('id',       t.uuid().primaryKey()),
            userId:  col('user_id',  t.uuid().notNull()),
            title:   col('title',    t.text()),
        });
        export const templates = table('templates', {
            id:   col('id',   t.uuid().primaryKey()),
            name: col('name', t.text()),
        });
        export const users = table('users', {
            id:    col('id',    t.uuid().primaryKey()),
            email: col('email', t.text()),
        });
    `, 'utf-8');
    return dir;
}

test('inferPolicyFromProject: 모델 기반 tenant 추론 + SQL op/table 기반 rules', async () => {
    const dir = await makeFixture();
    try {
        const opTableStats = new Map([
            ['SELECT:posts', { op: 'SELECT', table: 'posts', count: 3 }],
            ['DELETE:posts', { op: 'DELETE', table: 'posts', count: 1 }],
            ['DELETE:users', { op: 'DELETE', table: 'users', count: 1 }],
            ['SELECT:_dokkebi_sessions', { op: 'SELECT', table: '_dokkebi_sessions', count: 1 }],
        ]);
        const result = await inferPolicyFromProject(dir, { opTableStats });

        assert.ok(result.scannedModelFiles >= 1);
        assert.deepEqual(result.detectedTables.sort(), ['posts', 'users'].sort());
        // 'templates' 는 SHARED_TABLE_NAMES 관례에 해당 → shared 분류 (경고 없음)
        assert.deepEqual(result.sharedTables, ['templates']);
        assert.deepEqual(result.undetectedTables, []);
        assert.equal(result.warnings.length, 0, 'shared 테이블은 경고를 내지 않음');

        // tenant
        assert.equal(result.tables.posts.tenantColumn, 'user_id');
        assert.equal(result.tables.posts.mode, 'enforce');
        assert.equal(result.tables.users.tenantColumn, 'id');
        assert.equal(result.tables.templates.mode, 'none');
        assert.equal(result.tables.templates.shared, true);

        // 테이블별 sessionClaim 추론:
        //   users.id → 'user_id' (self-tenant 관례)
        //   posts.user_id → 'user_id' (컬럼명 그대로)
        assert.equal(result.tables.users.sessionClaim, 'user_id');
        assert.equal(result.tables.posts.sessionClaim, 'user_id');

        // rules
        assert.deepEqual(result.rules['SELECT:posts'], { public: true, _inferred: true });
        assert.deepEqual(result.rules['DELETE:posts'], { auth: true, _inferred: true });
        assert.deepEqual(result.rules['DELETE:users'], { roles: ['admin'], _inferred: true });
        assert.equal(result.rules['SELECT:_dokkebi_sessions'], undefined, '시스템 테이블은 규칙 생성 안 함');
    } finally {
        await fs.rm(dir, { recursive: true, force: true });
    }
});

// ─────────────────────────────────────────────────────────────
// 5. mergeInferredIntoConfig — 사용자 명시값 우선
// ─────────────────────────────────────────────────────────────

test('mergeInferredIntoConfig: autoApply 없으면 제안만 반환하고 config 는 변경하지 않음', () => {
    const user = {};
    const inferred = {
        tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } },
        rules: { 'SELECT:posts': { public: true, _inferred: true } },
    };
    const r = mergeInferredIntoConfig(user, inferred);
    // 실제 병합은 없음
    assert.deepEqual(r.policyAdds, []);
    assert.deepEqual(r.authzAdds, []);
    assert.equal(r.merged.policy, undefined);
    assert.equal(r.merged.authorization, undefined);
    // 제안은 수집
    assert.deepEqual(r.policyAutoSuggestions, ['posts']);
    assert.deepEqual(r.authzAutoSuggestions, ['SELECT:posts']);
});

test('mergeInferredIntoConfig: policy.autoApply:true 이면 즉시 병합 + 사용자 명시값 보존', () => {
    const user = {
        policy: {
            autoApply: true,
            tables: {
                posts: { tenantColumn: 'author_id', mode: 'enforce' }, // 사용자 값 유지
            },
        },
    };
    const inferred = {
        tables: {
            posts:    { tenantColumn: 'user_id', mode: 'enforce' },   // 덮이면 안 됨
            comments: { tenantColumn: 'user_id', mode: 'enforce' },   // 새로 추가됨
        },
        rules: {},
    };
    const r = mergeInferredIntoConfig(user, inferred);
    assert.equal(r.merged.policy.tables.posts.tenantColumn, 'author_id');
    assert.equal(r.merged.policy.tables.comments.tenantColumn, 'user_id');
    assert.deepEqual(r.policyAdds, ['comments']);
});

test('mergeInferredIntoConfig: authorization.autoApply:true 이면 규칙 병합 + 기본 * 추가', () => {
    const user = {
        authorization: {
            autoApply: true,
            mode: 'strict',
            rules: { 'DELETE:posts': { roles: ['admin'] } },
        },
    };
    const inferred = {
        tables: {},
        rules: {
            'SELECT:posts':    { public: true, _inferred: true },
            'DELETE:posts':    { auth: true, _inferred: true },
            'DELETE:comments': { auth: true, _inferred: true },
        },
    };
    const r = mergeInferredIntoConfig(user, inferred);
    assert.deepEqual(r.merged.authorization.rules['DELETE:posts'], { roles: ['admin'] });
    assert.deepEqual(r.merged.authorization.rules['SELECT:posts'], { public: true });
    assert.deepEqual(r.merged.authorization.rules['DELETE:comments'], { auth: true });
    assert.deepEqual(r.merged.authorization.rules['*'], { public: true });
    assert.equal(r.merged.authorization.mode, 'strict');
    assert.ok(r.authzAdds.includes('SELECT:posts'));
    assert.ok(!r.authzAdds.includes('DELETE:posts'));
});

test('mergeInferredIntoConfig: policy.enabled:false 면 추론 비활성 (제안도 생략)', () => {
    const user = { policy: { enabled: false }, authorization: { enabled: false } };
    const inferred = {
        tables: { posts: { tenantColumn: 'user_id', mode: 'enforce' } },
        rules: { 'SELECT:posts': { public: true, _inferred: true } },
    };
    const r = mergeInferredIntoConfig(user, inferred);
    assert.equal(r.merged.policy.enabled, false);
    assert.equal(r.merged.authorization.enabled, false);
    assert.deepEqual(r.policyAutoSuggestions, []);
    assert.deepEqual(r.authzAutoSuggestions, []);
});

// ─────────────────────────────────────────────────────────────
// 6. 테이블별 sessionClaim — 엔진 레벨 해석 (v5.4, 비-JWT 해시 tenant)
// ─────────────────────────────────────────────────────────────

test('_inferSessionClaim: users.id → user_id (self-tenant 관례)', () => {
    assert.equal(
        _inferSessionClaim('users', { tenantColumn: 'id', reason: 'self-tenant(users)' }),
        'user_id'
    );
});

test('_inferSessionClaim: 그 외 → tenantColumn 그대로 (creator_token 등)', () => {
    assert.equal(
        _inferSessionClaim('notos', { tenantColumn: 'creator_token', reason: 'convention' }),
        'creator_token'
    );
    assert.equal(
        _inferSessionClaim('messages', { tenantColumn: 'sender_token', reason: 'convention' }),
        'sender_token'
    );
});

test('_resolveTenantClaim: 테이블 명시 > 전역 > 컬럼명 순 fallback', () => {
    // 1) 테이블 명시값이 세션에 있으면 그걸 사용
    assert.deepEqual(
        _resolveTenantClaim({ user_id: 'u1', creator_token: 'c1' }, 'user_id', 'creator_token', 'id'),
        ['user_id', 'u1']
    );
    // 2) 테이블 명시값이 세션에 없으면 전역 사용
    assert.deepEqual(
        _resolveTenantClaim({ creator_token: 'c1' }, 'user_id', 'creator_token', 'id'),
        ['creator_token', 'c1']
    );
    // 3) 전역도 없으면 tenantCol 이름으로 fallback
    assert.deepEqual(
        _resolveTenantClaim({ sender_token: 's1' }, undefined, 'user_id', 'sender_token'),
        ['sender_token', 's1']
    );
    // 4) 아무것도 없으면 첫 후보 이름 + undefined (에러 메시지용)
    assert.deepEqual(
        _resolveTenantClaim({}, 'creator_token', 'user_id', 'id'),
        ['creator_token', undefined]
    );
});

test('verifyTenantPolicy: 테이블별 sessionClaim 이 서로 다른 혼합 프로젝트 (notofly 형)', () => {
    const policy = normalizePolicyConfig({
        enabled: true,
        mode: 'verify',
        sessionClaim: 'user_id',
        strict: false,
        tables: {
            notos:    { tenantColumn: 'creator_token', mode: 'enforce', sessionClaim: 'creator_token' },
            messages: { tenantColumn: 'sender_token',  mode: 'enforce', sessionClaim: 'sender_token' },
            users:    { tenantColumn: 'id',            mode: 'enforce', sessionClaim: 'user_id' },
        },
    });
    // 한 세션에 세 가지 식별값이 모두 들어있음 (JWT 없이 localStorage 해시만)
    const ctx = { user_id: 'U1', creator_token: 'C1', sender_token: 'S1' };

    // notos — creator_token 기반
    const r1 = verifyTenantPolicy('SELECT id FROM notos WHERE creator_token = ?', ['C1'], ctx, policy);
    assert.deepEqual(r1, { ok: true });

    // messages — sender_token 기반
    const r2 = verifyTenantPolicy('SELECT id FROM messages WHERE sender_token = ?', ['S1'], ctx, policy);
    assert.deepEqual(r2, { ok: true });

    // users — users.id 는 세션의 user_id 로 대조
    const r3 = verifyTenantPolicy('SELECT email FROM users WHERE id = ?', ['U1'], ctx, policy);
    assert.deepEqual(r3, { ok: true });

    // 값 mismatch 는 거부
    const r4 = verifyTenantPolicy('SELECT id FROM notos WHERE creator_token = ?', ['OTHER'], ctx, policy);
    assert.equal(r4.ok, false);
    assert.equal(r4.code, 'TENANT_MISMATCH');
});

test('verifyTenantPolicy: 테이블 명시 sessionClaim 이 없어도 컬럼명 fallback 으로 작동', () => {
    const policy = normalizePolicyConfig({
        enabled: true,
        mode: 'verify',
        sessionClaim: 'user_id',  // 전역
        tables: {
            // sessionClaim 명시 X — 엔진이 'creator_token' 이름으로 세션 조회 (fallback)
            notos: { tenantColumn: 'creator_token', mode: 'enforce' },
        },
    });
    const ctx = { creator_token: 'C1' }; // user_id 는 없음
    const r = verifyTenantPolicy(
        'SELECT id FROM notos WHERE creator_token = ?',
        ['C1'], ctx, policy
    );
    assert.deepEqual(r, { ok: true });
});

test('injectTenantPolicy: 테이블별 sessionClaim 기준으로 올바른 값 자동 주입', () => {
    const policy = normalizePolicyConfig({
        enabled: true,
        mode: 'inject',
        sessionClaim: 'user_id',
        strict: false,
        tables: {
            notos: { tenantColumn: 'creator_token', mode: 'inject', sessionClaim: 'creator_token' },
        },
    });
    const ctx = { creator_token: 'HASH-C1' };
    const r = injectTenantPolicy(
        'SELECT id, title FROM notos WHERE archived = 0',
        [], ctx, policy
    );
    assert.equal(r.ok, true);
    assert.equal(r.injected, true);
    // SQL 에 creator_token = ? 가 주입되고 params 끝에 HASH-C1 이 들어가야 함
    assert.match(r.sql, /creator_token\s*=\s*\?/i);
    assert.deepEqual(r.params, ['HASH-C1']);
});

test('verifyTenantPolicy: TENANT_MISSING 시 명시된 sessionClaim 이름을 에러에 노출', () => {
    const policy = normalizePolicyConfig({
        enabled: true,
        mode: 'verify',
        strict: false,
        tables: {
            notos: { tenantColumn: 'creator_token', mode: 'enforce', sessionClaim: 'creator_token' },
        },
    });
    const r = verifyTenantPolicy(
        'SELECT id FROM notos WHERE creator_token = ?',
        ['X'], /* ctx */ {}, policy
    );
    assert.equal(r.ok, false);
    assert.equal(r.code, 'TENANT_MISSING');
    assert.match(r.reason, /"creator_token"/);
});
