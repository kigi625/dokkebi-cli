/**
 * WIT (WebAssembly Interface Types) 기반 인터페이스 생성기
 *
 * Host-side Model + Guest-side Controller 패턴 구현:
 * - Host (브라우저 JS): DB 자격증명 보관, HTTPS 호출 실행
 * - Guest (QuickJS WASM): 라우터/컨트롤러 로직 실행
 *
 * WIT 파일을 파싱하여 JS 바인딩 글루 코드를 자동 생성합니다.
 */

import fs from 'fs/promises';
import path from 'path';

// ─────────────────────────────────────────────────────────────
// WIT 파일 내용 (pakage dokkebi:backend)
// ─────────────────────────────────────────────────────────────

export const DOKKEBI_WIT_CONTENT = `\
package dokkebi:backend@1.0.0;

// ──────────────────────────────────────────────────
// Host → Guest 로 import 되는 인터페이스
// 브라우저(Host)가 실제 구현을 제공하고,
// QuickJS(Guest)는 이 함수들을 호출만 합니다.
// ──────────────────────────────────────────────────

interface host-db {
  /// DB 쿼리 결과 레코드
  record query-result {
    rows: list<string>;
    affected: u32;
    last-insert-id: option<u64>;
  }

  /// Opaque Handle 기반 쿼리 실행
  /// handle-id: 실제 자격증명을 대신하는 숫자 핸들 (Host만 알고 있음)
  db-execute: func(
    handle-id: u32,
    sql: string,
    params: list<string>
  ) -> result<query-result, string>;

  /// 트랜잭션 일괄 실행
  db-transaction: func(
    handle-id: u32,
    statements: list<tuple<string, list<string>>>
  ) -> result<u32, string>;

  /// 테이블 존재 여부 확인 (마이그레이션용)
  db-table-exists: func(handle-id: u32, table-name: string) -> bool;
}

interface host-crypto {
  /// 브라우저 SubtleCrypto 위임
  random-bytes: func(len: u32) -> list<u8>;
  hash-sha256: func(data: list<u8>) -> list<u8>;
  /// HMAC-SHA256 서명 (JWT 서명 등)
  hmac-sign: func(key: list<u8>, data: list<u8>) -> list<u8>;
  /// 현재 Unix timestamp (ms)
  now-millis: func() -> u64;
}

interface host-kv {
  /// 세션 스토어 (sessionStorage 기반, WASM 외부에서 관리)
  kv-get: func(key: string) -> option<string>;
  kv-set: func(key: string, value: string, ttl-secs: option<u32>);
  kv-delete: func(key: string);
}

// ──────────────────────────────────────────────────
// Guest → Host 로 export 되는 인터페이스
// QuickJS(Guest)가 구현하고 브라우저(Host)가 호출합니다.
// ──────────────────────────────────────────────────

interface guest-router {
  /// HTTP 요청 레코드
  record request {
    method: string;
    path: string;
    query: string;
    body: string;
    headers: list<tuple<string, string>>;
  }

  /// HTTP 응답 레코드
  record response {
    status: u16;
    body: string;
    headers: list<tuple<string, string>>;
  }

  /// 라우터 초기화 (DB 핸들 등록)
  init: func(db-handle: u32, db-type: string) -> result<_, string>;

  /// 요청 처리 진입점
  handle-request: func(req: request) -> response;
}

interface guest-schema {
  /// 스키마 마이그레이션 실행 (DDL 생성)
  migrate: func(handle-id: u32) -> result<list<string>, string>;
}

// ──────────────────────────────────────────────────
// World 정의: 컴포넌트 전체 인터페이스
// ──────────────────────────────────────────────────

world dokkebi-backend {
  // Host가 제공하는 기능 (WASM이 import)
  import host-db;
  import host-crypto;
  import host-kv;

  // Guest가 제공하는 기능 (Host가 호출)
  export guest-router;
  export guest-schema;
}
`;

// ─────────────────────────────────────────────────────────────
// Host-side JS 바인딩 생성 (브라우저에서 실행)
// ─────────────────────────────────────────────────────────────

/**
 * Host-side 바인딩 JS 생성
 * QuickJS WASM이 import하는 함수들의 실제 구현을 담은 JS 코드를 생성합니다.
 *
 * @param {object} options
 * @param {string} options.dbType - 'd1' | 'supabase' | 'appwrite'
 * @returns {string} - 브라우저에서 실행될 호스트 바인딩 JS
 */
export function generateHostBindings(options = {}) {
    const { dbType = 'd1' } = options;

    return `
// ─── dokkebi Host Bindings (자동 생성됨) ───────────────────
// WIT 인터페이스: host-db, host-crypto, host-kv
// 이 코드는 브라우저에서 실행됩니다. WASM 외부에서만 자격증명을 보유합니다.

(function (globalThis) {
  'use strict';

  // ── Opaque Handle 스토어 ────────────────────────────────
  // WASM 메모리에는 절대 노출되지 않는 자격증명 저장소
  const _handleStore = new Map();
  let _nextHandle = 1;

  function _createHandle(credentials) {
    const id = _nextHandle++;
    _handleStore.set(id, Object.freeze({ ...credentials }));
    return id;
  }

  function _resolveHandle(id) {
    const creds = _handleStore.get(id);
    if (!creds) throw new Error(\`[dokkebi] Invalid DB handle: \${id}\`);
    return creds;
  }

  // ── host-db 인터페이스 구현 ─────────────────────────────

  const hostDb = {
    async dbExecute(handleId, sql, params) {
      const creds = _resolveHandle(handleId);
      try {
        const rows = await _dbDispatch(creds, sql, params);
        return { ok: true, value: rows };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    },

    async dbTransaction(handleId, statements) {
      const creds = _resolveHandle(handleId);
      try {
        let count = 0;
        for (const [sql, params] of statements) {
          await _dbDispatch(creds, sql, params);
          count++;
        }
        return { ok: true, value: count };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    },

    async dbTableExists(handleId, tableName) {
      const creds = _resolveHandle(handleId);
      try {
        const result = await _dbDispatch(
          creds,
          "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
          [tableName]
        );
        return result.rows.length > 0;
      } catch {
        return false;
      }
    },
  };

  // ── DB 벤더별 HTTPS 호출 디스패처 ─────────────────────

  async function _dbDispatch(creds, sql, params) {
    switch (creds.type) {
      case 'd1':        return _d1Execute(creds, sql, params);
      case 'supabase':  return _supabaseExecute(creds, sql, params);
      case 'appwrite':  return _appwriteExecute(creds, sql, params);
      default:
        throw new Error(\`[dokkebi] 알 수 없는 DB 타입: \${creds.type}\`);
    }
  }

  async function _d1Execute(creds, sql, params) {
    const url = \`\${creds.apiBase}/accounts/\${creds.accountId}/d1/database/\${creds.databaseId}/query\`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: \`Bearer \${creds.apiToken}\`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ sql, params }),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(\`D1 오류 (\${res.status}): \${err}\`);
    }
    const json = await res.json();
    const result = json.result?.[0] || {};
    return {
      rows: (result.results || []).map((r) => JSON.stringify(r)),
      affected: result.meta?.changes ?? 0,
      lastInsertId: result.meta?.last_row_id ?? null,
    };
  }

  async function _supabaseExecute(creds, sql, params) {
    // Supabase PostgreSQL REST (pg-meta RPC)
    const url = \`\${creds.supabaseUrl}/rest/v1/rpc/execute_sql\`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        apikey: creds.anonKey,
        Authorization: \`Bearer \${creds.serviceKey || creds.anonKey}\`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ query: sql, params }),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(\`Supabase 오류 (\${res.status}): \${err}\`);
    }
    const rows = await res.json();
    return {
      rows: (Array.isArray(rows) ? rows : [rows]).map((r) => JSON.stringify(r)),
      affected: rows.length || 0,
      lastInsertId: null,
    };
  }

  async function _appwriteExecute(creds, sql, params) {
    // Appwrite Databases REST API
    const url = \`\${creds.endpoint}/v1/databases/\${creds.databaseId}/collections\`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'X-Appwrite-Project': creds.projectId,
        'X-Appwrite-Key': creds.apiKey,
        'Content-Type': 'application/json',
      },
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(\`Appwrite 오류 (\${res.status}): \${err}\`);
    }
    const data = await res.json();
    return {
      rows: (data.documents || []).map((r) => JSON.stringify(r)),
      affected: data.total || 0,
      lastInsertId: null,
    };
  }

  // ── host-crypto 인터페이스 구현 ──────────────────────────

  const hostCrypto = {
    randomBytes(len) {
      return Array.from(crypto.getRandomValues(new Uint8Array(len)));
    },
    async hashSha256(data) {
      const buf = await crypto.subtle.digest('SHA-256', new Uint8Array(data));
      return Array.from(new Uint8Array(buf));
    },
    async hmacSign(key, data) {
      const cryptoKey = await crypto.subtle.importKey(
        'raw', new Uint8Array(key),
        { name: 'HMAC', hash: 'SHA-256' },
        false, ['sign']
      );
      const sig = await crypto.subtle.sign('HMAC', cryptoKey, new Uint8Array(data));
      return Array.from(new Uint8Array(sig));
    },
    nowMillis() {
      return BigInt(Date.now());
    },
  };

  // ── host-kv 인터페이스 구현 (sessionStorage 기반) ────────

  const hostKv = {
    kvGet(key) {
      return sessionStorage.getItem('dokkebi:' + key) ?? undefined;
    },
    kvSet(key, value, ttlSecs) {
      const entry = ttlSecs
        ? JSON.stringify({ v: value, exp: Date.now() + ttlSecs * 1000 })
        : value;
      sessionStorage.setItem('dokkebi:' + key, entry);
    },
    kvDelete(key) {
      sessionStorage.removeItem('dokkebi:' + key);
    },
  };

  // ── 공개 API ────────────────────────────────────────────
  // QuickJS WASM 초기화 시 이 객체를 import 함수로 주입합니다.

  globalThis.__DOKKEBI_HOST__ = {
    createHandle: _createHandle,
    hostDb,
    hostCrypto,
    hostKv,
  };

})(globalThis);
`;
}

// ─────────────────────────────────────────────────────────────
// Guest-side TypeScript 타입 정의 생성 (백엔드 개발자용)
// ─────────────────────────────────────────────────────────────

export function generateGuestTypes() {
    return `\
// 자동 생성된 파일 — 수정하지 마세요
// dokkebi WIT 인터페이스 타입 정의 (Guest-side)

export interface QueryResult {
  rows: string[];    // JSON 직렬화된 행
  affected: number;
  lastInsertId: bigint | null;
}

export interface DokkebiRequest {
  method: string;
  path: string;
  query: string;
  body: string;
  headers: [string, string][];
}

export interface DokkebiResponse {
  status: number;
  body: string;
  headers: [string, string][];
}

// Host가 주입하는 함수 타입 (WASM에서 import)
export interface HostDb {
  dbExecute(handleId: number, sql: string, params: string[]): Promise<{ ok: true; value: QueryResult } | { ok: false; error: string }>;
  dbTransaction(handleId: number, statements: [string, string[]][]): Promise<{ ok: true; value: number } | { ok: false; error: string }>;
  dbTableExists(handleId: number, tableName: string): Promise<boolean>;
}

export interface HostCrypto {
  randomBytes(len: number): number[];
  hashSha256(data: number[]): Promise<number[]>;
  hmacSign(key: number[], data: number[]): Promise<number[]>;
  nowMillis(): bigint;
}

export interface HostKv {
  kvGet(key: string): string | undefined;
  kvSet(key: string, value: string, ttlSecs?: number): void;
  kvDelete(key: string): void;
}

// 런타임에 주입되는 전역 컨텍스트
export interface DokkebiRuntime {
  db: HostDb;
  crypto: HostCrypto;
  kv: HostKv;
  dbHandle: number;
  dbType: 'd1' | 'supabase' | 'appwrite';
}
`;
}

// ─────────────────────────────────────────────────────────────
// 파일 출력 헬퍼
// ─────────────────────────────────────────────────────────────

/**
 * WIT 파일 및 타입 바인딩을 지정 경로에 출력합니다.
 * @param {string} witDir - WIT 파일 출력 디렉토리
 * @param {object} options - { dbType }
 */
export async function emitWitFiles(witDir, options = {}) {
    await fs.mkdir(witDir, { recursive: true });

    // WIT 인터페이스 파일
    await fs.writeFile(
        path.join(witDir, 'dokkebi.wit'),
        DOKKEBI_WIT_CONTENT,
        'utf-8'
    );

    // Host-side 바인딩 JS
    await fs.writeFile(
        path.join(witDir, 'host-bindings.js'),
        generateHostBindings(options),
        'utf-8'
    );

    // Guest-side TypeScript 타입
    await fs.writeFile(
        path.join(witDir, 'types.d.ts'),
        generateGuestTypes(),
        'utf-8'
    );

    return {
        wit: path.join(witDir, 'dokkebi.wit'),
        hostBindings: path.join(witDir, 'host-bindings.js'),
        guestTypes: path.join(witDir, 'types.d.ts'),
    };
}
