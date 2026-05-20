// backend/types/dokkebi.d.ts
// dokkebi 런타임 모듈 타입 선언
// 이 파일은 dokkebi:runtime / dokkebi-dsl 의 TypeScript 타입을 제공합니다.
// 실제 구현은 QuickJS WASM 런타임이 제공합니다 (별도 설치 불필요).

// ── dokkebi:runtime ───────────────────────────────────────────
declare module 'dokkebi:runtime' {
  export interface DokkebiContext {
    method: string;
    path: string;
    query: Record<string, string>;
    headers: Record<string, string>;
    params: Record<string, string>;
    body: any;
    rawBody: string;
    capability?: { token: string; proof: string; feature: string; exp: number; nonce: string; stateHash?: string | null };
    json(data: any, status?: number): DokkebiResponse;
    text(body: string, status?: number): DokkebiResponse;
    html(body: string, status?: number): DokkebiResponse;
    notFound(message?: string): DokkebiResponse;
    unauthorized(message?: string): DokkebiResponse;
    forbidden(message?: string): DokkebiResponse;
    badRequest(message?: string): DokkebiResponse;
    serverError(message?: string): DokkebiResponse;
    header(name: string, value: string): this;

    // ── Phase B — Sharding-aware DB API (단일 D1 모드에서는 동일 핸들 반환) ──
    /**
     * 샤드 키 객체로 단일 샤드 DB 핸들 반환.
     * 단일 D1 모드: 글로벌 db 와 동일한 핸들.
     * 샤딩 모드: dokkebi.config.js 의 strategy.key 값으로 결정적 라우팅.
     * 예) ctx.shardFor({ user_id: ctx.user.userId })
     */
    shardFor(key: Record<string, string | number | bigint>): DbBuilder;
    /** 글로벌 DB 핸들 (있으면) — 단일 D1 모드에서는 db 와 동일. */
    global(): DbBuilder | null;
    /**
     * 모든 샤드에 동일 작업 실행 (관제·집계용 명시 API).
     * 단일 D1 모드: fn 1번 호출.
     */
    fanout<R>(fn: (db: DbBuilder) => Promise<R>, opts?: { concurrency?: number }): Promise<R[]>;
    /**
     * 샤드 키 없이 사용하는 일반 핸들. 단일 D1: 모듈 db 와 동일.
     * 샤딩 모드: 첫 샤드로 라우팅 + 콘솔 워닝 (`shardFor({key})` 권장).
     */
    db(): DbBuilder;
  }

  export interface DokkebiResponse {
    status: number;
    body: string;
    headers: [string, string][];
  }

  export interface DbBuilder {
    select(table: any, columns?: string[]): QueryChain;
    insert(table: any, values: Record<string, any>): InsertChain;
    update(table: any, values: Record<string, any>): UpdateChain;
    delete(table: any): DeleteChain;
    raw(sql: string, params?: any[]): Promise<any[]>;
  }

  interface BaseChain {
    exec(): Promise<{ rows: any[]; affected: number; lastInsertId: any }>;
  }
  interface QueryChain extends BaseChain {
    where(condition: any): this;
    orderBy(col: any, dir?: 'asc' | 'desc'): this;
    limit(n: number): this;
    offset(n: number): this;
  }
  interface InsertChain extends BaseChain {
    returning(): this;
  }
  interface UpdateChain extends BaseChain {
    where(condition: any): this;
  }
  interface DeleteChain extends BaseChain {
    where(condition: any): this;
  }

  type RouteHandler = (ctx: DokkebiContext) => DokkebiResponse | Promise<DokkebiResponse | null | undefined> | null | undefined;

  export interface Router {
    get(path: string, ...handlers: RouteHandler[]): Router;
    post(path: string, ...handlers: RouteHandler[]): Router;
    put(path: string, ...handlers: RouteHandler[]): Router;
    patch(path: string, ...handlers: RouteHandler[]): Router;
    delete(path: string, ...handlers: RouteHandler[]): Router;
    use(fn: RouteHandler): Router;
  }

  export const router: Router;
  export const db: DbBuilder;
  export const capability: {
    unlock(feature: string, opts?: { stateHash?: string; state?: unknown; contextHash?: string; context?: unknown; jwt?: string }): Promise<{
      ok: boolean;
      capability?: { token: string; proof: string; feature: string; exp: number; nonce: string; stateHash?: string | null };
      error?: string;
      code?: string;
    }>;
  };

  export function use(fn: RouteHandler): void;
  export function cors(opts?: { origin?: string; methods?: string; headers?: string }): RouteHandler;
  export function logger(): RouteHandler;
  export function jwtAuth(secret: string, excludePaths?: string[]): RouteHandler;
  export function signJwt(payload: object, secret: string, expiresIn?: number): Promise<string>;
  export function verifyJwt(token: string, secret: string): Promise<Record<string, any>>;
}

// ── dokkebi-dsl ───────────────────────────────────────────────
declare module 'dokkebi-dsl' {
  export interface ColumnType {
    notNull(): this;
    primaryKey(): this;
    unique(): this;
    default(value: any): this;
    references(table: string, column?: string): this;
  }

  export const t: {
    text(): ColumnType;
    integer(): ColumnType;
    real(): ColumnType;
    blob(): ColumnType;
    boolean(): ColumnType;
    uuid(): ColumnType;
    timestamp(): ColumnType;
    json(): ColumnType;
    enum(values: string[]): ColumnType;
    serial(): ColumnType;
  };

  export function col(name: string, type: ColumnType): any;
  export function table(name: string, columns: Record<string, any>): any;
  export function createTableSql(tableDef: any): string;

  export function eq(col: any, value: any): any;
  export function neq(col: any, value: any): any;
  export function gt(col: any, value: any): any;
  export function gte(col: any, value: any): any;
  export function lt(col: any, value: any): any;
  export function lte(col: any, value: any): any;
  export function like(col: any, pattern: string): any;
  export function isNull(col: any): any;
  export function isNotNull(col: any): any;
  export function inList(col: any, values: any[]): any;
  export function and(...conditions: any[]): any;
  export function or(...conditions: any[]): any;
}

// ── dokkebi:client (프론트엔드 전용) ─────────────────────────
// v6.x+ 부터 window.dokkebi 전역 노출이 제거되었습니다 (XSS 표면 축소).
// 프론트엔드 코드는 반드시 이 가상 모듈에서 dokkebi 를 import 해야 합니다.
//
// 예: import { dokkebi } from 'dokkebi:client';
//     const res = await dokkebi.get('/api/users');
declare module 'dokkebi:client' {
  export interface DokkebiResponse {
    ok: boolean;
    status: number;
    body: string;
    json: any;
    error: string | null;
    headers: [string, string][];
  }

  export interface DokkebiClient {
    request(method: string, path: string, body?: any, headers?: Record<string, string>): Promise<DokkebiResponse>;
    request(opts: { method: string; path: string; body?: any; headers?: Record<string, string> }): Promise<DokkebiResponse>;
    get(path: string, headers?: Record<string, string>): Promise<DokkebiResponse>;
    post(path: string, body?: any, headers?: Record<string, string>): Promise<DokkebiResponse>;
    put(path: string, body?: any, headers?: Record<string, string>): Promise<DokkebiResponse>;
    delete(path: string, headers?: Record<string, string>): Promise<DokkebiResponse>;
    capability: {
      unlock(route: string, secret: string): Promise<{ ok: boolean; error?: string }>;
    };
    upload(file: File | Blob, targetPath?: string): Promise<{ opfsRef: string; size: number }>;
    download(opfsRef: string): Promise<string>;
    removeData(opfsRef: string): Promise<void>;
    removeDataDir(dirPath: string): Promise<void>;
    readonly opfsAvailable: boolean;
    /** 부트스트랩 초기화 완료를 명시적으로 기다림. 보통 자동 처리되므로 호출 불필요. */
    ready(): Promise<void>;
  }

  export const dokkebi: DokkebiClient;
  export default dokkebi;
}
