/**
 * dok dev 전용: POST /_dokkebi/blog-media / GET /media/*
 * Cloudflare R2 대신 프로젝트 루트 .dev-blog-media/ 에 저장 (로컬 글쓰기 미리보기용)
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID, createHmac, timingSafeEqual } from 'node:crypto';
import { Readable } from 'node:stream';

function base64UrlDecode(s) {
  let padded = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4;
  if (pad) padded += '='.repeat(4 - pad);
  return Buffer.from(padded, 'base64');
}

/** WASM/worker blog-media.ts 와 동일한 HS256 JWT 검증 */
function verifyJwtHs256(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const signingInput = `${parts[0]}.${parts[1]}`;
  let sigExpected;
  try {
    sigExpected = base64UrlDecode(parts[2]);
  } catch {
    return null;
  }
  const expected = createHmac('sha256', secret).update(signingInput).digest();
  if (sigExpected.length !== expected.length || !timingSafeEqual(sigExpected, expected)) {
    return null;
  }
  try {
    const payloadJson = base64UrlDecode(parts[1]).toString('utf8');
    const payload = JSON.parse(payloadJson);
    const exp = payload.exp;
    if (typeof exp === 'number' && exp * 1000 < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function extFromType(type, fallback) {
  const t = (type || '').toLowerCase();
  if (t.includes('jpeg') || t.includes('jpg')) return 'jpg';
  if (t.includes('png')) return 'png';
  if (t.includes('webp')) return 'webp';
  if (t.includes('gif')) return 'gif';
  if (t.includes('mp4')) return 'mp4';
  if (t.includes('webm')) return 'webm';
  return fallback || 'bin';
}

function json(res, body, status = 200) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(JSON.stringify(body));
}

async function nodeRequestFormData(req) {
  const url = `http://127.0.0.1${req.url || '/'}`;
  const body = Readable.toWeb(req);
  const request = new Request(url, {
    method: req.method,
    headers: req.headers,
    body,
    duplex: 'half',
  });
  return request.formData();
}

const MIME = {
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
};

/**
 * @returns {Promise<boolean>} 처리했으면 true (caller는 return)
 */
export async function tryDevBlogMediaPost(req, res, { jwtSecret, mediaRoot }) {
  const urlPath = req.url?.split('?')[0] || '';
  if (urlPath !== '/_dokkebi/blog-media' || req.method !== 'POST') return false;

  if (!jwtSecret) {
    // dev.js 가 항상 기본값을 넘기므로 일반적으로 도달하지 않음
    json(res, { error: 'JWT 시크릿이 비어 있습니다.' }, 500);
    return true;
  }

  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token) {
    json(res, { error: '로그인이 필요합니다.' }, 401);
    return true;
  }

  const payload = verifyJwtHs256(token, jwtSecret);
  const uid = payload?.userId;
  const userId = uid != null && uid !== '' ? String(uid) : '';
  if (!userId) {
    json(res, { error: '유효하지 않은 토큰입니다.' }, 401);
    return true;
  }

  const ct = req.headers['content-type'] || '';
  if (!ct.toLowerCase().includes('multipart/form-data')) {
    json(res, { error: 'multipart/form-data 로 file 필드를 보내 주세요.' }, 400);
    return true;
  }

  let form;
  try {
    form = await nodeRequestFormData(req);
  } catch {
    json(res, { error: '폼 파싱 실패' }, 400);
    return true;
  }

  const file = form.get('file');
  if (!file || typeof file.arrayBuffer !== 'function') {
    json(res, { error: 'file 필드가 필요합니다.' }, 400);
    return true;
  }

  const maxBytes = 95 * 1024 * 1024;
  if (file.size > maxBytes) {
    json(res, { error: '파일은 95MB 이하여야 합니다.' }, 413);
    return true;
  }

  const ext = extFromType(file.type, (file.name && file.name.split('.').pop()) || 'bin');
  const allowed = new Set(['jpg', 'jpeg', 'png', 'webp', 'gif', 'mp4', 'webm']);
  const normExt = ext === 'jpeg' ? 'jpg' : ext;
  if (!allowed.has(normExt)) {
    json(res, { error: `허용되지 않는 형식입니다: ${normExt}` }, 400);
    return true;
  }

  const key = `pub/${randomUUID()}.${normExt}`;
  const outDir = path.join(mediaRoot, path.dirname(key));
  await fs.mkdir(outDir, { recursive: true });
  const outPath = path.join(mediaRoot, key);
  const buf = Buffer.from(await file.arrayBuffer());
  await fs.writeFile(outPath, buf);

  const url = `/media/${key}`;
  json(res, { ok: true, url });
  return true;
}

/**
 * @returns {Promise<boolean>}
 */
export async function tryDevBlogMediaGet(req, res, urlPath, mediaRoot) {
  if (req.method !== 'GET') return false;
  const prefix = '/media/';
  if (!urlPath.startsWith(prefix)) return false;

  let rel = urlPath.slice(prefix.length).replace(/^\/+/, '');
  if (!rel || rel.includes('..')) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad path');
    return true;
  }

  const filePath = path.join(mediaRoot, rel);
  const resolved = path.resolve(filePath);
  const rootResolved = path.resolve(mediaRoot);
  if (!resolved.startsWith(rootResolved + path.sep) && resolved !== rootResolved) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad path');
    return true;
  }

  try {
    const data = await fs.readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME[ext] || 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'public, max-age=31536000, immutable',
      'Access-Control-Allow-Origin': '*',
    });
    res.end(data);
    return true;
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
    return true;
  }
}
