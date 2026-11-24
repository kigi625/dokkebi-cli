/**
 * Local GIF encode via ffmpeg for dokkebi CLI (dok serve / dok).
 * POST /_dokkebi/gif  { frames: dataURL[], delayMs, width?, height? }
 * → { gif: "data:image/gif;base64,..." }
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawn } from 'child_process';
import { randomBytes } from 'crypto';
import { resolveClientIp } from './clientIp.js';

// ── DoS 방어 ────────────────────────────────────────────────
//   인증이 없는 로컬 도구 엔드포인트이므로 IP당 레이트리밋과 입력 검증을 둔다.
const _gifBuckets = new Map(); // ip → { tokens, refillAt }
const _GIF_RPM = 10;
function _gifRateLimited(ip) {
    const refillMs = Math.max(50, Math.floor(60_000 / _GIF_RPM));
    const now = Date.now();
    let b = _gifBuckets.get(ip);
    if (!b) {
        if (_gifBuckets.size > 1000) _gifBuckets.clear();
        b = { tokens: _GIF_RPM, refillAt: now };
        _gifBuckets.set(ip, b);
    }
    const n = Math.floor((now - b.refillAt) / refillMs);
    if (n > 0) { b.tokens = Math.min(_GIF_RPM, b.tokens + n); b.refillAt = now; }
    if (b.tokens <= 0) return true;
    b.tokens -= 1;
    return false;
}

// ffmpeg 는 확장자보다 내용을 우선 sniff 하므로, PNG 시그니처를 강제해
// 임의 포맷 파서(concat/playlist 등)로 확장되는 것을 막는다.
const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const MAX_FRAME_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES = 60 * 1024 * 1024;

function _decodePngFrame(frame) {
    const b64 = stripDataUrl(frame);
    if (!b64) return null;
    const buf = Buffer.from(b64, 'base64');
    if (buf.length < PNG_MAGIC.length || buf.length > MAX_FRAME_BYTES) return null;
    if (!buf.subarray(0, PNG_MAGIC.length).equals(PNG_MAGIC)) return null;
    return buf;
}

function readJsonBody(req, limit = 25_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('요청이 너무 큽니다.'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

function run(bin, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += String(d); });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve(undefined);
      else reject(new Error(stderr.slice(-800) || `ffmpeg exit ${code}`));
    });
  });
}

function stripDataUrl(value) {
  const m = String(value || '').match(/^data:image\/\w+;base64,(.+)$/);
  return m ? m[1] : String(value || '');
}

/**
 * @returns {boolean} true if handled
 */
export async function tryDokkebiGifEncode(req, res, opts = {}) {
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'POST only' }));
    return true;
  }

  const ip = resolveClientIp(req, { trustProxy: opts.trustProxy === true });
  if (_gifRateLimited(ip)) {
    res.writeHead(429, { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '60' });
    res.end(JSON.stringify({ error: 'GIF 인코딩 요청이 너무 많습니다. 잠시 후 다시 시도하세요.' }));
    return true;
  }

  let body;
  try {
    body = await readJsonBody(req);
  } catch (error) {
    res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: error.message || 'invalid body' }));
    return true;
  }

  const frames = Array.isArray(body.frames) ? body.frames : [];
  const delayMs = Math.max(40, Math.min(500, Number(body.delayMs) || 90));
  if (!frames.length || frames.length > 48) {
    res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'frames는 1~48개여야 합니다.' }));
    return true;
  }

  const dir = path.join(os.tmpdir(), `dokkebi-gif-${randomBytes(6).toString('hex')}`);
  fs.mkdirSync(dir, { recursive: true });
  try {
    const decoded = [];
    let total = 0;
    for (let i = 0; i < frames.length; i++) {
      const buf = _decodePngFrame(frames[i]);
      if (!buf) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: `frame ${i}: PNG 이미지가 아니거나 크기가 너무 큽니다.` }));
        return true;
      }
      total += buf.length;
      if (total > MAX_TOTAL_BYTES) {
        res.writeHead(413, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: '프레임 총 용량이 너무 큽니다.' }));
        return true;
      }
      decoded.push(buf);
    }
    decoded.forEach((buf, i) => {
      fs.writeFileSync(path.join(dir, `f${String(i).padStart(4, '0')}.png`), buf);
    });
    const fps = Math.max(2, Math.min(25, Math.round(1000 / delayMs)));
    const palette = path.join(dir, 'palette.png');
    const outGif = path.join(dir, 'out.gif');
    await run('ffmpeg', [
      '-nostdin', '-loglevel', 'error', '-y',
      '-framerate', String(fps), '-f', 'image2', '-i', 'f%04d.png',
      '-vf', 'palettegen=reserve_transparent=1', palette,
    ], dir);
    await run('ffmpeg', [
      '-nostdin', '-loglevel', 'error', '-y',
      '-framerate', String(fps), '-f', 'image2', '-i', 'f%04d.png', '-i', palette,
      '-lavfi', 'paletteuse=alpha_threshold=64',
      '-gifflags', '-offsetting', outGif,
    ], dir);
    const gifB64 = fs.readFileSync(outGif).toString('base64');
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ gif: `data:image/gif;base64,${gifB64}`, via: 'ffmpeg' }));
  } catch (error) {
    res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({
      error: error?.message?.includes('ENOENT')
        ? 'ffmpeg가 설치되어 있지 않습니다. (brew install ffmpeg)'
        : (error?.message || 'GIF 인코딩 실패'),
    }));
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  return true;
}
