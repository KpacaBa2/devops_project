/**
 * Минимальный каркас Backend API (Node.js built-in http + crypto, 0 внешних зависимостей).
 * Роли:
 * 1. GET  /api/health          — проверка для Docker Compose healthcheck
 * 2. GET  /api/config          — публичная конфигурация (STORAGE_MODE, GOOGLE_CLIENT_ID)
 * 3. POST /api/auth/refresh    — пример проверки CSRF (Origin + X-Requested-With) и HttpOnly cookie cpv1_rt
 * 4. POST /api/sandbox/objects — простой REST для SandboxStorageAdapter:
 *    ПРИНИМАЕТ ТОЛЬКО зашифрованные пакеты CPV1 ("CPV1\x01") и ОТВЕРГАЕТ открытый JPEG ("FF D8 FF").
 */

import http from 'node:http';
import crypto from 'node:crypto';

const PORT = Number(process.env.PORT || 3000);
const APP_ORIGIN = process.env.APP_ORIGIN || 'http://localhost:18081';
const STORAGE_MODE = process.env.STORAGE_MODE || 'sandbox';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_BYTES || 5 * 1024 * 1024);

// Хранилище в памяти для CI/CD smoke-тестов (SandboxStorageAdapter)
const sandboxStore = new Map();

// Первые 5 байт формата CPV1: ASCII "CPV1" + 0x01
const CPV1_MAGIC = Buffer.from([0x43, 0x50, 0x56, 0x31, 0x01]);
// Первые 3 байта открытого JPEG: FF D8 FF
const JPEG_MAGIC = Buffer.from([0xff, 0xd8, 0xff]);
// Первые 4 байта открытого PNG: 89 50 4E 47
const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47]);

export function inspectUploadedBuffer(buf) {
  if (buf.length >= 3 && buf.subarray(0, 3).equals(JPEG_MAGIC)) {
    return { ok: false, error: 'PLAINTEXT_JPEG_REJECTED' };
  }
  if (buf.length >= 4 && buf.subarray(0, 4).equals(PNG_MAGIC)) {
    return { ok: false, error: 'PLAINTEXT_PNG_REJECTED' };
  }
  if (buf.length < 33 || !buf.subarray(0, 5).equals(CPV1_MAGIC)) {
    return { ok: false, error: 'MISSING_CPV1_HEADER' };
  }
  return { ok: true };
}

function sendJson(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

export const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (req.method === 'GET' && url.pathname === '/api/health') {
    return sendJson(res, 200, { status: 'ok', storageMode: STORAGE_MODE });
  }

  if (req.method === 'GET' && url.pathname === '/api/config') {
    return sendJson(res, 200, {
      storageMode: STORAGE_MODE,
      googleClientId: GOOGLE_CLIENT_ID,
      maxUploadBytes: MAX_UPLOAD_BYTES,
    });
  }

  // Защита от CSRF на всех POST /api/auth/* эндпоинтах: Origin + X-Requested-With
  if (req.method === 'POST' && url.pathname.startsWith('/api/auth/')) {
    const origin = req.headers['origin'];
    const xrw = req.headers['x-requested-with'];
    if (origin !== APP_ORIGIN || xrw !== 'CPV1-Client') {
      return sendJson(res, 403, { error: 'CSRF_VALIDATION_FAILED' });
    }
    return sendJson(res, 501, { error: 'AUTH_FLOW_STUB_READY_FOR_IMPLEMENTATION' });
  }

  // Простой REST для SandboxStorageAdapter: POST /api/sandbox/objects
  if (req.method === 'POST' && url.pathname === '/api/sandbox/objects') {
    const chunks = [];
    let total = 0;

    req.on('data', (chunk) => {
      total += chunk.length;
      if (total <= MAX_UPLOAD_BYTES + 1024) {
        chunks.push(chunk);
      }
    });

    req.on('end', () => {
      if (total > MAX_UPLOAD_BYTES) {
        return sendJson(res, 413, { error: 'PAYLOAD_TOO_LARGE' });
      }
      const buf = Buffer.concat(chunks);
      const check = inspectUploadedBuffer(buf);
      if (!check.ok) {
        return sendJson(res, 400, { error: check.error });
      }

      const id = crypto.randomUUID();
      const name = String(req.headers['x-object-name'] || `blob_${id}.enc`);
      sandboxStore.set(id, { id, name, data: buf });
      return sendJson(res, 201, { id, name, size: buf.length });
    });
    return;
  }

  // GET /api/sandbox/objects/:id
  if (req.method === 'GET' && url.pathname.startsWith('/api/sandbox/objects/')) {
    const id = url.pathname.split('/').pop();
    const record = sandboxStore.get(id);
    if (!record) {
      return sendJson(res, 404, { error: 'OBJECT_NOT_FOUND' });
    }
    res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
    return res.end(record.data);
  }

  return sendJson(res, 404, { error: 'NOT_FOUND' });
});

if (process.argv[1] && process.argv[1].endsWith('server.js')) {
  server.listen(PORT, () => {
    console.log(JSON.stringify({ level: 'info', event: 'api_started', port: PORT, storageMode: STORAGE_MODE }));
  });
}
