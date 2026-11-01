// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const LOCAL_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'local');
const LOCAL_HTML = readFileSync(path.join(LOCAL_DIR, 'confirm.html'), 'utf8');
const LOCAL_JS = readFileSync(path.join(LOCAL_DIR, 'app.js'), 'utf8');
const MAX_BODY_BYTES = 16 * 1024;

const ERROR_STATUS = {
  PAIRING_NOT_FOUND: 404,
  PAIRING_EXPIRED: 410,
  PAIRING_NOT_WAITING: 409,
  PAIRING_NOT_CLAIMED: 409,
  PAIRING_NOT_CONFIRMED: 409,
  PAIRING_NOT_CANCELLABLE: 409,
  PAIRING_PROOF_INVALID: 400,
  PROVISION_PROOF_INVALID: 400,
  SAS_MISMATCH: 400,
  PHONE_PUB_INVALID: 400,
  DEVICE_MISMATCH: 400,
  DEVICE_LIMIT: 429,
  DEVICE_NOT_FOUND: 404,
};

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'unsafe-inline'",
  "connect-src 'self'",
  "img-src 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
].join('; ');

function httpError(status, code) {
  const error = new Error(code);
  error.status = status;
  error.code = code;
  return error;
}

function safeEqualText(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function sendJson(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    ...extraHeaders,
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(payload);
}

function sendHtml(res, status, html) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(html),
    'Cache-Control': 'no-store',
    'Content-Security-Policy': CSP,
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(html);
}

function sendJs(res, status, js) {
  res.writeHead(status, {
    'Content-Type': 'application/javascript; charset=utf-8',
    'Content-Length': Buffer.byteLength(js),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(js);
}

async function readJson(req) {
  const type = String(req.headers['content-type'] ?? '').toLowerCase();
  if (!type.startsWith('application/json')) throw httpError(415, 'json_required');

  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw httpError(413, 'body_too_large');
    chunks.push(chunk);
  }
  if (size === 0) throw httpError(400, 'body_required');
  let parsed;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw httpError(400, 'invalid_json');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw httpError(400, 'invalid_json');
  }
  return parsed;
}

function checkHost(req, allowed) {
  if (!allowed.includes(req.headers.host)) throw httpError(403, 'forbidden');
}

function checkOrigin(req, allowed) {
  if (allowed.includes(req.headers.origin)) return;
  if (req.headers['sec-fetch-site'] === 'same-origin') return;
  throw httpError(403, 'forbidden');
}

function sendError(res, err, extraHeaders = {}) {
  const status = err.status ?? ERROR_STATUS[err.code] ?? 500;
  const code = status === 500 ? 'internal_error' : err.code ?? err.message ?? 'error';
  sendJson(res, status, { error: code }, extraHeaders);
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close(() => resolve());
    server.closeAllConnections?.();
  });
}

export function createBridgeServers({
  pairing,
  adminToken = randomBytes(24).toString('base64url'),
  host = '127.0.0.1',
  apiPort = 7788,
  localPort = 7789,
  version = '0.1.0',
  pwaOrigin = null,
} = {}) {
  if (!pairing) throw new TypeError('pairing is required');

  const allowedPwaOrigin = pwaOrigin ? new URL(pwaOrigin).origin : null;
  const localTokens = new Map();
  let actualApiPort = apiPort;
  let actualLocalPort = localPort;

  const allowedHosts = () => [`127.0.0.1:${actualLocalPort}`, `localhost:${actualLocalPort}`];
  const allowedOrigins = () => [`http://127.0.0.1:${actualLocalPort}`, `http://localhost:${actualLocalPort}`];

  function corsHeaders(req) {
    if (!allowedPwaOrigin || req.headers.origin !== allowedPwaOrigin) return {};
    return {
      'Access-Control-Allow-Origin': allowedPwaOrigin,
      'Access-Control-Allow-Methods': 'GET, POST',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '600',
      Vary: 'Origin',
    };
  }

  function checkAdmin(req) {
    if (!safeEqualText(req.headers['x-phonejob-admin'], adminToken)) {
      throw httpError(401, 'unauthorized');
    }
  }

  function requirePairToken(req, pairId) {
    if (!safeEqualText(req.headers['x-phonejob-pair-token'], localTokens.get(pairId))) {
      throw httpError(404, 'not_found');
    }
  }

  const apiServer = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://127.0.0.1');
      if (req.method === 'OPTIONS') {
        if (!allowedPwaOrigin || req.headers.origin !== allowedPwaOrigin) {
          res.writeHead(403);
          res.end();
          return;
        }
        res.writeHead(204, corsHeaders(req));
        res.end();
        return;
      }
      if (req.method === 'GET' && url.pathname === '/api/health') {
        const devices = pairing.listDevices();
        sendJson(
          res,
          200,
          {
            ok: true,
            version,
            paired_devices: devices.filter((device) => !device.revoked).length,
          },
          corsHeaders(req),
        );
        return;
      }
      if (req.method === 'POST' && url.pathname === '/api/pair/claim') {
        const body = await readJson(req);
        const result = await pairing.claimPairing({
          pairId: body.pair_id,
          phonePub: body.phone_pub,
          proof: body.proof,
        });
        sendJson(res, 200, result, corsHeaders(req));
        return;
      }
      if (req.method === 'POST' && url.pathname === '/api/pair/provision') {
        const body = await readJson(req);
        try {
          const envelope = await pairing.provisionOtp({
            pairId: body.pair_id,
            deviceId: body.device_id,
            proof: body.proof,
          });
          sendJson(res, 200, envelope, corsHeaders(req));
        } catch (err) {
          if (err.code === 'PAIRING_NOT_CONFIRMED') {
            sendJson(res, 202, { state: 'waiting' }, { ...corsHeaders(req), 'Retry-After': '1' });
            return;
          }
          throw err;
        }
        return;
      }
      sendJson(res, 404, { error: 'not_found' }, corsHeaders(req));
    } catch (err) {
      sendError(res, err, corsHeaders(req));
    }
  });

  const localServer = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://127.0.0.1');
      checkHost(req, allowedHosts());

      if (req.method === 'GET' && url.pathname === '/local/app.js') {
        sendJs(res, 200, LOCAL_JS);
        return;
      }

      const page = url.pathname.match(/^\/pair\/([A-Za-z0-9_-]+)$/);
      if (req.method === 'GET' && page) {
        if (!safeEqualText(url.searchParams.get('token'), localTokens.get(page[1]))) {
          throw httpError(404, 'not_found');
        }
        sendHtml(res, 200, LOCAL_HTML);
        return;
      }

      const status = url.pathname.match(/^\/api\/pair\/([A-Za-z0-9_-]+)$/);
      if (req.method === 'GET' && status) {
        requirePairToken(req, status[1]);
        sendJson(res, 200, pairing.getStatus(status[1]));
        return;
      }

      if (req.method === 'POST' && url.pathname === '/api/pair/start') {
        checkOrigin(req, allowedOrigins());
        checkAdmin(req);
        const body = await readJson(req);
        const result = await pairing.startPairing({ bridgeUrl: body.bridge_url });
        const token = randomBytes(24).toString('base64url');
        localTokens.set(result.pair_id, token);
        const localUrl = `http://127.0.0.1:${actualLocalPort}/pair/${result.pair_id}?token=${token}`;
        sendJson(res, 200, { ...result, local_url: localUrl });
        return;
      }

      const confirm = url.pathname.match(/^\/api\/pair\/([A-Za-z0-9_-]+)\/confirm$/);
      if (req.method === 'POST' && confirm) {
        checkOrigin(req, allowedOrigins());
        requirePairToken(req, confirm[1]);
        const body = await readJson(req);
        pairing.confirmPairing({ pairId: confirm[1], sas: body.sas });
        sendJson(res, 200, { ok: true });
        return;
      }

      const cancel = url.pathname.match(/^\/api\/pair\/([A-Za-z0-9_-]+)\/cancel$/);
      if (req.method === 'POST' && cancel) {
        checkOrigin(req, allowedOrigins());
        requirePairToken(req, cancel[1]);
        pairing.cancelPairing(cancel[1]);
        localTokens.delete(cancel[1]);
        sendJson(res, 200, { ok: true });
        return;
      }

      if (req.method === 'GET' && url.pathname === '/api/devices') {
        checkAdmin(req);
        sendJson(res, 200, { devices: pairing.listDevices() });
        return;
      }

      const device = url.pathname.match(/^\/api\/device\/(dev_[A-Za-z0-9_-]+)$/);
      if (req.method === 'DELETE' && device) {
        checkOrigin(req, allowedOrigins());
        checkAdmin(req);
        pairing.revokeDevice(device[1]);
        sendJson(res, 200, { ok: true });
        return;
      }

      sendJson(res, 404, { error: 'not_found' });
    } catch (err) {
      sendError(res, err);
    }
  });

  return {
    apiServer,
    localServer,
    adminToken,
    get apiPort() {
      return actualApiPort;
    },
    get localPort() {
      return actualLocalPort;
    },
    async start() {
      await Promise.all([listen(apiServer, apiPort, host), listen(localServer, localPort, host)]);
      actualApiPort = apiServer.address().port;
      actualLocalPort = localServer.address().port;
    },
    async close() {
      await Promise.all([closeServer(apiServer), closeServer(localServer)]);
    },
  };
}
