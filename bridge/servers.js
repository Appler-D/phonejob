// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import qrcode from 'qrcode-generator';

const LOCAL_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'local');
const LOCAL_HTML = readFileSync(path.join(LOCAL_DIR, 'confirm.html'), 'utf8');
const LOCAL_JS = readFileSync(path.join(LOCAL_DIR, 'app.js'), 'utf8');
const LOCAL_HOME_HTML = readFileSync(path.join(LOCAL_DIR, 'home.html'), 'utf8');
const LOCAL_HOME_JS = readFileSync(path.join(LOCAL_DIR, 'home.js'), 'utf8');
const LOCAL_HOME_CSS = readFileSync(path.join(LOCAL_DIR, 'home.css'), 'utf8');
const LOCAL_JOBS_HTML = readFileSync(path.join(LOCAL_DIR, 'jobs.html'), 'utf8');
const LOCAL_JOBS_JS = readFileSync(path.join(LOCAL_DIR, 'jobs.js'), 'utf8');
const LOCAL_JOBS_CSS = readFileSync(path.join(LOCAL_DIR, 'jobs.css'), 'utf8');
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
  JOB_INVALID: 400,
  JOB_DEVICE_REJECTED: 404,
  JOB_TIME_WINDOW: 400,
  JOB_OTP_INVALID: 400,
  JOB_WORKSPACE_NOT_ALLOWED: 400,
  JOB_FILES_UNSUPPORTED: 400,
  JOB_REPLAY: 409,
  JOB_INBOX_FAILED: 500,
  JOB_NOT_FOUND: 404,
  JOB_NOT_WAITING: 409,
  JOB_RESPONSE_INVALID: 400,
  JOB_STATUS_AUTH: 401,
  JOB_MOVE_FAILED: 500,
  JOB_RESULT_NOT_READY: 409,
  JOB_RESULT_BLOCKED: 409,
};

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "connect-src 'self'",
  "img-src 'self' data:",
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

function sendCss(res, status, css) {
  res.writeHead(status, {
    'Content-Type': 'text/css; charset=utf-8',
    'Content-Length': Buffer.byteLength(css),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(css);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => {
    switch (character) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      default:
        return '&#39;';
    }
  });
}

async function readJson(req, maxBytes = MAX_BODY_BYTES) {
  const type = String(req.headers['content-type'] ?? '').toLowerCase();
  if (!type.startsWith('application/json')) throw httpError(415, 'json_required');

  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw httpError(413, 'body_too_large');
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
  jobs = null,
  adminToken = randomBytes(24).toString('base64url'),
  host = '127.0.0.1',
  apiPort = 7788,
  localPort = 7789,
  version = '0.1.0',
  pwaOrigin = null,
  workspaces = [],
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
      'Access-Control-Allow-Headers':
        'Content-Type, X-PhoneJob-Device, X-PhoneJob-Ts, X-PhoneJob-Proof',
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
        const devices = await pairing.listDevices();
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
      if (req.method === 'POST' && url.pathname === '/api/job') {
        if (!jobs) {
          sendJson(res, 404, { error: 'not_found' }, corsHeaders(req));
          return;
        }
        const body = await readJson(req, 1024 * 1024);
        const result = await jobs.submit(body);
        sendJson(res, 200, result, corsHeaders(req));
        return;
      }
      const jobStatus = url.pathname.match(/^\/api\/job\/([A-Za-z0-9_-]{8,64})$/);
      if (req.method === 'GET' && jobStatus) {
        if (!jobs) {
          sendJson(res, 404, { error: 'not_found' }, corsHeaders(req));
          return;
        }
        const result = await jobs.getForDevice({
          jobId: jobStatus[1],
          deviceId: req.headers['x-phonejob-device'],
          ts: Number(req.headers['x-phonejob-ts']),
          proof: req.headers['x-phonejob-proof'],
        });
        sendJson(res, 200, result, corsHeaders(req));
        return;
      }
      const jobResult = url.pathname.match(/^\/api\/job\/([A-Za-z0-9_-]{8,64})\/result$/);
      if (req.method === 'GET' && jobResult) {
        if (!jobs) {
          sendJson(res, 404, { error: 'not_found' }, corsHeaders(req));
          return;
        }
        const result = await jobs.getResultForDevice({
          jobId: jobResult[1],
          deviceId: req.headers['x-phonejob-device'],
          ts: Number(req.headers['x-phonejob-ts']),
          proof: req.headers['x-phonejob-proof'],
        });
        sendJson(res, 200, result, corsHeaders(req));
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

      if (req.method === 'GET' && url.pathname === '/') {
        sendHtml(res, 200, LOCAL_HOME_HTML.replace('__ADMIN_TOKEN__', escapeHtml(adminToken)));
        return;
      }

      if (req.method === 'GET' && url.pathname === '/jobs') {
        sendHtml(res, 200, LOCAL_JOBS_HTML.replace('__ADMIN_TOKEN__', escapeHtml(adminToken)));
        return;
      }

      if (req.method === 'GET' && url.pathname === '/local/home.js') {
        sendJs(res, 200, LOCAL_HOME_JS);
        return;
      }

      if (req.method === 'GET' && url.pathname === '/local/home.css') {
        sendCss(res, 200, LOCAL_HOME_CSS);
        return;
      }

      if (req.method === 'GET' && url.pathname === '/local/jobs.js') {
        sendJs(res, 200, LOCAL_JOBS_JS);
        return;
      }

      if (req.method === 'GET' && url.pathname === '/local/jobs.css') {
        sendCss(res, 200, LOCAL_JOBS_CSS);
        return;
      }

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
        const qrPayload = { ...result.qr, workspaces };
        let pwaUrl = null;
        let qrDataUrl = null;
        if (allowedPwaOrigin) {
          const payload = Buffer.from(JSON.stringify(qrPayload), 'utf8').toString('base64url');
          pwaUrl = `${allowedPwaOrigin}/#pair=${payload}`;
          const qr = qrcode(0, 'M');
          qr.addData(pwaUrl);
          qr.make();
          const svg = qr.createSvgTag({ cellSize: 5, margin: 4 });
          qrDataUrl = `data:image/svg+xml;base64,${Buffer.from(svg, 'utf8').toString('base64')}`;
        }
        sendJson(res, 200, {
          ...result,
          qr: qrPayload,
          local_url: localUrl,
          pwa_url: pwaUrl,
          qr_data_url: qrDataUrl,
        });
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
        sendJson(res, 200, { devices: await pairing.listDevices() });
        return;
      }

      if (req.method === 'GET' && url.pathname === '/api/jobs') {
        if (!jobs) {
          sendJson(res, 404, { error: 'not_found' });
          return;
        }
        checkAdmin(req);
        sendJson(res, 200, { jobs: await jobs.listJobs() });
        return;
      }

      const jobDetail = url.pathname.match(/^\/api\/jobs\/([A-Za-z0-9_-]{8,64})$/);
      if (req.method === 'GET' && jobDetail) {
        if (!jobs) {
          sendJson(res, 404, { error: 'not_found' });
          return;
        }
        checkAdmin(req);
        sendJson(res, 200, await jobs.getJobDetail(jobDetail[1]));
        return;
      }

      const jobApprove = url.pathname.match(/^\/api\/jobs\/([A-Za-z0-9_-]{8,64})\/approve$/);
      if (req.method === 'POST' && jobApprove) {
        if (!jobs) {
          sendJson(res, 404, { error: 'not_found' });
          return;
        }
        checkOrigin(req, allowedOrigins());
        checkAdmin(req);
        const body = await readJson(req);
        sendJson(res, 200, await jobs.approveJob({ jobId: jobApprove[1], response: body.response }));
        return;
      }

      const jobReject = url.pathname.match(/^\/api\/jobs\/([A-Za-z0-9_-]{8,64})\/reject$/);
      if (req.method === 'POST' && jobReject) {
        if (!jobs) {
          sendJson(res, 404, { error: 'not_found' });
          return;
        }
        checkOrigin(req, allowedOrigins());
        checkAdmin(req);
        sendJson(res, 200, await jobs.rejectJob({ jobId: jobReject[1] }));
        return;
      }

      const device = url.pathname.match(/^\/api\/device\/(dev_[A-Za-z0-9_-]+)$/);
      if (req.method === 'DELETE' && device) {
        checkOrigin(req, allowedOrigins());
        checkAdmin(req);
        await pairing.revokeDevice(device[1]);
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
