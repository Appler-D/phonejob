// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import http from 'node:http';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PairingService } from '../bridge/pairing.js';
import { JobService } from '../bridge/job-service.js';
import { MemoryJobStore } from '../bridge/job-store.js';
import { createBridgeServers } from '../bridge/servers.js';
import {
  canonicalJson,
  computeSas,
  derivePairingKeys,
  deriveSharedSecret,
  generatePairingKeyPair,
  hmacSha256Base64Url,
  importPeerPublicKey,
  openEnvelope,
  openOtpProvisioning,
  pairingTranscript,
  sealEnvelope,
} from '../bridge/crypto.js';
import { computeConfirmationResponse } from '../bridge/confirm.js';
import { generateOtpSecret } from '../bridge/key-store.js';
import { totp } from '../bridge/totp.js';

function request(base, pathname, { method = 'GET', headers = {}, body, hostHeader } = {}) {
  const url = new URL(pathname, base);
  return new Promise((resolve, reject) => {
    const finalHeaders = { ...headers };
    if (body !== undefined) finalHeaders['Content-Length'] = Buffer.byteLength(body);
    if (hostHeader) finalHeaders.Host = hostHeader;
    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method,
        headers: finalHeaders,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function parse(response) {
  return JSON.parse(response.body);
}

async function setup(t, { pwaOrigin = null } = {}) {
  const otpSecret = generateOtpSecret();
  const loadOtp = async () => ({ secret: otpSecret, keyId: 'key-test' });
  const pairing = new PairingService({ loadOtp });
  const inboxDir = await mkdtemp(path.join(os.tmpdir(), 'phonejob-http-inbox-'));
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'phonejob-http-ws-'));
  t.after(() => rm(inboxDir, { recursive: true, force: true }));
  t.after(() => rm(workspace, { recursive: true, force: true }));

  const jobs = new JobService({
    deviceStore: pairing.deviceStore,
    jobStore: new MemoryJobStore(),
    loadOtp,
    inboxDir,
    workspaceAllowlist: [workspace],
  });
  const servers = createBridgeServers({
    pairing,
    jobs,
    adminToken: 'test-admin',
    apiPort: 0,
    localPort: 0,
    version: 'test',
    pwaOrigin,
    workspaces: [workspace],
  });
  await servers.start();
  t.after(() => servers.close());

  const api = `http://127.0.0.1:${servers.apiPort}`;
  const local = `http://127.0.0.1:${servers.localPort}`;
  return { pairing, jobs, servers, otpSecret, api, local, inboxDir, workspace };
}

async function startPairing(local, overrides = {}) {
  return request(local, '/api/pair/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-PhoneJob-Admin': 'test-admin',
      Origin: local,
      ...overrides.headers,
    },
    body: overrides.body ?? JSON.stringify({ bridge_url: 'https://bridge.test' }),
  });
}

async function claimPhone(api, start) {
  const phone = await generatePairingKeyPair();
  const phonePub = Buffer.from(phone.publicRaw).toString('base64url');
  const pcPublicKey = await importPeerPublicKey(Buffer.from(start.pc_pub, 'base64url'));
  const shared = await deriveSharedSecret(phone.privateKey, pcPublicKey);
  const keys = await derivePairingKeys(shared, start.pair_id);
  const proof = await hmacSha256Base64Url(
    keys.kSas,
    canonicalJson({ type: 'pair-claim', pair_id: start.pair_id, phone_pub: phonePub }),
  );
  const response = await request(api, '/api/pair/claim', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pair_id: start.pair_id, phone_pub: phonePub, proof }),
  });
  assert.equal(response.status, 200, response.body);
  const claim = parse(response);
  const transcript = pairingTranscript({
    pairId: start.pair_id,
    pcPub: start.pc_pub,
    phonePub,
    nonce: start.nonce,
    expiresAt: start.expires_at,
  });
  const sas = await computeSas(keys.kSas, transcript);
  const provisionProof = () =>
    hmacSha256Base64Url(
      keys.kConfirm,
      canonicalJson({
        type: 'otp-provision-request',
        pair_id: start.pair_id,
        device_id: claim.device_id,
      }),
    );
  return { phone, phonePub, keys, claim, sas, provisionProof };
}

test('HTTP pairing flow delivers the PC-generated K_otp', async (t) => {
  const { api, local, jobs, otpSecret, inboxDir, workspace } = await setup(t);

  const healthBefore = await request(api, '/api/health');
  assert.equal(healthBefore.status, 200);
  assert.equal(parse(healthBefore).paired_devices, 0);

  const startResponse = await startPairing(local);
  assert.equal(startResponse.status, 200, startResponse.body);
  const start = parse(startResponse);
  const localUrl = new URL(start.local_url);
  const token = localUrl.searchParams.get('token');
  assert.ok(token);

  const page = await request(local, localUrl.pathname + localUrl.search);
  assert.equal(page.status, 200);
  assert.match(page.body, /PhoneJob 配对确认/);
  assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);
  assert.equal(page.headers['x-frame-options'], 'DENY');

  const phone = await claimPhone(api, start);
  const status = await request(local, `/api/pair/${start.pair_id}`, {
    headers: { 'X-PhoneJob-Pair-Token': token },
  });
  assert.equal(status.status, 200);
  const statusBody = parse(status);
  assert.equal(statusBody.state, 'claimed');
  assert.equal(statusBody.sas, phone.sas);

  const confirm = await request(local, `/api/pair/${start.pair_id}/confirm`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-PhoneJob-Pair-Token': token,
      Origin: local,
    },
    body: JSON.stringify({ sas: phone.sas }),
  });
  assert.equal(confirm.status, 200, confirm.body);

  const provision = await request(api, '/api/pair/provision', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      pair_id: start.pair_id,
      device_id: phone.claim.device_id,
      proof: await phone.provisionProof(),
    }),
  });
  assert.equal(provision.status, 200, provision.body);
  const received = await openOtpProvisioning(phone.keys.kEnc, parse(provision));
  assert.equal(received.otpSecret.equals(otpSecret), true);

  const refreshTs = Math.floor(Date.now() / 1000);
  const refreshProof = await hmacSha256Base64Url(
    phone.keys.kAuth,
    canonicalJson({
      type: 'otp-refresh-v1',
      device_id: phone.claim.device_id,
      ts: refreshTs,
    }),
  );
  const refresh = await request(api, '/api/device/otp', {
    headers: {
      'X-PhoneJob-Device': phone.claim.device_id,
      'X-PhoneJob-Ts': String(refreshTs),
      'X-PhoneJob-Proof': refreshProof,
    },
  });
  assert.equal(refresh.status, 200, refresh.body);
  const openedRefresh = await openEnvelope(phone.keys.kEnc, parse(refresh));
  const refreshPayload = JSON.parse(Buffer.from(openedRefresh.plaintext).toString('utf8'));
  assert.equal(refreshPayload.type, 'otp-refresh-v1');
  assert.equal(refreshPayload.device_id, phone.claim.device_id);
  assert.equal(Buffer.from(refreshPayload.k_otp, 'base64url').equals(otpSecret), true);

  const jobNow = Date.now();
  const jobId = 'job_http_1';
  const job = {
    version: 1,
    job_id: jobId,
    device_id: phone.claim.device_id,
    target: { workspace, preset: 'default', session: null },
    intent: 'ask',
    text: 'hello http',
    files: [],
    reply: { want: 'text', max_bytes: 1024 },
  };
  const header = {
    v: 2,
    job_id: jobId,
    device_id: phone.claim.device_id,
    ts: Math.floor(jobNow / 1000),
    seq: 1,
    otp: totp(otpSecret, jobNow),
  };
  const envelope = await sealEnvelope(phone.keys.kEnc, header, JSON.stringify(job));
  const jobResponse = await request(api, '/api/job', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(envelope),
  });
  assert.equal(jobResponse.status, 200, jobResponse.body);
  assert.equal(parse(jobResponse).state, 'WAITING_CONFIRM');
  const pending = JSON.parse(
    await readFile(path.join(inboxDir, 'pending', jobId, 'job.json'), 'utf8'),
  );
  assert.equal(pending.text, 'hello http');
  await jobs.jobStore.saveAuthFailure({
    deviceId: phone.claim.device_id,
    failures: 3,
    windowStartedAt: Date.now(),
    lockedUntil: Date.now() + 300_000,
  });
  const jobList = await request(local, '/api/jobs', {
    headers: { 'X-PhoneJob-Admin': 'test-admin' },
  });
  assert.equal(jobList.status, 200);
  assert.equal(parse(jobList).jobs.length, 1);
  assert.equal(parse(jobList).locks.length, 1);
  assert.equal(parse(jobList).locks[0].failures, 3);
  await jobs.jobStore.clearAuthFailures(phone.claim.device_id);
  assert.equal(parse(jobList).jobs[0].job_id, jobId);

  const statusTs = Math.floor(Date.now() / 1000);
  const statusProof = await hmacSha256Base64Url(
    phone.keys.kAuth,
    canonicalJson({
      type: 'job-status-v1',
      device_id: phone.claim.device_id,
      job_id: jobId,
      ts: statusTs,
    }),
  );
  const phoneStatus = await request(api, `/api/job/${jobId}`, {
    headers: {
      'X-PhoneJob-Device': phone.claim.device_id,
      'X-PhoneJob-Ts': String(statusTs),
      'X-PhoneJob-Proof': statusProof,
    },
  });
  assert.equal(phoneStatus.status, 200, phoneStatus.body);
  const jobStatusBody = parse(phoneStatus);
  assert.equal(jobStatusBody.state, 'WAITING_CONFIRM');
  assert.match(jobStatusBody.challenge, /^\d{6}$/);
  assert.ok(jobStatusBody.job_hash);

  const detail = await request(local, `/api/jobs/${jobId}`, {
    headers: { 'X-PhoneJob-Admin': 'test-admin' },
  });
  assert.equal(detail.status, 200);
  const detailBody = parse(detail);
  assert.equal(detailBody.content.text, 'hello http');
  assert.equal(detailBody.challenge, jobStatusBody.challenge);
  assert.equal(detailBody.job_hash, jobStatusBody.job_hash);

  const expectedResponse = computeConfirmationResponse(
    phone.keys.kConfirm,
    jobStatusBody.job_hash,
    jobStatusBody.challenge,
  );
  const wrongResponse = expectedResponse === 'AAAAAAAA' ? 'BBBBBBBB' : 'AAAAAAAA';
  const wrongApprove = await request(local, `/api/jobs/${jobId}/approve`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-PhoneJob-Admin': 'test-admin',
      Origin: local,
    },
    body: JSON.stringify({ response: wrongResponse }),
  });
  assert.equal(wrongApprove.status, 400);
  assert.equal(parse(wrongApprove).error, 'JOB_RESPONSE_INVALID');

  const approve = await request(local, `/api/jobs/${jobId}/approve`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-PhoneJob-Admin': 'test-admin',
      Origin: local,
    },
    body: JSON.stringify({ response: expectedResponse }),
  });
  assert.equal(approve.status, 200, approve.body);
  assert.equal(parse(approve).state, 'QUEUED');
  const approvedJson = JSON.parse(
    await readFile(path.join(inboxDir, 'approved', jobId, 'job.json'), 'utf8'),
  );
  assert.equal(approvedJson.text, 'hello http');
  await assert.rejects(() => readFile(path.join(inboxDir, 'pending', jobId, 'job.json')));
  const jobListAfter = await request(local, '/api/jobs', {
    headers: { 'X-PhoneJob-Admin': 'test-admin' },
  });
  assert.equal(parse(jobListAfter).jobs[0].state, 'QUEUED');
  const statusAfter = await request(api, `/api/job/${jobId}`, {
    headers: {
      'X-PhoneJob-Device': phone.claim.device_id,
      'X-PhoneJob-Ts': String(statusTs),
      'X-PhoneJob-Proof': statusProof,
    },
  });
  assert.equal(statusAfter.status, 200);
  assert.equal(parse(statusAfter).state, 'QUEUED');

  const resultDir = path.join(inboxDir, 'done', jobId);
  await mkdir(path.join(resultDir, 'files'), { recursive: true });
  const resultFileBytes = Buffer.from('the answer as a file');
  const resultFileSha = createHash('sha256').update(resultFileBytes).digest('base64url');
  await writeFile(path.join(resultDir, 'files', '0'), resultFileBytes);
  await writeFile(
    path.join(resultDir, 'result.json'),
    JSON.stringify({
      job_id: jobId,
      status: 'done',
      finished_at: new Date().toISOString(),
      text: 'the answer',
      files: [{ name: 'answer.md', size: resultFileBytes.length, sha256: resultFileSha }],
      error: null,
    }),
  );
  const completed = await jobs.scanResults();
  assert.equal(completed.length, 1);
  assert.equal(completed[0].state, 'DONE');

  const finalStatus = await request(api, `/api/job/${jobId}`, {
    headers: {
      'X-PhoneJob-Device': phone.claim.device_id,
      'X-PhoneJob-Ts': String(statusTs),
      'X-PhoneJob-Proof': statusProof,
    },
  });
  assert.equal(finalStatus.status, 200);
  assert.equal(parse(finalStatus).state, 'DONE');

  const resultTs = Math.floor(Date.now() / 1000);
  const resultProof = await hmacSha256Base64Url(
    phone.keys.kAuth,
    canonicalJson({
      type: 'job-result-v1',
      device_id: phone.claim.device_id,
      job_id: jobId,
      ts: resultTs,
    }),
  );
  const resultResponse = await request(api, `/api/job/${jobId}/result`, {
    headers: {
      'X-PhoneJob-Device': phone.claim.device_id,
      'X-PhoneJob-Ts': String(resultTs),
      'X-PhoneJob-Proof': resultProof,
    },
  });
  assert.equal(resultResponse.status, 200, resultResponse.body);
  const openedResult = await openEnvelope(phone.keys.kEnc, parse(resultResponse));
  const resultBody = JSON.parse(Buffer.from(openedResult.plaintext).toString('utf8'));
  assert.equal(resultBody.text, 'the answer');
  assert.equal(resultBody.files.length, 1);
  assert.equal(resultBody.files[0].name, 'answer.md');

  const fileTs = Math.floor(Date.now() / 1000);
  const fileProof = await hmacSha256Base64Url(
    phone.keys.kAuth,
    canonicalJson({
      type: 'job-result-file-v1',
      device_id: phone.claim.device_id,
      job_id: jobId,
      ts: fileTs,
      file_index: 0,
    }),
  );
  const fileResponse = await request(api, `/api/job/${jobId}/result/file/0`, {
    headers: {
      'X-PhoneJob-Device': phone.claim.device_id,
      'X-PhoneJob-Ts': String(fileTs),
      'X-PhoneJob-Proof': fileProof,
    },
  });
  assert.equal(fileResponse.status, 200, fileResponse.body);
  const openedFile = await openEnvelope(phone.keys.kEnc, parse(fileResponse));
  assert.equal(openedFile.header.type, 'job-result-file-v1');
  assert.equal(openedFile.header.file_index, 0);
  assert.equal(openedFile.header.sha256, resultFileSha);
  assert.equal(Buffer.from(openedFile.plaintext).equals(resultFileBytes), true);

  const swappedFile = await request(api, `/api/job/${jobId}/result/file/1`, {
    headers: {
      'X-PhoneJob-Device': phone.claim.device_id,
      'X-PhoneJob-Ts': String(fileTs),
      'X-PhoneJob-Proof': fileProof,
    },
  });
  assert.equal(swappedFile.status, 401);
  assert.equal(parse(swappedFile).error, 'JOB_STATUS_AUTH');
  const jobListDone = await request(local, '/api/jobs', {
    headers: { 'X-PhoneJob-Admin': 'test-admin' },
  });
  assert.equal(parse(jobListDone).jobs[0].state, 'DONE');

  const healthAfter = await request(api, '/api/health');
  assert.equal(parse(healthAfter).paired_devices, 1);

  const devices = await request(local, '/api/devices', {
    headers: { 'X-PhoneJob-Admin': 'test-admin' },
  });
  assert.equal(devices.status, 200);
  assert.equal(parse(devices).devices.length, 1);

  const revoke = await request(local, `/api/device/${phone.claim.device_id}`, {
    method: 'DELETE',
    headers: { 'X-PhoneJob-Admin': 'test-admin', Origin: local },
  });
  assert.equal(revoke.status, 200);
  const devicesAfter = await request(local, '/api/devices', {
    headers: { 'X-PhoneJob-Admin': 'test-admin' },
  });
  assert.equal(parse(devicesAfter).devices[0].revoked, true);
});

test('local endpoints reject CSRF, bad tokens, and admin bypass', async (t) => {
  const { api, local } = await setup(t);
  const startResponse = await startPairing(local);
  const start = parse(startResponse);
  const token = new URL(start.local_url).searchParams.get('token');
  const phone = await claimPhone(api, start);

  const noAdmin = await startPairing(local, {
    headers: { 'X-PhoneJob-Admin': '' },
  });
  assert.equal(noAdmin.status, 401);

  const evilOrigin = await startPairing(local, {
    headers: { Origin: 'https://evil.test' },
  });
  assert.equal(evilOrigin.status, 403);

  const formStart = await startPairing(local, {
    headers: { 'Content-Type': 'text/plain' },
  });
  assert.equal(formStart.status, 415);

  const pageWithoutToken = await request(local, `/pair/${start.pair_id}`);
  assert.equal(pageWithoutToken.status, 404);

  const statusWithoutToken = await request(local, `/api/pair/${start.pair_id}`);
  assert.equal(statusWithoutToken.status, 404);

  const badHost = await request(local, localUrlPath(start, token), {
    hostHeader: 'evil.test',
  });
  assert.equal(badHost.status, 403);

  const confirmNoOrigin = await request(local, `/api/pair/${start.pair_id}/confirm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-PhoneJob-Pair-Token': token },
    body: JSON.stringify({ sas: phone.sas }),
  });
  assert.equal(confirmNoOrigin.status, 403);

  const confirmEvilOrigin = await request(local, `/api/pair/${start.pair_id}/confirm`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-PhoneJob-Pair-Token': token,
      Origin: 'https://evil.test',
    },
    body: JSON.stringify({ sas: phone.sas }),
  });
  assert.equal(confirmEvilOrigin.status, 403);

  const confirmForm = await request(local, `/api/pair/${start.pair_id}/confirm`, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'X-PhoneJob-Pair-Token': token,
      Origin: local,
    },
    body: 'sas=123456',
  });
  assert.equal(confirmForm.status, 415);

  const wrong = phone.sas === '000000' ? '111111' : '000000';
  const confirmWrong = await request(local, `/api/pair/${start.pair_id}/confirm`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-PhoneJob-Pair-Token': token,
      Origin: local,
    },
    body: JSON.stringify({ sas: wrong }),
  });
  assert.equal(confirmWrong.status, 400);
  assert.equal(parse(confirmWrong).error, 'SAS_MISMATCH');

  const confirm = await request(local, `/api/pair/${start.pair_id}/confirm`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-PhoneJob-Pair-Token': token,
      Origin: local,
    },
    body: JSON.stringify({ sas: phone.sas }),
  });
  assert.equal(confirm.status, 200);

  const apiStart = await sendApiJson(api, '/api/pair/start', {});
  assert.equal(apiStart.status, 404);
  const apiStatus = await request(api, `/api/pair/${start.pair_id}`);
  assert.equal(apiStatus.status, 404);
  const apiDevice = await request(api, `/api/device/${phone.claim.device_id}`, { method: 'DELETE' });
  assert.equal(apiDevice.status, 404);
});

test('API errors are mapped without leaking internals', async (t) => {
  const { api, local } = await setup(t);
  const start = parse(await startPairing(local));

  const unknown = await sendApiJson(api, '/api/pair/claim', {
    pair_id: 'missing',
    phone_pub: 'x',
    proof: 'x',
  });
  assert.equal(unknown.status, 404);
  assert.equal(parse(unknown).error, 'PAIRING_NOT_FOUND');

  const badProof = await sendApiJson(api, '/api/pair/claim', {
    pair_id: start.pair_id,
    phone_pub: 'not-a-key',
    proof: 'nope',
  });
  assert.equal(badProof.status, 400);
  assert.equal(parse(badProof).error, 'PHONE_PUB_INVALID');

  const phone = await claimPhone(api, start);
  const tooEarly = await sendApiJson(api, '/api/pair/provision', {
    pair_id: start.pair_id,
    device_id: phone.claim.device_id,
    proof: await phone.provisionProof(),
  });
  assert.equal(tooEarly.status, 202);
  assert.equal(parse(tooEarly).state, 'waiting');

  const badJson = await request(api, '/api/pair/claim', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{',
  });
  assert.equal(badJson.status, 400);
  assert.equal(parse(badJson).error, 'invalid_json');
});

test('PC home generates a QR payload for the PWA origin', async (t) => {
  const { local, workspace } = await setup(t, { pwaOrigin: 'http://127.0.0.1:8000' });

  const home = await request(local, '/');
  assert.equal(home.status, 200);
  assert.match(home.body, /PhoneJob 配对/);
  assert.match(home.body, /name="phonejob-admin-token" content="test-admin"/);
  assert.match(home.headers['content-security-policy'], /img-src 'self' data:/);
  assert.match(home.headers['content-security-policy'], /style-src 'self' 'unsafe-inline'/);
  assert.equal(home.headers['cache-control'], 'no-store');

  const homeJs = await request(local, '/local/home.js');
  assert.equal(homeJs.status, 200);
  assert.match(homeJs.headers['content-type'], /application\/javascript/);
  const homeCss = await request(local, '/local/home.css');
  assert.equal(homeCss.status, 200);

  const startResponse = await startPairing(local);
  assert.equal(startResponse.status, 200);
  const start = parse(startResponse);
  assert.ok(start.qr_data_url.startsWith('data:image/svg+xml;base64,'));
  assert.ok(start.pwa_url.startsWith('http://127.0.0.1:8000/#pair='));

  const encoded = start.pwa_url.split('#pair=')[1];
  const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  assert.equal(payload.pair_id, start.pair_id);
  assert.equal(payload.bridge_url, 'https://bridge.test');
  assert.equal(payload.expires_at, start.expires_at);
  assert.deepEqual(payload.workspaces, [workspace]);
  assert.ok(start.local_url.startsWith('http://127.0.0.1:'));
});

test('API only allows the configured PWA origin', async (t) => {
  const { api, local } = await setup(t, { pwaOrigin: 'http://127.0.0.1:8000' });
  const origin = 'http://127.0.0.1:8000';

  const preflight = await request(api, '/api/pair/claim', {
    method: 'OPTIONS',
    headers: {
      Origin: origin,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type, x-phonejob-device, x-phonejob-ts, x-phonejob-proof',
    },
  });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers['access-control-allow-origin'], origin);
  assert.match(preflight.headers['access-control-allow-headers'], /X-PhoneJob-Device/i);

  const health = await request(api, '/api/health', { headers: { Origin: origin } });
  assert.equal(health.headers['access-control-allow-origin'], origin);

  const evil = await request(api, '/api/health', { headers: { Origin: 'https://evil.test' } });
  assert.equal(evil.headers['access-control-allow-origin'], undefined);

  const evilPreflight = await request(api, '/api/pair/claim', {
    method: 'OPTIONS',
    headers: { Origin: 'https://evil.test' },
  });
  assert.equal(evilPreflight.status, 403);

  const localDevices = await request(local, '/api/devices', {
    headers: { 'X-PhoneJob-Admin': 'test-admin', Origin: origin },
  });
  assert.equal(localDevices.status, 200);
  assert.equal(localDevices.headers['access-control-allow-origin'], undefined);
});

function localUrlPath(start, token) {
  return `/pair/${start.pair_id}?token=${encodeURIComponent(token)}`;
}

function sendApiJson(api, pathname, body) {
  return request(api, pathname, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}
