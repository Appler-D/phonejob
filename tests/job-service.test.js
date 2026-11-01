// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { MemoryDeviceStore } from '../bridge/device-store.js';
import { MemoryJobStore } from '../bridge/job-store.js';
import { JobService } from '../bridge/job-service.js';
import {
  canonicalJson,
  hmacSha256Base64Url,
  openEnvelope,
  sealEnvelope,
  sealFileChunk,
} from '../bridge/crypto.js';
import { computeConfirmationResponse } from '../bridge/confirm.js';
import { generateOtpSecret } from '../bridge/key-store.js';
import { totp } from '../bridge/totp.js';

const DEVICE_ID = 'dev_test_device_1';
const KEYS = {
  kEnc: Buffer.alloc(32, 0x44),
  kConfirm: Buffer.alloc(32, 0x55),
  kAuth: Buffer.alloc(32, 0x66),
};

async function setup(
  t,
  {
    now = () => Date.now(),
    confirmTtlMs,
    uploadTtlMs,
    executionTtlMs,
  } = {},
) {
  const inbox = await mkdtemp(path.join(os.tmpdir(), 'phonejob-inbox-'));
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'phonejob-ws-'));
  t.after(() => rm(inbox, { recursive: true, force: true }));
  t.after(() => rm(workspace, { recursive: true, force: true }));

  const otpSecret = generateOtpSecret();
  const deviceStore = new MemoryDeviceStore();
  await deviceStore.saveDevice({
    deviceId: DEVICE_ID,
    phonePub: 'pub',
    keys: KEYS,
    keyId: 'key-test',
    createdAt: 1,
  });
  const jobStore = new MemoryJobStore();
  const service = new JobService({
    deviceStore,
    jobStore,
    loadOtp: async () => ({ secret: otpSecret, keyId: 'key-test' }),
    inboxDir: inbox,
    workspaceAllowlist: [workspace],
    now,
    confirmTtlMs,
    uploadTtlMs,
    executionTtlMs,
  });
  return { service, jobStore, deviceStore, inbox, workspace, otpSecret };
}

async function writeResult(inbox, jobId, overrides = {}) {
  const dir = path.join(inbox, 'done', jobId);
  await mkdir(dir, { recursive: true });
  const result = {
    job_id: jobId,
    status: 'done',
    finished_at: new Date().toISOString(),
    text: 'the answer',
    files: [],
    error: null,
    ...overrides,
  };
  await writeFile(path.join(dir, 'result.json'), JSON.stringify(result));
  return result;
}

async function makeEnvelope({
  secret,
  workspace,
  now,
  jobId = 'job_test_1',
  seq = 1,
  intent = 'ask',
  text = 'hello',
  files = [],
  targetWorkspace = workspace,
  payloadJobId = jobId,
  headerJobId = jobId,
  deviceId = DEVICE_ID,
  otpValue,
  ts,
}) {
  const job = {
    version: 1,
    job_id: payloadJobId,
    device_id: deviceId,
    target: { workspace: targetWorkspace, preset: 'default', session: null },
    intent,
    text,
    files,
    reply: { want: 'text', max_bytes: 1024 },
  };
  const header = {
    v: 2,
    job_id: headerJobId,
    device_id: deviceId,
    ts: ts ?? Math.floor(now / 1000),
    seq,
    otp: otpValue ?? totp(secret, now),
  };
  return sealEnvelope(KEYS.kEnc, header, JSON.stringify(job));
}

test('JobService accepts a valid ask job and writes pending/job.json', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const envelope = await makeEnvelope({ secret: f.otpSecret, workspace: f.workspace, now });

  const result = await f.service.submit(envelope);
  assert.equal(result.state, 'WAITING_CONFIRM');
  assert.equal(result.risk, 'low');

  const stored = await f.service.getJob(envelope.job_id);
  assert.equal(stored.state, 'WAITING_CONFIRM');
  assert.match(stored.challenge, /^\d{6}$/);
  assert.equal(typeof stored.job_hash, 'string');
  assert.equal((await f.service.listJobs()).length, 1);

  const job = JSON.parse(
    await readFile(path.join(f.inbox, 'pending', envelope.job_id, 'job.json'), 'utf8'),
  );
  assert.equal(job.job_id, envelope.job_id);
  assert.equal(job.text, 'hello');
  assert.equal(job.files.length, 0);
  assert.equal(job.target.workspace, path.resolve(f.workspace));
  assert.equal(job.risk, 'low');

  const again = await f.service.submit(envelope);
  assert.equal(again.state, 'WAITING_CONFIRM');
  assert.equal((await f.service.listJobs()).length, 1);
});

test('wrong OTP is rejected without consuming the sequence', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const valid = totp(f.otpSecret, now);
  const wrong = valid === '000000' ? '111111' : '000000';
  const bad = await makeEnvelope({ secret: f.otpSecret, workspace: f.workspace, now, otpValue: wrong });
  await assert.rejects(() => f.service.submit(bad), (err) => err.code === 'JOB_OTP_INVALID');

  const good = await makeEnvelope({ secret: f.otpSecret, workspace: f.workspace, now });
  assert.equal((await f.service.submit(good)).state, 'WAITING_CONFIRM');
});

test('time window, workspace, files, and job binding are enforced', async (t) => {
  const now = 1_761_900_000_000;
  const late = 121_000;
  const f = await setup(t, { now: () => now + late });
  const lateEnvelope = await makeEnvelope({ secret: f.otpSecret, workspace: f.workspace, now });
  await assert.rejects(() => f.service.submit(lateEnvelope), (err) => err.code === 'JOB_TIME_WINDOW');

  const f2 = await setup(t, { now: () => now });
  const notAllowed = await makeEnvelope({
    secret: f2.otpSecret,
    workspace: f2.workspace,
    now,
    targetWorkspace: path.join(f2.workspace, 'other'),
  });
  await assert.rejects(
    () => f2.service.submit(notAllowed),
    (err) => err.code === 'JOB_WORKSPACE_NOT_ALLOWED',
  );

  const withFile = await makeEnvelope({
    secret: f2.otpSecret,
    workspace: f2.workspace,
    now,
    files: [{ name: 'x.exe', size: 4, sha256: 'A'.repeat(43) }],
  });
  await assert.rejects(
    () => f2.service.submit(withFile),
    (err) => err.code === 'JOB_FILE_TYPE',
  );

  const mismatch = await makeEnvelope({
    secret: f2.otpSecret,
    workspace: f2.workspace,
    now,
    payloadJobId: 'job_other_1',
  });
  await assert.rejects(() => f2.service.submit(mismatch), (err) => err.code === 'JOB_INVALID');

  const tooLong = await makeEnvelope({
    secret: f2.otpSecret,
    workspace: f2.workspace,
    now,
    text: 'x'.repeat(64 * 1024 + 1),
  });
  await assert.rejects(() => f2.service.submit(tooLong), (err) => err.code === 'JOB_INVALID');

  const tampered = await makeEnvelope({ secret: f2.otpSecret, workspace: f2.workspace, now });
  tampered.job_id = 'job_tampered_1';
  await assert.rejects(() => f2.service.submit(tampered), (err) => err.code === 'JOB_INVALID');
});

test('replayed and out-of-order sequences are rejected', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });

  const first = await makeEnvelope({ secret: f.otpSecret, workspace: f.workspace, now, jobId: 'job_test_1', seq: 1 });
  assert.equal((await f.service.submit(first)).state, 'WAITING_CONFIRM');

  const replay = await makeEnvelope({ secret: f.otpSecret, workspace: f.workspace, now, jobId: 'job_test_2', seq: 1 });
  await assert.rejects(() => f.service.submit(replay), (err) => err.code === 'JOB_REPLAY');

  const second = await makeEnvelope({ secret: f.otpSecret, workspace: f.workspace, now, jobId: 'job_test_3', seq: 2 });
  assert.equal((await f.service.submit(second)).state, 'WAITING_CONFIRM');

  const older = await makeEnvelope({ secret: f.otpSecret, workspace: f.workspace, now, jobId: 'job_test_4', seq: 1 });
  await assert.rejects(() => f.service.submit(older), (err) => err.code === 'JOB_REPLAY');
  assert.equal((await f.service.listJobs()).length, 2);
});

test('unknown and revoked devices are rejected', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const unknown = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    deviceId: 'dev_unknown_1',
  });
  await assert.rejects(() => f.service.submit(unknown), (err) => err.code === 'JOB_DEVICE_REJECTED');

  await f.deviceStore.revokeDevice(DEVICE_ID);
  const revoked = await makeEnvelope({ secret: f.otpSecret, workspace: f.workspace, now });
  await assert.rejects(() => f.service.submit(revoked), (err) => err.code === 'JOB_DEVICE_REJECTED');
});

test('approval requires the phone response and moves the job to approved', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const envelope = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId: 'job_test_approve',
    seq: 1,
  });
  await f.service.submit(envelope);
  const job = await f.service.getJob('job_test_approve');
  const expected = computeConfirmationResponse(KEYS.kConfirm, job.job_hash, job.challenge);
  const wrong = expected === 'AAAAAAAA' ? 'BBBBBBBB' : 'AAAAAAAA';

  await assert.rejects(
    () => f.service.approveJob({ jobId: job.job_id, response: wrong }),
    (err) => err.code === 'JOB_RESPONSE_INVALID',
  );
  assert.equal((await f.service.getJob(job.job_id)).state, 'WAITING_CONFIRM');

  const approved = await f.service.approveJob({ jobId: job.job_id, response: expected });
  assert.equal(approved.state, 'QUEUED');
  assert.equal((await f.service.getJob(job.job_id)).state, 'QUEUED');
  assert.equal(
    JSON.parse(await readFile(path.join(f.inbox, 'approved', job.job_id, 'job.json'), 'utf8')).text,
    'hello',
  );
  await assert.rejects(() => readFile(path.join(f.inbox, 'pending', job.job_id, 'job.json')));
  await assert.rejects(
    () => f.service.approveJob({ jobId: job.job_id, response: expected }),
    (err) => err.code === 'JOB_NOT_WAITING',
  );
  assert.equal((await f.service.getJobDetail(job.job_id)).content.text, 'hello');
});

test('rejection moves the job to rejected', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const envelope = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId: 'job_test_reject',
    seq: 1,
  });
  await f.service.submit(envelope);
  const rejected = await f.service.rejectJob({ jobId: 'job_test_reject' });
  assert.equal(rejected.state, 'REJECTED');
  assert.equal((await f.service.getJob('job_test_reject')).state, 'REJECTED');
  assert.equal(
    JSON.parse(await readFile(path.join(f.inbox, 'rejected', 'job_test_reject', 'job.json'), 'utf8'))
      .text,
    'hello',
  );
  await assert.rejects(() => readFile(path.join(f.inbox, 'pending', 'job_test_reject', 'job.json')));
});

test('device status requires a signed request', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const jobId = 'job_test_status';
  const envelope = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId,
    seq: 1,
  });
  await f.service.submit(envelope);

  const ts = Math.floor(now / 1000);
  const message = canonicalJson({ type: 'job-status-v1', device_id: DEVICE_ID, job_id: jobId, ts });
  const proof = await hmacSha256Base64Url(KEYS.kAuth, message);
  const status = await f.service.getForDevice({ jobId, deviceId: DEVICE_ID, ts, proof });
  assert.equal(status.state, 'WAITING_CONFIRM');
  assert.match(status.challenge, /^\d{6}$/);
  assert.equal(typeof status.job_hash, 'string');

  await assert.rejects(
    () => f.service.getForDevice({ jobId, deviceId: DEVICE_ID, ts, proof: 'bad' }),
    (err) => err.code === 'JOB_STATUS_AUTH',
  );
  await assert.rejects(
    () => f.service.getForDevice({ jobId, deviceId: DEVICE_ID, ts: ts - 121, proof }),
    (err) => err.code === 'JOB_STATUS_AUTH',
  );
  await assert.rejects(
    () => f.service.getForDevice({ jobId, deviceId: 'dev_unknown_1', ts, proof }),
    (err) => err.code === 'JOB_DEVICE_REJECTED',
  );

  const missingProof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-status-v1', device_id: DEVICE_ID, job_id: 'job_missing_1', ts }),
  );
  await assert.rejects(
    () => f.service.getForDevice({ jobId: 'job_missing_1', deviceId: DEVICE_ID, ts, proof: missingProof }),
    (err) => err.code === 'JOB_NOT_FOUND',
  );
});

test('scanResults completes a job and the result is sealed for the phone', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const jobId = 'job_test_result';
  const envelope = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId,
    seq: 1,
  });
  await f.service.submit(envelope);
  const job = await f.service.getJob(jobId);
  await f.service.approveJob({
    jobId,
    response: computeConfirmationResponse(KEYS.kConfirm, job.job_hash, job.challenge),
  });
  await writeResult(f.inbox, jobId, { text: 'the answer' });

  const completed = await f.service.scanResults();
  assert.equal(completed.length, 1);
  assert.equal(completed[0].state, 'DONE');
  assert.equal((await f.service.getJob(jobId)).state, 'DONE');

  const ts = Math.floor(now / 1000);
  const proof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-result-v1', device_id: DEVICE_ID, job_id: jobId, ts }),
  );
  const sealed = await f.service.getResultForDevice({ jobId, deviceId: DEVICE_ID, ts, proof });
  const opened = await openEnvelope(KEYS.kEnc, sealed);
  const result = JSON.parse(Buffer.from(opened.plaintext).toString('utf8'));
  assert.equal(result.text, 'the answer');
  assert.equal(result.job_id, jobId);

  const statusProof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-status-v1', device_id: DEVICE_ID, job_id: jobId, ts }),
  );
  const status = await f.service.getForDevice({
    jobId,
    deviceId: DEVICE_ID,
    ts,
    proof: statusProof,
  });
  assert.equal(status.state, 'DONE');
  await assert.rejects(
    () => f.service.getResultForDevice({ jobId, deviceId: DEVICE_ID, ts, proof: 'bad' }),
    (err) => err.code === 'JOB_STATUS_AUTH',
  );
});

test('unsafe or invalid results are marked failed and blocked', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const jobId = 'job_test_blocked';
  const envelope = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId,
    seq: 1,
  });
  await f.service.submit(envelope);
  const job = await f.service.getJob(jobId);
  await f.service.approveJob({
    jobId,
    response: computeConfirmationResponse(KEYS.kConfirm, job.job_hash, job.challenge),
  });
  await writeResult(f.inbox, jobId, { text: `leak sk-${'A'.repeat(24)}` });

  const completed = await f.service.scanResults();
  assert.equal(completed[0].state, 'FAILED');
  assert.match(completed[0].error, /secret/);
  const updated = await f.service.getJob(jobId);
  assert.equal(updated.state, 'FAILED');
  assert.match(updated.result_error, /secret/);

  const ts = Math.floor(now / 1000);
  const proof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-result-v1', device_id: DEVICE_ID, job_id: jobId, ts }),
  );
  await assert.rejects(
    () => f.service.getResultForDevice({ jobId, deviceId: DEVICE_ID, ts, proof }),
    (err) => err.code === 'JOB_RESULT_BLOCKED',
  );
});

test('result is not available before the job is completed', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const jobId = 'job_test_not_ready';
  const envelope = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId,
    seq: 1,
  });
  await f.service.submit(envelope);
  const job = await f.service.getJob(jobId);
  await f.service.approveJob({
    jobId,
    response: computeConfirmationResponse(KEYS.kConfirm, job.job_hash, job.challenge),
  });
  const ts = Math.floor(now / 1000);
  const proof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-result-v1', device_id: DEVICE_ID, job_id: jobId, ts }),
  );
  await assert.rejects(
    () => f.service.getResultForDevice({ jobId, deviceId: DEVICE_ID, ts, proof }),
    (err) => err.code === 'JOB_RESULT_NOT_READY',
  );
});

test('file job uploads chunks, verifies hash, and moves to pending', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const jobId = 'job_test_file';
  const content = Buffer.alloc(600 * 1024, 0x5a);
  const sha256 = createHash('sha256').update(content).digest('base64url');
  const envelope = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId,
    seq: 1,
    files: [{ name: 'note.txt', size: content.length, sha256 }],
  });
  const submitted = await f.service.submit(envelope);
  assert.equal(submitted.state, 'UPLOADING');
  assert.equal(submitted.files[0].chunks, 2);

  const ts = Math.floor(now / 1000);
  const proof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-upload-v1', device_id: DEVICE_ID, job_id: jobId, ts }),
  );
  const chunk0 = await sealFileChunk(
    KEYS.kEnc,
    { jobId, fileIndex: 0, fileSha256: sha256, chunkIndex: 0, totalChunks: 2 },
    content.subarray(0, 512 * 1024),
  );
  const first = await f.service.uploadChunk({
    jobId,
    fileIndex: 0,
    envelope: chunk0,
    deviceId: DEVICE_ID,
    ts,
    proof,
  });
  assert.equal(first.state, 'UPLOADING');
  assert.equal(first.received, 1);
  assert.equal(first.total, 2);

  const chunk1 = await sealFileChunk(
    KEYS.kEnc,
    { jobId, fileIndex: 0, fileSha256: sha256, chunkIndex: 1, totalChunks: 2 },
    content.subarray(512 * 1024),
  );
  const second = await f.service.uploadChunk({
    jobId,
    fileIndex: 0,
    envelope: chunk1,
    deviceId: DEVICE_ID,
    ts,
    proof,
  });
  assert.equal(second.state, 'WAITING_CONFIRM');

  const job = await f.service.getJob(jobId);
  assert.equal(job.state, 'WAITING_CONFIRM');
  assert.match(job.challenge, /^\d{6}$/);
  const jobJson = JSON.parse(
    await readFile(path.join(f.inbox, 'pending', jobId, 'job.json'), 'utf8'),
  );
  assert.equal(jobJson.files[0].name, 'note.txt');
  assert.equal(jobJson.files[0].local_path, 'files/0-note.txt');
  const stored = await readFile(path.join(f.inbox, 'pending', jobId, 'files', '0-note.txt'));
  assert.equal(stored.equals(content), true);

  await f.service.approveJob({
    jobId,
    response: computeConfirmationResponse(KEYS.kConfirm, job.job_hash, job.challenge),
  });
  const approved = await readFile(path.join(f.inbox, 'approved', jobId, 'files', '0-note.txt'));
  assert.equal(approved.equals(content), true);
});

test('unsafe file metadata and corrupted chunks are rejected', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });

  const exe = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId: 'job_test_exe',
    seq: 1,
    files: [{ name: 'a.exe', size: 4, sha256: 'A'.repeat(43) }],
  });
  await assert.rejects(() => f.service.submit(exe), (err) => err.code === 'JOB_FILE_TYPE');

  const reserved = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId: 'job_test_reserved',
    seq: 1,
    files: [{ name: 'CON.txt', size: 4, sha256: 'A'.repeat(43) }],
  });
  await assert.rejects(() => f.service.submit(reserved), (err) => err.code === 'JOB_FILE_NAME');

  const content = Buffer.from('good');
  const sha256 = createHash('sha256').update(content).digest('base64url');
  const jobId = 'job_test_badchunk';
  const envelope = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId,
    seq: 1,
    files: [{ name: 'note.txt', size: content.length, sha256 }],
  });
  await f.service.submit(envelope);
  const ts = Math.floor(now / 1000);
  const proof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-upload-v1', device_id: DEVICE_ID, job_id: jobId, ts }),
  );
  const badChunk = await sealFileChunk(
    KEYS.kEnc,
    { jobId, fileIndex: 0, fileSha256: sha256, chunkIndex: 0, totalChunks: 1 },
    Buffer.from('evil'),
  );
  await assert.rejects(
    () =>
      f.service.uploadChunk({
        jobId,
        fileIndex: 0,
        envelope: badChunk,
        deviceId: DEVICE_ID,
        ts,
        proof,
      }),
    (err) => err.code === 'JOB_FILE_HASH_MISMATCH',
  );
  assert.equal((await f.service.getJob(jobId)).state, 'UPLOADING');
});

test('non-ask intents are high risk', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const envelope = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    intent: 'file',
  });
  const result = await f.service.submit(envelope);
  assert.equal(result.risk, 'high');
  const job = JSON.parse(
    await readFile(path.join(f.inbox, 'pending', envelope.job_id, 'job.json'), 'utf8'),
  );
  assert.equal(job.risk, 'high');
});

test('confirmation timeout expires the job and blocks approval', async (t) => {
  const now = 1_761_900_000_000;
  let current = now;
  const f = await setup(t, { now: () => current, confirmTtlMs: 1000 });
  const jobId = 'job_test_confirm_timeout';
  const envelope = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId,
    seq: 1,
  });
  await f.service.submit(envelope);
  const job = await f.service.getJob(jobId);
  const response = computeConfirmationResponse(KEYS.kConfirm, job.job_hash, job.challenge);

  assert.deepEqual(await f.service.scanTimeouts(), []);

  current = now + 1000;
  const expired = await f.service.scanTimeouts();
  assert.equal(expired.length, 1);
  assert.equal(expired[0].state, 'EXPIRED');
  assert.equal(expired[0].error, 'JOB_CONFIRM_TIMEOUT');
  const stored = await f.service.getJob(jobId);
  assert.equal(stored.state, 'EXPIRED');
  assert.equal(stored.result_error, 'JOB_CONFIRM_TIMEOUT');
  await assert.rejects(() => readFile(path.join(f.inbox, 'pending', jobId, 'job.json')));
  assert.equal(
    JSON.parse(await readFile(path.join(f.inbox, 'expired', jobId, 'job.json'), 'utf8')).job_id,
    jobId,
  );
  await assert.rejects(
    () => f.service.approveJob({ jobId, response }),
    (err) => err.code === 'JOB_NOT_WAITING',
  );
  assert.deepEqual(await f.service.scanTimeouts(), []);
});

test('upload timeout expires the job and removes staging', async (t) => {
  const now = 1_761_900_000_000;
  let current = now;
  const f = await setup(t, { now: () => current, uploadTtlMs: 1000 });
  const jobId = 'job_test_upload_timeout';
  const content = Buffer.from('slow upload');
  const sha256 = createHash('sha256').update(content).digest('base64url');
  const envelope = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId,
    seq: 1,
    files: [{ name: 'note.txt', size: content.length, sha256 }],
  });
  assert.equal((await f.service.submit(envelope)).state, 'UPLOADING');
  await readFile(path.join(f.inbox, 'pending', `.upload-${jobId}`, 'job.json'));

  current = now + 1000;
  const expired = await f.service.scanTimeouts();
  assert.equal(expired.length, 1);
  assert.equal(expired[0].state, 'EXPIRED');
  assert.equal(expired[0].error, 'JOB_UPLOAD_TIMEOUT');
  assert.equal((await f.service.getJob(jobId)).state, 'EXPIRED');
  await assert.rejects(() => readFile(path.join(f.inbox, 'pending', `.upload-${jobId}`, 'job.json')));
  await assert.rejects(() => readFile(path.join(f.inbox, 'pending', jobId, 'job.json')));
});

test('execution timeout fails a queued job and ignores a late result', async (t) => {
  const now = 1_761_900_000_000;
  let current = now;
  const f = await setup(t, { now: () => current, executionTtlMs: 1000 });
  const jobId = 'job_test_exec_timeout';
  const envelope = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId,
    seq: 1,
  });
  await f.service.submit(envelope);
  const job = await f.service.getJob(jobId);
  await f.service.approveJob({
    jobId,
    response: computeConfirmationResponse(KEYS.kConfirm, job.job_hash, job.challenge),
  });

  current = now + 999;
  assert.deepEqual(await f.service.scanTimeouts(), []);

  current = now + 1000;
  const expired = await f.service.scanTimeouts();
  assert.equal(expired.length, 1);
  assert.equal(expired[0].state, 'FAILED');
  assert.equal(expired[0].error, 'JOB_EXECUTION_TIMEOUT');
  const stored = await f.service.getJob(jobId);
  assert.equal(stored.state, 'FAILED');
  assert.equal(stored.result_error, 'JOB_EXECUTION_TIMEOUT');
  assert.equal(stored.finished_at, current);

  await writeResult(f.inbox, jobId, { text: 'too late' });
  assert.deepEqual(await f.service.scanResults(), []);
  assert.equal((await f.service.getJob(jobId)).state, 'FAILED');
});
