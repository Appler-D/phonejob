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
import { storedZip } from './zip-fixture.js';

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
    resultTtlMs,
    maxJobsPerHour,
    maxActiveJobs,
    maxInboxBytes,
    audit,
    notify,
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
    resultTtlMs,
    maxJobsPerHour,
    maxActiveJobs,
    maxInboxBytes,
    audit,
    notify,
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

async function writeResultFile(inbox, jobId, index, bytes, name = `answer-${index}.md`) {
  const dir = path.join(inbox, 'done', jobId, 'files');
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, String(index)), bytes);
  return {
    name,
    size: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('base64url'),
  };
}

async function readStatus(service, { jobId, deviceId, ts, proof }) {
  const sealed = await service.getForDevice({ jobId, deviceId, ts, proof });
  const opened = await openEnvelope(KEYS.kEnc, sealed);
  assert.equal(opened.header.type, 'job-status-v1');
  assert.equal(opened.header.job_id, jobId);
  assert.equal(opened.header.device_id, deviceId);
  assert.equal(opened.header.request_ts, ts);
  return JSON.parse(Buffer.from(opened.plaintext).toString('utf8'));
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
  const status = await readStatus(f.service, {
    jobId,
    deviceId: DEVICE_ID,
    ts,
    proof,
  });
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
  const status = await readStatus(f.service, {
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

test('result files are verified and sealed with an index-bound proof', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const jobId = 'job_test_result_file';
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

  const content = Buffer.from('the result file bytes');
  const meta = await writeResultFile(f.inbox, jobId, 0, content);
  await writeResult(f.inbox, jobId, { text: 'with file', files: [meta] });
  const completed = await f.service.scanResults();
  assert.equal(completed[0].state, 'DONE');

  const ts = Math.floor(now / 1000);
  const resultProof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-result-v1', device_id: DEVICE_ID, job_id: jobId, ts }),
  );
  const resultEnvelope = await f.service.getResultForDevice({
    jobId,
    deviceId: DEVICE_ID,
    ts,
    proof: resultProof,
  });
  const openedResult = await openEnvelope(KEYS.kEnc, resultEnvelope);
  const result = JSON.parse(Buffer.from(openedResult.plaintext).toString('utf8'));
  assert.equal(result.files.length, 1);
  assert.equal(result.files[0].name, meta.name);

  const fileProof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({
      type: 'job-result-file-v1',
      device_id: DEVICE_ID,
      job_id: jobId,
      ts,
      file_index: 0,
    }),
  );
  const sealed = await f.service.getResultFileForDevice({
    jobId,
    fileIndex: 0,
    deviceId: DEVICE_ID,
    ts,
    proof: fileProof,
  });
  const openedFile = await openEnvelope(KEYS.kEnc, sealed);
  assert.equal(openedFile.header.type, 'job-result-file-v1');
  assert.equal(openedFile.header.job_id, jobId);
  assert.equal(openedFile.header.file_index, 0);
  assert.equal(openedFile.header.sha256, meta.sha256);
  assert.equal(Buffer.from(openedFile.plaintext).equals(content), true);

  await assert.rejects(
    () =>
      f.service.getResultFileForDevice({
        jobId,
        fileIndex: 1,
        deviceId: DEVICE_ID,
        ts,
        proof: fileProof,
      }),
    (err) => err.code === 'JOB_STATUS_AUTH',
  );

  await writeFile(path.join(f.inbox, 'done', jobId, 'files', '0'), Buffer.from('tampered'));
  await assert.rejects(
    () =>
      f.service.getResultFileForDevice({
        jobId,
        fileIndex: 0,
        deviceId: DEVICE_ID,
        ts,
        proof: fileProof,
      }),
    (err) => err.code === 'JOB_RESULT_BLOCKED',
  );
});

test('scanResults rejects result files with bad hashes or secrets', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });

  const badHashJob = 'job_test_bad_result_file';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId: badHashJob,
      seq: 1,
    }),
  );
  const badHash = await f.service.getJob(badHashJob);
  await f.service.approveJob({
    jobId: badHashJob,
    response: computeConfirmationResponse(KEYS.kConfirm, badHash.job_hash, badHash.challenge),
  });
  const badMeta = await writeResultFile(f.inbox, badHashJob, 0, Buffer.from('good bytes'));
  await writeResult(f.inbox, badHashJob, {
    files: [{ ...badMeta, sha256: 'B'.repeat(43) }],
  });

  const secretJob = 'job_test_secret_result';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId: secretJob,
      seq: 2,
    }),
  );
  const secret = await f.service.getJob(secretJob);
  await f.service.approveJob({
    jobId: secretJob,
    response: computeConfirmationResponse(KEYS.kConfirm, secret.job_hash, secret.challenge),
  });
  const secretMeta = await writeResultFile(
    f.inbox,
    secretJob,
    0,
    Buffer.from(`leak sk-${'A'.repeat(24)}`),
  );
  await writeResult(f.inbox, secretJob, { files: [secretMeta] });

  const zipJob = 'job_test_zip_result';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId: zipJob,
      seq: 3,
    }),
  );
  const zipRecord = await f.service.getJob(zipJob);
  await f.service.approveJob({
    jobId: zipJob,
    response: computeConfirmationResponse(KEYS.kConfirm, zipRecord.job_hash, zipRecord.challenge),
  });
  const zipMeta = await writeResultFile(
    f.inbox,
    zipJob,
    0,
    storedZip([{ name: 'evil.exe', data: 'MZ' }]),
    'bundle.zip',
  );
  await writeResult(f.inbox, zipJob, { files: [zipMeta] });

  const officeJob = 'job_test_office_result';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId: officeJob,
      seq: 4,
    }),
  );
  const officeRecord = await f.service.getJob(officeJob);
  await f.service.approveJob({
    jobId: officeJob,
    response: computeConfirmationResponse(
      KEYS.kConfirm,
      officeRecord.job_hash,
      officeRecord.challenge,
    ),
  });
  const officeMeta = await writeResultFile(
    f.inbox,
    officeJob,
    0,
    storedZip([
      { name: 'word/document.xml', data: '<document/>' },
      { name: 'word/vbaProject.bin', data: 'MZ' },
    ]),
    'report.docx',
  );
  await writeResult(f.inbox, officeJob, { files: [officeMeta] });

  const completed = await f.service.scanResults();
  assert.equal(completed.length, 4);
  const badHashState = await f.service.getJob(badHashJob);
  assert.equal(badHashState.state, 'FAILED');
  assert.match(badHashState.result_error, /hash/);
  const secretState = await f.service.getJob(secretJob);
  assert.equal(secretState.state, 'FAILED');
  assert.match(secretState.result_error, /secret/);
  const zipState = await f.service.getJob(zipJob);
  assert.equal(zipState.state, 'FAILED');
  assert.match(zipState.result_error, /zip entry type/);
  const officeState = await f.service.getJob(officeJob);
  assert.equal(officeState.state, 'FAILED');
  assert.match(officeState.result_error, /zip entry is not allowed/);
});

test('job transitions emit redacted audit events', async (t) => {
  const now = 1_761_900_000_000;
  const events = [];
  const audit = {
    record(event, fields) {
      events.push({ event, ...fields });
    },
  };
  const f = await setup(t, { now: () => now, audit });
  const jobId = 'job_test_audit_events';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId,
      seq: 1,
      text: 'secret task text',
    }),
  );
  const job = await f.service.getJob(jobId);
  await f.service.approveJob({
    jobId,
    response: computeConfirmationResponse(KEYS.kConfirm, job.job_hash, job.challenge),
  });
  const content = Buffer.from('audited result');
  const meta = await writeResultFile(f.inbox, jobId, 0, content);
  await writeResult(f.inbox, jobId, { text: 'answer', files: [meta] });
  await f.service.scanResults();

  assert.deepEqual(
    events.map((entry) => entry.event),
    ['job.submitted', 'job.approved', 'job.completed'],
  );
  assert.equal(events[0].state, 'WAITING_CONFIRM');
  assert.equal(events[1].state, 'QUEUED');
  assert.equal(events[2].state, 'DONE');
  assert.equal(events[2].files, 1);
  assert.equal(events[2].file_bytes, content.length);
  for (const entry of events) {
    assert.equal(entry.job_id, jobId);
    for (const key of ['text', 'workspace', 'challenge', 'job_hash', 'file_name']) {
      assert.equal(key in entry, false, key);
    }
  }
});

test('zip uploads are scanned before they reach pending', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const ts = Math.floor(now / 1000);

  const evil = storedZip([{ name: 'evil.exe', data: 'MZ' }]);
  const evilSha = createHash('sha256').update(evil).digest('base64url');
  const jobId = 'job_test_zip_upload';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId,
      seq: 1,
      files: [{ name: 'bundle.zip', size: evil.length, sha256: evilSha }],
    }),
  );
  const proof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-upload-v1', device_id: DEVICE_ID, job_id: jobId, ts }),
  );
  const chunk = await sealFileChunk(
    KEYS.kEnc,
    { jobId, fileIndex: 0, fileSha256: evilSha, chunkIndex: 0, totalChunks: 1 },
    evil,
  );
  await assert.rejects(
    () =>
      f.service.uploadChunk({
        jobId,
        fileIndex: 0,
        envelope: chunk,
        deviceId: DEVICE_ID,
        ts,
        proof,
      }),
    (err) => err.code === 'JOB_ZIP_UNSAFE',
  );
  assert.equal((await f.service.getJob(jobId)).state, 'UPLOADING');

  const safe = storedZip([{ name: 'note.txt', data: 'safe' }]);
  const safeSha = createHash('sha256').update(safe).digest('base64url');
  const safeJob = 'job_test_zip_upload_ok';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId: safeJob,
      seq: 2,
      files: [{ name: 'bundle.zip', size: safe.length, sha256: safeSha }],
    }),
  );
  const safeProof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-upload-v1', device_id: DEVICE_ID, job_id: safeJob, ts }),
  );
  const safeChunk = await sealFileChunk(
    KEYS.kEnc,
    { jobId: safeJob, fileIndex: 0, fileSha256: safeSha, chunkIndex: 0, totalChunks: 1 },
    safe,
  );
  const uploaded = await f.service.uploadChunk({
    jobId: safeJob,
    fileIndex: 0,
    envelope: safeChunk,
    deviceId: DEVICE_ID,
    ts,
    proof: safeProof,
  });
  assert.equal(uploaded.state, 'WAITING_CONFIRM');
});

test('office uploads are scanned for macros and embeddings', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const ts = Math.floor(now / 1000);

  const macro = storedZip([
    { name: 'word/document.xml', data: '<document/>' },
    { name: 'word/vbaProject.bin', data: 'MZ' },
  ]);
  const macroSha = createHash('sha256').update(macro).digest('base64url');
  const jobId = 'job_test_office_macro';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId,
      seq: 1,
      files: [{ name: 'report.docx', size: macro.length, sha256: macroSha }],
    }),
  );
  const proof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-upload-v1', device_id: DEVICE_ID, job_id: jobId, ts }),
  );
  const chunk = await sealFileChunk(
    KEYS.kEnc,
    { jobId, fileIndex: 0, fileSha256: macroSha, chunkIndex: 0, totalChunks: 1 },
    macro,
  );
  await assert.rejects(
    () =>
      f.service.uploadChunk({
        jobId,
        fileIndex: 0,
        envelope: chunk,
        deviceId: DEVICE_ID,
        ts,
        proof,
      }),
    (err) => err.code === 'JOB_OFFICE_UNSAFE',
  );
  assert.equal((await f.service.getJob(jobId)).state, 'UPLOADING');

  const safe = storedZip([
    { name: 'word/document.xml', data: '<document/>' },
    {
      name: 'word/_rels/document.xml.rels',
      data: '<Relationships><Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com" TargetMode="External"/></Relationships>',
    },
  ]);
  const safeSha = createHash('sha256').update(safe).digest('base64url');
  const safeJob = 'job_test_office_safe';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId: safeJob,
      seq: 2,
      files: [{ name: 'report.docx', size: safe.length, sha256: safeSha }],
    }),
  );
  const safeProof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-upload-v1', device_id: DEVICE_ID, job_id: safeJob, ts }),
  );
  const safeChunk = await sealFileChunk(
    KEYS.kEnc,
    { jobId: safeJob, fileIndex: 0, fileSha256: safeSha, chunkIndex: 0, totalChunks: 1 },
    safe,
  );
  assert.equal(
    (
      await f.service.uploadChunk({
        jobId: safeJob,
        fileIndex: 0,
        envelope: safeChunk,
        deviceId: DEVICE_ID,
        ts,
        proof: safeProof,
      })
    ).state,
    'WAITING_CONFIRM',
  );

  const external = storedZip([
    { name: 'word/document.xml', data: '<document/>' },
    {
      name: 'word/_rels/document.xml.rels',
      data: '<Relationships><Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/template.dotm" TargetMode="External"/></Relationships>',
    },
  ]);
  const externalSha = createHash('sha256').update(external).digest('base64url');
  const externalJob = 'job_test_office_external';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId: externalJob,
      seq: 3,
      files: [{ name: 'report.docx', size: external.length, sha256: externalSha }],
    }),
  );
  const externalProof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-upload-v1', device_id: DEVICE_ID, job_id: externalJob, ts }),
  );
  const externalChunk = await sealFileChunk(
    KEYS.kEnc,
    { jobId: externalJob, fileIndex: 0, fileSha256: externalSha, chunkIndex: 0, totalChunks: 1 },
    external,
  );
  await assert.rejects(
    () =>
      f.service.uploadChunk({
        jobId: externalJob,
        fileIndex: 0,
        envelope: externalChunk,
        deviceId: DEVICE_ID,
        ts,
        proof: externalProof,
      }),
    (err) => err.code === 'JOB_OFFICE_UNSAFE',
  );
});

test('per-device submission rate limit resets after the window', async (t) => {
  const now = 1_761_900_000_000;
  let current = now;
  const f = await setup(t, { now: () => current, maxJobsPerHour: 1 });

  const first = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId: 'job_test_rate_1',
    seq: 1,
  });
  assert.equal((await f.service.submit(first)).state, 'WAITING_CONFIRM');

  const second = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId: 'job_test_rate_2',
    seq: 2,
  });
  await assert.rejects(
    () => f.service.submit(second),
    (err) => err.code === 'JOB_RATE_LIMITED',
  );
  assert.equal((await f.service.listJobs()).length, 1);

  current = now + 60 * 60_000 + 1;
  const third = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now: current,
    jobId: 'job_test_rate_3',
    seq: 2,
  });
  assert.equal((await f.service.submit(third)).state, 'WAITING_CONFIRM');
});

test('repeated OTP failures lock the device until the window passes', async (t) => {
  const now = 1_761_900_000_000;
  let current = now;
  const f = await setup(t, { now: () => current });
  const valid = totp(f.otpSecret, now);
  const wrong = valid === '000000' ? '111111' : '000000';

  for (let index = 0; index < 3; index += 1) {
    const envelope = await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId: `job_test_lock_${index}`,
      seq: 1,
      otpValue: wrong,
    });
    await assert.rejects(
      () => f.service.submit(envelope),
      (err) => err.code === 'JOB_OTP_INVALID',
    );
  }

  const locked = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId: 'job_test_lock_ok',
    seq: 1,
  });
  await assert.rejects(
    () => f.service.submit(locked),
    (err) => err.code === 'JOB_LOCKED',
  );

  current = now + 5 * 60_000 + 1;
  const unlocked = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now: current,
    jobId: 'job_test_lock_ok',
    seq: 1,
  });
  assert.equal((await f.service.submit(unlocked)).state, 'WAITING_CONFIRM');

  const next = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now: current,
    jobId: 'job_test_lock_next',
    seq: 2,
  });
  assert.equal((await f.service.submit(next)).state, 'WAITING_CONFIRM');
});

test('OTP lock survives a new JobService instance', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now });
  const valid = totp(f.otpSecret, now);
  const wrong = valid === '000000' ? '111111' : '000000';
  for (let index = 0; index < 3; index += 1) {
    const envelope = await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId: `job_test_persist_lock_${index}`,
      seq: 1,
      otpValue: wrong,
    });
    await assert.rejects(
      () => f.service.submit(envelope),
      (err) => err.code === 'JOB_OTP_INVALID',
    );
  }

  const second = new JobService({
    deviceStore: f.deviceStore,
    jobStore: f.jobStore,
    loadOtp: async () => ({ secret: f.otpSecret, keyId: 'key-test' }),
    inboxDir: f.inbox,
    workspaceAllowlist: [f.workspace],
    now: () => now,
  });
  const locked = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId: 'job_test_persist_lock_ok',
    seq: 1,
  });
  await assert.rejects(
    () => second.submit(locked),
    (err) => err.code === 'JOB_LOCKED',
  );
});

test('challenge response failures lock approvals until the window passes', async (t) => {
  const now = 1_761_900_000_000;
  let current = now;
  const f = await setup(t, { now: () => current });
  const jobId = 'job_test_challenge_lock';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId,
      seq: 1,
    }),
  );
  const job = await f.service.getJob(jobId);
  const expected = computeConfirmationResponse(KEYS.kConfirm, job.job_hash, job.challenge);
  const wrong = expected === 'AAAAAAAA' ? 'BBBBBBBB' : 'AAAAAAAA';

  for (let index = 0; index < 3; index += 1) {
    await assert.rejects(
      () => f.service.approveJob({ jobId, response: wrong }),
      (err) => err.code === 'JOB_RESPONSE_INVALID',
    );
  }
  await assert.rejects(
    () => f.service.approveJob({ jobId, response: expected }),
    (err) => err.code === 'JOB_LOCKED',
  );
  assert.equal((await f.service.getJob(jobId)).state, 'WAITING_CONFIRM');

  current = now + 5 * 60_000 + 1;
  const approved = await f.service.approveJob({ jobId, response: expected });
  assert.equal(approved.state, 'QUEUED');
});

test('retention expires old results and prunes inbox directories', async (t) => {
  const now = 1_761_900_000_000;
  let current = now;
  const f = await setup(t, { now: () => current, resultTtlMs: 1000 });
  const jobId = 'job_test_retention';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId,
      seq: 1,
    }),
  );
  const job = await f.service.getJob(jobId);
  await f.service.approveJob({
    jobId,
    response: computeConfirmationResponse(KEYS.kConfirm, job.job_hash, job.challenge),
  });
  const content = Buffer.from('retained result');
  const meta = await writeResultFile(f.inbox, jobId, 0, content);
  await writeResult(f.inbox, jobId, { text: 'answer', files: [meta] });
  await f.service.scanResults();
  await mkdir(path.join(f.inbox, 'working', jobId), { recursive: true });
  await writeFile(path.join(f.inbox, 'working', jobId, 'marker'), 'still here');

  assert.deepEqual(await f.service.scanRetention(), []);

  current = now + 1001;
  const removed = await f.service.scanRetention();
  assert.equal(removed.length, 1);
  assert.equal(removed[0].state, 'EXPIRED');
  assert.equal(removed[0].error, 'RESULT_EXPIRED');
  const stored = await f.service.getJob(jobId);
  assert.equal(stored.state, 'EXPIRED');
  assert.equal(stored.result_error, 'RESULT_EXPIRED');
  await assert.rejects(() => readFile(path.join(f.inbox, 'done', jobId, 'result.json')));
  await assert.rejects(() => readFile(path.join(f.inbox, 'working', jobId, 'marker')));

  const ts = Math.floor(current / 1000);
  const statusProof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-status-v1', device_id: DEVICE_ID, job_id: jobId, ts }),
  );
  const status = await readStatus(f.service, {
    jobId,
    deviceId: DEVICE_ID,
    ts,
    proof: statusProof,
  });
  assert.equal(status.state, 'EXPIRED');
  assert.equal(status.error, 'RESULT_EXPIRED');

  const resultProof = await hmacSha256Base64Url(
    KEYS.kAuth,
    canonicalJson({ type: 'job-result-v1', device_id: DEVICE_ID, job_id: jobId, ts }),
  );
  await assert.rejects(
    () => f.service.getResultForDevice({ jobId, deviceId: DEVICE_ID, ts, proof: resultProof }),
    (err) => err.code === 'JOB_RESULT_NOT_READY',
  );

  const rejectedId = 'job_test_retention_rejected';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now: current,
      jobId: rejectedId,
      seq: 2,
    }),
  );
  await f.service.rejectJob({ jobId: rejectedId });
  current += 1001;
  const pruned = await f.service.scanRetention();
  assert.equal(pruned.length, 1);
  assert.equal(pruned[0].state, 'REJECTED');
  assert.equal(pruned[0].error, 'RETENTION');
  assert.equal((await f.service.getJob(rejectedId)).state, 'REJECTED');
  await assert.rejects(() => readFile(path.join(f.inbox, 'rejected', rejectedId, 'job.json')));
  assert.deepEqual(await f.service.scanRetention(), []);
});

test('job transitions call the notifier', async (t) => {
  const now = 1_761_900_000_000;
  const events = [];
  const f = await setup(t, {
    now: () => now,
    notify: (event) => {
      events.push(event);
    },
  });
  const jobId = 'job_test_notify';
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId,
      seq: 1,
    }),
  );
  const job = await f.service.getJob(jobId);
  await f.service.approveJob({
    jobId,
    response: computeConfirmationResponse(KEYS.kConfirm, job.job_hash, job.challenge),
  });
  await writeResult(f.inbox, jobId, { text: 'done' });
  await f.service.scanResults();

  assert.deepEqual(
    events.map((event) => event.state),
    ['QUEUED', 'DONE'],
  );
  for (const event of events) {
    assert.equal(event.deviceId, DEVICE_ID);
    assert.equal(event.jobId, jobId);
  }
});

test('active job queue limit rejects new jobs until space frees', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now, maxActiveJobs: 1 });
  await f.service.submit(
    await makeEnvelope({
      secret: f.otpSecret,
      workspace: f.workspace,
      now,
      jobId: 'job_test_queue_1',
      seq: 1,
    }),
  );
  const second = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId: 'job_test_queue_2',
    seq: 2,
  });
  await assert.rejects(
    () => f.service.submit(second),
    (err) => err.code === 'JOB_QUEUE_FULL',
  );
  await f.service.rejectJob({ jobId: 'job_test_queue_1' });
  assert.equal((await f.service.submit(second)).state, 'WAITING_CONFIRM');
});

test('inbox byte limit rejects new jobs', async (t) => {
  const now = 1_761_900_000_000;
  const f = await setup(t, { now: () => now, maxInboxBytes: 100 });
  const blob = path.join(f.inbox, 'blob.bin');
  await writeFile(blob, Buffer.alloc(200));
  const blocked = await makeEnvelope({
    secret: f.otpSecret,
    workspace: f.workspace,
    now,
    jobId: 'job_test_disk_full',
    seq: 1,
  });
  await assert.rejects(
    () => f.service.submit(blocked),
    (err) => err.code === 'JOB_DISK_FULL',
  );
  await rm(blob);
  assert.equal((await f.service.submit(blocked)).state, 'WAITING_CONFIRM');
});
