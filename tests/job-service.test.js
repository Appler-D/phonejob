// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { MemoryDeviceStore } from '../bridge/device-store.js';
import { MemoryJobStore } from '../bridge/job-store.js';
import { JobService } from '../bridge/job-service.js';
import { sealEnvelope } from '../bridge/crypto.js';
import { generateOtpSecret } from '../bridge/key-store.js';
import { totp } from '../bridge/totp.js';

const DEVICE_ID = 'dev_test_device_1';
const KEYS = {
  kEnc: Buffer.alloc(32, 0x44),
  kConfirm: Buffer.alloc(32, 0x55),
  kAuth: Buffer.alloc(32, 0x66),
};

async function setup(t, { now = () => Date.now() } = {}) {
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
  });
  return { service, jobStore, deviceStore, inbox, workspace, otpSecret };
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
    files: [{ name: 'x.txt' }],
  });
  await assert.rejects(
    () => f2.service.submit(withFile),
    (err) => err.code === 'JOB_FILES_UNSUPPORTED',
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
