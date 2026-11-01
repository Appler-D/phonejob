// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { MemoryJobStore, SqliteJobStore } from '../bridge/job-store.js';

function job(id, createdAt) {
  return {
    job_id: id,
    device_id: 'dev_test_1',
    state: 'WAITING_CONFIRM',
    risk: 'low',
    intent: 'ask',
    workspace: 'C:\\workspace',
    inbox_path: `C:\\inbox\\${id}`,
    created_at: createdAt,
    updated_at: createdAt,
  };
}

test('MemoryJobStore enforces sequence, nonce, and job uniqueness', async () => {
  const store = new MemoryJobStore();
  assert.equal(await store.saveJobWithSequence({ job: job('job_test_1', 1), seq: 1, nonce: 'n1' }), true);
  assert.equal(await store.saveJobWithSequence({ job: job('job_test_1', 1), seq: 2, nonce: 'n2' }), false);
  assert.equal(await store.saveJobWithSequence({ job: job('job_test_2', 2), seq: 1, nonce: 'n3' }), false);
  assert.equal(await store.saveJobWithSequence({ job: job('job_test_2', 2), seq: 2, nonce: 'n1' }), false);
  assert.equal(await store.saveJobWithSequence({ job: job('job_test_2', 2), seq: 2, nonce: 'n2' }), true);
  assert.equal((await store.listJobs()).length, 2);
  assert.equal((await store.getJob('job_test_1')).state, 'WAITING_CONFIRM');
  await store.close();
});

test('SqliteJobStore persists jobs and replay state', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'phonejob-jobs-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'jobs.sqlite');

  const store = new SqliteJobStore({ filePath: file });
  assert.equal(await store.saveJobWithSequence({ job: job('job_test_1', 1), seq: 1, nonce: 'n1' }), true);
  assert.equal(await store.saveJobWithSequence({ job: job('job_test_1', 1), seq: 2, nonce: 'n2' }), false);
  assert.equal(await store.saveJobWithSequence({ job: job('job_test_2', 2), seq: 2, nonce: 'n1' }), false);
  assert.equal(await store.saveJobWithSequence({ job: job('job_test_2', 2), seq: 2, nonce: 'n2' }), true);
  await store.close();

  const reopened = new SqliteJobStore({ filePath: file });
  const jobs = await reopened.listJobs();
  assert.equal(jobs.length, 2);
  assert.equal(jobs[0].job_id, 'job_test_2');
  assert.equal(await reopened.saveJobWithSequence({ job: job('job_test_3', 3), seq: 1, nonce: 'n3' }), false);
  await reopened.close();
});

test('expireJob only transitions allowed states and persists', async (t) => {
  const memory = new MemoryJobStore();
  await memory.saveJobWithSequence({ job: job('job_test_expire', 1), seq: 1, nonce: 'n1' });
  assert.equal(
    await memory.expireJob({
      jobId: 'job_test_expire',
      fromStates: ['UPLOADING'],
      state: 'EXPIRED',
      resultError: 'JOB_UPLOAD_TIMEOUT',
      finishedAt: 2,
    }),
    false,
  );
  assert.equal(
    await memory.expireJob({
      jobId: 'job_test_expire',
      fromStates: ['WAITING_CONFIRM'],
      state: 'EXPIRED',
      resultError: 'JOB_CONFIRM_TIMEOUT',
      finishedAt: 2,
      inboxPath: 'C:\\inbox\\expired',
    }),
    true,
  );
  const memoryJob = await memory.getJob('job_test_expire');
  assert.equal(memoryJob.state, 'EXPIRED');
  assert.equal(memoryJob.result_error, 'JOB_CONFIRM_TIMEOUT');
  assert.equal(memoryJob.finished_at, 2);
  assert.equal(memoryJob.inbox_path, 'C:\\inbox\\expired');

  const dir = await mkdtemp(path.join(os.tmpdir(), 'phonejob-jobs-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'jobs.sqlite');
  const store = new SqliteJobStore({ filePath: file });
  await store.saveJobWithSequence({ job: job('job_test_expire', 1), seq: 1, nonce: 'n1' });
  assert.equal(
    await store.expireJob({
      jobId: 'job_test_expire',
      fromStates: ['WAITING_CONFIRM'],
      state: 'EXPIRED',
      resultError: 'JOB_CONFIRM_TIMEOUT',
      finishedAt: 2,
      inboxPath: 'C:\\inbox\\expired',
    }),
    true,
  );
  assert.equal(
    await store.expireJob({
      jobId: 'job_test_expire',
      fromStates: ['WAITING_CONFIRM'],
      state: 'EXPIRED',
      resultError: 'JOB_CONFIRM_TIMEOUT',
      finishedAt: 3,
    }),
    false,
  );
  await store.close();

  const reopened = new SqliteJobStore({ filePath: file });
  const persisted = await reopened.getJob('job_test_expire');
  assert.equal(persisted.state, 'EXPIRED');
  assert.equal(persisted.result_error, 'JOB_CONFIRM_TIMEOUT');
  assert.equal(persisted.finished_at, 2);
  assert.equal(persisted.inbox_path, 'C:\\inbox\\expired');
  await reopened.close();
});
