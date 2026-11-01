// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { AuditLog } from '../bridge/audit.js';

test('audit keeps whitelisted fields and drops job content', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'phonejob-audit-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'audit.jsonl');
  const audit = new AuditLog({ filePath: file, now: () => 1_761_900_000_000 });

  await audit.record('job.submitted', {
    job_id: 'job_test_audit',
    device_id: 'dev_test_device_1',
    state: 'WAITING_CONFIRM',
    risk: 'low',
    intent: 'ask',
    files: 2,
    file_bytes: 1234,
    text: 'secret task text',
    workspace: 'C:\\private\\workspace',
    challenge: '123456',
    job_hash: 'hash-value',
    file_name: 'answer.md',
  });
  await audit.record('job.completed', {
    job_id: 'job_test_audit',
    state: 'DONE',
    error: null,
  });
  await audit.close();

  const lines = (await readFile(file, 'utf8')).trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(lines.length, 2);
  assert.equal(lines[0].event, 'job.submitted');
  assert.equal(lines[0].job_id, 'job_test_audit');
  assert.equal(lines[0].device_id, 'dev_test_device_1');
  assert.equal(lines[0].files, 2);
  assert.equal(lines[0].file_bytes, 1234);
  assert.equal(lines[0].at, new Date(1_761_900_000_000).toISOString());
  for (const key of ['text', 'workspace', 'challenge', 'job_hash', 'file_name', 'token']) {
    assert.equal(key in lines[0], false, key);
  }
  assert.equal(lines[1].error, null);
});

test('audit serializes concurrent writes and rotates by size', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'phonejob-audit-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'audit.jsonl');
  const audit = new AuditLog({ filePath: file, maxBytes: 120, maxBackups: 2 });
  const writes = [];
  for (let index = 0; index < 8; index += 1) {
    writes.push(audit.record('job.submitted', { job_id: `job_${index}`, state: 'WAITING_CONFIRM' }));
  }
  await Promise.all(writes);
  await audit.close();

  const names = await readdir(dir);
  assert.equal(names.includes('audit.jsonl'), true);
  assert.equal(names.includes('audit.jsonl.1'), true);
  assert.equal(names.includes('audit.jsonl.2'), true);
  const current = (await readFile(file, 'utf8')).trim().split('\n');
  assert.equal(current.length, 1);
  assert.equal(JSON.parse(current[0]).event, 'job.submitted');
  const backup = (await readFile(`${file}.1`, 'utf8')).trim().split('\n');
  assert.equal(JSON.parse(backup[0]).event, 'job.submitted');
});

test('audit swallows write failures', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'phonejob-audit-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const audit = new AuditLog({ filePath: path.join(dir, 'bad\u0000name', 'audit.jsonl') });
  await audit.record('job.submitted', { job_id: 'job_test_audit' });
  await audit.close();
});
