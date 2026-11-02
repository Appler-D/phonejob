// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createBackup, restoreBackup } from '../bridge/backup.js';
import { SqliteJobStore } from '../bridge/job-store.js';

function job() {
  return {
    job_id: 'job_backup_1',
    device_id: 'dev_test_1',
    state: 'WAITING_CONFIRM',
    risk: 'low',
    intent: 'ask',
    workspace: 'C:\\workspace',
    inbox_path: 'C:\\inbox\\job_backup_1',
    created_at: 1,
    updated_at: 1,
  };
}

test('backup and restore round-trip data, database, audit, and inbox', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'phonejob-backup-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const dataDir = path.join(root, 'data');
  const inboxDir = path.join(root, 'inbox');
  const outDir = path.join(root, 'backup');
  await mkdir(dataDir, { recursive: true });
  await mkdir(path.join(inboxDir, 'pending', 'job_backup_1'), { recursive: true });
  await writeFile(path.join(dataDir, 'keys.bin'), Buffer.from('keys'));
  await writeFile(path.join(dataDir, 'vapid.bin'), Buffer.from('vapid'));
  await writeFile(path.join(dataDir, 'admin.token'), 'token\n');
  await writeFile(path.join(dataDir, 'audit.jsonl'), '{"event":"test"}\n');
  await writeFile(
    path.join(inboxDir, 'pending', 'job_backup_1', 'job.json'),
    '{"job_id":"job_backup_1"}',
  );
  const store = new SqliteJobStore({ filePath: path.join(dataDir, 'phonejob.sqlite') });
  await store.saveJobWithSequence({ job: job(), seq: 1, nonce: 'nonce-1' });
  await store.close();

  const backup = await createBackup({
    dataDir,
    inboxDir,
    outDir,
    includeInbox: true,
    now: () => 1_761_900_000_000,
  });
  assert.equal(backup.manifest.include_inbox, true);
  assert.equal(
    backup.manifest.files.some((file) => file.path === 'phonejob.sqlite'),
    true,
  );

  const dataDir2 = path.join(root, 'data-restored');
  const inboxDir2 = path.join(root, 'inbox-restored');
  const restored = await restoreBackup({
    backupDir: outDir,
    dataDir: dataDir2,
    inboxDir: inboxDir2,
  });
  assert.equal(restored.inboxDir, inboxDir2);
  assert.equal((await readFile(path.join(dataDir2, 'keys.bin'), 'utf8')), 'keys');
  assert.equal((await readFile(path.join(dataDir2, 'audit.jsonl'), 'utf8')), '{"event":"test"}\n');
  assert.equal(
    await readFile(path.join(inboxDir2, 'pending', 'job_backup_1', 'job.json'), 'utf8'),
    '{"job_id":"job_backup_1"}',
  );
  const reopened = new SqliteJobStore({ filePath: path.join(dataDir2, 'phonejob.sqlite') });
  assert.equal((await reopened.getJob('job_backup_1')).state, 'WAITING_CONFIRM');
  await reopened.close();

  const manifestPath = path.join(outDir, 'manifest.json');
  const tampered = JSON.parse(await readFile(manifestPath, 'utf8'));
  tampered.files[0].sha256 = 'B'.repeat(43);
  await writeFile(manifestPath, JSON.stringify(tampered));
  await assert.rejects(
    () =>
      restoreBackup({
        backupDir: outDir,
        dataDir: path.join(root, 'data-tampered'),
        inboxDir: path.join(root, 'inbox-tampered'),
      }),
    /checksum/,
  );
});
