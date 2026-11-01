// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { MemoryDeviceStore, SqliteDeviceStore } from '../bridge/device-store.js';

const WINDOWS = process.platform === 'win32';
const KEYS = {
  kEnc: Buffer.alloc(32, 0x11),
  kConfirm: Buffer.alloc(32, 0x22),
  kAuth: Buffer.alloc(32, 0x33),
};

test('MemoryDeviceStore stores, lists, reads, and revokes devices', async () => {
  const store = new MemoryDeviceStore();
  await store.saveDevice({
    deviceId: 'dev_a',
    phonePub: 'pub',
    keys: KEYS,
    keyId: 'key-test',
    createdAt: 1,
  });

  assert.deepEqual(await store.listDevices(), [
    { device_id: 'dev_a', created_at: 1, revoked: false },
  ]);
  const device = await store.getDevice('dev_a');
  assert.equal(device.phonePub, 'pub');
  assert.equal(device.keys.kEnc.equals(KEYS.kEnc), true);
  assert.equal(await store.revokeDevice('dev_a'), true);
  assert.equal((await store.listDevices())[0].revoked, true);
  assert.equal(await store.revokeDevice('dev_missing'), false);
  await store.close();
});

test('SqliteDeviceStore persists metadata and DPAPI-protected keys', { skip: !WINDOWS }, async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'phonejob-db-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'phonejob.sqlite');
  const createdAt = Date.now();

  const store = new SqliteDeviceStore({ filePath: file });
  await store.saveDevice({
    deviceId: 'dev_a',
    phonePub: 'pub',
    keys: KEYS,
    keyId: 'key-test',
    createdAt,
  });
  assert.deepEqual(await store.listDevices(), [
    { device_id: 'dev_a', created_at: createdAt, revoked: false },
  ]);
  const before = await store.getDevice('dev_a');
  assert.equal(before.keys.kEnc.equals(KEYS.kEnc), true);
  await store.close();

  const reopened = new SqliteDeviceStore({ filePath: file });
  const after = await reopened.getDevice('dev_a');
  assert.equal(after.keys.kEnc.equals(KEYS.kEnc), true);
  assert.equal(after.keys.kConfirm.equals(KEYS.kConfirm), true);
  assert.equal(after.keys.kAuth.equals(KEYS.kAuth), true);
  assert.equal(await reopened.revokeDevice('dev_a'), true);
  assert.equal((await reopened.listDevices())[0].revoked, true);
  await reopened.close();

  const blob = await readFile(file);
  assert.equal(blob.includes(KEYS.kEnc), false);
});
