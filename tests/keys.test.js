// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  createKeyStore,
  loadOrCreateKeyStore,
  otpFingerprint,
  readKeyStore,
  rotateKeyStore,
} from '../bridge/key-store.js';

const WINDOWS = process.platform === 'win32';

async function tempDir(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'phonejob-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

test('K_otp fingerprints are stable and distinguish secrets', () => {
  const secret = Buffer.alloc(32, 0x42);
  assert.equal(otpFingerprint(secret).length, 16);
  assert.equal(otpFingerprint(secret), otpFingerprint(Buffer.from(secret)));
  assert.notEqual(otpFingerprint(secret), otpFingerprint(Buffer.alloc(32, 0x43)));
});

test('DPAPI key store round-trips without storing plaintext', { skip: !WINDOWS }, async (t) => {
  const dir = await tempDir(t);
  const file = path.join(dir, 'keys.bin');
  const secret = Buffer.alloc(32, 0x11);

  const created = await createKeyStore(file, { secret });
  assert.equal(created.secret.equals(secret), true);

  const loaded = await readKeyStore(file);
  assert.equal(loaded.secret.equals(secret), true);
  assert.equal(loaded.keyId, created.keyId);

  const blob = await readFile(file);
  assert.equal(blob.includes(secret), false);
  assert.equal(blob.toString('utf8').includes(secret.toString('base64')), false);
});

test('loadOrCreateKeyStore reuses the existing key', { skip: !WINDOWS }, async (t) => {
  const dir = await tempDir(t);
  const file = path.join(dir, 'keys.bin');

  const first = await loadOrCreateKeyStore(file);
  const second = await loadOrCreateKeyStore(file);

  assert.equal(first.secret.equals(second.secret), true);
  assert.equal(first.keyId, second.keyId);
});

test('rotateKeyStore replaces the key', { skip: !WINDOWS }, async (t) => {
  const dir = await tempDir(t);
  const file = path.join(dir, 'keys.bin');

  const before = await loadOrCreateKeyStore(file);
  const after = await rotateKeyStore(file);

  assert.equal(before.secret.equals(after.secret), false);
  assert.notEqual(before.keyId, after.keyId);
});

test('corrupted key store is rejected instead of overwritten', { skip: !WINDOWS }, async (t) => {
  const dir = await tempDir(t);
  const file = path.join(dir, 'keys.bin');
  await writeFile(file, Buffer.from('not a dpapi blob'));

  await assert.rejects(() => readKeyStore(file), /DPAPI|corrupted|unsupported/i);
  await assert.rejects(() => loadOrCreateKeyStore(file), /DPAPI|corrupted|unsupported/i);
});
