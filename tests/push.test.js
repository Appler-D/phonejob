// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, createECDH, createPublicKey, hkdfSync, randomBytes, verify } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { buildVapidAuthorization, encryptPushPayload, sendPush } from '../bridge/push.js';
import { PushService } from '../bridge/push-service.js';
import { loadOrCreateVapidStore, readVapidStore } from '../bridge/vapid-store.js';

const subtle = globalThis.crypto.subtle;
const WINDOWS = process.platform === 'win32';

async function makeVapid() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const privateJwk = await subtle.exportKey('jwk', pair.privateKey);
  const publicKey = Buffer.from(await subtle.exportKey('raw', pair.publicKey)).toString(
    'base64url',
  );
  return { privateJwk, publicKey };
}

test('VAPID store persists and signs a verifiable JWT', { skip: !WINDOWS }, async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'phonejob-vapid-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'vapid.bin');
  const vapid = await loadOrCreateVapidStore(file);
  assert.equal(Buffer.from(vapid.publicKey, 'base64url').length, 65);
  const reopened = await readVapidStore(file);
  assert.equal(reopened.publicKey, vapid.publicKey);
  assert.equal(reopened.privateJwk.d, vapid.privateJwk.d);

  const now = 1_761_900_000_000;
  const authorization = buildVapidAuthorization({
    privateJwk: vapid.privateJwk,
    publicKey: vapid.publicKey,
    endpoint: 'https://push.example/send/abc',
    now,
  });
  const match = /^vapid t=([^,]+), k=(.+)$/.exec(authorization);
  assert.ok(match);
  assert.equal(match[2], vapid.publicKey);
  const [header, claims, signature] = match[1].split('.');
  const parsed = JSON.parse(Buffer.from(claims, 'base64url').toString('utf8'));
  assert.equal(parsed.aud, 'https://push.example');
  assert.equal(parsed.exp, Math.floor(now / 1000) + 12 * 60 * 60);
  const publicKey = createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: vapid.privateJwk.x, y: vapid.privateJwk.y },
    format: 'jwk',
  });
  assert.equal(
    verify(
      'sha256',
      Buffer.from(`${header}.${claims}`),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64url'),
    ),
    true,
  );
});

test('push payload encrypts to the subscription and sendPush posts it', async () => {
  const vapid = await makeVapid();
  const ua = createECDH('prime256v1');
  ua.generateKeys();
  const p256dh = ua.getPublicKey();
  const auth = randomBytes(16);
  const payload = Buffer.from(JSON.stringify({ hello: 'world' }));

  const body = encryptPushPayload(
    { p256dh: p256dh.toString('base64url'), auth: auth.toString('base64url') },
    payload,
  );
  const salt = body.subarray(0, 16);
  const recordSize = body.readUInt32BE(16);
  const idLength = body[20];
  const asPublic = body.subarray(21, 21 + idLength);
  const ciphertext = body.subarray(21 + idLength);
  assert.equal(recordSize, 4096);
  assert.equal(idLength, 65);

  const shared = ua.computeSecret(asPublic);
  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0'), p256dh, asPublic]);
  const ikm = Buffer.from(hkdfSync('sha256', shared, auth, keyInfo, 32));
  const cek = Buffer.from(
    hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16),
  );
  const nonce = Buffer.from(
    hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12),
  );
  const decipher = createDecipheriv('aes-128-gcm', cek, nonce);
  const tag = ciphertext.subarray(ciphertext.length - 16);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([
    decipher.update(ciphertext.subarray(0, ciphertext.length - 16)),
    decipher.final(),
  ]);
  assert.equal(plaintext[plaintext.length - 1], 0x02);
  assert.deepEqual(JSON.parse(plaintext.subarray(0, -1).toString('utf8')), { hello: 'world' });

  let captured;
  const fetchImpl = async (url, options) => {
    captured = { url, options };
    return { ok: true, status: 201 };
  };
  const result = await sendPush({
    subscription: {
      endpoint: 'https://push.example/send/abc',
      keys: { p256dh: p256dh.toString('base64url'), auth: auth.toString('base64url') },
    },
    vapid,
    payload,
    fetchImpl,
    now: 1_761_900_000_000,
  });
  assert.deepEqual(result, { ok: true, status: 201 });
  assert.equal(captured.url, 'https://push.example/send/abc');
  assert.equal(captured.options.method, 'POST');
  assert.equal(captured.options.headers['Content-Encoding'], 'aes128gcm');
  assert.match(captured.options.headers.Authorization, /^vapid t=.+, k=.+$/);
});

test('PushService sends job notifications and drops gone subscriptions', async () => {
  const vapid = await makeVapid();
  const ua = createECDH('prime256v1');
  ua.generateKeys();
  const subscription = {
    endpoint: 'https://push.example/sub/1',
    p256dh: ua.getPublicKey().toString('base64url'),
    auth: randomBytes(16).toString('base64url'),
  };
  let deleted = false;
  let status = 201;
  const store = {
    async getPushSubscription() {
      return subscription;
    },
    async deletePushSubscription() {
      deleted = true;
    },
  };
  const service = new PushService({
    deviceStore: store,
    vapid,
    fetchImpl: async () => ({ ok: status < 300, status }),
  });
  const sent = await service.notify({ deviceId: 'dev_test', jobId: 'job_test', state: 'DONE' });
  assert.equal(sent.ok, true);
  assert.equal(deleted, false);

  status = 410;
  const gone = await service.notify({ deviceId: 'dev_test', jobId: 'job_test', state: 'FAILED' });
  assert.equal(gone.status, 410);
  assert.equal(deleted, true);
});
