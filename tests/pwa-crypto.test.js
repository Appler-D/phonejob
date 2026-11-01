// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import * as bridge from '../bridge/crypto.js';
import { computeConfirmationResponse } from '../bridge/confirm.js';
import { hotp as bridgeHotp, verifyTotp } from '../bridge/totp.js';
import { generateOtpSecret } from '../bridge/key-store.js';
import * as pwa from '../pwa/crypto.js';

async function keysForBothSides() {
  const pc = await bridge.generatePairingKeyPair();
  const phone = await pwa.generatePairingKeyPair();
  const phonePub = pwa.toBase64Url(phone.publicRaw);
  const pcPub = pwa.toBase64Url(pc.publicRaw);
  const pcShared = await bridge.deriveSharedSecret(
    pc.privateKey,
    await bridge.importPeerPublicKey(phone.publicRaw),
  );
  const phoneShared = await pwa.deriveSharedSecret(
    phone.privateKey,
    await pwa.importPeerPublicKey(pc.publicRaw),
  );
  const pcKeys = await bridge.derivePairingKeys(pcShared, 'pair-pwa');
  const phoneKeys = await pwa.derivePairingKeys(phoneShared, 'pair-pwa');
  return { pc, phone, phonePub, pcPub, pcShared, phoneShared, pcKeys, phoneKeys };
}

test('PWA and bridge derive the same pairing keys, SAS, and claim proof', async () => {
  const { phone, phonePub, pcPub, pcShared, phoneShared, pcKeys, phoneKeys } = await keysForBothSides();

  assert.equal(Buffer.from(pcShared).equals(Buffer.from(phoneShared)), true);
  for (const name of ['kPair', 'kSas', 'kConfirm', 'kEnc', 'kAuth']) {
    assert.equal(Buffer.from(pcKeys[name]).equals(Buffer.from(phoneKeys[name])), true, name);
  }

  const transcript = {
    v: 1,
    pair_id: 'pair-pwa',
    pc_pub: pcPub,
    phone_pub: phonePub,
    nonce: 'pair-nonce',
    expires_at: 1_761_900_000_000,
  };
  assert.equal(
    await bridge.computeSas(pcKeys.kSas, transcript),
    await pwa.computeSas(phoneKeys.kSas, transcript),
  );

  const claim = { type: 'pair-claim', pair_id: 'pair-pwa', phone_pub: phonePub };
  assert.equal(
    await bridge.hmacSha256Base64Url(pcKeys.kSas, bridge.canonicalJson(claim)),
    await pwa.hmacSha256Base64Url(phoneKeys.kSas, pwa.canonicalJson(claim)),
  );

  await assert.rejects(() => crypto.subtle.exportKey('jwk', phone.privateKey));
});

test('PWA opens provisioning and computes TOTP with a non-extractable key', async () => {
  const { pcShared, phoneShared } = await keysForBothSides();
  const pcKeys = await bridge.derivePairingKeys(pcShared, 'pair-pwa');
  const phoneKeys = await pwa.derivePairingKeys(phoneShared, 'pair-pwa');
  const otpSecret = generateOtpSecret();
  const envelope = await bridge.sealOtpProvisioning(pcKeys.kEnc, {
    pairId: 'pair-pwa',
    deviceId: 'dev_test',
    keyId: 'key-test',
    otpSecret,
  });

  const received = await pwa.openOtpProvisioning(phoneKeys.kEnc, envelope);
  assert.equal(Buffer.from(received.otpSecret).equals(otpSecret), true);
  assert.equal(received.keyId, 'key-test');

  const raw = new Uint8Array(received.otpSecret);
  const key = await pwa.importOtpKey(raw);
  assert.equal(raw.every((byte) => byte === 0), true);
  await assert.rejects(() => crypto.subtle.exportKey('raw', key));

  const now = 1_761_900_000_000;
  const counter = Math.floor(now / 1000 / 30);
  const code = await pwa.totpWithKey(key, now);
  assert.equal(code, bridgeHotp(otpSecret, counter));
  assert.equal(verifyTotp(otpSecret, code, now), true);

  await assert.rejects(() =>
    pwa.openOtpProvisioning(phoneKeys.kEnc, { ...envelope, device_id: 'dev_other' }),
  );
});

test('PWA seals a job envelope the bridge can open', async () => {
  const { pcKeys, phoneKeys } = await keysForBothSides();
  const aesKey = await pwa.importAesKey(phoneKeys.kEnc);
  await assert.rejects(() => crypto.subtle.exportKey('raw', aesKey));

  const header = {
    v: 2,
    job_id: 'job_pwa_1',
    device_id: 'dev_test_device_1',
    ts: 1_761_900_000,
    seq: 1,
    otp: '123456',
  };
  const job = {
    version: 1,
    job_id: header.job_id,
    device_id: header.device_id,
    target: { workspace: 'D:\\work', preset: 'default', session: null },
    intent: 'ask',
    text: 'hello from pwa',
    files: [],
    reply: { want: 'text', max_bytes: 1024 },
  };
  const envelope = await pwa.sealEnvelope(aesKey, header, JSON.stringify(job));
  const opened = await bridge.openEnvelope(pcKeys.kEnc, envelope);
  assert.equal(Buffer.from(opened.plaintext).toString('utf8'), JSON.stringify(job));

  await assert.rejects(() =>
    bridge.openEnvelope(pcKeys.kEnc, { ...envelope, job_id: 'job_other_1' }),
  );

  const hmacKey = await pwa.importHmacKey(phoneKeys.kConfirm);
  await assert.rejects(() => crypto.subtle.exportKey('raw', hmacKey));
});

test('PWA and bridge seal and open file chunks', async () => {
  const { pcKeys, phoneKeys } = await keysForBothSides();
  const bytes = new Uint8Array(1024).fill(7);
  const meta = {
    jobId: 'job_test_file',
    fileIndex: 0,
    fileSha256: 'A'.repeat(43),
    chunkIndex: 0,
    totalChunks: 1,
  };
  const sealed = await bridge.sealFileChunk(pcKeys.kEnc, meta, bytes);
  const aesKey = await pwa.importAesKey(phoneKeys.kEnc);
  const opened = await pwa.openFileChunk(aesKey, sealed);
  assert.deepEqual(Array.from(opened.bytes), Array.from(bytes));

  const pwaSealed = await pwa.sealFileChunk(aesKey, meta, bytes);
  const bridgeOpened = await bridge.openFileChunk(phoneKeys.kEnc, pwaSealed);
  assert.deepEqual(Array.from(bridgeOpened.bytes), Array.from(bytes));
  await assert.rejects(() => pwa.openFileChunk(aesKey, { ...sealed, file_index: 1 }));
});

test('PWA opens a result envelope sealed by the bridge', async () => {
  const { pcKeys, phoneKeys } = await keysForBothSides();
  const header = {
    v: 1,
    type: 'job-result-v1',
    job_id: 'job_test_result',
    device_id: 'dev_test_device_1',
  };
  const result = {
    job_id: 'job_test_result',
    status: 'done',
    finished_at: '2026-11-01T00:00:00.000Z',
    text: 'the answer',
    files: [],
    error: null,
  };
  const sealed = await bridge.sealEnvelope(pcKeys.kEnc, header, JSON.stringify(result));
  const aesKey = await pwa.importAesKey(phoneKeys.kEnc);
  const opened = await pwa.openEnvelope(aesKey, sealed);
  assert.equal(Buffer.from(opened.plaintext).toString('utf8'), JSON.stringify(result));
  await assert.rejects(() =>
    pwa.openEnvelope(aesKey, { ...sealed, job_id: 'job_other_1' }),
  );
});

test('PWA confirmation response and status proof match the bridge', async () => {
  const { phoneKeys } = await keysForBothSides();
  const confirmKey = await pwa.importHmacKey(phoneKeys.kConfirm);
  const authKey = await pwa.importHmacKey(phoneKeys.kAuth);

  assert.equal(
    await pwa.computeReceiptResponse(confirmKey, 'job-hash', '123456'),
    computeConfirmationResponse(phoneKeys.kConfirm, 'job-hash', '123456'),
  );

  const statusMessage = bridge.canonicalJson({
    type: 'job-status-v1',
    device_id: 'dev_test_device_1',
    job_id: 'job_test_status',
    ts: 1_761_900_000,
  });
  assert.equal(
    pwa.toBase64Url(await pwa.hmacWithKey(authKey, statusMessage)),
    await bridge.hmacSha256Base64Url(phoneKeys.kAuth, statusMessage),
  );
});

test('PWA base64url and canonical JSON match the bridge', () => {
  const bytes = new Uint8Array([0, 1, 2, 3, 128, 250, 255]);
  assert.equal(pwa.toBase64Url(bytes), Buffer.from(bytes).toString('base64url'));
  assert.deepEqual(Array.from(pwa.fromBase64Url(pwa.toBase64Url(bytes))), Array.from(bytes));

  const value = { b: [1, 2], a: { d: 4, c: 3 } };
  assert.equal(pwa.canonicalJson(value), bridge.canonicalJson(value));
});
