// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import * as bridge from '../bridge/crypto.js';
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

test('PWA base64url and canonical JSON match the bridge', () => {
  const bytes = new Uint8Array([0, 1, 2, 3, 128, 250, 255]);
  assert.equal(pwa.toBase64Url(bytes), Buffer.from(bytes).toString('base64url'));
  assert.deepEqual(Array.from(pwa.fromBase64Url(pwa.toBase64Url(bytes))), Array.from(bytes));

  const value = { b: [1, 2], a: { d: 4, c: 3 } };
  assert.equal(pwa.canonicalJson(value), bridge.canonicalJson(value));
});
