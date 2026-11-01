// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalJson,
  computeSas,
  derivePairingKeys,
  deriveSharedSecret,
  generatePairingKeyPair,
  importPeerPublicKey,
  openEnvelope,
  openOtpProvisioning,
  sealEnvelope,
  sealOtpProvisioning,
} from '../bridge/crypto.js';
import { generateOtpSecret } from '../bridge/key-store.js';
import { totp, verifyTotp } from '../bridge/totp.js';

async function pairingFixture() {
  const pc = await generatePairingKeyPair();
  const phone = await generatePairingKeyPair();
  const pcShared = await deriveSharedSecret(pc.privateKey, await importPeerPublicKey(phone.publicRaw));
  const phoneShared = await deriveSharedSecret(phone.privateKey, await importPeerPublicKey(pc.publicRaw));
  const pcKeys = await derivePairingKeys(pcShared, 'pair-test');
  const phoneKeys = await derivePairingKeys(phoneShared, 'pair-test');
  const transcript = {
    v: 1,
    pair_id: 'pair-test',
    pc_pub: Buffer.from(pc.publicRaw).toString('base64url'),
    phone_pub: Buffer.from(phone.publicRaw).toString('base64url'),
    nonce: 'pair-nonce',
    expires: 120,
  };
  return { pc, phone, pcShared, phoneShared, pcKeys, phoneKeys, transcript };
}

test('canonicalJson is stable across key order', () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalJson({ a: [2, 1], b: { d: 4, c: 3 } }), '{"a":[2,1],"b":{"c":3,"d":4}}');
});

test('both sides derive the same pairing keys and SAS', async () => {
  const { pcShared, phoneShared, pcKeys, phoneKeys, transcript } = await pairingFixture();

  assert.equal(Buffer.from(pcShared).equals(Buffer.from(phoneShared)), true);
  for (const name of ['kPair', 'kSas', 'kConfirm', 'kEnc', 'kAuth']) {
    assert.equal(Buffer.from(pcKeys[name]).equals(Buffer.from(phoneKeys[name])), true, name);
  }

  const pcSas = await computeSas(pcKeys.kSas, transcript);
  const phoneSas = await computeSas(phoneKeys.kSas, transcript);
  assert.match(pcSas, /^\d{6}$/);
  assert.equal(pcSas, phoneSas);

  const changed = await computeSas(pcKeys.kSas, { ...transcript, phone_pub: 'different' });
  assert.notEqual(pcSas, changed);
});

test('envelope round-trips and rejects tampering', async () => {
  const { pcKeys, phoneKeys } = await pairingFixture();
  const header = {
    v: 2,
    job_id: 'job-1',
    device_id: 'device-1',
    ts: 1761900000,
    seq: 1,
    otp: '123456',
  };
  const sealed = await sealEnvelope(pcKeys.kEnc, header, JSON.stringify({ text: 'hello' }));
  const opened = await openEnvelope(phoneKeys.kEnc, sealed);
  assert.equal(Buffer.from(opened.plaintext).toString('utf8'), JSON.stringify({ text: 'hello' }));

  await assert.rejects(() => openEnvelope(phoneKeys.kEnc, { ...sealed, job_id: 'job-2' }));
  await assert.rejects(() => openEnvelope(phoneKeys.kEnc, { ...sealed, device_id: 'device-2' }));

  const tampered = Buffer.from(sealed.ct, 'base64url');
  tampered[0] ^= 0x01;
  await assert.rejects(() => openEnvelope(phoneKeys.kEnc, { ...sealed, ct: tampered.toString('base64url') }));

  const { pcKeys: otherKeys } = await pairingFixture();
  await assert.rejects(() => openEnvelope(otherKeys.kEnc, sealed));
});

test('PC-generated K_otp is provisioned to the phone and drives TOTP', async () => {
  const { pcKeys, phoneKeys } = await pairingFixture();
  const otpSecret = generateOtpSecret();
  const provisioning = await sealOtpProvisioning(pcKeys.kEnc, {
    pairId: 'pair-test',
    deviceId: 'device-1',
    keyId: 'key-1',
    otpSecret,
  });

  const received = await openOtpProvisioning(phoneKeys.kEnc, provisioning);
  assert.equal(received.otpSecret.equals(otpSecret), true);
  assert.equal(received.keyId, 'key-1');

  const now = 1_761_900_000_000;
  const code = totp(received.otpSecret, now);
  assert.equal(verifyTotp(otpSecret, code, now), true);

  await assert.rejects(() => openOtpProvisioning(phoneKeys.kEnc, { ...provisioning, device_id: 'device-2' }));
  await assert.rejects(() => openOtpProvisioning(phoneKeys.kEnc, { ...provisioning, key_id: 'key-2' }));
});
