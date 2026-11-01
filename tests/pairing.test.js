// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { PairingService } from '../bridge/pairing.js';
import {
  canonicalJson,
  computeSas,
  derivePairingKeys,
  deriveSharedSecret,
  generatePairingKeyPair,
  hmacSha256Base64Url,
  importPeerPublicKey,
  openOtpProvisioning,
  pairingTranscript,
} from '../bridge/crypto.js';
import { generateOtpSecret } from '../bridge/key-store.js';
import { totp, verifyTotp } from '../bridge/totp.js';

async function startFixture({ now = () => Date.now(), pairingTtlMs = 120_000 } = {}) {
  const otpSecret = generateOtpSecret();
  const service = new PairingService({
    loadOtp: async () => ({ secret: otpSecret, keyId: 'key-test' }),
    now,
    pairingTtlMs,
  });
  const start = await service.startPairing({ bridgeUrl: 'https://bridge.test' });
  const phone = await generatePairingKeyPair();
  const phonePub = Buffer.from(phone.publicRaw).toString('base64url');
  const pcPublicKey = await importPeerPublicKey(Buffer.from(start.pc_pub, 'base64url'));
  const shared = await deriveSharedSecret(phone.privateKey, pcPublicKey);
  const keys = await derivePairingKeys(shared, start.pair_id);
  const claimProof = await hmacSha256Base64Url(
    keys.kSas,
    canonicalJson({ type: 'pair-claim', pair_id: start.pair_id, phone_pub: phonePub }),
  );
  return { service, start, phone, phonePub, keys, claimProof, otpSecret };
}

async function claimedFixture(options) {
  const fixture = await startFixture(options);
  const claim = await fixture.service.claimPairing({
    pairId: fixture.start.pair_id,
    phonePub: fixture.phonePub,
    proof: fixture.claimProof,
  });
  const transcript = pairingTranscript({
    pairId: fixture.start.pair_id,
    pcPub: fixture.start.pc_pub,
    phonePub: fixture.phonePub,
    nonce: fixture.start.nonce,
    expiresAt: fixture.start.expires_at,
  });
  const sas = await computeSas(fixture.keys.kSas, transcript);
  return { ...fixture, claim, sas };
}

async function provisionProof(fixture) {
  return hmacSha256Base64Url(
    fixture.keys.kConfirm,
    canonicalJson({
      type: 'otp-provision-request',
      pair_id: fixture.start.pair_id,
      device_id: fixture.claim.device_id,
    }),
  );
}

test('pairing carries a PC-generated K_otp to the phone', async () => {
  const fixture = await claimedFixture();

  assert.equal(fixture.service.getStatus(fixture.start.pair_id).sas, fixture.sas);
  assert.equal(fixture.service.getStatus(fixture.start.pair_id).state, 'claimed');
  fixture.service.confirmPairing({ pairId: fixture.start.pair_id, sas: fixture.sas });

  const envelope = await fixture.service.provisionOtp({
    pairId: fixture.start.pair_id,
    deviceId: fixture.claim.device_id,
    proof: await provisionProof(fixture),
  });
  const received = await openOtpProvisioning(fixture.keys.kEnc, envelope);
  assert.equal(received.otpSecret.equals(fixture.otpSecret), true);
  assert.equal(received.keyId, 'key-test');

  const now = 1_761_900_000_000;
  const code = totp(received.otpSecret, now);
  assert.equal(verifyTotp(fixture.otpSecret, code, now), true);

  const retryProof = await provisionProof(fixture);
  const retry = await fixture.service.provisionOtp({
    pairId: fixture.start.pair_id,
    deviceId: fixture.claim.device_id,
    proof: retryProof,
  });
  assert.equal(retry.ct, envelope.ct);
  assert.equal((await fixture.service.listDevices()).length, 1);
  assert.equal(fixture.service.getStatus(fixture.start.pair_id).state, 'provisioned');
});

test('wrong SAS proof is rejected and the pairing can be retried', async () => {
  const fixture = await startFixture();
  await assert.rejects(
    fixture.service.claimPairing({
      pairId: fixture.start.pair_id,
      phonePub: fixture.phonePub,
      proof: 'not-a-proof',
    }),
    (err) => err.code === 'PAIRING_PROOF_INVALID',
  );
  assert.equal(fixture.service.getStatus(fixture.start.pair_id).state, 'waiting');

  const claim = await fixture.service.claimPairing({
    pairId: fixture.start.pair_id,
    phonePub: fixture.phonePub,
    proof: fixture.claimProof,
  });
  assert.equal(claim.device_id.startsWith('dev_'), true);
});

test('wrong SAS is rejected; correct SAS confirms', async () => {
  const fixture = await claimedFixture();
  const wrong = fixture.sas === '000000' ? '111111' : '000000';

  assert.throws(
    () => fixture.service.confirmPairing({ pairId: fixture.start.pair_id, sas: wrong }),
    (err) => err.code === 'SAS_MISMATCH',
  );
  assert.equal(fixture.service.confirmPairing({ pairId: fixture.start.pair_id, sas: fixture.sas }).ok, true);
});

test('K_otp cannot be provisioned before confirm or with a bad proof', async () => {
  const fixture = await claimedFixture();
  await assert.rejects(
    fixture.service.provisionOtp({
      pairId: fixture.start.pair_id,
      deviceId: fixture.claim.device_id,
      proof: await provisionProof(fixture),
    }),
    (err) => err.code === 'PAIRING_NOT_CONFIRMED',
  );

  fixture.service.confirmPairing({ pairId: fixture.start.pair_id, sas: fixture.sas });
  await assert.rejects(
    fixture.service.provisionOtp({
      pairId: fixture.start.pair_id,
      deviceId: 'dev_wrong',
      proof: await provisionProof(fixture),
    }),
    (err) => err.code === 'DEVICE_MISMATCH',
  );
  await assert.rejects(
    fixture.service.provisionOtp({
      pairId: fixture.start.pair_id,
      deviceId: fixture.claim.device_id,
      proof: 'bad',
    }),
    (err) => err.code === 'PROVISION_PROOF_INVALID',
  );
});

test('expired pairing is rejected', async () => {
  let now = 1_000_000;
  const fixture = await startFixture({ now: () => now, pairingTtlMs: 120_000 });
  now += 120_001;

  await assert.rejects(
    fixture.service.claimPairing({
      pairId: fixture.start.pair_id,
      phonePub: fixture.phonePub,
      proof: fixture.claimProof,
    }),
    (err) => err.code === 'PAIRING_EXPIRED',
  );
  assert.throws(
    () => fixture.service.getStatus(fixture.start.pair_id),
    (err) => err.code === 'PAIRING_NOT_FOUND',
  );
});

test('device revocation is local and idempotent', async () => {
  const fixture = await claimedFixture();
  fixture.service.confirmPairing({ pairId: fixture.start.pair_id, sas: fixture.sas });
  await fixture.service.provisionOtp({
    pairId: fixture.start.pair_id,
    deviceId: fixture.claim.device_id,
    proof: await provisionProof(fixture),
  });

  assert.equal((await fixture.service.revokeDevice(fixture.claim.device_id)).ok, true);
  assert.equal((await fixture.service.listDevices())[0].revoked, true);
  assert.equal((await fixture.service.revokeDevice(fixture.claim.device_id)).ok, true);
  await assert.rejects(
    () => fixture.service.revokeDevice('dev_missing'),
    (err) => err.code === 'DEVICE_NOT_FOUND',
  );
});
