// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { createECDH, randomBytes } from 'node:crypto';
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
  openOtpRefresh,
  pairingTranscript,
} from '../bridge/crypto.js';
import { generateOtpSecret } from '../bridge/key-store.js';
import { totp, verifyTotp } from '../bridge/totp.js';

async function startFixture({ now = () => Date.now(), pairingTtlMs = 120_000, audit, rotateOtp } = {}) {
  const otpSecret = generateOtpSecret();
  const service = new PairingService({
    loadOtp: async () => ({ secret: otpSecret, keyId: 'key-test' }),
    now,
    pairingTtlMs,
    rotateOtp,
    audit,
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

test('pairing emits redacted audit events', async () => {
  const events = [];
  const audit = {
    record(event, fields) {
      events.push({ event, ...fields });
    },
  };
  const fixture = await claimedFixture({ audit });
  const wrongSas = fixture.sas === '000000' ? '111111' : '000000';
  assert.throws(
    () => fixture.service.confirmPairing({ pairId: fixture.start.pair_id, sas: wrongSas }),
    (err) => err.code === 'SAS_MISMATCH',
  );
  await fixture.service.confirmPairing({ pairId: fixture.start.pair_id, sas: fixture.sas });
  await fixture.service.provisionOtp({
    pairId: fixture.start.pair_id,
    deviceId: fixture.claim.device_id,
    proof: await provisionProof(fixture),
  });
  await fixture.service.revokeDevice(fixture.claim.device_id);

  assert.deepEqual(
    events.map((entry) => entry.event),
    [
      'pairing.started',
      'pairing.claimed',
      'pairing.rejected',
      'pairing.confirmed',
      'pairing.provisioned',
      'pairing.revoked',
    ],
  );
  assert.equal(events[2].reason, 'sas_mismatch');
  for (const entry of events) {
    for (const key of ['sas', 'phone_pub', 'keys', 'otpSecret', 'proof']) {
      assert.equal(key in entry, false, key);
    }
  }
});

test('revoking a device rotates K_otp once', async () => {
  let rotations = 0;
  const fixture = await claimedFixture({
    rotateOtp: async () => {
      rotations += 1;
    },
  });
  fixture.service.confirmPairing({ pairId: fixture.start.pair_id, sas: fixture.sas });
  await fixture.service.provisionOtp({
    pairId: fixture.start.pair_id,
    deviceId: fixture.claim.device_id,
    proof: await provisionProof(fixture),
  });

  assert.equal((await fixture.service.revokeDevice(fixture.claim.device_id)).ok, true);
  assert.equal(rotations, 1);
  assert.equal((await fixture.service.revokeDevice(fixture.claim.device_id)).ok, true);
  assert.equal(rotations, 1);
});

test('a device can refresh the current OTP envelope', async () => {
  const fixture = await claimedFixture();
  fixture.service.confirmPairing({ pairId: fixture.start.pair_id, sas: fixture.sas });
  await fixture.service.provisionOtp({
    pairId: fixture.start.pair_id,
    deviceId: fixture.claim.device_id,
    proof: await provisionProof(fixture),
  });
  const deviceId = fixture.claim.device_id;
  const ts = Math.floor(fixture.service.now() / 1000);
  const proof = await hmacSha256Base64Url(
    fixture.keys.kAuth,
    canonicalJson({ type: 'otp-refresh-v1', device_id: deviceId, ts }),
  );
  const envelope = await fixture.service.refreshOtp({ deviceId, ts, proof });
  const opened = await openOtpRefresh(fixture.keys.kEnc, envelope);
  assert.equal(opened.deviceId, deviceId);
  assert.equal(opened.keyId, 'key-test');
  assert.equal(Buffer.from(opened.otpSecret).equals(fixture.otpSecret), true);

  await assert.rejects(
    () => fixture.service.refreshOtp({ deviceId, ts, proof: 'bad' }),
    (err) => err.code === 'DEVICE_AUTH',
  );
  await fixture.service.revokeDevice(deviceId);
  await assert.rejects(
    () => fixture.service.refreshOtp({ deviceId, ts, proof }),
    (err) => err.code === 'DEVICE_NOT_FOUND',
  );
});

test('a device can register and clear a push subscription', async () => {
  const fixture = await claimedFixture();
  fixture.service.confirmPairing({ pairId: fixture.start.pair_id, sas: fixture.sas });
  await fixture.service.provisionOtp({
    pairId: fixture.start.pair_id,
    deviceId: fixture.claim.device_id,
    proof: await provisionProof(fixture),
  });
  const deviceId = fixture.claim.device_id;
  const ua = createECDH('prime256v1');
  ua.generateKeys();
  const subscription = {
    endpoint: 'https://push.example/sub/1',
    keys: {
      p256dh: ua.getPublicKey().toString('base64url'),
      auth: randomBytes(16).toString('base64url'),
    },
  };
  const ts = Math.floor(fixture.service.now() / 1000);
  const proof = await hmacSha256Base64Url(
    fixture.keys.kAuth,
    canonicalJson({ type: 'push-subscribe-v1', device_id: deviceId, ts }),
  );
  assert.equal(
    (await fixture.service.registerPush({ deviceId, ts, proof, subscription })).ok,
    true,
  );
  const stored = await fixture.service.deviceStore.getPushSubscription(deviceId);
  assert.equal(stored.endpoint, subscription.endpoint);
  await assert.rejects(
    () => fixture.service.registerPush({ deviceId, ts, proof: 'bad', subscription }),
    (err) => err.code === 'DEVICE_AUTH',
  );
  await assert.rejects(
    () =>
      fixture.service.registerPush({
        deviceId,
        ts,
        proof,
        subscription: { ...subscription, endpoint: 'http://insecure.example' },
      }),
    (err) => err.code === 'PUSH_SUBSCRIPTION_INVALID',
  );
  await fixture.service.revokeDevice(deviceId);
  assert.equal(await fixture.service.deviceStore.getPushSubscription(deviceId), null);
});
