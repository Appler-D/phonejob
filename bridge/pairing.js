// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { randomBytes, timingSafeEqual } from 'node:crypto';
import {
  canonicalJson,
  computeSas,
  derivePairingKeys,
  deriveSharedSecret,
  generatePairingKeyPair,
  hmacSha256Base64Url,
  importPeerPublicKey,
  pairingTranscript,
  sealOtpProvisioning,
  sealOtpRefresh,
} from './crypto.js';
import { MemoryDeviceStore } from './device-store.js';

const PAIRING_TTL_MS = 120_000;
const PROVISION_TTL_MS = 300_000;
const MAX_DEVICES = 5;
const DEVICE_ID_RE = /^dev_[A-Za-z0-9_-]{8,64}$/;

function pairingError(code) {
  const error = new Error('Pairing rejected');
  error.code = code;
  return error;
}

function safeEqualText(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function safeEqualBase64Url(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left, 'base64url');
  const b = Buffer.from(right, 'base64url');
  return a.length === b.length && timingSafeEqual(a, b);
}

function decodePublicKey(value) {
  if (typeof value !== 'string') throw pairingError('PHONE_PUB_INVALID');
  const raw = Buffer.from(value, 'base64url');
  if (raw.length !== 65 || raw[0] !== 0x04 || raw.toString('base64url') !== value) {
    throw pairingError('PHONE_PUB_INVALID');
  }
  return new Uint8Array(raw);
}

export class PairingService {
  constructor({
    loadOtp,
    deviceStore = new MemoryDeviceStore(),
    now = () => Date.now(),
    pairingTtlMs = PAIRING_TTL_MS,
    provisionTtlMs = PROVISION_TTL_MS,
    rotateOtp = null,
    audit = null,
  } = {}) {
    if (typeof loadOtp !== 'function') throw new TypeError('loadOtp is required');
    this.loadOtp = loadOtp;
    this.deviceStore = deviceStore;
    this.now = now;
    this.pairingTtlMs = pairingTtlMs;
    this.provisionTtlMs = provisionTtlMs;
    this.rotateOtp = rotateOtp;
    this.audit = audit;
    this.pairings = new Map();
  }

  async startPairing({ bridgeUrl } = {}) {
    this.purgeExpired();
    const pairId = randomBytes(16).toString('base64url');
    const nonce = randomBytes(16).toString('base64url');
    const { publicRaw, privateKey } = await generatePairingKeyPair();
    const now = this.now();
    const session = {
      pairId,
      bridgeUrl,
      privateKey,
      pcPub: Buffer.from(publicRaw).toString('base64url'),
      nonce,
      state: 'waiting',
      createdAt: now,
      expiresAt: now + this.pairingTtlMs,
    };
    this.pairings.set(pairId, session);
    this.audit?.record('pairing.started', { pairing_id: pairId });
    return {
      pair_id: pairId,
      pc_pub: session.pcPub,
      nonce,
      expires_at: session.expiresAt,
      qr: {
        bridge_url: bridgeUrl,
        pair_id: pairId,
        pc_pub: session.pcPub,
        nonce,
        expires: Math.floor(this.pairingTtlMs / 1000),
        expires_at: session.expiresAt,
      },
    };
  }

  getStatus(pairId) {
    const session = this.#requirePairing(pairId);
    if (session.state === 'waiting') {
      return { state: 'waiting', expires_at: session.expiresAt };
    }
    return {
      state: session.state,
      device_id: session.deviceId,
      sas: session.sas,
      phone_pub: session.phonePub,
      expires_at: session.provisionExpiresAt ?? session.expiresAt,
    };
  }

  async claimPairing({ pairId, phonePub, proof }) {
    const session = this.#requirePairing(pairId);
    if (session.state !== 'waiting') throw pairingError('PAIRING_NOT_WAITING');
    if (this.now() > session.expiresAt) {
      this.pairings.delete(pairId);
      throw pairingError('PAIRING_EXPIRED');
    }

    const phonePubRaw = decodePublicKey(phonePub);
    const phonePublicKey = await importPeerPublicKey(phonePubRaw);
    const shared = await deriveSharedSecret(session.privateKey, phonePublicKey);
    const keys = await derivePairingKeys(shared, pairId);
    const expectedProof = await hmacSha256Base64Url(
      keys.kSas,
      canonicalJson({ type: 'pair-claim', pair_id: pairId, phone_pub: phonePub }),
    );
    if (!safeEqualBase64Url(proof, expectedProof)) {
      this.audit?.record('pairing.rejected', { pairing_id: pairId, reason: 'claim_proof' });
      throw pairingError('PAIRING_PROOF_INVALID');
    }

    const transcript = pairingTranscript({
      pairId,
      pcPub: session.pcPub,
      phonePub,
      nonce: session.nonce,
      expiresAt: session.expiresAt,
    });
    session.sas = await computeSas(keys.kSas, transcript);
    session.phonePub = phonePub;
    session.phonePubRaw = phonePubRaw;
    session.deviceId = `dev_${randomBytes(12).toString('base64url')}`;
    session.keys = keys;
    session.claimedAt = this.now();
    session.state = 'claimed';
    this.audit?.record('pairing.claimed', {
      pairing_id: pairId,
      device_id: session.deviceId,
    });
    return { device_id: session.deviceId };
  }

  confirmPairing({ pairId, sas }) {
    const session = this.#requirePairing(pairId);
    if (session.state !== 'claimed') throw pairingError('PAIRING_NOT_CLAIMED');
    if (this.now() > session.expiresAt) {
      this.pairings.delete(pairId);
      throw pairingError('PAIRING_EXPIRED');
    }
    const normalized = String(sas ?? '').replace(/\s+/g, '');
    if (!safeEqualText(normalized, session.sas)) {
      this.audit?.record('pairing.rejected', {
        pairing_id: pairId,
        device_id: session.deviceId,
        reason: 'sas_mismatch',
      });
      throw pairingError('SAS_MISMATCH');
    }
    session.state = 'confirmed';
    session.confirmedAt = this.now();
    session.provisionExpiresAt = session.confirmedAt + this.provisionTtlMs;
    this.audit?.record('pairing.confirmed', {
      pairing_id: pairId,
      device_id: session.deviceId,
    });
    return { ok: true };
  }

  async provisionOtp({ pairId, deviceId, proof }) {
    const session = this.#requirePairing(pairId);
    if (session.state !== 'confirmed' && session.state !== 'provisioned') {
      throw pairingError('PAIRING_NOT_CONFIRMED');
    }
    if (this.now() > session.provisionExpiresAt) {
      this.pairings.delete(pairId);
      throw pairingError('PAIRING_EXPIRED');
    }
    if (deviceId !== session.deviceId) {
      this.audit?.record('pairing.rejected', {
        pairing_id: pairId,
        device_id: deviceId,
        reason: 'device_mismatch',
      });
      throw pairingError('DEVICE_MISMATCH');
    }

    const expectedProof = await hmacSha256Base64Url(
      session.keys.kConfirm,
      canonicalJson({ type: 'otp-provision-request', pair_id: pairId, device_id: deviceId }),
    );
    if (!safeEqualBase64Url(proof, expectedProof)) {
      this.audit?.record('pairing.rejected', {
        pairing_id: pairId,
        device_id: deviceId,
        reason: 'provision_proof',
      });
      throw pairingError('PROVISION_PROOF_INVALID');
    }
    if (session.state === 'provisioned') return session.provisionEnvelope;
    const activeDevices = (await this.deviceStore.listDevices()).filter((device) => !device.revoked).length;
    if (activeDevices >= MAX_DEVICES) {
      this.audit?.record('pairing.rejected', {
        pairing_id: pairId,
        device_id: deviceId,
        reason: 'device_limit',
      });
      throw pairingError('DEVICE_LIMIT');
    }

    const { secret, keyId } = await this.loadOtp();
    if (!Buffer.isBuffer(secret) || secret.length !== 32) {
      throw new Error('Invalid OTP secret');
    }
    const envelope = await sealOtpProvisioning(session.keys.kEnc, {
      pairId,
      deviceId,
      keyId,
      otpSecret: secret,
    });
    await this.deviceStore.saveDevice({
      deviceId,
      phonePub: session.phonePub,
      keys: {
        kEnc: session.keys.kEnc,
        kConfirm: session.keys.kConfirm,
        kAuth: session.keys.kAuth,
      },
      keyId,
      createdAt: this.now(),
    });
    session.state = 'provisioned';
    session.provisionEnvelope = envelope;
    this.audit?.record('pairing.provisioned', {
      pairing_id: pairId,
      device_id: deviceId,
    });
    return envelope;
  }

  cancelPairing(pairId) {
    const session = this.#requirePairing(pairId);
    if (session.state === 'provisioned') throw pairingError('PAIRING_NOT_CANCELLABLE');
    this.pairings.delete(pairId);
    this.audit?.record('pairing.cancelled', {
      pairing_id: pairId,
      device_id: session.deviceId,
    });
    return { ok: true };
  }

  listDevices() {
    return this.deviceStore.listDevices();
  }

  async refreshOtp({ deviceId, ts, proof }) {
    if (typeof deviceId !== 'string' || !DEVICE_ID_RE.test(deviceId)) {
      throw pairingError('DEVICE_NOT_FOUND');
    }
    if (!Number.isInteger(ts) || Math.abs(this.now() / 1000 - ts) > 120) {
      throw pairingError('DEVICE_AUTH');
    }
    const device = await this.deviceStore.getDevice(deviceId);
    if (!device || device.revoked) throw pairingError('DEVICE_NOT_FOUND');
    const expected = await hmacSha256Base64Url(
      device.keys.kAuth,
      canonicalJson({ type: 'otp-refresh-v1', device_id: deviceId, ts }),
    );
    if (!safeEqualBase64Url(proof, expected)) throw pairingError('DEVICE_AUTH');
    const { secret, keyId } = await this.loadOtp();
    this.audit?.record('device.otp_refreshed', { device_id: deviceId });
    return sealOtpRefresh(device.keys.kEnc, { deviceId, keyId, otpSecret: secret });
  }

  async revokeDevice(deviceId) {
    const device = await this.deviceStore.getDevice(deviceId);
    if (!device) throw pairingError('DEVICE_NOT_FOUND');
    if (device.revoked) return { ok: true };
    const revoked = await this.deviceStore.revokeDevice(deviceId);
    if (!revoked) throw pairingError('DEVICE_NOT_FOUND');
    this.audit?.record('pairing.revoked', { device_id: deviceId });
    if (this.rotateOtp) {
      try {
        await this.rotateOtp();
      } catch {
        this.audit?.record('otp.rotate_failed', {
          device_id: deviceId,
          error: 'OTP_ROTATE_FAILED',
        });
        throw pairingError('OTP_ROTATE_FAILED');
      }
      this.audit?.record('otp.rotated', { device_id: deviceId, reason: 'device_revoked' });
    }
    return { ok: true };
  }

  purgeExpired() {
    const now = this.now();
    for (const [pairId, session] of this.pairings) {
      const expiry =
        session.state === 'confirmed' || session.state === 'provisioned'
          ? session.provisionExpiresAt
          : session.expiresAt;
      if (now > expiry) this.pairings.delete(pairId);
    }
  }

  #requirePairing(pairId) {
    const session = this.pairings.get(pairId);
    if (!session) throw pairingError('PAIRING_NOT_FOUND');
    return session;
  }
}
