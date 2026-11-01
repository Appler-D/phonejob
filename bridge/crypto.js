// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { randomBytes } from 'node:crypto';

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };
const AES_PARAMS = { name: 'AES-GCM', tagLength: 128 };
const HKDF_HASH = 'SHA-256';

function utf8(value) {
  return encoder.encode(value);
}

function toBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function fromBase64Url(value) {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

export async function generatePairingKeyPair() {
  const pair = await subtle.generateKey(ECDH_PARAMS, true, ['deriveBits']);
  const publicRaw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  const privateJwk = await subtle.exportKey('jwk', pair.privateKey);
  const privateKey = await subtle.importKey('jwk', privateJwk, ECDH_PARAMS, false, ['deriveBits']);
  return { publicRaw, privateKey };
}

export async function importPeerPublicKey(raw) {
  return subtle.importKey('raw', raw, ECDH_PARAMS, false, []);
}

export async function deriveSharedSecret(privateKey, peerPublicKey) {
  const bits = await subtle.deriveBits({ name: 'ECDH', public: peerPublicKey }, privateKey, 256);
  return new Uint8Array(bits);
}

async function hkdf(ikm, salt, info) {
  const baseKey = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: HKDF_HASH, salt: utf8(salt), info: utf8(info) },
    baseKey,
    256,
  );
  return new Uint8Array(bits);
}

export async function derivePairingKeys(sharedSecret, pairId) {
  const kPair = await hkdf(sharedSecret, pairId, 'phonejob/v1/pair');
  const [kSas, kConfirm, kEnc, kAuth] = await Promise.all([
    hkdf(kPair, pairId, 'phonejob/v1/sas'),
    hkdf(kPair, pairId, 'phonejob/v1/confirm'),
    hkdf(kPair, pairId, 'phonejob/v1/enc'),
    hkdf(kPair, pairId, 'phonejob/v1/auth'),
  ]);
  return { kPair, kSas, kConfirm, kEnc, kAuth };
}

export async function computeSas(kSas, transcript) {
  const digest = new Uint8Array(await subtle.digest('SHA-256', utf8(canonicalJson(transcript))));
  const hmacKey = await subtle.importKey('raw', kSas, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await subtle.sign('HMAC', hmacKey, digest));
  const value = ((mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | mac[3]) >>> 0;
  return String(value % 1_000_000).padStart(6, '0');
}

async function importAesKey(kEnc) {
  return subtle.importKey('raw', kEnc, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function sealEnvelope(kEnc, header, plaintext) {
  const nonce = randomBytes(12);
  const sealedHeader = { ...header, nonce: toBase64Url(nonce) };
  const aad = utf8(canonicalJson(sealedHeader));
  const key = await importAesKey(kEnc);
  const data = typeof plaintext === 'string' ? utf8(plaintext) : new Uint8Array(plaintext);
  const ciphertext = new Uint8Array(
    await subtle.encrypt({ ...AES_PARAMS, iv: nonce, additionalData: aad }, key, data),
  );
  return { ...sealedHeader, ct: toBase64Url(ciphertext) };
}

export async function openEnvelope(kEnc, envelope) {
  if (!envelope || typeof envelope !== 'object' || typeof envelope.ct !== 'string') {
    throw new Error('Invalid envelope');
  }
  const { ct, ...header } = envelope;
  if (typeof header.nonce !== 'string') {
    throw new Error('Invalid envelope');
  }
  const aad = utf8(canonicalJson(header));
  const key = await importAesKey(kEnc);
  const plaintext = await subtle.decrypt(
    { ...AES_PARAMS, iv: fromBase64Url(header.nonce), additionalData: aad },
    key,
    fromBase64Url(ct),
  );
  return { header, plaintext: new Uint8Array(plaintext) };
}

export async function sealOtpProvisioning(
  kEnc,
  { pairId, deviceId, keyId, otpSecret, issuedAt = new Date().toISOString() },
) {
  const nonce = randomBytes(12);
  const header = {
    v: 1,
    type: 'otp-provision',
    pair_id: pairId,
    device_id: deviceId,
    key_id: keyId,
    nonce: toBase64Url(nonce),
  };
  const payload = {
    v: 1,
    type: 'otp-provision',
    pair_id: pairId,
    device_id: deviceId,
    key_id: keyId,
    k_otp: toBase64Url(otpSecret),
    issued_at: issuedAt,
  };
  const aad = utf8(canonicalJson(header));
  const key = await importAesKey(kEnc);
  const ciphertext = new Uint8Array(
    await subtle.encrypt({ ...AES_PARAMS, iv: nonce, additionalData: aad }, key, utf8(JSON.stringify(payload))),
  );
  return { ...header, ct: toBase64Url(ciphertext) };
}

export async function openOtpProvisioning(kEnc, envelope) {
  if (
    !envelope ||
    typeof envelope !== 'object' ||
    envelope.type !== 'otp-provision' ||
    typeof envelope.ct !== 'string' ||
    typeof envelope.pair_id !== 'string' ||
    typeof envelope.device_id !== 'string' ||
    typeof envelope.key_id !== 'string' ||
    typeof envelope.nonce !== 'string'
  ) {
    throw new Error('Invalid provisioning envelope');
  }
  const { ct, ...header } = envelope;
  const aad = utf8(canonicalJson(header));
  const key = await importAesKey(kEnc);
  const plaintext = await subtle.decrypt(
    { ...AES_PARAMS, iv: fromBase64Url(header.nonce), additionalData: aad },
    key,
    fromBase64Url(ct),
  );
  let payload;
  try {
    payload = JSON.parse(decoder.decode(plaintext));
  } catch {
    throw new Error('Invalid provisioning payload');
  }
  if (
    payload.type !== 'otp-provision' ||
    payload.pair_id !== envelope.pair_id ||
    payload.device_id !== envelope.device_id ||
    payload.key_id !== envelope.key_id ||
    typeof payload.k_otp !== 'string'
  ) {
    throw new Error('Provisioning payload mismatch');
  }
  const otpSecret = Buffer.from(payload.k_otp, 'base64url');
  if (otpSecret.length !== 32) {
    throw new Error('Invalid OTP secret length');
  }
  return { otpSecret, keyId: payload.key_id, issuedAt: payload.issued_at };
}
