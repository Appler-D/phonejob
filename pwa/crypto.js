// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };
const AES_PARAMS = { name: 'AES-GCM', tagLength: 128 };

function bytesToBinary(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunk));
  }
  return binary;
}

export function toBase64Url(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  return btoa(bytesToBinary(bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(value) {
  const clean = String(value).replace(/=+$/, '');
  const padded = clean.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (clean.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
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
    { name: 'HKDF', hash: 'SHA-256', salt: encoder.encode(salt), info: encoder.encode(info) },
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

export function pairingTranscript({ pairId, pcPub, phonePub, nonce, expiresAt }) {
  return {
    v: 1,
    pair_id: pairId,
    pc_pub: pcPub,
    phone_pub: phonePub,
    nonce,
    expires_at: expiresAt,
  };
}

export async function computeSas(kSas, transcript) {
  const digest = new Uint8Array(await subtle.digest('SHA-256', encoder.encode(canonicalJson(transcript))));
  const hmacKey = await subtle.importKey('raw', kSas, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await subtle.sign('HMAC', hmacKey, digest));
  const value = ((mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | mac[3]) >>> 0;
  return String(value % 1_000_000).padStart(6, '0');
}

export async function hmacSha256Base64Url(key, message) {
  const hmacKey = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const data = typeof message === 'string' ? encoder.encode(message) : new Uint8Array(message);
  const mac = new Uint8Array(await subtle.sign('HMAC', hmacKey, data));
  return toBase64Url(mac);
}

async function importAesDecryptKey(kEnc) {
  return subtle.importKey('raw', kEnc, 'AES-GCM', false, ['decrypt']);
}

export async function importAesKey(kEnc) {
  return subtle.importKey('raw', kEnc, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function importHmacKey(key) {
  return subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

export async function sealEnvelope(kEncKey, header, plaintext) {
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const sealedHeader = { ...header, nonce: toBase64Url(nonce) };
  const data = typeof plaintext === 'string' ? encoder.encode(plaintext) : new Uint8Array(plaintext);
  const ciphertext = new Uint8Array(
    await subtle.encrypt(
      {
        ...AES_PARAMS,
        iv: nonce,
        additionalData: encoder.encode(canonicalJson(sealedHeader)),
      },
      kEncKey,
      data,
    ),
  );
  return { ...sealedHeader, ct: toBase64Url(ciphertext) };
}

export async function sealFileChunk(kEncKey, meta, bytes) {
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const header = {
    v: 1,
    type: 'job-file-chunk-v1',
    job_id: meta.jobId,
    file_index: meta.fileIndex,
    file_sha256: meta.fileSha256,
    chunk_index: meta.chunkIndex,
    total_chunks: meta.totalChunks,
    nonce: toBase64Url(nonce),
  };
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const ciphertext = new Uint8Array(
    await subtle.encrypt(
      {
        ...AES_PARAMS,
        iv: nonce,
        additionalData: encoder.encode(canonicalJson(header)),
      },
      kEncKey,
      data,
    ),
  );
  return { ...header, ct: toBase64Url(ciphertext) };
}

export async function openFileChunk(kEncKey, envelope) {
  if (
    !envelope ||
    typeof envelope !== 'object' ||
    typeof envelope.nonce !== 'string' ||
    typeof envelope.ct !== 'string'
  ) {
    throw new Error('Invalid file chunk');
  }
  const { ct, ...header } = envelope;
  const bytes = new Uint8Array(
    await subtle.decrypt(
      {
        ...AES_PARAMS,
        iv: fromBase64Url(header.nonce),
        additionalData: encoder.encode(canonicalJson(header)),
      },
      kEncKey,
      fromBase64Url(ct),
    ),
  );
  return { header, bytes };
}

export async function openEnvelope(kEncKey, envelope) {
  if (
    !envelope ||
    typeof envelope !== 'object' ||
    typeof envelope.ct !== 'string' ||
    typeof envelope.nonce !== 'string'
  ) {
    throw new Error('Invalid envelope');
  }
  const { ct, ...header } = envelope;
  const plaintext = await subtle.decrypt(
    {
      ...AES_PARAMS,
      iv: fromBase64Url(header.nonce),
      additionalData: encoder.encode(canonicalJson(header)),
    },
    kEncKey,
    fromBase64Url(ct),
  );
  return { header, plaintext: new Uint8Array(plaintext) };
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
  const key = await importAesDecryptKey(kEnc);
  const plaintext = await subtle.decrypt(
    {
      ...AES_PARAMS,
      iv: fromBase64Url(header.nonce),
      additionalData: encoder.encode(canonicalJson(header)),
    },
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
  const otpSecret = fromBase64Url(payload.k_otp);
  if (otpSecret.length !== 32) {
    throw new Error('Invalid OTP secret length');
  }
  return { otpSecret, keyId: payload.key_id, issuedAt: payload.issued_at };
}

export async function openOtpRefresh(kEncKey, envelope) {
  if (
    !envelope ||
    typeof envelope !== 'object' ||
    envelope.type !== 'otp-refresh-v1' ||
    typeof envelope.ct !== 'string' ||
    typeof envelope.device_id !== 'string' ||
    typeof envelope.key_id !== 'string' ||
    typeof envelope.nonce !== 'string'
  ) {
    throw new Error('Invalid refresh envelope');
  }
  const { ct, ...header } = envelope;
  const plaintext = await subtle.decrypt(
    {
      ...AES_PARAMS,
      iv: fromBase64Url(header.nonce),
      additionalData: encoder.encode(canonicalJson(header)),
    },
    kEncKey,
    fromBase64Url(ct),
  );
  let payload;
  try {
    payload = JSON.parse(decoder.decode(plaintext));
  } catch {
    throw new Error('Invalid refresh payload');
  }
  if (
    payload.type !== 'otp-refresh-v1' ||
    payload.device_id !== envelope.device_id ||
    payload.key_id !== envelope.key_id ||
    typeof payload.k_otp !== 'string'
  ) {
    throw new Error('Refresh payload mismatch');
  }
  const otpSecret = fromBase64Url(payload.k_otp);
  if (otpSecret.length !== 32) throw new Error('Invalid OTP secret length');
  return {
    deviceId: payload.device_id,
    keyId: payload.key_id,
    otpSecret,
    issuedAt: payload.issued_at,
  };
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32(bytes) {
  let value = 0;
  let bits = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export async function hmacWithKey(key, message) {
  return new Uint8Array(await subtle.sign('HMAC', key, encoder.encode(message)));
}

export async function computeReceiptResponse(key, jobHash, challenge) {
  const mac = await hmacWithKey(key, `confirm-v1\n${jobHash}\n${challenge}`);
  return base32(mac).slice(0, 8);
}

export async function importOtpKey(secret) {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) {
    throw new Error('Invalid OTP secret length');
  }
  try {
    return await subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  } finally {
    secret.fill(0);
  }
}

export async function hotpWithKey(key, counter, digits = 6) {
  if (!Number.isInteger(counter) || counter < 0) {
    throw new RangeError('counter must be a non-negative integer');
  }
  if (!Number.isInteger(digits) || digits < 1 || digits > 10) {
    throw new RangeError('digits must be an integer between 1 and 10');
  }
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(counter), false);
  const digest = new Uint8Array(await subtle.sign('HMAC', key, message));
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export async function totpWithKey(key, time = Date.now(), step = 30) {
  return hotpWithKey(key, Math.floor(time / 1000 / step));
}
