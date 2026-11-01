// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { protect, unprotect } from './dpapi.js';

const STORE_VERSION = 1;
const OTP_SECRET_BYTES = 32;

export function generateOtpSecret() {
  return randomBytes(OTP_SECRET_BYTES);
}

export function otpFingerprint(secret) {
  return createHash('sha256').update(secret).digest('hex').slice(0, 16);
}

function validateSecret(secret) {
  if (!Buffer.isBuffer(secret) || secret.length !== OTP_SECRET_BYTES) {
    throw new Error(`K_otp must be ${OTP_SECRET_BYTES} bytes`);
  }
}

async function writeStore(filePath, secret) {
  validateSecret(secret);
  const record = {
    version: STORE_VERSION,
    key_id: randomBytes(8).toString('hex'),
    created_at: new Date().toISOString(),
    k_otp: secret.toString('base64'),
  };
  const blob = await protect(Buffer.from(JSON.stringify(record), 'utf8'));
  await mkdir(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tmp, blob, { mode: 0o600 });
  await rename(tmp, filePath);
  return {
    secret,
    keyId: record.key_id,
    createdAt: record.created_at,
    version: record.version,
  };
}

export async function createKeyStore(filePath, { secret = generateOtpSecret() } = {}) {
  return writeStore(filePath, secret);
}

export async function readKeyStore(filePath) {
  const blob = await readFile(filePath);
  const plaintext = await unprotect(blob);
  let record;
  try {
    record = JSON.parse(plaintext.toString('utf8'));
  } catch {
    throw new Error('Key store is corrupted');
  }
  if (
    record?.version !== STORE_VERSION ||
    typeof record.k_otp !== 'string' ||
    typeof record.key_id !== 'string' ||
    typeof record.created_at !== 'string'
  ) {
    throw new Error('Key store has an unsupported format');
  }
  const secret = Buffer.from(record.k_otp, 'base64');
  validateSecret(secret);
  return {
    secret,
    keyId: record.key_id,
    createdAt: record.created_at,
    version: record.version,
  };
}

export async function loadOrCreateKeyStore(filePath) {
  try {
    return await readKeyStore(filePath);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return createKeyStore(filePath);
    }
    throw err;
  }
}

export async function rotateKeyStore(filePath) {
  return createKeyStore(filePath);
}
