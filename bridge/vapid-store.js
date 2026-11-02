// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { protect, unprotect } from './dpapi.js';

const STORE_VERSION = 1;
const subtle = globalThis.crypto.subtle;

function toBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

async function writeStore(filePath, record) {
  const blob = await protect(Buffer.from(JSON.stringify(record), 'utf8'));
  await mkdir(path.dirname(filePath), { recursive: true });
  const temp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(temp, blob, { mode: 0o600 });
  await rename(temp, filePath);
  return {
    publicKey: record.public_key,
    privateJwk: record.private_jwk,
    createdAt: record.created_at,
  };
}

async function createStore(filePath) {
  const pair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const publicRaw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  const privateJwk = await subtle.exportKey('jwk', pair.privateKey);
  return writeStore(filePath, {
    version: STORE_VERSION,
    public_key: toBase64Url(publicRaw),
    private_jwk: privateJwk,
    created_at: new Date().toISOString(),
  });
}

export async function readVapidStore(filePath) {
  const blob = await readFile(filePath);
  const plaintext = await unprotect(blob);
  let record;
  try {
    record = JSON.parse(plaintext.toString('utf8'));
  } catch {
    throw new Error('VAPID store is corrupted');
  }
  if (
    record?.version !== STORE_VERSION ||
    typeof record.public_key !== 'string' ||
    !record.private_jwk ||
    record.private_jwk.kty !== 'EC' ||
    record.private_jwk.crv !== 'P-256' ||
    typeof record.private_jwk.d !== 'string'
  ) {
    throw new Error('VAPID store has an unsupported format');
  }
  const publicRaw = Buffer.from(record.public_key, 'base64url');
  if (publicRaw.length !== 65 || publicRaw[0] !== 0x04) {
    throw new Error('VAPID public key is invalid');
  }
  return {
    publicKey: record.public_key,
    privateJwk: record.private_jwk,
    createdAt: record.created_at,
  };
}

export async function loadOrCreateVapidStore(filePath) {
  try {
    return await readVapidStore(filePath);
  } catch (err) {
    if (err.code === 'ENOENT') return createStore(filePath);
    throw err;
  }
}
