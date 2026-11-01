// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import os from 'node:os';
import path from 'node:path';
import { loadOrCreateKeyStore, otpFingerprint, rotateKeyStore } from './key-store.js';

const args = process.argv.slice(2);
const rotate = args.includes('--rotate');
const fileArg = args.find((arg) => !arg.startsWith('--'));
const defaultDir = process.env.DSH_HOME || path.join(os.homedir(), '.dsh');
const filePath = fileArg ? path.resolve(fileArg) : path.join(defaultDir, 'phonejob', 'keys.bin');

try {
  const store = rotate ? await rotateKeyStore(filePath) : await loadOrCreateKeyStore(filePath);
  console.log(`key store: ${filePath}`);
  console.log(`key id: ${store.keyId}`);
  console.log(`fingerprint: ${otpFingerprint(store.secret)}`);
  if (rotate) {
    console.log('rotated: old codes are invalid; re-provision paired devices.');
  }
  console.log('K_otp is generated and stored on this PC; do not share it.');
} catch (err) {
  console.error(`key init failed: ${err.message}`);
  process.exitCode = 1;
}
