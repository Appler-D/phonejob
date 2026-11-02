#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import os from 'node:os';
import path from 'node:path';
import { createBackup } from '../bridge/backup.js';

function argValue(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

const stateDir = process.env.DSH_HOME || path.join(os.homedir(), '.dsh');
const dataDir = process.env.PHONEJOB_KEYS
  ? path.dirname(path.resolve(process.env.PHONEJOB_KEYS))
  : path.join(stateDir, 'phonejob');
const inboxDir = process.env.PHONEJOB_INBOX || path.join(stateDir, 'phone-inbox');
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const outDir = path.resolve(argValue('--out') || `phonejob-backup-${stamp}`);
const includeInbox = process.argv.includes('--include-inbox');
const force = process.argv.includes('--force');

try {
  const result = await createBackup({ dataDir, inboxDir, outDir, includeInbox, force });
  console.log(`backup written: ${result.outDir}`);
  console.log(`files: ${result.manifest.files.map((file) => file.path).join(', ')}`);
  console.log(`inbox: ${result.manifest.include_inbox ? 'included' : 'not included'}`);
  console.log('warning: keys.bin/vapid.bin are DPAPI user-scoped; keep this backup private.');
} catch (err) {
  console.error(`backup failed: ${err.message}`);
  process.exitCode = 1;
}
