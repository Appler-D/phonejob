#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import os from 'node:os';
import path from 'node:path';
import { restoreBackup } from '../bridge/backup.js';

const backupArg = process.argv[2];
if (!backupArg || backupArg.startsWith('--')) {
  console.error('usage: node tools/restore.mjs <backupDir> [--force]');
  process.exit(1);
}
const force = process.argv.includes('--force');
const stateDir = process.env.DSH_HOME || path.join(os.homedir(), '.dsh');
const dataDir = process.env.PHONEJOB_KEYS
  ? path.dirname(path.resolve(process.env.PHONEJOB_KEYS))
  : path.join(stateDir, 'phonejob');
const inboxDir = process.env.PHONEJOB_INBOX || path.join(stateDir, 'phone-inbox');

try {
  const result = await restoreBackup({
    backupDir: path.resolve(backupArg),
    dataDir,
    inboxDir,
    force,
  });
  console.log(`restored data: ${result.dataDir}`);
  console.log(`restored inbox: ${result.inboxDir ?? 'not included'}`);
  console.log('stop the bridge before restoring, then start it again.');
} catch (err) {
  console.error(`restore failed: ${err.message}`);
  process.exitCode = 1;
}
