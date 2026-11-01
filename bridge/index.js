// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { createBridgeServers } from './servers.js';
import { PairingService } from './pairing.js';
import { loadOrCreateKeyStore } from './key-store.js';
import { SqliteDeviceStore } from './device-store.js';
import { SqliteJobStore } from './job-store.js';
import { JobService } from './job-service.js';
import { AuditLog } from './audit.js';

const VERSION = '0.1.0';
const stateDir = process.env.DSH_HOME || path.join(os.homedir(), '.dsh');
const dataDir = path.join(stateDir, 'phonejob');
const inboxDir = process.env.PHONEJOB_INBOX || path.join(stateDir, 'phone-inbox');
const workspaceAllowlist = String(process.env.PHONEJOB_WORKSPACES ?? '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const keysPath = process.env.PHONEJOB_KEYS
  ? path.resolve(process.env.PHONEJOB_KEYS)
  : path.join(dataDir, 'keys.bin');
const apiPort = Number(process.env.PHONEJOB_API_PORT ?? 7788);
const localPort = Number(process.env.PHONEJOB_LOCAL_PORT ?? 7789);

function envDuration(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`${name} must be a positive number of milliseconds`);
  }
  return Math.trunc(value);
}

const confirmTtlMs = envDuration('PHONEJOB_CONFIRM_TTL_MS', 10 * 60_000);
const uploadTtlMs = envDuration('PHONEJOB_UPLOAD_TTL_MS', 30 * 60_000);
const executionTtlMs = envDuration('PHONEJOB_EXECUTION_TTL_MS', 35 * 60_000);

function envPositiveInt(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

const maxJobsPerHour = envPositiveInt('PHONEJOB_MAX_JOBS_PER_HOUR', 10);

if (!Number.isInteger(apiPort) || apiPort < 0 || apiPort > 65535) {
  throw new Error('PHONEJOB_API_PORT must be an integer between 0 and 65535');
}
if (!Number.isInteger(localPort) || localPort < 0 || localPort > 65535) {
  throw new Error('PHONEJOB_LOCAL_PORT must be an integer between 0 and 65535');
}
if (apiPort !== 0 && apiPort === localPort) {
  throw new Error('API and local ports must differ');
}

let cachedKey;
const loadOtp = async () => {
  if (!cachedKey) {
    const store = await loadOrCreateKeyStore(keysPath);
    cachedKey = { secret: store.secret, keyId: store.keyId };
  }
  return cachedKey;
};

const adminToken = process.env.PHONEJOB_ADMIN_TOKEN || randomBytes(24).toString('base64url');
const tokenPath = path.join(path.dirname(keysPath), 'admin.token');
const dbPath = path.join(path.dirname(keysPath), 'phonejob.sqlite');
const auditPath = path.join(path.dirname(keysPath), 'audit.jsonl');
await mkdir(path.dirname(keysPath), { recursive: true });
await loadOtp();
await writeFile(tokenPath, `${adminToken}\n`, { mode: 0o600 });

const audit = new AuditLog({ filePath: auditPath });
const deviceStore = new SqliteDeviceStore({ filePath: dbPath });
const jobStore = new SqliteJobStore({ filePath: dbPath });
const pairing = new PairingService({ loadOtp, deviceStore });
const jobs = new JobService({
  deviceStore,
  jobStore,
  loadOtp,
  inboxDir,
  workspaceAllowlist,
  confirmTtlMs,
  uploadTtlMs,
  executionTtlMs,
  maxJobsPerHour,
  audit,
});
const servers = createBridgeServers({
  pairing,
  jobs,
  adminToken,
  apiPort,
  localPort,
  version: VERSION,
  pwaOrigin: process.env.PHONEJOB_PWA_ORIGIN || null,
  workspaces: workspaceAllowlist,
});

let resultTimer = null;
let timeoutTimer = null;

try {
  await servers.start();
  resultTimer = setInterval(() => {
    jobs.scanResults().catch((err) => {
      console.error(`result scan failed: ${err.message}`);
    });
  }, 1000);
  const scanTimeouts = () => {
    jobs.scanTimeouts().catch((err) => {
      console.error(`timeout scan failed: ${err.message}`);
    });
  };
  scanTimeouts();
  timeoutTimer = setInterval(scanTimeouts, 30_000);
  console.log('phonejob bridge');
  console.log(`  api:   http://127.0.0.1:${servers.apiPort} (expose this via the tunnel only)`);
  console.log(`  local: http://127.0.0.1:${servers.localPort} (never expose)`);
  console.log(`  keys:  ${keysPath}`);
  console.log(`  db:    ${dbPath}`);
  console.log(`  audit: ${auditPath}`);
  console.log(`  inbox: ${inboxDir}`);
  console.log(
    `  workspaces: ${workspaceAllowlist.length ? workspaceAllowlist.join(', ') : '(empty: jobs will be rejected)'}`,
  );
  console.log(`  admin token file: ${tokenPath}`);
} catch (err) {
  console.error(`failed to start: ${err.message}`);
  process.exitCode = 1;
  if (resultTimer) clearInterval(resultTimer);
  if (timeoutTimer) clearInterval(timeoutTimer);
  await servers.close();
  await audit.close();
  await jobStore.close();
  await deviceStore.close();
}

const shutdown = async () => {
  if (resultTimer) clearInterval(resultTimer);
  if (timeoutTimer) clearInterval(timeoutTimer);
  await servers.close();
  await audit.close();
  await jobStore.close();
  await deviceStore.close();
  process.exit(0);
};
process.once('SIGINT', shutdown);
process.once('SIGTERM', shutdown);
