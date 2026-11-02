// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
  copyFile,
  cp,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';

const MANIFEST = 'manifest.json';
const VERSION = 1;
const DATA_FILES = ['keys.bin', 'vapid.bin', 'admin.token'];
const REQUIRED_FILES = ['keys.bin', 'phonejob.sqlite'];

function hashFile(bytes) {
  return createHash('sha256').update(bytes).digest('base64url');
}

function sqlQuote(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

async function fileHash(file) {
  const bytes = await readFile(file);
  return { size: bytes.length, sha256: hashFile(bytes) };
}

async function listAuditFiles(dataDir) {
  let names;
  try {
    names = await readdir(dataDir);
  } catch {
    return [];
  }
  return names
    .filter((name) => name === 'audit.jsonl' || /^audit\.jsonl\.\d+$/.test(name))
    .sort();
}

async function exists(target) {
  try {
    await stat(target);
    return true;
  } catch {
    return false;
  }
}

export async function createBackup({
  dataDir,
  inboxDir,
  outDir,
  includeInbox = false,
  force = false,
  now = () => Date.now(),
} = {}) {
  if (!dataDir || !outDir) throw new Error('dataDir and outDir are required');
  const dbPath = path.join(dataDir, 'phonejob.sqlite');
  if (!(await exists(dbPath))) throw new Error('phonejob.sqlite not found; start the bridge once first');
  if (!(await exists(path.join(dataDir, 'keys.bin')))) {
    throw new Error('keys.bin not found; initialize the bridge once first');
  }
  if (await exists(outDir)) {
    if (!force) throw new Error('backup destination already exists');
    await rm(outDir, { recursive: true, force: true });
  }
  const tempDir = `${outDir}.${process.pid}.${now()}.tmp`;
  await mkdir(tempDir, { recursive: true });
  const files = [];
  try {
    for (const name of DATA_FILES) {
      const source = path.join(dataDir, name);
      if (!(await exists(source))) continue;
      await copyFile(source, path.join(tempDir, name));
    }
    for (const name of await listAuditFiles(dataDir)) {
      await copyFile(path.join(dataDir, name), path.join(tempDir, name));
    }

    const snapshot = path.join(tempDir, 'phonejob.sqlite');
    const db = new DatabaseSync(dbPath);
    try {
      db.exec(`VACUUM INTO ${sqlQuote(snapshot)}`);
    } finally {
      db.close();
    }
    const check = new DatabaseSync(snapshot, { readOnly: true });
    try {
      const row = check.prepare('PRAGMA integrity_check').get();
      const result = row?.integrity_check;
      if (result !== 'ok') throw new Error(`backup database integrity check failed: ${result}`);
    } finally {
      check.close();
    }

    if (includeInbox && inboxDir && (await exists(inboxDir))) {
      await cp(inboxDir, path.join(tempDir, 'inbox'), { recursive: true });
    }

    for (const name of await readdir(tempDir)) {
      if (name === MANIFEST || name === 'inbox') continue;
      files.push({ path: name, ...(await fileHash(path.join(tempDir, name))) });
    }
    const manifest = {
      version: VERSION,
      created_at: new Date(now()).toISOString(),
      include_inbox: Boolean(includeInbox),
      files,
    };
    await writeFile(path.join(tempDir, MANIFEST), JSON.stringify(manifest, null, 2), 'utf8');
    await rename(tempDir, outDir);
    return { outDir, manifest };
  } catch (err) {
    await rm(tempDir, { recursive: true, force: true });
    throw err;
  }
}

export async function restoreBackup({ backupDir, dataDir, inboxDir, force = false } = {}) {
  if (!backupDir || !dataDir) throw new Error('backupDir and dataDir are required');
  let manifest;
  try {
    manifest = JSON.parse(await readFile(path.join(backupDir, MANIFEST), 'utf8'));
  } catch {
    throw new Error('backup manifest is missing or invalid');
  }
  if (manifest?.version !== VERSION || !Array.isArray(manifest.files)) {
    throw new Error('backup manifest has an unsupported format');
  }
  for (const entry of manifest.files) {
    if (typeof entry?.path !== 'string' || path.basename(entry.path) !== entry.path) {
      throw new Error('backup manifest contains an unsafe path');
    }
    const actual = await fileHash(path.join(backupDir, entry.path));
    if (actual.size !== entry.size || actual.sha256 !== entry.sha256) {
      throw new Error(`backup file checksum failed: ${entry.path}`);
    }
  }
  for (const name of REQUIRED_FILES) {
    if (!manifest.files.some((entry) => entry.path === name)) {
      throw new Error(`backup is missing ${name}`);
    }
  }
  if (!force) {
    for (const entry of manifest.files) {
      if (await exists(path.join(dataDir, entry.path))) {
        throw new Error('target data already exists; pass --force to replace it');
      }
    }
    if (manifest.include_inbox && inboxDir && (await exists(inboxDir))) {
      throw new Error('target inbox already exists; pass --force to replace it');
    }
  }

  await mkdir(dataDir, { recursive: true });
  for (const entry of manifest.files) {
    await copyFile(path.join(backupDir, entry.path), path.join(dataDir, entry.path));
  }
  for (const suffix of ['-wal', '-shm']) {
    await rm(path.join(dataDir, `phonejob.sqlite${suffix}`), { force: true });
  }

  let restoredInbox = null;
  if (manifest.include_inbox && inboxDir && (await exists(path.join(backupDir, 'inbox')))) {
    if (await exists(inboxDir)) {
      const previous = `${inboxDir}.pre-restore-${Date.now()}`;
      await rename(inboxDir, previous);
    }
    await cp(path.join(backupDir, 'inbox'), inboxDir, { recursive: true });
    restoredInbox = inboxDir;
  }
  return { dataDir, inboxDir: restoredInbox, manifest };
}
