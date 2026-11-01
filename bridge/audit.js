// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { appendFile, mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

const FIELDS = new Set([
  'job_id',
  'pairing_id',
  'device_id',
  'state',
  'risk',
  'intent',
  'files',
  'file_bytes',
  'error',
  'reason',
]);
const DEFAULT_MAX_AGE_MS = 90 * 24 * 60 * 60_000;

function safeValue(key, value) {
  if (value === undefined || value === null) return value;
  if (key === 'files' || key === 'file_bytes') {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value !== 'string') return undefined;
  return value.slice(0, 200);
}

export class AuditLog {
  constructor({
    filePath,
    now = () => Date.now(),
    maxBytes = 5 * 1024 * 1024,
    maxBackups = 4,
    maxAgeMs = DEFAULT_MAX_AGE_MS,
  } = {}) {
    if (!filePath) throw new TypeError('filePath is required');
    this.filePath = path.resolve(filePath);
    this.now = now;
    this.maxBytes = maxBytes;
    this.maxBackups = maxBackups;
    this.maxAgeMs = maxAgeMs;
    this.size = null;
    this.queue = Promise.resolve();
  }

  record(event, fields = {}) {
    const entry = { at: new Date(this.now()).toISOString(), event };
    for (const [key, value] of Object.entries(fields)) {
      if (!FIELDS.has(key)) continue;
      const safe = safeValue(key, value);
      if (safe !== undefined) entry[key] = safe;
    }
    const line = `${JSON.stringify(entry)}\n`;
    this.queue = this.queue
      .then(() => this.#write(line))
      .catch(() => {});
    return this.queue;
  }

  async #write(line) {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    const bytes = Buffer.byteLength(line);
    if (this.size === null) {
      try {
        this.size = (await stat(this.filePath)).size;
      } catch {
        this.size = 0;
      }
    }
    if (this.maxBytes > 0 && this.size > 0 && this.size + bytes > this.maxBytes) {
      await this.#rotate();
      this.size = 0;
    }
    await appendFile(this.filePath, line, { mode: 0o600 });
    this.size += bytes;
  }

  async #rotate() {
    if (this.maxBackups <= 0) return;
    for (let index = this.maxBackups - 1; index >= 1; index -= 1) {
      await this.#move(`${this.filePath}.${index}`, `${this.filePath}.${index + 1}`);
    }
    await this.#move(this.filePath, `${this.filePath}.1`);
  }

  async #move(from, to) {
    await rm(to, { force: true }).catch(() => {});
    await rename(from, to).catch(() => {});
  }

  async prune() {
    if (!(this.maxAgeMs > 0)) return;
    await this.queue;
    const cutoff = this.now() - this.maxAgeMs;
    const files = [this.filePath];
    for (let index = 1; index <= this.maxBackups; index += 1) {
      files.push(`${this.filePath}.${index}`);
    }
    for (const file of files) {
      let text;
      try {
        text = await readFile(file, 'utf8');
      } catch {
        continue;
      }
      const lines = text.split('\n').filter((line) => line.trim() !== '');
      const kept = [];
      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          const at = Date.parse(entry.at);
          if (Number.isFinite(at) && at >= cutoff) kept.push(line);
        } catch {
          // Drop corrupt lines during retention maintenance.
        }
      }
      if (kept.length === lines.length) continue;
      try {
        if (kept.length === 0) {
          await rm(file, { force: true });
          if (file === this.filePath) this.size = 0;
          continue;
        }
        const temp = `${file}.${process.pid}.prune.tmp`;
        const content = `${kept.join('\n')}\n`;
        await writeFile(temp, content, { mode: 0o600 });
        await rm(file, { force: true });
        await rename(temp, file);
        if (file === this.filePath) this.size = Buffer.byteLength(content);
      } catch {
        // Retention failure must not prevent the bridge from starting.
      }
    }
  }

  close() {
    return this.queue;
  }
}
