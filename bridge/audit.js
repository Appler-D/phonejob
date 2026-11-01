// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { appendFile, mkdir, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';

const FIELDS = new Set([
  'job_id',
  'device_id',
  'state',
  'risk',
  'intent',
  'files',
  'file_bytes',
  'error',
  'reason',
]);

function safeValue(key, value) {
  if (value === undefined || value === null) return value;
  if (key === 'files' || key === 'file_bytes') {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value !== 'string') return undefined;
  return value.slice(0, 200);
}

export class AuditLog {
  constructor({ filePath, now = () => Date.now(), maxBytes = 5 * 1024 * 1024, maxBackups = 4 } = {}) {
    if (!filePath) throw new TypeError('filePath is required');
    this.filePath = path.resolve(filePath);
    this.now = now;
    this.maxBytes = maxBytes;
    this.maxBackups = maxBackups;
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

  close() {
    return this.queue;
  }
}
