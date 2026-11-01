// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export class MemoryJobStore {
  constructor() {
    this.jobs = new Map();
    this.deviceState = new Map();
  }

  async getJob(jobId) {
    return this.jobs.get(jobId) ?? null;
  }

  async listJobs() {
    return [...this.jobs.values()].sort((left, right) => right.created_at - left.created_at);
  }

  async saveJobWithSequence({ job, seq, nonce }) {
    if (this.jobs.has(job.job_id)) return false;
    const state = this.deviceState.get(job.device_id) ?? { lastSeq: 0, nonces: new Set() };
    if (seq <= state.lastSeq || state.nonces.has(nonce)) return false;
    state.lastSeq = seq;
    state.nonces.add(nonce);
    this.deviceState.set(job.device_id, state);
    this.jobs.set(job.job_id, { ...job });
    return true;
  }

  async decideJob({ jobId, state, inboxPath, decidedAt }) {
    const job = this.jobs.get(jobId);
    if (!job || job.state !== 'WAITING_CONFIRM') return false;
    job.state = state;
    job.inbox_path = inboxPath;
    job.decided_at = decidedAt;
    job.updated_at = decidedAt;
    return true;
  }

  async completeJob({ jobId, state, resultError = null, finishedAt }) {
    const job = this.jobs.get(jobId);
    if (!job || !['QUEUED', 'RUNNING'].includes(job.state)) return false;
    job.state = state;
    job.result_error = resultError;
    job.finished_at = finishedAt;
    job.updated_at = finishedAt;
    return true;
  }

  async completeUpload({ jobId, challenge, jobHash, inboxPath, updatedAt }) {
    const job = this.jobs.get(jobId);
    if (!job || job.state !== 'UPLOADING') return false;
    job.state = 'WAITING_CONFIRM';
    job.challenge = challenge;
    job.job_hash = jobHash;
    job.inbox_path = inboxPath;
    job.updated_at = updatedAt;
    return true;
  }

  async expireJob({ jobId, fromStates, state, resultError, finishedAt, inboxPath }) {
    const job = this.jobs.get(jobId);
    if (!job || !fromStates.includes(job.state)) return false;
    job.state = state;
    job.result_error = resultError;
    job.finished_at = finishedAt;
    job.updated_at = finishedAt;
    if (inboxPath !== undefined) job.inbox_path = inboxPath;
    return true;
  }

  async close() {}
}

export class SqliteJobStore {
  constructor({ filePath }) {
    mkdirSync(path.dirname(filePath), { recursive: true });
    this.db = new DatabaseSync(filePath);
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA synchronous = NORMAL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        state TEXT NOT NULL,
        risk TEXT NOT NULL,
        intent TEXT NOT NULL,
        workspace TEXT NOT NULL,
        inbox_path TEXT NOT NULL,
        challenge TEXT,
        job_hash TEXT,
        decided_at INTEGER,
        result_error TEXT,
        finished_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS seen_messages (
        device_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        seen_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, seq),
        UNIQUE (device_id, nonce)
      );
      CREATE INDEX IF NOT EXISTS seen_messages_ts ON seen_messages (device_id, seen_at);
    `);
    const columns = new Set(this.db.prepare('PRAGMA table_info(jobs)').all().map((column) => column.name));
    if (!columns.has('challenge')) this.db.exec('ALTER TABLE jobs ADD COLUMN challenge TEXT');
    if (!columns.has('job_hash')) this.db.exec('ALTER TABLE jobs ADD COLUMN job_hash TEXT');
    if (!columns.has('decided_at')) this.db.exec('ALTER TABLE jobs ADD COLUMN decided_at INTEGER');
    if (!columns.has('result_error')) this.db.exec('ALTER TABLE jobs ADD COLUMN result_error TEXT');
    if (!columns.has('finished_at')) this.db.exec('ALTER TABLE jobs ADD COLUMN finished_at INTEGER');
  }

  async getJob(jobId) {
    return this.db.prepare('SELECT * FROM jobs WHERE job_id = ?').get(jobId) ?? null;
  }

  async listJobs() {
    return this.db.prepare('SELECT * FROM jobs ORDER BY created_at DESC').all();
  }

  async saveJobWithSequence({ job, seq, nonce }) {
    const now = Date.now();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare('DELETE FROM seen_messages WHERE seen_at < ?').run(now - 86_400_000);
      const last = this.db
        .prepare('SELECT MAX(seq) AS lastSeq FROM seen_messages WHERE device_id = ?')
        .get(job.device_id)?.lastSeq ?? 0;
      if (seq <= last) {
        this.db.exec('ROLLBACK');
        return false;
      }
      if (
        this.db
          .prepare('SELECT 1 FROM seen_messages WHERE device_id = ? AND nonce = ?')
          .get(job.device_id, nonce)
      ) {
        this.db.exec('ROLLBACK');
        return false;
      }
      if (this.db.prepare('SELECT 1 FROM jobs WHERE job_id = ?').get(job.job_id)) {
        this.db.exec('ROLLBACK');
        return false;
      }
      this.db
        .prepare('INSERT INTO seen_messages (device_id, seq, nonce, seen_at) VALUES (?, ?, ?, ?)')
        .run(job.device_id, seq, nonce, now);
      this.db
        .prepare(`
          INSERT INTO jobs (job_id, device_id, state, risk, intent, workspace, inbox_path, challenge, job_hash, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          job.job_id,
          job.device_id,
          job.state,
          job.risk,
          job.intent,
          job.workspace,
          job.inbox_path,
          job.challenge ?? null,
          job.job_hash ?? null,
          job.created_at,
          job.updated_at,
        );
      this.db.exec('COMMIT');
      return true;
    } catch {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        // The transaction may already be closed.
      }
      return false;
    }
  }

  async decideJob({ jobId, state, inboxPath, decidedAt }) {
    const result = this.db
      .prepare(`
        UPDATE jobs
        SET state = ?, inbox_path = ?, decided_at = ?, updated_at = ?
        WHERE job_id = ? AND state = 'WAITING_CONFIRM'
      `)
      .run(state, inboxPath, decidedAt, decidedAt, jobId);
    return result.changes > 0;
  }

  async completeJob({ jobId, state, resultError = null, finishedAt }) {
    const result = this.db
      .prepare(`
        UPDATE jobs
        SET state = ?, result_error = ?, finished_at = ?, updated_at = ?
        WHERE job_id = ? AND state IN ('QUEUED', 'RUNNING')
      `)
      .run(state, resultError, finishedAt, finishedAt, jobId);
    return result.changes > 0;
  }

  async completeUpload({ jobId, challenge, jobHash, inboxPath, updatedAt }) {
    const result = this.db
      .prepare(`
        UPDATE jobs
        SET state = 'WAITING_CONFIRM', challenge = ?, job_hash = ?, inbox_path = ?, updated_at = ?
        WHERE job_id = ? AND state = 'UPLOADING'
      `)
      .run(challenge, jobHash, inboxPath, updatedAt, jobId);
    return result.changes > 0;
  }

  async expireJob({ jobId, fromStates, state, resultError, finishedAt, inboxPath }) {
    const placeholders = fromStates.map(() => '?').join(', ');
    let fields = 'state = ?, result_error = ?, finished_at = ?, updated_at = ?';
    const values = [state, resultError, finishedAt, finishedAt];
    if (inboxPath !== undefined) {
      fields += ', inbox_path = ?';
      values.push(inboxPath);
    }
    const result = this.db
      .prepare(`UPDATE jobs SET ${fields} WHERE job_id = ? AND state IN (${placeholders})`)
      .run(...values, jobId, ...fromStates);
    return result.changes > 0;
  }

  async close() {
    this.db.close();
  }
}
