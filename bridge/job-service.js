// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  canonicalJson,
  hmacSha256Base64Url,
  openEnvelope,
  openFileChunk,
  sealEnvelope,
} from './crypto.js';
import { computeConfirmationResponse, responsesEqual } from './confirm.js';
import { scanResultBytes, validateResult } from './result.js';
import { verifyTotp } from './totp.js';

const JOB_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const DEVICE_ID_RE = /^dev_[A-Za-z0-9_-]{8,64}$/;
const INTENTS = new Set(['ask', 'file', 'shell', 'mixed']);
const MAX_TEXT_BYTES = 64 * 1024;
const MAX_REPLY_BYTES = 20 * 1024 * 1024;
const MAX_FILES = 20;
const MAX_FILE_BYTES = 50 * 1024 * 1024;
const MAX_TOTAL_BYTES = 200 * 1024 * 1024;
const CHUNK_SIZE = 512 * 1024;
const DEFAULT_CONFIRM_TTL_MS = 10 * 60_000;
const DEFAULT_UPLOAD_TTL_MS = 30 * 60_000;
const DEFAULT_EXECUTION_TTL_MS = 35 * 60_000;
const ALLOWED_EXTENSIONS = new Set([
  '.jpg',
  '.jpeg',
  '.png',
  '.pdf',
  '.docx',
  '.xlsx',
  '.pptx',
  '.txt',
  '.md',
  '.zip',
]);
const RESERVED_NAMES = new Set([
  'CON',
  'PRN',
  'AUX',
  'NUL',
  ...Array.from({ length: 9 }, (_, index) => `COM${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `LPT${index + 1}`),
]);

function jobError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizePath(value) {
  const resolved = path.resolve(String(value));
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function safeEqualBase64(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left, 'base64url');
  const b = Buffer.from(right, 'base64url');
  return a.length === b.length && timingSafeEqual(a, b);
}

function safeFileName(value) {
  const base = path
    .basename(String(value ?? ''))
    .replace(/[\u0000-\u001f<>:"/\\|?*]/g, '_')
    .replace(/[. ]+$/g, '')
    .slice(0, 100);
  if (!base || base === '.' || base === '..') throw jobError('JOB_FILE_NAME');
  if (RESERVED_NAMES.has(base.split('.')[0].toUpperCase())) throw jobError('JOB_FILE_NAME');
  if (!ALLOWED_EXTENSIONS.has(path.extname(base).toLowerCase())) throw jobError('JOB_FILE_TYPE');
  return base;
}

function validateUploadFiles(files) {
  if (!Array.isArray(files) || files.length > MAX_FILES) throw jobError('JOB_FILES_INVALID');
  let total = 0;
  return files.map((file, index) => {
    if (!isObject(file)) throw jobError('JOB_FILES_INVALID');
    if (typeof file.name !== 'string' || !file.name) throw jobError('JOB_FILE_NAME');
    if (!Number.isInteger(file.size) || file.size <= 0 || file.size > MAX_FILE_BYTES) {
      throw jobError('JOB_FILE_SIZE');
    }
    if (typeof file.sha256 !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(file.sha256)) {
      throw jobError('JOB_FILE_HASH');
    }
    total += file.size;
    if (total > MAX_TOTAL_BYTES) throw jobError('JOB_FILES_INVALID');
    const name = safeFileName(file.name);
    return {
      name,
      size: file.size,
      sha256: file.sha256,
      storageName: `${index}-${name}`,
      chunks: Math.ceil(file.size / CHUNK_SIZE),
    };
  });
}

export class JobService {
  constructor({
    deviceStore,
    jobStore,
    loadOtp,
    inboxDir,
    workspaceAllowlist = [],
    now = () => Date.now(),
    confirmTtlMs = DEFAULT_CONFIRM_TTL_MS,
    uploadTtlMs = DEFAULT_UPLOAD_TTL_MS,
    executionTtlMs = DEFAULT_EXECUTION_TTL_MS,
  } = {}) {
    if (!deviceStore || !jobStore || typeof loadOtp !== 'function' || !inboxDir) {
      throw new TypeError('deviceStore, jobStore, loadOtp, and inboxDir are required');
    }
    this.deviceStore = deviceStore;
    this.jobStore = jobStore;
    this.loadOtp = loadOtp;
    this.inboxDir = path.resolve(inboxDir);
    this.workspaceAllowlist = workspaceAllowlist.map(normalizePath);
    this.now = now;
    this.confirmTtlMs = confirmTtlMs;
    this.uploadTtlMs = uploadTtlMs;
    this.executionTtlMs = executionTtlMs;
    this.scanning = false;
    this.timeoutScanning = false;
  }

  async submit(envelope) {
    if (!isObject(envelope)) throw jobError('JOB_INVALID');
    const { v, job_id, device_id, ts, seq, otp, nonce, ct } = envelope;
    if (v !== 2) throw jobError('JOB_INVALID');
    if (typeof job_id !== 'string' || !JOB_ID_RE.test(job_id)) throw jobError('JOB_INVALID');
    if (typeof device_id !== 'string' || !DEVICE_ID_RE.test(device_id)) throw jobError('JOB_INVALID');
    if (!Number.isInteger(ts) || !Number.isInteger(seq) || seq < 1) throw jobError('JOB_INVALID');
    if (typeof otp !== 'string' || !/^\d{6}$/.test(otp)) throw jobError('JOB_INVALID');
    if (typeof nonce !== 'string' || nonce.length === 0 || typeof ct !== 'string' || ct.length === 0) {
      throw jobError('JOB_INVALID');
    }

    const device = await this.deviceStore.getDevice(device_id);
    if (!device || device.revoked) throw jobError('JOB_DEVICE_REJECTED');

    let opened;
    try {
      opened = await openEnvelope(device.keys.kEnc, envelope);
    } catch {
      throw jobError('JOB_INVALID');
    }

    const now = this.now();
    if (Math.abs(now / 1000 - ts) > 120) throw jobError('JOB_TIME_WINDOW');

    const existing = await this.jobStore.getJob(job_id);
    if (existing) {
      if (existing.device_id !== device_id) throw jobError('JOB_INVALID');
      return { job_id: existing.job_id, state: existing.state, risk: existing.risk };
    }

    const { secret } = await this.loadOtp();
    if (!verifyTotp(secret, otp, now, { window: 1 })) throw jobError('JOB_OTP_INVALID');

    let job;
    try {
      job = JSON.parse(Buffer.from(opened.plaintext).toString('utf8'));
    } catch {
      throw jobError('JOB_INVALID');
    }
    if (!isObject(job)) throw jobError('JOB_INVALID');
    if (job.version !== 1 || job.job_id !== job_id || job.device_id !== device_id) {
      throw jobError('JOB_INVALID');
    }
    if (!INTENTS.has(job.intent)) throw jobError('JOB_INVALID');
    if (typeof job.text !== 'string' || Buffer.byteLength(job.text, 'utf8') > MAX_TEXT_BYTES) {
      throw jobError('JOB_INVALID');
    }
    if (!isObject(job.target) || typeof job.target.workspace !== 'string' || !job.target.workspace) {
      throw jobError('JOB_INVALID');
    }
    if (!Array.isArray(job.files)) throw jobError('JOB_INVALID');

    const preset = job.target.preset === undefined ? 'default' : job.target.preset;
    if (typeof preset !== 'string') throw jobError('JOB_INVALID');
    const session = job.target.session ?? null;
    if (session !== null && typeof session !== 'string') throw jobError('JOB_INVALID');
    const want = job.reply?.want ?? 'text';
    if (typeof want !== 'string') throw jobError('JOB_INVALID');
    const requestedMax = Number(job.reply?.max_bytes ?? MAX_REPLY_BYTES);
    const maxBytes = Number.isFinite(requestedMax)
      ? Math.min(Math.max(Math.trunc(requestedMax), 1), MAX_REPLY_BYTES)
      : MAX_REPLY_BYTES;

    const workspace = path.resolve(job.target.workspace);
    if (!this.workspaceAllowlist.includes(normalizePath(workspace))) {
      throw jobError('JOB_WORKSPACE_NOT_ALLOWED');
    }
    let info;
    try {
      info = await stat(workspace);
    } catch {
      throw jobError('JOB_WORKSPACE_NOT_ALLOWED');
    }
    if (!info.isDirectory()) throw jobError('JOB_WORKSPACE_NOT_ALLOWED');

    const uploadFiles = validateUploadFiles(job.files);
    const totalFileBytes = uploadFiles.reduce((sum, file) => sum + file.size, 0);
    const risk =
      job.intent === 'ask' && totalFileBytes <= 10 * 1024 * 1024 ? 'low' : 'high';
    const jobDir = path.join(this.inboxDir, 'pending', job_id);
    const jobJson = {
      version: 1,
      job_id,
      device_id,
      created_at: new Date(now).toISOString(),
      target: { workspace, preset, session },
      intent: job.intent,
      text: job.text,
      files: uploadFiles.map((file) => ({
        name: file.name,
        size: file.size,
        sha256: file.sha256,
        local_path: `files/${file.storageName}`,
      })),
      risk,
      reply: { want, max_bytes: maxBytes },
    };

    if (uploadFiles.length > 0) {
      const stagingDir = path.join(this.inboxDir, 'pending', `.upload-${job_id}`);
      await rm(stagingDir, { recursive: true, force: true });
      await mkdir(stagingDir, { recursive: true });
      await writeFile(path.join(stagingDir, 'job.json'), JSON.stringify(jobJson, null, 2), 'utf8');
      const saved = await this.jobStore.saveJobWithSequence({
        job: {
          job_id,
          device_id,
          state: 'UPLOADING',
          risk,
          intent: job.intent,
          workspace,
          inbox_path: jobDir,
          challenge: null,
          job_hash: null,
          created_at: now,
          updated_at: now,
        },
        seq,
        nonce,
      });
      if (!saved) {
        await rm(stagingDir, { recursive: true, force: true });
        const current = await this.jobStore.getJob(job_id);
        if (current && current.device_id === device_id) {
          return { job_id: current.job_id, state: current.state, risk: current.risk };
        }
        throw jobError('JOB_REPLAY');
      }
      return {
        job_id,
        state: 'UPLOADING',
        risk,
        files: uploadFiles.map((file, index) => ({
          index,
          name: file.name,
          size: file.size,
          chunks: file.chunks,
        })),
      };
    }

    const tempDir = path.join(
      this.inboxDir,
      'pending',
      `.tmp-${job_id}-${randomBytes(6).toString('hex')}`,
    );
    await mkdir(tempDir, { recursive: true });
    await writeFile(path.join(tempDir, 'job.json'), JSON.stringify(jobJson, null, 2), 'utf8');
    const jobHash = createHash('sha256').update(canonicalJson(jobJson), 'utf8').digest('base64url');
    const challenge = String(randomInt(100000, 1000000));

    const saved = await this.jobStore.saveJobWithSequence({
      job: {
        job_id,
        device_id,
        state: 'WAITING_CONFIRM',
        risk,
        intent: job.intent,
        workspace,
        inbox_path: jobDir,
        challenge,
        job_hash: jobHash,
        created_at: now,
        updated_at: now,
      },
      seq,
      nonce,
    });
    if (!saved) {
      await rm(tempDir, { recursive: true, force: true });
      const current = await this.jobStore.getJob(job_id);
      if (current && current.device_id === device_id) {
        return { job_id: current.job_id, state: current.state, risk: current.risk };
      }
      throw jobError('JOB_REPLAY');
    }

    try {
      await rename(tempDir, jobDir);
    } catch {
      await rm(jobDir, { recursive: true, force: true });
      try {
        await rename(tempDir, jobDir);
      } catch {
        throw jobError('JOB_INBOX_FAILED');
      }
    }
    return { job_id, state: 'WAITING_CONFIRM', risk };
  }

  async #verifyDevice({ jobId, deviceId, ts, proof, type, fileIndex }) {
    if (typeof jobId !== 'string' || !JOB_ID_RE.test(jobId)) throw jobError('JOB_NOT_FOUND');
    if (typeof deviceId !== 'string' || !DEVICE_ID_RE.test(deviceId)) {
      throw jobError('JOB_DEVICE_REJECTED');
    }
    if (!Number.isInteger(ts) || Math.abs(this.now() / 1000 - ts) > 120) {
      throw jobError('JOB_STATUS_AUTH');
    }
    const device = await this.deviceStore.getDevice(deviceId);
    if (!device || device.revoked) throw jobError('JOB_DEVICE_REJECTED');
    const message = canonicalJson({
      type,
      device_id: deviceId,
      job_id: jobId,
      ts,
      ...(fileIndex === undefined ? {} : { file_index: fileIndex }),
    });
    const expected = await hmacSha256Base64Url(device.keys.kAuth, message);
    if (!safeEqualBase64(proof, expected)) throw jobError('JOB_STATUS_AUTH');
    return device;
  }

  async getForDevice({ jobId, deviceId, ts, proof }) {
    await this.#verifyDevice({ jobId, deviceId, ts, proof, type: 'job-status-v1' });
    const job = await this.jobStore.getJob(jobId);
    if (!job || job.device_id !== deviceId) throw jobError('JOB_NOT_FOUND');
    return {
      job_id: job.job_id,
      state: job.state,
      challenge: job.challenge,
      job_hash: job.job_hash,
      risk: job.risk,
      error: job.result_error ?? null,
    };
  }

  async uploadChunk({ jobId, fileIndex, envelope, deviceId, ts, proof }) {
    const device = await this.#verifyDevice({
      jobId,
      deviceId,
      ts,
      proof,
      type: 'job-upload-v1',
    });
    if (!Number.isInteger(fileIndex) || fileIndex < 0) throw jobError('JOB_FILE_CHUNK');
    const job = await this.jobStore.getJob(jobId);
    if (!job || job.device_id !== deviceId) throw jobError('JOB_NOT_FOUND');
    if (job.state !== 'UPLOADING') throw jobError('JOB_NOT_UPLOADING');

    const stagingDir = path.join(this.inboxDir, 'pending', `.upload-${jobId}`);
    let content;
    try {
      content = JSON.parse(await readFile(path.join(stagingDir, 'job.json'), 'utf8'));
    } catch {
      throw jobError('JOB_UPLOAD_STATE');
    }
    const file = Array.isArray(content.files) ? content.files[fileIndex] : null;
    if (!file) throw jobError('JOB_FILE_CHUNK');
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

    let opened;
    try {
      opened = await openFileChunk(device.keys.kEnc, envelope);
    } catch {
      throw jobError('JOB_FILE_CHUNK');
    }
    const header = opened.header;
    if (
      header.type !== 'job-file-chunk-v1' ||
      header.job_id !== jobId ||
      header.file_index !== fileIndex ||
      header.file_sha256 !== file.sha256 ||
      header.chunk_index !== envelope.chunk_index ||
      header.total_chunks !== totalChunks ||
      !Number.isInteger(header.chunk_index) ||
      header.chunk_index < 0 ||
      header.chunk_index >= totalChunks
    ) {
      throw jobError('JOB_FILE_CHUNK');
    }
    const expectedLength =
      header.chunk_index === totalChunks - 1
        ? file.size - header.chunk_index * CHUNK_SIZE
        : CHUNK_SIZE;
    if (opened.bytes.length !== expectedLength) throw jobError('JOB_FILE_CHUNK');

    const chunksDir = path.join(stagingDir, 'chunks');
    await mkdir(chunksDir, { recursive: true });
    await writeFile(
      path.join(chunksDir, `${fileIndex}-${header.chunk_index}`),
      Buffer.from(opened.bytes),
    );

    const expectedTotal = content.files.reduce(
      (sum, item) => sum + Math.ceil(item.size / CHUNK_SIZE),
      0,
    );
    const received = (await readdir(chunksDir)).length;
    if (received < expectedTotal) {
      return { job_id: jobId, state: 'UPLOADING', received, total: expectedTotal };
    }

    for (let index = 0; index < content.files.length; index += 1) {
      const item = content.files[index];
      const total = Math.ceil(item.size / CHUNK_SIZE);
      const parts = [];
      for (let chunkIndex = 0; chunkIndex < total; chunkIndex += 1) {
        parts.push(await readFile(path.join(chunksDir, `${index}-${chunkIndex}`)));
      }
      const buffer = Buffer.concat(parts);
      if (
        buffer.length !== item.size ||
        createHash('sha256').update(buffer).digest('base64url') !== item.sha256
      ) {
        throw jobError('JOB_FILE_HASH_MISMATCH');
      }
      const filePath = path.join(stagingDir, item.local_path);
      await mkdir(path.dirname(filePath), { recursive: true });
      await writeFile(filePath, buffer);
    }
    await rm(chunksDir, { recursive: true, force: true });

    const jobHash = createHash('sha256')
      .update(canonicalJson(content), 'utf8')
      .digest('base64url');
    const challenge = String(randomInt(100000, 1000000));
    const finalDir = path.join(this.inboxDir, 'pending', jobId);
    try {
      await rm(finalDir, { recursive: true, force: true });
      await rename(stagingDir, finalDir);
    } catch {
      throw jobError('JOB_INBOX_FAILED');
    }
    const updated = await this.jobStore.completeUpload({
      jobId,
      challenge,
      jobHash,
      inboxPath: finalDir,
      updatedAt: this.now(),
    });
    if (!updated) {
      await rename(finalDir, stagingDir).catch(() => {});
      throw jobError('JOB_NOT_UPLOADING');
    }
    return { job_id: jobId, state: 'WAITING_CONFIRM', challenge };
  }

  async #verifyResultFile(jobId, result, index, forbidden, secret) {
    const file = result.files[index];
    if (!file) return { ok: false, error: 'result file missing' };
    let bytes;
    try {
      bytes = await readFile(path.join(this.inboxDir, 'done', jobId, 'files', String(index)));
    } catch {
      return { ok: false, error: 'result file missing' };
    }
    if (bytes.length !== file.size) return { ok: false, error: 'result file size mismatch' };
    if (createHash('sha256').update(bytes).digest('base64url') !== file.sha256) {
      return { ok: false, error: 'result file hash mismatch' };
    }
    if (bytes.includes(secret)) return { ok: false, error: 'result file blocked: key material' };
    const scan = scanResultBytes(bytes, forbidden);
    if (!scan.ok) return scan;
    return { ok: true, bytes };
  }

  async #verifyResultFiles(jobId, result, forbidden, secret) {
    for (let index = 0; index < result.files.length; index += 1) {
      const check = await this.#verifyResultFile(jobId, result, index, forbidden, secret);
      if (!check.ok) return check;
    }
    return { ok: true };
  }

  async scanResults() {
    if (this.scanning) return [];
    this.scanning = true;
    const completed = [];
    try {
      let entries;
      try {
        entries = await readdir(path.join(this.inboxDir, 'done'), { withFileTypes: true });
      } catch {
        return completed;
      }
      for (const entry of entries) {
        if (!entry.isDirectory() || !JOB_ID_RE.test(entry.name)) continue;
        const jobId = entry.name;
        const job = await this.jobStore.getJob(jobId);
        if (!job || !['QUEUED', 'RUNNING'].includes(job.state)) continue;
        let result;
        try {
          result = JSON.parse(
            await readFile(path.join(this.inboxDir, 'done', jobId, 'result.json'), 'utf8'),
          );
        } catch {
          continue;
        }
        const { secret } = await this.loadOtp();
        const forbidden = [secret.toString('base64'), secret.toString('hex')];
        let check = validateResult({ job, result, forbidden });
        if (check.ok) {
          check = await this.#verifyResultFiles(jobId, result, forbidden, secret);
        }
        const finishedAt = this.now();
        if (!check.ok) {
          await this.jobStore.completeJob({
            jobId,
            state: 'FAILED',
            resultError: check.error,
            finishedAt,
          });
          completed.push({ job_id: jobId, state: 'FAILED', error: check.error });
          continue;
        }
        const state = result.status === 'done' ? 'DONE' : 'FAILED';
        const error = result.status === 'failed' ? (result.error ?? 'failed') : null;
        await this.jobStore.completeJob({ jobId, state, resultError: error, finishedAt });
        completed.push({ job_id: jobId, state, error });
      }
      return completed;
    } finally {
      this.scanning = false;
    }
  }

  async scanTimeouts() {
    if (this.timeoutScanning) return [];
    this.timeoutScanning = true;
    const expired = [];
    try {
      const now = this.now();
      for (const job of await this.jobStore.listJobs()) {
        if (job.state === 'UPLOADING') {
          if (now - job.created_at < this.uploadTtlMs) continue;
          const updated = await this.jobStore.expireJob({
            jobId: job.job_id,
            fromStates: ['UPLOADING'],
            state: 'EXPIRED',
            resultError: 'JOB_UPLOAD_TIMEOUT',
            finishedAt: now,
          });
          if (!updated) continue;
          await rm(path.join(this.inboxDir, 'pending', `.upload-${job.job_id}`), {
            recursive: true,
            force: true,
          });
          expired.push({ job_id: job.job_id, state: 'EXPIRED', error: 'JOB_UPLOAD_TIMEOUT' });
          continue;
        }

        if (job.state === 'WAITING_CONFIRM') {
          if (now - job.updated_at < this.confirmTtlMs) continue;
          const pendingDir = path.join(this.inboxDir, 'pending', job.job_id);
          const expiredDir = path.join(this.inboxDir, 'expired', job.job_id);
          try {
            await mkdir(path.dirname(expiredDir), { recursive: true });
            await rename(pendingDir, expiredDir);
          } catch {
            try {
              await stat(expiredDir);
            } catch {
              continue;
            }
          }
          const updated = await this.jobStore.expireJob({
            jobId: job.job_id,
            fromStates: ['WAITING_CONFIRM'],
            state: 'EXPIRED',
            resultError: 'JOB_CONFIRM_TIMEOUT',
            finishedAt: now,
            inboxPath: expiredDir,
          });
          if (updated) {
            expired.push({ job_id: job.job_id, state: 'EXPIRED', error: 'JOB_CONFIRM_TIMEOUT' });
          }
          continue;
        }

        if (job.state === 'QUEUED' || job.state === 'RUNNING') {
          const since = job.decided_at ?? job.created_at;
          if (now - since < this.executionTtlMs) continue;
          const updated = await this.jobStore.completeJob({
            jobId: job.job_id,
            state: 'FAILED',
            resultError: 'JOB_EXECUTION_TIMEOUT',
            finishedAt: now,
          });
          if (updated) {
            expired.push({ job_id: job.job_id, state: 'FAILED', error: 'JOB_EXECUTION_TIMEOUT' });
          }
        }
      }
      return expired;
    } finally {
      this.timeoutScanning = false;
    }
  }

  async getResultForDevice({ jobId, deviceId, ts, proof }) {
    const device = await this.#verifyDevice({
      jobId,
      deviceId,
      ts,
      proof,
      type: 'job-result-v1',
    });
    const job = await this.jobStore.getJob(jobId);
    if (!job || job.device_id !== deviceId) throw jobError('JOB_NOT_FOUND');
    if (!['DONE', 'FAILED'].includes(job.state)) throw jobError('JOB_RESULT_NOT_READY');
    if (job.result_error) throw jobError('JOB_RESULT_BLOCKED');
    let result;
    try {
      result = JSON.parse(
        await readFile(path.join(this.inboxDir, 'done', jobId, 'result.json'), 'utf8'),
      );
    } catch {
      throw jobError('JOB_RESULT_NOT_READY');
    }
    const { secret } = await this.loadOtp();
    const check = validateResult({
      job,
      result,
      forbidden: [secret.toString('base64'), secret.toString('hex')],
    });
    if (!check.ok) throw jobError('JOB_RESULT_BLOCKED');
    return sealEnvelope(
      device.keys.kEnc,
      { v: 1, type: 'job-result-v1', job_id: jobId, device_id: deviceId },
      JSON.stringify(result),
    );
  }

  async getResultFileForDevice({ jobId, fileIndex, deviceId, ts, proof }) {
    const device = await this.#verifyDevice({
      jobId,
      deviceId,
      ts,
      proof,
      type: 'job-result-file-v1',
      fileIndex,
    });
    if (!Number.isInteger(fileIndex) || fileIndex < 0) {
      throw jobError('JOB_RESULT_FILE_NOT_FOUND');
    }
    const job = await this.jobStore.getJob(jobId);
    if (!job || job.device_id !== deviceId) throw jobError('JOB_NOT_FOUND');
    if (job.state !== 'DONE') throw jobError('JOB_RESULT_NOT_READY');
    if (job.result_error) throw jobError('JOB_RESULT_BLOCKED');
    let result;
    try {
      result = JSON.parse(
        await readFile(path.join(this.inboxDir, 'done', jobId, 'result.json'), 'utf8'),
      );
    } catch {
      throw jobError('JOB_RESULT_FILE_NOT_FOUND');
    }
    const { secret } = await this.loadOtp();
    const forbidden = [secret.toString('base64'), secret.toString('hex')];
    const check = validateResult({ job, result, forbidden });
    if (!check.ok) throw jobError('JOB_RESULT_BLOCKED');
    const file = result.files[fileIndex];
    if (!file) throw jobError('JOB_RESULT_FILE_NOT_FOUND');
    const verified = await this.#verifyResultFile(jobId, result, fileIndex, forbidden, secret);
    if (!verified.ok) throw jobError('JOB_RESULT_BLOCKED');
    return sealEnvelope(
      device.keys.kEnc,
      {
        v: 1,
        type: 'job-result-file-v1',
        job_id: jobId,
        device_id: deviceId,
        file_index: fileIndex,
        sha256: file.sha256,
        size: file.size,
      },
      verified.bytes,
    );
  }

  async getJobDetail(jobId) {
    if (typeof jobId !== 'string' || !JOB_ID_RE.test(jobId)) throw jobError('JOB_NOT_FOUND');
    const job = await this.jobStore.getJob(jobId);
    if (!job) throw jobError('JOB_NOT_FOUND');
    let content = null;
    try {
      content = JSON.parse(await readFile(path.join(job.inbox_path, 'job.json'), 'utf8'));
    } catch {
      content = null;
    }
    return { ...job, content };
  }

  async approveJob({ jobId, response }) {
    if (typeof jobId !== 'string' || !JOB_ID_RE.test(jobId)) throw jobError('JOB_NOT_FOUND');
    const job = await this.jobStore.getJob(jobId);
    if (!job) throw jobError('JOB_NOT_FOUND');
    if (job.state !== 'WAITING_CONFIRM') throw jobError('JOB_NOT_WAITING');
    if (!job.challenge || !job.job_hash) throw jobError('JOB_INVALID');
    const device = await this.deviceStore.getDevice(job.device_id);
    if (!device || device.revoked) throw jobError('JOB_DEVICE_REJECTED');
    const expected = computeConfirmationResponse(device.keys.kConfirm, job.job_hash, job.challenge);
    if (!responsesEqual(response, expected)) throw jobError('JOB_RESPONSE_INVALID');

    const pendingDir = path.join(this.inboxDir, 'pending', jobId);
    const approvedDir = path.join(this.inboxDir, 'approved', jobId);
    await mkdir(path.dirname(approvedDir), { recursive: true });
    try {
      await rename(pendingDir, approvedDir);
    } catch {
      throw jobError('JOB_MOVE_FAILED');
    }
    const decidedAt = this.now();
    const updated = await this.jobStore.decideJob({
      jobId,
      state: 'QUEUED',
      inboxPath: approvedDir,
      decidedAt,
    });
    if (!updated) {
      await rename(approvedDir, pendingDir).catch(() => {});
      throw jobError('JOB_NOT_WAITING');
    }
    return { job_id: jobId, state: 'QUEUED' };
  }

  async rejectJob({ jobId }) {
    if (typeof jobId !== 'string' || !JOB_ID_RE.test(jobId)) throw jobError('JOB_NOT_FOUND');
    const job = await this.jobStore.getJob(jobId);
    if (!job) throw jobError('JOB_NOT_FOUND');
    if (job.state !== 'WAITING_CONFIRM') throw jobError('JOB_NOT_WAITING');
    const pendingDir = path.join(this.inboxDir, 'pending', jobId);
    const rejectedDir = path.join(this.inboxDir, 'rejected', jobId);
    await mkdir(path.dirname(rejectedDir), { recursive: true });
    try {
      await rename(pendingDir, rejectedDir);
    } catch {
      throw jobError('JOB_MOVE_FAILED');
    }
    const decidedAt = this.now();
    const updated = await this.jobStore.decideJob({
      jobId,
      state: 'REJECTED',
      inboxPath: rejectedDir,
      decidedAt,
    });
    if (!updated) {
      await rename(rejectedDir, pendingDir).catch(() => {});
      throw jobError('JOB_NOT_WAITING');
    }
    return { job_id: jobId, state: 'REJECTED' };
  }

  listJobs() {
    return this.jobStore.listJobs();
  }

  getJob(jobId) {
    return this.jobStore.getJob(jobId);
  }
}
