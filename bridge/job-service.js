// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalJson, hmacSha256Base64Url, openEnvelope } from './crypto.js';
import { computeConfirmationResponse, responsesEqual } from './confirm.js';
import { verifyTotp } from './totp.js';

const JOB_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const DEVICE_ID_RE = /^dev_[A-Za-z0-9_-]{8,64}$/;
const INTENTS = new Set(['ask', 'file', 'shell', 'mixed']);
const MAX_TEXT_BYTES = 64 * 1024;
const MAX_REPLY_BYTES = 20 * 1024 * 1024;

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

export class JobService {
  constructor({
    deviceStore,
    jobStore,
    loadOtp,
    inboxDir,
    workspaceAllowlist = [],
    now = () => Date.now(),
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
    if (job.files.length > 0) throw jobError('JOB_FILES_UNSUPPORTED');

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

    const risk = job.intent === 'ask' ? 'low' : 'high';
    const jobDir = path.join(this.inboxDir, 'pending', job_id);
    const tempDir = path.join(
      this.inboxDir,
      'pending',
      `.tmp-${job_id}-${randomBytes(6).toString('hex')}`,
    );
    await mkdir(tempDir, { recursive: true });
    const jobJson = {
      version: 1,
      job_id,
      device_id,
      created_at: new Date(now).toISOString(),
      target: { workspace, preset, session },
      intent: job.intent,
      text: job.text,
      files: [],
      risk,
      reply: { want, max_bytes: maxBytes },
    };
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

  async getForDevice({ jobId, deviceId, ts, proof }) {
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
      type: 'job-status-v1',
      device_id: deviceId,
      job_id: jobId,
      ts,
    });
    const expected = await hmacSha256Base64Url(device.keys.kAuth, message);
    if (!safeEqualBase64(proof, expected)) throw jobError('JOB_STATUS_AUTH');
    const job = await this.jobStore.getJob(jobId);
    if (!job || job.device_id !== deviceId) throw jobError('JOB_NOT_FOUND');
    return {
      job_id: job.job_id,
      state: job.state,
      challenge: job.challenge,
      job_hash: job.job_hash,
      risk: job.risk,
    };
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
