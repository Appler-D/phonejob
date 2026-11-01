// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import path from 'node:path';

const MAX_RESULT_TEXT_BYTES = 200 * 1024;
export const MAX_RESULT_FILES = 10;
export const MAX_RESULT_FILE_BYTES = 10 * 1024 * 1024;
export const MAX_RESULT_TOTAL_BYTES = 20 * 1024 * 1024;
export const RESULT_EXTENSIONS = new Set([
  '.jpg',
  '.jpeg',
  '.png',
  '.pdf',
  '.docx',
  '.xlsx',
  '.pptx',
  '.txt',
  '.md',
  '.csv',
  '.json',
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
const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bghp_[A-Za-z0-9]{20,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
];

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function safeResultFileName(value) {
  if (typeof value !== 'string' || !value) return null;
  if (path.basename(value) !== value) return null;
  if (/[\u0000-\u001f<>:"/\\|?*]/.test(value) || /[. ]$/.test(value)) return null;
  if (value.length > 100) return null;
  if (RESERVED_NAMES.has(value.split('.')[0].toUpperCase())) return null;
  if (!RESULT_EXTENSIONS.has(path.extname(value).toLowerCase())) return null;
  return value;
}

export function scanResultBytes(bytes, forbidden = []) {
  const text = (Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes)).toString('latin1');
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(text)) return { ok: false, error: 'result file blocked: secret pattern' };
  }
  for (const value of forbidden) {
    if (typeof value === 'string' && value.length >= 16 && text.includes(value)) {
      return { ok: false, error: 'result file blocked: key material' };
    }
  }
  return { ok: true };
}

export function validateResult({ job, result, forbidden = [] }) {
  if (!isObject(result)) return { ok: false, error: 'result.json is not an object' };
  if (result.job_id !== job.job_id) return { ok: false, error: 'result job_id mismatch' };
  if (!['done', 'failed'].includes(result.status)) {
    return { ok: false, error: 'result status must be done or failed' };
  }
  if (typeof result.finished_at !== 'string') {
    return { ok: false, error: 'result finished_at missing' };
  }
  if (typeof result.text !== 'string') return { ok: false, error: 'result text missing' };
  if (Buffer.byteLength(result.text, 'utf8') > MAX_RESULT_TEXT_BYTES) {
    return { ok: false, error: 'result text too large' };
  }
  if (!Array.isArray(result.files)) return { ok: false, error: 'result files missing' };
  if (result.files.length > MAX_RESULT_FILES) {
    return { ok: false, error: 'result has too many files' };
  }
  if (result.status === 'failed' && result.files.length > 0) {
    return { ok: false, error: 'failed result must not contain files' };
  }
  if (result.error !== null && typeof result.error !== 'string') {
    return { ok: false, error: 'result error must be string or null' };
  }

  let total = 0;
  const names = new Set();
  for (const file of result.files) {
    if (!isObject(file)) return { ok: false, error: 'result file is not an object' };
    if (safeResultFileName(file.name) !== file.name) {
      return { ok: false, error: 'result file name is not allowed' };
    }
    if (names.has(file.name)) return { ok: false, error: 'result file names must be unique' };
    names.add(file.name);
    if (!Number.isInteger(file.size) || file.size <= 0 || file.size > MAX_RESULT_FILE_BYTES) {
      return { ok: false, error: 'result file size is not allowed' };
    }
    if (typeof file.sha256 !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(file.sha256)) {
      return { ok: false, error: 'result file hash is not allowed' };
    }
    total += file.size;
    if (total > MAX_RESULT_TOTAL_BYTES) return { ok: false, error: 'result files are too large' };
  }

  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(result.text)) return { ok: false, error: 'result blocked: secret pattern' };
  }
  for (const value of forbidden) {
    if (typeof value === 'string' && value.length >= 16 && result.text.includes(value)) {
      return { ok: false, error: 'result blocked: key material' };
    }
  }
  return { ok: true };
}
