// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
const MAX_RESULT_TEXT_BYTES = 200 * 1024;
const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bghp_[A-Za-z0-9]{20,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
];

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
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
  if (result.files.length > 0) return { ok: false, error: 'result files are not supported yet' };
  if (result.error !== null && typeof result.error !== 'string') {
    return { ok: false, error: 'result error must be string or null' };
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
