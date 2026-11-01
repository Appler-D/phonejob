// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { createHmac, timingSafeEqual } from 'node:crypto';

const DEFAULT_STEP_SECONDS = 30;
const DEFAULT_DIGITS = 6;
const DEFAULT_WINDOW = 1;

export function hotp(secret, counter, digits = DEFAULT_DIGITS) {
  if (!Buffer.isBuffer(secret) || secret.length === 0) {
    throw new TypeError('secret must be a non-empty Buffer');
  }
  if (!Number.isInteger(digits) || digits < 1 || digits > 10) {
    throw new RangeError('digits must be an integer between 1 and 10');
  }
  if (!Number.isInteger(counter) || counter < 0) {
    throw new RangeError('counter must be a non-negative integer');
  }
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', secret).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function totp(secret, time = Date.now(), { step = DEFAULT_STEP_SECONDS, digits = DEFAULT_DIGITS } = {}) {
  return hotp(secret, Math.floor(time / 1000 / step), digits);
}

export function verifyTotp(
  secret,
  code,
  time = Date.now(),
  { step = DEFAULT_STEP_SECONDS, digits = DEFAULT_DIGITS, window = DEFAULT_WINDOW } = {},
) {
  const normalized = String(code).replace(/[\s-]/g, '');
  if (!/^\d+$/.test(normalized) || normalized.length !== digits) {
    return false;
  }
  const counter = Math.floor(time / 1000 / step);
  for (let offset = -window; offset <= window; offset += 1) {
    const expected = hotp(secret, Math.max(0, counter + offset), digits);
    if (timingSafeEqual(Buffer.from(expected), Buffer.from(normalized))) {
      return true;
    }
  }
  return false;
}
