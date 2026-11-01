// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { createHmac, timingSafeEqual } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32(bytes) {
  let value = 0;
  let bits = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function computeConfirmationResponse(kConfirm, jobHash, challenge) {
  const mac = createHmac('sha256', kConfirm)
    .update(`confirm-v1\n${jobHash}\n${challenge}`)
    .digest();
  return base32(mac).slice(0, 8);
}

export function normalizeResponse(value) {
  return String(value ?? '')
    .replace(/[\s-]/g, '')
    .toUpperCase();
}

export function responsesEqual(left, right) {
  const a = Buffer.from(normalizeResponse(left));
  const b = Buffer.from(normalizeResponse(right));
  return a.length === b.length && timingSafeEqual(a, b);
}
