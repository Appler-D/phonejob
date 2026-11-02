// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
export const OUTBOX_MAX_AGE_MS = 10 * 60_000;

export function outboxBackoffMs(attempts) {
  const step = Math.max(0, Math.min(6, Math.trunc(Number(attempts) || 0)));
  return Math.min(60_000, 1000 * 2 ** step);
}

export function outboxExpired(createdAt, now = Date.now()) {
  return now - Number(createdAt) > OUTBOX_MAX_AGE_MS;
}
