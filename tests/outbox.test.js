// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { OUTBOX_MAX_AGE_MS, outboxBackoffMs, outboxExpired } from '../pwa/outbox.js';

test('outbox retry backoff and expiry', () => {
  assert.equal(outboxBackoffMs(0), 1000);
  assert.equal(outboxBackoffMs(1), 2000);
  assert.equal(outboxBackoffMs(2), 4000);
  assert.equal(outboxBackoffMs(6), 60_000);
  assert.equal(outboxBackoffMs(20), 60_000);
  assert.equal(outboxBackoffMs(-1), 1000);
  assert.equal(outboxExpired(1000, 1000 + OUTBOX_MAX_AGE_MS), false);
  assert.equal(outboxExpired(1000, 1000 + OUTBOX_MAX_AGE_MS + 1), true);
});
