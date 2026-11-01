// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateResult } from '../bridge/result.js';

const job = { job_id: 'job_test_result' };

function result(overrides = {}) {
  return {
    job_id: job.job_id,
    status: 'done',
    finished_at: '2026-11-01T00:00:00.000Z',
    text: 'the answer',
    files: [],
    error: null,
    ...overrides,
  };
}

test('valid result passes validation', () => {
  assert.equal(validateResult({ job, result: result() }).ok, true);
  assert.equal(validateResult({ job, result: result({ status: 'failed', text: '', error: 'boom' }) }).ok, true);
});

test('invalid results are rejected', () => {
  assert.equal(validateResult({ job, result: null }).ok, false);
  assert.equal(validateResult({ job, result: result({ job_id: 'job_other_1' }) }).ok, false);
  assert.equal(validateResult({ job, result: result({ status: 'ok' }) }).ok, false);
  assert.equal(validateResult({ job, result: result({ finished_at: null }) }).ok, false);
  assert.equal(validateResult({ job, result: result({ text: null }) }).ok, false);
  assert.equal(validateResult({ job, result: result({ files: [{ name: 'x' }] }) }).ok, false);
  assert.equal(validateResult({ job, result: result({ error: 42 }) }).ok, false);
  assert.equal(
    validateResult({ job, result: result({ text: 'x'.repeat(200 * 1024 + 1) }) }).ok,
    false,
  );
});

test('secret patterns and known key material block the result', () => {
  assert.equal(
    validateResult({ job, result: result({ text: `leak sk-${'A'.repeat(24)}` }) }).ok,
    false,
  );
  assert.equal(
    validateResult({ job, result: result({ text: '-----BEGIN RSA PRIVATE KEY-----' }) }).ok,
    false,
  );
  assert.equal(
    validateResult({ job, result: result({ text: `leak ${'A'.repeat(32)}` }), forbidden: ['A'.repeat(32)] }).ok,
    false,
  );
});
