// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  base32,
  computeConfirmationResponse,
  normalizeResponse,
  responsesEqual,
} from '../bridge/confirm.js';

test('base32 matches RFC 4648 vectors', () => {
  const vectors = [
    ['', ''],
    ['f', 'MY'],
    ['fo', 'MZXQ'],
    ['foo', 'MZXW6'],
    ['foob', 'MZXW6YQ'],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI'],
  ];
  for (const [input, expected] of vectors) {
    assert.equal(base32(Buffer.from(input, 'ascii')), expected, input);
  }
});

test('confirmation response is deterministic and normalized', () => {
  const key = Buffer.alloc(32, 0x77);
  const response = computeConfirmationResponse(key, 'job-hash', '123456');
  assert.match(response, /^[A-Z2-7]{8}$/);
  assert.equal(computeConfirmationResponse(key, 'job-hash', '123456'), response);
  assert.equal(computeConfirmationResponse(key, 'job-hash', '654321') === response, false);
  assert.equal(normalizeResponse(`${response.slice(0, 4)} ${response.slice(4).toLowerCase()}`), response);
  assert.equal(responsesEqual(response, response), true);
  assert.equal(responsesEqual(response, response === 'AAAAAAAA' ? 'BBBBBBBB' : 'AAAAAAAA'), false);
});
