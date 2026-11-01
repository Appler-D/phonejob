// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { hotp, totp, verifyTotp } from '../bridge/totp.js';

const RFC_SECRET = Buffer.from('12345678901234567890', 'ascii');

test('HOTP matches RFC 4226 vectors', () => {
  const expected = [
    '755224',
    '287082',
    '359152',
    '969429',
    '338314',
    '254676',
    '287922',
    '162583',
    '399871',
    '520489',
  ];
  expected.forEach((code, counter) => {
    assert.equal(hotp(RFC_SECRET, counter), code, `counter ${counter}`);
  });
});

test('TOTP matches RFC 6238 SHA-1 vectors', () => {
  const vectors = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];
  for (const [seconds, code] of vectors) {
    assert.equal(totp(RFC_SECRET, seconds * 1000, { digits: 8 }), code, `t=${seconds}`);
  }
});

test('verifyTotp accepts the current and adjacent steps', () => {
  const now = 59_000;
  const current = totp(RFC_SECRET, now);
  const previous = totp(RFC_SECRET, now - 30_000);
  const next = totp(RFC_SECRET, now + 30_000);

  assert.equal(verifyTotp(RFC_SECRET, current, now), true);
  assert.equal(verifyTotp(RFC_SECRET, previous, now), true);
  assert.equal(verifyTotp(RFC_SECRET, next, now), true);
});

test('verifyTotp rejects wrong, malformed, and out-of-window codes', () => {
  const now = 59_000;
  const current = totp(RFC_SECRET, now);
  const wrong = current === '000000' ? '111111' : '000000';

  assert.equal(verifyTotp(RFC_SECRET, wrong, now), false);
  assert.equal(verifyTotp(RFC_SECRET, '12345', now), false);
  assert.equal(verifyTotp(RFC_SECRET, 'abcdef', now), false);

  const outside = totp(RFC_SECRET, now + 90_000);
  assert.equal(verifyTotp(RFC_SECRET, outside, now, { window: 1 }), false);
});
