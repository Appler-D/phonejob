// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { scanZip } from '../bridge/zip-scan.js';
import { deflatedZip, storedZip } from './zip-fixture.js';

const allowed = new Set(['.txt', '.md', '.zip']);

test('safe zip archives pass, including deflated and nested entries', () => {
  assert.deepEqual(
    scanZip(storedZip([{ name: 'note.txt', data: 'hello' }, { name: 'dir/', data: '' }]), {
      allowedExtensions: allowed,
    }),
    { ok: true },
  );
  assert.equal(
    scanZip(deflatedZip([{ name: 'note.md', data: 'hello'.repeat(1000) }]), {
      allowedExtensions: allowed,
    }).ok,
    true,
  );
  const inner = storedZip([{ name: 'inside.txt', data: 'nested' }]);
  assert.equal(
    scanZip(storedZip([{ name: 'inner.zip', data: inner }]), { allowedExtensions: allowed }).ok,
    true,
  );
  assert.equal(
    scanZip(deflatedZip([{ name: 'inner.zip', data: inner }]), { allowedExtensions: allowed }).ok,
    true,
  );
});

test('unsafe zip entries are rejected', () => {
  const unsafe = [
    [{ name: '../evil.txt', data: 'x' }, 'zip entry path'],
    [{ name: '/evil.txt', data: 'x' }, 'zip entry path'],
    [{ name: 'dir\\evil.txt', data: 'x' }, 'zip entry path'],
    [{ name: 'evil.exe', data: 'MZ' }, 'zip entry type'],
    [{ name: 'CON.txt', data: 'x' }, 'zip entry path'],
    [{ name: 'trailing.txt.', data: 'x' }, 'zip entry path'],
    [{ name: 'note.txt', data: 'x', flags: 1 }, 'encrypted zip'],
    [{ name: 'link.txt', data: 'target', external: (0o120777 << 16) >>> 0 }, 'zip symlink'],
    [{ name: 'link/', data: '', external: (0o120777 << 16) >>> 0 }, 'zip symlink'],
    [{ name: 'dup.txt', data: 'a' }, null],
  ];
  for (const [entry, message] of unsafe) {
    const zip = storedZip(message === null ? [entry, { name: 'DUP.TXT', data: 'b' }] : [entry]);
    const result = scanZip(zip, { allowedExtensions: allowed });
    assert.equal(result.ok, false, entry.name);
    if (message) assert.match(result.error, new RegExp(message));
  }

  const nested = storedZip([
    { name: 'inner.zip', data: storedZip([{ name: 'evil.exe', data: 'MZ' }]) },
  ]);
  assert.match(scanZip(nested, { allowedExtensions: allowed }).error, /zip entry type/);

  const renamed = Buffer.from(storedZip([{ name: 'note.txt', data: 'x' }]));
  renamed.write('evil.exe', renamed.indexOf('note.txt'), 'utf8');
  assert.match(
    scanZip(renamed, { allowedExtensions: allowed }).error,
    /zip entry name mismatch/,
  );

  assert.match(
    scanZip(
      storedZip([
        {
          name: 'inner.zip',
          data: storedZip([{ name: 'deeper.zip', data: storedZip([]) }]),
        },
      ]),
      { allowedExtensions: allowed, maxDepth: 1 },
    ).error,
    /nested zip/,
  );
});

test('zip limits and corrupt archives are rejected', () => {
  const tooLarge = storedZip([{ name: 'big.txt', data: 'x', uncompressedSize: 101 }]);
  const largeResult = scanZip(tooLarge, { allowedExtensions: allowed, maxBytes: 100 });
  assert.equal(largeResult.ok, false);
  assert.equal(largeResult.reason, 'too_large');

  const tooMany = storedZip([
    { name: 'a.txt', data: 'a' },
    { name: 'b.txt', data: 'b' },
    { name: 'c.txt', data: 'c' },
  ]);
  assert.equal(scanZip(tooMany, { allowedExtensions: allowed, maxEntries: 2 }).ok, false);

  const corrupt = scanZip(Buffer.from('not a zip'), { allowedExtensions: allowed });
  assert.equal(corrupt.ok, false);
  assert.equal(corrupt.reason, 'invalid');
});

test('office containers can reject macros without an extension whitelist', () => {
  const rules = {
    allowedExtensions: null,
    forbiddenPatterns: [/(^|\/)vbaProject\.bin$/i, /(^|\/)embeddings\//i],
  };
  const safe = storedZip([
    { name: '[Content_Types].xml', data: '<Types/>' },
    { name: 'word/document.xml', data: '<document/>' },
  ]);
  assert.equal(scanZip(safe, rules).ok, true);
  const macro = storedZip([
    { name: 'word/document.xml', data: '<document/>' },
    { name: 'word/vbaProject.bin', data: 'MZ' },
  ]);
  assert.equal(scanZip(macro, rules).ok, false);
  const embedded = storedZip([
    { name: 'word/document.xml', data: '<document/>' },
    { name: 'word/embeddings/oleObject1.bin', data: 'MZ' },
  ]);
  assert.equal(scanZip(embedded, rules).ok, false);
});
