// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import path from 'node:path';
import { inflateRawSync } from 'node:zlib';

const EOCD_SIG = 0x06054b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;
const MAX_EOCD_COMMENT = 0xffff;
const RESERVED_NAMES = new Set([
  'CON',
  'PRN',
  'AUX',
  'NUL',
  ...Array.from({ length: 9 }, (_, index) => `COM${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `LPT${index + 1}`),
]);

function fail(reason, error) {
  return { ok: false, reason, error };
}

function findEocd(buffer) {
  if (buffer.length < 22) return -1;
  const min = Math.max(0, buffer.length - 22 - MAX_EOCD_COMMENT);
  for (let offset = buffer.length - 22; offset >= min; offset -= 1) {
    if (buffer.readUInt32LE(offset) !== EOCD_SIG) continue;
    if (offset + 22 + buffer.readUInt16LE(offset + 20) === buffer.length) return offset;
  }
  return -1;
}

function safeEntryParts(raw) {
  const directory = raw.endsWith('/');
  const value = directory ? raw.slice(0, -1) : raw;
  if (!value || value.length > 1024 || value.includes('\0') || value.includes('\ufffd')) {
    return null;
  }
  if (value.includes('\\') || value.includes('//')) return null;
  if (value.startsWith('/') || /^[A-Za-z]:/.test(value)) return null;
  if (/[\u0000-\u001f<>:"|?*]/.test(value) || /[. ]$/.test(value)) return null;
  const parts = value.split('/');
  if (parts.some((part) => part === '' || part === '.' || part === '..')) return null;
  const base = parts[parts.length - 1];
  if (RESERVED_NAMES.has(base.split('.')[0].toUpperCase())) return null;
  return { parts, directory };
}

function scanDirectory(buffer, options, state, depth) {
  const eocd = findEocd(buffer);
  if (eocd < 0) return fail('invalid', 'zip is corrupt');
  const disk = buffer.readUInt16LE(eocd + 4);
  const centralDisk = buffer.readUInt16LE(eocd + 6);
  const entriesOnDisk = buffer.readUInt16LE(eocd + 8);
  const totalEntries = buffer.readUInt16LE(eocd + 10);
  const centralSize = buffer.readUInt32LE(eocd + 12);
  const centralOffset = buffer.readUInt32LE(eocd + 16);
  if (disk !== 0 || centralDisk !== 0 || entriesOnDisk !== totalEntries) {
    return fail('invalid', 'multi-disk zip is not supported');
  }
  if (
    totalEntries === 0xffff ||
    centralSize === 0xffffffff ||
    centralOffset === 0xffffffff ||
    entriesOnDisk === 0xffff
  ) {
    return fail('invalid', 'zip64 is not supported');
  }
  if (centralOffset + centralSize > buffer.length) return fail('invalid', 'zip is corrupt');
  if (totalEntries > options.maxEntries - state.entries) {
    return fail('too_large', 'zip has too many entries');
  }

  let offset = centralOffset;
  const seen = new Set();
  for (let index = 0; index < totalEntries; index += 1) {
    if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== CENTRAL_SIG) {
      return fail('invalid', 'zip is corrupt');
    }
    const flags = buffer.readUInt16LE(offset + 8);
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const diskStart = buffer.readUInt16LE(offset + 34);
    const externalAttributes = buffer.readUInt32LE(offset + 38);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const nameEnd = offset + 46 + nameLength;
    const next = nameEnd + extraLength + commentLength;
    if (nameEnd > buffer.length || next > buffer.length) return fail('invalid', 'zip is corrupt');

    if (flags & 0x1 || flags & 0x40) return fail('unsafe', 'encrypted zip is not allowed');
    if (method !== 0 && method !== 8) return fail('invalid', 'zip compression is not allowed');
    if (
      compressedSize === 0xffffffff ||
      uncompressedSize === 0xffffffff ||
      localOffset === 0xffffffff ||
      diskStart !== 0
    ) {
      return fail('invalid', 'zip64 is not supported');
    }

    const name = buffer.toString('utf8', offset + 46, nameEnd);
    const entry = safeEntryParts(name);
    if (!entry) return fail('unsafe', 'zip entry path is not allowed');
    if (((externalAttributes >>> 16) & 0xf000) === 0xa000) {
      return fail('unsafe', 'zip symlink is not allowed');
    }
    const key = name.toLowerCase();
    if (seen.has(key)) return fail('unsafe', 'zip contains duplicate entries');
    seen.add(key);
    state.entries += 1;
    if (entry.directory) {
      offset = next;
      continue;
    }

    const extension = path.posix.extname(name).toLowerCase();
    if (!options.allowedExtensions.has(extension)) {
      return fail('unsafe', 'zip entry type is not allowed');
    }
    if (extension === '.zip' && depth >= options.maxDepth) {
      return fail('unsafe', 'nested zip is too deep');
    }

    state.bytes += uncompressedSize;
    if (state.bytes > options.maxBytes) return fail('too_large', 'zip expands too large');

    if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== LOCAL_SIG) {
      return fail('invalid', 'zip is corrupt');
    }
    const localFlags = buffer.readUInt16LE(localOffset + 6);
    const localMethod = buffer.readUInt16LE(localOffset + 8);
    if (localFlags & 0x1 || localFlags & 0x40) {
      return fail('unsafe', 'encrypted zip is not allowed');
    }
    if (localMethod !== method) return fail('invalid', 'zip is corrupt');
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const localNameStart = localOffset + 30;
    const localNameEnd = localNameStart + localNameLength;
    if (localNameEnd > buffer.length) return fail('invalid', 'zip is corrupt');
    const localName = buffer.toString('utf8', localNameStart, localNameEnd);
    if (localName !== name) return fail('unsafe', 'zip entry name mismatch');
    if (
      !(flags & 0x8) &&
      (buffer.readUInt32LE(localOffset + 18) !== compressedSize ||
        buffer.readUInt32LE(localOffset + 22) !== uncompressedSize)
    ) {
      return fail('invalid', 'zip is corrupt');
    }
    const dataStart = localNameEnd + localExtraLength;
    if (dataStart + compressedSize > buffer.length) return fail('invalid', 'zip is corrupt');

    if (extension === '.zip') {
      const data = buffer.subarray(dataStart, dataStart + compressedSize);
      let nested;
      if (method === 0) {
        if (compressedSize !== uncompressedSize) return fail('invalid', 'zip is corrupt');
        nested = data;
      } else {
        try {
          nested = inflateRawSync(data, { maxOutputLength: uncompressedSize + 1 });
        } catch {
          return fail('invalid', 'zip is corrupt');
        }
        if (nested.length !== uncompressedSize) return fail('invalid', 'zip is corrupt');
      }
      const result = scanDirectory(nested, options, state, depth + 1);
      if (!result.ok) return result;
    }

    offset = next;
  }
  if (offset !== centralOffset + centralSize) return fail('invalid', 'zip is corrupt');
  return { ok: true };
}

export function scanZip(buffer, options = {}) {
  if (!(options.allowedExtensions instanceof Set)) {
    throw new TypeError('allowedExtensions is required');
  }
  return scanDirectory(
    buffer,
    {
      allowedExtensions: options.allowedExtensions,
      maxEntries: options.maxEntries ?? 1000,
      maxBytes: options.maxBytes ?? 200 * 1024 * 1024,
      maxDepth: options.maxDepth ?? 2,
    },
    { entries: 0, bytes: 0 },
    0,
  );
}
