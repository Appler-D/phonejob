// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), 'dpapi.ps1');
const MAX_OUTPUT = 1024 * 1024;

function run(mode, data) {
  if (process.platform !== 'win32') {
    return Promise.reject(new Error('DPAPI is only available on Windows'));
  }
  if (!Buffer.isBuffer(data)) {
    return Promise.reject(new TypeError('data must be a Buffer'));
  }

  return new Promise((resolve, reject) => {
    const child = spawn(
      'powershell.exe',
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', SCRIPT, mode],
      { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] },
    );

    let stdout = '';
    let killed = false;
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      if (stdout.length > MAX_OUTPUT && !killed) {
        killed = true;
        child.kill();
      }
    });
    // Drain stderr without surfacing it: a malformed input error could echo key material.
    child.stderr.on('data', () => {});
    child.on('error', (err) => {
      reject(new Error(`DPAPI ${mode} failed: ${err.message}`));
    });
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`DPAPI ${mode} failed (exit ${code})`));
        return;
      }
      const encoded = stdout.trim();
      if (!encoded) {
        reject(new Error(`DPAPI ${mode} returned no data`));
        return;
      }
      resolve(Buffer.from(encoded, 'base64'));
    });

    child.stdin.end(data.toString('base64'));
  });
}

export function protect(data) {
  return run('protect', data);
}

export function unprotect(blob) {
  return run('unprotect', blob);
}
