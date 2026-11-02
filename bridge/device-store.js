// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { protect, unprotect } from './dpapi.js';

const SCHEMA_VERSION = 1;

function metadata(device) {
  return {
    device_id: device.deviceId,
    created_at: device.createdAt,
    revoked: Boolean(device.revoked),
  };
}

export class MemoryDeviceStore {
  constructor() {
    this.devices = new Map();
    this.pushSubscriptions = new Map();
  }

  async saveDevice(device) {
    const previous = this.devices.get(device.deviceId);
    this.devices.set(device.deviceId, {
      ...device,
      revoked: previous ? previous.revoked : false,
    });
  }

  async listDevices() {
    return [...this.devices.values()].map(metadata);
  }

  async getDevice(deviceId) {
    return this.devices.get(deviceId) ?? null;
  }

  async revokeDevice(deviceId) {
    const device = this.devices.get(deviceId);
    if (!device) return false;
    device.revoked = true;
    this.pushSubscriptions.delete(deviceId);
    return true;
  }

  async savePushSubscription({ deviceId, endpoint, p256dh, auth, updatedAt }) {
    this.pushSubscriptions.set(deviceId, {
      device_id: deviceId,
      endpoint,
      p256dh,
      auth,
      updated_at: updatedAt,
    });
  }

  async getPushSubscription(deviceId) {
    return this.pushSubscriptions.get(deviceId) ?? null;
  }

  async deletePushSubscription(deviceId) {
    this.pushSubscriptions.delete(deviceId);
  }

  async close() {}
}

export class SqliteDeviceStore {
  constructor({ filePath }) {
    mkdirSync(path.dirname(filePath), { recursive: true });
    this.db = new DatabaseSync(filePath);
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA synchronous = NORMAL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        phone_pub TEXT NOT NULL,
        keys_blob BLOB NOT NULL,
        key_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        device_id TEXT PRIMARY KEY,
        endpoint TEXT NOT NULL,
        p256dh TEXT NOT NULL,
        auth TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);
    const version = this.db.prepare('PRAGMA user_version').get()?.user_version ?? 0;
    if (version > SCHEMA_VERSION) {
      this.db.close();
      throw new Error(`Unsupported device database version ${version}`);
    }
    if (version < SCHEMA_VERSION) {
      this.db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
    }
  }

  async saveDevice({ deviceId, phonePub, keys, keyId, createdAt }) {
    const payload = JSON.stringify({
      kEnc: Buffer.from(keys.kEnc).toString('base64url'),
      kConfirm: Buffer.from(keys.kConfirm).toString('base64url'),
      kAuth: Buffer.from(keys.kAuth).toString('base64url'),
      keyId,
    });
    const blob = await protect(Buffer.from(payload, 'utf8'));
    this.db
      .prepare(`
        INSERT INTO devices (device_id, phone_pub, keys_blob, key_id, created_at, revoked)
        VALUES (?, ?, ?, ?, ?, 0)
        ON CONFLICT(device_id) DO UPDATE SET
          phone_pub = excluded.phone_pub,
          keys_blob = excluded.keys_blob,
          key_id = excluded.key_id,
          created_at = excluded.created_at
      `)
      .run(deviceId, phonePub, blob, keyId, createdAt);
  }

  async listDevices() {
    return this.db
      .prepare('SELECT device_id, created_at, revoked FROM devices ORDER BY created_at DESC')
      .all()
      .map((row) => ({
        device_id: row.device_id,
        created_at: row.created_at,
        revoked: Boolean(row.revoked),
      }));
  }

  async getDevice(deviceId) {
    const row = this.db.prepare('SELECT * FROM devices WHERE device_id = ?').get(deviceId);
    if (!row) return null;
    const plaintext = await unprotect(Buffer.from(row.keys_blob));
    const parsed = JSON.parse(plaintext.toString('utf8'));
    return {
      deviceId: row.device_id,
      phonePub: row.phone_pub,
      keys: {
        kEnc: Buffer.from(parsed.kEnc, 'base64url'),
        kConfirm: Buffer.from(parsed.kConfirm, 'base64url'),
        kAuth: Buffer.from(parsed.kAuth, 'base64url'),
      },
      keyId: row.key_id,
      createdAt: row.created_at,
      revoked: Boolean(row.revoked),
    };
  }

  async revokeDevice(deviceId) {
    const result = this.db.prepare('UPDATE devices SET revoked = 1 WHERE device_id = ?').run(deviceId);
    if (result.changes > 0) {
      this.db.prepare('DELETE FROM push_subscriptions WHERE device_id = ?').run(deviceId);
    }
    return result.changes > 0;
  }

  async savePushSubscription({ deviceId, endpoint, p256dh, auth, updatedAt }) {
    this.db
      .prepare(`
        INSERT INTO push_subscriptions (device_id, endpoint, p256dh, auth, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
          endpoint = excluded.endpoint,
          p256dh = excluded.p256dh,
          auth = excluded.auth,
          updated_at = excluded.updated_at
      `)
      .run(deviceId, endpoint, p256dh, auth, updatedAt);
  }

  async getPushSubscription(deviceId) {
    return (
      this.db.prepare('SELECT * FROM push_subscriptions WHERE device_id = ?').get(deviceId) ?? null
    );
  }

  async deletePushSubscription(deviceId) {
    this.db.prepare('DELETE FROM push_subscriptions WHERE device_id = ?').run(deviceId);
  }

  async close() {
    this.db.close();
  }
}
