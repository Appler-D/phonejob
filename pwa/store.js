// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
const DB_NAME = 'phonejob';
const DB_VERSION = 3;
let dbPromise = null;

function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('devices')) {
        db.createObjectStore('devices', { keyPath: 'device_id' });
      }
      if (!db.objectStoreNames.contains('keys')) {
        db.createObjectStore('keys', { keyPath: 'key_id' });
      }
      if (!db.objectStoreNames.contains('device_keys')) {
        db.createObjectStore('device_keys', { keyPath: 'device_id' });
      }
      if (!db.objectStoreNames.contains('outbox')) {
        const outbox = db.createObjectStore('outbox', { keyPath: 'id' });
        outbox.createIndex('device_id', 'device_id');
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return dbPromise;
}

export async function putDevice(device) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('devices', 'readwrite');
    transaction.objectStore('devices').put(device);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

export async function listDevices() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction('devices', 'readonly').objectStore('devices').getAll();
    request.onsuccess = () => {
      const devices = request.result ?? [];
      devices.sort((left, right) => String(right.created_at).localeCompare(String(left.created_at)));
      resolve(devices);
    };
    request.onerror = () => reject(request.error);
  });
}

export async function putKey(keyId, key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('keys', 'readwrite');
    transaction.objectStore('keys').put({ key_id: keyId, key });
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

export async function getKey(keyId) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction('keys', 'readonly').objectStore('keys').get(keyId);
    request.onsuccess = () => resolve(request.result?.key ?? null);
    request.onerror = () => reject(request.error);
  });
}

export async function putDeviceKeys(deviceId, keys) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('device_keys', 'readwrite');
    transaction.objectStore('device_keys').put({
      device_id: deviceId,
      enc: keys.enc,
      confirm: keys.confirm,
      auth: keys.auth,
    });
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

export async function getDeviceKeys(deviceId) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction('device_keys', 'readonly').objectStore('device_keys').get(deviceId);
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error);
  });
}

export async function deleteDevice(device) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['devices', 'keys', 'device_keys'], 'readwrite');
    transaction.objectStore('devices').delete(device.device_id);
    transaction.objectStore('keys').delete(device.key_id);
    transaction.objectStore('device_keys').delete(device.device_id);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

export async function putOutbox(entry) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('outbox', 'readwrite');
    transaction.objectStore('outbox').put(entry);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

export async function listOutbox(deviceId) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = db
      .transaction('outbox', 'readonly')
      .objectStore('outbox')
      .index('device_id')
      .getAll(deviceId);
    request.onsuccess = () => {
      const entries = request.result ?? [];
      entries.sort((left, right) => left.created_at - right.created_at);
      resolve(entries);
    };
    request.onerror = () => reject(request.error);
  });
}

export async function deleteOutbox(id) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('outbox', 'readwrite');
    transaction.objectStore('outbox').delete(id);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

export async function clearOutbox(deviceId) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('outbox', 'readwrite');
    const store = transaction.objectStore('outbox');
    const request = store.index('device_id').openKeyCursor(IDBKeyRange.only(deviceId));
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return;
      store.delete(cursor.primaryKey);
      cursor.continue();
    };
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}
