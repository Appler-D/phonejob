// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
const DB_NAME = 'phonejob';
const DB_VERSION = 1;
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

export async function deleteDevice(device) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['devices', 'keys'], 'readwrite');
    transaction.objectStore('devices').delete(device.device_id);
    transaction.objectStore('keys').delete(device.key_id);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}
