// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data?.json() ?? {};
  } catch {
    data = {};
  }
  const title = typeof data.title === 'string' ? data.title : 'PhoneJob';
  const body = typeof data.body === 'string' ? data.body : '';
  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      tag: typeof data.job_id === 'string' ? data.job_id : undefined,
      data: {
        job_id: typeof data.job_id === 'string' ? data.job_id : null,
        state: typeof data.state === 'string' ? data.state : null,
      },
    }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      const existing = windows.find((client) => 'focus' in client);
      if (existing) {
        await existing.focus();
        return;
      }
      await self.clients.openWindow('./');
    })(),
  );
});
