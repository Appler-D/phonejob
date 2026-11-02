// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { sendPush } from './push.js';

const STATE_TEXT = {
  QUEUED: '电脑已批准任务',
  DONE: '任务已完成',
  FAILED: '任务失败',
  REJECTED: '电脑拒绝了任务',
  EXPIRED: '任务已过期',
};

export class PushService {
  constructor({
    deviceStore,
    vapid,
    fetchImpl = globalThis.fetch,
    now = () => Date.now(),
    subject = 'mailto:phonejob@localhost',
  } = {}) {
    if (!deviceStore || !vapid) throw new TypeError('deviceStore and vapid are required');
    this.deviceStore = deviceStore;
    this.vapid = vapid;
    this.fetchImpl = fetchImpl;
    this.now = now;
    this.subject = subject;
  }

  async notify({ deviceId, jobId, state, error = null }) {
    try {
      const subscription = await this.deviceStore.getPushSubscription(deviceId);
      if (!subscription) return { ok: false, reason: 'no_subscription' };
      const payload = JSON.stringify({
        v: 1,
        type: 'job-state',
        job_id: jobId,
        state,
        error: error ? String(error).slice(0, 120) : null,
        title: 'PhoneJob',
        body: STATE_TEXT[state] ?? `任务状态：${state}`,
      });
      const result = await sendPush({
        subscription: {
          endpoint: subscription.endpoint,
          keys: { p256dh: subscription.p256dh, auth: subscription.auth },
        },
        vapid: this.vapid,
        payload,
        fetchImpl: this.fetchImpl,
        now: this.now(),
        subject: this.subject,
      });
      if (result.status === 404 || result.status === 410) {
        await this.deviceStore.deletePushSubscription(deviceId);
      }
      return result;
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : 'push failed' };
    }
  }
}
