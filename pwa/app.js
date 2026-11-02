// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import {
  canonicalJson,
  computeReceiptResponse,
  computeSas,
  derivePairingKeys,
  deriveSharedSecret,
  fromBase64Url,
  generatePairingKeyPair,
  hmacSha256Base64Url,
  hmacWithKey,
  importAesKey,
  importHmacKey,
  importOtpKey,
  importPeerPublicKey,
  openEnvelope,
  openOtpProvisioning,
  openOtpRefresh,
  pairingTranscript,
  sealEnvelope,
  sealFileChunk,
  toBase64Url,
  totpWithKey,
} from './crypto.js';
import {
  clearOutbox,
  deleteDevice,
  deleteOutbox,
  getDeviceKeys,
  getKey,
  listDevices,
  listOutbox,
  putDevice,
  putDeviceKeys,
  putKey,
  putOutbox,
} from './store.js';
import { outboxBackoffMs, outboxExpired } from './outbox.js';

const pairPanel = document.getElementById('pair-panel');
const totpPanel = document.getElementById('totp-panel');
const payloadInput = document.getElementById('pair-payload');
const pairButton = document.getElementById('pair-button');
const statusEl = document.getElementById('status');
const errorEl = document.getElementById('error');
const sasSection = document.getElementById('sas-section');
const sasEl = document.getElementById('sas');
const codeEl = document.getElementById('totp-code');
const remainingEl = document.getElementById('totp-remaining');
const deviceEl = document.getElementById('device-label');
const rePairButton = document.getElementById('repair-button');
const jobWorkspace = document.getElementById('job-workspace');
const jobIntent = document.getElementById('job-intent');
const jobText = document.getElementById('job-text');
const jobFiles = document.getElementById('job-files');
const jobFilesList = document.getElementById('job-files-list');
const jobSend = document.getElementById('job-send');
const jobStatusEl = document.getElementById('job-status');
const jobErrorEl = document.getElementById('job-error');
const outboxStatusEl = document.getElementById('outbox-status');
const jobWatch = document.getElementById('job-watch');
const jobChallengeEl = document.getElementById('job-challenge');
const jobResponseEl = document.getElementById('job-response');
const jobStateEl = document.getElementById('job-state');
const jobResultEl = document.getElementById('job-result');
const jobResultFilesEl = document.getElementById('job-result-files');
const pushButton = document.getElementById('push-button');
const pushStatusEl = document.getElementById('push-status');

const CHUNK_SIZE = 512 * 1024;

let currentDevice = null;
let currentKey = null;
let totpTimer = null;
let jobWatchTimer = null;
let outboxTimer = null;
let outboxBusy = false;
let jobSending = false;

function setStatus(text) {
  statusEl.textContent = text;
}

function setError(text) {
  errorEl.textContent = text;
}

function setJobStatus(text) {
  jobStatusEl.textContent = text;
}

function setJobError(text) {
  jobErrorEl.textContent = text;
}

function setOutboxStatus(text) {
  outboxStatusEl.textContent = text;
  outboxStatusEl.hidden = !text;
}

function setPushStatus(text) {
  pushStatusEl.textContent = text;
  pushStatusEl.hidden = !text;
}

function formatBytes(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function renderSelectedFiles(files) {
  jobFilesList.textContent = files.length
    ? files.map((file) => `${file.name} (${formatBytes(file.size)})`).join('、')
    : '';
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 10_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (err) {
    if (err?.name === 'AbortError') throw new TypeError('请求超时');
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

function stopTotp() {
  if (totpTimer) {
    clearInterval(totpTimer);
    totpTimer = null;
  }
}

function stopJobWatch() {
  if (jobWatchTimer) {
    clearInterval(jobWatchTimer);
    jobWatchTimer = null;
  }
}

function hideJobWatch() {
  stopJobWatch();
  jobWatch.hidden = true;
  jobChallengeEl.textContent = '';
  jobResponseEl.textContent = '';
  jobStateEl.textContent = '';
  jobResultEl.hidden = true;
  jobResultEl.textContent = '';
  jobResultFilesEl.hidden = true;
  jobResultFilesEl.replaceChildren();
}

async function renderTotp() {
  if (!currentKey) return;
  const now = Date.now();
  codeEl.textContent = await totpWithKey(currentKey, now);
  remainingEl.textContent = String(30 - (Math.floor(now / 1000) % 30));
}

function showTotp(device, key) {
  currentDevice = device;
  currentKey = key;
  pairPanel.hidden = true;
  totpPanel.hidden = false;
  deviceEl.textContent = `${new URL(device.bridge_url).host} · ${device.device_id.slice(0, 12)}…`;
  jobWorkspace.value = Array.isArray(device.workspaces) ? device.workspaces[0] ?? '' : '';
  setStatus('');
  setError('');
  setJobStatus('');
  setJobError('');
  stopTotp();
  renderTotp();
  totpTimer = setInterval(renderTotp, 1000);
  void refreshOtpKey();
  startOutbox();
  if (pushSupported()) {
    pushButton.hidden = false;
    if (Notification.permission === 'granted') void ensurePushSubscription(false);
  }
  if (device.last_job_id) {
    watchJob(device.last_job_id);
  } else {
    hideJobWatch();
  }
}

function showPair() {
  currentDevice = null;
  currentKey = null;
  stopTotp();
  totpPanel.hidden = true;
  pairPanel.hidden = false;
  sasSection.hidden = true;
  sasEl.textContent = '';
  setStatus('');
  setError('');
  setJobStatus('');
  setJobError('');
  jobFiles.value = '';
  renderSelectedFiles([]);
  hideJobWatch();
  pushButton.hidden = true;
  setPushStatus('');
}

function parsePayload(raw) {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('请粘贴电脑上的配对信息');
  let text = trimmed;
  if (!trimmed.startsWith('{')) {
    const url = new URL(trimmed);
    const encoded = new URLSearchParams(url.hash.replace(/^#/, '')).get('pair');
    if (!encoded) throw new Error('配对链接缺少 #pair');
    text = new TextDecoder().decode(fromBase64Url(encoded));
  }
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new Error('配对信息不是有效 JSON');
  }
  for (const key of ['bridge_url', 'pair_id', 'pc_pub', 'nonce', 'expires_at']) {
    if (payload?.[key] === undefined || payload[key] === null || payload[key] === '') {
      throw new Error(`配对信息缺少 ${key}`);
    }
  }
  const bridgeUrl = new URL(payload.bridge_url);
  if (!['http:', 'https:'].includes(bridgeUrl.protocol)) {
    throw new Error('bridge_url 必须是 http(s)');
  }
  const expiresAt = Number(payload.expires_at);
  if (!Number.isFinite(expiresAt)) throw new Error('expires_at 无效');
  const workspaces = Array.isArray(payload.workspaces)
    ? payload.workspaces
        .filter((value) => typeof value === 'string' && value.trim())
        .map((value) => value.trim())
    : [];
  return { ...payload, bridge_url: bridgeUrl.origin, expires_at: expiresAt, workspaces };
}

async function errorText(response) {
  try {
    const body = await response.json();
    return body?.error || `HTTP ${response.status}`;
  } catch {
    return `HTTP ${response.status}`;
  }
}

async function waitForProvision(base, payload, deviceId, proof) {
  const deadline = payload.expires_at + 7 * 60_000;
  while (Date.now() < deadline) {
    const response = await fetchWithTimeout(`${base}/api/pair/provision`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pair_id: payload.pair_id, device_id: deviceId, proof }),
    });
    const body = await response.json().catch(() => null);
    const code = body?.error || `HTTP ${response.status}`;
    if (response.status === 202 || body?.state === 'waiting' || (response.status === 409 && code === 'PAIRING_NOT_CONFIRMED')) {
      await delay(1000);
      continue;
    }
    if (response.ok) return body;
    if (response.status === 404 || response.status === 410) {
      throw new Error('配对已过期，请在电脑上重新生成');
    }
    if (response.status === 429) throw new Error('设备数量已满');
    throw new Error(code);
  }
  throw new Error('等待电脑确认超时');
}

async function startPairing() {
  setError('');
  pairButton.disabled = true;
  try {
    const payload = parsePayload(payloadInput.value);
    if (Date.now() > payload.expires_at) {
      throw new Error('配对信息已过期，请在电脑上重新生成');
    }
    const base = payload.bridge_url;
    setStatus('生成手机密钥…');
    const phone = await generatePairingKeyPair();
    const phonePub = toBase64Url(phone.publicRaw);
    const pcPublicKey = await importPeerPublicKey(fromBase64Url(payload.pc_pub));
    const shared = await deriveSharedSecret(phone.privateKey, pcPublicKey);
    const keys = await derivePairingKeys(shared, payload.pair_id);
    const claimProof = await hmacSha256Base64Url(
      keys.kSas,
      canonicalJson({ type: 'pair-claim', pair_id: payload.pair_id, phone_pub: phonePub }),
    );

    setStatus('提交配对…');
    const claimResponse = await fetchWithTimeout(`${base}/api/pair/claim`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pair_id: payload.pair_id, phone_pub: phonePub, proof: claimProof }),
    });
    if (!claimResponse.ok) throw new Error(await errorText(claimResponse));
    const claim = await claimResponse.json();

    const transcript = pairingTranscript({
      pairId: payload.pair_id,
      pcPub: payload.pc_pub,
      phonePub,
      nonce: payload.nonce,
      expiresAt: payload.expires_at,
    });
    const sas = await computeSas(keys.kSas, transcript);
    sasEl.textContent = sas;
    sasSection.hidden = false;
    setStatus('等待电脑确认 SAS…');

    const provisionProof = await hmacSha256Base64Url(
      keys.kConfirm,
      canonicalJson({
        type: 'otp-provision-request',
        pair_id: payload.pair_id,
        device_id: claim.device_id,
      }),
    );
    const envelope = await waitForProvision(base, payload, claim.device_id, provisionProof);

    setStatus('导入电脑下发的密码子…');
    const received = await openOtpProvisioning(keys.kEnc, envelope);
    const otpKey = await importOtpKey(received.otpSecret);
    await putKey(received.keyId, otpKey);
    const deviceKeys = {
      enc: await importAesKey(keys.kEnc),
      confirm: await importHmacKey(keys.kConfirm),
      auth: await importHmacKey(keys.kAuth),
    };
    await putDeviceKeys(claim.device_id, deviceKeys);
    const device = {
      device_id: claim.device_id,
      key_id: received.keyId,
      bridge_url: base,
      created_at: new Date().toISOString(),
      sas,
      seq: 0,
      workspaces: payload.workspaces,
    };
    await putDevice(device);
    for (const name of ['kPair', 'kSas', 'kConfirm', 'kEnc', 'kAuth']) {
      if (keys[name] instanceof Uint8Array) keys[name].fill(0);
    }
    payloadInput.value = '';
    showTotp(device, otpKey);
  } catch (err) {
    setStatus('配对失败');
    setError(err instanceof TypeError ? '无法连接 bridge（检查隧道、CORS 或网络）' : err.message);
  } finally {
    pairButton.disabled = false;
  }
}

async function refreshOtpKey() {
  if (!currentDevice) return false;
  try {
    const deviceKeys = await getDeviceKeys(currentDevice.device_id);
    if (!deviceKeys) return false;
    const ts = Math.floor(Date.now() / 1000);
    const proof = toBase64Url(
      await hmacWithKey(
        deviceKeys.auth,
        canonicalJson({
          type: 'otp-refresh-v1',
          device_id: currentDevice.device_id,
          ts,
        }),
      ),
    );
    const response = await fetchWithTimeout(`${currentDevice.bridge_url}/api/device/otp`, {
      headers: {
        'X-PhoneJob-Device': currentDevice.device_id,
        'X-PhoneJob-Ts': String(ts),
        'X-PhoneJob-Proof': proof,
      },
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      if (body?.error === 'DEVICE_NOT_FOUND' || body?.error === 'DEVICE_AUTH') {
        setError('设备已被吊销或认证失败，请重新配对');
      }
      return false;
    }
    const opened = await openOtpRefresh(deviceKeys.enc, body);
    if (opened.deviceId !== currentDevice.device_id) throw new Error('刷新信封设备不匹配');
    if (opened.keyId === currentDevice.key_id) return true;
    const otpKey = await importOtpKey(opened.otpSecret);
    await putKey(opened.keyId, otpKey);
    currentKey = otpKey;
    currentDevice.key_id = opened.keyId;
    await putDevice(currentDevice);
    renderTotp();
    setError('');
    return true;
  } catch (err) {
    if (err instanceof TypeError) return false;
    setError(err.message);
    return false;
  }
}

function pushSupported() {
  return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
}

async function ensurePushSubscription(interactive) {
  if (!currentDevice) return false;
  if (!pushSupported()) {
    setPushStatus('当前浏览器不支持 Web Push');
    return false;
  }
  try {
    let permission = Notification.permission;
    if (permission === 'default') {
      if (!interactive) return false;
      permission = await Notification.requestPermission();
    }
    if (permission !== 'granted') {
      if (interactive) setPushStatus('通知权限未授予');
      return false;
    }
    const registration = await navigator.serviceWorker.register('./sw.js');
    await navigator.serviceWorker.ready;
    const health = await fetchWithTimeout(`${currentDevice.bridge_url}/api/health`);
    const info = await health.json().catch(() => null);
    if (!health.ok || typeof info?.vapid_public_key !== 'string') {
      throw new Error('服务器未启用通知');
    }
    let subscription = await registration.pushManager.getSubscription();
    if (subscription) {
      const currentKey = subscription.options?.applicationServerKey;
      if (
        currentKey &&
        toBase64Url(new Uint8Array(currentKey)) !== info.vapid_public_key
      ) {
        await subscription.unsubscribe();
        subscription = null;
      }
    }
    if (!subscription) {
      subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: fromBase64Url(info.vapid_public_key),
      });
    }
    const deviceKeys = await getDeviceKeys(currentDevice.device_id);
    if (!deviceKeys) throw new Error('设备密钥缺失，请重新配对');
    const ts = Math.floor(Date.now() / 1000);
    const proof = toBase64Url(
      await hmacWithKey(
        deviceKeys.auth,
        canonicalJson({
          type: 'push-subscribe-v1',
          device_id: currentDevice.device_id,
          ts,
        }),
      ),
    );
    const response = await fetchWithTimeout(`${currentDevice.bridge_url}/api/device/push`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id: currentDevice.device_id,
        ts,
        proof,
        subscription: subscription.toJSON(),
      }),
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) throw new Error(body?.error || `HTTP ${response.status}`);
    setPushStatus('已启用完成通知');
    return true;
  } catch (err) {
    setPushStatus(err instanceof TypeError ? '无法连接 bridge' : err.message);
    return false;
  }
}

async function fetchJobStatus(jobId) {
  const deviceKeys = await getDeviceKeys(currentDevice.device_id);
  if (!deviceKeys) throw new Error('设备密钥缺失，请重新配对');
  const ts = Math.floor(Date.now() / 1000);
  const proof = toBase64Url(
    await hmacWithKey(
      deviceKeys.auth,
      canonicalJson({
        type: 'job-status-v1',
        device_id: currentDevice.device_id,
        job_id: jobId,
        ts,
      }),
    ),
  );
  const response = await fetchWithTimeout(
    `${currentDevice.bridge_url}/api/job/${encodeURIComponent(jobId)}`,
    {
      headers: {
        'X-PhoneJob-Device': currentDevice.device_id,
        'X-PhoneJob-Ts': String(ts),
        'X-PhoneJob-Proof': proof,
      },
    },
  );
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.error || `HTTP ${response.status}`);
  const opened = await openEnvelope(deviceKeys.enc, body);
  const header = opened.header;
  if (
    header.type !== 'job-status-v1' ||
    header.job_id !== jobId ||
    header.device_id !== currentDevice.device_id ||
    header.request_ts !== ts
  ) {
    throw new Error('状态信封不匹配');
  }
  return JSON.parse(new TextDecoder().decode(opened.plaintext));
}

async function fetchJobResult(jobId) {
  const deviceKeys = await getDeviceKeys(currentDevice.device_id);
  if (!deviceKeys) throw new Error('设备密钥缺失，请重新配对');
  const ts = Math.floor(Date.now() / 1000);
  const proof = toBase64Url(
    await hmacWithKey(
      deviceKeys.auth,
      canonicalJson({
        type: 'job-result-v1',
        device_id: currentDevice.device_id,
        job_id: jobId,
        ts,
      }),
    ),
  );
  const response = await fetchWithTimeout(
    `${currentDevice.bridge_url}/api/job/${encodeURIComponent(jobId)}/result`,
    {
      headers: {
        'X-PhoneJob-Device': currentDevice.device_id,
        'X-PhoneJob-Ts': String(ts),
        'X-PhoneJob-Proof': proof,
      },
    },
    15_000,
  );
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.error || `HTTP ${response.status}`);
  const opened = await openEnvelope(deviceKeys.enc, body);
  if (
    opened.header.type !== 'job-result-v1' ||
    opened.header.job_id !== jobId ||
    opened.header.device_id !== currentDevice.device_id
  ) {
    throw new Error('结果信封不匹配');
  }
  return JSON.parse(new TextDecoder().decode(opened.plaintext));
}

async function fetchJobResultFile(jobId, fileIndex) {
  const deviceKeys = await getDeviceKeys(currentDevice.device_id);
  if (!deviceKeys) throw new Error('设备密钥缺失，请重新配对');
  const ts = Math.floor(Date.now() / 1000);
  const proof = toBase64Url(
    await hmacWithKey(
      deviceKeys.auth,
      canonicalJson({
        type: 'job-result-file-v1',
        device_id: currentDevice.device_id,
        job_id: jobId,
        ts,
        file_index: fileIndex,
      }),
    ),
  );
  const response = await fetchWithTimeout(
    `${currentDevice.bridge_url}/api/job/${encodeURIComponent(jobId)}/result/file/${fileIndex}`,
    {
      headers: {
        'X-PhoneJob-Device': currentDevice.device_id,
        'X-PhoneJob-Ts': String(ts),
        'X-PhoneJob-Proof': proof,
      },
    },
    30_000,
  );
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.error || `HTTP ${response.status}`);
  const opened = await openEnvelope(deviceKeys.enc, body);
  const header = opened.header;
  if (
    header.type !== 'job-result-file-v1' ||
    header.job_id !== jobId ||
    header.device_id !== currentDevice.device_id ||
    header.file_index !== fileIndex
  ) {
    throw new Error('结果文件信封不匹配');
  }
  return { bytes: opened.plaintext, header };
}

function saveResultFile(bytes, name) {
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  anchor.rel = 'noopener';
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function renderResultFiles(jobId, files) {
  jobResultFilesEl.replaceChildren();
  if (!Array.isArray(files) || files.length === 0) {
    jobResultFilesEl.hidden = true;
    return;
  }
  jobResultFilesEl.hidden = false;
  files.forEach((file, index) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'secondary';
    button.textContent = `下载 ${file.name} (${formatBytes(file.size)})`;
    button.addEventListener('click', async () => {
      button.disabled = true;
      try {
        const { bytes, header } = await fetchJobResultFile(jobId, index);
        const digest = toBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
        if (
          bytes.length !== file.size ||
          digest !== file.sha256 ||
          header.sha256 !== file.sha256 ||
          header.size !== file.size
        ) {
          throw new Error('结果文件校验失败');
        }
        saveResultFile(bytes, file.name);
      } catch (err) {
        jobStateEl.textContent = err instanceof TypeError ? '无法连接 bridge' : err.message;
      } finally {
        button.disabled = false;
      }
    });
    jobResultFilesEl.append(button);
  });
}

function retryableError(message) {
  const error = new Error(message);
  error.retryable = true;
  return error;
}

async function enqueueOutbox(jobId, workspace, intent, text, deviceKeys) {
  const createdAt = Date.now();
  const envelope = await sealEnvelope(
    deviceKeys.enc,
    {
      v: 1,
      type: 'outbox-v1',
      job_id: jobId,
      device_id: currentDevice.device_id,
      created_at: createdAt,
    },
    JSON.stringify({ workspace, intent, text }),
  );
  await putOutbox({
    id: jobId,
    device_id: currentDevice.device_id,
    created_at: createdAt,
    attempts: 0,
    next_at: createdAt,
    envelope,
  });
  setOutboxStatus('已加入待发送队列，网络恢复后自动重试');
  startOutbox();
}

async function submitOutboxEntry(entry, deviceKeys) {
  const opened = await openEnvelope(deviceKeys.enc, entry.envelope);
  const header = opened.header;
  if (
    header.type !== 'outbox-v1' ||
    header.job_id !== entry.id ||
    header.device_id !== entry.device_id
  ) {
    throw new Error('队列条目损坏');
  }
  const payload = JSON.parse(new TextDecoder().decode(opened.plaintext));
  await refreshOtpKey();
  if (!currentKey) throw new Error('动态密码子缺失，请重新配对');
  const now = Date.now();
  const seq = Number(currentDevice.seq ?? 0) + 1;
  const envelope = await sealEnvelope(
    deviceKeys.enc,
    {
      v: 2,
      job_id: entry.id,
      device_id: currentDevice.device_id,
      ts: Math.floor(now / 1000),
      seq,
      otp: await totpWithKey(currentKey, now),
    },
    JSON.stringify({
      version: 1,
      job_id: entry.id,
      device_id: currentDevice.device_id,
      target: { workspace: payload.workspace, preset: 'default', session: null },
      intent: payload.intent,
      text: payload.text,
      files: [],
      reply: { want: 'text', max_bytes: 20 * 1024 * 1024 },
    }),
  );
  let response;
  try {
    response = await fetchWithTimeout(`${currentDevice.bridge_url}/api/job`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });
  } catch (err) {
    throw retryableError(err instanceof TypeError ? '无法连接 bridge' : err.message);
  }
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const code = body?.error || `HTTP ${response.status}`;
    const error = new Error(code);
    error.retryable =
      response.status === 408 || response.status === 429 || response.status >= 500;
    throw error;
  }
  if (!body || typeof body !== 'object') throw retryableError('bridge 响应无效');
  currentDevice.seq = seq;
  currentDevice.last_job_id = entry.id;
  await putDevice(currentDevice);
  await deleteOutbox(entry.id);
  setOutboxStatus('');
  setJobError('');
  setJobStatus(`已提交 ${entry.id}，状态 ${body.state}`);
  watchJob(entry.id);
}

async function processOutbox() {
  if (outboxBusy || jobSending || !currentDevice || !currentKey) return;
  outboxBusy = true;
  try {
    const entries = await listOutbox(currentDevice.device_id);
    if (entries.length === 0) {
      setOutboxStatus('');
      return;
    }
    const now = Date.now();
    const active = [];
    for (const entry of entries) {
      if (outboxExpired(entry.created_at, now)) {
        await deleteOutbox(entry.id);
        setJobError('待发送任务已过期，请重新发送');
        continue;
      }
      active.push(entry);
    }
    if (active.length === 0) {
      setOutboxStatus('');
      return;
    }
    setOutboxStatus(`待发送 ${active.length} 条，网络恢复后自动重试`);
    const due = active.filter((entry) => Number(entry.next_at ?? 0) <= now);
    for (const entry of due) {
      try {
        const deviceKeys = await getDeviceKeys(currentDevice.device_id);
        if (!deviceKeys) {
          await deleteOutbox(entry.id);
          setOutboxStatus('');
          setError('设备密钥缺失，请重新配对');
          continue;
        }
        await submitOutboxEntry(entry, deviceKeys);
        return;
      } catch (err) {
        if (err.retryable) {
          const attempts = Number(entry.attempts ?? 0) + 1;
          await putOutbox({
            ...entry,
            attempts,
            next_at: Date.now() + outboxBackoffMs(attempts),
          });
          setJobError('网络暂不可用，待发送任务会自动重试');
          continue;
        }
        await deleteOutbox(entry.id);
        setJobError(err.message || '待发送任务失败');
      }
    }
  } catch {
    // IndexedDB unavailable; keep the form-based flow working.
  } finally {
    outboxBusy = false;
  }
}

function startOutbox() {
  if (outboxTimer) {
    void processOutbox();
    return;
  }
  outboxTimer = setInterval(() => {
    void processOutbox();
  }, 5000);
  void processOutbox();
}

async function watchJob(jobId) {
  stopJobWatch();
  jobWatch.hidden = false;
  jobResultEl.hidden = true;
  jobResultEl.textContent = '';
  jobResultFilesEl.hidden = true;
  jobResultFilesEl.replaceChildren();
  jobStateEl.textContent = '等待电脑确认…';
  const tick = async () => {
    try {
      const status = await fetchJobStatus(jobId);
      if (status.challenge && status.job_hash) {
        jobChallengeEl.textContent = status.challenge;
        const deviceKeys = await getDeviceKeys(currentDevice.device_id);
        if (deviceKeys) {
          jobResponseEl.textContent = await computeReceiptResponse(
            deviceKeys.confirm,
            status.job_hash,
            status.challenge,
          );
        }
      }
      if (status.state === 'UPLOADING') {
        jobStateEl.textContent = '正在接收文件…';
      } else if (status.state === 'QUEUED' || status.state === 'RUNNING') {
        jobStateEl.textContent = '电脑已批准，等待执行';
      } else if (status.state === 'REJECTED') {
        jobStateEl.textContent = '电脑已拒绝';
        stopJobWatch();
      } else if (status.state === 'EXPIRED') {
        stopJobWatch();
        jobStateEl.textContent =
          status.error === 'JOB_UPLOAD_TIMEOUT'
            ? '上传超时，请重新发送'
            : status.error === 'JOB_CONFIRM_TIMEOUT'
              ? '确认超时，请重新发送'
              : status.error === 'RESULT_EXPIRED'
                ? '结果已过期，无法再下载'
                : `任务已超时${status.error ? `：${status.error}` : ''}`;
      } else if (status.state === 'FAILED') {
        stopJobWatch();
        jobStateEl.textContent = `执行失败${status.error ? `：${status.error}` : ''}`;
      } else if (status.state === 'DONE') {
        stopJobWatch();
        jobStateEl.textContent = '已完成';
        try {
          const result = await fetchJobResult(jobId);
          jobResultEl.textContent = result.text || result.error || '(空结果)';
          jobResultEl.hidden = false;
          renderResultFiles(jobId, result.files);
        } catch (err) {
          jobResultEl.textContent = err instanceof TypeError ? '无法连接 bridge' : err.message;
          jobResultEl.hidden = false;
        }
      } else {
        jobStateEl.textContent = '等待电脑确认…';
      }
    } catch (err) {
      jobStateEl.textContent = err instanceof TypeError ? '无法连接 bridge' : err.message;
    }
  };
  jobWatchTimer = setInterval(tick, 2000);
  tick();
}

async function uploadJobFiles(jobId, files, deviceKeys) {
  const totalChunks = files.reduce(
    (sum, file) => sum + Math.ceil(file.size / CHUNK_SIZE),
    0,
  );
  let sent = 0;
  for (let fileIndex = 0; fileIndex < files.length; fileIndex += 1) {
    const file = files[fileIndex];
    const chunks = Math.ceil(file.size / CHUNK_SIZE);
    for (let chunkIndex = 0; chunkIndex < chunks; chunkIndex += 1) {
      const start = chunkIndex * CHUNK_SIZE;
      const bytes = new Uint8Array(
        await file.file.slice(start, start + CHUNK_SIZE).arrayBuffer(),
      );
      const envelope = await sealFileChunk(
        deviceKeys.enc,
        {
          jobId,
          fileIndex,
          fileSha256: file.sha256,
          chunkIndex,
          totalChunks: chunks,
        },
        bytes,
      );
      const ts = Math.floor(Date.now() / 1000);
      const proof = toBase64Url(
        await hmacWithKey(
          deviceKeys.auth,
          canonicalJson({
            type: 'job-upload-v1',
            device_id: currentDevice.device_id,
            job_id: jobId,
            ts,
          }),
        ),
      );
      const response = await fetchWithTimeout(
        `${currentDevice.bridge_url}/api/job/${encodeURIComponent(jobId)}/file/${fileIndex}`,
        {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'X-PhoneJob-Device': currentDevice.device_id,
            'X-PhoneJob-Ts': String(ts),
            'X-PhoneJob-Proof': proof,
          },
          body: JSON.stringify(envelope),
        },
        15_000,
      );
      const body = await response.json().catch(() => null);
      if (!response.ok) throw new Error(body?.error || `HTTP ${response.status}`);
      sent += 1;
      setJobStatus(`上传中 ${sent}/${totalChunks}`);
      if (body.state === 'WAITING_CONFIRM') return;
    }
  }
}

async function sendJob() {
  if (!currentDevice || !currentKey) {
    setJobError('请先完成配对');
    return;
  }
  setJobError('');
  setJobStatus('');
  const workspace = jobWorkspace.value.trim();
  const text = jobText.value.trim();
  const intent = jobIntent.value;
  const selected = [...jobFiles.files];
  if (!workspace) {
    setJobError('请填写工作区');
    return;
  }
  if (!text && selected.length === 0) {
    setJobError('请填写任务内容或选择附件');
    return;
  }
  if (outboxBusy) {
    setJobError('正在重试待发送任务，请稍后再试');
    return;
  }
  const deviceKeys = await getDeviceKeys(currentDevice.device_id);
  if (!deviceKeys) {
    setJobError('设备密钥缺失，请重新配对');
    return;
  }
  await refreshOtpKey();

  jobSend.disabled = true;
  jobSending = true;
  let queuedJob = null;
  try {
    const fileMeta = [];
    if (selected.length > 0) setJobStatus('计算文件校验…');
    for (const file of selected) {
      if (file.size > 50 * 1024 * 1024) throw new Error(`${file.name} 超过 50MB`);
      const bytes = new Uint8Array(await file.arrayBuffer());
      const sha256 = toBase64Url(
        new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
      );
      fileMeta.push({ file, name: file.name, size: file.size, sha256 });
    }

    const seq = Number(currentDevice.seq ?? 0) + 1;
    const now = Date.now();
    const jobId = crypto.randomUUID();
    queuedJob = { jobId, workspace, intent, text };
    const header = {
      v: 2,
      job_id: jobId,
      device_id: currentDevice.device_id,
      ts: Math.floor(now / 1000),
      seq,
      otp: await totpWithKey(currentKey, now),
    };
    const job = {
      version: 1,
      job_id: jobId,
      device_id: currentDevice.device_id,
      target: { workspace, preset: 'default', session: null },
      intent,
      text,
      files: fileMeta.map(({ name, size, sha256 }) => ({ name, size, sha256 })),
      reply: { want: 'text', max_bytes: 20 * 1024 * 1024 },
    };
    const envelope = await sealEnvelope(deviceKeys.enc, header, JSON.stringify(job));
    const response = await fetchWithTimeout(
      `${currentDevice.bridge_url}/api/job`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope),
      },
      15_000,
    );
    const body = await response.json().catch(() => null);
    if (!response.ok) throw new Error(body?.error || `HTTP ${response.status}`);
    currentDevice.seq = seq;
    currentDevice.last_job_id = body.job_id;
    await putDevice(currentDevice);
    setJobStatus(`已提交 ${body.job_id}，状态 ${body.state}`);
    jobText.value = '';
    jobFiles.value = '';
    renderSelectedFiles([]);
    if (body.state === 'UPLOADING') {
      await uploadJobFiles(body.job_id, fileMeta, deviceKeys);
    }
    watchJob(body.job_id);
  } catch (err) {
    const networkFailure =
      err instanceof TypeError || /^HTTP 50[234]$/.test(String(err.message ?? ''));
    if (networkFailure && selected.length === 0 && queuedJob) {
      try {
        await enqueueOutbox(
          queuedJob.jobId,
          queuedJob.workspace,
          queuedJob.intent,
          queuedJob.text,
          deviceKeys,
        );
        setJobError('');
        setJobStatus('');
        jobText.value = '';
        jobFiles.value = '';
        renderSelectedFiles([]);
      } catch (queueErr) {
        setJobError(`加入待发送队列失败：${queueErr.message}`);
      }
      return;
    }
    if (networkFailure && selected.length > 0) {
      setJobError('网络不可用；附件任务暂不支持离线排队，请稍后重试');
      return;
    }
    setJobError(
      err instanceof TypeError
        ? '无法连接 bridge（检查隧道、CORS 或网络）'
        : err.message === 'JOB_RATE_LIMITED'
          ? '提交过于频繁，请稍后再试'
          : err.message === 'JOB_LOCKED'
            ? '动态密码子错误次数过多，请稍后再试'
            : err.message === 'JOB_OTP_INVALID'
              ? '动态密码子不正确'
              : err.message === 'JOB_QUEUE_FULL'
                ? '电脑待处理任务已满，请稍后再试'
                : err.message === 'JOB_DISK_FULL'
                  ? '电脑收件箱空间不足，请清理后再试'
                  : err.message === 'JOB_OFFICE_UNSAFE'
                    ? 'Office 文件包含宏或嵌入对象，已拒绝'
                    : err.message === 'JOB_OFFICE_INVALID'
                      ? 'Office 文件结构无效，已拒绝'
                      : err.message === 'JOB_OFFICE_TOO_LARGE'
                        ? 'Office 文件解压后过大，已拒绝'
                        : err.message,
    );
  } finally {
    jobSending = false;
    jobSend.disabled = false;
  }
}

async function init() {
  const encoded = new URLSearchParams(location.hash.replace(/^#/, '')).get('pair');
  if (encoded) {
    try {
      payloadInput.value = new TextDecoder().decode(fromBase64Url(encoded));
    } catch {
      // Ignore a malformed fragment; the user can paste the payload manually.
    }
  }
  try {
    const devices = await listDevices();
    if (devices.length) {
      const device = devices[0];
      const key = await getKey(device.key_id);
      if (key) {
        showTotp(device, key);
        return;
      }
    }
  } catch {
    // IndexedDB is unavailable; pairing still works for this session.
  }
  showPair();
}

pairButton.addEventListener('click', startPairing);
jobFiles.addEventListener('change', () => renderSelectedFiles([...jobFiles.files]));
jobSend.addEventListener('click', sendJob);
pushButton.addEventListener('click', () => {
  void ensurePushSubscription(true);
});
rePairButton.addEventListener('click', async () => {
  if (currentDevice) {
    try {
      await clearOutbox(currentDevice.device_id);
      await deleteDevice(currentDevice);
    } catch {
      // The local key may already be gone; continue to the pairing view.
    }
  }
  showPair();
});
window.addEventListener('online', () => {
  void refreshOtpKey();
});

init();
