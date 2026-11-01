// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import {
  canonicalJson,
  computeSas,
  derivePairingKeys,
  deriveSharedSecret,
  fromBase64Url,
  generatePairingKeyPair,
  hmacSha256Base64Url,
  importAesKey,
  importHmacKey,
  importOtpKey,
  importPeerPublicKey,
  openOtpProvisioning,
  pairingTranscript,
  sealEnvelope,
  toBase64Url,
  totpWithKey,
} from './crypto.js';
import {
  deleteDevice,
  getDeviceKeys,
  getKey,
  listDevices,
  putDevice,
  putDeviceKeys,
  putKey,
} from './store.js';

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
const jobSend = document.getElementById('job-send');
const jobStatusEl = document.getElementById('job-status');
const jobErrorEl = document.getElementById('job-error');

let currentDevice = null;
let currentKey = null;
let totpTimer = null;

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

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function stopTotp() {
  if (totpTimer) {
    clearInterval(totpTimer);
    totpTimer = null;
  }
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
    const response = await fetch(`${base}/api/pair/provision`, {
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
    const claimResponse = await fetch(`${base}/api/pair/claim`, {
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
  if (!workspace) {
    setJobError('请填写工作区');
    return;
  }
  if (!text) {
    setJobError('请填写任务内容');
    return;
  }
  const deviceKeys = await getDeviceKeys(currentDevice.device_id);
  if (!deviceKeys) {
    setJobError('设备密钥缺失，请重新配对');
    return;
  }

  jobSend.disabled = true;
  try {
    const seq = Number(currentDevice.seq ?? 0) + 1;
    const now = Date.now();
    const jobId = crypto.randomUUID();
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
      files: [],
      reply: { want: 'text', max_bytes: 20 * 1024 * 1024 },
    };
    const envelope = await sealEnvelope(deviceKeys.enc, header, JSON.stringify(job));
    const response = await fetch(`${currentDevice.bridge_url}/api/job`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) throw new Error(body?.error || `HTTP ${response.status}`);
    currentDevice.seq = seq;
    await putDevice(currentDevice);
    setJobStatus(`已提交 ${body.job_id}，状态 ${body.state}`);
    jobText.value = '';
  } catch (err) {
    setJobError(err instanceof TypeError ? '无法连接 bridge（检查隧道、CORS 或网络）' : err.message);
  } finally {
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
jobSend.addEventListener('click', sendJob);
rePairButton.addEventListener('click', async () => {
  if (currentDevice) {
    try {
      await deleteDevice(currentDevice);
    } catch {
      // The local key may already be gone; continue to the pairing view.
    }
  }
  showPair();
});

init();
