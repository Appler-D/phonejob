// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
(() => {
  const token = document.querySelector('meta[name="phonejob-admin-token"]')?.content || '';
  const bridgeInput = document.getElementById('bridge-url');
  const startButton = document.getElementById('start-button');
  const statusEl = document.getElementById('status');
  const errorEl = document.getElementById('error');
  const result = document.getElementById('result');
  const qrImage = document.getElementById('qr');
  const confirmLink = document.getElementById('confirm-link');

  function setStatus(text) {
    statusEl.textContent = text;
  }

  function setError(text) {
    errorEl.textContent = text;
  }

  async function startPairing() {
    setError('');
    const bridgeUrl = bridgeInput.value.trim();
    if (!/^https?:\/\//.test(bridgeUrl)) {
      setError('Bridge URL 必须是 http(s) 地址');
      return;
    }
    startButton.disabled = true;
    setStatus('生成中…');
    result.hidden = true;
    try {
      const response = await fetch('/api/pair/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-PhoneJob-Admin': token,
        },
        body: JSON.stringify({ bridge_url: bridgeUrl }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
      if (!body.qr_data_url) {
        setStatus('已创建配对，但 bridge 未配置 PHONEJOB_PWA_ORIGIN，无法生成二维码。');
        return;
      }
      qrImage.src = body.qr_data_url;
      confirmLink.href = body.local_url;
      result.hidden = false;
      setStatus('二维码已生成；请用手机扫描，并在电脑上打开确认页。');
    } catch (err) {
      setStatus('生成失败');
      setError(err.message);
    } finally {
      startButton.disabled = false;
    }
  }

  startButton.addEventListener('click', startPairing);
})();
