// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
(() => {
  const match = location.pathname.match(/\/pair\/([A-Za-z0-9_-]+)$/);
  const pairId = match ? match[1] : '';
  const token = new URLSearchParams(location.search).get('token') || '';
  const stateEl = document.getElementById('state');
  const form = document.getElementById('confirm-form');
  const sasEl = document.getElementById('pc-sas');
  const input = document.getElementById('sas');
  const errorEl = document.getElementById('error');
  const cancelButton = document.getElementById('cancel');
  let timer = null;
  let focused = false;

  const headers = { 'X-PhoneJob-Pair-Token': token };

  function setError(text) {
    errorEl.textContent = text;
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  async function request(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { ...headers, ...(options.headers || {}) },
      cache: 'no-store',
    });
    let body = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    if (!response.ok) {
      const error = new Error(body && body.error ? body.error : '请求失败');
      error.status = response.status;
      throw error;
    }
    return body;
  }

  async function refresh() {
    if (!pairId || !token) {
      stateEl.textContent = '配对链接无效';
      stop();
      return;
    }
    try {
      const status = await request(`/api/pair/${encodeURIComponent(pairId)}`);
      if (status.state === 'waiting') {
        stateEl.textContent = '等待手机扫码并提交配对…';
        form.hidden = true;
      } else if (status.state === 'claimed') {
        stateEl.textContent = '手机已提交，请核对 SAS';
        sasEl.textContent = status.sas;
        form.hidden = false;
        if (!focused) {
          input.focus();
          focused = true;
        }
      } else if (status.state === 'confirmed') {
        stateEl.textContent = '已确认，等待手机接收密码子…';
        form.hidden = true;
      } else if (status.state === 'provisioned') {
        stateEl.textContent = '配对完成，可以关闭窗口。';
        form.hidden = true;
        stop();
      } else {
        stateEl.textContent = '未知状态';
        form.hidden = true;
      }
      setError('');
    } catch (error) {
      if (error.status === 404 || error.status === 410) {
        stateEl.textContent = '配对不存在或已过期';
        form.hidden = true;
        stop();
      } else {
        setError(error.message);
      }
    }
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const sas = input.value.replace(/\s+/g, '');
    if (!/^\d{6}$/.test(sas)) {
      setError('请输入 6 位数字 SAS');
      return;
    }
    setError('');
    try {
      await request(`/api/pair/${encodeURIComponent(pairId)}/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sas }),
      });
      stateEl.textContent = '已确认，等待手机接收密码子…';
      form.hidden = true;
      stop();
      timer = setInterval(refresh, 2000);
    } catch (error) {
      setError(error.message === 'SAS_MISMATCH' ? 'SAS 不一致，请重新核对' : error.message);
    }
  });

  cancelButton.addEventListener('click', async () => {
    try {
      await request(`/api/pair/${encodeURIComponent(pairId)}/cancel`, { method: 'POST' });
    } catch {
      // The pairing may already be gone; the UI still leaves the confirm view.
    }
    stateEl.textContent = '已取消';
    form.hidden = true;
    stop();
  });

  refresh();
  timer = setInterval(refresh, 2000);
})();
