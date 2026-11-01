// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
(() => {
  const token = document.querySelector('meta[name="phonejob-admin-token"]')?.content || '';
  const listError = document.getElementById('list-error');
  const empty = document.getElementById('empty');
  const jobsEl = document.getElementById('jobs');
  const detail = document.getElementById('detail');
  const detailMeta = document.getElementById('detail-meta');
  const detailText = document.getElementById('detail-text');
  const detailTarget = document.getElementById('detail-target');
  const detailChallenge = document.getElementById('detail-challenge');
  const detailResponse = document.getElementById('detail-response');
  const detailStatus = document.getElementById('detail-status');
  const detailError = document.getElementById('detail-error');
  const approveButton = document.getElementById('approve');
  const rejectButton = document.getElementById('reject');

  let selected = null;

  async function request(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { 'X-PhoneJob-Admin': token, ...(options.headers || {}) },
      cache: 'no-store',
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) throw new Error(body?.error || `HTTP ${response.status}`);
    return body;
  }

  function renderJobs(jobs) {
    jobsEl.replaceChildren();
    const waiting = jobs.filter((job) => job.state === 'WAITING_CONFIRM');
    empty.hidden = waiting.length > 0;
    for (const job of jobs) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = `job ${job.state === 'WAITING_CONFIRM' ? 'waiting' : 'done'}${job.risk === 'high' ? ' high' : ''}`;
      const id = document.createElement('span');
      id.className = 'job-id';
      id.textContent = job.job_id;
      const meta = document.createElement('span');
      meta.className = 'job-meta';
      meta.textContent = `${job.state} · ${job.risk} · ${job.intent}`;
      button.append(id, meta);
      button.addEventListener('click', () => loadDetail(job.job_id));
      jobsEl.append(button);
    }
  }

  async function refreshList() {
    try {
      const body = await request('/api/jobs');
      renderJobs(body.jobs);
      listError.textContent = '';
    } catch (err) {
      listError.textContent = err instanceof TypeError ? '无法连接 bridge' : err.message;
    }
  }

  async function loadDetail(jobId) {
    selected = jobId;
    try {
      const job = await request(`/api/jobs/${encodeURIComponent(jobId)}`);
      detail.hidden = false;
      detailMeta.textContent = `${job.job_id} · ${job.device_id} · ${job.state} · risk ${job.risk}`;
      detailText.textContent = job.content?.text ?? '(job.json missing)';
      detailTarget.replaceChildren();
      const entries = [
        ['workspace', job.content?.target?.workspace ?? job.workspace],
        ['intent', job.content?.intent ?? job.intent],
        ['files', String(job.content?.files?.length ?? 0)],
        ['risk', job.risk],
      ];
      for (const [name, value] of entries) {
        const term = document.createElement('dt');
        term.textContent = name;
        const description = document.createElement('dd');
        description.textContent = value;
        detailTarget.append(term, description);
      }
      detailChallenge.textContent = job.challenge ?? '';
      detailResponse.value = '';
      detailStatus.textContent =
        job.state === 'WAITING_CONFIRM' ? '等待输入手机响应码' : `状态：${job.state}`;
      approveButton.disabled = job.state !== 'WAITING_CONFIRM';
      rejectButton.disabled = job.state !== 'WAITING_CONFIRM';
      detailError.textContent = '';
    } catch (err) {
      detail.hidden = false;
      detailMeta.textContent = jobId;
      detailText.textContent = '';
      detailTarget.replaceChildren();
      detailChallenge.textContent = '';
      detailStatus.textContent = '';
      detailError.textContent = err instanceof TypeError ? '无法连接 bridge' : err.message;
    }
  }

  approveButton.addEventListener('click', async () => {
    if (!selected) return;
    const value = detailResponse.value.replace(/\s+/g, '');
    if (!/^[A-Z2-7]{8}$/i.test(value)) {
      detailError.textContent = '请输入 8 位响应码';
      return;
    }
    approveButton.disabled = true;
    detailError.textContent = '';
    try {
      const result = await request(`/api/jobs/${encodeURIComponent(selected)}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ response: value }),
      });
      detailStatus.textContent = `已批准，状态 ${result.state}`;
      rejectButton.disabled = true;
      await refreshList();
      await loadDetail(selected);
      detailStatus.textContent = `已批准，状态 ${result.state}`;
    } catch (err) {
      detailError.textContent = err.message;
      approveButton.disabled = false;
    }
  });

  rejectButton.addEventListener('click', async () => {
    if (!selected) return;
    rejectButton.disabled = true;
    detailError.textContent = '';
    try {
      const result = await request(`/api/jobs/${encodeURIComponent(selected)}/reject`, {
        method: 'POST',
      });
      detailStatus.textContent = `已拒绝，状态 ${result.state}`;
      approveButton.disabled = true;
      await refreshList();
      await loadDetail(selected);
      detailStatus.textContent = `已拒绝，状态 ${result.state}`;
    } catch (err) {
      detailError.textContent = err.message;
      rejectButton.disabled = false;
    }
  });

  refreshList();
  setInterval(refreshList, 3000);
})();
