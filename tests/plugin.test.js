// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  apply,
  buildPrompt,
  extractOutcome,
  nextJob,
  readJob,
  stageFiles,
  writeResult,
} from '../plugin/index.js';
import { validateResult } from '../bridge/result.js';

test('plugin claims, stages, prompts, and records a result', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'phonejob-plugin-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const inbox = path.join(root, 'phone-inbox');
  const workspace = path.join(root, 'workspace');
  const jobId = 'job_test_plugin';
  const jobDir = path.join(inbox, 'approved', jobId);
  await mkdir(path.join(jobDir, 'files'), { recursive: true });
  await mkdir(workspace, { recursive: true });
  await writeFile(path.join(jobDir, 'files', '0-note.txt'), 'hello file');
  const job = {
    version: 1,
    job_id: jobId,
    device_id: 'dev_test_device_1',
    target: { workspace, preset: 'default', session: null },
    intent: 'ask',
    text: 'read the attachment',
    files: [
      {
        name: 'note.txt',
        size: 10,
        sha256: 'A'.repeat(43),
        local_path: 'files/0-note.txt',
      },
    ],
    risk: 'low',
  };
  await writeFile(path.join(jobDir, 'job.json'), JSON.stringify(job));

  const claimed = await nextJob(inbox);
  assert.equal(claimed.claimed, true);
  assert.equal(claimed.id, jobId);
  assert.equal(await readJob(claimed.dir).then((value) => value.text), 'read the attachment');
  const resumed = await nextJob(inbox);
  assert.equal(resumed.id, jobId);
  assert.equal(resumed.claimed, false);

  const stage = await stageFiles(job, claimed.dir, workspace);
  assert.equal(await readFile(path.join(stage, '0-note.txt'), 'utf8'), 'hello file');
  const prompt = buildPrompt(job, stage);
  assert.match(prompt, /PHONEJOB job_test_plugin/);
  assert.match(prompt, /0-note\.txt/);
  assert.match(prompt, /read the attachment/);

  const events = [
    { seq: 1, type: 'turn/start', data: { turn: 1 } },
    {
      seq: 2,
      type: 'assistant/message',
      data: { message: { content: [{ type: 'text', text: 'the result' }] } },
    },
    { seq: 3, type: 'turn/end', data: { reason: { kind: 'completed' } } },
  ];
  const done = extractOutcome(events, 1);
  assert.equal(done.status, 'done');
  assert.equal(done.text, 'the result');
  assert.equal(done.error, null);

  const failed = extractOutcome(
    [
      { seq: 1, type: 'turn/start', data: { turn: 1 } },
      {
        seq: 2,
        type: 'turn/end',
        data: { reason: { kind: 'error', error: { message: 'model failed' } } },
      },
    ],
    1,
  );
  assert.equal(failed.status, 'failed');
  assert.equal(failed.error, 'model failed');

  const result = await writeResult(inbox, jobId, done);
  assert.equal(result.status, 'done');
  assert.equal(validateResult({ job, result }).ok, true);
  const stored = JSON.parse(
    await readFile(path.join(inbox, 'done', jobId, 'result.json'), 'utf8'),
  );
  assert.equal(stored.text, 'the result');
  assert.equal(stored.files.length, 0);
  assert.equal(await nextJob(inbox), null);
});

test('plugin cancels a job that exceeds jobTimeoutMs and records the failure', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'phonejob-plugin-timeout-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const inbox = path.join(root, 'phone-inbox');
  const workspace = path.join(root, 'workspace');
  const jobId = 'job_test_timeout';
  const jobDir = path.join(inbox, 'approved', jobId);
  await mkdir(jobDir, { recursive: true });
  await mkdir(workspace, { recursive: true });
  const job = {
    version: 1,
    job_id: jobId,
    device_id: 'dev_test_device_1',
    target: { workspace, preset: 'default', session: null },
    intent: 'ask',
    text: 'this should time out',
    files: [],
  };
  await writeFile(path.join(jobDir, 'job.json'), JSON.stringify(job));

  let canceled = null;
  let idleCalls = 0;
  const agent = {
    session: { seq: 0, events: [] },
    whenIdle() {
      idleCalls += 1;
      return idleCalls === 1 || canceled ? Promise.resolve() : new Promise(() => {});
    },
    followup() {},
    cancel(cause) {
      canceled = cause;
    },
  };
  const handles = [];
  const ctx = {
    get(name) {
      if (name === 'agents') {
        return {
          get: () => null,
          resume: async () => {
            throw new Error('missing session');
          },
          create: async ({ setup }) => {
            setup?.({ on() {} });
            const handle = { agent, dispose: async () => {} };
            handles.push(handle);
            return handle;
          },
        };
      }
      if (name === 'agentDefaultModel') {
        return { currentSelection: () => ({ provider: 'test', model: 'test' }) };
      }
      if (name === 'sessions') return { flush: async () => {} };
      return undefined;
    },
    effect(fn) {
      this.cleanup = fn();
    },
  };

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  apply(ctx, { inbox, pollMs: 60_000, jobTimeoutMs: 1000 });
  t.after(() => ctx.cleanup?.());
  for (let index = 0; index < 200 && idleCalls < 2; index += 1) await sleep(10);
  assert.equal(idleCalls, 2);

  let result = null;
  for (let index = 0; index < 300 && !result; index += 1) {
    try {
      result = JSON.parse(
        await readFile(path.join(inbox, 'done', jobId, 'result.json'), 'utf8'),
      );
    } catch {
      await sleep(10);
    }
  }
  assert.ok(result, 'timeout result was not written');
  assert.deepEqual(canceled, { kind: 'hook', reason: 'phonejob-timeout' });
  assert.equal(result.status, 'failed');
  assert.equal(result.text, '');
  assert.match(result.error, /timeout after 1 seconds/);

  ctx.cleanup();
});
