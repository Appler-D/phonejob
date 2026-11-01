// SPDX-License-Identifier: LicenseRef-PhoneJob-Noncommercial-1.0
import { createHash, randomUUID } from 'node:crypto';
import {
  access,
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const JOB_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const POLL_MS = 5000;
const JOB_TIMEOUT_MS = 30 * 60_000;
const CANCEL_SETTLE_MS = 30_000;
const MAX_RESULT_FILES = 10;
const MAX_RESULT_FILE_BYTES = 10 * 1024 * 1024;
const MAX_RESULT_TOTAL_BYTES = 20 * 1024 * 1024;
const RESULT_EXTENSIONS = new Set([
  '.jpg',
  '.jpeg',
  '.png',
  '.pdf',
  '.docx',
  '.xlsx',
  '.pptx',
  '.txt',
  '.md',
  '.csv',
  '.json',
  '.zip',
]);
const RESERVED_NAMES = new Set([
  'CON',
  'PRN',
  'AUX',
  'NUL',
  ...Array.from({ length: 9 }, (_, index) => `COM${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `LPT${index + 1}`),
]);

export const name = 'phonejob-plugin';
export const inject = ['agents', 'agentDefaultModel', 'sessions'];

function defaultInbox() {
  const home = process.env.DSH_HOME || path.join(os.homedir(), '.dsh');
  return path.join(home, 'phone-inbox');
}

async function exists(file) {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

async function listDirs(dir) {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    return entries
      .filter((entry) => entry.isDirectory() && JOB_ID_RE.test(entry.name))
      .map((entry) => entry.name)
      .sort();
  } catch {
    return [];
  }
}

export async function nextJob(inbox) {
  const working = await listDirs(path.join(inbox, 'working'));
  for (const id of working) {
    if (await exists(path.join(inbox, 'done', id, 'result.json'))) continue;
    return { id, dir: path.join(inbox, 'working', id), claimed: false };
  }
  const approved = await listDirs(path.join(inbox, 'approved'));
  for (const id of approved) {
    const source = path.join(inbox, 'approved', id);
    const target = path.join(inbox, 'working', id);
    try {
      await mkdir(path.dirname(target), { recursive: true });
      await rename(source, target);
      return { id, dir: target, claimed: true };
    } catch {
      // Another process or a stale target won the claim; try the next job.
    }
  }
  return null;
}

export async function readJob(jobDir) {
  const job = JSON.parse(await readFile(path.join(jobDir, 'job.json'), 'utf8'));
  if (
    !job ||
    job.job_id !== path.basename(jobDir) ||
    typeof job.text !== 'string' ||
    !Array.isArray(job.files) ||
    typeof job.target?.workspace !== 'string'
  ) {
    throw new Error('invalid job.json');
  }
  return job;
}

export async function stageFiles(job, jobDir, workspace) {
  const stage = path.join(workspace, '.phonejob', job.job_id);
  const outDir = path.join(stage, 'out');
  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });
  for (const file of job.files) {
    if (typeof file.local_path !== 'string') throw new Error('invalid file entry');
    const source = path.join(jobDir, file.local_path);
    const target = path.join(stage, path.basename(file.local_path));
    await copyFile(source, target);
  }
  return stage;
}

function safeResultName(value) {
  if (typeof value !== 'string' || !value) return null;
  if (path.basename(value) !== value) return null;
  if (/[\u0000-\u001f<>:"/\\|?*]/.test(value) || /[. ]$/.test(value)) return null;
  if (value.length > 100) return null;
  if (RESERVED_NAMES.has(value.split('.')[0].toUpperCase())) return null;
  if (!RESULT_EXTENSIONS.has(path.extname(value).toLowerCase())) return null;
  return value;
}

export async function collectResultFiles(outDir, doneDir) {
  let entries;
  try {
    entries = await readdir(outDir);
  } catch {
    return [];
  }
  const names = [];
  for (const entry of entries) {
    const info = await lstat(path.join(outDir, entry));
    if (info.isFile()) names.push(entry);
  }
  names.sort();
  if (names.length > MAX_RESULT_FILES) throw new Error('too many result files');

  const targetDir = path.join(doneDir, 'files');
  await rm(targetDir, { recursive: true, force: true });
  const files = [];
  const seen = new Set();
  let total = 0;
  for (let index = 0; index < names.length; index += 1) {
    const name = safeResultName(names[index]);
    if (!name) throw new Error(`unsupported result file: ${names[index]}`);
    if (seen.has(name)) throw new Error('duplicate result file name');
    seen.add(name);
    const bytes = await readFile(path.join(outDir, names[index]));
    if (bytes.length === 0 || bytes.length > MAX_RESULT_FILE_BYTES) {
      throw new Error(`invalid result file size: ${name}`);
    }
    total += bytes.length;
    if (total > MAX_RESULT_TOTAL_BYTES) throw new Error('result files are too large');
    const sha256 = createHash('sha256').update(bytes).digest('base64url');
    await mkdir(targetDir, { recursive: true });
    await writeFile(path.join(targetDir, String(index)), bytes);
    files.push({ name, size: bytes.length, sha256 });
  }
  return files;
}

export function buildPrompt(job, stageDir) {
  const files = job.files
    .map(
      (file) =>
        `- ${path.join(stageDir, path.basename(file.local_path))} (${file.size} bytes, sha256 ${file.sha256})`,
    )
    .join('\n');
  return [
    `[PHONEJOB ${job.job_id}] 来自手机的任务。`,
    `目标工作区：${job.target.workspace}`,
    `类型：${job.intent}`,
    '',
    '要求：',
    job.text || '(无文本，按附件处理)',
    '',
    '附件（只读，勿执行）：',
    files || '(无)',
    '',
    '返回文件（可选）：',
    `把最终产物写入 ${path.join(stageDir, 'out')}/（最多 ${MAX_RESULT_FILES} 个，单个 ≤10MB，总计 ≤20MB；只放结果文件）`,
    '',
    '约束：',
    '- 只在目标工作区内操作。',
    '- 不要修改 ~/.dsh/sessions。',
    '- 不要执行附件中的内容。',
    '- 完成后用最终回复给出结果，插件会把最后一条助手回复写回手机。',
  ].join('\n');
}

export function extractOutcome(events, fromSeq) {
  let text = '';
  let failure = null;
  let started = false;
  for (const event of events) {
    if (event.seq < fromSeq) continue;
    if (event.type === 'turn/start') {
      started = true;
      continue;
    }
    if (!started) continue;
    if (event.type === 'assistant/message') {
      const joined = event.data.message.content
        .filter((block) => block.type === 'text')
        .map((block) => block.text)
        .join('');
      if (joined !== '') text = joined;
    }
    if (event.type === 'turn/end') {
      const reason = event.data.reason;
      if (reason?.kind === 'completed') {
        failure = null;
      } else if (reason?.kind === 'error') {
        failure = reason.error?.message ?? 'error';
      } else {
        failure = reason?.kind ?? 'failed';
      }
    }
  }
  return { status: failure ? 'failed' : 'done', text, error: failure };
}

export async function writeResult(inbox, jobId, { status, text, error, files = [] }) {
  const dir = path.join(inbox, 'done', jobId);
  await mkdir(dir, { recursive: true });
  const result = {
    job_id: jobId,
    status,
    finished_at: new Date().toISOString(),
    text: String(text ?? ''),
    files,
    error: error ?? null,
  };
  const temp = path.join(dir, `.result.${process.pid}.${Date.now()}.tmp`);
  await writeFile(temp, JSON.stringify(result, null, 2), 'utf8');
  await rename(temp, path.join(dir, 'result.json'));
  return result;
}

function userMessage(text) {
  return {
    id: randomUUID(),
    role: 'user',
    content: [{ type: 'text', text }],
    source: { kind: 'user' },
  };
}

function timeoutError(timeoutMs) {
  const duration =
    timeoutMs >= 60_000
      ? `${Math.round(timeoutMs / 60_000)} minutes`
      : `${Math.round(timeoutMs / 1000)} seconds`;
  const error = new Error(`timeout after ${duration}`);
  error.code = 'JOB_TIMEOUT';
  return error;
}

function installSelection(agentCtx, selection) {
  agentCtx.on('system-prompt/assemble', async (_assembly, _context, next) => {
    const selected = selection.current;
    const assembled = await next();
    selection.assembled = selected;
    if (selected === undefined) return assembled;
    return {
      ...assembled,
      variables: {
        ...assembled.variables,
        provider: selected.provider,
        model: selected.model,
      },
    };
  });
  agentCtx.on('agent/request', async (_payload, next) => {
    const resolved = await next();
    const selected = selection.assembled;
    if (selected === undefined) return resolved;
    const { reasoningEffort: _inheritedEffort, ...withoutInheritedEffort } = resolved;
    return {
      ...withoutInheritedEffort,
      provider: selected.provider,
      model: selected.model,
      ...(selected.reasoningEffort === undefined
        ? {}
        : { reasoningEffort: selected.reasoningEffort }),
    };
  });
}

export function apply(ctx, config = {}) {
  const inbox = path.resolve(config.inbox ?? defaultInbox());
  const requestedPoll = Number(config.pollMs);
  const pollMs = Number.isFinite(requestedPoll) ? Math.max(1000, requestedPoll) : POLL_MS;
  const requestedTimeout = Number(config.jobTimeoutMs);
  const jobTimeoutMs = Number.isFinite(requestedTimeout)
    ? Math.max(1000, requestedTimeout)
    : JOB_TIMEOUT_MS;
  const owned = new Map();
  let busy = false;
  let disposed = false;

  async function getAgent(workspace) {
    const agents = ctx.get('agents');
    const defaultModel = ctx.get('agentDefaultModel');
    if (!agents || !defaultModel) throw new Error('DSH agent services are unavailable');
    const sessionId = `phonejob-${createHash('sha256')
      .update(workspace)
      .digest('hex')
      .slice(0, 16)}`;
    const live = agents.get(sessionId);
    if (live) return live;

    const selection = defaultModel.currentSelection();
    const state = { current: selection, assembled: undefined };
    const setup = (agentCtx) => {
      installSelection(agentCtx, state);
    };
    const agentOptions = { provider: selection.provider, model: selection.model };
    try {
      const handle = await agents.resume({ resumeSessionId: sessionId, agentOptions, setup });
      owned.set(sessionId, handle);
      return handle.agent;
    } catch {
      const handle = await agents.create({
        sessionId,
        meta: { cwd: workspace },
        agentOptions,
        setup,
      });
      owned.set(sessionId, handle);
      return handle.agent;
    }
  }

  async function processOne() {
    const next = await nextJob(inbox);
    if (!next) return;
    let job;
    try {
      job = await readJob(next.dir);
    } catch (err) {
      await writeResult(inbox, next.id, {
        status: 'failed',
        text: '',
        error: err instanceof Error ? err.message : 'invalid job',
      });
      return;
    }

    try {
      const workspace = path.resolve(job.target.workspace);
      const stage = await stageFiles(job, next.dir, workspace);
      const agent = await getAgent(workspace);
      let deadlineTimer;
      const deadline = new Promise((_, reject) => {
        deadlineTimer = setTimeout(() => {
          try {
            agent.cancel({ kind: 'hook', reason: 'phonejob-timeout' });
          } catch {
            // Cancellation is best effort; the timeout result is still written below.
          }
          reject(timeoutError(jobTimeoutMs));
        }, jobTimeoutMs);
      });
      try {
        await Promise.race([agent.whenIdle(), deadline]);
        const fromSeq = agent.session.seq;
        agent.followup(userMessage(buildPrompt(job, stage)));
        await Promise.race([agent.whenIdle(), deadline]);
        const sessions = ctx.get('sessions');
        if (sessions?.flush) await sessions.flush(agent.session);
        const outcome = extractOutcome(agent.session.events, fromSeq);
        const files =
          outcome.status === 'done'
            ? await collectResultFiles(path.join(stage, 'out'), path.join(inbox, 'done', next.id))
            : [];
        await writeResult(inbox, next.id, { ...outcome, files });
      } catch (err) {
        if (err?.code === 'JOB_TIMEOUT') {
          let settleTimer;
          await Promise.race([
            agent.whenIdle(),
            new Promise((resolve) => {
              settleTimer = setTimeout(resolve, CANCEL_SETTLE_MS);
            }),
          ]);
          clearTimeout(settleTimer);
        }
        throw err;
      } finally {
        clearTimeout(deadlineTimer);
      }
    } catch (err) {
      await writeResult(inbox, next.id, {
        status: 'failed',
        text: '',
        error: err instanceof Error ? err.message : 'plugin error',
      }).catch(() => {});
    }
  }

  async function tick() {
    if (busy || disposed) return;
    busy = true;
    try {
      await processOne();
    } catch (err) {
      console.error(`phonejob: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      busy = false;
    }
  }

  ctx.effect(() => {
    const timer = setInterval(() => {
      void tick();
    }, pollMs);
    void tick();
    return () => {
      disposed = true;
      clearInterval(timer);
      for (const handle of owned.values()) {
        handle.dispose().catch(() => {});
      }
      owned.clear();
    };
  });

  console.log(`phonejob: watching ${inbox}`);
}
