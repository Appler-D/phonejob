# PhoneJob

> 手机 → 自己电脑的端到端加密任务通道。**设计稿 + P0 起步；完整通道尚未实现，未经安全审计。**

PhoneJob 让手机在公网把「任务 + 文件」加密发给自己的电脑；电脑端用动态密码子和屏幕挑战码人工确认后，任务才落入本地收件箱；DSH 插件读取执行，结果加密回传。它不是远程桌面，也不是给团队用的任务分发系统。

**它只服务一个人、自己的设备。禁止用于任何形式的变相加班。**

## 状态

- 设计稿：[docs/implementation-plan.md](docs/implementation-plan.md)
- 安全评审：[docs/security-review.md](docs/security-review.md)（6 个 P0；密码子归属已定）
- 实现：P0 起步（电脑端 `K_otp` / DPAPI / TOTP / P-256 配对 / 配对服务 / HTTP 与本地确认页 / PC 配对首页与 QR / SQLite 设备与 job 状态 / PWA 配对、TOTP、发送任务与附件、挑战响应与结果展示、结果文件下载 / 服务端 job 校验、分片上传、pending 落盘、挑战码与电脑审批、结果加密回传、结果文件校验与加密下载、确认/上传/执行超时 / DSH 插件认领、会话唤醒、结果与文件回写，隔离 DSH 已验，桌面真实模型回复待验证）；当前设计不应直接部署到公网
- 密码子归属：电脑首次安装时生成 `K_otp`，手机只加载 TOTP 公式并计算，不生成密码子

## 开发（P0 起步）

- `bridge/key-store.js`：电脑生成 32B `K_otp`，DPAPI（用户级）保护后写入 `keys.bin`
- `bridge/totp.js`：RFC 4226 / RFC 6238 HOTP/TOTP，支持 ±1 步验证
- `bridge/crypto.js`：P-256 ECDH、HKDF、SAS、AES-GCM 信封、`K_otp` 加密下发
- `bridge/pairing.js`：start → claim（SAS 证明）→ 本地确认 SAS → `K_otp` 下发 → 设备登记/吊销；配对开始、认领、拒绝、确认、下发与吊销写审计
- `bridge/device-store.js`：SQLite 设备元数据 + 每设备 `kEnc/kConfirm/kAuth` 的 DPAPI blob；内存 store 供测试
- `bridge/job-service.js`：job 信封校验（设备/时间窗/重放/TOTP/AAD/工作区）、风险分级、每设备每小时任务上限、OTP 失败锁定、`pending/<job_id>/job.json` 原子落盘、分片上传与文件 SHA-256/大小复核、zip 内部条目扫描、挑战码/`job_hash`、手机签名状态查询、审批/拒绝并移动目录、扫描 `done/` 结果与结果文件并按设备加密、确认/上传/执行超时
- `bridge/zip-scan.js`：`zip` 内部路径、类型、加密、嵌套深度、条目数与解压大小检查；结果文件同样扫描
- `bridge/confirm.js`：HMAC-SHA256 + Base32 的 8 位确认码（绑定 `job_hash` 与挑战码）
- `bridge/result.js`：结果与结果文件元数据校验、大小/类型限制、密钥/私钥模式扫描；`K_otp` 泄露阻断
- `bridge/crypto.js`：新增文件分片 AES-GCM 的 `sealFileChunk` / `openFileChunk`
- `bridge/job-store.js`：SQLite `jobs` + `seen_messages`（seq/nonce 防重放，重启保留；challenge/job_hash/decided_at）
- `bridge/audit.js`：配对/任务事件写 `audit.jsonl`；字段白名单（job/pairing/device/state/risk/intent/文件数/字节/错误），不记录正文、路径、挑战码、job_hash、SAS、公钥或密钥；按 5MB 轮转、保留 4 份备份、启动时清理 90 天前条目
- `bridge/servers.js`：API 端口放 `health/claim/provision/job`、带设备签名的 `GET /api/job/:id|result|result/file/:idx` 与 `PUT /api/job/:id/file/:idx`；本地端口放 `start/status/confirm/cancel/devices/jobs` 与 approve/reject，带 Host/Origin/JSON/admin/pair token 校验；生成 PWA 配对二维码
- `bridge/local/`：PC 配对首页（`/`）、待确认任务页（`/jobs`）与配对确认页（CSP、`X-Frame-Options: DENY`、一次性 pair token）
- `bridge/index.js`：启动入口；首次启动生成/加载 `K_otp`，写 `admin.token`，起 API 7788 + 本地 7789，打开 SQLite，每秒扫描 `done/` 结果并每 30 秒处理超时，任务状态写入 `audit.jsonl`
- `bridge/key-init.js`：初始化与轮换 CLI，不打印密码子
- `pwa/crypto.js`：浏览器 P-256/HKDF/SAS/AES-GCM；把电脑下发的 `K_otp` 导入为**不可导出 HMAC 密钥**，只计算 TOTP；`sealEnvelope` 用于提交 job
- `pwa/store.js`：IndexedDB 保存设备元数据、TOTP 密钥，以及不可导出的 `kEnc/kConfirm/kAuth`
- `pwa/app.js` / `pwa/index.html`：配对 → 显示 SAS → TOTP；发送任务表单（工作区从二维码预填、seq 持久化、可选附件分片上传）；轮询状态、显示挑战码/响应码；结果返回后解密显示并下载结果文件
- `plugin/index.js`：DSH Cordis 插件；轮询 `approved/`、原子认领到 `working/`、把附件复制到 `<workspace>/.phonejob/<id>/`、唤醒按 workspace 复用的专用会话；agent 的最终回复自动写成 `done/<id>/result.json`，输出目录 `out/` 中的文件复制到 `done/<id>/files/`；超过 30 分钟取消当前轮并回写超时失败；隔离 DSH 已实机验证认领/会话/失败结果回写
- `plugin/cordis.patch.yml`：bundle patch，安装时自动插入 `phone-job` 行（`pollMs` / `jobTimeoutMs`）
- `tools/serve-pwa.js`：本地 PWA 开发服务器（PWA 生产托管须独立稳定 origin，并在 bridge 配 `PHONEJOB_PWA_ORIGIN`）
- 测试：`npm test`（Node 24 test runner；`qrcode-generator` 仅用于本地 QR；80 项通过）
- 已验证：Chrome 端到端配对 + TOTP + 附件分片上传 + 发送任务 + 挑战码/响应 + 电脑审批 + 结果回传；600KB 文件按 2 片上传并审批进 `approved/`；隔离 DSH（临时 `DSH_HOME` + 空凭据）里插件真实加载、认领 `job_dsh_test`、创建会话、等待 agent，并在无 API key 时写出 `failed` 结果；插件纯函数（认领、附件复制、提示词、结果解析/回写/输出文件收集）已测；确认/上传/执行超时、结果文件哈希/密钥扫描与加密下载、zip 条目扫描、任务与配对审计字段白名单、轮转/90 天清理、任务限流、OTP/挑战码锁定及其 SQLite 持久化已用单元/HTTP 测试覆盖
- 桌面版真实模型回复仍待验证：npx CLI `0.1.0-rc.6` 读取桌面版 `0.2.0-rc.2` 的 `.credentials.yaml` 时格式不兼容（在插件之前中止），所以没有用 npx CLI 启动同一个 `DSH_HOME`；没有修改你的凭据文件
- 下一步：在桌面版安装插件并跑一条真实模型任务；Service Worker/Web Push、iOS Safari 实测

```bash
npm install
npm test
node bridge/key-init.js            # 首次初始化；默认 %DSH_HOME%\phonejob\keys.bin
node bridge/key-init.js --rotate   # 轮换；旧码失效，需重新下发设备
node bridge/index.js               # 启动 bridge；API 127.0.0.1:7788，本地 127.0.0.1:7789
npm run pwa:dev                    # PWA 开发服务器 http://127.0.0.1:8000
```

本地联调时让 bridge 允许 PWA origin，并配置允许的 job 工作区：

```bash
PHONEJOB_PWA_ORIGIN=http://127.0.0.1:8000 \
PHONEJOB_WORKSPACES="C:/Temp/phonejob-ws" \
node bridge/index.js
```

`PHONEJOB_WORKSPACES` 为空时所有 job 都会被拒绝。附件限制：最多 20 个、单文件 ≤50MB、任务总计 ≤200MB、512KB 分片；类型白名单 jpg/jpeg/png/pdf/docx/xlsx/pptx/txt/md/zip。zip 会检查内部路径、类型、加密、嵌套深度与声明解压大小。结果文件限制：最多 10 个、单文件 ≤10MB、总计 ≤20MB；类型白名单在附件基础上增加 csv/json，zip 同样扫描。审批已实现（`pending/` → `approved/`）；DSH 执行已实现，未获批的任务不会进入 `approved/`。

超时默认值：上传 30 分钟、确认 10 分钟（超时移入 `expired/` 并标记 `EXPIRED`）、执行 35 分钟（bridge 兜底标记 `FAILED`；插件自身 30 分钟取消当前轮）。可用 `PHONEJOB_UPLOAD_TTL_MS` / `PHONEJOB_CONFIRM_TTL_MS` / `PHONEJOB_EXECUTION_TTL_MS` 覆盖 bridge 默认值。

限流：每设备每小时最多 10 个任务（`PHONEJOB_MAX_JOBS_PER_HOUR`）；OTP 或挑战码连续失败 3 次锁 5 分钟、10 次锁 1 小时。锁定状态存 SQLite，bridge 重启后仍保留。

PWA 生产的静态托管需在响应头设置 CSP（含 `frame-ancestors`，meta 里无效）；bridge 的 `PHONEJOB_PWA_ORIGIN` 必须与 PWA origin 完全一致。

配对流程：打开 `http://127.0.0.1:7789/` → 确认 Bridge URL（本机 `http://127.0.0.1:7788`）→ 生成二维码 → 手机扫描打开 PWA → 在电脑上打开确认页核对 SAS。二维码需要配置 `PHONEJOB_PWA_ORIGIN`；未配置时仍可用 PWA 手动粘贴配对信息。二维码会带上 `PHONEJOB_WORKSPACES`，PWA 发送任务时自动预填工作区。

审批流程：PWA 发送任务后显示电脑挑战码与手机响应码；打开电脑 `http://127.0.0.1:7789/jobs`，选择任务，核对挑战码，输入手机响应码并批准。确认码绑定 `job_hash`，错误响应不会移动 `pending/`。

结果回传：DSH 插件把 `done/<job_id>/result.json` 写入收件箱，并把 `<workspace>/.phonejob/<job_id>/out/` 下的产物复制到 `done/<job_id>/files/`；bridge 每秒扫描，校验文本、文件元数据、SHA-256 和密钥模式后加密；PWA 通过签名接口拉取文本，结果文件按索引单独加密下载并在手机上复核 SHA-256。结果文件不执行、不预览，下载后请在本地自行判断。

## DSH 插件

插件是自带 bundle patch 的本地包；用 DSH 自带的 CLI 安装，然后重启桌面应用：

```powershell
dsh plugin --profile desktop add link:D:\phonejob\plugin
```

插件默认监听 `%DSH_HOME%\phone-inbox`，与 bridge 默认一致。审批后的任务会被认领，附件复制到 `<workspace>\.phonejob\<job_id>\`，插件按 workspace 复用专用会话；agent 的最终回复自动回写结果。桌面版首次运行会在 DSH 里出现对应会话，工具调用可能仍需你在 DSH 中确认。

> 已在隔离 `DSH_HOME` 里用空凭据验证插件加载与执行路径（模型请求按预期因无 key 失败并回写 `failed`）。本机 npx CLI 是 `0.1.0-rc.6`、桌面版是 `0.2.0-rc.2`，两者凭据文件格式不一致；桌面真实模型验证请用桌面版自带的 CLI/应用，不要用 npx CLI 启动同一个 `DSH_HOME`。

`bridge/index.js` 首次启动也会加载/生成 `K_otp`；本地管理 token 写到 `%DSH_HOME%\phonejob\admin.token`，不打印到日志。配对与任务审计写到 `%DSH_HOME%\phonejob\audit.jsonl`，不包含任务正文、工作区路径、挑战码、SAS 或密钥；按 5MB 轮转，保留 4 份备份，启动时清理 90 天前条目。

## 许可：源码可见，但禁止商业使用与劳动剥削

本仓库**不是 OSI 开源项目**。它采用 [PhoneJob Noncommercial License 1.0](LICENSE)：以 PolyForm Noncommercial 1.0.0 为基础，并附加以下条件：

- 禁止任何商业用途；商业使用需另行取得书面许可。
- **禁止**任何组织（包括公司、团队、学校、政府、公益机构）使用本软件：
  - 在员工、外包或学生约定工作时间之外派发、安排、监控、记录、考核或催办任务；
  - 要求或暗示任何人在休息、休假、下班时间保持在线、响应或待命；
  - 掩盖工时、规避加班费/调休/休息休假，或其他规避劳动法的行为。
- 违反上述条件即终止许可；对劳动用途不适用 32 天整改期。

一句话：**这是给自己用的工具，不是给老板用来变相加班的工具。**

基础许可文本：[PolyForm Noncommercial 1.0.0](https://github.com/polyformproject/polyform-licenses/blob/1.0.0/PolyForm-Noncommercial-1.0.0.md)

[可接受使用摘要](ACCEPTABLE-USE.md) · [完整许可](LICENSE)

## 安全说明

- 未经过独立安全审计；请自行评估风险，不要直接暴露到公网。
- 隧道只应转发到本机回环地址；桥不信任隧道传来的任何身份声明。
- 许可证只约束对本软件的使用，不能替代劳动法，也不能约束雇佣关系。

## 计划结构

```text
bridge/   常驻桥：配对、解密、TOTP、挑战码、收件箱
pwa/      手机端 PWA
plugin/   DSH 插件
tests/    密码学、端到端与攻击用例
docs/     设计文档
```

## 贡献

提交贡献前请先开 issue 确认许可安排，详见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题请走 [SECURITY.md](SECURITY.md)。

## 版权

Copyright (c) 2026 Appler-D.

Required Notice: Copyright 2026 Appler-D (https://github.com/Appler-D/phonejob)

---

## English summary

PhoneJob is a personal, end-to-end encrypted phone-to-PC task channel. This repository is **source-available, not OSI open source**. The license prohibits commercial use and any organizational use to assign, monitor, evaluate, or enforce work outside agreed working hours, including by noncommercial organizations. See [LICENSE](LICENSE). The design is not implemented or security-audited.
