# PhoneJob

> 手机 → 自己电脑的端到端加密任务通道。**设计稿 + P0 起步；完整通道尚未实现，未经安全审计。**

PhoneJob 让手机在公网把「任务 + 文件」加密发给自己的电脑；电脑端用动态密码子和屏幕挑战码人工确认后，任务才落入本地收件箱；DSH 插件读取执行，结果加密回传。它不是远程桌面，也不是给团队用的任务分发系统。

**它只服务一个人、自己的设备。禁止用于任何形式的变相加班。**

## 状态

- 设计稿：[docs/implementation-plan.md](docs/implementation-plan.md)
- 安全评审：[docs/security-review.md](docs/security-review.md)（6 个 P0；密码子归属已定）
- 实现：P0 起步（电脑端 `K_otp` / DPAPI / TOTP / P-256 配对 / 配对服务 / HTTP 与本地确认页 / PC 配对首页与 QR / SQLite 设备与 job 状态 / PWA 配对、TOTP 与发送任务 / 服务端 job 信封校验与 pending 落盘）；任务确认、文件分片、DSH 插件未开始；当前设计不应直接部署到公网
- 密码子归属：电脑首次安装时生成 `K_otp`，手机只加载 TOTP 公式并计算，不生成密码子

## 开发（P0 起步）

- `bridge/key-store.js`：电脑生成 32B `K_otp`，DPAPI（用户级）保护后写入 `keys.bin`
- `bridge/totp.js`：RFC 4226 / RFC 6238 HOTP/TOTP，支持 ±1 步验证
- `bridge/crypto.js`：P-256 ECDH、HKDF、SAS、AES-GCM 信封、`K_otp` 加密下发
- `bridge/pairing.js`：start → claim（SAS 证明）→ 本地确认 SAS → `K_otp` 下发 → 设备登记/吊销
- `bridge/device-store.js`：SQLite 设备元数据 + 每设备 `kEnc/kConfirm/kAuth` 的 DPAPI blob；内存 store 供测试
- `bridge/job-service.js`：job 信封校验（设备/时间窗/重放/TOTP/AAD/工作区）、风险分级、`pending/<job_id>/job.json` 原子落盘
- `bridge/job-store.js`：SQLite `jobs` + `seen_messages`（seq/nonce 防重放，重启保留）
- `bridge/servers.js`：API 端口放 `health/claim/provision/job`；本地端口放 `start/status/confirm/cancel/devices/jobs`，带 Host/Origin/JSON/admin/pair token 校验；生成 PWA 配对二维码
- `bridge/local/`：PC 配对首页（`/`）与本地确认页（CSP、`X-Frame-Options: DENY`、一次性 pair token）
- `bridge/index.js`：启动入口；首次启动生成/加载 `K_otp`，写 `admin.token`，起 API 7788 + 本地 7789，打开 SQLite
- `bridge/key-init.js`：初始化与轮换 CLI，不打印密码子
- `pwa/crypto.js`：浏览器 P-256/HKDF/SAS/AES-GCM；把电脑下发的 `K_otp` 导入为**不可导出 HMAC 密钥**，只计算 TOTP；`sealEnvelope` 用于提交 job
- `pwa/store.js`：IndexedDB 保存设备元数据、TOTP 密钥，以及不可导出的 `kEnc/kConfirm/kAuth`
- `pwa/app.js` / `pwa/index.html`：配对 → 显示 SAS → TOTP；发送任务表单（工作区从二维码预填、seq 持久化、等待电脑确认）
- `tools/serve-pwa.js`：本地 PWA 开发服务器（PWA 生产托管须独立稳定 origin，并在 bridge 配 `PHONEJOB_PWA_ORIGIN`）
- 测试：`npm test`（Node 24 test runner；`qrcode-generator` 仅用于本地 QR；38 项通过）
- 已验证：Chrome 端到端配对 + TOTP + 发送任务；刷新后从 IndexedDB 继续计算；`K_otp`/`kEnc`/`kConfirm` 均 `extractable:false`；PC 首页 QR + 确认页链接；SQLite 设备/job 持久化；PWA 提交的 job 落 `pending/`、重启后仍在
- 下一步：挑战码/审批、DSH 插件认领/回传、文件分片、Service Worker/Web Push、iOS Safari 实测

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

`PHONEJOB_WORKSPACES` 为空时所有 job 都会被拒绝；`job.files` 非空暂不支持（下一阶段做分片）。job 先落 `pending/` 并停在 `WAITING_CONFIRM`，审批/执行尚未实现。

PWA 生产的静态托管需在响应头设置 CSP（含 `frame-ancestors`，meta 里无效）；bridge 的 `PHONEJOB_PWA_ORIGIN` 必须与 PWA origin 完全一致。

配对流程：打开 `http://127.0.0.1:7789/` → 确认 Bridge URL（本机 `http://127.0.0.1:7788`）→ 生成二维码 → 手机扫描打开 PWA → 在电脑上打开确认页核对 SAS。二维码需要配置 `PHONEJOB_PWA_ORIGIN`；未配置时仍可用 PWA 手动粘贴配对信息。二维码会带上 `PHONEJOB_WORKSPACES`，PWA 发送任务时自动预填工作区。

`bridge/index.js` 首次启动也会加载/生成 `K_otp`；本地管理 token 写到 `%DSH_HOME%\phonejob\admin.token`，不打印到日志。

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
