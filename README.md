# PhoneJob

> 手机 → 自己电脑的端到端加密任务通道。**设计稿 + P0 起步；完整通道尚未实现，未经安全审计。**

PhoneJob 让手机在公网把「任务 + 文件」加密发给自己的电脑；电脑端用动态密码子和屏幕挑战码人工确认后，任务才落入本地收件箱；DSH 插件读取执行，结果加密回传。它不是远程桌面，也不是给团队用的任务分发系统。

**它只服务一个人、自己的设备。禁止用于任何形式的变相加班。**

## 状态

- 设计稿：[docs/implementation-plan.md](docs/implementation-plan.md)
- 安全评审：[docs/security-review.md](docs/security-review.md)（6 个 P0；密码子归属已定）
- 实现：P0 起步（电脑端 `K_otp` / DPAPI / TOTP / P-256 配对密码学 / 配对服务）；bridge HTTP、PWA、DSH 插件未开始；当前设计不应直接部署到公网
- 密码子归属：电脑首次安装时生成 `K_otp`，手机只加载 TOTP 公式并计算，不生成密码子

## 开发（P0 起步）

- `bridge/key-store.js`：电脑生成 32B `K_otp`，DPAPI（用户级）保护后写入 `keys.bin`
- `bridge/totp.js`：RFC 4226 / RFC 6238 HOTP/TOTP，支持 ±1 步验证
- `bridge/crypto.js`：P-256 ECDH、HKDF、SAS、AES-GCM 信封、`K_otp` 加密下发
- `bridge/pairing.js`：start → claim（SAS 证明）→ 本地确认 SAS → `K_otp` 下发 → 设备登记/吊销（内存态）
- `bridge/key-init.js`：初始化与轮换 CLI，不打印密码子
- 测试：`npm test`（Node 24 test runner，无第三方依赖；19 项通过）
- 下一步：bridge HTTP 层 + 本地确认页（CSRF）+ PWA 端 TOTP 公式

```bash
npm test
node bridge/key-init.js            # 首次初始化；默认 %DSH_HOME%\phonejob\keys.bin
node bridge/key-init.js --rotate   # 轮换；旧码失效，需重新下发设备
```

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
