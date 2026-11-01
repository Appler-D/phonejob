# PhoneJob · 手机 → 电脑任务通道 实现方案

> **状态**：v1.1 设计稿（2026-11-01），尚未实现，未经独立安全评审；不要直接部署到公网。v1.1 起 `K_otp` 由电脑端生成并下发，详见 §7.1；其余评审项见 [security-review.md](security-review.md)。
> **许可**：本仓库采用 PhoneJob Noncommercial License 1.0（见 [LICENSE](../LICENSE)）。
> **路径占位**：文中 `<WORKSPACE>`、`<DSH_INSTALL>`、`<PHONEJOB_HOME>`、`<BACKUP_DIR>` 需替换为本机实际路径。
> **交接对象**：任意具备文件读写与命令执行能力的实现 agent。
> **读完本文即可开工**：目标、边界、密码学参数、协议、目录结构、验收用例都已定死；不确定处给了默认值（标 `DEFAULT`），不要自行发挥。
> **目标环境**：Windows 10/11 + DeepSeek Harness 桌面版（内核 0.2.1-rc.3+，profile `desktop`）。手机端：iOS Safari / Android Chrome（PWA，**不开发原生 App**）。

---

## 0. 一句话定义

手机在公网把「任务 + 文件」端到端加密发给电脑上的常驻桥 `phonejob-bridge`；桥用**动态密码子（TOTP）+ 电脑屏幕上的挑战码**验证，只有电脑端确认正确并由人点击批准，任务才落进本地收件箱；DSH 的 `dsh-phone-job` 插件读取收件箱执行，结果再加密回传手机。

它**不是**远程桌面，**不是**又一个 Web GUI——只传"任务"和"结果"。

---

## 1. 目标 / 非目标

### 1.1 目标
1. 手机在**公网**（4G/5G/任意 Wi-Fi）向家里电脑发任务与文件，不要求公网 IP、不用 VPN。
2. 每条任务都要过**两道闸**：① 密码学校验（动态密码子）；② 人眼确认（电脑屏幕上的挑战码 + 点击批准）。
3. 任务落到电脑上一个**可读的目录/队列**（"对应的程序"），DSH 读它执行，结果回传手机。
4. 隧道/中继服务商**看不到明文**，也无法伪造任务或篡改结果。
5. 全链路可审计、可吊销、可一键拒绝；不写坏 DSH 的会话文件。

### 1.2 非目标
- 不做实时同屏 GUI（那是 `@linxin666/dsh-remote-web-ui` 的活，可并存）。
- 不做多用户/多租户；只服务**一个人、最多 5 台设备**。
- 不做公网暴露 DSH 的 `/api`；任务通道是独立端口、独立认证。
- 不实现文件在线预览/编辑（手机只上传、只下载结果）。
- 不改 DSH 内核、不直接写 `~/.dsh/sessions`。

---

## 2. 术语与银行类比

| 银行网银 | 本方案 | 说明 |
|---|---|---|
| U 盾 / 动态令牌 | 电脑端 `K_otp`（32B） | 首次安装/初始化时由电脑生成，DPAPI 保存；配对时经 E2E 下发给手机；手机只保存为不可导出 HMAC 密钥并计算 TOTP，不生成密码子 |
| 交易要素 | `job.json` 的 intent/text/files 的 SHA-256 | 挑战码绑定这份摘要，改一个字都对不上 |
| 交易挑战码 | 电脑随机 6 位 `challenge` | 显示在电脑屏幕上，只对这一次任务有效 |
| 交易确认码 | 手机计算 `HMAC(K_confirm, challenge)` 前 8 位 Base32 | 用户把手机上的码抄进电脑 |
| 柜员复核 | 电脑端「批准执行」按钮 | 默认每条任务都要点；可按意图白名单自动放行 |
| 双人复核 | 风险分级（见 §7.7） | 高风险任务额外要求再输一次密码子 |

---

## 3. 总体架构

```
┌──────────────┐   HTTPS/WSS (公网, 只承载密文)   ┌─────────────────────────────┐
│  手机 PWA     │ ───────────────────────────────▶ │  Cloudflare Tunnel / 中继    │
│  (浏览器)     │ ◀─────────────────────────────── │  (看不到明文, 不可伪造)       │
└──────────────┘                                   └──────────────┬──────────────┘
                                                                  │ 127.0.0.1:7788
                                                                  ▼
                                                   ┌─────────────────────────────┐
                                                   │ phonejob-bridge (常驻进程)   │
                                                   │  · 解密/验签/验密码子        │
                                                   │  · 挑战码 UI (托盘 + 本地页)  │
                                                   │  · 写收件箱 / 取结果          │
                                                   └──────────────┬──────────────┘
                                                                  │ 文件系统
                                                                  ▼
                                                   ┌─────────────────────────────┐
                                                   │ %DSH_HOME%\phone-inbox\      │
                                                   │   pending/ approved/ done/   │
                                                   └──────────────┬──────────────┘
                                                                  │ 插件轮询
                                                                  ▼
                                                   ┌─────────────────────────────┐
                                                   │ DSH 插件 dsh-phone-job       │
                                                   │  · 读任务 → 起会话执行        │
                                                   │  · phone_job_reply 写结果     │
                                                   └─────────────────────────────┘
```

**关键边界**：隧道只搬运密文；bridge 是唯一能解密的东西；DSH 只看到已批准的任务。

---

## 4. 组件与职责

### 4.1 手机端 PWA（`phonejob-pwa`）
- 技术：原生 ES Module + Service Worker，无框架要求；WebCrypto 做全部密码学。
- 页面：
  1. `#/pair` 配对（扫电脑上的二维码）
  2. `#/jobs` 任务列表（状态灯：待确认/执行中/完成/失败）
  3. `#/new` 新建任务（意图选择、文本、文件、目标程序）
  4. `#/job/:id` 详情（挑战码、确认码输入、结果下载）
  5. `#/devices` 设备与吊销

> P0 已实现「配对 + TOTP」单页；任务列表、新建、详情、设备页在任务通道阶段补齐。

- 存储：IndexedDB；`K_otp` 以**不可导出 HMAC CryptoKey** 保存（`extractable:false`），由电脑端生成、配对时下发；`K_confirm`/`K_enc` 在配对会话内存中使用，任务通道阶段再按需持久化。手机端只加载 TOTP 公式，不生成密码子。
- 推送：Web Push（仅 HTTPS 源可用）；无推送权限时前端 30s 轮询。

### 4.2 隧道 / 中继（不自研服务器）
- **默认 `DEFAULT`**：Cloudflare Tunnel（`cloudflared`），复用 `dsh-pocket` 的做法；给 PC 一个 `https://<随机>.trycloudflare.com`，或固定域名的 named tunnel。
- 备选：自建 VPS 中继（只做 WebSocket 转发 + 离线存储转发）。
- 备选：Tailscale（私网，不暴露公网）。
- **约束**：隧道层不得接触明文密钥；bridge 不信任任何来自隧道的身份声明。

### 4.3 `phonejob-bridge`（新写，Node 24 单进程）
- 监听 `127.0.0.1:7788`（`DEFAULT`），只允许隧道转发进来。
- 职责：配对、会话令牌、解密验签、TOTP 校验、挑战码生成与 UI、任务落盘、结果回传、审计日志、限流锁定。
- 存储：SQLite（`phonejob.sqlite`）存设备元数据与 DPAPI 加密的每设备密钥 blob；`K_otp` 在 `keys.bin`；任务文件落 `phone-inbox/`。
- 生命周期：Windows 计划任务「登录时启动」或 `nssm` 服务；崩溃自动重启。

### 4.4 本地收件箱（"对应的程序"）
```
%DSH_HOME%\phone-inbox\
  pending\<job_id>\job.json
  pending\<job_id>\files\<原名>
  approved\<job_id>\...        ← 只有批准后才移动到这里
  done\<job_id>\result.json
  done\<job_id>\result\*
  rejected\<job_id>\
```
`job.json` 结构见 §6。DSH 插件**只读 `approved/`**。

### 4.5 DSH 插件 `dsh-phone-job`
- 形态：cordis bundle 插件（参考 `dsh-plugin-desktop-notify` 的结构），`cordis.patch.yml` 插入一行。
- 提供工具：
  - `phone_job_list(status)` — 列出任务
  - `phone_job_read(id)` — 读任务正文 + 文件清单（路径、大小、sha256）
  - `phone_job_claim(id)` — 认领，防止重复执行
  - `phone_job_reply(id, text, files?)` — 写结果并标记完成
- 唤醒机制：插件每 5s 轮询 `approved/`；发现未认领任务时，通过 Host 的 session 服务向**专用会话**追加一条 user 消息（内容 = 任务正文 + 文件绝对路径 + 执行约束），由 agent 正常处理。
  - 若宿主不提供追加消息 API，降级为：插件在会话里注册一个"待办"提示 + 由 bridge 调用本地 DSH `/api`（需本地 auth token）。
- 结果：`phone_job_reply` 写 `done/<id>/result.json`，bridge 监听到后加密回传。

### 4.6 结果回传
- 结果 ≤ 200KB 直接 JSON；超过则写文件（≤ 20MB/任务）。
- 手机端：Web Push 通知 → 打开详情页 → 从桥下载（同样 AEAD 加密）。

---

## 5. 状态机

```
CREATED ──上传完成──▶ UPLOADED ──解密/验签/验TOTP通过──▶ WAITING_CONFIRM
   │                                                          │
   │                                          用户输入正确确认码 + 点批准
   │                                                          ▼
   └──超时/失败/拒绝──▶ REJECTED                    APPROVED ──bridge 移入 approved/──▶ QUEUED
                                                                                   │
                                                             插件 claim ◀─────────┘
                                                                   ▼
                                                              RUNNING ──reply──▶ DONE ──回传──▶ DELIVERED
                                                                   └──异常/超时──▶ FAILED
```

- 未在 `WAITING_CONFIRM` 前通过全部校验的任务，**永远不落进 `approved/`**。
- 每个状态转换写审计日志（JSONL，含 job_id、时间、来源指纹、结果）。

---

## 6. 数据模型

### 6.1 `job.json`（bridge 解密后的明文，落盘前脱掉密钥字段）
```json
{
  "version": 1,
  "job_id": "01J9ZK3M8Q7X2V0Q5T6R8S9W0A",
  "device_id": "dev_7f3a…",
  "created_at": "2026-10-31T14:02:11.000Z",
  "target": { "workspace": "<WORKSPACE>", "preset": "default", "session": null },
  "intent": "ask | shell | file | mixed",
  "text": "把这份卷子第 3 题解出来，结果存成 md",
  "files": [
    { "name": "exam.jpg", "size": 1843200, "sha256": "9f2c…", "local_path": "files/exam.jpg" }
  ],
  "risk": "low | high",
  "reply": { "want": "text+file", "max_bytes": 20971520 }
}
```

### 6.2 密文信封（线上唯一格式）
```json
{
  "v": 2,
  "job_id": "01J9…",
  "device_id": "dev_7f3a…",
  "ts": 1761919331,
  "seq": 42,
  "otp": "481920",
  "nonce": "b64url:12B",
  "ct": "b64url:AES-256-GCM 密文(含 tag)"
}
```

> AAD = canonical(header 字段，含 nonce)；不单独传 `aad` 字段，接收方重建后解密。

### 6.3 `result.json`
```json
{
  "job_id": "01J9…",
  "status": "done | failed",
  "finished_at": "2026-10-31T14:09:02.000Z",
  "text": "答案如下……",
  "files": [{ "name": "answer.md", "size": 5120, "sha256": "…" }],
  "error": null
}
```

---

## 7. 安全设计（核心）

### 7.1 配对（一次性，带 SAS 人眼校验）
1. PC 端 bridge 生成临时 P-256 密钥对（v1 默认；X25519 可选），显示二维码：`{bridge_url, pair_id, pc_pub, nonce, expires_at}`（`expires_at` 为绝对时间，SAS transcript 需要）。
2. 手机扫码 → 生成自己的 P-256 密钥对 → 双方 ECDH → `K_pair = HKDF(P-256_shared, salt=pair_id, info="phonejob/v1/pair")`。
3. PC 与手机**各自显示 6 位 SAS 码**（由 `K_pair` 与配对 transcript 派生），用户核对两侧一致后，在 PC 点「确认配对」。
4. 派生并存储：
   - `K_confirm = HKDF(K_pair, salt=pair_id, info="phonejob/v1/confirm")`
   - `K_enc  = HKDF(K_pair, salt=pair_id, info="phonejob/v1/enc")`
   - `K_otp` **不从 `K_pair` 派生**：电脑端在首次安装/初始化时生成 32B 随机密码子并 DPAPI 保存；
     配对确认后由电脑用 `K_enc` 加密下发给手机（AAD 绑定 `pair_id/device_id`），
     手机导入为不可导出 HMAC `CryptoKey`。
5. 设备记录落 SQLite（device_id、公钥、创建时间、最后活跃、吊销位、密码子版本）。

> 安全要点：SAS 校验挡住隧道层 MITM；配对码 120s 过期，一次性。
>
> 密码子生命周期：电脑生成 → DPAPI 保存 → 配对确认后下发 → 手机只计算不生成；
> 吊销任一设备时电脑轮换 `K_otp` 并重新下发给剩余设备，未在线的设备需重新配对。
> 电脑端是密码子的唯一生成者，手机端不上传、不生成密码子。

### 7.2 每条消息的校验链（顺序不可调换）
1. **解密**：AES-256-GCM(`K_enc`, nonce, AAD=header) → 失败即丢弃，不落盘。
2. **时间窗**：`|now - ts| ≤ 120s`。
3. **防重放**：`(device_id, seq)` 单调递增 + `(device_id, nonce)` 最近 10k 条缓存；重复即拒。
4. **动态密码子**：`TOTP = HOTP(K_otp, floor(now/30))` 取 6 位，按服务端当前时间允许 ±1 步；`ts` 只用于时间窗。不等即拒（计一次失败）。`K_otp` 由电脑生成并保存，手机只执行公式。
5. **风险判定**：`intent ∈ {shell, file, mixed}` 或路径越界 → `risk=high`。

以上全过才进入 `WAITING_CONFIRM`。

### 7.3 挑战码机制（"只有电脑确认正确才执行"）
1. bridge 计算 `challenge = 6 位随机数`（`crypto.randomInt(100000,1000000)`），与 `job_hash = SHA256(canonical(job.json))` 一起存入待确认表。
2. **电脑屏幕**弹出确认窗（托盘 + 本地 `127.0.0.1:7789/confirm` 页面），显示：任务摘要、文件列表与短哈希、挑战码、输入框。
3. 手机详情页同时显示同一个挑战码（经加密通道下发）→ 用户在手机上打开自己的 App，得到 `response = Base32(HMAC-SHA256(K_confirm, "confirm-v1" || job_hash || challenge))[0:8]`。
4. 用户把 8 位 `response` 抄进电脑确认窗 → bridge 校验 → 通过后显示「批准执行」按钮。
5. 点击批准 → bridge 把 job 移入 `approved/`，状态 `QUEUED`。

> 这一步的价值：即使手机被远程控制、或隧道被完全攻破，攻击者也必须**让电脑前的人看到并输入一个只有手里设备才能算出的码**。

### 7.4 密码学参数（固定，不得自行更改）
| 用途 | 算法 |
|---|---|
| 密钥协商 | P-256 ECDH（v1 默认，WebCrypto 全平台支持；X25519 可选，Chrome 133+/Firefox 130+，Safari 需实测） |
| KDF | HKDF-SHA256，salt = pair_id，info 按用途域分离，32B 输出 |
| 对称加密 | AES-256-GCM，12B 随机 nonce，AAD = 规范化 header JSON |
| 消息认证 | GCM tag（128bit）+ 外层 TOTP |
| 动态密码子 | HOTP/TOTP RFC 6238，SHA-1，6 位，30s，±1 步；`K_otp` 32B 由电脑首次安装生成，DPAPI 保存，配对时经 `K_enc` 下发，手机只计算 |
| 挑战响应 | HMAC-SHA256(K_confirm, "confirm-v1" \|\| job_hash \|\| challenge) → Base32 前 8 位 |
| 文件完整性 | SHA-256，落盘后复核 |
| 电脑端密钥存储 | Windows DPAPI（`CryptProtectData`，用户级）：`K_otp` 在 `keys.bin`；每设备 `kEnc/kConfirm/kAuth` 以 DPAPI blob 存 SQLite |

### 7.5 限流与锁定
- 每设备：10 任务/小时，20 文件/任务，单文件 ≤ 50MB，任务总大小 ≤ 200MB。
- 密码子/挑战码错误：同设备错 3 次锁 5 分钟，错 10 次锁 1 小时并在电脑端弹「可疑活动」。
- 未配对来源：直接 404（不返回任何区分信息）。
- 所有失败写审计日志，含来源 IP（仅桥本地可见）与时间。

### 7.6 任务内容的安全
- 文件一律视为**不可信**：DSH 侧只用工具读取，不执行；扩展名白名单（jpg/png/pdf/docx/xlsx/pptx/txt/md/zip），PE/JS/脚本类直接拒绝。
- `text` 里禁止出现"忽略以上指令"类模板（不是硬性拦截，但在 PC 确认窗高亮提示）。
- 结果回传前扫描：不含 `K_*`、不含 `sk-`/`ghp_` 等密钥模式，否则阻止并提示。
- 目标限制：`target.workspace` 必须是配置里的白名单；`intent=shell` 只能落到一个受限 preset。

### 7.7 风险分级
| 风险 | 触发条件 | 额外要求 |
|---|---|---|
| low | ask/text、文件只读 | 挑战码 + 一次点击 |
| high | shell、写文件、>10MB、未知路径 | 挑战码 + 再输一次动态密码子 + 点击 |

### 7.8 威胁模型
| 威胁 | 对策 |
|---|---|
| 隧道/中继被攻破 | E2E 加密 + PWA 独立 origin/SRI；隧道只提供 API，不能替换客户端代码 |
| 手机丢失 | 设备吊销（PC 端一键）+ 轮换 `K_otp` + 挑战码仍需人确认 |
| 重放旧任务 | seq 单调 + nonce 缓存 + 时间窗 |
| 伪造任务 | 无 K_otp 算不出 TOTP；无 K_enc 解不开 |
| 中间人替换文件 | 文件 SHA-256 在 job.json 内，落盘后复核 |
| 恶意文件诱导执行 | 扩展名白名单 + intent 工具限制 + 沙箱 + 高风险二次确认 |
| 任务文本/文件提示注入 | 声明为不可信数据 + 按 intent 限制工具 + 高风险人工批准 |
| 电脑被远控 | 挑战码挡不住远控；只能依赖电脑前的人/Windows Hello，威胁模型不防已失陷的 PC |
| DoS | 限流 + 队列上限 + 单任务 TTL 24h |

---

## 8. 协议契约

### 8.1 HTTP（经隧道，全部 HTTPS）
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | 返回 `{ok, version, paired_devices}`（不含敏感信息） |
| POST | `/api/session` | 用 `K_auth` + 服务端 nonce 换 15 分钟 Bearer token（仅查询） |
| POST | `/api/pair/claim` | 手机提交公钥 + SAS 证明 |
| POST | `/api/pair/provision` | 配对确认后，电脑用 `K_enc` 下发电脑生成的 `K_otp` |
| POST | `/api/job` | 提交密文信封（≤ 1MB 元数据；文件走分片） |
| PUT | `/api/job/:id/file/:idx` | 分片上传密文块（`Content-Range`） |
| GET | `/api/job/:id` | 查询状态（需设备会话令牌） |
| GET | `/api/job/:id/result` | 取加密结果 |
| DELETE | `/api/device/:id` | 吊销设备（仅本地发起） |

> PWA 独立 origin 时，API 只允许配置的 `PHONEJOB_PWA_ORIGIN` 的 CORS；本地 7789 不设 CORS。
>
> 本地 7789 另有 `GET /api/jobs`（admin），用于后续确认 UI；P1 只落 `pending/` + `WAITING_CONFIRM`，文件分片未实现。

### 8.2 设备会话令牌
- 每次连接先 `POST /api/session`：服务端发一次性 nonce，手机用
  `K_auth = HKDF(K_pair, salt=pair_id, info="phonejob/v1/auth")` 计算
  `HMAC(K_auth, "session-v1" || device_id || nonce || ts)`，换 15 分钟 Bearer token。
- Bearer token 只用于查询，**不能**提交新任务（提交必须带完整信封）。

### 8.3 分片上传
- 每片 ≤ 1MB，独立 AES-GCM 加密，`job_id + idx + total` 作 AAD。
- 全部收齐后 bridge 解密合并 → 复核 sha256 → 才置 `UPLOADED`。

---

## 9. PC 端确认界面

- **托盘图标**（bridge 进程）：有待确认任务时闪烁 + Windows 通知。
- **确认窗**（`127.0.0.1:7789/confirm/<id>`，本地浏览器/WebView 打开）：
  - 顶部：设备名、时间、风险等级（high 红色）
  - 中部：任务文本（前 500 字）、文件列表（名/大小/短哈希）、意图
  - 关键区：**挑战码大号显示** + 8 位确认码输入框（错误时抖动）
  - 底部：`拒绝` / `批准一次` / `批准并加入白名单（仅 low 风险）`
- 关闭窗口 = 拒绝（默认拒绝）。
- 60 秒无操作自动拒绝（`DEFAULT`）。

---

## 10. DSH 侧执行（插件行为）

1. 轮询 `approved/`，取最早未认领任务，`claim` 原子重命名到 `working/`。
2. 在专用会话（`session title = "手机任务"`）追加 user 消息：
   ```
   [PHONEJOB <id>] 来自手机的任务。
   目标：<target.workspace> / preset=<preset>
   要求：<text>
   文件：<绝对路径列表>（只读，勿执行）
   约束：不得修改 ~/.dsh/sessions；完成后必须调用 phone_job_reply。
   ```
3. agent 执行完调用 `phone_job_reply(id, text, files)`。
4. 插件写 `done/<id>/`，bridge 加密回传。
5. 超时（`DEFAULT` 30 分钟）→ `FAILED`，回传错误摘要。

---

## 11. 可靠性与离线

- 手机端任务本地队列：网络失败自动重试（指数退避，最长 10 分钟）。
- bridge 离线：隧道断开时手机收到 503，任务保留在手机队列，PC 上线后补投。
- 幂等：同一 `job_id` 重复提交只接受第一次，后续返回当前状态。
- 任务 TTL 24h：超时未执行自动 `REJECTED` 并通知手机。
- 结果丢失：手机端可按 job_id 重新拉取（结果保留 7 天）。

---

## 12. 部署与运维

```powershell
# 1) 首次初始化：电脑生成本用户专属密码子，DPAPI 保存到 keys.bin
node <PHONEJOB_HOME>\bridge\key-init.js

# 2) 安装 bridge（录成 Windows 计划任务：登录时启动）
node <PHONEJOB_HOME>\bridge\index.js

# 3) 起隧道（必须固定 hostname；quick tunnel 仅实验，不能用于密钥/推送）
cloudflared tunnel run phonejob

# 4) 扫码配对（bridge 托盘 → 显示二维码）

# 4) 安装 DSH 插件
& '<DSH_INSTALL>\resources\runtime\cli\bin\dsh.cmd' plugin --profile desktop add link:<PHONEJOB_HOME>\plugin

# 5) PWA：独立稳定 origin 托管 pwa/（GitHub Pages / Cloudflare Pages 等）
#    并在 bridge 环境设置 PHONEJOB_PWA_ORIGIN=<该 origin>

# 6) 打开电脑配对首页：http://127.0.0.1:7789/
```

- 防火墙：只需允许 `cloudflared` 出站；**不开放任何入站端口**。
- 备份：`phonejob.sqlite` + `keys.bin` 每日备份到 `<BACKUP_DIR>`。
- 吊销：托盘「解除全部设备」→ 清空设备表 + 轮换 `K_pair` 与 `K_otp`（需重新配对/下发）。
- 日志：`%DSH_HOME%\phonejob\audit.jsonl`，保留 90 天。

---

## 13. 实施计划（分期，每期可独立验收）

| 阶段 | 内容 | 验收 |
|---|---|---|
| P0 骨架 | bridge 起服务、健康检查、隧道连通、二维码配对（SAS）、电脑生成 `K_otp` | 手机能配对成功；错 SAS 被拒；手机不生成密码子 |
| P1 任务通道 | 信封加密、TOTP、防重放、文件分片上传、收件箱落盘 | 篡改/重放/错误密码子全部被拒 |
| P2 人工确认 | 托盘 + 确认窗 + 挑战码/确认码 | 未输入正确确认码无法进入 `approved/` |
| P3 DSH 执行 | 插件认领、会话唤醒、`phone_job_reply`、结果回传 | 一条完整"发题→解→回传"闭环 |
| P4 打磨 | Push、白名单、风险分级、审计面板、吊销 | 断网重连、吊销、锁定全部通过 |

---

## 14. 测试用例（必须全部通过）

1. 未配对设备提交 → 404，无落盘。
2. 篡改密文 1 字节 → GCM 校验失败，无落盘。
3. 重放同一信封 → 拒绝，审计记录一条。
4. TOTP 错 1 位 → 拒绝；连错 3 次 → 锁 5 分钟。
5. 挑战码窗显示后 60 秒不操作 → 自动拒绝。
6. 确认码错 → 拒绝，任务留在 `WAITING_CONFIRM`。
7. 正确确认码 + 批准 → 进入 `approved/`，插件 5s 内认领。
8. 文件 sha256 不一致 → 拒绝。
9. 扩展名 `.exe` → 拒绝。
10. 同一 job_id 重复提交 → 返回同一状态，不重复执行。
11. PC 断网 5 分钟 → 任务在手机队列，恢复后补投成功。
12. 结果含 `sk-` 模式 → 阻止回传并告警。
13. 吊销设备后 → 该设备所有请求 401。
14. 并发 5 任务 → 顺序执行，不串结果。

---

## 15. 交付物清单

```
<PHONEJOB_HOME>\
  bridge\
    index.js            # Node 24，无框架，node:crypto + node:sqlite
    crypto.js           # HKDF/AES-GCM/TOTP/SAS
    confirm-ui\         # 本地确认页（纯 HTML）
    config.json         # 端口、白名单、限流、TTL
  pwa\
    index.html app.js sw.js manifest.webmanifest
  plugin\               # DSH 插件
    cordis.patch.yml index.js lib\
  docs\
    本文件
  tests\
    crypto.test.js e2e.test.js attack.test.js
```

---

## 16. 给实现 agent 的硬约束

1. **不允许**自研加密原语；只用 Node `crypto` 与浏览器 WebCrypto 的标准实现。
2. **不允许**把 `K_*` 写进日志、返回值、错误信息。
3. **不允许**绕开确认窗直接落 `approved/`（即使配置为自动放行，也必须写审计记录）。
4. **不允许**修改 `~/.dsh/sessions`、不直接写会话文件；只通过插件 API。
5. 所有路径必须做 `realpath` + 前缀白名单校验，防目录穿越。
6. 先写 `tests/attack.test.js`（上面 14 条攻击用例），再写实现。
7. 任一验收用例失败 → 视为未完成，不得交付。

---

## 17. 开放问题（默认值已给，可后续调整）

| 问题 | 默认 |
|---|---|
| 隧道选型 | 固定 hostname（named tunnel / Tailscale Funnel / 自建）；quick tunnel 仅实验，不能用于密钥/推送 |
| PWA 托管 | 独立稳定 origin（GitHub Pages / Cloudflare Pages）；bridge 配 `PHONEJOB_PWA_ORIGIN` |
| 密码子归属 | 电脑首次安装/初始化生成 32B `K_otp`，DPAPI 保存；配对时下发；手机不生成 |
| 手机 UI 框架 | 原生 JS（无构建链） |
| 会话归属 | 单独会话「手机任务」，不污染现有会话 |
| 自动放行 | 关闭；仅 `intent=ask` 且 `risk=low` 可开启白名单 |
| 结果大小 | 20MB/任务 |
| 多设备 | 最多 5 台，各自独立 `K_pair`；`K_otp` 为用户级，吊销任一设备时轮换并重新下发剩余设备 |
| 设备持久化 | SQLite 元数据 + 每设备密钥的 DPAPI blob；`K_otp` 在 `keys.bin` |
| 文件通道 | P1 暂不支持；`job.files` 非空拒绝，下一阶段做分片 |
| 工作区白名单 | `PHONEJOB_WORKSPACES` 必填；为空时 job 全部拒绝 |
| 任务确认 | 当前落 `pending/` + `WAITING_CONFIRM`；挑战码/审批/DSH 执行下一步 |
| 曲线 | v1 以 P-256 为主；X25519 可选，按目标设备实测 |

---

*版本 v1.3 · 2026-11-01 · `K_otp` 电脑生成；设备/job SQLite 持久化；PC 配对首页/QR；服务端 job 信封校验与 pending 落盘；其余评审项待定*
