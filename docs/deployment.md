# 部署检查表

> 当前版本未经独立安全审计。先在小范围、自己的设备上验证，不要直接暴露到公网。

## 1. PWA 静态托管

- 使用独立、稳定的 HTTPS origin（GitHub Pages、Cloudflare Pages 等）。
- 子路径托管时同时设置 origin 与完整 URL，例如 GitHub Pages 项目站点：

```bash
PHONEJOB_PWA_ORIGIN=https://<user>.github.io
PHONEJOB_PWA_URL=https://<user>.github.io/phonejob/
```

- 静态服务器需返回 PWA 的 CSP、`sw.js` 的 `application/javascript`，并允许 Service Worker 在该路径下注册。
- GitHub Pages：把 `pwa/` 发布到 `gh-pages` 或 Pages 工作流；首次使用需在仓库 Settings → Pages 启用。

## 2. 隧道

- 只暴露 API 端口（默认 7788），本地端口（默认 7789）绝不能暴露。
- 推荐 Cloudflare named tunnel 或 Tailscale；quick tunnel 仅实验，不用于长期密钥/推送。
- 隧道层不得注入身份声明；bridge 只信设备签名、TOTP 与挑战码。

## 3. bridge 环境

```bash
PHONEJOB_WORKSPACES="D:/work" \
PHONEJOB_PWA_ORIGIN="https://<user>.github.io" \
PHONEJOB_PWA_URL="https://<user>.github.io/phonejob/" \
PHONEJOB_VAPID_SUBJECT="mailto:you@example.com" \
node bridge/index.js
```

可选：`PHONEJOB_API_PORT`、`PHONEJOB_LOCAL_PORT`、`PHONEJOB_CONFIRM_TTL_MS`、`PHONEJOB_UPLOAD_TTL_MS`、`PHONEJOB_EXECUTION_TTL_MS`、`PHONEJOB_RESULT_TTL_MS`、`PHONEJOB_MAX_JOBS_PER_HOUR`、`PHONEJOB_MAX_ACTIVE_JOBS`、`PHONEJOB_MAX_INBOX_BYTES`。

Windows 登录自启动：

```powershell
powershell -ExecutionPolicy Bypass -File tools/install-autostart.ps1 `
  -Workspace "D:\work" -PwaOrigin "https://<user>.github.io" -PwaUrl "https://<user>.github.io/phonejob/"
```

## 4. 首次配对与基本验证

1. 打开本地 `http://127.0.0.1:7789/`，确认 bridge URL 指向公网 API 地址。
2. 手机扫码/粘贴配对信息，核对两侧 SAS，在电脑确认。
3. 手机发送一条无附件任务，电脑 `/jobs` 输入响应码并批准。
4. 确认手机状态变为 `QUEUED`/`RUNNING`/`DONE`，结果可解密。
5. 停 bridge 后发送文本任务，重启后确认离线队列自动补投。

## 5. Web Push

- 需要 HTTPS PWA origin（或 localhost 调试）和浏览器可访问的推送服务。
- PWA 中点击“启用完成通知”并授予通知权限；iOS 需先“添加到主屏幕”，且系统版本支持 Web Push。
- 插件/电脑完成后应收到 `QUEUED`/`DONE`/`FAILED`/`REJECTED`/`EXPIRED` 通知。
- 若通知不达：检查浏览器通知权限、VAPID 公钥是否随 bridge 改变、推送服务网络。
- 未实测项：真实推送服务、iOS 推送。

## 6. DSH 插件

```powershell
dsh plugin --profile desktop add link:D:\phonejob\plugin
```

- 用桌面版自带的 CLI/应用安装；不要用不兼容的 npx CLI 打开同一个 `DSH_HOME`。
- 批准一个任务后确认插件认领 `approved/` → `working/`，bridge 状态变 `RUNNING`，最终写入 `done/<id>/result.json`。
- 桌面真实模型回复仍需实际运行验证。

## 7. 备份与恢复

```bash
node tools/backup.mjs --include-inbox --out D:/phonejob-backup
node tools/restore.mjs D:/phonejob-backup --force
```

- 恢复前停止 bridge。
- `keys.bin`/`vapid.bin` 是 DPAPI 用户级密钥，只能由同一 Windows 用户恢复。
- 备份目录包含数据库、审计、收件箱明文；自行加密保管。

## 8. 验收清单

- [ ] 手机与电脑 SAS 一致，配对成功
- [ ] 无附件任务可发送、审批、执行、取结果
- [ ] 附件分片上传与结果文件下载
- [ ] 断网后文本任务入队，恢复后补投
- [ ] 电脑拒绝/超时/锁定状态手机可见
- [ ] Web Push 通知（真实推送服务）
- [ ] 桌面 DSH 真实模型任务
- [ ] iOS Safari/主屏幕安装
- [ ] 备份可在同用户下恢复
- [ ] 本地 7789 未暴露，CSP/CORS 正确
