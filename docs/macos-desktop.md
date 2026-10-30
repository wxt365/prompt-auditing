# macOS 菜单栏版使用说明

## 安装与启动

适用于 macOS 13 或更新版本。Apple Silicon 使用 `arm64` 包，Intel Mac 使用 `amd64` 包；实际原生验证范围见文末。

解压后将 `Codex Security Gateway.app` 放到“应用程序”或其他固定目录，再双击启动。程序在顶部菜单栏显示盾牌图标，不显示终端或 Dock 图标。菜单提供“打开管理界面”和“退出”；再次打开已经运行的同一 `.app` 会重新打开管理页。

默认构建为供本机测试的临时签名包，未经过 Apple 公证。下载分发时可能受到 Gatekeeper 限制；确认来源后可通过系统“隐私与安全性”中的“仍要打开”处理。正式分发需使用 Developer ID 签名和 Apple 公证。

## 首次配置

1. 首次启动自动打开浏览器管理页；保存连接设置前代理不会启动。
2. 填写上游 API 基础地址，支持 `https://example.com/v1` 和 `http://192.168.137.250:33000/v1/`。HTTP 会明文传输正文和认证信息。
3. 本地监听端口默认 `18080`，只接受本机连接。默认“沿用客户端认证”，无需在管理页填写 API Key。
4. 点击“保存并应用”，然后将客户端 API 基础地址改为页面显示的地址，通常为 `http://127.0.0.1:18080/v1`，保留客户端原认证。
5. 如需网关保存上游 Key，选择“由网关配置上游 API Key”，保存后点击“复制本地令牌”，将此令牌用于客户端认证。

自 `0.1.1` 起，Chat Completions 同时接受 `POST /chat/completions` 和 `POST /v1/chat/completions`。两种路径执行相同检测、脱敏及审计，并按同一上游配置转发，不重复拼接 `/v1`；Responses 仍使用 `POST /v1/responses`。

自 `0.1.2` 起，新增 `POST /images/generations`（JSON）和 `POST /images/edits`（JSON 或 multipart）。这两个本地入口不加 `/v1`，例如直接请求 `http://127.0.0.1:18080/images/generations`；图片客户端若自动附加 `/images/...`，其 Base URL 应设为 `http://127.0.0.1:18080`。上游仍可配置为 `http://192.168.137.250:33000/v1/`，转发路径为 `/v1/images/...`。`/alpha/search` 暂不支持。

图片生成示例（`GATEWAY_BEARER` 使用客户端原密钥；网关持钥模式则使用本地令牌）：

```bash
curl http://127.0.0.1:18080/images/generations \
  -H "Authorization: Bearer $GATEWAY_BEARER" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-image-1","prompt":"画一只白猫"}'
```

图片编辑示例：

```bash
curl http://127.0.0.1:18080/images/edits \
  -H "Authorization: Bearer $GATEWAY_BEARER" \
  -F 'model=gpt-image-1' -F 'prompt=将背景改为蓝色' \
  -F 'image[]=@input.png'
```

模型需由你的上游支持；Gateway 不修改模型名。图片本身、远程 URL 和文件 ID 指向的内容不做 OCR 或敏感内容检测；只有提示词可脱敏，其他字段与文件名仍检测，无法安全替换时阻断。multipart 阻断审计以 JSON 保存文本、文件名、字段头、大小和 SHA-256，不保存图片二进制。当前源码新安装默认请求体限额为 1 GiB（1024 MiB），允许继续调大；multipart 开销和 Base64 膨胀也计入限额，gzip 压缩与解压后分别受限，超限返回 413。升级保留已有设置；若仍为 5 或 100 MiB，请在“连接设置 → 请求限制与审计保留 → 最大请求体（MiB）”改为 1024，点击“保存并应用”。已发布的 `0.1.3` 包仍默认 100 MiB，需重新构建才能使用新默认值及界面。限额提高不代表支持 PDF 附件。

“检查上游连接”只发送不带认证的 `HEAD <上游地址>/models`，最多等待 5 秒；收到 401、404 或其他 HTTP 状态只代表网络与 HTTP 可达，不代表模型调用成功。

## 规则、日志与退出

“安全规则”支持中文名称、关键字拦截、替换、正则和私网 IPv4 检测，保存后应用。先替换，再检查替换结果；模型名、角色、工具名称和 JSON 键名不会被替换，替换规则命中不可替换字段时阻断。

“审计日志”查询持久记录；阻断记录保存凭证脱敏后的请求 JSON。“实时日志”默认关闭，开启后内存保留最近 500 条请求元信息，退出程序后清空。

关闭浏览器后代理继续运行。从菜单栏点击“打开管理界面”可重新进入；点击“退出”停止代理并回收数据库。在途请求最多等待 15 秒，之后终止仍未结束的连接。

## 设置与凭证

数据目录为当前用户的 `~/Library/Application Support/CodexSecurityGateway`，包含 `settings.db`、`policy.db`、`audit.db` 和单实例锁文件。目录权限为 `0700`，文件为 `0600`；已有宽权限目录会被拒绝，程序不会自动放宽权限。

设置中的本地令牌和上游 Key 通过 AES-256-GCM 加密；加密密钥保存在 macOS 登录钥匙串，服务名为 `com.prompt-auditing.gateway.settings`。钥匙串锁定、访问被拒绝、密钥丢失或密文校验失败时拒绝启动，不会退回明文保存。首次使用或更换程序签名后，系统可能要求允许访问钥匙串。

“沿用客户端认证”不会保存请求中的认证密钥。切换回该模式并保存时，会清除设置库中之前保存的上游 Key。Windows DPAPI 设置库不能直接复制到 macOS 使用；不要覆盖数据库来处理权限或启动错误。

## 从源码构建

需要 Go 1.26.5 和 Xcode Command Line Tools；运行程序无需安装 Go、Python 或 Node.js。

```bash
bash scripts/build-macos-package.sh 0.1.3 arm64
# Intel 构建：将 arm64 改为 amd64
```

产物在 `dist/codex-gateway-macos-arm64-0.1.3/` 和同名 ZIP 中，包含 `.app`、本说明和 SHA-256 文件。构建拒绝覆盖已有同版本产物。

桌面版使用 CGO 调用系统 AppKit 和 Security 框架；原有 `scripts/build-release.sh` 仍生成无 CGO 的 CLI 以及 Windows 桌面版，不包含 macOS `.app`。

## 验证边界

2026-10-28 在 macOS 27.0.1 / Apple Silicon / Go 1.26.5 上完成：

- `go test ./...`、`go vet ./...` 通过。
- 原生 AppKit 菜单栏启动回调和 SIGTERM 正常退出通过；单实例互斥、释放及锁文件符号链接拒绝通过。
- 使用独立测试钥匙串条目验证跨进程解密、随机 nonce、密文篡改拒绝及缺失密钥时不自动创建。测试条目在检查后清理，不访问用户已有凭证。
- 管理 API 在两种认证模式下保存设置、应用规则、两种协议的脱敏 SSE 和阻断、审计凭证脱除及数据库重新打开恢复均通过；上游为本机测试服务。
- Apple Silicon `.app` 构建、临时签名验证、Info.plist 和 ZIP/SHA-256 检查通过。Windows 桌面版与 macOS 无 CGO CLI 仍可交叉构建。

以上不代表真实模型服务或完整人工桌面操作已验证；菜单鼠标操作、浏览器打开后的完整交互、Intel 原生运行、Developer ID 签名及 Apple 公证仍需对应环境验收。

原生回归可按以下命令运行。管理集成测试通过链接参数使用独立钥匙串服务名；不要改成正式服务名。

```bash
go test -tags native_e2e -run TestNativeDarwin -v ./internal/platform
go test -tags native_e2e,keychain_e2e \
  -ldflags '-X github.com/xiaotaowang/prompt-auditing/internal/platform.keychainService=com.prompt-auditing.gateway.test.manual' \
  -run TestNativeDarwinDesktop -v ./internal/app
# 测试结束后，仅删除上条命令创建的测试条目：
security delete-generic-password -s com.prompt-auditing.gateway.test.manual -a desktop-settings-key-v1
```
