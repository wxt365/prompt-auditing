# macOS 菜单栏版使用说明

## 0.1.10 测试包

本版将上游响应头等待时间默认改为 300 秒，可在连接设置中调整；保留实时日志紧凑布局及 Session 并发统计。提供 Apple Silicon（arm64）和 Intel（amd64）两个独立包，均要求 macOS 13 或更新版本；Intel 包已交叉构建，尚未在 Intel Mac 原生运行验证。

自 0.1.8 起支持实时并发监控：进入“实时日志”即可每秒查看当前占用 / 上限、按匿名 Session 汇总的 HTTP / SSE / WebSocket 占用，以及活跃请求明细，无需开启日志采集。缺少或冲突的 Session 标识归入“未识别”；空闲 WebSocket 仍占一个名额。具体口径见“规则、日志与退出”。

本包支持 Responses、Chat Completions、图片生成、图片编辑及模型列表的带 `/v1` 和无前缀两种入口，并支持 Chat Completions 标准 `image_url` 图片消息。新增 `GET /v1/responses` 与 `GET /responses` 的 WebSocket 连接，以及两种路径下的指定响应 GET 查询；WebSocket 内每条客户端事件均经过检测与审计，普通无 ID、无协议升级的 GET 仍返回 405。详见同目录 [Responses 长连接与查询](responses-websocket.md) 和 [图片接口说明](image-endpoints.md)。

升级前从菜单栏退出旧实例，备份整个数据目录，再启动新版，保留现有设置与规则。从 `0.1.5`、`0.1.6` 或 `0.1.7` 升级不新增数据库迁移；更早版本可能升级至 Schema 4，回退需恢复相应备份。已完成本机模拟上游验证，尚未进行本版本与真实客户端、模型服务的联调。

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

自 `0.1.1` 起，Chat Completions 同时接受 `POST /chat/completions` 和 `POST /v1/chat/completions`。当前源码的 Responses 也同时接受 `POST /responses` 和 `POST /v1/responses`，已发布的 `0.1.5` 包尚未包含 `/responses` 别名。每个接口的两种路径执行相同检测、脱敏及审计，并按同一上游配置转发，不重复拼接 `/v1`。

自 `0.1.5` 起支持 `GET /models` 和 `GET /v1/models` 获取上游模型列表。Cherry Studio 使用 OpenAI 兼容提供商时，可将 API 基础地址设为 `http://127.0.0.1:18080/v1`，再获取模型列表。两种入口均向上游 Base URL 追加 `/models`；沿用当前认证方式，不修改返回的模型名。

`0.1.5` 同时增加拒绝请求的接口诊断：在“审计日志 → 阻断 / 拒绝”中查看请求方法、脱敏路径、本地状态码和请求 ID，无需开启实时采集。升级前从菜单栏退出旧实例并备份整个数据目录；新版启动时将规则和审计数据库升级至 Schema 4，保留配置和历史记录。旧版程序不能直接打开升级后的数据库，回退需恢复升级前备份。

自 `0.1.2` 起，新增 `POST /images/generations`（JSON）和 `POST /images/edits`（JSON 或 multipart）。当前源码也接受 `/v1/images/generations` 和 `/v1/images/edits` 别名，已发布的 `0.1.5` 包尚未包含别名支持。图片客户端若自动附加 `/images/...`，本地 Base URL 可设为 `http://127.0.0.1:18080` 或 `http://127.0.0.1:18080/v1`。两种入口均按上游 Base URL 拼接，例如上游配置为 `http://192.168.137.250:33000/v1/`，转发路径为 `/v1/images/...`，不会重复 `/v1`。`/alpha/search` 暂不支持。

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

自 0.1.10 起默认等待上游响应头 300 秒，可在“连接设置 → 请求限制与审计保留 → 上游响应头等待时间（秒）”填写正整数并保存应用。未设置该字段的旧配置升级后采用 300 秒，已有自定义值保留。此设置适用于所有代理 HTTP 请求和 WebSocket 握手，不是整个图片生成或流式响应的总时限；连接检查仍为 5 秒，客户端超时独立生效。已分发的 0.1.9 及更早包仍为原来的 30 秒，需升级至 0.1.10 才支持此参数。

## 规则、日志与退出

“安全规则”支持中文名称、关键字拦截、替换、正则和私网 IPv4 检测，保存后应用。先替换，再检查替换结果；模型名、角色、工具名称和 JSON 键名不会被替换，替换规则命中不可替换字段时阻断。

“审计日志”查询持久记录；阻断记录保存凭证脱敏后的请求 JSON。“实时日志”默认关闭，开启后内存保留最近 500 条请求元信息，退出程序后清空。

“实时日志”顶部的“当前并发占用”每秒刷新实际占用和上限、Session 分组，以及活跃请求的接口、协议、阶段和持续时间，无需开启采集，清空日志也不影响统计。HTTP/SSE 在请求处理结束后释放名额；WebSocket 整条连接占一个名额，包括空闲连接，连接内事件不重复计数。限流仍为所有客户端共享，满额直接拒绝，不按 Session 分配额度。

Session 读取 `session_id` 或 `X-Session-ID` 请求头，也识别 JSON 的 `client_metadata.session_id`（WebSocket 支持 `response.client_metadata.session_id`）。标识仅用于观察，不作为身份认证；未提供、无效或相互冲突时归入“未识别”，不能据此推断真实 Session 数。标识限 256 字节的字母、数字、下划线、连字符或点。页面只返回当前代理实例内稳定的匿名标签，重启后变化，不保存原始 Session 标识。读取正文前暂时可能显示未识别；连接内出现不同标识后将保持未识别，避免将多 Session 的复用连接误归给单一 Session。

关闭浏览器后代理继续运行。从菜单栏点击“打开管理界面”可重新进入；点击“退出”停止代理并回收数据库。在途请求最多等待 15 秒，之后终止仍未结束的连接。

## 设置与凭证

数据目录为当前用户的 `~/Library/Application Support/CodexSecurityGateway`，包含 `settings.db`、`policy.db`、`audit.db` 和单实例锁文件。目录权限为 `0700`，文件为 `0600`；已有宽权限目录会被拒绝，程序不会自动放宽权限。

设置中的本地令牌和上游 Key 通过 AES-256-GCM 加密；加密密钥保存在 macOS 登录钥匙串，服务名为 `com.prompt-auditing.gateway.settings`。钥匙串锁定、访问被拒绝、密钥丢失或密文校验失败时拒绝启动，不会退回明文保存。首次使用或更换程序签名后，系统可能要求允许访问钥匙串。

“沿用客户端认证”不会保存请求中的认证密钥。切换回该模式并保存时，会清除设置库中之前保存的上游 Key。Windows DPAPI 设置库不能直接复制到 macOS 使用；不要覆盖数据库来处理权限或启动错误。

## 从源码构建

需要 Go 1.26.5 和 Xcode Command Line Tools；运行程序无需安装 Go、Python 或 Node.js。

```bash
bash scripts/build-macos-package.sh 0.1.9 arm64
# Intel 构建：将 arm64 改为 amd64
```

产物在 `dist/codex-gateway-macos-arm64-0.1.9/` 和同名 ZIP 中，包含 `.app`、本说明和 SHA-256 文件；Intel 包名称中的架构为 `amd64`。构建拒绝覆盖已有同版本产物。

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
