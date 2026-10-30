# Codex Security Gateway

本地 Prompt 安全审计代理，同时处理 `POST /v1/responses` 和 `POST /v1/chat/completions`，支持文本请求、普通 JSON 和 SSE 流式响应。Chat Completions 也接受不带版本前缀的 `POST /chat/completions`，两种路径使用相同检测与审计流程，按配置的上游地址拼接标准接口路径，不重复添加 `/v1`。Responses 支持带图片及自定义工具历史的 Codex 会话：文本参与审计，图片原样转发，图片内容不做识别。Gateway 只监听回环地址，在请求发送到固定 HTTP 或 HTTPS 上游前执行阻断、告警和非级联脱敏，并将规则与审计分别保存到 `policy.db` 和 `audit.db`。

图片接口使用不带版本前缀的 `POST /images/generations` 和 `POST /images/edits`。生成接受 JSON，编辑接受 JSON 图片引用或 multipart 文件上传；提示词参与检测与脱敏，图片内容不做识别。请求示例、上游路径拼接及审计边界见 [图片接口使用说明](docs/image-endpoints.md)。`/alpha/search` 暂不支持。

当前源码新安装默认请求体上限为 **1 GiB（1024 MiB，1073741824 字节）**，为官方图片请求和多图上传预留空间，可按上游需要继续调大；gzip 压缩与解压后的大小均受限，超限返回 413。升级保留已保存的限制；已有桌面版若仍为 5 或 100 MiB，请在“连接设置 → 请求限制与审计保留”改为 1024 并保存应用。CLI 修改 `max_body_bytes: 1073741824` 后重启。模型、图片尺寸等业务限制由上游判断；此调整不增加 PDF 或其他未支持附件的处理能力。已发布的 `0.1.3` 包仍默认 100 MiB。

## Windows 桌面使用

试用包解压后双击 `codex-gateway.exe`，首次运行自动打开本地浏览器管理页。完整操作步骤见 [离线使用说明](docs/windows-trial-guide.html)，可用 `scripts/build-windows-package.ps1` 重新生成分发包。

当前 Windows x64 试用版为 `trial-20261028.3`，压缩包位于 `dist/codex-gateway-windows-x64-20261028-r3.zip`，包含程序、离线说明和 SHA-256 校验文件；包含下述首次配置、连接检查及管理查询改进；两种协议统一递归审计并保留普通 JSON 扩展字段，避免客户端新增元数据时反复出现本地 422。详见 [JSON 扩展兼容](docs/json-extensions-20261028.md)。

1. 新安装显示“待配置上游”，保存有效连接设置前不启动代理。在“连接设置”填写本地监听端口（默认 `18080`）和实际使用的上游 API 基础地址。本地地址由程序保留为回环地址，默认 `127.0.0.1`。默认选择“沿用客户端认证”，无需填写 API Key。可先点击“检查上游连接”，再点击“保存并应用”；顶部“本地代理运行中”仅表示本地服务正常。修改端口后需同步更新客户端 API 地址。
2. 在“安全规则”添加、编辑、启停或删除规则，点击“保存并应用规则”。只需填写规则名称，支持中文，最多 128 个字符，例如“敏感字替换”；内部 ID 自动生成，改名不会改变 ID。匹配和替换内容支持中文。
3. 将客户端 API 基础地址设为页面显示的本地地址，继续使用客户端现有的认证密钥。
4. 请求被拦截时，打开“审计日志”，点击“查看详情”。顶部直接列出导致阻断的规则，明细中阻断行置顶标红，并与替换预检、仅告警区分；旧记录未保存逐条动作时明确提示无法还原。点击“展开请求内容”查看凭证脱敏后的原始 JSON，命中词会高亮，也可下载完整 JSON。默认查询阻断 / 拒绝记录，可按动作、请求 ID、规则名称和时间筛选并翻页。
5. 调试请求无响应或重连时，进入“实时日志”点击“开启采集”。每秒刷新接口、处理阶段、本地 / 上游状态码、耗时及异常原因，可筛选请求、只看异常或清空记录。默认关闭，内存保留最近 500 条，关闭页面后继续采集，退出程序后清空。

桌面模式不需要手工创建 YAML、初始化数据库或设置环境变量。设置自动保存在当前用户的 `%APPDATA%\CodexSecurityGateway` 目录。

“检查上游连接”检查当前填写的地址，不保存设置；最多等待 5 秒，发送不带认证的 `HEAD <上游地址>/models`，不调用模型。收到 HTTP 响应（包括 401、404、405 或 500）只说明网络与 HTTP 可达，不代表密钥、模型或完整请求可用。已有连接配置保持原启动方式。

“沿用客户端认证”模式将客户端发来的 Bearer 认证头转发给固定上游，由上游验证凭证；网关不读取 Codex 的 `auth.json`，也不保存客户端请求中的凭证。Codex 只需将原模型提供商的 `base_url` 改为 `http://127.0.0.1:18080/v1`，保留原认证配置。例如网关上游填 `http://192.168.137.250:33000/v1`，两个协议就分别转发到该地址下的对应接口。请求缺少 Bearer 凭证时返回 401。

如需网关持有上游密钥，可切换“由网关配置上游 API Key”，填写密钥并让客户端使用“复制本地令牌”取得的独立令牌。此模式凭证通过 Windows DPAPI 加密保存。切回客户端认证并保存时清除网关之前保存的上游密钥。升级前已保存密钥的配置保留原模式；未配置密钥的配置自动使用客户端认证。

程序仅在右下角通知区域显示托盘图标，不显示控制台窗口。单击托盘图标或右键选择“打开配置界面”可进入管理页；关闭浏览器页面后代理继续运行。配置完成后再次启动只显示托盘，配置异常时会打开管理页。右键选择“退出”可停止服务；退出时会等待在途请求和审计，15 秒后终止仍未结束的请求。

桌面模式使用独立的数据目录，不会自动迁移原 CLI 配置和规则。下方命令行操作保留为高级使用方式。Windows 密钥保护和托盘行为需要 Windows 原生验证。当前新增功能的验证边界见 [桌面模式说明](docs/desktop-mode.md)。

## macOS 桌面使用

macOS 版采用顶部菜单栏图标和同一套浏览器管理页，双击 `.app` 启动，关闭页面后继续代理，从菜单栏退出。凭证由登录钥匙串中的密钥加密保护，数据保存在当前用户的 `~/Library/Application Support/CodexSecurityGateway`。支持 HTTP/HTTPS 上游和两种请求协议。

在 Mac 上执行 `bash scripts/build-macos-package.sh 0.1.3 arm64` 生成 Apple Silicon 桌面包；Intel 使用 `amd64`。桌面包构建需要 CGO 和 Xcode Command Line Tools，默认临时签名，未经过 Apple 公证。安装、配置及验证边界见 [macOS 使用说明](docs/macos-desktop.md)。

调试期间可让日常 Codex 保持直连，运行 `python -X utf8 scripts/test-codex-gateway.py` 在独立进程中临时走网关；支持图片和旧会话临时副本，不需要反复修改配置或重启。详见 [本机独立测试](docs/local-gateway-testing.md)。

权威需求和验收边界见 [MVP 设计文档](docs/codex-security-gateway-mvp-design.md)，当前逐项状态见 [验收证据矩阵](docs/acceptance-evidence.md)。

## 构建

开发环境固定使用 Go `1.26.5`：

```bash
go test ./...
go build -o codex-gateway ./cmd/codex-gateway
```

生成首发双平台产物、版本信息和 SHA-256 校验文件：

```bash
./scripts/build-release.sh 0.1.0
```

输出目录为 `dist/`：

- `codex-gateway-windows-amd64.exe`
- `codex-gateway-desktop-windows-amd64.exe`（无控制台的托盘与浏览器管理页）
- `codex-gateway-darwin-arm64`
- `SHA256SUMS`

以上产物均使用 `CGO_ENABLED=0` 构建，不依赖 Go、Python 或 Node.js 运行时。交叉编译成功只证明目标格式和架构，不等同于目标系统原生 E2E 通过。内网依赖代理及本轮 Windows 验证结果见 [桌面模式说明](docs/desktop-mode.md)。

## 初始化

默认配置位于 `config/gateway.yaml`。相对数据库路径以该 YAML 所在目录为基准解析。配置文件、数据库目录和数据库文件必须只允许当前用户访问。

macOS：

```bash
chmod 600 config/gateway.yaml
./codex-gateway init --config config/gateway.yaml
./codex-gateway check-config --config config/gateway.yaml
```

Windows PowerShell 使用当前用户 ACL，不要把配置和数据库放在其他用户可写目录：

```powershell
.\codex-gateway.exe init --config config\gateway.yaml
.\codex-gateway.exe check-config --config config\gateway.yaml
```

`init` 首次创建 `policy.db`、`audit.db` 和默认规则；数据库已存在时会拒绝覆盖。默认规则随程序打包，包含 API Key 检测、密码赋值检测、私网 IPv4 检测，以及预置的“敏感字替换”和“敏感字拦截”；可在管理页编辑。其中私网 IPv4 检测默认关闭，手动启用后仅告警，其余默认规则启用。升级不会补写或覆盖已有规则。数据库目录不存在时会以当前用户独占权限创建；已存在目录必须预先满足权限要求，Gateway 不会修改共享目录或系统目录的权限。

## Codex 配置

在 Codex 的 `config.toml` 中添加：

```toml
model_provider = "security_gateway"

[model_providers.security_gateway]
name = "Codex Security Gateway"
base_url = "http://127.0.0.1:18080/v1"
env_key = "CODEX_GATEWAY_TOKEN"
wire_api = "responses"
```

`CODEX_GATEWAY_TOKEN` 是 Codex 到本机 Gateway 的独立令牌，至少 32 字节；`OPENAI_API_KEY` 只由 Gateway 读取并替换为上游认证 Header。CLI 模式通过环境变量读取这两个值，不写入 YAML 或 SQLite；桌面模式通过管理页设置凭证，使用 DPAPI 加密后存入 `settings.db`。

回环监听不是本地容器的完整网络隔离。macOS Docker Desktop 的 `host.docker.internal` 可代理访问宿主回环端口，因此不要把 `CODEX_GATEWAY_TOKEN` 注入不受信任容器；需要禁止容器建立 TCP 连接时，必须配置宿主防火墙或容器网络策略。

Gateway 支持固定的 HTTP 或 HTTPS 上游。使用 HTTPS 时，Gateway 使用系统根证书池验证上游 TLS，最低版本为 TLS 1.2；需要信任企业代理或测试 CA 时，可通过标准环境变量 `SSL_CERT_FILE` 指定 PEM 证书文件，该证书会追加到系统根证书池，不会关闭证书校验。使用 HTTP 时，Prompt、工具内容和上游认证信息会以明文传输，启动时会输出安全警告，只应在已接受该风险的受控网络中使用。

上游 4xx/5xx 错误保持原状态码和非敏感诊断内容。Gateway 会在 `max_body_bytes` 上限内安全处理普通 JSON、文本或 gzip 错误正文，结构化移除本地 Token 和上游 API Key，并重新计算响应 Header；无法安全解析或超过上限时返回不含上游正文的通用诊断。正常 2xx JSON/SSE 响应仍直接流式转发。

macOS：

```bash
export CODEX_GATEWAY_TOKEN='<至少 32 字节的本机随机令牌>'
export OPENAI_API_KEY='<OpenAI API Key>'
./codex-gateway start --config config/gateway.yaml
```

Windows PowerShell：

```powershell
$env:CODEX_GATEWAY_TOKEN = '<至少 32 字节的本机随机令牌>'
$env:OPENAI_API_KEY = '<OpenAI API Key>'
.\codex-gateway.exe start --config config\gateway.yaml
```

健康检查：

```bash
curl http://127.0.0.1:18080/healthz
```

## 规则管理

规则写入 `policy.db`，每次变更会原子递增规则集版本。运行中的 Gateway 使用启动时快照，修改后需要执行 `check-config` 并重启。

以上重启要求针对 CLI；桌面管理页在保存并应用后自动重启代理、加载新快照。

```bash
./codex-gateway policy list --config config/gateway.yaml

./codex-gateway policy add-block --config config/gateway.yaml \
  --id keyword.block-enterprise \
  --keyword 客户A \
  --keyword 项目B

./codex-gateway policy add-replacement --config config/gateway.yaml \
  --id keyword.replace-enterprise \
  --mapping 内部系统A=业务系统 \
  --mapping 生产数据库A=测试数据库

./codex-gateway policy add-regex --config config/gateway.yaml \
  --id credential.custom \
  --action block \
  --case-sensitive \
  --pattern 'secret-[A-Za-z0-9]+'

./codex-gateway policy add-private-ipv4 --config config/gateway.yaml \
  --id network.private-ipv4-custom \
  --action warn

./codex-gateway policy disable --config config/gateway.yaml --id keyword.block-enterprise
./codex-gateway policy enable --config config/gateway.yaml --id keyword.block-enterprise
./codex-gateway policy delete --config config/gateway.yaml --id keyword.block-enterprise
```

先基于原始内容执行一次替换，再用替换后的内容检查阻断、告警和放行规则；替换结果不会再次触发其他替换规则。替换后仍命中阻断规则则拒绝，否则有替换时以 `mask` 转发，无替换时按 `warn > allow` 处理。工具名称、模型名称和结构字段等不可安全替换的位置命中替换规则时仍阻断。规则执行顺序不依赖表格顺序或规则 ID。

## 验证

```bash
go vet ./...
go test -race ./...
go test -tags performance -v ./tests/performance
```

真实 Codex 契约测试需要本机 Codex CLI，并且必须在确认不会产生未授权外联后显式启用：

```bash
RUN_CODEX_CONTRACT=1 \
  go test -tags codex_contract -run TestCodex0144ResponsesContract -v ./tests/contract
```

macOS 原生产物 E2E 还需要设置 `GATEWAY_BINARY`。`TestDarwinArtifactWithRealCodex` 会移除 OpenAI 凭证和代理环境变量，并通过 macOS `sandbox-exec` 将 Codex 子进程限制为只能访问 `localhost:*`；缺少 `sandbox-exec` 时测试会拒绝运行：

```bash
GATEWAY_BINARY=dist/codex-gateway-darwin-arm64 \
  go test -tags native_e2e -run 'TestDarwinArtifact(Core|WithRealCodex)$' -v ./tests/e2e
```

Windows AMD64 原生环境使用同一发布产物执行核心 E2E：

```powershell
$env:GATEWAY_BINARY = "dist\codex-gateway-windows-amd64.exe"
go test -tags native_e2e -run TestWindowsArtifactCore -v ./tests/e2e
```

Windows 原生 E2E 和公网 OpenAI 联调必须在对应授权环境单独执行，不能用交叉编译、假上游或本机单元测试替代。
