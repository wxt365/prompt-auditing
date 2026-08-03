# Codex Security Gateway

面向 Codex CLI 的本地 Prompt 安全审计代理。Gateway 只监听回环地址，在请求发送到固定 HTTPS 上游前执行阻断、告警和非级联脱敏，并将规则与审计分别保存到 `policy.db` 和 `audit.db`。

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
- `codex-gateway-darwin-arm64`
- `SHA256SUMS`

两个二进制均使用 `CGO_ENABLED=0` 构建，不依赖 Go、Python 或 Node.js 运行时。交叉编译成功只证明目标格式和架构，不等同于目标系统原生 E2E 通过。

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

`init` 首次创建 `policy.db`、`audit.db` 和默认规则；数据库已存在时会拒绝覆盖。数据库目录不存在时会以当前用户独占权限创建；已存在目录必须预先满足权限要求，Gateway 不会修改共享目录或系统目录的权限。

## Codex 配置

在 Codex 的 `config.toml` 中添加：

```toml
model_provider = "security_gateway"

[model_providers.security_gateway]
name = "Codex Security Gateway"
base_url = "http://127.0.0.1:8080/v1"
env_key = "CODEX_GATEWAY_TOKEN"
wire_api = "responses"
```

`CODEX_GATEWAY_TOKEN` 是 Codex 到本机 Gateway 的独立令牌，至少 32 字节；`OPENAI_API_KEY` 只由 Gateway 读取并替换为上游认证 Header。两者不得写入 YAML 或 SQLite。

回环监听不是本地容器的完整网络隔离。macOS Docker Desktop 的 `host.docker.internal` 可代理访问宿主回环端口，因此不要把 `CODEX_GATEWAY_TOKEN` 注入不受信任容器；需要禁止容器建立 TCP 连接时，必须配置宿主防火墙或容器网络策略。

Gateway 使用系统根证书池验证上游 TLS，最低版本为 TLS 1.2。需要信任企业代理或测试 CA 时，可通过标准环境变量 `SSL_CERT_FILE` 指定 PEM 证书文件；该证书会追加到系统根证书池，不会关闭证书校验。

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
curl http://127.0.0.1:8080/healthz
```

## 规则管理

规则写入 `policy.db`，每次变更会原子递增规则集版本。运行中的 Gateway 使用启动时快照，修改后需要执行 `check-config` 并重启。

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

动作优先级固定为 `block > mask > warn > allow`。替换基于原始请求一次完成，替换结果不会再次触发其他替换规则。

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
