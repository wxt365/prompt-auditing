# Codex Security Gateway Windows x86 测试版使用说明

## 1. 产物范围

本测试包用于验证 32 位 Windows 架构兼容性：

- 目标平台：`windows/386`；
- 文件格式：PE32 Console，Intel 80386；
- 构建版本：`0.1.1-x86-test`；
- 源码标识：`working-tree-20260804`；
- Go 版本：`go1.26.5`；
- `CGO_ENABLED=0`，不依赖 Go、Python、Node.js 或额外 SQLite 运行时。

该产物来自当前未提交工作树，仅用于测试。权威设计的正式 Windows 首发目标仍是 `windows/amd64`。目前只完成了 `windows/386` 全包交叉编译和原生 E2E 测试程序交叉编译，尚未在原生 Windows x86 环境执行 E2E，不能作为正式发布或 Windows 原生验收通过证据。

## 2. 文件与校验

测试目录包含：

```text
windows-x86-test/
├── codex-gateway-windows-386.exe
├── gateway.yaml
├── README-WINDOWS-X86.md
└── SHA256SUMS
```

在 PowerShell 中校验 EXE：

```powershell
Get-FileHash .\codex-gateway-windows-386.exe -Algorithm SHA256
Get-Content .\SHA256SUMS
```

期望 SHA-256：

```text
d7bc1804ab959e111a1a6f7a21d88f6f3863849cfad945ff3536fa0c0a4b0bab
```

检查版本：

```powershell
.\codex-gateway-windows-386.exe version
```

期望输出：

```text
codex-gateway 0.1.1-x86-test (working-tree-20260804)
```

## 3. 安装位置

把整个目录放到当前 Windows 用户独占、不可被其他普通用户写入的位置，例如：

```text
C:\Users\<当前用户名>\CodexSecurityGateway
```

不要放到共享目录、网络共享、公共桌面或允许其他用户写入的目录。Gateway 会检查配置目录、配置文件、数据库目录及数据库文件的 Windows ACL；权限不满足时会失败关闭。

如果 Windows 阻止从网络下载的 EXE，可在确认哈希正确后执行：

```powershell
Unblock-File .\codex-gateway-windows-386.exe
```

## 4. 配置

包内 `gateway.yaml` 默认内容：

```yaml
version: 1
listen: 127.0.0.1:18080
upstream: http://192.168.137.250:33000/v1/
policy_db: data/policy.db
audit_db: data/audit.db
max_body_bytes: 5242880
max_concurrent_requests: 10
audit_retention_days: 30
audit_max_bytes: 104857600
```

约束：

- `listen` 必须是回环地址；
- `upstream` 必须是固定 HTTP 或 HTTPS 地址；
- `policy_db` 和 `audit_db` 必须是不同文件；
- 相对数据库路径以 `gateway.yaml` 所在目录为基准；
- 不得把 `CODEX_GATEWAY_TOKEN` 或 `OPENAI_API_KEY` 写入 YAML。

HTTP 上游会明文传输 Prompt、工具内容和 `OPENAI_API_KEY` 对应的 Bearer 认证信息，启动时会输出警告。HTTPS 上游仍会执行系统根证书校验和最低 TLS 1.2 限制。

## 5. 首次初始化

在测试目录打开 PowerShell：

```powershell
.\codex-gateway-windows-386.exe init --config .\gateway.yaml
.\codex-gateway-windows-386.exe check-config --config .\gateway.yaml
```

`init` 只允许执行一次，它会：

- 把配置文件 ACL 收敛为当前用户独占；
- 创建受当前用户 ACL 保护的 `data` 目录；
- 创建 `policy.db`、`audit.db` 和三条默认规则。

数据库已经存在时，`init` 会拒绝覆盖。不要清空、截断或手工新建空数据库；`start` 和 `check-config` 会拒绝未初始化的空库，不会自动恢复默认规则。

## 6. 启动 Gateway

先生成一个至少 32 字节的随机本地令牌。以下命令兼容传统 Windows PowerShell：

```powershell
$bytes = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$gatewayToken = -join ($bytes | ForEach-Object { $_.ToString('x2') })
$rng.Dispose()
$gatewayToken
```

暂时记录输出值，Gateway 和 Codex 必须使用同一个 `CODEX_GATEWAY_TOKEN`。不要把该令牌提交到仓库或发给其他用户。

在第一个 PowerShell 窗口启动 Gateway：

```powershell
$env:CODEX_GATEWAY_TOKEN = '<上一步生成的令牌>'
$env:OPENAI_API_KEY = '<用于测试的 OpenAI API Key>'
.\codex-gateway-windows-386.exe start --config .\gateway.yaml
```

正常启动会输出监听地址、上游域名、规则版本和数据库路径，但不会输出凭证。

在第二个 PowerShell 窗口检查健康状态：

```powershell
Invoke-RestMethod http://127.0.0.1:18080/healthz
```

期望 `status` 为 `ok`，并返回当前 `rule_set_version`。

## 7. 接入 Codex CLI

编辑当前用户的 `$HOME\.codex\config.toml`，加入：

```toml
model_provider = "security_gateway"

[model_providers.security_gateway]
name = "Codex Security Gateway"
base_url = "http://127.0.0.1:18080/v1"
env_key = "CODEX_GATEWAY_TOKEN"
wire_api = "responses"
```

在启动 Codex 的第二个 PowerShell 窗口设置同一个本地令牌：

```powershell
$env:CODEX_GATEWAY_TOKEN = '<与 Gateway 相同的令牌>'
codex
```

Codex 窗口不需要设置 `OPENAI_API_KEY`。Gateway 会验证本地令牌，并使用第一个窗口中的 `OPENAI_API_KEY` 替换上游认证 Header。

## 8. 规则管理

规则变更使用同一 EXE 和配置文件：

```powershell
.\codex-gateway-windows-386.exe policy list --config .\gateway.yaml

.\codex-gateway-windows-386.exe policy add-block --config .\gateway.yaml `
  --id keyword.block-enterprise `
  --keyword '客户A' `
  --keyword '项目B'

.\codex-gateway-windows-386.exe policy add-replacement --config .\gateway.yaml `
  --id keyword.replace-enterprise `
  --mapping '内部系统A=业务系统'

.\codex-gateway-windows-386.exe policy disable --config .\gateway.yaml --id keyword.block-enterprise
.\codex-gateway-windows-386.exe policy enable --config .\gateway.yaml --id keyword.block-enterprise
.\codex-gateway-windows-386.exe policy delete --config .\gateway.yaml --id keyword.block-enterprise
```

规则变更后执行：

```powershell
.\codex-gateway-windows-386.exe check-config --config .\gateway.yaml
```

运行中的 Gateway 使用启动时规则快照，不会热加载。修改规则后必须停止并重新启动 Gateway。

当前执行顺序为：

```text
一次性替换 → 检查替换后的内容 → 仍违禁则阻断，否则放行
```

替换产生的目标字不会再次触发替换规则，但会参与阻断和告警检查。替换并通过检查的请求记录为 `mask`，没有替换的请求按 `warn > allow` 处理。协议字段、工具名称和 JSON 动态键只允许检测，不允许替换；脱敏规则命中这些位置时会提升为阻断。

## 9. 停止

在运行 Gateway 的 PowerShell 窗口按 `Ctrl+C`。正常停止会输出：

```text
Gateway 已停止
```

不要直接结束进程，正常中断会等待在途 HTTP 请求和审计事务完成。

## 10. 常见错误

### `Gateway 配置目录不可信` 或 ACL 校验失败

配置目录或文件允许其他用户写入。把完整目录移动到当前用户私有目录，确认没有共享写权限，然后重新执行 `init`。不要通过关闭 ACL 校验绕过该错误。

### `数据库已存在，拒绝覆盖`

已经完成初始化，不要再次运行 `init`。改为运行 `check-config` 或 `start`。

### `缺少 schema_migrations，必须先执行 init`

数据库为空或不是 Gateway 初始化的数据库。停止测试，核对文件路径并从可信备份恢复；不要让 Gateway 静默创建默认规则后继续运行。

### `listen` 端口被占用

修改 `gateway.yaml` 的 `listen` 端口，并同步修改 Codex `config.toml` 中的 `base_url`。

### HTTP `401 gateway_unauthorized`

Codex 进程中的 `CODEX_GATEWAY_TOKEN` 与 Gateway 进程不一致，或长度不足 32 字节。

### HTTP `403 prompt_blocked`

请求命中阻断规则，Gateway 未调用上游。根据企业规则调整输入，不要通过删除审计库规避阻断。

### HTTP `503 security_engine_unavailable`

安全扫描超时、取消、命中超过 10,000 条或内部检测失败。该请求已失败关闭，未发送上游。

### HTTP `503 audit_unavailable`

审计写入或审计健康检查失败。Gateway 会阻断新请求；检查磁盘空间、文件 ACL 和数据库完整性。

## 11. 安全与测试边界

- `audit.db` 包含被阻断请求的完整 JSON 和敏感命中内容，应按企业敏感资产保护；
- `gateway.yaml`、两个数据库及 WAL/SHM 文件必须只允许当前用户访问；
- Gateway 只监听回环地址，但回环监听不等同于对本地容器的完整网络隔离；
- x86 进程受 32 位地址空间限制，不应把本测试包当作高并发或大规模规则场景的容量证明；
- 交叉编译、PE32 格式检查和测试程序编译不等于原生 Windows x86 E2E；
- 正式发布仍需在目标 Windows 环境完成启动、ACL、阻断、脱敏、SQLite 审计、上游认证替换及 `Ctrl+C` 优雅停止测试。

测试反馈至少应包含：Windows 版本、系统架构、Codex 版本、`version` 输出、复现命令、错误输出和 `x-gateway-request-id`。反馈中不得包含本地令牌、OpenAI API Key 或完整敏感请求体。
