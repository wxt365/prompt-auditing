# 本机独立测试网关

日常 Codex 的 `config.toml` 保持直连上游，网关按正常方式在托盘运行。测试脚本在独立 Codex 进程中用 `-c` 临时覆盖当前提供商的地址，不修改 `config.toml` 或 `auth.json`，不需要重启正在使用的 Codex。

请从资源管理器双击新版网关 EXE 启动。自动测试环境启动的子进程可能随宿主退出；需要从脚本启动时，可执行 `powershell -NoProfile -File scripts/start-desktop.ps1`，由现有桌面 Explorer 启动网关。正式切换 Codex 前，打开 `http://127.0.0.1:18080/healthz`，确认返回 `"status":"ok"`；连接失败说明本地服务不可达，尚未进入内容审计。

本机已有 Python 3.13，脚本只使用标准库，需要 Python 3.11 或以上。默认从桌面端安装目录选择最新的 `codex.exe`，执行前显示路径、版本、目标和模型；可用 `--codex` 明确指定版本。认证由 Codex 沿用当前提供商配置取得，脚本不读取密钥。

在项目根目录运行基础测试：

```powershell
python -X utf8 scripts/test-codex-gateway.py
```

测试图片请求：

```powershell
python -X utf8 scripts/test-codex-gateway.py --image C:\test\sample.png
```

复制已有会话的历史进行测试：

```powershell
python -X utf8 scripts/test-codex-gateway.py --session <会话ID>
```

本次正在使用的会话 ID 为 `01a17b66-ec38-7f83-ac7e-1dde03ce615b`。`--session` 使用 `codex exec fork` 和 `--ephemeral`，创建临时副本，不续写原会话；该方式适合检查包含图片、工具调用的历史是否仍触发 422。

默认提示词要求仅回复 `OK`，运行在临时工作目录及只读沙箱。测试只输出模型回复和错误，不保存完整请求。成功时显示模型回复、配置未改变的校验结果和“测试通过”；失败退出码为 1。模型请求会发送到网关当前配置的真实上游。

如需检查工具调用，可显式指定测试提示词；只读沙箱及不批准操作的限制仍生效：

```powershell
python -X utf8 scripts/test-codex-gateway.py --prompt "调用命令工具输出 gateway-probe，然后回复 OK。"
```

测试超时默认 120 秒，可用 `--timeout` 调整；重试关闭，422 会直接显示具体字段路径。测试成功仅证明本次使用的版本、会话历史和请求通过，后续不同请求仍可能出现新的协议兼容问题。

2026-10-27 本机验证：桌面端 `0.162.0-alpha.2` 的新请求和当前会话临时副本均通过 `http://127.0.0.1:8080/v1`，由网关访问内网上游并收到 `OK`；日常配置保持直连上游，测试前后配置字节一致。

当前测试脚本默认访问 `18080`；已有配置仍使用其他端口时，通过 `--url http://127.0.0.1:端口/v1` 指定实际地址。
