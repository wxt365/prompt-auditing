"""使用独立 Codex 进程测试网关，不修改用户配置或认证文件。"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:18080/v1", help="待测网关地址；已有配置使用其他端口时请显式指定")
    parser.add_argument("--codex", type=Path, help="指定 Codex 可执行文件；默认使用桌面端安装目录中的最新版本")
    parser.add_argument("--model", help="默认沿用 config.toml 中的模型")
    parser.add_argument("--image", type=Path, help="附加测试图片")
    parser.add_argument("--session", help="复制指定旧会话进行测试，不续写原会话")
    parser.add_argument("--prompt", default="Do not call any tools. Reply only OK.", help="测试提示词")
    parser.add_argument("--timeout", type=int, default=120, help="超时秒数，默认 120")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("timeout 必须大于零")
    if args.image and not args.image.is_file():
        parser.error("测试图片不存在")

    config_path = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "config.toml"
    original = config_path.read_bytes()
    config = tomllib.loads(original.decode("utf-8-sig"))
    provider = config.get("model_provider")
    if not provider or provider not in config.get("model_providers", {}):
        parser.error("当前配置必须选择已有的自定义模型提供商")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", provider):
        parser.error("当前提供商名称不支持命令行点分路径")
    model = args.model or config.get("model")
    if not model:
        parser.error("请通过 --model 指定模型")
    binary = args.codex
    if binary is None:
        directory = Path(os.environ["LOCALAPPDATA"]) / "OpenAI" / "Codex" / "bin"
        candidates = list(directory.glob("*/codex.exe"))
        if not candidates:
            parser.error("未找到桌面端 Codex，请通过 --codex 指定")
        binary = max(candidates, key=lambda path: path.stat().st_mtime)
    binary = binary.resolve(strict=True)
    version = subprocess.check_output([str(binary), "--version"], text=True).strip()
    print(f"测试程序：{binary}\n版本：{version}\n目标：{args.url}\n模型：{model}", flush=True)

    # 健康检查不携带认证；实际请求由 Codex 按现有配置取得认证信息。
    health_url = args.url.removesuffix("/").removesuffix("/v1") + "/healthz"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(health_url, timeout=5) as response:
            health = json.load(response)
    except urllib.error.URLError as error:
        raise RuntimeError(f"网关不可达：{health_url}。请先从资源管理器双击启动新版网关，再重试。详细原因：{error.reason}") from error
    if health.get("status") != "ok":
        raise RuntimeError("网关健康检查未通过")

    # 临时目录隔离项目配置；只读沙箱约束模型可能产生的工具调用。
    with tempfile.TemporaryDirectory(prefix="codex-gateway-probe-") as directory:
        command = [str(binary), "exec", "--ephemeral", "--ignore-rules", "--skip-git-repo-check",
                   "--json", "-s", "read-only", "-C", directory]
        overrides = {
            "model_provider": provider,
            "model": model,
            "model_reasoning_effort": "low",
            "approval_policy": "never",
            "features.plugins": False,
            f"model_providers.{provider}.base_url": args.url,
            f"model_providers.{provider}.request_max_retries": 0,
            f"model_providers.{provider}.stream_max_retries": 0,
        }
        for key, value in overrides.items():
            command.extend(["-c", key + "=" + json.dumps(value)])
        if args.session:
            command.extend(["fork", args.session])
        if args.image:
            command.extend(["--image", str(args.image.resolve())])
        command.append(args.prompt)
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=args.timeout, encoding="utf-8", errors="replace")

    # 解析 JSONL，仅输出回复和错误，不输出工具参数、完整请求及认证信息。
    completed = False
    errors = []
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        kind = event.get("type")
        if kind == "turn.completed":
            completed = True
        elif kind in ("error", "turn.failed"):
            errors.append(event.get("message") or event.get("error", {}).get("message", "未知错误"))
        elif kind == "item.completed" and event.get("item", {}).get("type") == "agent_message":
            print("模型回复：", event["item"].get("text", ""))
    if config_path.read_bytes() != original:
        print("检测到 config.toml 在测试期间被其他进程更改；本脚本没有写入配置。", file=sys.stderr)
    else:
        print("config.toml 校验：未改变（SHA-256 " + hashlib.sha256(original).hexdigest()[:12] + "）")
    if result.returncode or not completed:
        for error in dict.fromkeys(errors):
            print("测试错误：", error, file=sys.stderr)
        if not errors:
            print("Codex 未完成测试：", result.stderr[-2000:], file=sys.stderr)
        return 1
    print("测试通过：Codex → 本地网关 → 上游。")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.TimeoutExpired:
        print("测试超时；日常 Codex 配置未修改。", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, RuntimeError) as error:
        print("测试失败：", error, file=sys.stderr)
        sys.exit(1)
