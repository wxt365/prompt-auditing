#!/usr/bin/env bash

set -euo pipefail

release_version="${1:-}"
if [[ -z "${release_version}" ]]; then
  echo "用法: $0 <版本号> [提交标识]" >&2
  exit 2
fi
if [[ ! "${release_version}" =~ ^[0-9A-Za-z._+-]+$ ]]; then
  echo "版本号只能包含字母、数字、点、下划线、加号和连字符" >&2
  exit 2
fi

release_commit="${2:-$(git rev-parse --short=12 HEAD 2>/dev/null || true)}"
if [[ -z "${release_commit}" ]]; then
  echo "无法取得 Git 提交标识，拒绝生成发布产物" >&2
  exit 2
fi
if [[ ! "${release_commit}" =~ ^[0-9A-Fa-f]+$ ]]; then
  echo "提交标识必须是十六进制 Git 提交" >&2
  exit 2
fi

release_directory="${RELEASE_OUTPUT_DIR:-dist}"
windows_name="codex-gateway-windows-amd64.exe"
desktop_name="codex-gateway-desktop-windows-amd64.exe"
darwin_name="codex-gateway-darwin-arm64"
linker_flags="-s -w -X main.version=${release_version} -X main.commit=${release_commit}"

mkdir -p "${release_directory}"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${linker_flags}" -o "${release_directory}/${windows_name}" ./cmd/codex-gateway
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${linker_flags} -H=windowsgui" -o "${release_directory}/${desktop_name}" ./cmd/codex-gateway-desktop
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "${linker_flags}" -o "${release_directory}/${darwin_name}" ./cmd/codex-gateway

go version -m "${release_directory}/${windows_name}"
go version -m "${release_directory}/${desktop_name}"
go version -m "${release_directory}/${darwin_name}"
if command -v file >/dev/null 2>&1; then
  file "${release_directory}/${windows_name}"
  file "${release_directory}/${desktop_name}"
  file "${release_directory}/${darwin_name}"
fi

checksum() {
  local artifact="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${artifact}" | awk '{print $1}'
  else
    shasum -a 256 "${artifact}" | awk '{print $1}'
  fi
}

{
  printf '%s  %s\n' "$(checksum "${release_directory}/${windows_name}")" "${windows_name}"
  printf '%s  %s\n' "$(checksum "${release_directory}/${desktop_name}")" "${desktop_name}"
  printf '%s  %s\n' "$(checksum "${release_directory}/${darwin_name}")" "${darwin_name}"
} >"${release_directory}/SHA256SUMS"

echo "发布构建完成: ${release_directory}"
