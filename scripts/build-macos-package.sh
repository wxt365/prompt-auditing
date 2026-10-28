#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "macOS 桌面包需要在安装 Xcode Command Line Tools 的 Mac 上构建。" >&2
  exit 2
fi
package_version="${1:-0.1.0}"
package_arch="${2:-$(go env GOARCH)}"
if [[ ! "$package_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$package_arch" != arm64 && "$package_arch" != amd64 ]]; then
  echo "用法: bash scripts/build-macos-package.sh <数字版本，如 0.1.0> [arm64|amd64]" >&2
  exit 2
fi
package_root="$(cd "$(dirname "$0")/.." && pwd)"
package_name="codex-gateway-macos-${package_arch}-${package_version}"
package_output="${package_root}/dist/${package_name}"
package_app="${package_output}/Codex Security Gateway.app"
if [[ -e "$package_output" || -e "${package_output}.zip" || -e "${package_output}.zip.sha256" ]]; then
  echo "目标包已存在，请使用新的版本号，避免覆盖已分发的包。" >&2
  exit 2
fi
xcrun --find clang >/dev/null
mkdir -p "${package_app}/Contents/MacOS"
cp "${package_root}/scripts/macos/Info.plist" "${package_app}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${package_version}" "${package_app}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${package_version}" "${package_app}/Contents/Info.plist"
cd "$package_root"
CGO_ENABLED=1 GOOS=darwin GOARCH="$package_arch" \
  CGO_CFLAGS="${CGO_CFLAGS:-} -mmacosx-version-min=13.0" \
  CGO_LDFLAGS="${CGO_LDFLAGS:-} -mmacosx-version-min=13.0" \
  go build -trimpath -ldflags "-X main.version=${package_version}" \
  -o "${package_app}/Contents/MacOS/codex-gateway" ./cmd/codex-gateway-desktop
cp "${package_root}/docs/macos-desktop.md" "${package_output}/使用说明.md"
# 默认临时签名供本机测试；Developer ID 签名同时启用公证所需的运行时保护和时间戳。
package_identity="${MACOS_SIGN_IDENTITY:--}"
if [[ "$package_identity" == - ]]; then
  codesign --force --sign - --timestamp=none "$package_app"
else
  codesign --force --sign "$package_identity" --options runtime --timestamp "$package_app"
fi
codesign --verify --strict "$package_app"
plutil -lint "${package_app}/Contents/Info.plist"
(
  cd "$package_output"
  shasum -a 256 "Codex Security Gateway.app/Contents/MacOS/codex-gateway" "使用说明.md" > SHA256SUMS.txt
)
ditto -c -k --sequesterRsrc --keepParent "$package_output" "${package_output}.zip"
(
  cd "${package_root}/dist"
  shasum -a 256 "${package_name}.zip" > "${package_name}.zip.sha256"
)
echo "macOS 桌面包: ${package_output}.zip"
