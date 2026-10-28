param(
    [string]$Executable = (Join-Path $PSScriptRoot '..\dist\codex-gateway-desktop-windows-amd64.exe')
)

$ErrorActionPreference = 'Stop'
$gatewayExecutable = (Resolve-Path -LiteralPath $Executable).Path
$gatewayDirectory = Split-Path -Parent $gatewayExecutable

# 通过现有桌面 Explorer 启动，避免将网关作为 Codex 测试进程的子进程。
$gatewayWindows = (New-Object -ComObject Shell.Application).Windows()
$gatewayLocation = 0
$gatewayRoot = 0
$gatewayWindow = 0
$gatewayDesktop = $gatewayWindows.FindWindowSW([ref]$gatewayLocation, [ref]$gatewayRoot, 8, [ref]$gatewayWindow, 1)
if ($null -eq $gatewayDesktop) {
    throw 'Explorer desktop is unavailable. Open the gateway EXE from Explorer.'
}
$gatewayDesktop.Document.Application.ShellExecute($gatewayExecutable, '', $gatewayDirectory, 'open', 0)
