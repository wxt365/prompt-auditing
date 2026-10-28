param(
    [string]$GoExecutable = 'go',
    [string]$GatewayVersion = 'trial-20261028.3',
    [string]$PackageName = 'codex-gateway-windows-x64-20261028-r3'
)

$ErrorActionPreference = 'Stop'
$GatewayRoot = Split-Path -Parent $PSScriptRoot
if ($GatewayVersion -notmatch '^[A-Za-z0-9._-]+$' -or $PackageName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
    throw '版本或包名称无效。'
}
$GatewayOutput = Join-Path $GatewayRoot (Join-Path 'dist' $PackageName)
$GatewayArchive = "$GatewayOutput.zip"
if ((Test-Path -LiteralPath $GatewayOutput) -or (Test-Path -LiteralPath $GatewayArchive)) {
    throw '目标包已存在，请使用新的 PackageName，避免覆盖已分发的包。'
}
New-Item -ItemType Directory -Path $GatewayOutput | Out-Null
$GatewayOldGOOS = $env:GOOS
$GatewayOldGOARCH = $env:GOARCH
$GatewayOldCGO = $env:CGO_ENABLED
Push-Location -LiteralPath $GatewayRoot
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    $GatewayBinary = Join-Path $GatewayOutput 'codex-gateway.exe'
    & $GoExecutable build -trimpath -ldflags "-H=windowsgui -X main.version=$GatewayVersion" -o $GatewayBinary ./cmd/codex-gateway-desktop
    if ($LASTEXITCODE -ne 0) { throw 'Windows 程序构建失败。' }
    $GatewayGuide = Join-Path $GatewayOutput '使用说明.html'
    $GatewayGuideSource = Join-Path $GatewayRoot 'docs/windows-trial-guide.html'
    # 使用与本次构建一致的版本号生成说明，避免包内标识不一致。
    $GatewayGuideText = [IO.File]::ReadAllText($GatewayGuideSource).Replace('trial-20261028.3', $GatewayVersion)
    [IO.File]::WriteAllText($GatewayGuide, $GatewayGuideText, (New-Object Text.UTF8Encoding($false)))
    $GatewayChecksums = foreach ($GatewayFile in @($GatewayBinary, $GatewayGuide)) {
        $GatewayHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $GatewayFile).Hash.ToLowerInvariant()
        "$GatewayHash  $([IO.Path]::GetFileName($GatewayFile))"
    }
    $GatewayChecksumFile = Join-Path $GatewayOutput 'SHA256SUMS.txt'
    [IO.File]::WriteAllLines($GatewayChecksumFile, $GatewayChecksums, (New-Object Text.UTF8Encoding($false)))
    # 明确只打包这三个文件，避免混入本机配置、日志或历史构建。
    Compress-Archive -LiteralPath @($GatewayBinary, $GatewayGuide, $GatewayChecksumFile) -DestinationPath $GatewayArchive -CompressionLevel Optimal
    $GatewayArchiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $GatewayArchive).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$GatewayArchive.sha256", "$GatewayArchiveHash  $PackageName.zip`r`n", (New-Object Text.UTF8Encoding($false)))
    Write-Output "Package: $GatewayArchive"
} finally {
    Pop-Location
    $env:GOOS = $GatewayOldGOOS
    $env:GOARCH = $GatewayOldGOARCH
    $env:CGO_ENABLED = $GatewayOldCGO
}
