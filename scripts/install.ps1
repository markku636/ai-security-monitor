<#
  ai-security-agent (asa) installer for Windows (Windows PowerShell 5.1 or PowerShell 7).

    irm https://github.com/markku636/ai-security-agent/releases/latest/download/install.ps1 | iex

  Environment variables:
    ASA_VERSION        version to install (default: latest release)
    ASA_INSTALL_DIR    install directory (default: %LOCALAPPDATA%\asa\bin, added to your PATH)
    ASA_HUB_URL        Security Hub URL to enroll with (needs ASA_ENROLL_KEY)
    ASA_ENROLL_KEY     enroll key or client key from the Hub
    ASA_SERVICE        none | user | system (start at login / at boot)
    ASA_DOWNLOAD_BASE  mirror that serves asa-<version>-windows-<arch>.exe and SHA256SUMS
    ASA_NO_MODIFY_PATH set to 1 to leave your PATH unchanged

  The executable is verified against the release's SHA256SUMS before it is installed.
#>
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Repo = 'markku636/ai-security-agent'
$Version = $env:ASA_VERSION
$Dir = $env:ASA_INSTALL_DIR
$Hub = $env:ASA_HUB_URL
$Key = $env:ASA_ENROLL_KEY
$Service = if ($env:ASA_SERVICE) { $env:ASA_SERVICE } else { 'none' }
$Base = $env:ASA_DOWNLOAD_BASE
# Security Hub 提供的 /install.ps1 會把自己的網址填在這裡（只給 ASA_ENROLL_KEY 時註冊到這個 Hub）
$DefaultHub = ''

function Say([string]$m) { Write-Host "asa-install: $m" }
function Invoke-Asa([string[]]$a) {
  & $script:Exe @a
  if ($LASTEXITCODE -ne 0) { throw "asa $($a -join ' ') failed (exit $LASTEXITCODE)" }
}

if (@('none', 'user', 'system') -notcontains $Service) { throw 'ASA_SERVICE must be none, user or system' }
if ($Key -and -not $Hub) { $Hub = $DefaultHub }
if ($Hub -and -not $Key) { throw 'ASA_HUB_URL needs ASA_ENROLL_KEY (an enroll key or client key from the Hub)' }
if ($Key -and -not $Hub) { throw 'ASA_ENROLL_KEY needs ASA_HUB_URL' }

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'x64' }
if (-not $Version) {
  $rel = Invoke-RestMethod -UseBasicParsing -Headers @{ 'User-Agent' = 'asa-install' } "https://api.github.com/repos/$Repo/releases/latest"
  $Version = [string]$rel.tag_name
  if (-not $Version) { throw 'could not find the latest release' }
}
$Version = $Version.TrimStart('v')
$asset = "asa-$Version-windows-$arch.exe"
if (-not $Base) { $Base = "https://github.com/$Repo/releases/download/v$Version" }
$Base = $Base.TrimEnd('/')

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('asa-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Say "downloading $asset from $Base"
  Invoke-WebRequest -UseBasicParsing -Headers @{ 'User-Agent' = 'asa-install' } "$Base/$asset" -OutFile (Join-Path $tmp 'asa.exe')
  Invoke-WebRequest -UseBasicParsing -Headers @{ 'User-Agent' = 'asa-install' } "$Base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')
  $expected = Get-Content (Join-Path $tmp 'SHA256SUMS') | ForEach-Object {
    $p = $_.Trim() -split '\s+'
    if ($p.Count -ge 2 -and $p[1].TrimStart('*') -eq $asset) { $p[0].ToLowerInvariant() }
  } | Select-Object -First 1
  if (-not $expected) { throw "$asset is not listed in SHA256SUMS" }
  $actual = (Get-FileHash (Join-Path $tmp 'asa.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { throw "SHA256 mismatch for $asset (expected $expected, got $actual)" }

  if (-not $Dir) { $Dir = Join-Path $env:LOCALAPPDATA 'asa\bin' }
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $script:Exe = Join-Path $Dir 'asa.exe'
  if (Test-Path $script:Exe) {
    # 執行中的 exe 不能覆寫但可以改名；asa self-update 會清掉 .old-*
    Move-Item -Force $script:Exe ("$($script:Exe).old-" + (Get-Date -Format 'yyyyMMddHHmmss'))
  }
  Move-Item -Force (Join-Path $tmp 'asa.exe') $script:Exe
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
Say "installed $($script:Exe) ($(& $script:Exe version))"

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if ($env:ASA_NO_MODIFY_PATH -ne '1' -and ($userPath -split ';') -notcontains $Dir) {
  [Environment]::SetEnvironmentVariable('Path', (($userPath.TrimEnd(';') + ';' + $Dir).TrimStart(';')), 'User')
  $env:Path = "$env:Path;$Dir"
  Say "added $Dir to your PATH (open a new terminal to use asa)"
}

if ($Service -eq 'system') {
  # 系統服務用 C:\ProgramData\ai-security-agent 與檔案密鑰庫：直接註冊到那裡；asa 需要時會請求系統管理員權限
  $sysdir = Join-Path $env:ProgramData 'ai-security-agent'
  if ($Hub) { Invoke-Asa @('--config-dir', $sysdir, '--secrets-backend', 'file', 'enroll', $Hub, '--key', $Key) }
  Invoke-Asa @('--config-dir', $sysdir, 'service', 'install', '--system', '--yes')
}
else {
  if ($Hub) { Invoke-Asa @('enroll', $Hub, '--key', $Key) }
  if ($Service -eq 'user') { Invoke-Asa @('service', 'install', '--yes') }
}
Say 'done. Next: asa doctor; asa scan; asa service status'
