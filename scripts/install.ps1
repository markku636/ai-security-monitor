<#
  AI Security Monitor (ai-security-monitor) installer for Windows (Windows PowerShell 5.1 or PowerShell 7).

    irm https://github.com/markku636/ai-security-monitor/releases/latest/download/install.ps1 | iex

  Environment variables (the old ASA_* names still work):
    AI_SECURITY_MONITOR_VERSION         version to install (default: latest release)
    AI_SECURITY_MONITOR_INSTALL_DIR     install directory (default: %LOCALAPPDATA%\ai-security-monitor\bin,
                                        or %ProgramFiles%\ai-security-monitor with the system service; added to your PATH)
    AI_SECURITY_MONITOR_HUB_URL         Security Hub URL to enroll with (needs AI_SECURITY_MONITOR_ENROLL_KEY)
    AI_SECURITY_MONITOR_ENROLL_KEY      enroll key or client key from the Hub
    AI_SECURITY_MONITOR_SERVICE         none | user | system (start at login / at boot; system needs an administrator PowerShell)
    AI_SECURITY_MONITOR_DOWNLOAD_BASE   mirror that serves ai-security-monitor-<version>-windows-<arch>.exe and SHA256SUMS
    AI_SECURITY_MONITOR_NO_MODIFY_PATH  set to 1 to leave your PATH unchanged

  The executable is verified against the release's SHA256SUMS before it is installed.
#>
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# 新名 AI_SECURITY_MONITOR_<X> 優先，沒設才讀改名前的 ASA_<X>
function Get-Setting([string]$name) {
  $v = [Environment]::GetEnvironmentVariable("AI_SECURITY_MONITOR_$name")
  if (-not $v) { $v = [Environment]::GetEnvironmentVariable("ASA_$name") }
  return $v
}

$Repo = 'markku636/ai-security-monitor'
$Name = 'ai-security-monitor'
$Version = Get-Setting 'VERSION'
$Dir = Get-Setting 'INSTALL_DIR'
$Hub = Get-Setting 'HUB_URL'
$Key = Get-Setting 'ENROLL_KEY'
$Service = Get-Setting 'SERVICE'
if (-not $Service) { $Service = 'none' }
$Base = Get-Setting 'DOWNLOAD_BASE'
$NoModifyPath = Get-Setting 'NO_MODIFY_PATH'
# Security Hub 提供的 /install.ps1 會把自己的網址填在這裡（只給 AI_SECURITY_MONITOR_ENROLL_KEY 時註冊到這個 Hub）
$DefaultHub = ''

function Say([string]$m) { Write-Host "ai-security-monitor-install: $m" }
function Invoke-Monitor([string[]]$a) {
  & $script:Exe @a
  if ($LASTEXITCODE -ne 0) { throw "$Name $($a -join ' ') failed (exit $LASTEXITCODE)" }
}

if (@('none', 'user', 'system') -notcontains $Service) { throw 'AI_SECURITY_MONITOR_SERVICE must be none, user or system' }
if ($Key -and -not $Hub) { $Hub = $DefaultHub }
if ($Hub -and -not $Key) { throw 'AI_SECURITY_MONITOR_HUB_URL needs AI_SECURITY_MONITOR_ENROLL_KEY (an enroll key or client key from the Hub)' }
if ($Key -and -not $Hub) { throw 'AI_SECURITY_MONITOR_ENROLL_KEY needs AI_SECURITY_MONITOR_HUB_URL' }

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'x64' }
if (-not $Version) {
  $rel = Invoke-RestMethod -UseBasicParsing -Headers @{ 'User-Agent' = 'ai-security-monitor-install' } "https://api.github.com/repos/$Repo/releases/latest"
  $Version = [string]$rel.tag_name
  if (-not $Version) { throw 'could not find the latest release' }
}
$Version = $Version.TrimStart('v')
$asset = "$Name-$Version-windows-$arch.exe"
if (-not $Base) { $Base = "https://github.com/$Repo/releases/download/v$Version" }
$Base = $Base.TrimEnd('/')

if (-not $Dir) {
  if ($Service -eq 'system') {
    # 系統服務以 LocalSystem 執行：執行檔放在一般使用者不能改寫的 Program Files
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { throw 'AI_SECURITY_MONITOR_SERVICE=system installs into Program Files: run this from an administrator PowerShell' }
    $Dir = Join-Path $env:ProgramFiles $Name
  }
  else {
    $Dir = Join-Path $env:LOCALAPPDATA "$Name\bin"
  }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("$Name-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Say "downloading $asset from $Base"
  Invoke-WebRequest -UseBasicParsing -Headers @{ 'User-Agent' = 'ai-security-monitor-install' } "$Base/$asset" -OutFile (Join-Path $tmp "$Name.exe")
  Invoke-WebRequest -UseBasicParsing -Headers @{ 'User-Agent' = 'ai-security-monitor-install' } "$Base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')
  $expected = Get-Content (Join-Path $tmp 'SHA256SUMS') | ForEach-Object {
    $p = $_.Trim() -split '\s+'
    if ($p.Count -ge 2 -and $p[1].TrimStart('*') -eq $asset) { $p[0].ToLowerInvariant() }
  } | Select-Object -First 1
  if (-not $expected) { throw "$asset is not listed in SHA256SUMS" }
  $actual = (Get-FileHash (Join-Path $tmp "$Name.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { throw "SHA256 mismatch for $asset (expected $expected, got $actual)" }

  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $script:Exe = Join-Path $Dir "$Name.exe"
  if (Test-Path $script:Exe) {
    # 執行中的 exe 不能覆寫但可以改名；ai-security-monitor self-update 會清掉 .old-*
    Move-Item -Force $script:Exe ("$($script:Exe).old-" + (Get-Date -Format 'yyyyMMddHHmmss'))
  }
  Move-Item -Force (Join-Path $tmp "$Name.exe") $script:Exe
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
Say "installed $($script:Exe) ($(& $script:Exe version))"

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if ($NoModifyPath -ne '1' -and ($userPath -split ';') -notcontains $Dir) {
  [Environment]::SetEnvironmentVariable('Path', (($userPath.TrimEnd(';') + ';' + $Dir).TrimStart(';')), 'User')
  $env:Path = "$env:Path;$Dir"
  Say "added $Dir to your PATH (open a new terminal to use $Name)"
}

# 改名前（0.1.x）的 asa：新版的 service install 會移除舊的 asa 服務／登入啟動項目；舊執行檔留著不動
$legacyExe = Join-Path $env:LOCALAPPDATA 'asa\bin\asa.exe'
if (Test-Path $legacyExe) {
  Say "found the previous version at $legacyExe (asa); '$Name service install' replaces its start-at-boot entry, then you can delete $(Split-Path $legacyExe) and remove it from your PATH"
}

if ($Service -eq 'system') {
  # 系統服務用 C:\ProgramData\ai-security-monitor 與檔案密鑰庫：直接註冊到那裡
  $sysdir = Join-Path $env:ProgramData $Name
  $legacySysdir = Join-Path $env:ProgramData 'ai-security-agent'
  if ($Hub -and -not (Test-Path $sysdir) -and (Test-Path $legacySysdir)) {
    # 改名前的系統設定目錄：先複製過來（保留 agent_id 與註冊），舊服務在 service install 時移除
    Say "copying $legacySysdir to $sysdir"
    Get-ChildItem -Recurse -File $legacySysdir | Where-Object { $_.Name -ne 'watch.lock' } | ForEach-Object {
      $dst = Join-Path $sysdir $_.FullName.Substring($legacySysdir.Length).TrimStart('\')
      New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
      Copy-Item -Force $_.FullName $dst
    }
  }
  if ($Hub) { Invoke-Monitor @('--config-dir', $sysdir, '--secrets-backend', 'file', 'enroll', $Hub, '--key', $Key) }
  Invoke-Monitor @('--config-dir', $sysdir, 'service', 'install', '--system', '--yes')
}
else {
  if ($Hub) { Invoke-Monitor @('enroll', $Hub, '--key', $Key) }
  if ($Service -eq 'user') { Invoke-Monitor @('service', 'install', '--yes') }
}
Say "done. Next: $Name doctor; $Name scan; $Name service status"
