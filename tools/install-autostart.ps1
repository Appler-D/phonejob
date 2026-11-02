[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$TaskName = 'PhoneJobBridge',
  [Parameter(Mandatory = $true)]
  [string]$Workspace,
  [string]$PwaOrigin = '',
  [string]$PwaUrl = '',
  [string]$VapidSubject = '',
  [string]$DshHome = '',
  [string]$NodePath = '',
  [string]$Inbox = '',
  [int]$ApiPort = 7788,
  [int]$LocalPort = 7789,
  [switch]$Start
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath (Join-Path $repo 'bridge\index.js'))) {
  throw "bridge\index.js not found under $repo"
}
if (-not (Test-Path -LiteralPath $Workspace -PathType Container)) {
  throw "workspace does not exist: $Workspace"
}
if (-not $NodePath) {
  $NodePath = (Get-Command node -ErrorAction Stop).Source
}
if (-not (Test-Path -LiteralPath $NodePath)) {
  throw "node executable not found: $NodePath"
}
if (-not $DshHome) {
  $DshHome = Join-Path $env:USERPROFILE '.dsh'
}

$stateDir = Join-Path $env:LOCALAPPDATA 'PhoneJob'
$wrapper = Join-Path $stateDir 'start-bridge.ps1'
$log = Join-Path $stateDir 'bridge.log'

function Quote-Ps([string]$value) {
  return "'" + $value.Replace("'", "''") + "'"
}

$lines = @(
  "`$env:DSH_HOME = $(Quote-Ps $DshHome)",
  "`$env:PHONEJOB_WORKSPACES = $(Quote-Ps $Workspace)",
  "`$env:PHONEJOB_API_PORT = $(Quote-Ps ([string]$ApiPort))",
  "`$env:PHONEJOB_LOCAL_PORT = $(Quote-Ps ([string]$LocalPort))"
)
if ($PwaOrigin) { $lines += "`$env:PHONEJOB_PWA_ORIGIN = $(Quote-Ps $PwaOrigin)" }
if ($PwaUrl) { $lines += "`$env:PHONEJOB_PWA_URL = $(Quote-Ps $PwaUrl)" }
if ($VapidSubject) { $lines += "`$env:PHONEJOB_VAPID_SUBJECT = $(Quote-Ps $VapidSubject)" }
if ($Inbox) { $lines += "`$env:PHONEJOB_INBOX = $(Quote-Ps $Inbox)" }
$lines += "Set-Location -LiteralPath $(Quote-Ps $repo)"
$lines += "& $(Quote-Ps $NodePath) $(Quote-Ps 'bridge\index.js') *>> $(Quote-Ps $log)"

if (-not $PSCmdlet.ShouldProcess($TaskName, 'write wrapper and register logon task')) {
  return
}

New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
Set-Content -LiteralPath $wrapper -Value $lines -Encoding UTF8
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
  '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $wrapper
)
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -StartWhenAvailable `
  -RestartCount 3 `
  -RestartInterval (New-TimeSpan -Minutes 1) `
  -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask `
  -TaskName $TaskName `
  -Action $action `
  -Trigger $trigger `
  -Settings $settings `
  -Description 'PhoneJob bridge autostart' `
  -RunLevel Limited `
  -Force | Out-Null

Write-Host "registered scheduled task: $TaskName"
Write-Host "wrapper: $wrapper"
Write-Host "log: $log"
if ($Start) {
  Start-ScheduledTask -TaskName $TaskName
  Write-Host "started task: $TaskName"
}
