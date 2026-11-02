[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$TaskName = 'PhoneJobBridge',
  [switch]$KeepWrapper
)

$ErrorActionPreference = 'Stop'
if ($PSCmdlet.ShouldProcess($TaskName, 'unregister logon task')) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "unregistered scheduled task: $TaskName"
}
if (-not $KeepWrapper) {
  $wrapper = Join-Path $env:LOCALAPPDATA 'PhoneJob\start-bridge.ps1'
  if ($PSCmdlet.ShouldProcess($wrapper, 'remove wrapper')) {
    Remove-Item -LiteralPath $wrapper -Force -ErrorAction SilentlyContinue
    Write-Host "removed wrapper: $wrapper"
  }
}
