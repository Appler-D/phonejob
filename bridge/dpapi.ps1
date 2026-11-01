param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('protect', 'unprotect')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

$encoded = [Console]::In.ReadToEnd().Trim()
if ([string]::IsNullOrWhiteSpace($encoded)) {
    throw 'No input'
}

$data = [Convert]::FromBase64String($encoded)
if ($Mode -eq 'protect') {
    $result = [Security.Cryptography.ProtectedData]::Protect($data, $null, 'CurrentUser')
}
else {
    $result = [Security.Cryptography.ProtectedData]::Unprotect($data, $null, 'CurrentUser')
}

[Console]::Out.Write([Convert]::ToBase64String($result))
