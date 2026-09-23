<#
.SYNOPSIS
This PowerShell script remediates Windows 11 STIG WN11-CC-000165 by restricting
unauthenticated RPC clients from connecting to the RPC server.

.NOTES
Author          : Kekoa Giron
LinkedIn        : linkedin.com/in/kekoagiron/
GitHub          : github.com/kekoag6
Date Created    : 2026-09-21
Last Modified   : 2026-09-21
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN11-CC-000165
Severity        : CAT II
Vulnerability ID: V-253383
Documentation   : https://www.stigaview.com/products/win11/v2r8/WN11-CC-000165/

.TESTED ON
Date(s) Tested  : 2026-09-21
Tested By       : Kekoa Giron
Systems Tested  : Windows 11
PowerShell Ver. :

.USAGE
Run PowerShell as Administrator.

Example syntax:

PS C:\> .\remediate-WN11-CC-000165.ps1

This script configures the following registry value:

Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc
Value Name    : RestrictRemoteClients
Value Type    : REG_DWORD
Value Data    : 1

Manual Group Policy Path:

Computer Configuration
> Administrative Templates
> System
> Remote Procedure Call
> Restrict Unauthenticated RPC clients
> Enabled
> Authenticated
#>

# Windows 11 STIG WN11-CC-000165 remediation

# Restrict unauthenticated RPC clients from connecting
# to the RPC server

# Define registry path and value

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
$valueName = "RestrictRemoteClients"
$valueData = 1

# Create registry path if it does not exist

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Create or update RestrictRemoteClients as a DWORD

New-ItemProperty `
    -Path $registryPath `
    -Name $valueName `
    -Value $valueData `
    -PropertyType DWord `
    -Force | Out-Null

# Verify the setting

$result = Get-ItemProperty `
    -Path $registryPath `
    -Name $valueName

Write-Host ""
Write-Host "STIG WN11-CC-000165 remediation applied successfully."
Write-Host "Registry Path: $registryPath"
Write-Host "RestrictRemoteClients: $($result.RestrictRemoteClients)"
Write-Host ""

if ($result.RestrictRemoteClients -eq 1) {
    Write-Host "Validation: PASSED" -ForegroundColor Green
}
else {
    Write-Host "Validation: FAILED" -ForegroundColor Red
}
