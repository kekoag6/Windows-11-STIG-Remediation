<#
.SYNOPSIS
This PowerShell script remediates Windows 11 STIG WN11-CC-000100 by preventing
Windows from downloading print driver packages over HTTP.

.NOTES
Author          : Kekoa Giron
LinkedIn        : linkedin.com/in/kekoagiron/
GitHub          : github.com/kekoag6
Date Created    : 2026-09-21
Last Modified   : 2026-09-21
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN11-CC-000100
Severity        : CAT II
Vulnerability ID: V-253374
Documentation   : https://www.stigaview.com/products/win11/v2r8/WN11-CC-000100/

.TESTED ON
Date(s) Tested  : 2026-09-21
Tested By       : Kekoa Giron
Systems Tested  : Windows 11
PowerShell Ver. :

.USAGE
Run PowerShell as Administrator.

Example syntax:

PS C:\> .\remediate-WN11-CC-000100.ps1

The script creates or updates the following registry value:

Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers
Value Name    : DisableWebPnPDownload
Value Type    : REG_DWORD
Value Data    : 1
#>

# Windows 11 STIG WN11-CC-000100 remediation
# Prevent downloading print driver packages over HTTP

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$valueName = "DisableWebPnPDownload"
$valueData = 1

# Create the registry path if it does not exist

if (-not (Test-Path $registryPath)) {
    New-Item `
        -Path $registryPath `
        -Force | Out-Null
}

# Create or update DisableWebPnPDownload as a DWORD

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
Write-Host "STIG WN11-CC-000100 remediation applied successfully." -ForegroundColor Green
Write-Host "Registry Path: $registryPath"
Write-Host "DisableWebPnPDownload: $($result.DisableWebPnPDownload)"
Write-Host ""

if ($result.DisableWebPnPDownload -eq 1) {
    Write-Host "Validation: PASSED" -ForegroundColor Green
}
else {
    Write-Host "Validation: FAILED" -ForegroundColor Red
}
