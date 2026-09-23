<#
.SYNOPSIS
This PowerShell script remediates Windows 11 STIG WN11-CC-000155 by disabling
Solicited Remote Assistance on the system.

.NOTES
Author          : Kekoa Giron
LinkedIn        : linkedin.com/in/kekoagiron/
GitHub          : github.com/kekoag6
Date Created    : 2026-09-21
Last Modified   : 2026-09-21
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN11-CC-000155
Severity        : CAT I
Vulnerability ID: V-253382
Documentation   : https://www.stigaview.com/products/win11/v2r8/WN11-CC-000155/

.TESTED ON
Date(s) Tested  : 2026-09-21
Tested By       : Kekoa Giron
Systems Tested  : Windows 11
PowerShell Ver. :

.USAGE
Run PowerShell as Administrator.

Example syntax:

PS C:\> .\remediate-WN11-CC-000155.ps1

This script configures the following registry value:

Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
Value Name    : fAllowToGetHelp
Value Type    : REG_DWORD
Value Data    : 0

Manual Group Policy Path:

Computer Configuration
> Administrative Templates
> System
> Remote Assistance
> Configure Solicited Remote Assistance
> Disabled
#>

# Windows 11 STIG WN11-CC-000155 remediation

# Disable Solicited Remote Assistance

# Define registry path and value

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$valueName = "fAllowToGetHelp"
$valueData = 0

# Create registry path if it does not exist

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Create or update fAllowToGetHelp as a DWORD

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
Write-Host "STIG WN11-CC-000155 remediation applied successfully."
Write-Host "Registry Path: $registryPath"
Write-Host "fAllowToGetHelp: $($result.fAllowToGetHelp)"
Write-Host ""

if ($result.fAllowToGetHelp -eq 0) {
    Write-Host "Validation: PASSED" -ForegroundColor Green
}
else {
    Write-Host "Validation: FAILED" -ForegroundColor Red
}
