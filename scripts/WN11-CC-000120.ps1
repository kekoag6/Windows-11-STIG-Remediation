<#
.SYNOPSIS
This PowerShell script remediates Windows 11 STIG WN11-CC-000120 by preventing
the network selection user interface (UI) from being displayed on the Windows
logon screen.

.NOTES
Author          : Kekoa Giron
LinkedIn        : linkedin.com/in/kekoagiron/
GitHub          : github.com/kekoag6
Date Created    : 2026-09-21
Last Modified   : 2026-09-21
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN11-CC-000120
Severity        : CAT II
Vulnerability ID: V-253378
Documentation   : https://www.stigaview.com/products/win11/v2r8/WN11-CC-000120/

.TESTED ON
Date(s) Tested  : 2026-09-21
Tested By       : Kekoa Giron
Systems Tested  : Windows 11
PowerShell Ver. :

.USAGE
Run PowerShell as Administrator.

Example syntax:

PS C:\> .\remediate-WN11-CC-000120.ps1

This script configures the following registry value:

Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows\System
Value Name    : DontDisplayNetworkSelectionUI
Value Type    : REG_DWORD
Value Data    : 1

Manual Group Policy Path:

Computer Configuration
> Administrative Templates
> System
> Logon
> Do not display network selection UI
> Enabled
#>

# Windows 11 STIG WN11-CC-000120 remediation

# Prevent the network selection UI from being displayed
# on the Windows logon screen

# Define registry path and value

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$valueName = "DontDisplayNetworkSelectionUI"
$valueData = 1

# Create registry path if it does not exist

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Create or update DontDisplayNetworkSelectionUI as a DWORD

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
Write-Host "STIG WN11-CC-000120 remediation applied successfully."
Write-Host "Registry Path: $registryPath"
Write-Host "DontDisplayNetworkSelectionUI: $($result.DontDisplayNetworkSelectionUI)"
Write-Host ""

if ($result.DontDisplayNetworkSelectionUI -eq 1) {
    Write-Host "Validation: PASSED" -ForegroundColor Green
}
else {
    Write-Host "Validation: FAILED" -ForegroundColor Red
}
