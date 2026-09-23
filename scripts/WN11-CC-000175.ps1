<#
.SYNOPSIS
This PowerShell script remediates Windows 11 STIG WN11-CC-000175 by preventing
the Application Compatibility Program Inventory from collecting data and
sending the information to Microsoft.

.NOTES
Author          : Kekoa Giron
LinkedIn        : linkedin.com/in/kekoagiron/
GitHub          : github.com/kekoag6
Date Created    : 2026-09-21
Last Modified   : 2026-09-21
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN11-CC-000175
Severity        : CAT III
Vulnerability ID: V-253385
Documentation   : https://www.stigaview.com/products/win11/v2r8/WN11-CC-000175/

.TESTED ON
Date(s) Tested  : 2026-09-21
Tested By       : Kekoa Giron
Systems Tested  : Windows 11
PowerShell Ver. :

.USAGE
Run PowerShell as Administrator.

Example syntax:

PS C:\> .\remediate-WN11-CC-000175.ps1

This script configures the following registry value:

Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat
Value Name    : DisableInventory
Value Type    : REG_DWORD
Value Data    : 1

Manual Group Policy Path:

Computer Configuration
> Administrative Templates
> Windows Components
> Application Compatibility
> Turn off Inventory Collector
> Enabled
#>

# Windows 11 STIG WN11-CC-000175 remediation

# Prevent the Application Compatibility Program Inventory
# from collecting and sending system information to Microsoft

# Define registry path and value

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
$valueName = "DisableInventory"
$valueData = 1

# Create registry path if it does not exist

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Create or update DisableInventory as a DWORD

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
Write-Host "STIG WN11-CC-000175 remediation applied successfully."
Write-Host "Registry Path: $registryPath"
Write-Host "DisableInventory: $($result.DisableInventory)"
Write-Host ""

if ($result.DisableInventory -eq 1) {
    Write-Host "Validation: PASSED" -ForegroundColor Green
}
else {
    Write-Host "Validation: FAILED" -ForegroundColor Red
}
