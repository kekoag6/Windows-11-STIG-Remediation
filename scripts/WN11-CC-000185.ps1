<#
.SYNOPSIS
This PowerShell script remediates Windows 11 STIG WN11-CC-000185 by preventing
AutoRun commands from executing on the system.

.NOTES
Author          : Kekoa Giron
LinkedIn        : linkedin.com/in/kekoagiron/
GitHub          : github.com/kekoag6
Date Created    : 2026-09-21
Last Modified   : 2026-09-21
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN11-CC-000185
Severity        : CAT I
Vulnerability ID: V-253387
Documentation   : https://www.stigaview.com/products/win11/v2r8/WN11-CC-000185/

.TESTED ON
Date(s) Tested  : 2026-09-21
Tested By       : Kekoa Giron
Systems Tested  : Windows 11
PowerShell Ver. :

.USAGE
Run PowerShell as Administrator.

Example syntax:

PS C:\> .\remediate-WN11-CC-000185.ps1

This script configures the following registry value:

Registry Path : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
Value Name    : NoAutorun
Value Type    : REG_DWORD
Value Data    : 1

Manual Group Policy Path:

Computer Configuration
> Administrative Templates
> Windows Components
> AutoPlay Policies
> Set the default behavior for AutoRun
> Enabled
> Do not execute any autorun commands
#>

# Windows 11 STIG WN11-CC-000185 remediation

# Prevent AutoRun commands from executing

# Define registry path and value

$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName = "NoAutorun"
$valueData = 1

# Create registry path if it does not exist

if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Create or update NoAutorun as a DWORD

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
Write-Host "STIG WN11-CC-000185 remediation applied successfully."
Write-Host "Registry Path: $registryPath"
Write-Host "NoAutorun: $($result.NoAutorun)"
Write-Host ""

if ($result.NoAutorun -eq 1) {
    Write-Host "Validation: PASSED" -ForegroundColor Green
}
else {
    Write-Host "Validation: FAILED" -ForegroundColor Red
}
