<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Kekoa Giron
    LinkedIn        : linkedin.com/in/kekoagiron/
    GitHub          : github.com/kekoag6
    Date Created    : 2026-09-19
    Last Modified   : 2026-09-19
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000500/

.TESTED ON
    Date(s) Tested  : 2026-09-19
    Tested By       : Kekoa Giron
    Systems Tested  : Windows 11
    PowerShell Ver. : 

.USAGE
    Run PowerShell as Administrator.
    Example syntax:
    PS C:\> .\WN11-AU-000500.ps1
#>

# Windows 11 STIG remediation
# Configure Application Event Log maximum size to 32768 KB

# Define registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$valueName = "MaxSize"
$valueData = 32768    # 0x00008000 in decimal

# Create registry path if it does not exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Create or update MaxSize as a DWORD
New-ItemProperty `
    -Path $registryPath `
    -Name $valueName `
    -Value $valueData `
    -PropertyType DWord `
    -Force | Out-Null

# Verify the setting
$result = Get-ItemProperty -Path $registryPath -Name $valueName

Write-Host "STIG remediation applied successfully."
Write-Host "Registry Path: $registryPath"
Write-Host "MaxSize: $($result.MaxSize) KB"

