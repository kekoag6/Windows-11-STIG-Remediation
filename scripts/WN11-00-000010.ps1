<#
.SYNOPSIS
This PowerShell script remediates Windows 11 STIG WN11-00-000010 by enabling
Azure Trusted Launch, Secure Boot, and virtual TPM (vTPM) on a compatible Azure VM.

.NOTES
Author          : Kekoa Giron
LinkedIn        : linkedin.com/in/kekoagiron/
GitHub          : github.com/kekoag6
Date Created    : 2026-09-21
Last Modified   : 2026-09-21
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN11-00-000010
Severity        : CAT II
Vulnerability ID: V-253255
Documentation   : https://www.stigaview.com/products/win11/v2r8/WN11-00-000010/
Azure Docs      : https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-existing-vm

.TESTED ON
Date(s) Tested  : 2026-09-21
Tested By       : Kekoa Giron
Systems Tested  : Microsoft Azure Windows 11 VM
PowerShell Ver. : Azure Cloud Shell / Az PowerShell

.REQUIREMENTS
- Azure PowerShell (Az module)
- Azure VM compatible with Trusted Launch
- Generation 2 / Trusted Launch-compatible VM configuration
- Sufficient Azure RBAC permissions to:
  - Read the VM
  - Deallocate the VM
  - Modify the VM security profile
  - Start the VM

.MANUAL REMEDIATION
This STIG can also be remediated manually through the Azure Portal.

1. Sign in to the Azure Portal.
2. Navigate to Virtual Machines.
3. Select the affected Windows 11 VM.
4. Navigate to:

   Settings > Configuration

5. Locate the Security type setting.
6. Change the Security type from:

   Standard

   to:

   Trusted launch

7. Enable the following security features:

   - Secure Boot
   - vTPM

8. Select Save.
9. Allow Azure to deallocate the VM if required.
10. Start the VM after the configuration change is complete.
11. Connect to the Windows 11 VM.
12. Validate the TPM configuration using:

   tpm.msc

   or:

   Get-Tpm

Expected TPM state:

TpmPresent : True
TpmReady   : True

The TPM Management console should also report that the TPM is ready for use
and that the specification version is 2.0.

NOTE:
The Azure Portal method requires the same Azure permissions as the PowerShell
method. If the account does not have permission to deallocate the VM or modify
its security profile, an Azure administrator must perform the change or a new
VM must be deployed with Trusted Launch and vTPM enabled.

.USAGE
Run this script from Azure Cloud Shell using PowerShell or from a system
with the Az PowerShell module installed and authenticated.

Example syntax:

PS> .\remediate-WN11-00-000010.ps1 `
      -ResourceGroupName "my-resource-group" `
      -VMName "windows-11-vm"

After the VM starts, validate inside Windows with:

PS> Get-Tpm

Expected:

TpmPresent : True
TpmReady   : True

You can also run:

tpm.msc

The TPM status should indicate that the TPM is ready for use and the
specification version should be 2.0.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$VMName
)

# Windows 11 STIG WN11-00-000010 remediation
# Enable Azure Trusted Launch, Secure Boot, and virtual TPM (vTPM)

Write-Host "WN11-00-000010 remediation starting..." -ForegroundColor Cyan
Write-Host "VM: $VMName"
Write-Host "Resource Group: $ResourceGroupName"
Write-Host ""

# Confirm the VM exists

try {
    $vm = Get-AzVM `
        -ResourceGroupName $ResourceGroupName `
        -Name $VMName `
        -ErrorAction Stop

    Write-Host "VM located successfully." -ForegroundColor Green
}
catch {
    Write-Error "Unable to locate VM '$VMName' in resource group '$ResourceGroupName'."
    exit 1
}

# Deallocate the VM before changing its security profile

try {
    Write-Host "Deallocating VM..." -ForegroundColor Yellow

    Stop-AzVM `
        -ResourceGroupName $ResourceGroupName `
        -Name $VMName `
        -Force `
        -ErrorAction Stop

    Write-Host "VM successfully deallocated." -ForegroundColor Green
}
catch {
    Write-Error "Unable to deallocate the VM. Verify Azure RBAC permissions."
    exit 1
}

# Enable Trusted Launch, Secure Boot, and virtual TPM

try {
    Write-Host "Enabling Trusted Launch, Secure Boot, and vTPM..." -ForegroundColor Yellow

    Get-AzVM `
        -ResourceGroupName $ResourceGroupName `
        -VMName $VMName |
    Update-AzVM `
        -SecurityType TrustedLaunch `
        -EnableSecureBoot $true `
        -EnableVtpm $true `
        -ErrorAction Stop

    Write-Host "Trusted Launch security configuration applied." -ForegroundColor Green
}
catch {
    Write-Error "Unable to modify the VM security profile."
    Write-Error "The VM may be incompatible with Trusted Launch or the account may lack the required Azure RBAC permissions."
    exit 1
}

# Verify Azure-side security configuration

try {
    $updatedVM = Get-AzVM `
        -ResourceGroupName $ResourceGroupName `
        -Name $VMName `
        -ErrorAction Stop

    Write-Host ""
    Write-Host "Azure security configuration:" -ForegroundColor Cyan
    Write-Host "Security Type : $($updatedVM.SecurityProfile.SecurityType)"
    Write-Host "Secure Boot   : $($updatedVM.SecurityProfile.UefiSettings.SecureBootEnabled)"
    Write-Host "vTPM          : $($updatedVM.SecurityProfile.UefiSettings.VTpmEnabled)"
}
catch {
    Write-Warning "Unable to retrieve the updated Azure security configuration."
}

# Start the VM

try {
    Write-Host ""
    Write-Host "Starting VM..." -ForegroundColor Yellow

    Start-AzVM `
        -ResourceGroupName $ResourceGroupName `
        -Name $VMName `
        -ErrorAction Stop

    Write-Host "VM started successfully." -ForegroundColor Green
}
catch {
    Write-Error "The security configuration was updated, but the VM could not be started."
    exit 1
}

# Display post-remediation validation instructions

Write-Host ""
Write-Host "STIG WN11-00-000010 remediation complete." -ForegroundColor Green
Write-Host ""
Write-Host "Validate from inside the Windows 11 VM with:"
Write-Host ""
Write-Host "Get-Tpm" -ForegroundColor Cyan
Write-Host ""
Write-Host "Expected:"
Write-Host "TpmPresent : True"
Write-Host "TpmReady   : True"
Write-Host ""
Write-Host "Also run tpm.msc and verify that TPM 2.0 is enabled and ready for use."
