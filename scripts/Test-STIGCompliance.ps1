<#
.SYNOPSIS
    Audits a Windows 11 host against the ten DISA STIG controls remediated by the
    scripts in this repository and reports PASS / FAIL / NOT CONFIGURED for each.

.DESCRIPTION
    Read-only. Makes no changes to the system. Run it before remediation to capture
    a baseline, and again afterwards to evidence that each control landed.

    The Azure Trusted Launch control (WN11-00-000010) is not registry-backed and is
    reported as MANUAL — verify it against the VM security profile in Azure.

.NOTES
    Author          : Kekoa Giron
    GitHub          : github.com/kekoag6
    Version         : 1.0
    Scope           : Windows 11 STIG v2r8

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    PS C:\> .\Test-STIGCompliance.ps1
    PS C:\> .\Test-STIGCompliance.ps1 -CsvPath .\stig-baseline.csv
#>

[CmdletBinding()]
param(
    [string]$CsvPath
)

$controls = @(
    @{ StigId = 'WN11-AU-000500'; Severity = 'CAT II'
       Description = 'Application event log max size >= 32768 KB'
       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
       Name = 'MaxSize'; Expected = 32768; Comparison = 'AtLeast' }

    @{ StigId = 'WN11-CC-000100'; Severity = 'CAT II'
       Description = 'Print driver downloads over HTTP disabled'
       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
       Name = 'DisableWebPnPDownload'; Expected = 1; Comparison = 'Equals' }

    @{ StigId = 'WN11-CC-000105'; Severity = 'CAT II'
       Description = 'Web publishing / online ordering wizard downloads disabled'
       Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
       Name = 'NoWebServices'; Expected = 1; Comparison = 'Equals' }

    @{ StigId = 'WN11-CC-000120'; Severity = 'CAT II'
       Description = 'Network selection UI hidden on logon screen'
       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
       Name = 'DontDisplayNetworkSelectionUI'; Expected = 1; Comparison = 'Equals' }

    @{ StigId = 'WN11-CC-000155'; Severity = 'CAT I'
       Description = 'Solicited Remote Assistance disabled'
       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
       Name = 'fAllowToGetHelp'; Expected = 0; Comparison = 'Equals' }

    @{ StigId = 'WN11-CC-000165'; Severity = 'CAT II'
       Description = 'Unauthenticated RPC clients restricted'
       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
       Name = 'RestrictRemoteClients'; Expected = 1; Comparison = 'Equals' }

    @{ StigId = 'WN11-CC-000175'; Severity = 'CAT III'
       Description = 'Application Compatibility Program Inventory disabled'
       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
       Name = 'DisableInventory'; Expected = 1; Comparison = 'Equals' }

    @{ StigId = 'WN11-CC-000180'; Severity = 'CAT I'
       Description = 'AutoPlay disabled for non-volume devices'
       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
       Name = 'NoAutoplayfornonVolume'; Expected = 1; Comparison = 'Equals' }

    @{ StigId = 'WN11-CC-000185'; Severity = 'CAT I'
       Description = 'AutoRun commands prevented from executing'
       Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
       Name = 'NoAutorun'; Expected = 1; Comparison = 'Equals' }
)

$results = foreach ($c in $controls) {

    $actual = $null
    $status = 'NOT CONFIGURED'

    if (Test-Path $c.Path) {
        $prop = Get-ItemProperty -Path $c.Path -Name $c.Name -ErrorAction SilentlyContinue
        if ($null -ne $prop) {
            $actual = $prop.($c.Name)

            $status = switch ($c.Comparison) {
                'AtLeast' { if ($actual -ge $c.Expected) { 'PASS' } else { 'FAIL' } }
                default   { if ($actual -eq $c.Expected) { 'PASS' } else { 'FAIL' } }
            }
        }
    }

    [pscustomobject]@{
        StigId      = $c.StigId
        Severity    = $c.Severity
        Status      = $status
        Expected    = $c.Expected
        Actual      = if ($null -eq $actual) { '(not set)' } else { $actual }
        Description = $c.Description
    }
}

# WN11-00-000010 is an Azure VM security-profile setting, not a registry value.
$results += [pscustomobject]@{
    StigId      = 'WN11-00-000010'
    Severity    = 'CAT II'
    Status      = 'MANUAL'
    Expected    = 'TrustedLaunch + SecureBoot + vTPM'
    Actual      = 'verify in Azure'
    Description = 'Azure Trusted Launch, Secure Boot, and vTPM enabled'
}

Write-Host ''
Write-Host 'Windows 11 STIG Compliance Check' -ForegroundColor Cyan
Write-Host "Host: $env:COMPUTERNAME    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ''

foreach ($r in $results) {
    $color = switch ($r.Status) {
        'PASS'   { 'Green' }
        'FAIL'   { 'Red' }
        'MANUAL' { 'Yellow' }
        default  { 'DarkYellow' }
    }
    Write-Host ('{0,-16} {1,-8} ' -f $r.StigId, $r.Severity) -NoNewline
    Write-Host ('{0,-16}' -f $r.Status) -ForegroundColor $color -NoNewline
    Write-Host $r.Description
}

$pass = ($results | Where-Object Status -eq 'PASS').Count
$fail = ($results | Where-Object Status -in 'FAIL','NOT CONFIGURED').Count

Write-Host ''
Write-Host "Passed: $pass    Failed / not configured: $fail    Manual: 1"
Write-Host ''

if ($CsvPath) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation
    Write-Host "Results written to $CsvPath" -ForegroundColor Cyan
    Write-Host ''
}

$results
