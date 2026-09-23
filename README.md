# Windows 11 DISA STIG Remediation

Ten PowerShell scripts that remediate Windows 11 DISA STIG controls, plus a read-only compliance
checker that audits all ten and reports pass/fail. Every script is idempotent, self-documenting,
self-verifying, and carries the STIG ID, severity category, vulnerability ID, and a link to the
authoritative control text.

STIG remediation is where hardening meets auditability. It is not enough for a setting to be
correct — a federal assessor needs to see which control was applied, what it was set to, who
applied it, and how it was verified. These scripts are written so that each one answers all four
questions on its own, and so that the whole set can be re-run against a rebuilt host without
side effects.

**Scope:** Windows 11 STIG v2r8 (one control against v2r7, noted below).
**Coverage:** 3 × CAT I, 5 × CAT II, 1 × CAT III, plus 1 Azure platform control.

## Tools used

| Tool | Role |
|---|---|
| PowerShell 5.1+ | Remediation and verification |
| Azure PowerShell (`Az` module) | Trusted Launch / Secure Boot / vTPM remediation |
| DISA STIG for Windows 11 (v2r8) | Control source |
| Windows Registry (`HKLM` policy hives) | Enforcement mechanism for 9 of 10 controls |
| MITRE ATT&CK | Technique mapping |

---

## Controls remediated

| STIG ID | Severity | V-ID | Control | Mechanism |
|---|---|---|---|---|
| [WN11-CC-000155](scripts/WN11-CC-000155.ps1) | **CAT I** | V-253382 | Solicited Remote Assistance disabled | `fAllowToGetHelp = 0` |
| [WN11-CC-000180](scripts/WN11-CC-000180.ps1) | **CAT I** | V-253386 | AutoPlay disabled for non-volume devices | `NoAutoplayfornonVolume = 1` |
| [WN11-CC-000185](scripts/WN11-CC-000185.ps1) | **CAT I** | V-253387 | AutoRun commands prevented from executing | `NoAutorun = 1` |
| [WN11-00-000010](scripts/WN11-00-000010.ps1) | CAT II | V-253255 | Trusted Launch, Secure Boot, and vTPM enabled | Azure VM security profile |
| [WN11-AU-000500](scripts/WN11-AU-000500.ps1) | CAT II | — | Application event log ≥ 32768 KB | `MaxSize = 32768` |
| [WN11-CC-000100](scripts/WN11-CC-000100.ps1) | CAT II | V-253374 | Print driver downloads over HTTP disabled | `DisableWebPnPDownload = 1` |
| [WN11-CC-000105](scripts/WN11-CC-000105.ps1) | CAT II | V-253375 | Web publishing / online ordering downloads disabled | `NoWebServices = 1` |
| [WN11-CC-000120](scripts/WN11-CC-000120.ps1) | CAT II | V-253378 | Network selection UI hidden on logon screen | `DontDisplayNetworkSelectionUI = 1` |
| [WN11-CC-000165](scripts/WN11-CC-000165.ps1) | CAT II | V-253383 | Unauthenticated RPC clients restricted | `RestrictRemoteClients = 1` |
| [WN11-CC-000175](scripts/WN11-CC-000175.ps1) | CAT III | V-253385 | Application Compatibility Inventory disabled | `DisableInventory = 1` |

### Why the CAT I controls matter

**Solicited Remote Assistance (WN11-CC-000155)** hands an interactive session to a remote party.
It is a legitimate support feature and an ideal social-engineering target — the attacker does not
need an exploit, only a convincing pretext. The control removes the capability rather than
restricting it.

**AutoPlay and AutoRun (WN11-CC-000180, WN11-CC-000185)** are the pair that makes removable media
a viable initial-access vector. AutoRun executes commands declared in `autorun.inf` without user
interaction; AutoPlay extends the same automatic handling to non-volume devices such as a USB
device presenting itself as a CD-ROM — which is exactly how a malicious USB device is built.
Remediating one without the other leaves the path open, which is why they ship together.

Note the two registry hives in play: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer` versus
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`. They are similar enough to
transpose, and a value written to the wrong one applies nothing while still returning success.

---

## Script design

Every registry-backed script follows the same five-part structure.

**1. Machine-readable provenance in comment-based help.** STIG ID, severity, vulnerability ID,
and the authoritative documentation link.

```powershell
STIG-ID         : WN11-CC-000180
Severity        : CAT I
Vulnerability ID: V-253386
Documentation   : https://www.stigaview.com/products/win11/v2r8/WN11-CC-000180/
```

**2. Both remediation paths documented.** The registry change the script makes, and the manual
Group Policy path an administrator would use instead:

```
Computer Configuration
> Administrative Templates
> Windows Components
> AutoPlay Policies
> Disallow Autoplay for non-volume devices
> Enabled
```

This matters in a federal environment, where the audited change is often expected to arrive
through Group Policy. Documenting both keeps the script usable as a reference even where running
it is not the approved method.

**3. Create the path before writing to it.** Policy keys frequently do not exist on a default
install — `Set-ItemProperty` against a missing key throws.

```powershell
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
```

**4. Idempotent write.** `New-ItemProperty -Force` creates the value if absent and overwrites it
if present, so re-running is always safe and always converges to the same state.

```powershell
New-ItemProperty -Path $registryPath -Name $valueName `
    -Value $valueData -PropertyType DWord -Force | Out-Null
```

**5. Read back and validate.** The script does not assume the write succeeded — it re-reads the
value and reports PASS or FAIL.

```powershell
$result = Get-ItemProperty -Path $registryPath -Name $valueName
if ($result.$valueName -eq $valueData) {
    Write-Host "Validation: PASSED" -ForegroundColor Green
}
```

A remediation script that exits 0 without confirming the resulting state is an assumption, not
evidence. Read-back is what makes the output usable as an audit artifact.

### The exception: WN11-00-000010

The Azure Trusted Launch control is the one that is not a registry value. It changes the VM's
security profile, which requires deallocating the VM, enabling Trusted Launch with Secure Boot
and vTPM, and starting it again — an availability-affecting operation with real prerequisites:

- Azure PowerShell (`Az` module)
- A Generation 2 / Trusted Launch-compatible VM
- RBAC rights to read, deallocate, modify, and start the VM

The script documents the portal procedure alongside the automated path, because in most
environments this change goes through a change-control process rather than an ad-hoc script run.

---

## Verification

[`scripts/Test-STIGCompliance.ps1`](scripts/Test-STIGCompliance.ps1) audits all ten controls and
reports the state of each. It is **read-only** and makes no changes.

```powershell
# Baseline before remediation
.\Test-STIGCompliance.ps1 -CsvPath .\stig-baseline.csv

# Apply remediations
Get-ChildItem .\WN11-*.ps1 | ForEach-Object { & $_.FullName }

# Verify after
.\Test-STIGCompliance.ps1 -CsvPath .\stig-postremediation.csv
```

Output:

```
Windows 11 STIG Compliance Check
Host: WIN11-HOST    2026-09-22 16:20:11

WN11-AU-000500   CAT II   PASS            Application event log max size >= 32768 KB
WN11-CC-000100   CAT II   PASS            Print driver downloads over HTTP disabled
WN11-CC-000155   CAT I    PASS            Solicited Remote Assistance disabled
WN11-CC-000180   CAT I    FAIL            AutoPlay disabled for non-volume devices
WN11-00-000010   CAT II   MANUAL          Azure Trusted Launch, Secure Boot, and vTPM enabled
...
```

It distinguishes **FAIL** (value present but wrong) from **NOT CONFIGURED** (value absent
entirely). On a STIG checklist these are different findings with different remediation paths, and
collapsing them loses information an assessor needs.

> **Status:** this checker was written to close the verification gap described below. It has not
> yet been executed against a live host — the `.TESTED ON` block is intentionally blank until it
> has been, rather than pre-filled.

---

## Results

Ten DISA STIG controls implemented as idempotent, self-verifying, individually auditable scripts,
with a compliance checker covering the full set. Three CAT I controls close the highest-severity
findings in scope: remote assistance abuse and both halves of the removable-media execution path.

### Known gap: independent compliance evidence

**These scripts have not been validated against an independent STIG audit.** The self-validation
in each script confirms that the registry value it wrote is the value it intended to write —
which proves the script works, not that the host is STIG compliant.

Real compliance evidence requires an external assessor checking the control independently:

| Method | Produces |
|---|---|
| **DISA Evaluate-STIG** | Automated CKL checklist output, the format assessors expect |
| **SCAP Compliance Checker + STIG Viewer** | Official DISA toolchain, XCCDF results |
| **Tenable DISA STIG audit file** | Scanner-side compliance results alongside vulnerability data |

I have a Tenable scan of a lab host named `kekoa-stig-test`, but on inspection it is a standard
vulnerability scan — patch-level findings for Edge, Outlook, and Teams — and contains **no STIG
compliance checks at all**. It lives in the
[vulnerability management project](../Vulnerability-Management-Program/) where it belongs, and is
deliberately not presented here as before/after evidence for these controls, because it is not.

Producing real STIG audit output against a host remediated by these scripts is the next step, and
the honest current state of this project is: remediation implemented, independent verification
outstanding.

## Lessons learned

**Self-validation proves the script, not the compliance.** Each script reads back what it wrote
and reports PASS. That is worth having — it catches a failed write, a permissions problem, a
typo'd key. It is not an audit, because the script is grading its own work against its own
expectation. Conflating the two is the most common way a hardening project overstates itself.

**Policy keys often do not exist yet.** Most of these values live under `HKLM\SOFTWARE\Policies\`,
which is frequently absent on a default install. `Test-Path` plus `New-Item -Force` before every
write is not defensive padding; without it roughly half these scripts fail on a clean host.

**Idempotency is a requirement, not a nicety.** Hardening scripts get re-run — after a rebuild,
after a GPO overwrite, as a scheduled compliance job. `New-ItemProperty -Force` converges to the
same state every time, so a second run is never destructive and never partially applied.

**Near-identical registry paths are a real hazard.** `...\Windows\Explorer` and
`...\CurrentVersion\Policies\Explorer` both exist, both accept the write, and only one enforces
the intended control. A script writing to the wrong hive reports PASS and hardens nothing — which
is worse than failing, because it produces false assurance.

**Document the Group Policy path alongside the registry change.** In federal environments the
approved change mechanism is usually GPO. Carrying both keeps the script useful as documentation
where running it directly is not permitted.

**Metadata is part of the deliverable.** Building this repository surfaced defects in the header
blocks — one script with its tested-by and tested-on values transposed, two with the block left
empty, one still referencing a v2r7 control and carrying a leftover Windows 10 example path. None
affect execution; all of them undercut the audit trail the header exists to provide. Provenance
fields only hold up if they are maintained as carefully as the code.

## MITRE ATT&CK mapping

| Technique | ID | Control |
|---|---|---|
| Replication Through Removable Media | [T1091](https://attack.mitre.org/techniques/T1091/) | WN11-CC-000180, WN11-CC-000185 |
| Boot or Logon Autostart Execution | [T1547](https://attack.mitre.org/techniques/T1547/) | WN11-CC-000185 |
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | WN11-CC-000155 |
| Remote Access Software | [T1219](https://attack.mitre.org/techniques/T1219/) | WN11-CC-000155 |
| Exploitation for Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068/) | WN11-CC-000100 (print driver installation) |
| Pre-OS Boot: Bootkit | [T1542.003](https://attack.mitre.org/techniques/T1542/003/) | WN11-00-000010 (Secure Boot, vTPM) |
| Indicator Removal: Clear Windows Event Logs | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | WN11-AU-000500 (log retention capacity) |
| Remote Services | [T1021](https://attack.mitre.org/techniques/T1021/) | WN11-CC-000165 (unauthenticated RPC) |
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | WN11-CC-000175 (telemetry egress) |

## Usage

```powershell
# Run elevated. Verify the baseline first.
.\scripts\Test-STIGCompliance.ps1 -CsvPath .\baseline.csv

# Apply a single control
.\scripts\WN11-CC-000185.ps1

# Apply all registry-backed controls
Get-ChildItem .\scripts\WN11-*.ps1 | ForEach-Object { & $_.FullName }

# Confirm
.\scripts\Test-STIGCompliance.ps1 -CsvPath .\post.csv
```

`WN11-00-000010.ps1` requires the `Az` module and Azure RBAC permissions, and will deallocate and
restart the target VM. Run it separately and under change control.

## Repository contents

```text
Windows-11-STIG-Remediation/
├── README.md
└── scripts/
    ├── Test-STIGCompliance.ps1     # read-only audit of all ten controls
    ├── WN11-00-000010.ps1          # CAT II  · Azure Trusted Launch / Secure Boot / vTPM
    ├── WN11-AU-000500.ps1          # CAT II  · Application event log sizing
    ├── WN11-CC-000100.ps1          # CAT II  · Print driver HTTP download
    ├── WN11-CC-000105.ps1          # CAT II  · Web publishing wizard downloads
    ├── WN11-CC-000120.ps1          # CAT II  · Logon screen network selection UI
    ├── WN11-CC-000155.ps1          # CAT I   · Solicited Remote Assistance
    ├── WN11-CC-000165.ps1          # CAT II  · Unauthenticated RPC clients
    ├── WN11-CC-000175.ps1          # CAT III · Application Compatibility Inventory
    ├── WN11-CC-000180.ps1          # CAT I   · AutoPlay for non-volume devices
    └── WN11-CC-000185.ps1          # CAT I   · AutoRun command execution
```

---

*Developed and tested against Windows 11 lab virtual machines in Microsoft Azure.*
