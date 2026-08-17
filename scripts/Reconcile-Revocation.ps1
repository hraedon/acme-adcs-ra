<#
.SYNOPSIS
    Read-only revocation reconciliation between the RA store and the ADCS CA (WI-017).

.DESCRIPTION
    Compares the RA store's certificate status (valid / revoked) with the live
    ADCS CA database obtained via `certutil -view`. This script is intentionally
    read-only: it never writes to the RA database and never calls
    `certutil -revoke`. It reports drift in three buckets:

      * in_sync                       -- both views agree
      * revoked_at_ca_valid_in_ra     -- the CA has revoked the cert but the RA
                                         still considers it valid
      * revoked_in_ra_active_at_ca    -- the RA has recorded revocation but the
                                         cert is still active at the CA (run
                                         Revoke-Cert.ps1 to close the loop)

    Run this as a CA reader or officer from a host that has line-of-sight to the
    CA and certutil available. The export is generated to a temporary file, parsed
    by the Python reconciliation script, and then deleted.

    The CA configuration string and all other real identifiers must be supplied at
    runtime; committed samples use placeholders (`CA01\WORK-DOMAIN-CA`).

.PARAMETER CaConfig
    The CA configuration string (`CA01\WORK-DOMAIN-CA` form). Required.

.PARAMETER DbPath
    Path to the RA SQLite database. Required.

.PARAMETER Json
    Emit a JSON report instead of the human-readable report.

.EXAMPLE
    # Human-readable reconciliation report:
    powershell -File .\scripts\Reconcile-Revocation.ps1 `
        -CaConfig 'CA01\WORK-DOMAIN-CA' -DbPath 'C:\acme-adcs-ra\ra.db'

.EXAMPLE
    # JSON report for automation:
    powershell -File .\scripts\Reconcile-Revocation.ps1 `
        -CaConfig 'CA01\WORK-DOMAIN-CA' -DbPath 'C:\acme-adcs-ra\ra.db' -Json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CaConfig,
    [Parameter(Mandatory = $true)][string]$DbPath,
    [switch]$Json
)

$ErrorActionPreference = "Stop"

function Die([string]$Message, [int]$Code) {
    [Console]::Error.WriteLine("ERROR: $Message")
    exit $Code
}

if (-not (Test-Path -Path $DbPath)) {
    Die "RA database not found: $DbPath" 2
}

# Elevated helpers are resolved to absolute paths, never left to ambient PATH.
#
# This script ran `& certutil ...` and `& python @arguments` by bare name. A
# writable PATH entry -- or, for a child launched through cmd, the current
# directory -- turns either into code execution with this script's privileges on
# the host that holds the RA's CA-officer context. Same class as round-6
# finding 3, which removed PATH-selected py/python/winget from the installer;
# this sibling was missed. certutil is a System32 binary, so it is addressed
# absolutely. Python is not, so it is resolved through Get-Command and required
# to be an Application with a rooted source -- and the current directory is
# removed from the child search path either way.
$env:NoDefaultCurrentDirectoryInExePath = '1'
$certutilExe = Join-Path $env:windir 'System32\certutil.exe'
if (-not (Test-Path -LiteralPath $certutilExe)) {
    Die "certutil.exe not found at $certutilExe." 2
}
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd -or
    $pythonCmd.CommandType -ne [System.Management.Automation.CommandTypes]::Application -or
    -not $pythonCmd.Source -or -not [System.IO.Path]::IsPathRooted($pythonCmd.Source)) {
    Die "No python interpreter resolved to an absolute executable path; install Python 3.12+ machine-wide." 2
}
$pythonExe = $pythonCmd.Source
# `Get-Command python` IS the PATH lookup -- resolving it to an absolute path
# proves only that SOMETHING was found, not that a non-administrator could not
# have planted it. A binary in a writable PATH directory is an Application with
# a rooted Source and satisfies every condition above. Hold it to the same
# provenance rule the installer applies before it executes an interpreter:
# the file and its whole ancestor chain must be administrator-only.
if ($pythonExe -like '*\WindowsApps\*') {
    Die "Refusing the Windows Store python stub at $pythonExe; install Python 3.12+ machine-wide." 2
}
. (Join-Path $PSScriptRoot 'lib\InstallVerifyLib.ps1')
$pyChainViolations = @(Test-PathChainTrusted -Path $pythonExe)
if ($pyChainViolations.Count -gt 0) {
    Die ("Refusing to run ${pythonExe}: it or its ancestor chain is not administrator-only.`n  " +
         (($pyChainViolations | Select-Object -First 4) -join "`n  ")) 2
}

$pythonScript = Join-Path $PSScriptRoot 'reconcile_revocation.py'
if (-not (Test-Path -Path $pythonScript)) {
    Die "Reconciliation script not found: $pythonScript" 2
}

$tempFile = [System.IO.Path]::GetTempFileName()
Rename-Item -Path $tempFile -NewName "$tempFile.txt" -Force | Out-Null
$exportPath = "$tempFile.txt"

try {
    Write-Output "Exporting CA revocation view from '$CaConfig'..."
    # certutil's exit status was previously ignored, so a failed or partial
    # export was written out and reconciled against as though it were the CA's
    # complete answer -- and an export missing rows reads downstream as
    # agreement (2026-08-18 F2). Capture the status and hand it to the
    # reconciler, which refuses to compare anything when it is non-zero.
    # Request.RevokedReason is exported because Disposition=21 alone does not
    # prove revocation: reason 8 (removeFromCRL) leaves the disposition at 21
    # while the certificate is off the CRL and valid (2026-08-18 wave 3 F1).
    # The EAP shield exists because this script runs under EAP=Stop and, on
    # Windows PowerShell 5.1, the first line certutil writes to a MERGED
    # stderr terminates the pipeline before $LASTEXITCODE is read (SyncLib's
    # documented live observation) -- the exit-status contract this whole
    # block was written to enforce would be unreachable exactly when it
    # matters, on a failing export.
    $priorEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $viewOut = & $certutilExe @('-view', '-config', $CaConfig, '-out', 'SerialNumber,Disposition,RequestID,Request.RevokedReason') 2>&1
        $exportExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorEap
    }
    $viewOut | Out-File -FilePath $exportPath -Encoding utf8 -ErrorAction Stop
    if ($exportExitCode -ne 0) {
        Die ("certutil -view exited {0}; the export is incomplete and no comparison was attempted. Check CA connectivity and reader rights on '{1}'." -f $exportExitCode, $CaConfig) 2
    }

    $arguments = @(
        $pythonScript,
        '--db', $DbPath,
        '--ca-export', $exportPath,
        '--ca-export-exit-code', $exportExitCode
    )
    if ($Json.IsPresent) {
        $arguments += '--json'
    }

    Write-Output "Running reconciliation against RA store..."
    & $pythonExe @arguments
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0) {
        Write-Output "PASS: revocation state is in sync."
    }
    elseif ($exitCode -eq 1) {
        Write-Output "DRIFT detected. Review the buckets above."
        Write-Output "For 'revoked_in_ra_active_at_ca' entries, run scripts/Revoke-Cert.ps1 as a CA officer."
        Write-Output "For 'revoked_at_ca_valid_in_ra' entries, verify the RA store and ACME revocation records."
    }
    else {
        # Exit 2 is INDETERMINATE, not merely "the script broke": the export did
        # not account for every certificate the RA knows about, so a live
        # unrevoked certificate could be sitting in the gap. It must never be
        # read as a pass.
        Die "Reconciliation could not be completed (exit $exitCode). This is NOT a pass -- revocation state is unproven. Review the report above." $exitCode
    }
}
finally {
    if (Test-Path -Path $exportPath) {
        Remove-Item -Path $exportPath -Force -ErrorAction SilentlyContinue
    }
}
