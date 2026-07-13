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

$pythonScript = Join-Path $PSScriptRoot 'reconcile_revocation.py'
if (-not (Test-Path -Path $pythonScript)) {
    Die "Reconciliation script not found: $pythonScript" 2
}

$tempFile = [System.IO.Path]::GetTempFileName()
Rename-Item -Path $tempFile -NewName "$tempFile.txt" -Force | Out-Null
$exportPath = "$tempFile.txt"

try {
    Write-Output "Exporting CA revocation view from '$CaConfig'..."
    $viewOut = certutil -view -config $CaConfig -out SerialNumber,Disposition,RequestID
    $viewOut | Out-File -FilePath $exportPath -Encoding utf8 -ErrorAction Stop

    $arguments = @(
        $pythonScript,
        '--db', $DbPath,
        '--ca-export', $exportPath
    )
    if ($Json.IsPresent) {
        $arguments += '--json'
    }

    Write-Output "Running reconciliation against RA store..."
    & python @arguments
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
        Die "Reconciliation script exited with code $exitCode." $exitCode
    }
}
finally {
    if (Test-Path -Path $exportPath) {
        Remove-Item -Path $exportPath -Force -ErrorAction SilentlyContinue
    }
}
