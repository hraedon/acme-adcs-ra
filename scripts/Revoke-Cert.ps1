<#
.SYNOPSIS
    Revoke a certificate at the ADCS CA out-of-band (WI-010).

.DESCRIPTION
    acme-adcs-ra's `revokeCert` endpoint records the revocation in the RA store
    only -- it does NOT write the CA CRL, because the RA's gMSA intentionally
    holds no CA-officer ("Manage CA") rights (the project's tightest security
    tenet; see docs/threat-model.md §E). This script is the operator-run,
    CA-officer credential that performs the actual `certutil -revoke` against
    the CA, closing the loop the RA started.

    Run this as a CA officer (NOT the gMSA, NOT the RA host service account)
    from a management host that has RSAT / certutil available and line-of-sight
    to the CA. The serial or ReqID it consumes is exactly what the RA already
    stores and surfaces in its audit log and `revokeCert` response
    (`details.serial`, `details.req_id`, and the `out_of_band_revocation` hint).

    The script:
      1. Confirms the cert exists at the CA (by serial or ReqID) before
         revoking, so a typo cannot silently no-op. Confirmation is
         locale-independent: it matches the hex serial value (which is always
         hex regardless of OS locale), not a localized column header.
      2. Maps the RFC 8555 reason code (0-10) to the `certutil -revoke`
         reason code (0=unspecified, 1=compromised, 2=CA compromise,
         3=affiliation changed, 4=superseded, 5=cessation of operation,
         6=certificate hold, 8=remove from CRL, 9=privilege withdrawn,
         10=AA compromise). Reason 7 is unused in RFC 5280 and is rejected.
      3. Runs `certutil -revoke <serial> <reason> -config <CA>` and prints the
         outcome.
      4. Re-publishes the CRL so the revocation is visible without waiting for
         the next scheduled publication (`certutil -CRL republish -config <CA>`).

    This is a documented, auditable operator action -- the RA's audit log
    records `revocation_scope=ra-store-only, ca_crl_updated=false` and this
    script's invocation (with the operator identity in the CA database) is the
    matching out-of-band half. Keep both records together in incident review.

.PARAMETER Serial
    The certificate serial number (uppercase hex, no `0x` prefix) as the RA
    stores it (e.g. `1A2B3C...`). Use this when you have the RA's
    `details.serial`.

.PARAMETER ReqID
    The ADCS request ID (decimal) as the RA stores it (e.g. `42`). Use this
    when you have the RA's `details.req_id`. The script looks up the serial
    from the CA database via `certutil -view` and then revokes by serial
    (`certutil -revoke` accepts serials only). Either -Serial or -ReqID is
    required; -Serial wins if both are given.

.PARAMETER CaConfig
    The CA configuration string (`CA01\WORK-DOMAIN-CA` form). Required --
    certutil needs it to address the CA. Use the placeholder form in committed
    samples; the real value lives in gitignored local config.

.PARAMETER Reason
    RFC 8555 revocation reason code (0-10). Default 0 (unspecified).

.PARAMETER SkipPublishCrl
    Skip the `certutil -CRL republish` step (use if a scheduled publication is
    imminent or another operator is publishing).

.EXAMPLE
    # Revoke by serial with the RA's details.serial:
    powershell -File .\scripts\Revoke-Cert.ps1 `
        -CaConfig 'CA01\WORK-DOMAIN-CA' -Serial '1A2B3C' -Reason 1

.EXAMPLE
    # Revoke by the RA's details.req_id (looks up the serial first):
    powershell -File .\scripts\Revoke-Cert.ps1 `
        -CaConfig 'CA01\WORK-DOMAIN-CA' -ReqID 42 -Reason 0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Serial")]
    [string]$Serial,

    [Parameter(Mandatory = $true, ParameterSetName = "ReqID")]
    [string]$ReqID,

    [Parameter(Mandatory = $true)][string]$CaConfig,
    [int]$Reason = 0,
    [switch]$SkipPublishCrl
)

$ErrorActionPreference = "Stop"

# Write an error message to stderr and exit with a specific code. Using
# [Console]::Error.WriteLine (not Write-Error) so $ErrorActionPreference=Stop
# does not turn the message into a terminating exception that swallows the
# exit code — the documented exit-code contract (3=validation, 4=not-found,
# certutil-code=transport) must be reachable by wrapping automation.
function Die([string]$Message, [int]$Code) {
    [Console]::Error.WriteLine("ERROR: $Message")
    exit $Code
}

# RFC 5280 §5.3.1 reason codes. certutil -revoke uses the same numeric codes,
# EXCEPT reason 7 is "unused" in RFC 5280 (not an RFC 8555 reason) and is
# rejected here. Reason 6 is certificateHold; reason 8 is removeFromCRL (the
# un-hold operation, accepted for completeness).
$validReasons = @(0, 1, 2, 3, 4, 5, 6, 8, 9, 10)
if ($Reason -notin $validReasons) {
    Die ("Reason {0} is not a valid RFC 8555 revocation reason (0-6, 8-10). Reason 7 is unused in RFC 5280." -f $Reason) 3
}

function Invoke-CertUtil([string[]]$CertutilArgs) {
    $out = & certutil @CertutilArgs 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Die ("certutil exited {0}: {1}" -f $code, ($out -join "`n")) $code
    }
    return $out
}

# Locale-independent confirmation: match the hex serial value itself (always
# hex regardless of OS locale), not a localized column header. This avoids
# the WI-007 class of bug (locale-dependent string parsing).
function Confirm-SerialAtCa([string]$CaConfig, [string]$SerialHex) {
    Write-Output ("Confirming cert with serial {0} at CA '{1}'..." -f $SerialHex, $CaConfig)
    $viewOut = Invoke-CertUtil @('-view', '-config', $CaConfig, '-restrict', "SerialNumber=$SerialHex", '-out', 'SerialNumber')
    $viewOut | ForEach-Object { Write-Output $_ }
    # The hex serial value is locale-independent; match it case-insensitively
    # in the joined output. If certutil -view found no matching row, the
    # serial value will not appear. Join the array first — -notmatch on an
    # array filters (returns non-matching elements, always truthy), not a
    # boolean test.
    $joined = $viewOut -join "`n"
    if ($joined -notmatch [regex]::Escape($SerialHex)) {
        Die ("No certificate with serial {0} found at CA '{1}' -- refusing to revoke." -f $SerialHex, $CaConfig) 4
    }
}

# Look up the serial from a ReqID via certutil -view, locale-independently.
# certutil -view output pairs the column with its value; the SerialNumber
# value is a hex string (locale-independent). Parse it with a hex regex.
function Get-SerialFromReqId([string]$CaConfig, [string]$Rid) {
    Write-Output ("Looking up serial for ReqID {0} at CA '{1}'..." -f $Rid, $CaConfig)
    $viewOut = Invoke-CertUtil @('-view', '-config', $CaConfig, '-restrict', "RequestID=$Rid", '-out', 'SerialNumber')
    $viewOut | ForEach-Object { Write-Output $_ }
    # The serial is a hex string (0-9A-Fa-f). With -out SerialNumber the output
    # is restricted to the serial column, so the longest hex run is the serial
    # (row indices and other metadata are shorter / non-hex). Word-boundary
    # anchored to avoid matching a hex substring embedded in a longer token.
    $joined = $viewOut -join "`n"
    $allMatches = [regex]::Matches($joined, '\b[0-9A-Fa-f]{8,}\b')
    if ($allMatches.Count -eq 0) {
        Die ("Could not find a serial number for ReqID {0} at CA '{1}' -- the request may not have issued a cert." -f $Rid, $CaConfig) 4
    }
    # Serials are the longest hex run in -out SerialNumber output.
    $serial = ($allMatches | Sort-Object { $_.Value.Length } -Descending | Select-Object -First 1).Value
    return $serial.ToUpperInvariant()
}

# 1. Resolve the target serial and confirm it exists at the CA.
if ($PSCmdlet.ParameterSetName -eq "Serial") {
    if ([string]::IsNullOrWhiteSpace($Serial)) {
        Die "-Serial is empty or whitespace." 3
    }
    $targetSerial = $Serial.Trim().ToUpperInvariant() -replace '^0x', ''
    Confirm-SerialAtCa $CaConfig $targetSerial
} else {
    $rid = $ReqID.Trim()
    if ($rid -notmatch '^\d+$') {
        Die ("ReqID '{0}' is not a decimal integer." -f $rid) 3
    }
    $targetSerial = Get-SerialFromReqId $CaConfig $rid
    Confirm-SerialAtCa $CaConfig $targetSerial
}

# 2. Revoke by serial. certutil -revoke accepts serials only (not ReqIDs).
#    Syntax: certutil -revoke <SerialNumber> [Reason] -config <CA>
Write-Output ("Revoking serial {0}, reason = {1}..." -f $targetSerial, $Reason)
$revokeOut = Invoke-CertUtil @('-revoke', $targetSerial, "$Reason", '-config', $CaConfig)
$revokeOut | ForEach-Object { Write-Output $_ }
Write-Output ("PASS: certutil -revoke reported success for serial {0} (reason {1})." -f $targetSerial, $Reason)

# 3. Re-publish the CRL so the revocation is visible without waiting for the
#    next scheduled publication. This is the operator-visible "the CRL now
#    reflects the revocation" step the RA's audit log records as still-pending
#    (ca_crl_updated=false) until this script runs.
if ($SkipPublishCrl) {
    Write-Output "Skipping CRL publication (-SkipPublishCrl). The revocation will appear at the next scheduled publication."
} else {
    Write-Output ("Publishing CRL at CA '{0}'..." -f $CaConfig)
    $publishOut = Invoke-CertUtil @('-CRL', 'republish', '-config', $CaConfig)
    $publishOut | ForEach-Object { Write-Output $_ }
    Write-Output "PASS: CRL republished."
}

Write-Output ""
Write-Output ("Out-of-band revocation complete. The RA audit log recorded this cert as")
Write-Output ("revocation_scope=ra-store-only, ca_crl_updated=false -- update the incident")
Write-Output ("record to note the out-of-band step is now done and the CRL is published.")
exit 0