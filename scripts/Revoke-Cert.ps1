<#
.SYNOPSIS
    Revoke a certificate at the ADCS CA out-of-band (WI-010), with a
    requester check (WI-022) that refuses to revoke certs not issued by the
    expected enrollment identity.

.DESCRIPTION
    acme-adcs-ra's `revokeCert` endpoint records the revocation in the RA store
    only -- it does NOT write the CA CRL, because the RA's gMSA intentionally
    holds no CA-officer ("Manage CA") rights (the project's tightest security
    tenet; see docs/threat-model.md section E). This script is the operator-run,
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
         hex regardless of OS locale), not a localized column header. It then
         asserts the CA-DB `Request.RequesterName` equals -RequesterName
         (default the enrollment gMSA), refusing to revoke a cert not issued by
         the expected identity (WI-022 -- defense-in-depth before the CA-side
         officer restriction; the requester value is a SID/name string, not a
         localized header, so the check is locale-independent).
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

    Exit codes:
      0  = success
      3  = validation error (bad params, invalid reason)
      4  = cert not found at the CA (serial or ReqID does not resolve)
      5  = requester mismatch (cert was not issued by the expected enrollment
           identity -- WI-022)
      N  = certutil exit code (transport / CA-side failure)

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

.PARAMETER RequesterName
    The expected enrollment identity (the gMSA that enrolls via the RA), in
    `DOMAIN\account` form. The script asserts the CA-DB
    `Request.RequesterName` of the target cert matches this value before
    revoking (WI-022 -- defense-in-depth, bounds any operator typo or
    automation to the RA's own issuance). Default:
    `WORK-DOMAIN\gMSA-acme-ra$` (placeholder form -- the real value lives in
    gitignored local config). The comparison is case-insensitive and
    locale-independent (the requester value is a SID/name string, not a
    localized column header).

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
    [string]$RequesterName = "WORK-DOMAIN\gMSA-acme-ra$",
    [switch]$SkipPublishCrl
)

$ErrorActionPreference = "Stop"

# Write an error message to stderr and exit with a specific code. Using
# [Console]::Error.WriteLine (not Write-Error) so $ErrorActionPreference=Stop
# does not turn the message into a terminating exception that swallows the
# exit code -- the documented exit-code contract (3=validation, 4=not-found,
# 5=requester mismatch, certutil-code=transport) must be reachable by wrapping
# automation.
function Die([string]$Message, [int]$Code) {
    [Console]::Error.WriteLine("ERROR: $Message")
    exit $Code
}

# RFC 5280 section 5.3.1 reason codes. certutil -revoke uses the same numeric codes,
# EXCEPT reason 7 is "unused" in RFC 5280 (not an RFC 8555 reason) and is
# rejected here. Reason 6 is certificateHold; reason 8 is removeFromCRL (the
# un-hold operation, accepted for completeness).
$validReasons = @(0, 1, 2, 3, 4, 5, 6, 8, 9, 10)
if ($Reason -notin $validReasons) {
    Die ("Reason {0} is not a valid RFC 8555 revocation reason (0-6, 8-10). Reason 7 is unused in RFC 5280." -f $Reason) 3
}

# WI-022: the requester check is a defense-in-depth gate -- an empty value
# would match trivially, so require it non-empty. The default is the gMSA
# placeholder; an operator may override it per deployment.
if ([string]::IsNullOrWhiteSpace($RequesterName)) {
    Die "-RequesterName is empty or whitespace. Pass the expected enrollment identity (e.g. WORK-DOMAIN\gMSA-acme-ra$)." 3
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
# the WI-007 class of bug (locale-dependent string parsing). Also asserts the
# CA-DB RequesterName matches the expected enrollment identity (WI-022):
# the requester value is a SID/name string (locale-independent), so the check
# matches the value, not a localized column header.
function Confirm-SerialAtCa([string]$CaConfig, [string]$SerialHex, [string]$ExpectedRequester) {
    Write-Output ("Confirming cert with serial {0} at CA '{1}'..." -f $SerialHex, $CaConfig)
    $viewOut = Invoke-CertUtil @('-view', '-config', $CaConfig, '-restrict', "SerialNumber=$SerialHex", '-out', 'SerialNumber')
    $viewOut | ForEach-Object { Write-Output $_ }
    # The hex serial value is locale-independent; match it case-insensitively
    # in the joined output. If certutil -view found no matching row, the
    # serial value will not appear. Join the array first -- -notmatch on an
    # array filters (returns non-matching elements, always truthy), not a
    # boolean test.
    $joined = $viewOut -join "`n"
    if ($joined -notmatch [regex]::Escape($SerialHex)) {
        Die ("No certificate with serial {0} found at CA '{1}' -- refusing to revoke." -f $SerialHex, $CaConfig) 4
    }

    # WI-022: assert the cert was requested by the expected enrollment
    # identity (defense-in-depth before the CA-side officer restriction).
    Write-Output ("Confirming requester for serial {0} is '{1}'..." -f $SerialHex, $ExpectedRequester)
    $reqOut = Invoke-CertUtil @('-view', '-config', $CaConfig, '-restrict', "SerialNumber=$SerialHex", '-out', 'Request.RequesterName')
    $reqOut | ForEach-Object { Write-Output $_ }
    $reqJoined = $reqOut -join "`n"
    # The requester value is a DOMAIN\account string (locale-independent);
    # extract it with a regex rather than matching a localized header. The
    # first DOMAIN\account token in the output is the requester -- certutil
    # -view -out Request.RequesterName emits only that column, so no other
    # backslash-bearing token appears.
    $actualRequester = $null
    $reqMatch = [regex]::Match($reqJoined, '([A-Za-z0-9][A-Za-z0-9._-]*\\[A-Za-z0-9][A-Za-z0-9._$-]*)')
    if ($reqMatch.Success) {
        $actualRequester = $reqMatch.Groups[1].Value
    }
    if ($null -eq $actualRequester) {
        Die ("Could not parse Request.RequesterName for serial {0} at CA '{1}' -- refusing to revoke (unable to confirm requester)." -f $SerialHex, $CaConfig) 5
    }
    if (-not $actualRequester.Equals($ExpectedRequester, [System.StringComparison]::OrdinalIgnoreCase)) {
        Die ("Requester mismatch for serial {0}: expected '{1}', got '{2}' -- refusing to revoke (cert was not issued by the expected enrollment identity)." -f $SerialHex, $ExpectedRequester, $actualRequester) 5
    }
    Write-Output ("PASS: requester confirmed: {0}" -f $actualRequester)
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
    Confirm-SerialAtCa $CaConfig $targetSerial $RequesterName
} else {
    $rid = $ReqID.Trim()
    if ($rid -notmatch '^\d+$') {
        Die ("ReqID '{0}' is not a decimal integer." -f $rid) 3
    }
    $targetSerial = Get-SerialFromReqId $CaConfig $rid
    Confirm-SerialAtCa $CaConfig $targetSerial $RequesterName
}

# 2. Revoke by serial. certutil -revoke accepts serials only (not ReqIDs).
#    Syntax: certutil -config <CA> -revoke <SerialNumber> [Reason]
#    NOTE: -config must precede the -revoke verb. certutil's -revoke collects
#    every following token as a positional arg, so a trailing "-config <CA>"
#    is mis-parsed ("Expected no more than 2 args, received 4") rather than
#    consumed as the config option.
Write-Output ("Revoking serial {0}, reason = {1}..." -f $targetSerial, $Reason)
$revokeOut = Invoke-CertUtil @('-config', $CaConfig, '-revoke', $targetSerial, "$Reason")
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
    $publishOut = Invoke-CertUtil @('-config', $CaConfig, '-CRL', 'republish')
    $publishOut | ForEach-Object { Write-Output $_ }
    Write-Output "PASS: CRL republished."
}

Write-Output ""
Write-Output ("Out-of-band revocation complete. The RA audit log recorded this cert as")
Write-Output ("revocation_scope=ra-store-only, ca_crl_updated=false -- update the incident")
Write-Output ("record to note the out-of-band step is now done and the CRL is published.")
exit 0