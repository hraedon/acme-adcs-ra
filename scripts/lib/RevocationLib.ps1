# Dot-sourceable library: revocation reason validation and requester comparison.
# Extracted from Revoke-Cert.ps1 for testability. Used by the Pester tests
# (tests/pester/Revocation.Tests.ps1). The production script keeps its logic
# inline (it is simple enough); this lib validates the same logic independently.

# RFC 5280 section 5.3.1 reason codes. certutil -revoke uses the same numeric codes,
# EXCEPT reason 7 is "unused" in RFC 5280 (not an RFC 8555 reason) and is
# rejected here. Reason 6 is certificateHold; reason 8 is removeFromCRL (the
# un-hold operation, accepted for completeness).
function Get-ValidRevocationReasons {
    return @(0, 1, 2, 3, 4, 5, 6, 8, 9, 10)
}

function Test-RevocationReason([int]$Reason) {
    return $Reason -in (Get-ValidRevocationReasons)
}

function Compare-RequesterName([string]$Actual, [string]$Expected) {
    if ([string]::IsNullOrEmpty($Actual)) { return $false }
    return $Actual.Equals($Expected, [System.StringComparison]::OrdinalIgnoreCase)
}

# Convert a serial to the form the ADCS CA database stores, so a
# `-restrict "SerialNumber=..."` clause matches exactly.
#
# The RA emits serials via Python's format(n, 'x'), which never produces a
# leading zero. ADCS stores the full byte string, so a certificate whose
# high-order byte is 0x0N is recorded with a leading zero the RA's form lacks
# (e.g. RA "6AB1..." vs CA "06AB1..."). The restrict clause is an exact string
# match, so the lookup would find 0 rows and Revoke-Cert.ps1 would exit 4 --
# fail-safe (nothing wrongly revoked) but it silently stops the automated
# revocation loop for that certificate until someone investigates.
#
# A hex serial derived from bytes always has an even number of digits, so
# re-padding an odd-length value to even reconstructs the CA's form exactly.
# Verified against the lab CA 2026-08-11: 61 issued serials, lengths 32 and 38,
# none currently leading-zero -- this is a latent case, not an observed one.
function Get-CaSerialForm([string]$Serial) {
    if ([string]::IsNullOrWhiteSpace($Serial)) { return $Serial }
    $s = $Serial.Trim()
    if ($s.StartsWith("0x", [System.StringComparison]::OrdinalIgnoreCase)) {
        $s = $s.Substring(2)
    }
    if ($s.Length % 2 -eq 1) { $s = "0" + $s }
    return $s
}
