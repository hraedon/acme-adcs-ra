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
