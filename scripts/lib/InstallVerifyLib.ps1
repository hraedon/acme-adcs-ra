# Dot-sourceable library: authenticity checks for the prerequisite MSI the
# Windows installer runs as Administrator.
#
# 2026-08-17 F1. install-windows.ps1 hash-pins its entire Python runtime and
# build closure, and then accepted `-HttpPlatformHandlerMsi https://...` (or
# plain `http://...`), downloaded whatever bytes came back, and handed them
# straight to `msiexec /i` as Administrator. There was no digest and no
# publisher check anywhere on that path. An intercepted plaintext download, or a
# compromised accepted origin, is Administrator code execution on the issuance
# host -- the one place in this system where that is worth the most.
#
# The decision logic lives here, taking plain values rather than doing its own
# I/O, so it can be exercised on Linux by tests/pester/InstallVerify.Tests.ps1.
# The installer keeps the I/O (Invoke-WebRequest, Get-FileHash,
# Get-AuthenticodeSignature) and calls these to decide.

# Classify an -HttpPlatformHandlerMsi value: 'https', 'http', or 'local'.
function Get-MsiSourceKind {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Source)
    $s = $Source.Trim()
    if ($s -match '^(?i)https://') { return 'https' }
    if ($s -match '^(?i)http://')  { return 'http' }
    return 'local'
}

# Gate the source before a single byte is fetched.
#
# Plaintext HTTP is refused outright rather than "allowed but hashed": a digest
# supplied over the same channel an attacker controls proves nothing, and there
# is no reason for this artifact to arrive unauthenticated when HTTPS exists.
# A remote source additionally REQUIRES an out-of-band SHA-256, because TLS
# authenticates the origin, not the artifact -- a compromised or substituted
# mirror still serves a valid certificate.
#
# Throws on refusal (the installer runs with $ErrorActionPreference = 'Stop').
function Assert-MsiSourceAcceptable {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Source,
        [AllowEmptyString()][string]$Sha256 = ""
    )
    $kind = Get-MsiSourceKind $Source
    if ($kind -eq 'http') {
        throw ("Refusing to download the HttpPlatformHandler MSI over plaintext HTTP ({0}). " -f $Source) +
              "This artifact is executed by msiexec as Administrator on the issuance host. " +
              "Use an https:// URL with -HttpPlatformHandlerSha256, or pass a vetted local path."
    }
    if ($kind -eq 'https' -and [string]::IsNullOrWhiteSpace($Sha256)) {
        throw "Refusing to download the HttpPlatformHandler MSI without -HttpPlatformHandlerSha256. " +
              "HTTPS authenticates the origin, not the bytes: supply the expected SHA-256 out of band " +
              "(Microsoft publishes it; or hash a copy you have already vetted)."
    }
    return $kind
}

# Compare two SHA-256 digests tolerantly of presentation, strictly of value.
#
# Operators paste digests from many places: Get-FileHash emits uppercase,
# sha256sum lowercase, some pages insert spaces or colons. None of that changes
# the value, and rejecting a correct digest for its spelling would push people
# toward skipping the check. A malformed or wrong-length digest is NOT tolerated
# -- it fails, rather than being padded or truncated into a comparison.
function Test-Sha256Match {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Actual,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Expected
    )
    $normalize = {
        param([string]$v)
        if ($null -eq $v) { return "" }
        ($v -replace '[\s:-]', '').Trim().ToUpperInvariant()
    }
    $a = & $normalize $Actual
    $e = & $normalize $Expected
    if ($a.Length -ne 64 -or $e.Length -ne 64) { return $false }
    if ($a -notmatch '^[0-9A-F]{64}$' -or $e -notmatch '^[0-9A-F]{64}$') { return $false }
    # Ordinal, case-insensitive already handled by the uppercase normalization.
    return [string]::Equals($a, $e, [System.StringComparison]::Ordinal)
}

# Decide whether an Authenticode signature is acceptable for this artifact.
#
# Takes the Status and signer Subject as strings rather than the signature
# object, so the matrix below is testable without a signed file on disk.
#
# Only 'Valid' passes. In particular 'UnknownError', 'NotSigned', and
# 'HashMismatch' do not, and neither does 'UnknownError' with a plausible
# subject -- a tampered MSI whose signature no longer verifies is exactly the
# case this exists to catch. The publisher must also match: a validly signed
# MSI from someone else is still not the artifact we asked for.
function Test-MsiSignatureAcceptable {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Status,
        [AllowEmptyString()][string]$SignerSubject = "",
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ExpectedPublisher
    )
    if ($Status -ne 'Valid') { return $false }
    if ([string]::IsNullOrWhiteSpace($SignerSubject)) { return $false }
    if ([string]::IsNullOrWhiteSpace($ExpectedPublisher)) { return $false }
    return $SignerSubject.IndexOf(
        $ExpectedPublisher, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}
