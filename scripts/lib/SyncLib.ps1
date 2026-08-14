# Dot-sourceable library: sync-revocation helpers extracted from
# Sync-Revocations.ps1 for testability. Used by the Pester tests
# (tests/pester/Sync.Tests.ps1) AND dot-sourced by the production script, so
# what CI exercises is what runs -- a test-only copy proves nothing about the
# shipped path.

# Invoke-RestMethod may unwrap a single-element array into a scalar, and an
# empty JSON array may deserialize as $null. Force a clean array, filtering
# out any null entries (defensive against PowerShell's inconsistent empty-
# array deserialization across versions).
function Get-PendingRevocations([object]$Response) {
    $pending = @()
    if ($Response -and $Response.pending_revocations) {
        $pending = @($Response.pending_revocations | Where-Object { $_ })
    }
    return $pending
}

function Get-SyncExitCode([int]$FailedCount) {
    if ($FailedCount -gt 0) { return 2 }
    return 0
}

# Run a child script and return its output and exit code WITHOUT letting the
# child's stderr become a terminating error in the caller.
#
# `& native 2>&1` does not do this on its own: it turns each stderr line into
# an ErrorRecord on the output stream, and under $ErrorActionPreference='Stop'
# -- which Sync-Revocations.ps1 sets -- the first one throws. That made the
# per-serial failure handling unreachable: a failed revoke aborted the whole
# batch instead of being logged and counted, and the script exited 1 rather
# than the documented 2 (partial failure) or 5 (requester mismatch).
# Suppressing Stop for the duration of the call is what makes the child's
# failure handleable. (Found on the lab CA, 2026-08-13.)
function Invoke-ChildScript([string]$Exe, [string[]]$Arguments) {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $Exe @Arguments 2>&1
        return [pscustomobject]@{ Output = @($out); ExitCode = $LASTEXITCODE }
    } finally {
        $ErrorActionPreference = $prevEap
    }
}

# Validate the RA base URL before any credential is attached to a request.
#
# This script sends a high-value maintenance Bearer token to whatever
# -RaBaseUrl it is handed. Nothing used to check the scheme, so a deployment
# typo ("http://..." instead of "https://...", or a stale hostname) silently
# disclosed the token to anyone on the path. The RA runbooks say HTTPS; a
# runbook is not a control.
#
# Rejects, in order: unparseable/relative URLs, any scheme but https, embedded
# credentials (https://user:pass@host -- which also hide the real authority),
# a query or fragment, and any path beyond "/". Returns the normalised base
# (no trailing slash) for endpoint joining.
#
# -AllowInsecureUrl is the explicit, deliberate opt-out for a loopback lab
# where the RA serves plain HTTP; it still refuses cleartext to a non-loopback
# host, because that is the case that leaks the token onto a network.
function Assert-SafeRaUrl {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Url,
        [switch]$AllowInsecureUrl
    )

    if ([string]::IsNullOrWhiteSpace($Url)) {
        throw "RaBaseUrl must not be empty."
    }

    $uri = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)) {
        throw ("RaBaseUrl '{0}' is not an absolute URL." -f $Url)
    }

    # [System.Uri] returns an IPv6 host in its bracketed literal form ("[::1]"),
    # so compare against the unbracketed address or the opt-out silently never
    # applies to an IPv6 loopback lab. Deliberately an explicit allowlist rather
    # than $uri.IsLoopback, which also accepts the whole of 127.0.0.0/8.
    $hostName = $uri.Host.ToLowerInvariant().Trim('[', ']')
    $loopback = @('localhost', '127.0.0.1', '::1') -contains $hostName

    if ($uri.Scheme -ne 'https') {
        if (-not ($AllowInsecureUrl -and $uri.Scheme -eq 'http' -and $loopback)) {
            throw ("RaBaseUrl '{0}' uses scheme '{1}'; the maintenance token may " +
                   "only be sent over https. (Pass -AllowInsecureUrl for a " +
                   "loopback-only lab over http.)") -f $Url, $uri.Scheme
        }
    }

    if (-not [string]::IsNullOrEmpty($uri.UserInfo)) {
        throw ("RaBaseUrl '{0}' embeds credentials in the URL; remove the " +
               "user:password@ portion." -f $Url)
    }

    if (-not [string]::IsNullOrEmpty($uri.Fragment)) {
        throw ("RaBaseUrl '{0}' carries a fragment; it must be a bare base URL." -f $Url)
    }

    if (-not [string]::IsNullOrEmpty($uri.Query)) {
        throw ("RaBaseUrl '{0}' carries a query string; it must be a bare base URL." -f $Url)
    }

    if ($uri.AbsolutePath -ne '/' -and -not [string]::IsNullOrEmpty($uri.AbsolutePath)) {
        throw ("RaBaseUrl '{0}' carries a path ('{1}'); it must be a bare base URL " +
               "-- the script appends /acme/admin/... itself." -f $Url, $uri.AbsolutePath)
    }

    return $Url.TrimEnd('/')
}

# Classify a Revoke-Cert.ps1 exit code into what the batch should do next.
#
# 2026-08-17 F4. This used to be inline as "5 aborts, any other non-zero is a
# failure, continue" -- and that lumped together two situations that need
# opposite handling. A serial the CA has ALREADY revoked is not a failure: the
# CA side is exactly what was wanted, and the only outstanding work is the RA
# confirmation callback that failed on an earlier run. Treating it as a failure
# meant `continue` fired before the callback was retried, so one dropped HTTPS
# request left the RA audit permanently out of step with the CA and required a
# human to repair. `Revoke-Cert.ps1` now exits 6 for that state.
#
# Returns one of:
#   'revoked'            0 -- revoked now; confirm it
#   'already-revoked'    6 -- no CA-side change was needed; confirm it anyway
#   'requester-mismatch' 5 -- policy violation; abort the WHOLE batch
#   'failed'             anything else -- log, count, skip this serial
function Get-RevokeOutcome([int]$ExitCode) {
    switch ($ExitCode) {
        0       { return 'revoked' }
        6       { return 'already-revoked' }
        5       { return 'requester-mismatch' }
        default { return 'failed' }
    }
}

# Does this outcome mean the RA confirmation callback should be attempted?
#
# Deliberately a separate predicate rather than `-ne 'failed'`: the answer for
# 'requester-mismatch' must be NO even though it is also not a plain failure,
# and stating that explicitly keeps a future outcome from defaulting into
# "confirm it" by omission. Confirming is an assertion that the CA revoked the
# certificate; nothing may claim it without grounds.
function Test-ShouldConfirmWithRa([string]$Outcome) {
    return ($Outcome -eq 'revoked' -or $Outcome -eq 'already-revoked')
}
