<#
.SYNOPSIS
    CA-side pull agent that closes the automated revocation loop (WI-024).

.DESCRIPTION
    This is the headline deliverable of v1.5: it automates the out-of-band
    CA-side revocation step that was previously a manual operator action
    (`scripts/Revoke-Cert.ps1`).

    The loop:
      1. GET <RaBaseUrl>/acme/admin/revocations/pending  (WI-023 endpoint,
         admin-token-gated) -> the RA's "revoked-in-RA-but-active-at-CA" set:
         a list of {serial, req_id, reason, revoked_at}.
      2. For each serial, call `Revoke-Cert.ps1` (which now self-checks the
         requester, WI-022) against the CA. `certutil -revoke -config` is
         remote-capable, so the agent does NOT need to run on the CA -- no
         Kerberos double-hop.
      3. On success, POST <RaBaseUrl>/acme/admin/revocations/<serial>/confirm
         with {"ca_crl_updated": true} so the RA audit flips
         `ca_crl_updated` to true and the serial drops out of the pending
         set on the next pull (idempotent).

    Two deployment topologies are supported:

      - Two-identity (default, recommended): the agent runs as a scheduled
        task on a UTILITY HOST (not the CA) under a dedicated
        `gMSA-acme-revoker$` whose CA-side officer power is template-scoped
        to `ACME-ServerAuth` by the CA's `OfficerRights` restriction
        (WI-025). The enrollment gMSA holds no CA-officer rights -- the
        cardinal invariant holds.

      - Single-identity (opt-in, -LocalMode): the agent runs on the RA host
        under the enrollment gMSA, which is also the revoker. The enrollment
        gMSA must be granted template-scoped OfficerRights on the CA (see
        docs/operations.md ## Single-identity deployment). This is a weaker
        posture (one credential compromise grants both issue and revoke --
        see threat-model section E) but operationally simpler. The invocation
        mechanism is unchanged; -LocalMode signals deployment intent and
        adjusts the mode banner/output.

    Fail-visible, dry-run default. Without -Execute the script is report-only:
    it fetches the pending set and prints what it WOULD do, making no change.
    Pass -Execute to arm it. Every auto-revoke lands in the CA DB (under the
    revoker identity) and the RA audit (via the confirm callback).

    The script is safe to run repeatedly: `Revoke-Cert.ps1` rejects reason 7,
    and a serial that is already revoked at the CA surfaces as a non-zero
    exit from `Revoke-Cert.ps1`, which the agent logs and continues past
    (fail-visible, does not abort the whole batch).

    Exit codes:
      0  = success (all pending serials revoked-and-confirmed, or dry-run
           completed, or no pending revocations)
      1  = the RA was unreachable or the pending endpoint returned an error
      2  = partial failure (one or more serials failed to revoke; see the
           per-serial log lines above)

.PARAMETER RaBaseUrl
    The RA's base URL (e.g. "https://ra.WORK-DOMAIN.local"). The admin
    pending endpoint is at <RaBaseUrl>/acme/admin/revocations/pending.

.PARAMETER AdminToken
    The RA admin Bearer token (ACME_RA_ADMIN_TOKEN). Gates the admin
    endpoints. Treat like an EAB MAC key -- do not commit, do not log.
    Optional: if omitted, the token is read from the ACME_ADMIN_TOKEN
    environment variable. The scheduled-task registration
    (Register-MaintenanceTasks.ps1 -RegisterRevocationSync) uses the
    environment form so the token never appears on this script's process
    command line.

.PARAMETER CaConfig
    The CA configuration string ("CA01\WORK-DOMAIN-CA" form). Passed through
    to `Revoke-Cert.ps1` for `certutil -revoke -config`.

.PARAMETER RequesterName
    The expected enrollment identity, passed through to `Revoke-Cert.ps1`'s
    -RequesterName (WI-022 requester check). Default:
    "WORK-DOMAIN\gMSA-acme-ra$" (placeholder form).

.PARAMETER DryRun
    Explicit dry-run: fetch the pending set and print what would be done,
    making no change. This is the default behavior when neither -DryRun nor
    -Execute is given.

.PARAMETER Execute
    Arm the script to actually revoke (call `Revoke-Cert.ps1` and the RA
    confirm callback). Mutually exclusive with -DryRun. Without this switch
    the script is report-only.

.PARAMETER ScriptDir
    Directory containing `Revoke-Cert.ps1`. Default: the same directory as
    this script ($PSScriptRoot).

.PARAMETER LocalMode
    Single-identity deployment: the agent runs on the RA host under the
    enrollment gMSA (which is also the revoker). The enrollment gMSA must
    have template-scoped OfficerRights on the CA (see docs/operations.md
    ## Single-identity deployment). The requester check passes trivially
    since the revoker IS the enrollment gMSA. This flag adjusts the mode
    banner and output; the invocation mechanism is unchanged.

.PARAMETER PublishCrl
    Force an immediate CRL republish after each revocation (passes through by
    NOT setting Revoke-Cert.ps1's -SkipPublishCrl). OFF by default: the default
    is least-privilege -- the revoker/officer identity revokes the cert (which
    the CA records immediately) but does NOT republish the CRL, so the
    revocation becomes visible at the next scheduled CRL publication.
    `certutil -CRL republish` requires the Manage-CA role, so -PublishCrl is
    only usable when the identity has been granted CRL-publish rights. That is
    an explicit operator trade-off: CRL freshness in exchange for a broader
    grant (in the single-identity topology it means the internet-facing
    enrollment identity also holds Manage-CA -- strongly discouraged; more
    defensible for the dedicated two-identity revoker). See threat-model
    section E and docs/operations.md.

.EXAMPLE
    # Dry run (default -- report only, no changes):
    powershell -File .\scripts\Sync-Revocations.ps1 `
        -RaBaseUrl "https://ra.WORK-DOMAIN.local" `
        -AdminToken "REPLACE-WITH-HIGH-ENTROPY-ADMIN-TOKEN" `
        -CaConfig 'CA01\WORK-DOMAIN-CA'

.EXAMPLE
    # Execute (actually revoke pending serials at the CA):
    powershell -File .\scripts\Sync-Revocations.ps1 `
        -RaBaseUrl "https://ra.WORK-DOMAIN.local" `
        -AdminToken "REPLACE-WITH-HIGH-ENTROPY-ADMIN-TOKEN" `
        -CaConfig 'CA01\WORK-DOMAIN-CA' -Execute

.EXAMPLE
    # Single-identity deployment (agent on the RA host under the enrollment
    # gMSA, which is also the revoker):
    powershell -File .\scripts\Sync-Revocations.ps1 `
        -RaBaseUrl "https://ra.WORK-DOMAIN.local" `
        -AdminToken "REPLACE-WITH-HIGH-ENTROPY-ADMIN-TOKEN" `
        -CaConfig 'CA01\WORK-DOMAIN-CA' -Execute -LocalMode

.NOTES
    Schedule as a Windows Scheduled Task running as `gMSA-acme-revoker$` on
    a utility host with line-of-sight to both the RA (HTTPS) and the CA
    (certutil -config RPC/DCOM). See docs/operations.md ## Automated
    revocation. No signing key, no enrollment -- this is an operator/revoker
    tool only.

    For single-identity deployments, pass -LocalMode and schedule the task
    on the RA host under the enrollment gMSA (which is also the revoker).
    See docs/operations.md ## Single-identity deployment and threat-model
    section E for the explicit trade-off. The invocation mechanism is the same
    either way; -LocalMode signals the deployment topology.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RaBaseUrl,
    [string]$AdminToken = "",
    [Parameter(Mandatory = $true)][string]$CaConfig,
    [string]$RequesterName = "WORK-DOMAIN\gMSA-acme-ra$",
    [switch]$DryRun,
    [switch]$Execute,
    [string]$ScriptDir = "",
    [switch]$LocalMode,
    [switch]$PublishCrl
)

$ErrorActionPreference = "Stop"

function Die([string]$Message, [int]$Code) {
    [Console]::Error.WriteLine("ERROR: $Message")
    exit $Code
}

# Fail-visible: dry-run is the default. -Execute arms the script. Both
# switches is a contradiction.
if ($Execute -and $DryRun) {
    Die "-Execute and -DryRun are mutually exclusive. Use -Execute to revoke, or neither for a dry run (default)." 3
}
$liveMode = [bool]$Execute

# Admin token: prefer the -AdminToken parameter; fall back to the
# ACME_ADMIN_TOKEN environment variable. The scheduled-task registration
# passes it via the environment so the token never lands on this script's
# process command line (visible in a process listing during the run window).
if ([string]::IsNullOrWhiteSpace($AdminToken)) {
    $AdminToken = $env:ACME_ADMIN_TOKEN
}
if ([string]::IsNullOrWhiteSpace($AdminToken)) {
    Die "No admin token supplied: pass -AdminToken or set the ACME_ADMIN_TOKEN environment variable." 3
}

# Resolve the Revoke-Cert.ps1 path.
if ([string]::IsNullOrWhiteSpace($ScriptDir)) {
    $ScriptDir = $PSScriptRoot
}
$revokeScript = Join-Path $ScriptDir 'Revoke-Cert.ps1'
if (-not (Test-Path $revokeScript)) {
    Die "Revoke-Cert.ps1 not found at '$revokeScript'" 1
}

# Resolve the PowerShell host to invoke Revoke-Cert.ps1 in a child process
# (so its `exit` becomes $LASTEXITCODE, not propagated as our own).
$pwshExe = $null
try {
    $pwshExe = (Get-Process -Id $PID).Path
} catch {
    $pwshExe = $null
}
if ([string]::IsNullOrWhiteSpace($pwshExe)) { $pwshExe = "powershell.exe" }

# Normalize the base URL (strip trailing slash for joining).
$base = $RaBaseUrl.TrimEnd('/')
$headers = @{ 'Authorization' = "Bearer $AdminToken" }

if ($liveMode) {
    if ($LocalMode) {
        Write-Output "MODE: EXECUTE (live, single-identity -- revoking as the enrollment gMSA)."
    } else {
        Write-Output "MODE: EXECUTE (live -- revocations WILL be applied at the CA)."
    }
} else {
    if ($LocalMode) {
        Write-Output "MODE: DRY-RUN (report only, single-identity). Pass -Execute to apply."
        Write-Output "NOTE: -LocalMode in dry-run is still report-only -- no revocations are applied."
    } else {
        Write-Output "MODE: DRY-RUN (report only -- no changes). Pass -Execute to apply."
    }
}
Write-Output ""

# 1. Fetch the pending revocations from the RA.
$pendingUrl = "$base/acme/admin/revocations/pending"
Write-Output "Fetching pending revocations from: $pendingUrl"
try {
    $response = Invoke-RestMethod -Method Get -Uri $pendingUrl -Headers $headers -TimeoutSec 60
} catch {
    Die ("RA unreachable -- GET {0} failed: {1}" -f $pendingUrl, $_.Exception.Message) 1
}

# Invoke-RestMethod may unwrap a single-element array into a scalar, and an
# empty JSON array may deserialize as $null. Force a clean array, filtering
# out any null entries (defensive against PowerShell's inconsistent empty-
# array deserialization across versions).
$pending = @()
if ($response -and $response.pending_revocations) {
    $pending = @($response.pending_revocations | Where-Object { $_ })
}
$total = $pending.Count
Write-Output ("Pending revocations: {0}" -f $total)
Write-Output ""

if ($total -eq 0) {
    Write-Output "Nothing to do -- RA has no pending CA-side revocations."
    Write-Output "SYNC COMPLETE: 0 pending, 0 revoked, 0 failed, 0 dry-run"
    exit 0
}

# 2. Process each pending revocation.
$revoked = 0
$failed = 0
$dryRunCount = 0
$index = 0

foreach ($entry in $pending) {
    $index++
    $serial = [string]$entry.serial
    $reqId = [string]$entry.req_id
    if ([string]::IsNullOrWhiteSpace($reqId)) { $reqId = "(none)" }
    $reason = 0
    if ($null -ne $entry.reason -and "$($entry.reason)" -ne '') {
        $reason = [int]$entry.reason
    }
    $revokedAt = [string]$entry.revoked_at

    if (-not $liveMode) {
        $dryRunCount++
        Write-Output ("[DRY-RUN] [{0}/{1}] Would revoke serial {2} (reason {3}, req_id {4}, revoked_at {5})" -f $index, $total, $serial, $reason, $reqId, $revokedAt)
        continue
    }

    Write-Output ("[{0}/{1}] Revoking serial {2} (reason {3}, req_id {4})..." -f $index, $total, $serial, $reason, $reqId)
    # Run Revoke-Cert.ps1 in a child PowerShell process so its `exit` code is
    # captured via $LASTEXITCODE (not propagated as our own). Redirect stderr
    # to stdout (2>&1) so the child's Die() messages display as output without
    # triggering the parent's $ErrorActionPreference=Stop as a native error.
    # By default, skip the CRL republish (certutil -CRL republish requires the
    # Manage-CA role, which a least-privilege revoker/officer identity does NOT
    # hold -- the revocation is recorded at the CA and appears at the next
    # scheduled CRL publication). Pass -PublishCrl to force an immediate
    # republish, which requires the identity to hold CRL-publish (Manage-CA)
    # rights -- an explicit operator trade-off (CRL freshness vs. a broader
    # grant). See docs/operations.md and threat-model section E.
    $revokeArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $revokeScript,
        '-CaConfig', $CaConfig, '-Serial', $serial, '-Reason', "$reason",
        '-RequesterName', $RequesterName
    )
    if (-not $PublishCrl) { $revokeArgs += '-SkipPublishCrl' }
    $revokeOutput = & $pwshExe @revokeArgs 2>&1
    $revokeExit = $LASTEXITCODE
    $revokeOutput | ForEach-Object { Write-Output $_ }

    if ($revokeExit -eq 5) {
        $failed++
        [Console]::Error.WriteLine(("CRITICAL: Revoke-Cert.ps1 exited 5 (requester mismatch) for serial {0} -- the cert was NOT issued by the expected enrollment gMSA. This is a policy violation. Aborting the batch." -f $serial))
        exit 5
    }
    if ($revokeExit -ne 0) {
        $failed++
        [Console]::Error.WriteLine(("WARNING: Revoke-Cert.ps1 exited {0} for serial {1} -- logged, continuing to next serial." -f $revokeExit, $serial))
        continue
    }

    Write-Output ("PASS: revoked serial {0} at the CA. Confirming with the RA..." -f $serial)

    # 3. Confirm with the RA so the audit flips ca_crl_updated=true and the
    #    serial drops out of the pending set. A confirm failure does NOT undo
    #    the CA-side revocation (which already happened) -- it means the RA
    #    audit still shows ca_crl_updated=false and the serial will reappear
    #    on the next pull. Log visibly and keep counting it as revoked.
    $confirmUrl = "$base/acme/admin/revocations/$serial/confirm"
    $confirmBody = '{"ca_crl_updated": true}'
    try {
        Invoke-RestMethod -Method Post -Uri $confirmUrl -Headers $headers `
            -Body $confirmBody -ContentType 'application/json' -TimeoutSec 60 | Out-Null
        Write-Output ("PASS: confirmed serial {0} with the RA." -f $serial)
    } catch {
        [Console]::Error.WriteLine(("WARNING: confirm POST for serial {0} failed: {1}" -f $serial, $_.Exception.Message))
        [Console]::Error.WriteLine("         The CA-side revocation SUCCEEDED, but the RA audit was not updated.")
        [Console]::Error.WriteLine("         The serial will reappear on the next pull until the confirm succeeds.")
    }
    $revoked++
    Write-Output ""
}

# 4. Summary.
Write-Output ""
Write-Output ("SYNC COMPLETE: {0} pending, {1} revoked, {2} failed, {3} dry-run" -f $total, $revoked, $failed, $dryRunCount)

if ($failed -gt 0) {
    exit 2
}
exit 0
