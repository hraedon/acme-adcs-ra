<#
.SYNOPSIS
    Register the acme-adcs-ra scheduled maintenance tasks (WI-013).

.DESCRIPTION
    Creates or updates the acme-adcs-ra scheduled maintenance tasks (WI-013).
    By default, two tasks drive the RA's admin maintenance endpoints on a
    cadence (default 15 minutes):

      - acme-adcs-ra-nonce-cleanup        -> DELETE /acme/admin/nonces
      - acme-adcs-ra-expired-order-sweep -> DELETE /acme/admin/expired-orders

    Both endpoints require the admin Bearer token (ACME_RA_ADMIN_TOKEN).
    Since 2026-08-19 F2 the token is NOT written into the task definition:
    the action reads it at run time from the RA's dotenv (-DotEnvPath), which
    the installer ACLs to Administrators/SYSTEM full and the task's gMSA
    read-only. A task definition therefore carries a file path, not a
    credential, and the secret never reaches a process command line. Treat the
    token like an EAB MAC key (see docs/operations.md ## Admin token and
    reclaim runbook).

    Optionally (-RegisterRevocationSync), a third task --
    acme-adcs-ra-sync-revocations -- runs the CA-side revocation pull agent
    (Sync-Revocations.ps1, WI-024) on the same cadence. Unlike the
    nonce/sweep tasks (which call Invoke-RestMethod against an admin
    endpoint), the sync task runs Sync-Revocations.ps1 as a PowerShell
    command with -Execute. Off by default so the two-identity utility-host
    deployment is unaffected.

    The tasks are idempotent: if a task already exists, it is updated in
    place (Unregister + Register). Use -WhatIf to preview the actions
    without registering anything.

.PARAMETER BaseUrl
    The RA's public base URL (e.g. "https://acme-ra.WORK-DOMAIN.local/").
    Must match ACME_RA_BASE_URL -- the admin endpoints are under /acme/admin/.

.PARAMETER AdminToken
    Declare that this host's tasks should hold ADMIN authority. This is a
    SWITCH, not a value: since the Daybreak 2026-08-15 review the script
    accepts no secret on its command line at all -- the registration command
    is shell history and a process argument list, which is exactly where a
    one-time-pasted token should never travel. The task action loads
    ACME_RA_ADMIN_TOKEN from -DotEnvPath at RUN TIME; the value must already
    be present there. Required (as a flag) when registering the general
    nonce/sweep tasks; omit it entirely on a dedicated revocation host.

.PARAMETER ConfirmToken
    Declare that the revocation-sync task should load the revocation
    CONFIRM credential (ACME_RA_REVOCATION_CONFIRM_TOKEN) from -DotEnvPath at
    run time. A SWITCH, like -AdminToken: the value itself is never accepted
    here. The confirm token is the least-privilege credential and the only
    one the confirm endpoint accepts; preferred over -AdminToken for the sync
    task. The value must already be present in the dotenv.

.PARAMETER IntervalMinutes
    Cadence in minutes for both tasks (default 15).

.PARAMETER TaskUser
    The account the tasks run as. Default is the gMSA
    ("WORK-DOMAIN\gMSA-acme-ra$") so the task can read acme-ra.env if needed
    and has no more privilege than the RA itself. Alternatively pass
    "NT AUTHORITY\SYSTEM" or a dedicated service account.

.PARAMETER TaskFolder
    Optional scheduled-task folder (default "\acme-adcs-ra\"). Must start
    and end with a backslash.

.PARAMETER RegisterRevocationSync
    Also register the acme-adcs-ra-sync-revocations task, which runs
    Sync-Revocations.ps1 (the CA-side revocation pull agent, WI-024) on the
    same cadence. Requires -CaConfig. Off by default so the two-identity
    utility-host deployment (where the sync task is registered separately on
    the utility host) is unaffected.

.PARAMETER CaConfig
    The CA configuration string ("CA01\WORK-DOMAIN-CA" form). Required when
    -RegisterRevocationSync is set; passed through to Sync-Revocations.ps1
    (and onward to Revoke-Cert.ps1 / certutil -revoke -config). Ignored
    when -RegisterRevocationSync is not set.

.PARAMETER RequesterName
    The expected enrollment identity, passed through to Sync-Revocations.ps1's
    -RequesterName (the WI-022 requester check in Revoke-Cert.ps1). Must be the
    real DOMAIN\account under which the RA enrolls (as recorded in the CA DB
    Requester column), e.g. "CONTOSO\gMSA-acme-ra$". Defaults to the committed
    placeholder "WORK-DOMAIN\gMSA-acme-ra$" -- override it, or the requester
    check refuses every revoke ("Requester mismatch"). Only meaningful with
    -RegisterRevocationSync.

.PARAMETER PublishCrl
    Passed through to Sync-Revocations.ps1 as -PublishCrl: force an immediate
    CRL republish after each revocation. OFF by default (least-privilege: the
    revocation is recorded at the CA and appears at the next scheduled CRL
    publication). Enabling it requires the task identity to hold Manage-CA
    (CRL-publish) rights -- an explicit operator trade-off. See
    Sync-Revocations.ps1 .PARAMETER PublishCrl and threat-model section E.
    Only meaningful with -RegisterRevocationSync.

.PARAMETER LocalMode
    Passed through to Sync-Revocations.ps1 as -LocalMode, signalling
    single-identity deployment (agent on the RA host under the enrollment
    gMSA, which is also the revoker). Only meaningful with
    -RegisterRevocationSync. See Sync-Revocations.ps1 .PARAMETER LocalMode
    and docs/operations.md ## Single-identity deployment.

.PARAMETER DryRun
    Register the revocation-sync task in report-only mode: the task action
    passes -DryRun (not -Execute) to Sync-Revocations.ps1, so it fetches the
    pending set and prints what it would do without making any change. Use
    this for the dry-run -> execute promotion path (see docs/operations.md
    ## Dry-run -> execute promotion). Re-register without -DryRun to arm the
    task. Only meaningful with -RegisterRevocationSync.

.PARAMETER WhatIf
    Dry run: print the actions that would be taken without registering
    anything.

.EXAMPLE
    # Register both tasks as the gMSA on a 15-minute cadence. Note: -AdminToken
    # is a FLAG -- the value lives in the dotenv, never on a command line:
    powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
        -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
        -AdminToken `
        -IntervalMinutes 15 `
        -TaskUser "WORK-DOMAIN\gMSA-acme-ra$"

.EXAMPLE
    # Dry run (does not register anything):
    powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
        -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
        -AdminToken -WhatIf

.EXAMPLE
    # Single-identity deployment: also register the revocation-sync task on
    # the RA host under the enrollment gMSA (which is also the revoker):
    powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
        -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
        -AdminToken -ConfirmToken `
        -IntervalMinutes 15 `
        -TaskUser "WORK-DOMAIN\gMSA-acme-ra$" `
        -RegisterRevocationSync -CaConfig 'CA01\WORK-DOMAIN-CA' -LocalMode

.NOTES
    Run elevated (local Administrator). Requires the ScheduledTasks module
    (built into Windows Server). See docs/operations.md ## Scheduled
    maintenance tasks. No signing key, no enrollment -- this is an operator
    admin tool only.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$BaseUrl,
    # Daybreak 2026-08-15 review: these used to be [string] parameters, so the
    # one-time registration command carried the FULL token values through the
    # shell history and the invoking process's argument list -- the last place
    # a secret still traveled after F2 moved them out of the task definitions.
    # They are SWITCHES now: they declare WHICH key the task loads from the
    # dotenv at run time, and a value cannot be passed at all. A pre-switch
    # invocation fails loudly at parameter binding rather than silently
    # continuing.
    [switch]$AdminToken,
    [switch]$ConfirmToken,
    [int]$IntervalMinutes = 15,
    [string]$TaskUser = "WORK-DOMAIN\gMSA-acme-ra$",
    [string]$TaskFolder = "\acme-adcs-ra\",
    [switch]$RegisterRevocationSync,
    [switch]$RevocationSyncOnly,
    [string]$CaConfig = "",
    [string]$RequesterName = "WORK-DOMAIN\gMSA-acme-ra$",
    [switch]$LocalMode,
    [switch]$DryRun,
    [switch]$PublishCrl,
    [switch]$AllowInsecureUrl,
    # Where the task reads its credentials AT RUN TIME (2026-08-19 F2). The
    # tokens are never written into the task definition; the action loads
    # them from this file, which the installer ACLs to Administrators/SYSTEM
    # full and the task's gMSA read-only.
    [string]$DotEnvPath = "C:\ProgramData\acme-adcs-ra\acme-ra.env"
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot/lib/TaskActionLib.ps1"
. "$PSScriptRoot/lib/SyncLib.ps1"

if ($IntervalMinutes -lt 1) {
    Write-Error "-IntervalMinutes must be >= 1 (got $IntervalMinutes)."
    exit 3
}

# Which task groups are we registering?
#   * General maintenance (nonce cleanup + expired-order sweep) hit admin-only
#     endpoints, so they require the admin token and belong ONLY on the RA host.
#   * The revocation-sync task runs on the (recommended separate) revocation
#     host and needs only the narrow confirm token.
# -RevocationSyncOnly is the dedicated-revocation-host mode: it skips the
# general tasks entirely, so no admin token is required or planted there.
$registerGeneral = -not $RevocationSyncOnly
$registerSync = $RegisterRevocationSync -or $RevocationSyncOnly

# The general maintenance tasks' actions load the admin token; refuse to
# register them without the -AdminToken flag. On a revocation host, pass
# -RevocationSyncOnly to skip them.
if ($registerGeneral -and -not $AdminToken) {
    Write-Error ("-AdminToken is required to register the general nonce/sweep maintenance tasks " +
                 "(their actions load ACME_RA_ADMIN_TOKEN from the dotenv at run time). It is a FLAG: " +
                 "the value must already be in the dotenv and is never passed here. On a dedicated " +
                 "revocation host, pass -RevocationSyncOnly with -ConfirmToken to register only the " +
                 "revocation-sync task and omit the admin authority entirely.")
    exit 3
}

# The revocation-sync task needs at least one credential. ConfirmToken is the
# least-privilege choice and the only one the confirm endpoint accepts; the
# admin flag remains as a fallback for deployments not yet split.
if ($registerSync -and -not $ConfirmToken -and -not $AdminToken) {
    Write-Error "-RegisterRevocationSync/-RevocationSyncOnly requires -ConfirmToken (preferred) or -AdminToken -- as flags; the values live in the dotenv, not on this command line."
    exit 3
}

# The revocation-sync task requires -CaConfig (passed through to
# Sync-Revocations.ps1 and onward to Revoke-Cert.ps1 / certutil -config).
if ($registerSync -and [string]::IsNullOrWhiteSpace($CaConfig)) {
    Write-Error "-RegisterRevocationSync/-RevocationSyncOnly requires -CaConfig (the CA configuration string, e.g. 'CA01\WORK-DOMAIN-CA')."
    exit 3
}

# M-2: -LocalMode and -DryRun only have an effect with -RegisterRevocationSync.
# Warn (don't fail) so a misplaced flag is visible rather than silently ignored.
if (($LocalMode -or $DryRun) -and -not $RegisterRevocationSync) {
    Write-Warning "-LocalMode and -DryRun only apply to the revocation-sync task; pass -RegisterRevocationSync to register it. Ignoring these flags for the nonce/sweep tasks."
}

# Validate the base URL before it is baked into a scheduled-task action. A
# task registered against an http:// or credential-embedding URL would send
# the dotenv-loaded token in cleartext or to an attacker's host on every run,
# forever, with nothing in the task output to show it.
try {
    $base = Assert-SafeRaUrl -Url $BaseUrl -AllowInsecureUrl:$AllowInsecureUrl
} catch {
    Write-Error $_.Exception.Message
    exit 3
}

# Two maintenance tasks: (name, endpoint path). Both are DELETE with the
# admin Bearer token. The task action is a PowerShell one-liner that invokes
# Invoke-RestMethod with the header. The action reads the token from the
# dotenv at run time (2026-08-19 F2) -- it is never interpolated here.
$tasks = @(
    @{
        Name = "acme-adcs-ra-nonce-cleanup"
        Path = "/acme/admin/nonces"
        Description = "acme-adcs-ra: DELETE /acme/admin/nonces (nonce GC). See docs/operations.md."
    },
    @{
        Name = "acme-adcs-ra-expired-order-sweep"
        Path = "/acme/admin/expired-orders"
        Description = "acme-adcs-ra: DELETE /acme/admin/expired-orders (RFC 8555 7.1.6 sweep). See docs/operations.md."
    }
)

# Build a ScheduledTask principal for the task user. A gMSA (or any non-well-
# known service account) must use LogonType=Password so the host retrieves the
# managed password. LogonType=Interactive (the Register-ScheduledTask -User
# default) leaves the task unable to start -- a gMSA is never interactively
# logged on, so the task registers but silently never runs. Well-known service
# accounts (SYSTEM / LOCAL SERVICE / NETWORK SERVICE) use ServiceAccount.
function Get-TaskPrincipal([string]$UserId) {
    $u = $UserId.ToUpperInvariant()
    $svc = ($u -eq 'SYSTEM' -or $u -eq 'NT AUTHORITY\SYSTEM' -or $u -like '*LOCAL SERVICE' -or $u -like '*NETWORK SERVICE')
    $logon = if ($svc) { 'ServiceAccount' } else { 'Password' }
    return New-ScheduledTaskPrincipal -UserId $UserId -LogonType $logon -RunLevel Limited
}

function Register-OrUpdate-Task([hashtable]$TaskDef) {
    $taskName = $TaskDef.Name
    $fullName = "$TaskFolder$taskName"
    $url = "$base$($TaskDef.Path)"
    $actionScript = Build-ActionScriptBlock $url $DotEnvPath

    if ($PSCmdlet.ShouldProcess($fullName, "Register scheduled task")) {
        # Idempotent: unregister the existing task if present, then register.
        if (Get-ScheduledTask -TaskName $fullName -ErrorAction SilentlyContinue) {
            Write-Output ("Updating existing task: $fullName")
            Unregister-ScheduledTask -TaskName $fullName -Confirm:$false
        } else {
            Write-Output ("Registering new task: $fullName")
        }

        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"$actionScript`""
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
            -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 2)

        # Register under the task user via a principal with the correct
        # LogonType (Password for a gMSA -- the host retrieves the managed
        # password; a gMSA never logs on interactively). See Get-TaskPrincipal.
        $registerParams = @{
            TaskName  = $fullName
            Action    = $action
            Trigger   = $trigger
            Settings  = $settings
            Principal = (Get-TaskPrincipal $TaskUser)
            Force     = $true
        }
        Register-ScheduledTask @registerParams | Out-Null

        Write-Output ("Registered: $fullName")
        Write-Output ("  User:     $TaskUser")
        Write-Output ("  Interval: $IntervalMinutes min")
        Write-Output ("  Endpoint: $url")
    } else {
        Write-Output ("[WhatIf] Would register: $fullName")
        Write-Output ("[WhatIf]   User:     $TaskUser")
        Write-Output ("[WhatIf]   Interval: $IntervalMinutes min")
        Write-Output ("[WhatIf]   Endpoint: $url")
    }
}

# Registers the revocation-sync task (acme-adcs-ra-sync-revocations), which
# runs Sync-Revocations.ps1 -Execute on the maintenance cadence. Unlike the
# nonce/sweep tasks, the action calls Sync-Revocations.ps1 (not
# Invoke-RestMethod). The admin token is delivered to the task via the
# environment ($env:ACME_ADMIN_TOKEN in the action), not on a command line.
function Register-RevocationSyncTask {
    $taskName = "acme-adcs-ra-sync-revocations"
    $fullName = "$TaskFolder$taskName"

    # Resolve Sync-Revocations.ps1 relative to this registration script
    # (same scripts/ directory). The path is embedded in the task action at
    # registration time -- $PSScriptRoot is NOT available when the task runs.
    $syncScriptPath = Join-Path $PSScriptRoot 'Sync-Revocations.ps1'
    if (-not (Test-Path $syncScriptPath)) {
        Write-Error "Sync-Revocations.ps1 not found at '$syncScriptPath' (expected alongside this registration script in the same directory)."
        exit 1
    }

    # Which KEYS the action loads is what preserves least privilege now -- the
    # secrets themselves never enter the task definition (2026-08-19 F2) and,
    # since the Daybreak 2026-08-15 review, never enter this script either.
    $actionScript = Build-SyncActionCommand -BaseUrl $base -CaConfigStr $CaConfig `
        -Local $LocalMode -DryRunMode $DryRun -ScriptPath $syncScriptPath `
        -Requester $RequesterName -PublishCrlMode $PublishCrl -DotEnvPath $DotEnvPath `
        -LoadAdminToken ([bool]$AdminToken) `
        -LoadConfirmToken ([bool]$ConfirmToken)

    if (-not $ConfirmToken) {
        Write-Warning ("-ConfirmToken not set. The RA refuses the general admin token on the " +
                       "revocation-confirm endpoint, so this task will revoke at the CA and then " +
                       "fail every confirm, leaving serials on the pending list. Set " +
                       "ACME_RA_REVOCATION_CONFIRM_TOKEN in the RA's dotenv and pass the flag here.")
    }

    if ($PSCmdlet.ShouldProcess($fullName, "Register revocation-sync scheduled task")) {
        # Idempotent: unregister the existing task if present, then register.
        if (Get-ScheduledTask -TaskName $fullName -ErrorAction SilentlyContinue) {
            Write-Output ("Updating existing task: $fullName")
            Unregister-ScheduledTask -TaskName $fullName -Confirm:$false
        } else {
            Write-Output ("Registering new task: $fullName")
        }

        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"$actionScript`""
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
            -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 2)

        # Register under the task user via a principal with the correct
        # LogonType (Password for a gMSA -- see Get-TaskPrincipal). Same default
        # task user as the nonce/sweep tasks.
        $registerParams = @{
            TaskName  = $fullName
            Action    = $action
            Trigger   = $trigger
            Settings  = $settings
            Principal = (Get-TaskPrincipal $TaskUser)
            Force     = $true
        }
        Register-ScheduledTask @registerParams | Out-Null

        Write-Output ("Registered: $fullName")
        Write-Output ("  User:     $TaskUser")
        Write-Output ("  Interval: $IntervalMinutes min")
        Write-Output ("  Script:   $syncScriptPath")
        Write-Output ("  CaConfig: $CaConfig")
        if ($LocalMode) {
            Write-Output ("  Mode:     single-identity (-LocalMode)")
        }
        # Make the report-only-vs-armed distinction loud. -DryRun registers a
        # REAL, scheduled task that will run on the cadence -- it just runs
        # Sync-Revocations.ps1 in report-only mode. This is NOT the same as
        # -WhatIf (which registers nothing). Re-register without -DryRun to arm.
        if ($DryRun) {
            Write-Warning ("Task '$taskName' is ARMED and will run every $IntervalMinutes min, but in REPORT-ONLY mode (-DryRun): it fetches the pending set and logs what it would do, applying NO revocations. Re-register WITHOUT -DryRun to apply revocations.")
        } else {
            Write-Warning ("Task '$taskName' is LIVE: it will apply revocations at the CA every $IntervalMinutes min as $TaskUser. Confirm you have completed the dry-run (-DryRun) validation first.")
        }
    } else {
        Write-Output ("[WhatIf] Would register: $fullName")
        Write-Output ("[WhatIf]   User:     $TaskUser")
        Write-Output ("[WhatIf]   Interval: $IntervalMinutes min")
        Write-Output ("[WhatIf]   Script:   $syncScriptPath")
        Write-Output ("[WhatIf]   CaConfig: $CaConfig")
        if ($LocalMode) {
            Write-Output ("[WhatIf]   Mode:     single-identity (-LocalMode)")
        }
        if ($DryRun) {
            Write-Output ("[WhatIf]   Mode:     report-only (-DryRun); re-register without -DryRun to arm")
        } else {
            Write-Output ("[WhatIf]   Mode:     LIVE (will apply revocations)")
        }
    }
}

# General maintenance tasks (nonce cleanup, expired-order sweep). Skipped on a
# dedicated revocation host (-RevocationSyncOnly) so the admin token is never
# planted there.
if ($registerGeneral) {
    foreach ($task in $tasks) {
        Register-OrUpdate-Task $task
    }
}

# Optionally register the revocation-sync task (WI-032). Off by default so
# the two-identity utility-host deployment is unaffected.
if ($registerSync) {
    Write-Output ""
    Register-RevocationSyncTask
}

# Validation: list the tasks and print their NextRunTime (if not WhatIf).
if (-not $WhatIfPreference) {
    Write-Output ""
    Write-Output "Validation -- registered tasks:"
    # Get-ScheduledTask matches the leaf name via -TaskName + the folder via
    # -TaskPath; passing the full "\folder\name" as -TaskName does NOT match.
    $names = @()
    if ($registerGeneral) { $names += @($tasks | ForEach-Object { $_.Name }) }
    if ($registerSync) { $names += 'acme-adcs-ra-sync-revocations' }
    foreach ($name in $names) {
        $t = Get-ScheduledTask -TaskName $name -TaskPath $TaskFolder -ErrorAction SilentlyContinue
        if ($t) {
            $info = Get-ScheduledTaskInfo -TaskName $name -TaskPath $TaskFolder
            Write-Output ("  {0}{1}: State={2}, NextRunTime={3}" -f $TaskFolder, $name, $t.State, $info.NextRunTime)
        } else {
            Write-Output ("  {0}{1}: NOT FOUND (registration failed)" -f $TaskFolder, $name)
            exit 1
        }
    }
}

Write-Output ""
Write-Output "Done. See docs/operations.md ## Scheduled maintenance tasks."
Write-Output "NOTE: the task actions load their credentials from"
Write-Output "      $DotEnvPath at RUN TIME. Rotating a token means editing the"
Write-Output "      dotenv (and recycling the app pool if the RA itself reads it) -- there is"
Write-Output "      nothing to re-register and no credential here to rotate."
exit 0
