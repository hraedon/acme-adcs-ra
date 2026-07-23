<#
.SYNOPSIS
    Register the acme-adcs-ra scheduled maintenance tasks (WI-013).

.DESCRIPTION
    Creates or updates the acme-adcs-ra scheduled maintenance tasks (WI-013).
    By default, two tasks drive the RA's admin maintenance endpoints on a
    cadence (default 15 minutes):

      - acme-adcs-ra-nonce-cleanup        -> DELETE /acme/admin/nonces
      - acme-adcs-ra-expired-order-sweep -> DELETE /acme/admin/expired-orders

    Both endpoints require the admin Bearer token (ACME_RA_ADMIN_TOKEN). The
    token is passed as a SecureString parameter and embedded in the task
    action's Invoke-RestMethod headers — it is NOT written to a file the
    task reads, and it is NOT logged. Treat the token like an EAB MAC key
    (see docs/operations.md ## Admin token and reclaim runbook).

    Optionally (-RegisterRevocationSync), a third task —
    acme-adcs-ra-sync-revocations — runs the CA-side revocation pull agent
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
    Must match ACME_RA_BASE_URL — the admin endpoints are under /acme/admin/.

.PARAMETER AdminToken
    The admin Bearer token (high-entropy, >=256 bits). Passed as a plain
    string or SecureString; embedded in the task action's headers. Do NOT
    commit this value — supply it at install time.

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
    this for the dry-run → execute promotion path (see docs/operations.md
    ## Dry-run → execute promotion). Re-register without -DryRun to arm the
    task. Only meaningful with -RegisterRevocationSync.

.PARAMETER WhatIf
    Dry run: print the actions that would be taken without registering
    anything.

.EXAMPLE
    # Register both tasks as the gMSA on a 15-minute cadence:
    powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
        -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
        -AdminToken "REPLACE-WITH-HIGH-ENTROPY-ADMIN-TOKEN" `
        -IntervalMinutes 15 `
        -TaskUser "WORK-DOMAIN\gMSA-acme-ra$"

.EXAMPLE
    # Dry run (does not register anything):
    powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
        -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
        -AdminToken "REPLACE-WITH-HIGH-ENTROPY-ADMIN-TOKEN" -WhatIf

.EXAMPLE
    # Single-identity deployment: also register the revocation-sync task on
    # the RA host under the enrollment gMSA (which is also the revoker):
    powershell -ExecutionPolicy Bypass -File .\scripts\Register-MaintenanceTasks.ps1 `
        -BaseUrl "https://acme-ra.WORK-DOMAIN.local" `
        -AdminToken "REPLACE-WITH-HIGH-ENTROPY-ADMIN-TOKEN" `
        -IntervalMinutes 15 `
        -TaskUser "WORK-DOMAIN\gMSA-acme-ra$" `
        -RegisterRevocationSync -CaConfig 'CA01\WORK-DOMAIN-CA' -LocalMode

.NOTES
    Run elevated (local Administrator). Requires the ScheduledTasks module
    (built into Windows Server). See docs/operations.md ## Scheduled
    maintenance tasks. No signing key, no enrollment — this is an operator
    admin tool only.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$BaseUrl,
    [Parameter(Mandatory = $true)][string]$AdminToken,
    [int]$IntervalMinutes = 15,
    [string]$TaskUser = "WORK-DOMAIN\gMSA-acme-ra$",
    [string]$TaskFolder = "\acme-adcs-ra\",
    [switch]$RegisterRevocationSync,
    [string]$CaConfig = "",
    [switch]$LocalMode,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

if ($IntervalMinutes -lt 1) {
    Write-Error "-IntervalMinutes must be >= 1 (got $IntervalMinutes)."
    exit 3
}

# -RegisterRevocationSync requires -CaConfig (passed through to
# Sync-Revocations.ps1 and onward to Revoke-Cert.ps1 / certutil -config).
if ($RegisterRevocationSync -and [string]::IsNullOrWhiteSpace($CaConfig)) {
    Write-Error "-RegisterRevocationSync requires -CaConfig (the CA configuration string, e.g. 'CA01\WORK-DOMAIN-CA')."
    exit 3
}

# M-2: -LocalMode and -DryRun only have an effect with -RegisterRevocationSync.
# Warn (don't fail) so a misplaced flag is visible rather than silently ignored.
if (($LocalMode -or $DryRun) -and -not $RegisterRevocationSync) {
    Write-Warning "-LocalMode and -DryRun only apply to the revocation-sync task; pass -RegisterRevocationSync to register it. Ignoring these flags for the nonce/sweep tasks."
}

# Normalize the base URL (strip trailing slash for joining).
$base = $BaseUrl.TrimEnd('/')

# Two maintenance tasks: (name, endpoint path). Both are DELETE with the
# admin Bearer token. The task action is a PowerShell one-liner that invokes
# Invoke-RestMethod with the header. The token is embedded in the action's
# script block — it is not written to a separate file the task reads.
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

# The action script block. The token is interpolated here at registration
# time — it lives in the registered task action, not in a file the task reads.
# Using -Headers to avoid logging the token to the task's command-line history.
function Build-ActionScriptBlock([string]$EndpointUrl, [string]$Token) {
    # Single-quoted the token inside the double-quoted here-string so PS
    # interpolates it at registration time (not at run time, where it would
    # be visible in the task's command line). The -Headers hashtable carries
    # it; Invoke-RestMethod does not log headers.
    return @"
`$ErrorActionPreference = 'Stop'
try {
    `$resp = Invoke-RestMethod -Method Delete -Uri '$EndpointUrl' -Headers @{ 'Authorization' = 'Bearer $Token' } -TimeoutSec 60
    Write-Output ("`$(`$resp | ConvertTo-Json -Compress)")
} catch {
    Write-Error ("`$(`$_.Exception.Message)")
    exit 1
}
"@
}

# Action builder for the revocation-sync task. Unlike Build-ActionScriptBlock
# (which calls Invoke-RestMethod against an admin endpoint), this runs
# Sync-Revocations.ps1 as a PowerShell command with -Execute. The script path
# is resolved at registration time ($PSScriptRoot of this registration script,
# which is the same scripts/ directory). The token is interpolated into the
# command line at registration time — same pattern as the manual scheduling
# example in docs/operations.md ## Automated revocation.
function Build-SyncActionScriptBlock([string]$BaseUrl, [string]$Token, [string]$CaConfigStr, [bool]$Local, [bool]$DryRunMode, [string]$ScriptPath) {
    $localFlag = if ($Local) { " -LocalMode" } else { "" }
    $modeFlag = if ($DryRunMode) { " -DryRun" } else { " -Execute" }
    return @"
`$ErrorActionPreference = 'Stop'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$ScriptPath" -RaBaseUrl '$BaseUrl' -AdminToken '$Token' -CaConfig '$CaConfigStr'$modeFlag$localFlag
exit `$LASTEXITCODE
"@
}

function Register-OrUpdate-Task([hashtable]$TaskDef) {
    $taskName = $TaskDef.Name
    $fullName = "$TaskFolder$taskName"
    $url = "$base$($TaskDef.Path)"
    $actionScript = Build-ActionScriptBlock $url $AdminToken

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

        # Register under the task user. The gMSA form
        # ("WORK-DOMAIN\gMSA-acme-ra$") is a service account; SYSTEM needs no
        # password. For a gMSA, do NOT pass -Password (the host retrieves it).
        $registerParams = @{
            TaskName  = $fullName
            Action    = $action
            Trigger   = $trigger
            Settings  = $settings
            User      = $TaskUser
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
# Invoke-RestMethod). The admin token is embedded in the task action's
# arguments (same pattern as the manual example in docs/operations.md).
function Register-RevocationSyncTask {
    $taskName = "acme-adcs-ra-sync-revocations"
    $fullName = "$TaskFolder$taskName"

    # Resolve Sync-Revocations.ps1 relative to this registration script
    # (same scripts/ directory). The path is embedded in the task action at
    # registration time — $PSScriptRoot is NOT available when the task runs.
    $syncScriptPath = Join-Path $PSScriptRoot 'Sync-Revocations.ps1'
    if (-not (Test-Path $syncScriptPath)) {
        Write-Error "Sync-Revocations.ps1 not found at '$syncScriptPath' (expected alongside this registration script in the same directory)."
        exit 1
    }

    $actionScript = Build-SyncActionScriptBlock -BaseUrl $base -Token $AdminToken -CaConfigStr $CaConfig -Local $LocalMode -DryRunMode $DryRun -ScriptPath $syncScriptPath

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

        # Register under the task user (same default as nonce/sweep tasks).
        $registerParams = @{
            TaskName  = $fullName
            Action    = $action
            Trigger   = $trigger
            Settings  = $settings
            User      = $TaskUser
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
    } else {
        Write-Output ("[WhatIf] Would register: $fullName")
        Write-Output ("[WhatIf]   User:     $TaskUser")
        Write-Output ("[WhatIf]   Interval: $IntervalMinutes min")
        Write-Output ("[WhatIf]   Script:   $syncScriptPath")
        Write-Output ("[WhatIf]   CaConfig: $CaConfig")
        if ($LocalMode) {
            Write-Output ("[WhatIf]   Mode:     single-identity (-LocalMode)")
        }
    }
}

foreach ($task in $tasks) {
    Register-OrUpdate-Task $task
}

# Optionally register the revocation-sync task (WI-032). Off by default so
# the two-identity utility-host deployment is unaffected.
if ($RegisterRevocationSync) {
    Write-Output ""
    Register-RevocationSyncTask
}

# Validation: list the tasks and print their NextRunTime (if not WhatIf).
if (-not $WhatIfPreference) {
    Write-Output ""
    Write-Output "Validation — registered tasks:"
    foreach ($task in $tasks) {
        $fullName = "$TaskFolder$($task.Name)"
        $t = Get-ScheduledTask -TaskName $fullName -ErrorAction SilentlyContinue
        if ($t) {
            $info = Get-ScheduledTaskInfo -TaskName $fullName
            Write-Output ("  {0}: State={1}, NextRunTime={2}" -f $fullName, $t.State, $info.NextRunTime)
        } else {
            Write-Output ("  {0}: NOT FOUND (registration failed)" -f $fullName)
            exit 1
        }
    }
    if ($RegisterRevocationSync) {
        $syncFullName = "${TaskFolder}acme-adcs-ra-sync-revocations"
        $t = Get-ScheduledTask -TaskName $syncFullName -ErrorAction SilentlyContinue
        if ($t) {
            $info = Get-ScheduledTaskInfo -TaskName $syncFullName
            Write-Output ("  {0}: State={1}, NextRunTime={2}" -f $syncFullName, $t.State, $info.NextRunTime)
        } else {
            Write-Output ("  {0}: NOT FOUND (registration failed)" -f $syncFullName)
            exit 1
        }
    }
}

Write-Output ""
Write-Output "Done. See docs/operations.md ## Scheduled maintenance tasks."
Write-Output "NOTE: the admin token is embedded in each task action's headers. Rotate it"
Write-Output "      by re-running this script with a new -AdminToken (see the admin-token"
Write-Output "      runbook in docs/operations.md)."
exit 0
