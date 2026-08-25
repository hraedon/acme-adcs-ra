# Dot-sourceable library: task-action builders for Register-MaintenanceTasks.ps1.
# Used by Register-MaintenanceTasks.ps1 and the Pester tests
# (tests/pester/TaskAction.Tests.ps1).

# Escape a value for embedding in a PowerShell SINGLE-quoted literal, and wrap
# it in the quotes. In a single-quoted string PowerShell escapes a quote by
# DOUBLING it, and nothing else is special -- so this is the whole rule.
#
# 2026-08-19 F4 (low, CWE-78). Every field below used to be pasted between bare
# single quotes under a documented "assume no single quote" comment, while
# registration validated none of them. One quote in a URL, CA config string or
# requester name closes the literal and the remainder is executed by
# powershell.exe -Command as the task identity. An assumption that nothing
# checks is not a control.
function ConvertTo-PsSingleQuotedLiteral {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Value)
    if ($null -eq $Value) { $Value = "" }
    # A double quote cannot be represented here. The literal itself would be
    # fine, but every caller's output is wrapped in an OUTER -Command "..."
    # (Register-MaintenanceTasks.ps1), and CommandLineToArgvW re-splits on the
    # embedded quote -- the R2-4 defect, reachable again through any input
    # value that carries one. Escaping it was F4's job for single quotes
    # because a single quote IS representable (by doubling); a double quote is
    # not representable in this position at all, so refusing it is the only
    # sound answer. Inputs are URLs, Windows paths and DOMAIN\name values --
    # none can legitimately contain one.
    if ($Value.IndexOf('"') -ge 0) {
        throw ("Task-action input contains a double quote, which cannot be embedded in a -Command-wrapped action: '{0}'" -f $Value)
    }
    return "'" + $Value.Replace("'", "''") + "'"
}

# Emit the PowerShell that loads a token from the RA's dotenv AT RUN TIME.
#
# 2026-08-19 F2 (medium, CWE-214). The tokens used to be interpolated straight
# into the action text. That text is persisted in the Task Scheduler definition
# and handed to powershell.exe -Command, so the credential was readable by
# anyone who could read the task registration and visible again in process
# arguments while the task ran. What travels now is a FILE PATH; the secret
# stays in acme-ra.env, which the installer ACLs to Administrators/SYSTEM full
# and the gMSA read-only. The task runs as the gMSA, so it can read it and
# almost nobody else can.
#
# Emits only single-quoted literals, preserving the no-double-quotes invariant
# that lets the whole command sit inside -Command "...".
function Build-DotEnvTokenLoad {
    param(
        [Parameter(Mandatory = $true)][string]$DotEnvPath,
        [Parameter(Mandatory = $true)][string]$DotEnvKey,
        [Parameter(Mandatory = $true)][string]$EnvVarName
    )
    $pathLit = ConvertTo-PsSingleQuotedLiteral $DotEnvPath
    $prefixLit = ConvertTo-PsSingleQuotedLiteral ($DotEnvKey + '=')
    # -match on an array filters it, so `$hit` is the first matching LINE.
    # Substring past the first '=' keeps values that themselves contain '='.
    return ("`$l = @(Get-Content -LiteralPath $pathLit -ErrorAction Stop); " +
            "`$hit = @(`$l | Where-Object { `$_.StartsWith($prefixLit) }) | Select-Object -First 1; " +
            "if (`$hit) { `$env:$EnvVarName = `$hit.Substring(`$hit.IndexOf('=') + 1) }; ")
}

# The action script block for the nonce-cleanup / expired-order-sweep tasks.
#
# The admin token is read from the dotenv at run time (F2) rather than baked
# into the Authorization header at registration time. Invoke-RestMethod still
# carries it in -Headers, which it does not log.
function Build-ActionScriptBlock([string]$EndpointUrl, [string]$DotEnvPath) {
    $urlLit = ConvertTo-PsSingleQuotedLiteral $EndpointUrl
    $pathLit = ConvertTo-PsSingleQuotedLiteral $DotEnvPath
    # SAME TWO INVARIANTS AS Build-SyncActionCommand, and for the same reason:
    # the caller wraps this whole string in `-Command "..."`, so
    #   1. it must contain NO double quote, or the embedded quote closes the
    #      outer one and CommandLineToArgvW re-splits the action into tokens;
    #   2. it must be ONE line, so what Task Scheduler shows an operator is what
    #      actually runs.
    # This builder honoured neither. It emitted `"Bearer $tok"` and two
    # `("$(...)")` interpolations -- six double quotes across eleven lines -- so
    # the registered action re-tokenised at run time into
    # `... = Bearer $tok }` and died with "The term 'Bearer' is not recognized".
    # Registration still reported success (New-ScheduledTaskAction only stores
    # the string, and the post-register check reads NextRunTime, never
    # LastTaskResult), so nonce GC and the RFC 8555 7.1.6 expired-order sweep
    # would have failed silently on every run. Build-SyncActionCommand had the
    # invariant, a comment explaining it, and two tests; this sibling had none.
    # Single quotes and string concatenation only below.
    return (
        "`$ErrorActionPreference = 'Stop'; " +
        "`$lines = @(Get-Content -LiteralPath $pathLit -ErrorAction Stop); " +
        "`$hit = @(`$lines | Where-Object { `$_.StartsWith('ACME_RA_ADMIN_TOKEN=') }) | Select-Object -First 1; " +
        "if (-not `$hit) { Write-Error 'ACME_RA_ADMIN_TOKEN not found in the RA dotenv'; exit 1 }; " +
        "`$tok = `$hit.Substring(`$hit.IndexOf('=') + 1); " +
        "try { " +
            "`$resp = Invoke-RestMethod -Method Delete -Uri $urlLit " +
                "-Headers @{ 'Authorization' = ('Bearer ' + `$tok) } -TimeoutSec 60; " +
            "Write-Output (`$resp | ConvertTo-Json -Compress); " +
        "} catch { " +
            "Write-Error (`$_.Exception.Message); " +
            "exit 1; " +
        "}"
    )
}

# Action builder for the revocation-sync task. Unlike Build-ActionScriptBlock
# (which calls Invoke-RestMethod against an admin endpoint), this runs
# Sync-Revocations.ps1 with -Execute (or -DryRun). The script path is resolved
# at registration time ($PSScriptRoot of this registration script, the same
# scripts/ directory).
#
# Three invariants:
#   1. The returned command contains NO double quotes -- only single-quoted
#      literals -- so it is safe to wrap in -Command "..." at registration time.
#      (An earlier version used -File "<path>", whose embedded double quotes
#      collided with the outer -Command quotes; the script is invoked with the
#      call operator & '<path>' instead, so a spaced path needs no double
#      quotes, and it runs in-process -- no nested powershell.exe hop.)
#   2. Tokens are never passed as parameters and, since 2026-08-19 F2, are no
#      longer interpolated into the action either. The action loads them from
#      the ACL'd dotenv into $env:ACME_ADMIN_TOKEN / $env:ACME_CONFIRM_TOKEN,
#      which Sync-Revocations.ps1 already reads as its fallback. So the token
#      lands on no command line and in no task definition.
#   3. Least privilege is preserved by which KEYS are loaded, not by which
#      secrets are pasted: a dedicated revocation host registered without admin
#      authority emits no ACME_RA_ADMIN_TOKEN load at all, so even a host that
#      can read the dotenv gets a task that never puts the broader token into
#      its environment. The confirm token alone is sufficient authority for the
#      whole sync workflow.
function Build-SyncActionCommand {
    param(
        [string]$BaseUrl,
        [string]$CaConfigStr,
        [bool]$Local,
        [bool]$DryRunMode,
        [string]$ScriptPath,
        [string]$Requester,
        [bool]$PublishCrlMode,
        [Parameter(Mandatory = $true)][string]$DotEnvPath,
        [bool]$LoadAdminToken = $false,
        [bool]$LoadConfirmToken = $true,
        # Carried through from the registrar (2026-08-24 F10). Sync-Revocations
        # now re-checks its own tree on every run, so a task registered from a
        # deliberately untrusted lab path must be told that was deliberate --
        # otherwise the documented -AllowUntrustedScriptPath flow registers a
        # task that refuses to run, which strands exactly the case the override
        # exists for. Default false: the flag never appears in an ordinary
        # action, so the run-time gate stays armed everywhere it matters.
        [bool]$AllowUntrustedScriptPath = $false
    )
    $localFlag = if ($Local) { " -LocalMode" } else { "" }
    $modeFlag = if ($DryRunMode) { " -DryRun" } else { " -Execute" }
    $crlFlag = if ($PublishCrlMode) { " -PublishCrl" } else { "" }
    $untrustedFlag = if ($AllowUntrustedScriptPath) { " -AllowUntrustedScriptPath" } else { "" }

    $adminEnv = ""
    if ($LoadAdminToken) {
        $adminEnv = Build-DotEnvTokenLoad -DotEnvPath $DotEnvPath `
            -DotEnvKey 'ACME_RA_ADMIN_TOKEN' -EnvVarName 'ACME_ADMIN_TOKEN'
    }
    $confirmEnv = ""
    if ($LoadConfirmToken) {
        $confirmEnv = Build-DotEnvTokenLoad -DotEnvPath $DotEnvPath `
            -DotEnvKey 'ACME_RA_REVOCATION_CONFIRM_TOKEN' -EnvVarName 'ACME_CONFIRM_TOKEN'
    }

    $scriptLit = ConvertTo-PsSingleQuotedLiteral $ScriptPath
    $baseLit = ConvertTo-PsSingleQuotedLiteral $BaseUrl
    $caLit = ConvertTo-PsSingleQuotedLiteral $CaConfigStr
    $reqLit = ConvertTo-PsSingleQuotedLiteral $Requester
    return ("$adminEnv$confirmEnv& $scriptLit -RaBaseUrl $baseLit -CaConfig $caLit " +
            "-RequesterName $reqLit$modeFlag$localFlag$crlFlag$untrustedFlag; exit `$LASTEXITCODE")
}
