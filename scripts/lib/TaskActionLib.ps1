# Dot-sourceable library: task-action builders for Register-MaintenanceTasks.ps1.
# Used by Register-MaintenanceTasks.ps1 and the Pester tests
# (tests/pester/TaskAction.Tests.ps1).

# The action script block. The token is interpolated here at registration
# time -- it lives in the registered task action, not in a file the task reads.
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
# Sync-Revocations.ps1 with -Execute (or -DryRun). The script path is resolved
# at registration time ($PSScriptRoot of this registration script, the same
# scripts/ directory).
#
# Two invariants, both matching the nonce/sweep action (Build-ActionScriptBlock):
#   1. The returned command contains NO double quotes -- only single-quoted
#      literals -- so it is safe to wrap in -Command "..." at registration time.
#      (An earlier version used -File "<path>", whose embedded double quotes
#      collided with the outer -Command quotes; the script is invoked with the
#      call operator & '<path>' instead, so a spaced path needs no double
#      quotes, and it runs in-process -- no nested powershell.exe hop.)
#   2. The admin token is passed via the environment ($env:ACME_ADMIN_TOKEN),
#      NOT as a -AdminToken parameter, so it never lands on Sync-Revocations.ps1's
#      process command line. Sync-Revocations.ps1 reads the env fallback.
# The single-quoted literals assume the token / URL / CA config contain no
# single quote -- the same assumption the nonce/sweep action already makes.
function Build-SyncActionCommand([string]$BaseUrl, [string]$Token, [string]$CaConfigStr, [bool]$Local, [bool]$DryRunMode, [string]$ScriptPath, [string]$Requester, [bool]$PublishCrlMode) {
    $localFlag = if ($Local) { " -LocalMode" } else { "" }
    $modeFlag = if ($DryRunMode) { " -DryRun" } else { " -Execute" }
    $crlFlag = if ($PublishCrlMode) { " -PublishCrl" } else { "" }
    return "`$env:ACME_ADMIN_TOKEN = '$Token'; & '$ScriptPath' -RaBaseUrl '$BaseUrl' -CaConfig '$CaConfigStr' -RequesterName '$Requester'$modeFlag$localFlag$crlFlag; exit `$LASTEXITCODE"
}
