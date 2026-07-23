# Dot-sourceable library: sync-revocation helpers extracted from
# Sync-Revocations.ps1 for testability. Used by the Pester tests
# (tests/pester/Sync.Tests.ps1). The production script keeps its logic
# inline; this lib validates the same logic independently.

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
