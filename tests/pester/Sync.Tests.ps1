BeforeAll {
    . "$PSScriptRoot/../../scripts/lib/SyncLib.ps1"
}

Describe 'Get-PendingRevocations' {
    It 'Returns empty array for $null response' {
        $result = Get-PendingRevocations $null
        @($result).Count | Should -Be 0
    }

    It 'Returns empty array for response with no pending_revocations property' {
        $response = [pscustomobject]@{ other_field = 'value' }
        $result = Get-PendingRevocations $response
        @($result).Count | Should -Be 0
    }

    It 'Returns empty array for response with pending_revocations = $null' {
        $response = [pscustomobject]@{ pending_revocations = $null }
        $result = Get-PendingRevocations $response
        @($result).Count | Should -Be 0
    }

    It 'Returns single-element array when response has one pending revocation' {
        $response = [pscustomobject]@{
            pending_revocations = @([pscustomobject]@{ serial = 'AABB'; req_id = 1 })
        }
        $result = Get-PendingRevocations $response
        @($result).Count | Should -Be 1
    }

    It 'Returns multi-element array correctly' {
        $response = [pscustomobject]@{
            pending_revocations = @(
                [pscustomobject]@{ serial = 'AABB'; req_id = 1 },
                [pscustomobject]@{ serial = 'CCDD'; req_id = 2 },
                [pscustomobject]@{ serial = 'EEFF'; req_id = 3 }
            )
        }
        $result = Get-PendingRevocations $response
        @($result).Count | Should -Be 3
    }

    It 'Filters out null entries in the array' {
        $response = [pscustomobject]@{
            pending_revocations = @(
                [pscustomobject]@{ serial = 'AABB'; req_id = 1 },
                $null,
                [pscustomobject]@{ serial = 'CCDD'; req_id = 2 }
            )
        }
        $result = Get-PendingRevocations $response
        @($result).Count | Should -Be 2
    }
}

Describe 'Get-SyncExitCode' {
    It 'Returns 0 when FailedCount is 0' {
        Get-SyncExitCode 0 | Should -Be 0
    }

    It 'Returns 2 when FailedCount is 1' {
        Get-SyncExitCode 1 | Should -Be 2
    }

    It 'Returns 2 when FailedCount is 5' {
        Get-SyncExitCode 5 | Should -Be 2
    }
}
