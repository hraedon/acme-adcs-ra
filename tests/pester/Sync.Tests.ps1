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

Describe 'Assert-SafeRaUrl' {
    # 2026-08-13 review, finding 4: Sync-Revocations.ps1 sent the maintenance
    # Bearer token to whatever -RaBaseUrl it was given, with no scheme check.

    It 'Accepts a plain https base URL and strips the trailing slash' {
        Assert-SafeRaUrl -Url 'https://ra.example.local/' | Should -Be 'https://ra.example.local'
    }

    It 'Accepts https with a non-default port' {
        Assert-SafeRaUrl -Url 'https://ra.example.local:9443' | Should -Be 'https://ra.example.local:9443'
    }

    It 'Rejects cleartext http to a remote host' {
        { Assert-SafeRaUrl -Url 'http://ra.example.local' } | Should -Throw -ExpectedMessage '*only be sent over https*'
    }

    It 'Rejects cleartext http to a remote host even with -AllowInsecureUrl' {
        # The opt-out is for a loopback lab, not for putting the token on a network.
        { Assert-SafeRaUrl -Url 'http://ra.example.local' -AllowInsecureUrl } |
            Should -Throw -ExpectedMessage '*only be sent over https*'
    }

    It 'Allows http to loopback only with the explicit opt-out' {
        { Assert-SafeRaUrl -Url 'http://127.0.0.1:8000' } | Should -Throw
        Assert-SafeRaUrl -Url 'http://127.0.0.1:8000' -AllowInsecureUrl | Should -Be 'http://127.0.0.1:8000'
    }

    It 'Rejects embedded credentials' {
        { Assert-SafeRaUrl -Url 'https://user:pass@ra.example.local' } |
            Should -Throw -ExpectedMessage '*embeds credentials*'
    }

    It 'Rejects a fragment' {
        { Assert-SafeRaUrl -Url 'https://ra.example.local/#frag' } |
            Should -Throw -ExpectedMessage '*fragment*'
    }

    It 'Rejects a query string' {
        { Assert-SafeRaUrl -Url 'https://ra.example.local/?a=b' } |
            Should -Throw -ExpectedMessage '*query string*'
    }

    It 'Rejects a path beyond the root' {
        { Assert-SafeRaUrl -Url 'https://ra.example.local/some/path' } |
            Should -Throw -ExpectedMessage '*carries a path*'
    }

    It 'Rejects a non-http scheme' {
        { Assert-SafeRaUrl -Url 'file:///etc/passwd' } | Should -Throw
    }

    It 'Rejects a relative URL' {
        { Assert-SafeRaUrl -Url 'ra.example.local' } |
            Should -Throw -ExpectedMessage '*not an absolute URL*'
    }

    It 'Rejects an empty URL' {
        { Assert-SafeRaUrl -Url '' } | Should -Throw -ExpectedMessage '*must not be empty*'
    }
}
