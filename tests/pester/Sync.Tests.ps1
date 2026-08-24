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

    It 'Treats an IPv6 literal loopback as loopback' {
        # [System.Uri].Host renders IPv6 bracketed ("[::1]"), so comparing it
        # raw against '::1' silently made the opt-out unreachable for an IPv6
        # loopback lab. Fail-closed, but wrong.
        { Assert-SafeRaUrl -Url 'http://[::1]:8000' } | Should -Throw
        Assert-SafeRaUrl -Url 'http://[::1]:8000' -AllowInsecureUrl | Should -Be 'http://[::1]:8000'
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

Describe 'Invoke-ChildScript' {
    BeforeAll {
        # A child that fails the way Revoke-Cert.ps1 fails: a Die() message on
        # stderr and a non-zero exit code.
        $script:childPath = Join-Path ([System.IO.Path]::GetTempPath()) 'sync-child-test.ps1'
        Set-Content -Path $script:childPath -Encoding ASCII -Value @(
            '[Console]::Error.WriteLine("ERROR: certutil exited -2146877431")'
            'Write-Output "some stdout line"'
            'exit 4'
        )
        $script:exe = (Get-Process -Id $PID).Path
    }

    AfterAll {
        Remove-Item $script:childPath -Force -ErrorAction SilentlyContinue
    }

    # NOTE ON WHAT THIS FILE CANNOT COVER.
    #
    # The defect this function exists to fix -- found on the lab CA 2026-08-13
    # -- is that under Windows PowerShell 5.1 a bare `& $exe @args 2>&1` turns
    # the child's first stderr line into a TERMINATING error when the caller
    # has $ErrorActionPreference='Stop', so Sync-Revocations.ps1's per-serial
    # failure handling never ran and the batch aborted on the first failure.
    #
    # That is NOT reproducible here. pwsh 7 defaults
    # $PSNativeCommandUseErrorActionPreference to $false, so a native command's
    # stderr never becomes a terminating error on this host; a "does not throw"
    # assertion would pass with the fix reverted -- verified by mutation, which
    # is why no such test is written. The tests below pin the parts of the
    # contract that DO bite cross-platform (both mutation-checked). The
    # stderr/EAP behaviour itself is covered only by the live lab re-proof
    # (docs/live-reproof-runbook.md).
    It 'Returns the child exit code so a failure can be handled, not thrown' {
        $ErrorActionPreference = 'Stop'
        $run = Invoke-ChildScript $script:exe @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:childPath
        )
        $run.ExitCode | Should -Be 4
    }

    It 'Captures both the stderr message and stdout for logging' {
        $ErrorActionPreference = 'Stop'
        $run = Invoke-ChildScript $script:exe @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:childPath
        )
        ($run.Output | Out-String) | Should -Match 'certutil exited'
        ($run.Output | Out-String) | Should -Match 'some stdout line'
    }

}

Describe 'Get-RevokeOutcome' {
    # 2026-08-17 F4. "Any non-zero is a failure" conflated a genuine revoke
    # failure with a serial the CA had already revoked. The second is not a
    # failure -- the CA side is correct and only the RA callback is outstanding
    # -- but it took the `continue` branch, so the callback was never retried
    # and one dropped HTTPS request desynchronized the two sides for good.

    It 'classifies 0 as revoked' {
        Get-RevokeOutcome 0 | Should -Be 'revoked'
    }

    It 'classifies 6 as already revoked at the CA' {
        Get-RevokeOutcome 6 | Should -Be 'already-revoked'
    }

    It 'classifies 5 as a requester mismatch (batch-aborting)' {
        Get-RevokeOutcome 5 | Should -Be 'requester-mismatch'
    }

    It 'classifies every other code as a failure' {
        foreach ($code in @(1, 2, 3, 4, 7, 8, 87, 255)) {
            Get-RevokeOutcome $code | Should -Be 'failed'
        }
    }
}

Describe 'Test-ShouldConfirmWithRa' {
    It 'confirms a fresh revocation' {
        Test-ShouldConfirmWithRa 'revoked' | Should -BeTrue
    }

    It 'confirms an already-revoked serial -- this is the F4 recovery path' {
        # The whole point: the CA-side state is right and the callback is the
        # only thing left to do, so the retry must reach it.
        Test-ShouldConfirmWithRa 'already-revoked' | Should -BeTrue
    }

    It 'does NOT confirm a requester mismatch' {
        # Confirming asserts the CA revoked the cert. A cert that failed the
        # requester check was never revoked, and must never be claimed as such.
        Test-ShouldConfirmWithRa 'requester-mismatch' | Should -BeFalse
    }

    It 'does NOT confirm a failure' {
        Test-ShouldConfirmWithRa 'failed' | Should -BeFalse
    }

    It 'does NOT confirm an unrecognized outcome' {
        # Fail closed: a future outcome must not default into "confirm it".
        Test-ShouldConfirmWithRa 'something-new' | Should -BeFalse
        Test-ShouldConfirmWithRa '' | Should -BeFalse
    }
}

# --- 2026-08-23 codex scan, finding 6: no bearer tokens on the argv ----------
#
# Sync-Revocations.ps1 accepted -AdminToken/-ConfirmToken as raw STRING
# parameters and its examples recommended pasting the secret value onto the
# command line -- shell history and process argument listings. The switches
# now only declare which environment variable supplies the credential, the
# Register-MaintenanceTasks.ps1 pattern since the 2026-08-15 review.
Describe 'Sync-Revocations credential surface (2026-08-23 finding 6)' {
    BeforeAll {
        $script:syncPath = (Resolve-Path "$PSScriptRoot/../../scripts/Sync-Revocations.ps1").Path
        $script:text = Get-Content -Raw $script:syncPath
        $script:ast = [System.Management.Automation.Language.Parser]::ParseInput(
            $script:text, [ref]$null, [ref]$null)
        $script:params = @($script:ast.ParamBlock.Parameters)
        # The same PowerShell host that runs this suite runs the script under
        # test: pwsh on Linux CI, Windows PowerShell 5.1 on the Windows job.
        $script:psExe = (Get-Process -Id $PID).Path

        # The script under test writes its failures to stderr via
        # [Console]::Error, and under Windows PowerShell 5.1 `& $exe ... 2>&1`
        # turns each stderr line into an ErrorRecord that is TERMINATING under
        # EAP=Stop -- the exact trap scripts/lib/SyncLib.ps1 documents and
        # defends around (observed live on the lab CA, 2026-08-13). Same
        # save/suppress/restore shape here. Defined in BeforeAll because
        # Pester 5 runs Describe bodies at discovery, not at It run time.
        function Invoke-SyncScriptCaptured {
            param([string[]]$ExtraArgs)
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                $out = & $script:psExe -NoProfile -ExecutionPolicy Bypass -File $script:syncPath `
                    -RaBaseUrl 'https://ra.example.invalid' -CaConfig 'CA01\WORK-DOMAIN-CA' `
                    @ExtraArgs 2>&1
                return @{ Output = ($out | Out-String); ExitCode = $LASTEXITCODE }
            } finally {
                $ErrorActionPreference = $prevEap
            }
        }
    }

    It '-AdminToken is a switch -- it cannot carry a value' {
        $p = $script:params | Where-Object { $_.Name.Extent.Text -eq '$AdminToken' }
        @($p).Count | Should -Be 1
        $p[0].StaticType.Name | Should -Be 'SwitchParameter'
    }

    It '-ConfirmToken is a switch -- it cannot carry a value' {
        $p = $script:params | Where-Object { $_.Name.Extent.Text -eq '$ConfirmToken' }
        @($p).Count | Should -Be 1
        $p[0].StaticType.Name | Should -Be 'SwitchParameter'
    }

    It 'no value-shaped use of either token remains in the body' {
        $script:text | Should -Not -Match 'IsNullOrWhiteSpace\(\$(AdminToken|ConfirmToken)\)'
    }

    It 'no example shows a value-shaped -AdminToken/-ConfirmToken' {
        $script:text | Should -Not -Match '-(Admin|Confirm)Token "'
        $script:text | Should -Not -Match 'REPLACE-WITH-HIGH-ENTROPY'
    }

    It 'the credential values come from the environment' {
        $script:text | Should -Match '\$env:ACME_ADMIN_TOKEN'
        $script:text | Should -Match '\$env:ACME_CONFIRM_TOKEN'
    }

    It 'a value passed to the flag never becomes the credential (fails before the network)' {
        # Regression shape of the original [string] parameters: the literal on
        # the command line became the bearer token and reached the RA. Now the
        # flag only SELECTS the environment variable, and with the variable
        # unset the script dies (exit 3) before any request is made.
        $run = Invoke-SyncScriptCaptured -ExtraArgs @('-AdminToken', 'argv-secret')
        $run.ExitCode | Should -Be 3
        $run.Output | Should -Match 'ACME_ADMIN_TOKEN is not set'
    }

    It 'the confirm flag fails loudly when its variable is unset' {
        $run = Invoke-SyncScriptCaptured -ExtraArgs @('-ConfirmToken')
        $run.ExitCode | Should -Be 3
        $run.Output | Should -Match 'ACME_CONFIRM_TOKEN is not set'
    }

    It 'direct manual operation works by setting the environment first' {
        # The documented manual path: set the variable, pass the bare flag.
        # The credential is accepted (no exit 3); the run then proceeds to the
        # RA fetch and dies unreachable (.invalid never resolves) with exit 1.
        $env:ACME_CONFIRM_TOKEN = 'env-sourced-value'
        try {
            $run = Invoke-SyncScriptCaptured -ExtraArgs @('-ConfirmToken')
            $run.ExitCode | Should -Be 1
            $run.Output | Should -Match 'RA unreachable'
        } finally {
            Remove-Item env:ACME_CONFIRM_TOKEN -ErrorAction SilentlyContinue
        }
    }
}
