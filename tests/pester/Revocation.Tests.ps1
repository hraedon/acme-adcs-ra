BeforeAll {
    . "$PSScriptRoot/../../scripts/lib/RevocationLib.ps1"
}

Describe 'Get-ValidRevocationReasons' {
    It 'Returns exactly @(0, 1, 2, 3, 4, 5, 6, 9, 10)' {
        $reasons = Get-ValidRevocationReasons
        $reasons | Should -Be @(0, 1, 2, 3, 4, 5, 6, 9, 10)
    }

    It 'Does NOT contain 7' {
        $reasons = Get-ValidRevocationReasons
        $reasons | Should -Not -Contain 7
    }

    It 'Does NOT contain 8 (removeFromCRL un-revokes)' {
        # Plan 004 proved against the lab CA that reason 8 leaves a held
        # certificate "off the CRL and valid". A revocation path must never
        # be able to emit it.
        $reasons = Get-ValidRevocationReasons
        $reasons | Should -Not -Contain 8
    }
}

Describe 'Test-RevocationReason' {
    It 'Returns $true for each valid reason' {
        foreach ($r in @(0, 1, 2, 3, 4, 5, 6, 9, 10)) {
            Test-RevocationReason $r | Should -BeTrue -Because "reason $r should be valid"
        }
    }

    It 'Returns $false for 7 (unused in RFC 5280)' {
        Test-RevocationReason 7 | Should -BeFalse
    }

    It 'Returns $false for 8 (removeFromCRL is the un-revoke operation)' {
        Test-RevocationReason 8 | Should -BeFalse
    }

    It 'Returns $false for -1' {
        Test-RevocationReason -1 | Should -BeFalse
    }

    It 'Returns $false for 11' {
        Test-RevocationReason 11 | Should -BeFalse
    }
}

Describe 'Compare-RequesterName' {
    It 'Exact match returns $true' {
        Compare-RequesterName 'WORK-DOMAIN\gMSA-acme-ra$' 'WORK-DOMAIN\gMSA-acme-ra$' | Should -BeTrue
    }

    It 'Case-insensitive match returns $true' {
        Compare-RequesterName 'WORK-DOMAIN\gmsa-acme-ra$' 'WORK-DOMAIN\gMSA-acme-ra$' | Should -BeTrue
    }

    It 'Different domain returns $false' {
        Compare-RequesterName 'OTHER-DOMAIN\gMSA-acme-ra$' 'WORK-DOMAIN\gMSA-acme-ra$' | Should -BeFalse
    }

    It 'Different account returns $false' {
        Compare-RequesterName 'WORK-DOMAIN\svc-other$' 'WORK-DOMAIN\gMSA-acme-ra$' | Should -BeFalse
    }

    It 'Empty actual returns $false' {
        Compare-RequesterName '' 'WORK-DOMAIN\gMSA-acme-ra$' | Should -BeFalse
    }
}

Describe "Get-CaSerialForm" {
    It "re-pads an odd-length serial to the CA's stored even-length form" {
        # The RA emits format(n,'x') which drops a leading zero; ADCS stores the
        # full byte string, and -restrict is an exact string match.
        Get-CaSerialForm "6AB1C" | Should -Be "06AB1C"
    }

    It "leaves an even-length serial unchanged" {
        Get-CaSerialForm "6C0000006E14EDCC" | Should -Be "6C0000006E14EDCC"
    }

    It "strips an 0x prefix before padding" {
        Get-CaSerialForm "0x6AB1C" | Should -Be "06AB1C"
        Get-CaSerialForm "0X6AB1C2" | Should -Be "6AB1C2"
    }

    It "trims surrounding whitespace" {
        Get-CaSerialForm "  6AB1C2  " | Should -Be "6AB1C2"
    }

    It "returns empty or whitespace input unchanged" {
        Get-CaSerialForm "" | Should -Be ""
    }
}

Describe 'Get-RevocationCompletionMessage' {
    # 2026-08-16 rescan F2. The default batch path passes -SkipPublishCrl, and
    # the old unconditional trailer told the operator the CRL was published
    # anyway -- in the same output that had just said publication was skipped.
    # Closing containment on that line leaves a revoked certificate accepted by
    # relying parties until the next scheduled CRL.

    It 'never claims publication on the skip path' {
        $lines = Get-RevocationCompletionMessage -Serial '6AB1C2' -SkipPublishCrl
        $text = $lines -join ' '
        $text | Should -Not -Match 'CRL is published'
        $text | Should -Not -Match 'has been republished'
        $text | Should -Match 'NOT republished'
    }

    It 'says containment is not complete on the skip path' {
        $text = (Get-RevocationCompletionMessage -Serial '6AB1C2' -SkipPublishCrl) -join ' '
        $text | Should -Match 'PARTIALLY complete'
        $text | Should -Match 'Do NOT close containment'
    }

    It 'claims publication only on the publish path' {
        $text = (Get-RevocationCompletionMessage -Serial '6AB1C2') -join ' '
        $text | Should -Match 'the CRL is published'
        $text | Should -Match 'has been republished'
        $text | Should -Not -Match 'PARTIALLY complete'
    }

    It 'gives the two branches distinct completion text' {
        $skip = (Get-RevocationCompletionMessage -Serial '6AB1C2' -SkipPublishCrl) -join "`n"
        $publish = (Get-RevocationCompletionMessage -Serial '6AB1C2') -join "`n"
        $skip | Should -Not -Be $publish
    }

    It 'names the serial it acted on in both branches' {
        ((Get-RevocationCompletionMessage -Serial '6AB1C2' -SkipPublishCrl) -join ' ') |
            Should -Match '6AB1C2'
        ((Get-RevocationCompletionMessage -Serial '6AB1C2') -join ' ') |
            Should -Match '6AB1C2'
    }
}

# 2026-08-14 live re-proof. Test-SerialRevokedAtCa lives in Revoke-Cert.ps1
# rather than lib/, so nothing covered it, and the wave-3 F1 fix shipped inert:
# its branches wrote three Write-Output diagnostics before `return $false`, and
# a PowerShell function returns EVERYTHING on the success stream. The call site
# is `if (Test-SerialRevokedAtCa ...)`; @(three strings, $false) is a non-empty
# array, which is truthy, so a reason-8 certificate -- off the CRL and still
# VALID -- was read as "already revoked".
#
# The function is extracted by AST so these assertions run against the real
# shipped text, and certutil is stubbed so no CA is required.
Describe 'Test-SerialRevokedAtCa (extracted from Revoke-Cert.ps1)' {
    BeforeAll {
        $script:src = Join-Path $PSScriptRoot '../../scripts/Revoke-Cert.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path $script:src).Path, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $n.Name -eq 'Test-SerialRevokedAtCa' }, $true) | Select-Object -First 1
        if ($null -eq $fn) { throw 'Test-SerialRevokedAtCa not found in Revoke-Cert.ps1' }
        Invoke-Expression $fn.Extent.Text
    }

    It 'returns a value that is FALSE at the call site for a reason-8 row' {
        $serial = '6C000000C053029C6A2F5FA7A70000000000C0'
        # Every restrict matches: disposition 21 yes, disposition 20 no, reason 8 yes.
        function certutil {
            $global:LASTEXITCODE = 0
            $restrict = $args[0] | Where-Object { $_ -like 'SerialNumber=*' }
            if (-not $restrict) { $restrict = ($args | Where-Object { $_ -like 'SerialNumber=*' }) }
            if ("$restrict" -like '*Disposition=20*') { return @('no rows') }
            return @("  Serial Number: `"$serial`"")
        }
        $result = Test-SerialRevokedAtCa 'CA\ca' $serial

        # The assertion that matters is the caller's, not -Be $false: the bug
        # returned an ARRAY ending in $false, which -Be $false would not catch
        # but `if (...)` reads as true.
        $truthy = if ($result) { $true } else { $false }
        $truthy | Should -BeFalse -Because 'a reason-8 row must not be read as already-revoked'
        @($result).Count | Should -Be 1 -Because 'diagnostics must not join the return value'
    }

    It 'returns a value that is FALSE at the call site when the CA fails to discriminate' {
        $serial = '6C000000C053029C6A2F5FA7A70000000000C0'
        # Pathological CA: returns the serial for BOTH dispositions.
        function certutil {
            $global:LASTEXITCODE = 0
            return @("  Serial Number: `"$serial`"")
        }
        $result = Test-SerialRevokedAtCa 'CA\ca' $serial
        $truthy = if ($result) { $true } else { $false }
        $truthy | Should -BeFalse -Because 'an undiscriminating Disposition filter is not proof of revocation'
        @($result).Count | Should -Be 1 -Because 'diagnostics must not join the return value'
    }

    It 'still reports TRUE for an ordinarily revoked certificate' {
        $serial = '6C000000C053029C6A2F5FA7A70000000000C0'
        function certutil {
            $global:LASTEXITCODE = 0
            $restrict = $args[0] | Where-Object { $_ -like 'SerialNumber=*' }
            if ("$restrict" -like '*Disposition=20*') { return @('no rows') }
            if ("$restrict" -like '*RevokedReason=8*') { return @('no rows') }
            return @("  Serial Number: `"$serial`"")
        }
        $result = Test-SerialRevokedAtCa 'CA\ca' $serial
        $truthy = if ($result) { $true } else { $false }
        $truthy | Should -BeTrue -Because 'a plain disposition-21 row with no reason 8 IS revoked'
    }
}
