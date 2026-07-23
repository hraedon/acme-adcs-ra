BeforeAll {
    . "$PSScriptRoot/../../scripts/lib/RevocationLib.ps1"
}

Describe 'Get-ValidRevocationReasons' {
    It 'Returns exactly @(0, 1, 2, 3, 4, 5, 6, 8, 9, 10)' {
        $reasons = Get-ValidRevocationReasons
        $reasons | Should -Be @(0, 1, 2, 3, 4, 5, 6, 8, 9, 10)
    }

    It 'Does NOT contain 7' {
        $reasons = Get-ValidRevocationReasons
        $reasons | Should -Not -Contain 7
    }
}

Describe 'Test-RevocationReason' {
    It 'Returns $true for each valid reason' {
        foreach ($r in @(0, 1, 2, 3, 4, 5, 6, 8, 9, 10)) {
            Test-RevocationReason $r | Should -BeTrue -Because "reason $r should be valid"
        }
    }

    It 'Returns $false for 7 (unused in RFC 5280)' {
        Test-RevocationReason 7 | Should -BeFalse
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
