BeforeAll {
    . "$PSScriptRoot/../../scripts/lib/InstallVerifyLib.ps1"
}

# 2026-08-17 F1. install-windows.ps1 hash-pinned its whole Python closure and
# then handed an unverified, possibly plaintext-HTTP-downloaded MSI to msiexec
# as Administrator on the issuance host.

Describe 'Get-MsiSourceKind' {
    It 'classifies https URLs' {
        Get-MsiSourceKind 'https://example.invalid/h.msi' | Should -Be 'https'
        Get-MsiSourceKind 'HTTPS://EXAMPLE.INVALID/h.msi' | Should -Be 'https'
    }

    It 'classifies plaintext http URLs' {
        Get-MsiSourceKind 'http://example.invalid/h.msi' | Should -Be 'http'
        Get-MsiSourceKind 'HtTp://example.invalid/h.msi' | Should -Be 'http'
    }

    It 'classifies everything else as local' {
        Get-MsiSourceKind 'C:\vetted\HttpPlatformHandler.msi' | Should -Be 'local'
        Get-MsiSourceKind '\\fileserver\share\h.msi' | Should -Be 'local'
        Get-MsiSourceKind '' | Should -Be 'local'
    }

    It 'ignores surrounding whitespace' {
        Get-MsiSourceKind '  https://example.invalid/h.msi  ' | Should -Be 'https'
    }
}

Describe 'Assert-MsiSourceAcceptable' {
    It 'refuses plaintext HTTP outright, even with a digest' {
        {
            Assert-MsiSourceAcceptable -Source 'http://example.invalid/h.msi' `
                -Sha256 ('A' * 64)
        } | Should -Throw -ExpectedMessage '*plaintext HTTP*'
    }

    It 'refuses an https source with no expected digest' {
        {
            Assert-MsiSourceAcceptable -Source 'https://example.invalid/h.msi'
        } | Should -Throw -ExpectedMessage '*-HttpPlatformHandlerSha256*'
    }

    It 'refuses an https source whose digest is whitespace' {
        {
            Assert-MsiSourceAcceptable -Source 'https://example.invalid/h.msi' -Sha256 '   '
        } | Should -Throw -ExpectedMessage '*-HttpPlatformHandlerSha256*'
    }

    It 'accepts an https source with a digest' {
        Assert-MsiSourceAcceptable -Source 'https://example.invalid/h.msi' `
            -Sha256 ('a' * 64) | Should -Be 'https'
    }

    It 'accepts a vetted local path without a digest' {
        Assert-MsiSourceAcceptable -Source 'C:\vetted\h.msi' | Should -Be 'local'
    }
}

Describe 'Test-Sha256Match' {
    It 'matches regardless of case' {
        Test-Sha256Match -Actual ('a' * 64) -Expected ('A' * 64) | Should -BeTrue
    }

    It 'matches through operator-pasted separators' {
        $digest = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
        $spaced = ($digest -split '(.{8})' | Where-Object { $_ } ) -join ' '
        Test-Sha256Match -Actual $digest -Expected $spaced | Should -BeTrue
    }

    It 'rejects a different digest' {
        Test-Sha256Match -Actual ('a' * 64) -Expected (('a' * 63) + 'b') | Should -BeFalse
    }

    It 'rejects a truncated or over-long digest rather than comparing a prefix' {
        Test-Sha256Match -Actual ('a' * 64) -Expected ('a' * 32) | Should -BeFalse
        Test-Sha256Match -Actual ('a' * 64) -Expected ('a' * 65) | Should -BeFalse
    }

    It 'rejects empty input on either side' {
        Test-Sha256Match -Actual '' -Expected ('a' * 64) | Should -BeFalse
        Test-Sha256Match -Actual ('a' * 64) -Expected '' | Should -BeFalse
    }

    It 'rejects non-hexadecimal input of the right length' {
        Test-Sha256Match -Actual ('z' * 64) -Expected ('z' * 64) | Should -BeFalse
    }
}

Describe 'Test-MsiSignatureAcceptable' {
    # Pester 5 runs Describe bodies at discovery and It bodies at run time, so a
    # bare Describe-scope variable is not visible inside It. BeforeAll is.
    BeforeAll { $expected = 'CN=Microsoft Corporation' }

    It 'accepts a valid signature from the expected publisher' {
        Test-MsiSignatureAcceptable -Status 'Valid' `
            -SignerSubject 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' `
            -ExpectedPublisher $expected | Should -BeTrue
    }

    It 'rejects every non-Valid status, including a plausible signer' {
        foreach ($status in @('NotSigned', 'HashMismatch', 'UnknownError', 'NotTrusted', 'Incompatible')) {
            Test-MsiSignatureAcceptable -Status $status `
                -SignerSubject 'CN=Microsoft Corporation, O=Microsoft Corporation' `
                -ExpectedPublisher $expected | Should -BeFalse
        }
    }

    It 'rejects a validly signed MSI from a different publisher' {
        Test-MsiSignatureAcceptable -Status 'Valid' `
            -SignerSubject 'CN=Evil Corp, O=Evil Corp, C=XX' `
            -ExpectedPublisher $expected | Should -BeFalse
    }

    It 'rejects a valid status with no signer at all' {
        Test-MsiSignatureAcceptable -Status 'Valid' -SignerSubject '' `
            -ExpectedPublisher $expected | Should -BeFalse
    }

    It 'refuses to pass anything when the expected publisher is blank' {
        # Otherwise an empty -HttpPlatformHandlerPublisher would turn the
        # publisher check into a no-op that still looks like it ran.
        Test-MsiSignatureAcceptable -Status 'Valid' `
            -SignerSubject 'CN=Evil Corp' -ExpectedPublisher '' | Should -BeFalse
    }

    It 'matches the publisher case-insensitively' {
        Test-MsiSignatureAcceptable -Status 'Valid' `
            -SignerSubject 'cn=microsoft corporation, o=microsoft corporation' `
            -ExpectedPublisher $expected | Should -BeTrue
    }
}

# 2026-08-14 live re-proof. The inline form of this check threw "pip is too old"
# on pip 26.2.1 and blocked every fresh install on Windows. The shape below --
# a two-element Object[] whose second element is the empty trailing line -- is
# what `(& $py -m pip --version) 2>&1` actually returns on the RA host; it was
# captured there, not imagined. Feeding the helper a plain string would pass
# even against the broken implementation, which is precisely why it must not.
Describe 'Get-PipMajorVersion' {
    It 'parses the real two-element array PowerShell returns for pip --version' {
        $real = @('pip 26.2.1 from C:\ProgramData\acme-adcs-ra\venv\Lib\site-packages\pip (python 3.14)', '')
        Get-PipMajorVersion $real | Should -Be 26
    }

    It 'parses a plain single-line string' {
        Get-PipMajorVersion 'pip 23.0.1 from /usr/lib/pip (python 3.12)' | Should -Be 23
    }

    It 'still recognises a genuinely ancient pip, so the floor can fire' {
        Get-PipMajorVersion @('pip 9.0.1 from C:\py\lib\pip (python 3.6)', '') | Should -Be 9
    }

    It 'reports -1 rather than 0 when the banner cannot be parsed' {
        # 0 would look like an ancient pip and block the install; -1 is the
        # caller's signal to warn and continue.
        Get-PipMajorVersion @('', '') | Should -Be -1
        Get-PipMajorVersion 'command not found' | Should -Be -1
        Get-PipMajorVersion $null | Should -Be -1
    }
}
