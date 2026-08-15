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

# 2026-08-19 F1 (high, CWE-426). The elevated installer preferred and executed
# $InstallDir\python\python.exe ~250 lines before it created that directory or
# applied an ACL to it, so a local user who pre-creates the predictable
# ProgramData tree got their interpreter run as Administrator.
Describe 'Test-InstallRootAttributesAcceptable' {
    It 'accepts an ordinary directory' {
        Test-InstallRootAttributesAcceptable ([System.IO.FileAttributes]::Directory) | Should -BeTrue
    }

    It 'refuses a reparse point, which would redirect every later write and ACL' {
        $junction = [System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::ReparsePoint
        Test-InstallRootAttributesAcceptable $junction | Should -BeFalse
    }

    It 'refuses a file standing where the directory should be' {
        Test-InstallRootAttributesAcceptable ([System.IO.FileAttributes]::Normal) | Should -BeFalse
    }

    It 'refuses null rather than treating "cannot tell" as acceptable' {
        Test-InstallRootAttributesAcceptable $null | Should -BeFalse
    }
}

Describe 'Test-DestinationInterpreterTrusted' {
    It 'refuses the destination interpreter while the root is unclaimed' {
        # This is the finding itself: before the ACL is applied, a planted
        # python.exe must never be a candidate no matter how ordinary it looks.
        Test-DestinationInterpreterTrusted -RootSecured $false `
            -InterpreterAttributes ([System.IO.FileAttributes]::Normal) | Should -BeFalse
    }

    It 'accepts it once the root has been claimed and re-ACLd' {
        Test-DestinationInterpreterTrusted -RootSecured $true `
            -InterpreterAttributes ([System.IO.FileAttributes]::Normal) | Should -BeTrue
    }

    It 'still refuses a reparse-point interpreter inside a secured root' {
        $link = [System.IO.FileAttributes]::Normal -bor [System.IO.FileAttributes]::ReparsePoint
        Test-DestinationInterpreterTrusted -RootSecured $true -InterpreterAttributes $link | Should -BeFalse
    }

    It 'refuses when the interpreter cannot be stat-ed' {
        Test-DestinationInterpreterTrusted -RootSecured $true -InterpreterAttributes $null | Should -BeFalse
    }
}

# --- Daybreak 2026-08-15: hostile-tree ACL lockdown ----------------------------
#
# /inheritance:r removes only INHERITED ACEs, so the F1 "claim" left an
# attacker's explicit ACEs and ownership intact while treating the namespace
# as trustworthy. The fix is takeown + /reset + /grant:r + a read-back proof;
# Test-AclDumpLocked is the decision core of that proof, so it gets fixture
# dumps shaped like real `icacls /save` output -- including the exact attacker
# shapes the fix exists to catch.

Describe 'Test-AclDumpLocked' {
    BeforeAll {
        $script:allowed = @(
            'S-1-5-32-544', 'S-1-5-18', 'BUILTIN\Administrators',
            'NT AUTHORITY\SYSTEM', 'BA', 'SY',
            'S-1-5-21-1111222233-4444555566-7777888899'
        )
        $script:cleanTree = @'
acme-adcs-ra
D:PAI(A;OICI;FA;;;S-1-5-32-544)(A;OICI;FA;;;S-1-5-18)
acme-adcs-ra\python
D:AI(A;OICIID;FA;;;S-1-5-32-544)(A;OICIID;FA;;;S-1-5-18)
acme-adcs-ra\python\python.exe
D:AI(A;ID;FA;;;S-1-5-32-544)(A;ID;FA;;;S-1-5-18)
acme-adcs-ra\venv
D:AI(A;OICIID;FA;;;S-1-5-32-544)(A;OICIID;FA;;;S-1-5-18)
'@
    }

    It 'accepts a locked tree (protected root, inheriting descendants)' {
        $v = Test-AclDumpLocked -DumpText $script:cleanTree -AllowedTrustees $script:allowed
        @($v).Count | Should -Be 0
    }

    It 'flags an explicit attacker ACE that survived the reset (the finding itself)' {
        $dump = @'
acme-adcs-ra
D:PAI(A;OICI;FA;;;S-1-5-32-544)(A;OICI;FA;;;S-1-5-18)
acme-adcs-ra\python
D:PAI(A;OICI;FA;;;S-1-5-32-544)(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-1-0)
'@
        $v = @(Test-AclDumpLocked -DumpText $dump -AllowedTrustees $script:allowed)
        $v.Count | Should -BeGreaterThan 0
        ($v -join ' ') | Should -Match 'EXPLICIT ACE survived'
        ($v -join ' ') | Should -Match "unexpected trustee 'S-1-1-0'"
    }

    It 'flags a protected child DACL that does not inherit the root' {
        $dump = $script:cleanTree -replace 'acme-adcs-ra\\python\r?\nD:AI', "acme-adcs-ra\python`nD:PAI"
        $v = @(Test-AclDumpLocked -DumpText $dump -AllowedTrustees $script:allowed)
        ($v -join ' ') | Should -Match 'PROTECTED and does not inherit'
    }

    It 'flags a DENY ace anywhere' {
        $dump = $script:cleanTree -replace '\(A;ID;FA;;;S-1-5-18\)', '(D;ID;FA;;;S-1-5-18)'
        $v = @(Test-AclDumpLocked -DumpText $dump -AllowedTrustees $script:allowed)
        ($v -join ' ') | Should -Match 'DENY ACE present'
    }

    It 'flags an unexpected trustee even on a properly inherited ace' {
        $dump = $script:cleanTree -replace 'S-1-5-18\)$', 'S-1-5-32-545)'
        $v = @(Test-AclDumpLocked -DumpText $dump -AllowedTrustees $script:allowed)
        ($v -join ' ') | Should -Match "unexpected trustee 'S-1-5-32-545'"
    }

    It 'flags an empty DACL (no ACEs at all) instead of reading it as clean' {
        $dump = @'
acme-adcs-ra
D:PAI(A;OICI;FA;;;S-1-5-32-544)(A;OICI;FA;;;S-1-5-18)
acme-adcs-ra\venv
D:AI
'@
        $v = @(Test-AclDumpLocked -DumpText $dump -AllowedTrustees $script:allowed)
        ($v -join ' ') | Should -Match 'carries no ACEs'
    }

    It 'flags an unlocked root (first entry not protected)' {
        $dump = @'
acme-adcs-ra
D:AI(A;OICI;FA;;;S-1-5-32-544)(A;OICI;FA;;;S-1-5-18)
'@
        $v = @(Test-AclDumpLocked -DumpText $dump -AllowedTrustees $script:allowed)
        ($v -join ' ') | Should -Match 'expected a PROTECTED DACL'
    }

    It 'flags an inherited ace on the root (its DACL must be exactly ours)' {
        $dump = @'
acme-adcs-ra
D:PAI(A;OICIID;FA;;;S-1-5-32-544)(A;OICI;FA;;;S-1-5-18)
'@
        $v = @(Test-AclDumpLocked -DumpText $dump -AllowedTrustees $script:allowed)
        ($v -join ' ') | Should -Match 'INHERITED ACE on an object whose DACL should be exactly ours'
    }

    It 'skips exempted leaf names (verified separately in single-object mode)' {
        $dump = @'
acme-adcs-ra
D:PAI(A;OICI;FA;;;S-1-5-32-544)(A;OICI;FA;;;S-1-5-18)
acme-adcs-ra\acme-ra.env
D:PAI(A;;FR;;;S-1-5-32-544)(A;;FR;;;S-1-5-18)(A;;FR;;;S-1-5-21-1111222233-4444555566-7777888899)
'@
        $v = Test-AclDumpLocked -DumpText $dump -AllowedTrustees $script:allowed -ExemptLeafNames @('acme-ra.env')
        @($v).Count | Should -Be 0
        # ...and the same entry WITHOUT the exemption is (correctly) flagged,
        # so the exemption cannot hide anything the verifier would otherwise catch.
        $v2 = @(Test-AclDumpLocked -DumpText $dump -AllowedTrustees $script:allowed)
        $v2.Count | Should -BeGreaterThan 0
    }

    It 'single-object mode: accepts the dotenv shape' {
        $dump = @'
acme-ra.env
D:PAI(A;;FR;;;S-1-5-32-544)(A;;FR;;;S-1-5-18)(A;;FR;;;S-1-5-21-1111222233-4444555566-7777888899)
'@
        $v = Test-AclDumpLocked -DumpText $dump -AllowedTrustees $script:allowed -AllEntriesMustBeProtected
        @($v).Count | Should -Be 0
    }

    It 'single-object mode: refuses an unlocked object' {
        $dump = @'
acme-ra.env
D:AI(A;;FR;;;S-1-5-32-544)(A;;FR;;;S-1-5-18)
'@
        $v = @(Test-AclDumpLocked -DumpText $dump -AllowedTrustees $script:allowed -AllEntriesMustBeProtected)
        ($v -join ' ') | Should -Match 'expected a PROTECTED DACL'
    }

    It 'fails closed on an unparsable/empty dump' {
        $v = @(Test-AclDumpLocked -DumpText '' -AllowedTrustees $script:allowed)
        $v.Count | Should -Be 1
        $v[0] | Should -Match 'no entries parsed'
    }
}

# The installer must actually USE the lockdown sequence: the raw one-line
# icacls claim (the bypassable form) must be gone, and both ACL passes must
# end in the read-back proof. Text-level, because these run on Linux where
# icacls/takeown do not exist; the lab re-proof exercises the real calls.
Describe 'install-windows.ps1 uses the hostile-tree lockdown' {
    BeforeAll {
        $script:installer = Get-Content -Raw "$PSScriptRoot/../../scripts/install-windows.ps1"
    }

    It 'no raw /inheritance:r claim remains on the install root' {
        $script:installer | Should -Not -Match 'icacls\s+\$InstallDir\s+/inheritance:r'
        $script:installer | Should -Not -Match 'icacls\s+\$envFile\s+/inheritance:r'
    }

    It 'ownership+reset runs on both ACL passes' {
        @([regex]::Matches($script:installer, 'Reset-TreeToInherited -Path \$InstallDir')).Count | Should -Be 2
    }

    It 'both passes end in the read-back proof' {
        @([regex]::Matches($script:installer, 'Assert-InstallTreeLocked -Root \$InstallDir')).Count | Should -Be 2
    }

    It 'the dotenv gets its own protected DACL' {
        $script:installer | Should -Match 'Set-ObjectProtectedDacl -Path \$envFile'
    }

    It 'the install-root trust flag is set only after the proof' {
        $iProof = $script:installer.IndexOf('Assert-InstallTreeLocked -Root $InstallDir')
        $iFlag = $script:installer.IndexOf('$script:installRootSecured = $true')
        $iProof | Should -BeGreaterThan -1
        $iFlag | Should -BeGreaterThan $iProof
    }
}
