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

    It 'requires an out-of-band digest for a local path too' {
        { Assert-MsiSourceAcceptable -Source 'C:\vetted\h.msi' } |
            Should -Throw -ExpectedMessage '*-HttpPlatformHandlerSha256*'
        Assert-MsiSourceAcceptable -Source 'C:\vetted\h.msi' -Sha256 ('a' * 64) |
            Should -Be 'local'
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

# --- Live-run finding, 2026-08-15: icacls /save is UTF-16LE without a BOM ------
#
# The first live execution of the two-tree installer proved a healthy tree
# FAILED its own ACL verification: `Get-Content -Raw` decoded the BOM-less
# UTF-16LE /save file as ANSI (5.1) / UTF-8 (pwsh 7), every second character
# became NUL, no line started with 'D:', and Test-AclDumpLocked failed closed
# with 'no entries parsed'. No earlier test had decoded a real /save file --
# the fixtures were hand-typed SDDL strings -- so this was invisible from
# Linux and from CI alike. These tests build the dump as BYTES, the way icacls
# writes it.
Describe 'Get-IcaclsDumpText (live-run finding: icacls /save is BOM-less UTF-16LE)' {
    BeforeAll {
        $script:dumpText = @'
acme-adcs-ra
D:PAI(A;OICI;FA;;;S-1-5-32-544)(A;OICI;FA;;;S-1-5-18)
acme-adcs-ra\venv
D:AI(A;OICIID;FA;;;S-1-5-32-544)(A;OICIID;FA;;;S-1-5-18)
'@
        $script:dir = New-Item -ItemType Directory -Force -Path (Join-Path ([IO.Path]::GetTempPath()) ("ra-dumptext-" + [guid]::NewGuid().ToString('N')))
        # icacls /save, byte for byte: UTF-16LE, no BOM, CRLF line endings.
        $script:noBom = New-Object System.Text.UnicodeEncoding($false, $false)
        $script:fNoBom = Join-Path $script:dir 'dump-nobom.txt'
        [IO.File]::WriteAllText($script:fNoBom, $script:dumpText, $script:noBom)
        # Same dump with a BOM, in case a future icacls writes one.
        $script:fBom = Join-Path $script:dir 'dump-bom.txt'
        [IO.File]::WriteAllText($script:fBom, $script:dumpText, [System.Text.Encoding]::Unicode)
        # A plain single-byte dump, in case a future icacls ever writes ANSI.
        $script:fAnsi = Join-Path $script:dir 'dump-ansi.txt'
        [IO.File]::WriteAllText($script:fAnsi, $script:dumpText, [System.Text.Encoding]::ASCII)
    }
    AfterAll { Remove-Item -LiteralPath $script:dir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'decodes a BOM-less UTF-16LE dump so the parser finds the entries (what icacls /save actually writes)' {
        $text = Get-IcaclsDumpText -Path $script:fNoBom
        @($text -split "`r?`n" | Where-Object { $_.StartsWith('D:') }).Count | Should -Be 2
        $v = @(Test-AclDumpLocked -DumpText $text -AllowedTrustees @('S-1-5-32-544', 'S-1-5-18'))
        @($v).Count | Should -Be 0
    }

    It 'decodes a BOM-prefixed UTF-16LE dump identically' {
        $text = Get-IcaclsDumpText -Path $script:fBom
        @($text -split "`r?`n" | Where-Object { $_.StartsWith('D:') }).Count | Should -Be 2
    }

    It 'still decodes a single-byte dump' {
        $text = Get-IcaclsDumpText -Path $script:fAnsi
        @($text -split "`r?`n" | Where-Object { $_.StartsWith('D:') }).Count | Should -Be 2
    }

    It 'the old reader fails this same file, so this test cannot pass against the old code' {
        # Mutation guard: this is what Windows PowerShell 5.1's Get-Content -Raw
        # did -- decode the bytes with the platform default (ANSI) because there
        # is no BOM. (This very pwsh SNIFS BOM-less UTF-16, which is why the
        # defect passed every local Pester run and only bit on 5.1, live.) The
        # comparison must be ORDINAL: culture-sensitive StartsWith ignores NUL
        # characters, so it falsely "matches" the mangled lines on pwsh and the
        # guard would pass on both old and fixed code.
        $bytes = [IO.File]::ReadAllBytes($script:fNoBom)
        $old = [System.Text.Encoding]::Default.GetString($bytes)
        @($old -split "`r?`n" | Where-Object { $_.StartsWith('D:', [System.StringComparison]::Ordinal) }).Count | Should -Be 0
    }
}
# --- Daybreak 2026-08-15 SECOND rescan -----------------------------------------
#
# Four findings; three of them Windows-installer ones:
#
#   F1 (high)   a preplanted manifest authenticated a preplanted interpreter,
#               because both lived in the namespace the attacker controlled.
#   F2 (medium) takeown has no /L, so a junction raced in after the prewalk
#               redirected an ELEVATED recursive ownership rewrite out of tree.
#   F3 (medium) separate ownership/DACL/hash/exec passes over a LIVE tree left
#               attacker-owned descendants and retained gMSA write handles.

Describe 'Test-IcaclsOutputClean (F2: a partial icacls run is a failure)' {
    It 'accepts a clean run' {
        Test-IcaclsOutputClean -ExitCode 0 -Output 'Successfully processed 12 files; Failed processing 0 files' |
            Should -BeTrue
    }

    It 'rejects a non-zero exit code' {
        Test-IcaclsOutputClean -ExitCode 1 -Output 'Successfully processed 0 files; Failed processing 0 files' |
            Should -BeFalse
    }

    It 'rejects a zero exit code that still reports failed objects (what /c used to hide)' {
        Test-IcaclsOutputClean -ExitCode 0 -Output @(
            'C:\ProgramData\acme-adcs-ra\python: Access is denied.',
            'Successfully processed 40 files; Failed processing 1 files'
        ) | Should -BeFalse
    }

    It 'is not fooled by the zero-failure line containing a digit run' {
        Test-IcaclsOutputClean -ExitCode 0 -Output 'Successfully processed 100 files; Failed processing 0 files' |
            Should -BeTrue
    }

    It 'accepts empty or null output on a zero exit (quiet mode prints nothing useful)' {
        Test-IcaclsOutputClean -ExitCode 0 -Output '' | Should -BeTrue
        Test-IcaclsOutputClean -ExitCode 0 -Output $null | Should -BeTrue
    }
}

Describe 'Get-AdministratorsOwnerCandidates (F2)' {
    It 'always offers the locale-independent SID form first' {
        @(Get-AdministratorsOwnerCandidates)[0] | Should -Be '*S-1-5-32-544'
    }

    It 'never returns an empty candidate list, even where SIDs cannot be translated' {
        @(Get-AdministratorsOwnerCandidates).Count | Should -BeGreaterOrEqual 1
    }
}

Describe 'Test-AppPoolWorkersGone (F3: the worker must be dead, not draining)' {
    It 'reports gone when appcmd lists no worker at all' {
        Test-AppPoolWorkersGone -AppcmdWpOutput '' -AppPool 'acme-adcs-ra' | Should -BeTrue
        Test-AppPoolWorkersGone -AppcmdWpOutput $null -AppPool 'acme-adcs-ra' | Should -BeTrue
    }

    It 'reports gone when the only live workers belong to other pools' {
        Test-AppPoolWorkersGone -AppcmdWpOutput @(
            'WP "4120" (applicationPool:cert-watch)',
            'WP "9008" (applicationPool:DefaultAppPool)'
        ) -AppPool 'acme-adcs-ra' | Should -BeTrue
    }

    It 'reports NOT gone while our own worker is still alive' {
        Test-AppPoolWorkersGone -AppcmdWpOutput @(
            'WP "4120" (applicationPool:cert-watch)',
            'WP "7331" (applicationPool:acme-adcs-ra)'
        ) -AppPool 'acme-adcs-ra' | Should -BeFalse
    }

    It 'does not match a pool whose name merely contains ours' {
        Test-AppPoolWorkersGone -AppcmdWpOutput 'WP "7331" (applicationPool:acme-adcs-ra-staging)' `
            -AppPool 'acme-adcs-ra' | Should -BeTrue
    }

    It 'fails CLOSED on output it cannot parse rather than reading it as all-clear' {
        Test-AppPoolWorkersGone -AppcmdWpOutput 'ERROR ( message:Configuration error. )' `
            -AppPool 'acme-adcs-ra' | Should -BeFalse
    }
}

Describe 'Test-OwnerAllowed (F3: every descendant owner, not just the root)' {
    It 'accepts the Administrators group and SYSTEM by SID' {
        Test-OwnerAllowed -Owner 'S-1-5-32-544' -AllowedOwnerSids @('S-1-5-32-544', 'S-1-5-18') | Should -BeTrue
        Test-OwnerAllowed -Owner 'S-1-5-18'     -AllowedOwnerSids @('S-1-5-32-544', 'S-1-5-18') | Should -BeTrue
    }

    It 'refuses any other owner -- an owner holds implicit WRITE_DAC' {
        Test-OwnerAllowed -Owner 'S-1-5-21-1-2-3-1001' -AllowedOwnerSids @('S-1-5-32-544', 'S-1-5-18') |
            Should -BeFalse
    }

    It 'refuses an owner it cannot resolve to a SID (cannot-tell is not allowed)' {
        Test-OwnerAllowed -Owner 'WORKGROUP\nobody-here' -AllowedOwnerSids @('S-1-5-32-544') | Should -BeFalse
        Test-OwnerAllowed -Owner ''   -AllowedOwnerSids @('S-1-5-32-544') | Should -BeFalse
        Test-OwnerAllowed -Owner '   ' -AllowedOwnerSids @('S-1-5-32-544') | Should -BeFalse
    }
}

Describe 'Get-TreePaths (F3: per-object inspection must not be redirectable)' {
    BeforeAll {
        $script:tpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-test-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path (Join-Path $script:tpRoot "a/b") | Out-Null
        Set-Content -Path (Join-Path $script:tpRoot "a/f1.txt") -Value "x"
        Set-Content -Path (Join-Path $script:tpRoot "a/b/f2.txt") -Value "y"
    }
    AfterAll {
        Remove-Item -LiteralPath $script:tpRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'returns the root plus every directory and file beneath it' {
        $paths = Get-TreePaths -Path $script:tpRoot
        @($paths).Count | Should -Be 5
        ($paths -join ';') | Should -Match 'f2\.txt'
    }

    It 'returns nothing for a path that does not exist' {
        @(Get-TreePaths -Path (Join-Path $script:tpRoot "no-such-dir")).Count | Should -Be 0
    }

    It 'THROWS on a reparse point rather than walking through it' {
        $linkTarget = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-target-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $linkTarget | Out-Null
        $link = Join-Path $script:tpRoot "a/link"
        $made = $false
        try {
            New-Item -ItemType SymbolicLink -Path $link -Target $linkTarget -ErrorAction Stop | Out-Null
            $made = $true
        } catch {
            # Unprivileged Windows cannot create symlinks; the Linux CI run can.
        }
        if ($made) {
            { Get-TreePaths -Path $script:tpRoot } | Should -Throw -ExpectedMessage '*reparse point*'
            Remove-Item -LiteralPath $link -Force -ErrorAction SilentlyContinue
        } else {
            Set-ItResult -Skipped -Because 'this host cannot create a symbolic link'
        }
        Remove-Item -LiteralPath $linkTarget -Recurse -Force -ErrorAction SilentlyContinue
    }
}


# --- 2026-08-15 rescan-3: retire the adoption model ----------------------------
#
# Four rounds of findings all shared one premise: that a directory a local user
# might have created first could be made safe to ADOPT. Each round's mechanism
# -- ACL claim, ownership claim, link walk, content manifest, out-of-tree anchor
# -- became the next round's finding.
#
# The premise is gone. Executable content moved to %ProgramFiles%, which
# non-administrators cannot create in; state stayed in %ProgramData% where the
# gMSA needs write and nothing is executed; and a pre-existing root is either
# provably ours or refused. The tests below pin the properties that only exist
# as STRUCTURE, so a future edit cannot quietly reintroduce the model.

Describe 'Get-ForeignRootRefusal (the operator must be able to act on a refusal)' {
    BeforeAll {
        $script:refusal = Get-ForeignRootRefusal -Path 'C:\ProgramData\acme-adcs-ra' `
            -Purpose 'state (database, logs, secrets)' `
            -Reasons @('C:\ProgramData\acme-adcs-ra : owner is BUILTIN\Users') `
            -Preserve @('C:\ProgramData\acme-adcs-ra\acme_ra.db')
    }

    It 'names the path, the purpose and why it did not qualify' {
        $script:refusal | Should -Match 'C:\\ProgramData\\acme-adcs-ra'
        $script:refusal | Should -Match 'state \(database, logs, secrets\)'
        $script:refusal | Should -Match 'owner is BUILTIN\\Users'
    }

    It 'tells the operator what to DO, not just that it failed' {
        # A refusal nobody can act on gets worked around, which is worse than
        # not refusing.
        $script:refusal | Should -Match 'What to do'
        $script:refusal | Should -Match 'Remove or rename'
        $script:refusal | Should -Match 'Re-run this installer'
    }

    It 'lists the files worth keeping BEFORE telling them to delete the directory' {
        $iKeep = $script:refusal.IndexOf('acme_ra.db')
        $iDel  = $script:refusal.IndexOf('Remove or rename')
        $iKeep | Should -BeGreaterThan -1
        $iDel  | Should -BeGreaterThan $iKeep
    }

    It 'warns that preserved files from a foreign tree are themselves suspect' {
        # The planted acme-ra.env case: it carries ACME_RA_EAB_ALLOWLIST and
        # ACME_RA_SAN_SCOPES, so restoring it unexamined hands over issuance.
        $script:refusal | Should -Match 'Inspect them before reusing them'
    }

    It 'caps the reason list rather than printing hundreds of violations' {
        $many = Get-ForeignRootRefusal -Path 'C:\x' -Purpose 'runtime (code)' `
            -Reasons (1..50 | ForEach-Object { "violation $_" })
        $many | Should -Match 'and 45 more'
    }
}

Describe 'install-windows.ps1 separates code from state' {
    BeforeAll {
        $script:installer = Get-Content -Raw "$PSScriptRoot/../../scripts/install-windows.ps1"
        $script:lib = Get-Content -Raw "$PSScriptRoot/../../scripts/lib/InstallVerifyLib.ps1"
        $script:webconfig = Get-Content -Raw "$PSScriptRoot/../../deploy/iis/web.config"
    }

    It 'defaults the runtime to %ProgramFiles% and the state to %ProgramData%' {
        $script:installer | Should -Match '\$RuntimeDir = "\$env:ProgramFiles\\acme-adcs-ra"'
        $script:installer | Should -Match '\$InstallDir = "C:\\ProgramData\\acme-adcs-ra"'
    }

    It 'puts the venv in the RUNTIME tree, never the state tree' {
        $script:installer | Should -Match '\$runtimeCurrent = Join-Path \$RuntimeDir "current"'
        $script:installer | Should -Match '\$venv\s+= Join-Path \$runtimeCurrent "venv"'
        $script:installer | Should -Not -Match '\$venv\s+= Join-Path \$InstallDir'
    }

    It 'grants the gMSA execute on code and modify on state -- never write on code' {
        $script:installer | Should -Match "\`$runtimeGrants = @\(\s*\r?\n\s*'\*S-1-5-32-544:\(OI\)\(CI\)F', '\*S-1-5-18:\(OI\)\(CI\)F', \('\*' \+ \`$gmsaSid \+ ':\(OI\)\(CI\)RX'\)"
        $script:installer | Should -Match "\`$stateGrants = @\(\s*\r?\n\s*'\*S-1-5-32-544:\(OI\)\(CI\)F', '\*S-1-5-18:\(OI\)\(CI\)F', \('\*' \+ \`$gmsaSid \+ ':\(OI\)\(CI\)M'\)"
        # The runtime tree must never carry a Modify or Full grant for the gMSA.
        $script:installer | Should -Not -Match "runtimeGrants[^)]*GmsaAccount \+ ':\(OI\)\(CI\)M'"
        $script:installer | Should -Not -Match "runtimeGrants[^)]*GmsaAccount \+ ':\(OI\)\(CI\)F'"
    }

    It 'points web.config processPath at the runtime tree' {
        $script:webconfig | Should -Match 'processPath="C:\\Program Files\\acme-adcs-ra\\current\\venv\\Scripts\\python.exe"'
        $script:webconfig | Should -Not -Match 'processPath="C:\\ProgramData'
    }

    It 'keeps the database, logs and dotenv in the state tree' {
        $script:webconfig | Should -Match 'ACME_RA_DB_PATH" value="C:\\ProgramData\\acme-adcs-ra\\acme_ra\.db"'
        $script:webconfig | Should -Match 'ACME_RA_DOTENV" value="C:\\ProgramData\\acme-adcs-ra\\acme-ra\.env"'
    }

    It 'rewrites BOTH roots in web.config when either is overridden' {
        $script:installer | Should -Match '\$wcContent\.Replace\(\$defaultRuntime, \$RuntimeDir\)'
        $script:installer | Should -Match '\$wcContent\.Replace\(\$defaultState, \$InstallDir\)'
    }
}

# --- Live-run finding #2, 2026-08-15: the rollback forgot the state tree ------
#
# Every install's state-root claim runs `icacls /reset /t`, which strips the
# dotenv's own protected DACL; it was only re-applied ~150 lines later, AFTER
# the runtime build. A build that failed in between (the documented rollback
# path) rolled the RUNTIME back meticulously and left acme-ra.env -- the EAB
# allowlist and SAN scopes -- inheriting gMSA MODIFY. Found live: the next
# install's pre-flight then refused the whole tree, bricking the install.
#
# Source-order assertions on the installer (the same pattern as the Describe
# above); the ACL semantics themselves are Test-AclDumpLocked's, already
# unit-tested.
Describe 'install-windows.ps1: a failed build must not leave the dotenv unprotected' {
    BeforeAll {
        $script:installer = Get-Content -Raw "$PSScriptRoot/../../scripts/install-windows.ps1"
    }

    It 're-protects the dotenv IMMEDIATELY after the state-root claim, before the runtime build' {
        $claim = $script:installer.IndexOf("Initialize-SecuredRoot -Path `$InstallDir")
        $reprotect = $script:installer.IndexOf('re-protected', $claim)
        $build = $script:installer.IndexOf('Reset-RuntimeDirectory -RuntimeDir $RuntimeDir')
        $claim | Should -BeGreaterThan 0
        $build | Should -BeGreaterThan 0
        $reprotect | Should -BeGreaterThan $claim
        $reprotect | Should -BeLessThan $build
    }

    It 'the rollback handler restores the dotenv DACL and re-proves the state tree' {
        $catch = $script:installer.IndexOf('} catch {', $script:installer.IndexOf('try {', $script:installer.IndexOf('Reset-RuntimeDirectory')))
        $catch | Should -BeGreaterThan 0
        $body = $script:installer.Substring($catch, [Math]::Min(3000, $script:installer.Length - $catch))
        $body | Should -Match 'Set-ObjectProtectedDacl -Path \$envFile'
        $body | Should -Match 'Assert-InstallTreeLocked -Root \$InstallDir'
    }
}


Describe 'install-windows.ps1 never adopts a namespace' {
    BeforeAll {
        $script:installer = Get-Content -Raw "$PSScriptRoot/../../scripts/install-windows.ps1"
        $script:lib = Get-Content -Raw "$PSScriptRoot/../../scripts/lib/InstallVerifyLib.ps1"
    }

    It 'runs the provenance pre-flight on BOTH roots before claiming either' {
        @([regex]::Matches($script:installer, 'Initialize-SecuredRoot -Path')).Count | Should -Be 2
        $script:installer | Should -Match 'Initialize-SecuredRoot -Path \$RuntimeDir'
        $script:installer | Should -Match 'Initialize-SecuredRoot -Path \$InstallDir'
        # ... and the claim inside it is gated on the verdict.
        $iProv  = $script:installer.IndexOf('$prov = Get-RootProvenance -Path $Path')
        $iClaim = $script:installer.IndexOf('Reset-TreeToInherited -Path $Path')
        $iProv  | Should -BeGreaterThan -1
        $iClaim | Should -BeGreaterThan $iProv
    }

    It 'refuses a foreign root instead of force-claiming it' {
        $script:installer | Should -Match "'foreign' \{"
        $script:installer | Should -Match 'throw \(Get-ForeignRootRefusal'
    }

    It 'resolves the gMSA SID BEFORE the pre-flight, which needs it' {
        # The pre-flight has to know what a finished install looks like, and a
        # finished install carries a gMSA ACE on both roots.
        $iSid = $script:installer.IndexOf('$gmsaSid = (New-Object System.Security.Principal.NTAccount($GmsaAccount))')
        $iRoot = $script:installer.IndexOf('Initialize-SecuredRoot -Path $RuntimeDir')
        $iSid  | Should -BeGreaterThan -1
        $iRoot | Should -BeGreaterThan $iSid
    }

    It 'no longer executes, verifies or reuses a destination interpreter' {
        # The whole manifest/anchor apparatus is gone, along with the question
        # it answered. Its return would mean the adoption model came back.
        foreach ($gone in @('Test-TreeManifestMatches', 'Test-TreeManifestAuthentic',
                            'Get-TreeManifestAnchor', 'Set-TreeManifestAnchor',
                            'Save-TreeManifest', 'Test-DestinationInterpreterTrusted',
                            'python.manifest.json')) {
            $script:installer | Should -Not -Match ([regex]::Escape($gone))
            $script:lib       | Should -Not -Match ([regex]::Escape($gone))
        }
        $script:installer | Should -Not -Match '\$InstallDir "python\\\\python\.exe"'
    }

    It 'builds the runtime fresh rather than cleaning up a reused one' {
        $iReset = $script:installer.IndexOf('$reset = Reset-RuntimeDirectory -RuntimeDir $RuntimeDir')
        $iVenv  = $script:installer.IndexOf('-m", "venv", $venv')
        $iReset | Should -BeGreaterThan -1
        $iVenv  | Should -BeGreaterThan $iReset
        # The old delete-the-venv-first dance is gone; there is nothing to delete.
        $script:installer | Should -Not -Match 'Remove-Item -LiteralPath \$venv -Recurse -Force'
    }

    It 'rolls the previous runtime back when the build throws' {
        $script:installer | Should -Match 'Restore-RetiredRuntime -RuntimeDir \$RuntimeDir -Retired \$retiredRuntime'
        $iCatch   = $script:installer.IndexOf('} catch {')
        $iRestore = $script:installer.IndexOf('Restore-RetiredRuntime -RuntimeDir $RuntimeDir')
        $iCatch   | Should -BeGreaterThan -1
        $iRestore | Should -BeGreaterThan $iCatch
    }

    It 'removes the retired runtime BEFORE proving the new one, and says so' {
        # The retired tree sits inside $RuntimeDir, so leaving it there would
        # put a whole second (old) venv inside the recursive ownership reset
        # and the read-back proof -- doubling their cost and letting a tree we
        # are about to delete fail the proof of the tree we just built.
        $iRemove = $script:installer.IndexOf('Remove-Item -LiteralPath $retiredRuntime')
        $iProve  = $script:installer.IndexOf('Assert-InstallTreeLocked -Root $RuntimeDir')
        $iRemove | Should -BeGreaterThan -1
        $iProve  | Should -BeGreaterThan $iRemove
        # ... and the rollback target is cleared so the catch cannot claim to
        # have restored something that is gone.
        $script:installer | Should -Match '\$retiredRuntime = \$null'
    }

    It 'tells the operator plainly when a failure is past the rollback point' {
        # A proof failure after the retired tree is gone leaves the host with a
        # built-but-unverified runtime and the pool deliberately stopped. That
        # is the right direction, and it has to be legible.
        $script:installer | Should -Match 'no previous runtime to fall back to'
        $script:installer | Should -Match 'app pool has been left'
        # The restore branch must report its actual result, not assume success.
        $script:installer | Should -Match 'if \(Restore-RetiredRuntime -RuntimeDir \$RuntimeDir -Retired \$retiredRuntime\)'
    }

    It 'still stops and proves the app pool dead before any of it' {
        $iStop  = $script:installer.IndexOf('Stop-AppPoolAndWait -AppcmdExe $appcmdExe')
        $iRoot  = $script:installer.IndexOf('Initialize-SecuredRoot -Path $RuntimeDir')
        $iStop  | Should -BeGreaterThan -1
        $iRoot  | Should -BeGreaterThan $iStop
    }

    It 'still refuses every link-following privileged operation' {
        $script:lib       | Should -Not -Match 'takeown\.exe'
        $script:installer | Should -Not -Match 'takeown\.exe'
        $calls = @([regex]::Matches($script:lib, '&\s+\$script:IcaclsExe[^\r\n]*'))
        $calls.Count | Should -BeGreaterOrEqual 5
        foreach ($c in $calls) {
            $c.Value | Should -Match '\s/L\b'
            $c.Value | Should -Not -Match '\s/c\b'
        }
    }

    It 'proves both trees with the same function the pre-flight uses' {
        # One definition of "ours", so the end of one install and the start of
        # the next cannot disagree.
        $script:lib | Should -Match 'function Get-InstallTreeViolations'
        $script:lib | Should -Match 'Get-InstallTreeViolations -Root \$Root -AllowedTrustees \$AllowedTrustees'
        $script:lib | Should -Match 'Get-InstallTreeViolations -Root \$Path -AllowedTrustees \$AllowedTrustees'
    }
}

Describe 'Get-TreeOwnerViolations root/descendant split' {
    It 'holds the root to a stricter owner set than its descendants' {
        # The state tree legitimately contains gMSA-owned files (log lines, the
        # SQLite journal). Its ROOT never is: a directory a non-administrator
        # created is owned by them, and that is the pre-flight's best signal.
        $lib = Get-Content -Raw "$PSScriptRoot/../../scripts/lib/InstallVerifyLib.ps1"
        $lib | Should -Match '\[string\[\]\]\$RootOwnerSids = @\(\)'
        $lib | Should -Match '\$expected = if \(\$isRoot\) \{ \$rootSids \} else \{ @\(\$AllowedOwnerSids\) \}'
    }

    It 'passes the gMSA as a permitted state-tree owner, but never for the runtime' {
        $installer = Get-Content -Raw "$PSScriptRoot/../../scripts/install-windows.ps1"
        $installer | Should -Match "\`$stateOwnerSids = @\('S-1-5-32-544', 'S-1-5-18', \`$gmsaSid\)"
        # The runtime claim passes no -AllowedOwnerSids override, so it keeps
        # the Administrators/SYSTEM default.
        $installer | Should -Match 'Initialize-SecuredRoot -Path \$RuntimeDir -Purpose ''runtime \(code\)'' `\r?\n\s*-Grants \$runtimeGrants -AllowedTrustees \$raTrustees\r?\n'
    }
}

Describe 'Runtime staging is rename-based and rollback-safe' {
    It 'retires with a directory rename, not a copy' {
        $lib = Get-Content -Raw "$PSScriptRoot/../../scripts/lib/InstallVerifyLib.ps1"
        $lib | Should -Match '\[System\.IO\.Directory\]::Move\(\$current, \$retired\)'
        $lib | Should -Match '\[System\.IO\.Directory\]::Move\(\$Retired, \$current\)'
        # Exactly those two, and nothing else moving a runtime: Move-Item can
        # silently degrade to copy-then-delete across volumes, which is neither
        # atomic nor cheap for a tree this size.
        @([regex]::Matches($lib, '\[System\.IO\.Directory\]::Move')).Count | Should -Be 2
    }

    It 'builds at the FINAL path because a venv is not relocatable' {
        # pyvenv.cfg records an absolute home and Scripts\*.exe embed the
        # interpreter path; a built-then-renamed venv cannot find its stdlib.
        $lib = Get-Content -Raw "$PSScriptRoot/../../scripts/lib/InstallVerifyLib.ps1"
        $lib | Should -Match 'venv is NOT relocatable'
        $lib | Should -Match "\`$current = Join-Path \`$RuntimeDir 'current'"
    }

    It 'prunes leftovers from an interrupted run without failing the install' {
        $lib = Get-Content -Raw "$PSScriptRoot/../../scripts/lib/InstallVerifyLib.ps1"
        $lib | Should -Match 'function Remove-StaleRuntimeDirectories'
        $lib | Should -Match "\.staging-\*"
        $lib | Should -Match "\.retired-\*"
    }
}

Describe 'Reset-RuntimeDirectory / Restore-RetiredRuntime round trip' {
    BeforeAll {
        $script:rt = Join-Path ([System.IO.Path]::GetTempPath()) ("rt-test-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $script:rt | Out-Null
    }
    AfterAll {
        Remove-Item -LiteralPath $script:rt -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'creates current\ on a first install, with nothing retired' {
        # Set-ObjectProtectedDacl is Windows-only, so this exercises the
        # rename/create logic alone -- which is the part with the ordering bug
        # potential.
        $r = Reset-RuntimeDirectory -RuntimeDir $script:rt
        $r.Retired | Should -BeNullOrEmpty
        Test-Path -LiteralPath $r.Current | Should -BeTrue
        (Get-ChildItem -LiteralPath $r.Current -Force).Count | Should -Be 0
    }

    It 'retires a populated runtime and hands back an EMPTY one' {
        Set-Content -Path (Join-Path $script:rt "current/old-marker.txt") -Value "previous build"
        $r = Reset-RuntimeDirectory -RuntimeDir $script:rt
        $r.Retired | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath (Join-Path $r.Retired "old-marker.txt") | Should -BeTrue
        (Get-ChildItem -LiteralPath $r.Current -Force).Count | Should -Be 0
        $script:lastRetired = $r.Retired
    }

    It 'puts the retired runtime back, discarding the half-built one' {
        Set-Content -Path (Join-Path $script:rt "current/half-built.txt") -Value "failed build"
        Restore-RetiredRuntime -RuntimeDir $script:rt -Retired $script:lastRetired | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:rt "current/old-marker.txt") | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:rt "current/half-built.txt") | Should -BeFalse
    }

    It 'is a no-op when there is nothing to restore' {
        Restore-RetiredRuntime -RuntimeDir $script:rt -Retired "" | Should -BeFalse
        Restore-RetiredRuntime -RuntimeDir $script:rt -Retired (Join-Path $script:rt ".retired-nope") |
            Should -BeFalse
    }

    It 'removes the stale staging and retired directories it finds' {
        New-Item -ItemType Directory -Force -Path (Join-Path $script:rt ".staging-abc") | Out-Null
        New-Item -ItemType Directory -Force -Path (Join-Path $script:rt ".retired-def") | Out-Null
        Remove-StaleRuntimeDirectories -RuntimeDir $script:rt | Should -Be 2
        Test-Path -LiteralPath (Join-Path $script:rt "current") | Should -BeTrue
    }
}

Describe 'Root and dotenv ownership are held strictly (rescan-3 audit)' {
    BeforeAll {
        $script:lib = Get-Content -Raw "$PSScriptRoot/../../scripts/lib/InstallVerifyLib.ps1"
        $script:installer = Get-Content -Raw "$PSScriptRoot/../../scripts/install-windows.ps1"
    }

    It 'never derives the strict owner set from the loose one' {
        # Found while auditing the rework. The state tree permits gMSA-owned
        # DESCENDANTS (log files, the SQLite journal). If the root and the
        # protected entries inherited that permission, a compromised worker
        # could delete acme-ra.env -- it holds Modify on the parent, which
        # includes delete-child -- write its own, and have the NEXT install
        # accept the tree as "ours" and preserve the planted file. That file
        # carries ACME_RA_EAB_ALLOWLIST and ACME_RA_SAN_SCOPES.
        $script:lib | Should -Match "\[string\[\]\]\`$RootOwnerSids = @\('S-1-5-32-544', 'S-1-5-18'\)"
        $script:lib | Should -Match '-AllowedOwnerSids \$AllowedOwnerSids -RootOwnerSids \$RootOwnerSids'
    }

    It 'owner-checks every protected entry, not just its DACL' {
        $script:lib | Should -Match '\$entryOwner = \(Get-Acl -LiteralPath \$entryPath\)\.Owner'
        $script:lib | Should -Match 'Test-OwnerAllowed -Owner \$entryOwner -AllowedOwnerSids \$RootOwnerSids'
    }

    It 'the installer registers the dotenv as a protected entry on every pass' {
        # Three passes now: the state-root claim, the final post-install proof,
        # and the rollback handler's re-proof (a failed build must leave the
        # dotenv protected too -- live finding #2, 2026-08-15).
        @([regex]::Matches($script:installer, "ProtectedEntries @\{ 'acme-ra\.env'")).Count |
            Should -Be 3
    }

    It 'Test-OwnerAllowed would reject a gMSA-owned object under the strict set' {
        # The strict set by SID, exercised directly: a domain account SID is not
        # Administrators or SYSTEM, however legitimate it is elsewhere.
        Test-OwnerAllowed -Owner 'S-1-5-21-99-88-77-1104' `
            -AllowedOwnerSids @('S-1-5-32-544', 'S-1-5-18') | Should -BeFalse
        Test-OwnerAllowed -Owner 'S-1-5-21-99-88-77-1104' `
            -AllowedOwnerSids @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-21-99-88-77-1104') |
            Should -BeTrue
    }
}

# --- Daybreak round 4 (2026-08-15): four findings on the two-tree installer ---
#
#   M1  TOCTOU on first-install state-root creation: New-Item -Force adopted a
#       directory raced into the gap after the absence check; setowner /t then
#       normalised the attacker's files and the planted dotenv shipped.
#   M2  A clean legacy single-tree layout passes the generic trustee/owner/DACL
#       provenance check (same SIDs, plain inheritance) while the preserved
#       web.config keeps launching the old gMSA-writable ProgramData venv.
#   L1  Bare py/python names through cmd /c resolve from the CWD first.
#   L2  Overlapping -RuntimeDir/-InstallDir silently collapse the RX/Modify
#       boundary; both grant sets have the same proof shape, so everything
#       reads back green.

Describe 'Get-PathRelation / Test-PathInsideTree (L2: the boundary must be two trees)' {
    It 'identifies equal roots across case and trailing-slash noise' {
        Get-PathRelation -A 'C:\Program Files\acme-adcs-ra' -B 'c:\program files\ACME-ADCS-RA\' |
            Should -Be 'equal'
    }

    It 'identifies state nested inside the runtime tree' {
        Get-PathRelation -A 'C:\ra\state' -B 'C:\ra' | Should -Be 'a-inside-b'
        Get-PathRelation -A 'C:\ra' -B 'C:\ra\state' | Should -Be 'b-inside-a'
    }

    It 'refuses a drive root as an install tree' {
        { Get-PathRelation -A 'C:\x' -B 'C:\' } | Should -Throw '*drive root*'
    }

    It 'identifies the two default roots as disjoint' {
        Get-PathRelation -A 'C:\Program Files\acme-adcs-ra' -B 'C:\ProgramData\acme-adcs-ra' |
            Should -Be 'disjoint'
    }

    It 'Test-PathInsideTree: a ProgramData processPath is inside the state tree' {
        Test-PathInsideTree -Path 'C:\ProgramData\acme-adcs-ra\venv\Scripts\python.exe' `
            -Tree 'C:\ProgramData\acme-adcs-ra' | Should -BeTrue
        Test-PathInsideTree -Path 'C:\Program Files\acme-adcs-ra\current\venv\Scripts\python.exe' `
            -Tree 'C:\ProgramData\acme-adcs-ra' | Should -BeFalse
    }

    It 'Test-PathInsideTree: a sibling with a shared prefix is NOT inside' {
        Test-PathInsideTree -Path 'C:\ProgramData\acme-adcs-ra-legacy\x' `
            -Tree 'C:\ProgramData\acme-adcs-ra' | Should -BeFalse
    }
}

Describe 'Get-InstallTreeViolations: executable content at the state root (M2)' {
    BeforeAll {
        $script:root = New-Item -ItemType Directory -Force -Path (Join-Path ([IO.Path]::GetTempPath()) ("ra-forbidden-" + [guid]::NewGuid().ToString('N')))
        # A plausible clean legacy tree: venv + python + scripts + the data files.
        New-Item -ItemType Directory -Force -Path (Join-Path $script:root 'venv\Scripts') | Out-Null
        Set-Content (Join-Path $script:root 'venv\Scripts\python.exe') 'fake interpreter'
        New-Item -ItemType Directory -Force -Path (Join-Path $script:root 'python') | Out-Null
        New-Item -ItemType Directory -Force -Path (Join-Path $script:root 'scripts') | Out-Null
        Set-Content (Join-Path $script:root 'acme_ra.db') 'db'
        Set-Content (Join-Path $script:root 'acme-ra.env') 'env'
        $script:allowed = @('S-1-5-32-544', 'S-1-5-18', 'BA', 'SY')
    }
    AfterAll { Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue }

    It 'refuses a legacy venv at the state root, naming it as executable content' {
        $v = @(Get-InstallTreeViolations -Root $script:root.FullName -AllowedTrustees $script:allowed `
            -ForbiddenTopLevelEntries @('venv', 'python', 'scripts'))
        $v.Count | Should -BeGreaterThan 0
        ($v -join ' ') | Should -Match 'venv : executable content at the state tree root'
        ($v -join ' ') | Should -Match 'operator-requirements\.md section 4'
    }

    It 'the refusal is decided BEFORE the icacls walk, so it is the only violation' {
        # On Linux icacls.exe does not exist, so any test that reaches the ACL
        # stage picks up an icacls failure violation. Exactly one violation
        # here proves the forbidden check short-circuits the walk.
        $v = @(Get-InstallTreeViolations -Root $script:root.FullName -AllowedTrustees $script:allowed `
            -ForbiddenTopLevelEntries @('venv', 'python', 'scripts'))
        $v.Count | Should -Be 1
    }

    It 'does not fire on a tree without the forbidden names, with or without the parameter' {
        # On Linux the ACL stage cannot run (no icacls.exe), so a tree that
        # passes the forbidden check surfaces an icacls error instead of
        # violations. Either way the forbidden-content message must NOT appear.
        $clean = New-Item -ItemType Directory -Force -Path (Join-Path $script:root.FullName 'sub-clean')
        Set-Content (Join-Path $clean 'acme_ra.db') 'db'
        foreach ($withList in @($true, $false)) {
            $out = ''
            try {
                $args_ = @{ Root = $clean.FullName; AllowedTrustees = $script:allowed }
                if ($withList) { $args_['ForbiddenTopLevelEntries'] = @('venv', 'python', 'scripts') }
                $out = (Get-InstallTreeViolations @args_) -join ' '
            } catch { $out = "$_" }
            $out | Should -Not -Match 'executable content at the state tree root'
        }
    }
}

Describe 'install-windows.ps1: Daybreak round 4 fixes' {
    BeforeAll {
        $script:installer = Get-Content -Raw "$PSScriptRoot/../../scripts/install-windows.ps1"
    }

    It 'M1: atomically creates an absent root with its final DACL and re-verifies on collision' {
        $absent = $script:installer.IndexOf("'absent' {")
        $absent | Should -BeGreaterThan 0
        $branch = $script:installer.Substring($absent, [Math]::Min(2200, $script:installer.Length - $absent))
        $branch | Should -Match 'New-AtomicProtectedDirectory -Path \$Path -Grants \$Grants'
        $branch | Should -Not -Match 'New-Item -ItemType Directory'
        # ...and the collision path re-runs the provenance verdict rather than
        # adopting whatever appeared.
        $branch | Should -Match 'Get-RootProvenance -Path \$Path'
        $branch | Should -Match "prov\.State -ne 'ours'"
    }

    It 'M2: the state claim, the final proof and the rollback proof all forbid legacy executable names' {
        @([regex]::Matches($script:installer, 'ForbiddenTopLevelEntries \$stateForbiddenEntries')).Count |
            Should -Be 3   # the state claim, the rollback re-proof, the final proof
        $script:installer | Should -Match '\$stateForbiddenEntries = @\(''venv'', ''python'', ''scripts''\)'
        # The runtime claim must NOT pass the list: its venv is legitimate.
        $rt = $script:installer.IndexOf('Initialize-SecuredRoot -Path $RuntimeDir')
        $rtCall = $script:installer.Substring($rt, 120)
        $rtCall | Should -Not -Match 'ForbiddenTopLevelEntries'
    }

    It 'M2: refuses (not warns) when a preserved web.config launches a state-tree interpreter' {
        # Round 5 hardened this from a warning with a swallowed parse failure
        # into a fail-closed validation shared with -ConfigureIIS.
        $script:installer | Should -Match 'Assert-WebConfigLaunchTrusted -WebConfigPath \$siteWcPath'
        $script:installer | Should -Not -Match '\[!!\] .*INSIDE the state tree'
    }

    It 'L1: disables CWD executable lookup before any cmd /c, and resolves bare probe names' {
        $envSet = $script:installer.IndexOf("NoDefaultCurrentDirectoryInExePath = '1'")
        $probe = $script:installer.IndexOf('function Invoke-PyProbe')
        $envSet | Should -BeGreaterThan 0
        $probe | Should -BeGreaterThan $envSet
        $script:installer | Should -Match 'Get-Command \$Exe -ErrorAction SilentlyContinue'
    }

    It 'L2: refuses overlapping runtime/state roots before touching the host' {
        $ov = $script:installer.IndexOf('Get-PathRelation -A $RuntimeDir -B $InstallDir')
        $ov | Should -BeGreaterThan 0
        # The refusal must precede every host mutation: the pool stop, both
        # claims, and the runtime build.
        foreach ($marker in @('Stop-AppPoolAndWait', 'Initialize-SecuredRoot -Path $RuntimeDir', 'Reset-RuntimeDirectory')) {
            $script:installer.IndexOf($marker) | Should -BeGreaterThan $ov
        }
        $script:installer | Should -Match "rootRelation -ne 'disjoint'"
    }
}

# --- Daybreak round 5 (2026-08-15): five findings on the round-4 fixes -------
#
#   H   file-plant race into a freshly created root (closed by Lock-FreshRoot:
#       protect-at-creation + empty-proof, no /reset on the fresh path)
#   M   lexical path comparison missed aliases (dot segments, slashes, 8.3,
#       junctions) -- canonicalisation added
#   M   PATH-resolved interpreter executed elevated unproven -- chain gate
#   M   SitePath/web.config adopted unverified -- provenance + throwing
#       launch-config validation
#   M   replayable authenticated requests grew the audit stores unboundedly
#       (app-side; pytest covers it)

Describe 'Get-CanonicalPathString / Get-PathRelation (round 5: aliases)' {
    It 'refuses dot-segment aliases rather than trying to normalize them' {
        { Get-PathRelation -A 'C:\Program Files\acme-adcs-ra\current\..\..\acme-adcs-ra' -B 'C:\Program Files\acme-adcs-ra' } |
            Should -Throw '*ambiguous Win32 component*'
    }

    It 'refuses forward-slash spellings while case noise still normalises' {
        { Get-PathRelation -A 'c:/program files/acme-adcs-ra' -B 'C:\Program Files\ACME-ADCS-RA\' } |
            Should -Throw '*absolute local drive paths*'
        Get-PathRelation -A 'c:\program files\acme-adcs-ra' -B 'C:\Program Files\ACME-ADCS-RA\' |
            Should -Be 'equal'
    }

    It 'refuses trailing-dot and trailing-space Win32 aliases' {
        { Get-PathRelation -A 'C:\ProgramData\acme-ra' -B 'C:\ProgramData\acme-ra.' } |
            Should -Throw '*ambiguous Win32 component*'
        { Get-PathRelation -A 'C:\ProgramData\acme-ra' -B 'C:\ProgramData\acme-ra ' } |
            Should -Throw '*ambiguous Win32 component*'
    }

    It 'refuses UNC, device, ADS, and reserved-device paths' {
        { Get-PathRelation -A '\\server\share\dir' -B 'C:\safe\dir' } | Should -Throw '*absolute local drive paths*'
        { Get-PathRelation -A 'C:\safe:stream' -B 'C:\other' } | Should -Throw '*ambiguous Win32 component*'
        { Get-PathRelation -A 'C:\NUL\dir' -B 'C:\other' } | Should -Throw '*reserved device name*'
    }

    It 'genuinely disjoint roots stay disjoint (no false positives)' {
        Get-PathRelation -A 'C:\Program Files\acme-adcs-ra' -B 'C:\ProgramData\acme-adcs-ra' |
            Should -Be 'disjoint'
    }

    It 'junction aliases resolve through the kernel (Windows only)' -Skip:($env:OS -ne 'Windows_NT') {
        $base = Join-Path ([IO.Path]::GetTempPath()) ("ra-junction-" + [guid]::NewGuid().ToString('N'))
        $real = Join-Path $base 'real'
        $link = Join-Path $base 'link'
        New-Item -ItemType Directory -Force -Path $real | Out-Null
        $null = & cmd.exe /c "mklink /J `"$link`" `"$real`" 2>&1"
        if (-not (Test-Path $link)) { Set-ItResult -Skipped -Because 'junction creation unavailable'; return }
        try {
            Get-PathRelation -A "$link\venv" -B "$real\venv" | Should -Be 'equal'
            Get-PathRelation -A "$link\state" -B "$real" | Should -Be 'a-inside-b'
        } finally {
            & cmd.exe /c "rmdir `"$link`" 2>&1" | Out-Null
            Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Test-AceEndangersBytes (round 5: the interpreter chain rule)' {
    BeforeAll {
        # FileSystemRights / InheritanceFlags enum values are plain ints on
        # every platform, so the matrix runs on Linux too.
        $WD = [int][System.Security.AccessControl.FileSystemRights]::WriteData
        $AD = [int][System.Security.AccessControl.FileSystemRights]::AppendData
        $RX = [int][System.Security.AccessControl.FileSystemRights]::ReadAndExecute
        $FC = [int][System.Security.AccessControl.FileSystemRights]::FullControl
        $OI = [int][System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $IO = [int][System.Security.AccessControl.PropagationFlags]::InheritOnly
    }

    It 'the live C:\ pattern: Users (CI)(IO) CreateFiles must NOT flag (it does not apply to this object)' {
        # Live-probed: C:\ carries exactly this ACE. It grants nothing on C:\
        # itself; where it lands (a freshly created first-level directory shows
        # an APPLICABLE Users CreateFiles), the chain walk flags the child.
        Test-AceEndangersBytes -Identity 'BUILTIN\Users' -Rights $WD -AceType 'Allow' -InheritanceFlags ([int][System.Security.AccessControl.InheritanceFlags]::ContainerInherit) -PropagationFlags $IO -IsDirectory $true |
            Should -BeFalse
    }

    It 'the live ProgramData pattern: applicable (non-IO) Users Write MUST flag' {
        # rights=278 (0x116, the 'Write' composite), inh=ContainerInherit, prop=None
        Test-AceEndangersBytes -Identity 'BUILTIN\Users' -Rights 278 -AceType 'Allow' -InheritanceFlags ([int][System.Security.AccessControl.InheritanceFlags]::ContainerInherit) -PropagationFlags 0 -IsDirectory $true |
            Should -BeTrue
    }

    It 'raw generic bits: GenericRead and GenericExecute must NOT flag; GenericWrite and GenericAll MUST' {
        # Found live: the first version of the mask carried 0x80000000 as
        # "GenericAll" -- it is GenericRead -- and rejected every %ProgramFiles%
        # Users GR,GE ACE as write-class, blocking the whole install.
        Test-AceEndangersBytes -Identity 'BUILTIN\Users' -Rights 0xA0000000 -AceType 'Allow' -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 |
            Should -BeFalse     # GenericRead|GenericExecute (the Program Files pattern)
        Test-AceEndangersBytes -Identity 'BUILTIN\Users' -Rights 0x40000000 -AceType 'Allow' -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 |
            Should -BeTrue      # GenericWrite
        Test-AceEndangersBytes -Identity 'BUILTIN\Users' -Rights 0x10000000 -AceType 'Allow' -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 |
            Should -BeTrue      # GenericAll
    }

    It 'flags Users CreateFiles on a directory (the ProgramData pattern)' {
        Test-AceEndangersBytes -Identity 'BUILTIN\Users' -Rights $WD -AceType 'Allow' -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 |
            Should -BeTrue
    }

    It 'does NOT flag Users RX (Program Files pattern) or the C:\ create-subdir-only ACE' {
        Test-AceEndangersBytes -Identity 'BUILTIN\Users' -Rights $RX -AceType 'Allow' -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 |
            Should -BeFalse
        # C:\ grants Users AppendData (create subdirectory) non-object-inherit:
        # that cannot replace bytes.
        Test-AceEndangersBytes -Identity 'BUILTIN\Users' -Rights $AD -AceType 'Allow' -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 |
            Should -BeFalse
    }

    It 'flags object-inherit AppendData (byte-append lands on files)' {
        Test-AceEndangersBytes -Identity 'S-1-5-32-545' -Rights $AD -AceType 'Allow' -InheritanceFlags $OI -IsDirectory $true -PropagationFlags 0 |
            Should -BeTrue
    }

    It 'flags Everyone Modify/FullControl and deny-style supersets, ignores deny ACEs and admin trustees' {
        Test-AceEndangersBytes -Identity 'Everyone' -Rights $FC -AceType 'Allow' -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 |
            Should -BeTrue
        Test-AceEndangersBytes -Identity 'Everyone' -Rights $FC -AceType 'Deny' -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 |
            Should -BeFalse
        Test-AceEndangersBytes -Identity 'BUILTIN\Administrators' -Rights $FC -AceType 'Allow' -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 |
            Should -BeFalse
        Test-AceEndangersBytes -Identity 'NT AUTHORITY\Authenticated Users' -Rights $WD -AceType 'Allow' -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 |
            Should -BeTrue
    }

    It 'THE FINDING: flags arbitrary named users and groups with write access' {
        Test-AceEndangersBytes -Identity 'WORK-DOMAIN\LowPrivUser' -Rights $FC `
            -AceType 'Allow' -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 |
            Should -BeTrue
        Test-AceEndangersBytes -Identity 'WORK-DOMAIN\DelegatedOperators' -Rights $WD `
            -AceType 'Allow' -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 |
            Should -BeTrue
    }

    It 'allows a write ACE only when its resolved SID is explicitly authorized' {
        $sid = 'S-1-5-21-99-88-77-1104'
        Test-AceEndangersBytes -Identity $sid -Rights $FC -AceType 'Allow' `
            -InheritanceFlags 0 -IsDirectory $true -PropagationFlags 0 `
            -AllowedWriterSids @($sid) | Should -BeFalse
    }

    It 'on a FILE, byte-append (AppendData) is dangerous regardless of inheritance' {
        Test-AceEndangersBytes -Identity 'Everyone' -Rights $AD -AceType 'Allow' -InheritanceFlags 0 -IsDirectory $false -PropagationFlags 0 |
            Should -BeTrue
    }
}

Describe 'Assert-WebConfigLaunchTrusted (round 5: launch config fails closed)' {
    BeforeAll {
        $script:dir = New-Item -ItemType Directory -Force -Path (Join-Path ([IO.Path]::GetTempPath()) ("ra-wcval-" + [guid]::NewGuid().ToString('N')))
        $script:good = @'
<?xml version="1.0" encoding="utf-8"?>
<configuration><system.webServer>
  <httpPlatform processPath="C:\Program Files\acme-adcs-ra\current\venv\Scripts\python.exe" arguments="-m acme_adcs_ra" />
</system.webServer></configuration>
'@
        $script:inState = $script:good.Replace(
            'C:\Program Files\acme-adcs-ra\current\venv\Scripts\python.exe',
            'C:\ProgramData\acme-adcs-ra\venv\Scripts\python.exe')
        $script:elsewhere = $script:good.Replace(
            'C:\Program Files\acme-adcs-ra\current\venv\Scripts\python.exe',
            'C:\Tools\ra-launcher.exe')
        $script:broken = '<configuration><system.webServer><httpPlatform processPath="C:\x'
        Set-Content (Join-Path $script:dir 'good.xml') $script:good
        Set-Content (Join-Path $script:dir 'state.xml') $script:inState
        Set-Content (Join-Path $script:dir 'else.xml') $script:elsewhere
        Set-Content (Join-Path $script:dir 'broken.xml') $script:broken
    }
    AfterAll { Remove-Item -LiteralPath $script:dir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'accepts a processPath inside the runtime tree' {
        { Assert-WebConfigLaunchTrusted -WebConfigPath (Join-Path $script:dir 'good.xml') `
            -InstallDir 'C:\ProgramData\acme-adcs-ra' -RuntimeDir 'C:\Program Files\acme-adcs-ra' `
            -ExpectedProcessPath 'C:\Program Files\acme-adcs-ra\current\venv\Scripts\python.exe' } |
            Should -Not -Throw
    }

    It 'REFUSES a processPath inside the state tree (gMSA-writable interpreter)' {
        { Assert-WebConfigLaunchTrusted -WebConfigPath (Join-Path $script:dir 'state.xml') `
            -InstallDir 'C:\ProgramData\acme-adcs-ra' -RuntimeDir 'C:\Program Files\acme-adcs-ra' `
            -ExpectedProcessPath 'x' } | Should -Throw '*INSIDE the state tree*'
    }

    It 'REFUSES a processPath outside the runtime tree entirely' {
        { Assert-WebConfigLaunchTrusted -WebConfigPath (Join-Path $script:dir 'else.xml') `
            -InstallDir 'C:\ProgramData\acme-adcs-ra' -RuntimeDir 'C:\Program Files\acme-adcs-ra' `
            -ExpectedProcessPath 'x' } | Should -Throw '*OUTSIDE the runtime tree*'
    }

    It 'REFUSES unparseable XML (the old code swallowed this)' {
        { Assert-WebConfigLaunchTrusted -WebConfigPath (Join-Path $script:dir 'broken.xml') `
            -InstallDir 'C:\ProgramData\acme-adcs-ra' -RuntimeDir 'C:\Program Files\acme-adcs-ra' `
            -ExpectedProcessPath 'x' } | Should -Throw '*not parseable XML*'
    }
}

Describe 'install-windows.ps1: round-5 fixes' {
    BeforeAll {
        $script:installer = Get-Content -Raw "$PSScriptRoot/../../scripts/install-windows.ps1"
    }

    It 'H: a fresh root is created with the protected DACL atomically and SKIPS reset' {
        $absent = $script:installer.IndexOf("'absent' {")
        $branch = $script:installer.Substring($absent, [Math]::Min(2600, $script:installer.Length - $absent))
        $branch | Should -Match 'New-AtomicProtectedDirectory -Path \$Path -Grants \$Grants'
        $freshSkip = $script:installer.IndexOf('if (-not $fresh)')
        $reset = $script:installer.IndexOf('Reset-TreeToInherited -Path $Path')
        $freshSkip | Should -BeGreaterThan 0
        $reset | Should -BeGreaterThan $freshSkip
    }

    It 'H: CreateDirectoryW receives the security descriptor in the creation call' {
        $lib = Get-Content -Raw "$PSScriptRoot/../../scripts/lib/InstallVerifyLib.ps1"
        $lib | Should -Match 'CreateDirectoryW\(string path, ref SECURITY_ATTRIBUTES attributes\)'
        $lib | Should -Match 'lpSecurityDescriptor = pinned\.AddrOfPinnedObject\(\)'
        $lib | Should -Match '\[ACMERA\.AtomicDirectory\]::Create'
        $fn = $lib.IndexOf('function New-AtomicProtectedDirectory')
        $body = $lib.Substring($fn, [Math]::Min(5000, $lib.Length - $fn))
        $body | Should -Not -Match '/reset'
    }

    It 'M: interpreter candidates are chain-gated BEFORE the first probe executes them' {
        $gate = $script:installer.IndexOf('Test-PathChainTrusted -Path $chainProbePath')
        $probe = $script:installer.IndexOf('Invoke-PyProbe -Exe $l.Exe -Arguments ($l.Args + @("--version"))')
        $gate | Should -BeGreaterThan 0
        $probe | Should -BeGreaterThan $gate
        # ...and the self-resolved interpreter gets its own gate before adoption
        $selfGate = $script:installer.IndexOf('Test-PathChainTrusted -Path $resolved')
        $selfGate | Should -BeGreaterThan 0
    }

    It 'M: SitePath is disjointness-checked against BOTH managed roots' {
        @([regex]::Matches($script:installer, 'Get-PathRelation -A \$SitePath')).Count | Should -Be 4
        $postRuntime = $script:installer.IndexOf("throw 'Site and runtime roots resolve")
        $postState = $script:installer.IndexOf("throw 'Site and state roots resolve")
        $runtimeCreate = $script:installer.IndexOf('Initialize-SecuredRoot -Path $RuntimeDir')
        $stateCreate = $script:installer.IndexOf('Initialize-SecuredRoot -Path $InstallDir')
        $postRuntime | Should -BeGreaterThan $runtimeCreate
        $postRuntime | Should -BeLessThan $stateCreate
        $postState | Should -BeGreaterThan $stateCreate
    }

    It 'M: -ConfigureIIS proves a pre-existing site tree (reparse + per-object DACL) or refuses' {
        $script:installer | Should -Match 'Find-ReparsePoints -Path \$SitePath'
        $script:installer | Should -Match 'Test-ObjectDaclTrusted -Path \$obj\.FullName'
        $script:installer | Should -Not -Match 'AlsoFlagTrustees'
        $script:installer | Should -Match 'is not administrator-only'
    }

    It 'M: a fresh SitePath is locked at creation like the managed roots' {
        $script:installer | Should -Match 'New-AtomicProtectedDirectory -Path \$SitePath -Grants \$siteGrants'
    }

    It 'M: the post-install web.config check is a THROW on every run, not a warning' {
        $script:installer | Should -Match 'Assert-WebConfigLaunchTrusted -WebConfigPath \$siteWcPath'
        # the old warning-only text is gone
        $script:installer | Should -Not -Match '\[!!\] .*INSIDE the state tree'
    }

    It 'validates repository inputs before dot-sourcing and builds only from the protected snapshot' {
        $gate = $script:installer.IndexOf('Assert-BootstrapTreeTrusted -Path $inputPath')
        $dotSource = $script:installer.IndexOf('. "$PSScriptRoot/lib/InstallVerifyLib.ps1"')
        $copy = $script:installer.IndexOf("Copy-Item -LiteralPath (Join-Path `$repoRoot 'src')")
        $build = $script:installer.IndexOf('pip install --no-deps --no-build-isolation --upgrade $sourceSnapshot')
        $gate | Should -BeGreaterThan 0
        $dotSource | Should -BeGreaterThan $gate
        $copy | Should -BeGreaterThan $dotSource
        $build | Should -BeGreaterThan $copy
        $script:installer | Should -Not -Match 'pip install --no-deps --no-build-isolation --upgrade \$repoRoot'
    }

    It 'does not execute PATH-selected Python or winget in -InstallPrereqs' {
        $start = $script:installer.IndexOf('function Install-Prerequisites')
        $end = $script:installer.IndexOf('# --- Stop the worker', $start)
        $body = $script:installer.Substring($start, $end - $start)
        $body | Should -Not -Match '&\s+(py|python|python3|winget)\b'
        $body | Should -Not -Match 'cmd\s+/c.*(py|python)'
        $body | Should -Match 'Python is not auto-installed'
    }

    It 'stages, hashes, and executes the MSI only under protected installer scratch' {
        $stage = $script:installer.IndexOf("`$msi = Join-Path `$installerScratch")
        $hash = $script:installer.IndexOf('Get-FileHash -Algorithm SHA256 -Path $msi')
        $exec = $script:installer.IndexOf('Start-Process $msiexec')
        $stage | Should -BeGreaterThan 0
        $hash | Should -BeGreaterThan $stage
        $exec | Should -BeGreaterThan $hash
        $script:installer | Should -Match "Join-Path \`$env:windir 'System32\\msiexec\.exe'"
        $script:installer | Should -Not -Match 'Start-Process msiexec\.exe'
    }
}
