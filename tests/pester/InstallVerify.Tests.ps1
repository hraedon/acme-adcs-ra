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

# --- Daybreak 2026-08-15 rescan F1: destination bytes must authenticate ---------
#
# "We ACL'd the tree" bounds future writes; it says nothing about the bytes
# already in it. The shared interpreter is therefore only executable when its
# whole tree matches a manifest the gMSA cannot rewrite. These round-trip the
# manifest machinery on Linux (Get-FileHash is cross-platform) against the
# exact attacker shapes: tampered file, planted file, deleted file, corrupt or
# missing manifest.

Describe 'Tree manifest (shared-Python authentication)' {
    BeforeAll {
        $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ("mfst-test-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $script:root | Out-Null
        $script:manifest = Join-Path $script:root "manifest.json"
        # The manifest lives OUTSIDE the tree it vouches for in production
        # (python.manifest.json is a sibling of python\), mirror that here.
        $script:tree = Join-Path $script:root "python"
        New-Item -ItemType Directory -Force -Path (Join-Path $script:tree "Scripts") | Out-Null
        Set-Content -Path (Join-Path $script:tree "python.exe") -Value "PE-exe-bytes"
        Set-Content -Path (Join-Path $script:tree "python313.dll") -Value "PE-dll-bytes"
        Set-Content -Path (Join-Path $script:tree "Scripts\pip.exe") -Value "PE-pip-bytes"
    }
    AfterAll {
        Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'Save-TreeManifest covers every file, recursively' {
        $script:n = Save-TreeManifest -Root $script:tree -ManifestPath $script:manifest
        $script:n | Should -Be 3
    }

    It 'an untouched tree verifies' {
        $r = Test-TreeManifestMatches -Root $script:tree -ManifestPath $script:manifest
        $r.Ok | Should -BeTrue
    }

    It 'a tampered python.exe fails verification (the planted-interpreter case)' {
        Set-Content -Path (Join-Path $script:tree "python.exe") -Value "evil-replacement"
        $r = Test-TreeManifestMatches -Root $script:tree -ManifestPath $script:manifest
        $r.Ok | Should -BeFalse
        ($r.Details -join ' ') | Should -Match 'hash mismatch: python\.exe'
        # restore
        Set-Content -Path (Join-Path $script:tree "python.exe") -Value "PE-exe-bytes"
    }

    It 'a planted extra file fails verification (set equality, not subset)' {
        Set-Content -Path (Join-Path $script:tree "sitecustomize.py") -Value "import os; os.system('...')"
        $r = Test-TreeManifestMatches -Root $script:tree -ManifestPath $script:manifest
        $r.Ok | Should -BeFalse
        ($r.Details -join ' ') | Should -Match 'unmanifested file in tree: sitecustomize\.py'
        Remove-Item -LiteralPath (Join-Path $script:tree "sitecustomize.py") -Force
    }

    It 'a deleted manifested file fails verification' {
        Remove-Item -LiteralPath (Join-Path $script:tree "Scripts\pip.exe") -Force
        $r = Test-TreeManifestMatches -Root $script:tree -ManifestPath $script:manifest
        $r.Ok | Should -BeFalse
        ($r.Details -join ' ') | Should -Match 'manifest entry missing from tree: Scripts/pip\.exe'
        Set-Content -Path (Join-Path $script:tree "Scripts\pip.exe") -Value "PE-pip-bytes"
    }

    It 'a corrupt manifest fails closed, not open' {
        Set-Content -LiteralPath $script:manifest -Value '{not json'
        $r = Test-TreeManifestMatches -Root $script:tree -ManifestPath $script:manifest
        $r.Ok | Should -BeFalse
        $r.Reason | Should -Match 'unreadable'
    }

    It 'a missing manifest fails closed (pre-fix trees carry no manifest)' {
        Remove-Item -LiteralPath $script:manifest -Force
        $r = Test-TreeManifestMatches -Root $script:tree -ManifestPath $script:manifest
        $r.Ok | Should -BeFalse
        $r.Reason | Should -Match 'missing'
    }
}

# --- Daybreak 2026-08-15 rescan F1/F2: the installer must USE the new controls --
#
# Text/AST level (Linux CI cannot run takeown/icacls; the live install run is
# separately owed and recorded). The properties pinned here are the ones the
# findings were about: no unverified destination-local interpreter may enter
# the launcher list; the venv cannot survive a run; every recursive privileged
# operation is preceded by the reparse walk; icacls never follows a link.

Describe 'install-windows.ps1 authenticates destination bytes (rescan)' {
    BeforeAll {
        $script:installer = Get-Content -Raw "$PSScriptRoot/../../scripts/install-windows.ps1"
        $script:lib = Get-Content -Raw "$PSScriptRoot/../../scripts/lib/InstallVerifyLib.ps1"
    }

    It 'the shared-python launcher candidate is gated on ANCHORED manifest verification' {
        # Test-TreeManifestAuthentic, not Test-TreeManifestMatches: the second
        # rescan's F1 is that a manifest inside the namespace it describes
        # authenticates nothing on its own.
        $script:installer | Should -Match 'Test-TreeManifestAuthentic -Root \(Split-Path \$sharedCandidate\)'
        $script:installer | Should -Not -Match 'Test-TreeManifestMatches -Root \(Split-Path \$sharedCandidate\)'
        # The gate must come BEFORE the candidate is added to $launchers.
        $iGate = $script:installer.IndexOf('Test-TreeManifestAuthentic -Root (Split-Path $sharedCandidate)')
        $iAdd  = $script:installer.IndexOf('$launchers += @{ Exe = $sharedCandidate')
        $iGate | Should -BeGreaterThan -1
        $iAdd  | Should -BeGreaterThan $iGate
    }

    It 'no manifest check anywhere in the installer skips the out-of-tree anchor' {
        @([regex]::Matches($script:installer, 'Test-TreeManifestMatches')).Count | Should -Be 0
        @([regex]::Matches($script:installer, 'Test-TreeManifestAuthentic')).Count | Should -Be 2
        @([regex]::Matches($script:installer, '-AnchorDigest \$pyAnchor')).Count | Should -Be 2
    }

    It 'the anchor is read before any destination interpreter is trusted' {
        $iRead = $script:installer.IndexOf('$pyAnchor = Get-TreeManifestAnchor -InstallDir $InstallDir')
        $iUse  = $script:installer.IndexOf('Test-TreeManifestAuthentic -Root (Split-Path $sharedCandidate)')
        $iRead | Should -BeGreaterThan -1
        $iUse  | Should -BeGreaterThan $iRead
    }

    It 'an unverified shared-python tree is removed, not skipped' {
        $script:installer | Should -Match 'unverified shared-python removal'
    }

    It 'the venv is deleted before recreation every run' {
        $iDel = $script:installer.IndexOf('Remove-Item -LiteralPath $venv -Recurse -Force')
        $iNew = $script:installer.IndexOf('-m", "venv", $venv')
        $iDel | Should -BeGreaterThan -1
        $iNew | Should -BeGreaterThan $iDel
    }

    It 'the manifest is written, DACL-protected AND anchored at build time' {
        $iSave = $script:installer.IndexOf('Save-TreeManifest -Root $sharedPyDir')
        $iProt = $script:installer.IndexOf('Set-ObjectProtectedDacl -Path $pyManifest')
        $iAnch = $script:installer.IndexOf('Set-TreeManifestAnchor -InstallDir $InstallDir')
        $iSave | Should -BeGreaterThan -1
        $iProt | Should -BeGreaterThan $iSave
        $iAnch | Should -BeGreaterThan $iSave
    }

    It 'every recursive reset and the verify are reparse-walked' {
        @([regex]::Matches($script:installer, 'Assert-NoReparsePoints -Path')).Count | Should -BeGreaterOrEqual 4
    }

    It 'no privileged filesystem operation follows a link any more' {
        # takeown has no /L. It was the last link-following privileged step in
        # the claim path (second rescan F2) and must not come back.
        $script:lib      | Should -Not -Match 'takeown\.exe'
        $script:installer| Should -Not -Match 'takeown\.exe'
        # Every icacls invocation in the library carries /L.
        $calls = @([regex]::Matches($script:lib, '&\s+icacls\.exe[^\r\n]*'))
        $calls.Count | Should -BeGreaterOrEqual 5
        foreach ($c in $calls) { $c.Value | Should -Match '\s/L\b' }
    }

    It 'no icacls call uses /c, which skips objects it cannot process' {
        foreach ($c in @([regex]::Matches($script:lib, '&\s+icacls\.exe[^\r\n]*'))) {
            $c.Value | Should -Not -Match '\s/c\b'
        }
    }

    It 'every icacls result is checked with Test-IcaclsOutputClean, not just $LASTEXITCODE' {
        $calls = @([regex]::Matches($script:lib, '&\s+icacls\.exe')).Count
        $checks = @([regex]::Matches($script:lib, 'Test-IcaclsOutputClean -ExitCode \$LASTEXITCODE')).Count
        $checks | Should -Be $calls
    }

    It 'ownership is claimed before the DACL reset, so the reset cannot be denied' {
        $iOwn = $script:lib.IndexOf('/setowner $principal /t /q /L')
        $iRes = $script:lib.IndexOf('$Path /reset /t /q /L')
        $iOwn | Should -BeGreaterThan -1
        $iRes | Should -BeGreaterThan $iOwn
    }

    It 'the app pool is stopped and proven dead BEFORE the install root is claimed' {
        $iStop  = $script:installer.IndexOf('Stop-AppPoolAndWait -AppcmdExe $appcmdExe')
        $iClaim = $script:installer.IndexOf('Reset-TreeToInherited -Path $InstallDir')
        $iHash  = $script:installer.IndexOf('Test-TreeManifestAuthentic -Root (Split-Path $sharedCandidate)')
        $iStop  | Should -BeGreaterThan -1
        $iClaim | Should -BeGreaterThan $iStop
        $iHash  | Should -BeGreaterThan $iStop
        # ... and the old fire-and-forget stop (no worker proof) is gone.
        $script:installer | Should -Not -Match 'stop apppool /apppool\.name:"\$AppPool" 2>\$null \| Out-Null\s*\r?\n\s*Start-Sleep'
    }

    It 'the tree proof checks EVERY owner, not only the root' {
        $script:lib | Should -Match 'Get-TreeOwnerViolations -Root \$Root'
        # The old root-only Get-Acl owner check is gone from Assert-InstallTreeLocked.
        $script:lib | Should -Not -Match '\$acl = Get-Acl -LiteralPath \$Root'
    }

    It 'the walk never descends into a reparse point (manual stack, not -Recurse)' {
        $script:lib | Should -Match 'function Find-ReparsePoints'
        $script:lib | Should -Not -Match 'Get-ChildItem.*-Recurse.*reparse'
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

Describe 'Get-ManifestAnchorValueName (F1)' {
    It 'normalizes case and trailing separators to ONE anchor per install root' {
        $a = Get-ManifestAnchorValueName -InstallDir 'C:\ProgramData\acme-adcs-ra'
        Get-ManifestAnchorValueName -InstallDir 'c:\programdata\acme-adcs-ra\'   | Should -Be $a
        Get-ManifestAnchorValueName -InstallDir '  C:\ProgramData\acme-adcs-ra ' | Should -Be $a
    }

    It 'keeps distinct install roots distinct' {
        (Get-ManifestAnchorValueName -InstallDir 'C:\ProgramData\acme-adcs-ra') |
            Should -Not -Be (Get-ManifestAnchorValueName -InstallDir 'D:\ra')
    }
}

Describe 'Test-TreeManifestAuthentic (F1: the self-authenticating manifest)' {
    BeforeAll {
        $script:aRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("anch-test-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $script:aRoot | Out-Null
        $script:aTree = Join-Path $script:aRoot "python"
        New-Item -ItemType Directory -Force -Path $script:aTree | Out-Null
        Set-Content -Path (Join-Path $script:aTree "python.exe") -Value "genuine-PE-bytes"
        $script:aManifest = Join-Path $script:aRoot "python.manifest.json"
        Save-TreeManifest -Root $script:aTree -ManifestPath $script:aManifest | Out-Null
        $script:aDigest = Get-FileSha256 -Path $script:aManifest
    }
    AfterAll {
        Remove-Item -LiteralPath $script:aRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'accepts a tree whose manifest matches the out-of-tree anchor' {
        $r = Test-TreeManifestAuthentic -Root $script:aTree -ManifestPath $script:aManifest `
                                        -AnchorDigest $script:aDigest
        $r.Ok | Should -BeTrue
    }

    It 'refuses when there is no anchor at all -- the first-install case' {
        foreach ($empty in @('', '   ', $null)) {
            $r = Test-TreeManifestAuthentic -Root $script:aTree -ManifestPath $script:aManifest `
                                            -AnchorDigest $empty
            $r.Ok | Should -BeFalse
            $r.Reason | Should -Match 'no out-of-tree anchor'
        }
    }

    It 'THE FINDING: a preplanted interpreter with its OWN matching manifest is refused' {
        # Exactly the attack: the attacker writes both files, so they agree with
        # each other perfectly. Test-TreeManifestMatches (the old gate) passes.
        Set-Content -Path (Join-Path $script:aTree "python.exe") -Value "attacker-PE-bytes"
        Save-TreeManifest -Root $script:aTree -ManifestPath $script:aManifest | Out-Null
        (Test-TreeManifestMatches -Root $script:aTree -ManifestPath $script:aManifest).Ok |
            Should -BeTrue -Because 'the pair is self-consistent; that was the whole problem'

        $r = Test-TreeManifestAuthentic -Root $script:aTree -ManifestPath $script:aManifest `
                                        -AnchorDigest $script:aDigest
        $r.Ok | Should -BeFalse
        $r.Reason | Should -Match 'does not match its out-of-tree anchor'

        # restore the genuine pair for the tests below
        Set-Content -Path (Join-Path $script:aTree "python.exe") -Value "genuine-PE-bytes"
        Save-TreeManifest -Root $script:aTree -ManifestPath $script:aManifest | Out-Null
        (Get-FileSha256 -Path $script:aManifest) | Should -Be $script:aDigest
    }

    It 'still catches tampered BYTES under an anchored manifest (the gMSA case)' {
        Set-Content -Path (Join-Path $script:aTree "python.exe") -Value "rewritten-by-the-app-pool"
        $r = Test-TreeManifestAuthentic -Root $script:aTree -ManifestPath $script:aManifest `
                                        -AnchorDigest $script:aDigest
        $r.Ok | Should -BeFalse
        ($r.Details -join ' ') | Should -Match 'hash mismatch'
        Set-Content -Path (Join-Path $script:aTree "python.exe") -Value "genuine-PE-bytes"
    }

    It 'refuses a missing manifest even when an anchor exists' {
        $gone = Join-Path $script:aRoot "not-here.json"
        $r = Test-TreeManifestAuthentic -Root $script:aTree -ManifestPath $gone -AnchorDigest $script:aDigest
        $r.Ok | Should -BeFalse
        $r.Reason | Should -Match 'manifest missing'
    }

    It 'refuses a malformed anchor rather than comparing loosely' {
        $r = Test-TreeManifestAuthentic -Root $script:aTree -ManifestPath $script:aManifest `
                                        -AnchorDigest $script:aDigest.Substring(0, 32)
        $r.Ok | Should -BeFalse
    }
}

Describe 'Get-FileSha256' {
    It 'returns empty string (not an error) for a file that is not there' {
        Get-FileSha256 -Path (Join-Path ([System.IO.Path]::GetTempPath()) 'definitely-absent-xyz') |
            Should -Be ''
    }
}
