BeforeAll {
    . "$PSScriptRoot/../../scripts/lib/OfficerRightsLib.ps1"
}

Describe 'Convert-SidToBinary' {
    It 'S-1-1-0 (Everyone) produces 12 bytes starting with revision 1, sub-authority count 1' {
        $bytes = Convert-SidToBinary 'S-1-1-0'
        $bytes.Length | Should -Be 12
        $bytes[0] | Should -Be 1
        $bytes[1] | Should -Be 1
    }

    It 'S-1-5-32-544 (BUILTIN\Administrators) produces the correct binary' {
        $bytes = Convert-SidToBinary 'S-1-5-32-544'
        $hex = Convert-BytesToHex $bytes
        $hex | Should -Be '01020000000000052000000020020000'
    }
}

Describe 'Convert-BytesToHex' {
    It '@(0x01, 0x0A, 0xFF) produces "010aff"' {
        $result = Convert-BytesToHex @([byte]0x01, [byte]0x0A, [byte]0xFF)
        $result | Should -Be '010aff'
    }

    It 'Empty array produces ""' {
        $result = Convert-BytesToHex @()
        $result | Should -Be ''
    }
}

Describe 'Build-CallbackAce' {
    BeforeAll {
        $script:officerSid = 'S-1-5-21-1004336348-1177238915-682003330-517'
        $script:templateOid = '1.3.6.1.4.1.311.21.8.16593888.12298824.5193888.14804498.16898264.10598498.10498398'
        $script:ace = Build-CallbackAce $script:officerSid $script:templateOid
    }

    It 'Starts with byte 9 (AceType = ACCESS_ALLOWED_CALLBACK)' {
        $script:ace[0] | Should -Be 9
    }

    It 'Byte[1] is 0 (AceFlags)' {
        $script:ace[1] | Should -Be 0
    }

    It 'AccessMask at offset 4 is 0x00010000 (little-endian: 00 00 01 00)' {
        $script:ace[4] | Should -Be 0x00
        $script:ace[5] | Should -Be 0x00
        $script:ace[6] | Should -Be 0x01
        $script:ace[7] | Should -Be 0x00
    }

    It 'ACE size field (bytes 2-3, uint16 LE) equals the total array length' {
        $aceSize = [BitConverter]::ToUInt16($script:ace, 2)
        $aceSize | Should -Be $script:ace.Length
    }

    It 'Trustee SID in the ACE matches the officer SID' {
        $sidStr = Convert-BinaryToSidString $script:ace 8
        $sidStr | Should -Be $script:officerSid
    }

    It 'Opaque ApplicationData contains SidCount=1 (first 4 bytes = 01 00 00 00)' {
        $officerSidBytes = Convert-SidToBinary $script:officerSid
        $appDataOffset = 8 + $officerSidBytes.Length
        $script:ace[$appDataOffset] | Should -Be 1
        $script:ace[$appDataOffset + 1] | Should -Be 0
        $script:ace[$appDataOffset + 2] | Should -Be 0
        $script:ace[$appDataOffset + 3] | Should -Be 0
    }

    It 'Everyone SID (S-1-1-0) appears in the app data after SidCount' {
        $officerSidBytes = Convert-SidToBinary $script:officerSid
        $everyoneSidBytes = Convert-SidToBinary 'S-1-1-0'
        $appDataOffset = 8 + $officerSidBytes.Length + 4
        $everyoneInAce = Convert-BinaryToSidString $script:ace $appDataOffset
        $everyoneInAce | Should -Be 'S-1-1-0'
    }

    It 'Template OID appears as UTF-16LE followed by a 2-byte null terminator' {
        $officerSidBytes = Convert-SidToBinary $script:officerSid
        $everyoneSidBytes = Convert-SidToBinary 'S-1-1-0'
        $oidOffset = 8 + $officerSidBytes.Length + 4 + $everyoneSidBytes.Length
        $oidBytes = [System.Text.Encoding]::Unicode.GetBytes($script:templateOid)
        $expectedLen = $oidBytes.Length + 2
        $actualOid = [System.Text.Encoding]::Unicode.GetString($script:ace, $oidOffset, $oidBytes.Length)
        $actualOid | Should -Be $script:templateOid
        $script:ace[$oidOffset + $oidBytes.Length] | Should -Be 0
        $script:ace[$oidOffset + $oidBytes.Length + 1] | Should -Be 0
    }

    It 'Round-trip: Build-OfficerRightsSD then Get-ExistingAces recovers the officer SID' {
        $aceList = [System.Collections.Generic.List[byte[]]]::new()
        $aceList.Add($script:ace)
        $sd = Build-OfficerRightsSD $aceList
        $parsed = Get-ExistingAces $sd
        $parsed.Count | Should -Be 1
        $parsed[0].OfficerSid | Should -Be $script:officerSid
    }
}

Describe 'Build-OfficerRightsSD' {
    BeforeAll {
        $script:officerSid = 'S-1-5-21-1004336348-1177238915-682003330-517'
        $script:templateOid = '1.3.6.1.4.1.311.21.8.16593888.12298824.5193888.14804498.16898264.10598498.10498398'
    }

    Context 'Single ACE' {
        BeforeAll {
            $ace = Build-CallbackAce $script:officerSid $script:templateOid
            $aceList = [System.Collections.Generic.List[byte[]]]::new()
            $aceList.Add($ace)
            $script:sd = Build-OfficerRightsSD $aceList
        }

        It 'SD starts with revision 1' {
            $script:sd[0] | Should -Be 1
        }

        It 'Control is 0x8004 (bytes 2-3 LE = 04 80)' {
            $script:sd[2] | Should -Be 0x04
            $script:sd[3] | Should -Be 0x80
        }

        It 'Owner offset is 20 (bytes 4-7 LE)' {
            $ownerOffset = [BitConverter]::ToUInt32($script:sd, 4)
            $ownerOffset | Should -Be 20
        }

        It 'Owner SID at offset 20 is S-1-5-32-544' {
            $ownerSid = Convert-BinaryToSidString $script:sd 20
            $ownerSid | Should -Be 'S-1-5-32-544'
        }

        It 'DACL offset (bytes 16-19 LE) points to a valid ACL with revision 2' {
            $daclOffset = [BitConverter]::ToUInt32($script:sd, 16)
            $script:sd[$daclOffset] | Should -Be 2
        }

        It 'AceCount in the ACL header matches the number of ACEs passed' {
            $daclOffset = [BitConverter]::ToUInt32($script:sd, 16)
            $aceCount = [BitConverter]::ToUInt16($script:sd, $daclOffset + 4)
            $aceCount | Should -Be 1
        }
    }

    Context 'Two ACEs' {
        BeforeAll {
            $ace1 = Build-CallbackAce $script:officerSid $script:templateOid
            $ace2 = Build-CallbackAce 'S-1-5-21-1004336348-1177238915-682003330-518' $script:templateOid
            $aceList = [System.Collections.Generic.List[byte[]]]::new()
            $aceList.Add($ace1)
            $aceList.Add($ace2)
            $script:sd2 = Build-OfficerRightsSD $aceList
        }

        It 'AceCount = 2' {
            $daclOffset = [BitConverter]::ToUInt32($script:sd2, 16)
            $aceCount = [BitConverter]::ToUInt16($script:sd2, $daclOffset + 4)
            $aceCount | Should -Be 2
        }

        It 'Both trustee SIDs are recoverable via Get-ExistingAces' {
            $parsed = Get-ExistingAces $script:sd2
            $parsed.Count | Should -Be 2
            $parsed[0].OfficerSid | Should -Be 'S-1-5-21-1004336348-1177238915-682003330-517'
            $parsed[1].OfficerSid | Should -Be 'S-1-5-21-1004336348-1177238915-682003330-518'
        }
    }
}

Describe 'Get-ExistingAces' {
    # Regression, found live on the CA 2026-08-13, corrected 2026-08-14.
    # PowerShell unwraps a single-element array as it crosses a function
    # boundary, and the resulting bare [pscustomobject] has NO .Count under
    # Windows PowerShell 5.1 (pwsh 7 yields 1, which is why this suite was
    # green while Set-OfficerRights.ps1 aborted on a *successful*
    # single-officer provisioning). The contract that fixes that is at the CALL
    # SITE -- `@(Get-ExistingAces $bytes)` -- so that is what these assert.
    # Asserting the bare return type instead is what let the empty-case
    # phantom entry ship; see the two count tests below.
    It 'Is an array at the call site, even for a single ACE (PS 5.1 .Count trap)' {
        $ace = Build-CallbackAce 'S-1-5-21-1004336348-1177238915-682003330-517' '1.3.6.1.4.1.311.21.8.16593888.12298824.5193888.14804498.16898264.10598498.10498398'
        $aceList = [System.Collections.Generic.List[byte[]]]::new()
        $aceList.Add($ace)
        $result = @(Get-ExistingAces (Build-OfficerRightsSD $aceList))
        $result -is [array] | Should -BeTrue
    }

    It 'Is an array at the call site when there are no ACEs to report' {
        @(Get-ExistingAces $null) -is [array] | Should -BeTrue
        @(Get-ExistingAces ([byte[]]@(1, 2, 3, 4, 5))) -is [array] | Should -BeTrue
    }

    It 'Returns empty array for $null input' {
        $result = Get-ExistingAces $null
        $result.Count | Should -Be 0
    }

    It 'Returns empty array for a byte array shorter than 20 bytes' {
        $result = Get-ExistingAces ([byte[]]@(1, 2, 3, 4, 5))
        $result.Count | Should -Be 0
    }

    # The two tests above assign the result; the SHIPPED call sites wrap it in
    # @(), and that is a different expression. Assignment collapses a
    # single-item pipeline back to the item, so `,@()` looked empty here while
    # `@(Get-ExistingAces $null)` was a 1-element array holding an empty array.
    # Set-OfficerRights.ps1 then treated a pristine CA (OfficerRights absent --
    # the default, so this is the FIRST-provisioning path) as having one
    # existing ACE, carried it into the builder with a $null RawAce, and died
    # on "Buffer cannot be null" having written nothing. Found on the CA
    # 2026-08-14. Assert the call-site expression, not a convenient one.
    It 'Counts zero through the @() the call sites use (no phantom entry)' {
        @(Get-ExistingAces $null).Count | Should -Be 0
        @(Get-ExistingAces ([byte[]]@(1, 2, 3, 4, 5))).Count | Should -Be 0
    }

    It 'Counts one through the @() the call sites use' {
        $ace = Build-CallbackAce 'S-1-5-21-1004336348-1177238915-682003330-517' '1.3.6.1.4.1.311.21.8.16593888.12298824.5193888.14804498.16898264.10598498.10498398'
        $aceList = [System.Collections.Generic.List[byte[]]]::new()
        $aceList.Add($ace)
        $wrapped = @(Get-ExistingAces (Build-OfficerRightsSD $aceList))
        $wrapped.Count | Should -Be 1
        # Not just the count: the element must be the ACE record itself, not an
        # array holding it, or `[byte[]]$a.RawAce` flattens via member
        # enumeration and the rebuilt blob is corrupt.
        $wrapped[0].OfficerSid | Should -BeOfType [string]
        $wrapped[0].RawAce | Should -Not -BeNullOrEmpty
    }

    It 'Correctly parses a well-formed SD' {
        $ace = Build-CallbackAce 'S-1-5-21-1004336348-1177238915-682003330-517' '1.3.6.1.4.1.311.21.8.16593888.12298824.5193888.14804498.16898264.10598498.10498398'
        $aceList = [System.Collections.Generic.List[byte[]]]::new()
        $aceList.Add($ace)
        $sd = Build-OfficerRightsSD $aceList
        $result = Get-ExistingAces $sd
        $result.Count | Should -Be 1
        $result[0].OfficerSid | Should -Be 'S-1-5-21-1004336348-1177238915-682003330-517'
    }

    It 'Throws on corrupt ACE (size field < 8)' {
        $ace = Build-CallbackAce 'S-1-5-21-1004336348-1177238915-682003330-517' '1.3.6.1.4.1.311.21.8.16593888.12298824.5193888.14804498.16898264.10598498.10498398'
        $aceList = [System.Collections.Generic.List[byte[]]]::new()
        $aceList.Add($ace)
        $sd = Build-OfficerRightsSD $aceList
        $daclOffset = [BitConverter]::ToUInt32($sd, 16)
        $aceStart = $daclOffset + 8
        $sd[$aceStart + 2] = 4
        $sd[$aceStart + 3] = 0
        { Get-ExistingAces $sd } | Should -Throw '*size*less than minimum*'
    }
}
