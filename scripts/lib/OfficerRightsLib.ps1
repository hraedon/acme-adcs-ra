# Dot-sourceable library: SID/byte helpers, ACE/SD builders, and ACE extraction
# for the OfficerRights restriction. Used by Set-OfficerRights.ps1 and the
# Pester tests (tests/pester/OfficerRights.Tests.ps1).

# --- SID / byte helpers ------------------------------------------------------

# Convert a SID string (S-1-5-...) to its binary form.
# Cross-platform: does not use System.Security.Principal.SecurityIdentifier
# (Windows-only). Implements the SID binary format directly:
#   [revision:1][subAuthCount:1][identifierAuthority:6 BE][subAuths:4 LE each]
function Convert-SidToBinary([string]$SidString) {
    $parts = $SidString.Split('-')
    if ($parts[0] -ne 'S' -or $parts.Count -lt 3) {
        throw "Invalid SID string: $SidString"
    }
    $revision = [byte][int]$parts[1]
    $subAuthCount = $parts.Count - 3
    $iaStr = $parts[2]
    $ia = if ($iaStr.StartsWith('0x')) { [uint64]::Parse($iaStr.Substring(2), [System.Globalization.NumberStyles]::HexNumber) } else { [uint64]$iaStr }

    $bytes = [byte[]]::new(8 + 4 * $subAuthCount)
    $bytes[0] = $revision
    $bytes[1] = [byte]$subAuthCount
    $bytes[2] = [byte](($ia -shr 40) -band 0xFF)
    $bytes[3] = [byte](($ia -shr 32) -band 0xFF)
    $bytes[4] = [byte](($ia -shr 24) -band 0xFF)
    $bytes[5] = [byte](($ia -shr 16) -band 0xFF)
    $bytes[6] = [byte](($ia -shr 8) -band 0xFF)
    $bytes[7] = [byte]($ia -band 0xFF)
    for ($i = 0; $i -lt $subAuthCount; $i++) {
        $sa = [uint32]$parts[$i + 3]
        $offset = 8 + 4 * $i
        $bytes[$offset] = [byte]($sa -band 0xFF)
        $bytes[$offset + 1] = [byte](($sa -shr 8) -band 0xFF)
        $bytes[$offset + 2] = [byte](($sa -shr 16) -band 0xFF)
        $bytes[$offset + 3] = [byte](($sa -shr 24) -band 0xFF)
    }
    return $bytes
}

# Convert a binary SID to its string form (S-1-5-...).
# Cross-platform companion to Convert-SidToBinary.
function Convert-BinaryToSidString([byte[]]$Bytes, [int]$Offset) {
    $revision = $Bytes[$Offset]
    $subAuthCount = $Bytes[$Offset + 1]
    $ia = ([uint64]$Bytes[$Offset + 2] -shl 40) -bor ([uint64]$Bytes[$Offset + 3] -shl 32) -bor
          ([uint64]$Bytes[$Offset + 4] -shl 24) -bor ([uint64]$Bytes[$Offset + 5] -shl 16) -bor
          ([uint64]$Bytes[$Offset + 6] -shl 8) -bor [uint64]$Bytes[$Offset + 7]
    $iaStr = if ($ia -ge 0x100000000) { '0x' + $ia.ToString('x12') } else { "$ia" }
    $sb = "S-$revision-$iaStr"
    for ($i = 0; $i -lt $subAuthCount; $i++) {
        $saOffset = $Offset + 8 + 4 * $i
        $sa = [uint32]$Bytes[$saOffset] -bor ([uint32]$Bytes[$saOffset + 1] -shl 8) -bor
              ([uint32]$Bytes[$saOffset + 2] -shl 16) -bor ([uint32]$Bytes[$saOffset + 3] -shl 24)
        $sb += "-$sa"
    }
    return $sb
}

# Get the binary length of a SID starting at the given offset in a byte array.
function Get-SidBinaryLength([byte[]]$Bytes, [int]$Offset) {
    return 8 + 4 * [int]$Bytes[$Offset + 1]
}

# Convert a byte array to a continuous lowercase hex string (for certutil).
function Convert-BytesToHex([byte[]]$Bytes) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $Bytes) { [void]$sb.Append($b.ToString('x2')) }
    return $sb.ToString()
}

# --- ACE / SD builders (the Plan-004 byte recipe) ---------------------------

# Build a single ACCESS_ALLOWED_CALLBACK_ACE.
#   AceType  = 9 (ACCESS_ALLOWED_CALLBACK_ACE_TYPE)
#   Mask     = 0x00010000
#   Trustee  = the officer's SID
#   Opaque   = [SidCount=1 u32 LE][Everyone S-1-1-0][template OID UTF-16LE + null]
function Build-CallbackAce([string]$OfficerSidString, [string]$TemplateOidString) {
    $officerSidBytes = Convert-SidToBinary $OfficerSidString
    $everyoneSidBytes = Convert-SidToBinary "S-1-1-0"

    # Template OID as UTF-16LE + 2-byte null terminator.
    $templateBytes = [System.Text.Encoding]::Unicode.GetBytes($TemplateOidString)
    $nullTerm = [byte[]](0x00, 0x00)

    # ApplicationData (opaque callback blob):
    # [SidCount u32 LE = 1][Everyone SID][template UTF-16LE + null]
    $ms = New-Object System.IO.MemoryStream
    $ms.Write([BitConverter]::GetBytes([uint32]1), 0, 4)          # SidCount = 1 (all subjects)
    $ms.Write($everyoneSidBytes, 0, $everyoneSidBytes.Length)     # Everyone S-1-1-0
    $ms.Write($templateBytes, 0, $templateBytes.Length)            # template OID
    $ms.Write($nullTerm, 0, 2)                                     # UTF-16 null terminator
    $appData = $ms.ToArray()

    # ACE = header(4) + mask(4) + trustee SID + application data
    $aceSize = 4 + 4 + $officerSidBytes.Length + $appData.Length

    $ace = New-Object System.IO.MemoryStream
    $ace.WriteByte([byte]9)                                        # AceType = ACCESS_ALLOWED_CALLBACK
    $ace.WriteByte([byte]0)                                        # AceFlags
    $ace.Write([BitConverter]::GetBytes([uint16]$aceSize), 0, 2)   # AceSize (LE)
    $ace.Write([BitConverter]::GetBytes([uint32]0x00010000), 0, 4)  # AccessMask
    $ace.Write($officerSidBytes, 0, $officerSidBytes.Length)       # Trustee SID
    $ace.Write($appData, 0, $appData.Length)                       # ApplicationData
    return $ace.ToArray()
}

# Build a self-relative SECURITY_DESCRIPTOR with the given ACE byte arrays.
#   Owner   = S-1-5-32-544 (BUILTIN\Administrators) -- mandatory.
#   Control = 0x8004 (SE_SELF_RELATIVE | SE_DACL_PRESENT).
#   DACL    = revision 2, the supplied ACEs.
# AceBytesList is a list/collection of byte[] (one per ACE). Note: no
# [byte[][]] type annotation -- PowerShell's array += flattens nested arrays,
# so callers use [System.Collections.Generic.List[byte[]]] to preserve each
# ACE as a single element.
function Build-OfficerRightsSD($AceBytesList) {
    $ownerSid = Convert-SidToBinary "S-1-5-32-544"

    # Build the ACL (DACL): header(8) + ACEs
    $aclMs = New-Object System.IO.MemoryStream
    $aclMs.WriteByte([byte]2)   # AclRevision = 2
    $aclMs.WriteByte([byte]0)   # Sbz1
    $aclSize = 8
    foreach ($ace in $AceBytesList) { $aclSize += $ace.Length }
    $aclMs.Write([BitConverter]::GetBytes([uint16]$aclSize), 0, 2)         # AclSize
    $aclMs.Write([BitConverter]::GetBytes([uint16]$AceBytesList.Count), 0, 2) # AceCount
    $aclMs.Write([BitConverter]::GetBytes([uint16]0), 0, 2)                 # Sbz2
    foreach ($ace in $AceBytesList) {
        $aclMs.Write($ace, 0, $ace.Length)
    }
    $aclBytes = $aclMs.ToArray()

    # SD layout: header(20) + owner + DACL
    $ownerOffset = 20
    $daclOffset = $ownerOffset + $ownerSid.Length

    $sd = New-Object System.IO.MemoryStream
    $sd.WriteByte([byte]1)                                              # Revision
    $sd.WriteByte([byte]0)                                              # Sbz1
    $sd.Write([BitConverter]::GetBytes([uint16]0x8004), 0, 2)           # Control
    $sd.Write([BitConverter]::GetBytes([uint32]$ownerOffset), 0, 4)     # Owner offset
    $sd.Write([BitConverter]::GetBytes([uint32]0), 0, 4)                # Group offset (none)
    $sd.Write([BitConverter]::GetBytes([uint32]0), 0, 4)                 # SACL offset (none)
    $sd.Write([BitConverter]::GetBytes([uint32]$daclOffset), 0, 4)       # DACL offset
    $sd.Write($ownerSid, 0, $ownerSid.Length)                           # Owner SID
    $sd.Write($aclBytes, 0, $aclBytes.Length)                           # DACL
    return $sd.ToArray()
}

# --- Existing-ACE extraction (for add-replace / remove) ---------------------

# Parse the current OfficerRights SD and return, for each ACE, the trustee SID
# and the raw ACE bytes. This lets us filter by officer without re-parsing the
# opaque ApplicationData -- non-matching ACEs are preserved verbatim.
function Get-ExistingAces([byte[]]$Bytes) {
    $result = @()
    if ($null -eq $Bytes -or $Bytes.Length -lt 20) { return $result }
    $daclOffset = [BitConverter]::ToUInt32($Bytes, 16)
    if ($daclOffset -eq 0 -or $daclOffset -ge $Bytes.Length) { return $result }
    $aceCount = [BitConverter]::ToUInt16($Bytes, $daclOffset + 4)
    $aceOffset = $daclOffset + 8
    for ($i = 0; $i -lt $aceCount; $i++) {
        if ($aceOffset + 8 -gt $Bytes.Length) { break }
        $aceSize = [BitConverter]::ToUInt16($Bytes, $aceOffset + 2)
        if ($aceSize -lt 8) {
            throw "Corrupt ACE at offset ${aceOffset}: size $aceSize is less than minimum 8 bytes"
        }
        if ($aceOffset + $aceSize -gt $Bytes.Length) {
            throw "Corrupt ACE at offset ${aceOffset}: size $aceSize exceeds remaining buffer ($($Bytes.Length - $aceOffset) bytes)"
        }
        $sidStart = $aceOffset + 8
        $sid = Convert-BinaryToSidString $Bytes $sidStart
        $rawAce = $Bytes[$aceOffset..($aceOffset + $aceSize - 1)]
        $result += [pscustomobject]@{ OfficerSid = $sid; RawAce = $rawAce }
        $aceOffset += $aceSize
    }
    return $result
}
