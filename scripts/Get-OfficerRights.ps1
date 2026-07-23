<#
.SYNOPSIS
    Read-only reader for the CA's OfficerRights restriction (WI-025).

.DESCRIPTION
    Reads the CA's `OfficerRights` registry value (a self-relative security
    descriptor containing callback ACEs that scope certificate officers to
    specific templates -- the ADCS "Restrict Certificate Managers" feature
    proven live in Plan 004 / WI-021) and prints each OfficerRights ACE in
    human-readable form: officer SID, access mask, ACE type (allow/deny),
    subject SIDs (the "for whom" scope -- Everyone = all subjects), and the
    template OID (the "which template" scope).

    This is the verify-by-readback tool: after running `Set-OfficerRights.ps1`
    (and restarting certsvc), run this to confirm the ACE landed correctly
    before trusting the restriction. See Plan 004 "Verify well-formed by
    reading it back".

    Run on the CA host (`certutil -getreg` reads the local registry). The CA
    config string identifies which CA; it is also used for the registry-path
    fallback if certutil's output is not parseable.

    Exit codes:
      0 = at least one OfficerRights ACE was found and printed
      1 = no OfficerRights value present (officer rights unrestricted -- the
          default CA state)

.PARAMETER CaConfig
    The CA configuration string ("CA01\WORK-DOMAIN-CA" form). Used to identify
    the CA and as the registry subkey name for the read fallback.

.EXAMPLE
    powershell -File .\scripts\Get-OfficerRights.ps1 -CaConfig 'CA01\WORK-DOMAIN-CA'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CaConfig
)

$ErrorActionPreference = "Stop"

function Die([string]$Message, [int]$Code) {
    [Console]::Error.WriteLine("ERROR: $Message")
    exit $Code
}

# Read the OfficerRights REG_BINARY from the CA. Returns a byte[], or $null
# if the value is absent (the default, unrestricted state). Tries certutil
# -getreg first; falls back to the registry provider using the CA name
# extracted from the config string.
function Get-OfficerRightsBytes([string]$Config) {
    # certutil -getreg reads the local CA's registry.
    $out = & certutil -getreg CA\OfficerRights 2>&1
    $joined = ($out -join "`n")
    if ($LASTEXITCODE -eq 0) {
        # The hex value lines contain space-separated byte pairs. A line with
        # >= 4 hex pairs is a value line (excludes the registry path and the
        # "command completed" footer, which carry no long hex runs).
        $hexPairs = @()
        foreach ($line in $out) {
            $pairs = [regex]::Matches($line, '\b[0-9A-Fa-f]{2}\b')
            if ($pairs.Count -ge 4) {
                foreach ($m in $pairs) { $hexPairs += $m.Value }
            }
        }
        if ($hexPairs.Count -ge 20) {
            $bytes = [byte[]]::new($hexPairs.Count)
            for ($i = 0; $i -lt $hexPairs.Count; $i++) {
                $bytes[$i] = [Convert]::ToByte($hexPairs[$i], 16)
            }
            return $bytes
        }
    }

    # Fallback: read the registry directly. The CA name is the part of the
    # config string after the backslash (e.g. WORK-DOMAIN-CA in CA01\WORK-DOMAIN-CA).
    $caName = $Config.Split('\')[-1]
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName"
    if (Test-Path $regPath) {
        $props = Get-ItemProperty -Path $regPath -Name 'OfficerRights' -ErrorAction SilentlyContinue
        if ($null -ne $props -and $null -ne $props.OfficerRights) {
            return [byte[]]($props.OfficerRights)
        }
    }
    return $null
}

# Parse a SID from a byte array at the given offset. Returns a hashtable
# with the SID string and the number of bytes consumed.
function Parse-SidAt([byte[]]$Data, [int]$Offset) {
    if ($Offset + 8 -gt $Data.Length) {
        return $null
    }
    $sid = [System.Security.Principal.SecurityIdentifier]::new($Data, $Offset)
    return @{ Sid = $sid.Value; Length = $sid.BinaryLength }
}

# Parse the OfficerRights SD and return a list of ACE hashtables.
function Parse-OfficerRightsSD([byte[]]$Bytes) {
    if ($null -eq $Bytes -or $Bytes.Length -lt 20) {
        return $null
    }
    $revision = $Bytes[0]
    $control = [BitConverter]::ToUInt16($Bytes, 2)
    $ownerOffset = [BitConverter]::ToUInt32($Bytes, 4)
    $daclOffset = [BitConverter]::ToUInt32($Bytes, 16)

    if ($daclOffset -eq 0 -or $daclOffset -ge $Bytes.Length) {
        return $null
    }

    # ACL header: AclRevision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2) = 8 bytes
    $aclRevision = $Bytes[$daclOffset]
    $aceCount = [BitConverter]::ToUInt16($Bytes, $daclOffset + 4)

    $aces = @()
    $aceOffset = $daclOffset + 8
    for ($i = 0; $i -lt $aceCount; $i++) {
        if ($aceOffset + 8 -gt $Bytes.Length) { break }
        $aceType = $Bytes[$aceOffset]
        $aceSize = [BitConverter]::ToUInt16($Bytes, $aceOffset + 2)
        $accessMask = [BitConverter]::ToUInt32($Bytes, $aceOffset + 4)

        # Trustee SID starts at aceOffset + 8 (the SidStart field).
        $sidStart = $aceOffset + 8
        $sidInfo = Parse-SidAt $Bytes $sidStart
        if ($null -eq $sidInfo) { break }

        # ApplicationData (opaque callback blob) follows the SID:
        #   [SidCount u32 LE][subject SIDs][template UTF-16LE + null]
        $appDataStart = $sidStart + $sidInfo.Length
        $appDataEnd = $aceOffset + $aceSize
        $appDataBytes = $Bytes[$appDataStart..($appDataEnd - 1)]

        $subjectSids = @()
        $templateOid = ""
        if ($appDataBytes.Length -ge 4) {
            $sidCount = [BitConverter]::ToUInt32($appDataBytes, 0)
            $cursor = 4
            for ($s = 0; $s -lt $sidCount; $s++) {
                $subSid = Parse-SidAt $appDataBytes $cursor
                if ($null -eq $subSid) { break }
                $subjectSids += $subSid.Sid
                $cursor += $subSid.Length
            }
            # The remaining bytes are the template OID (UTF-16LE + null).
            if ($cursor -lt $appDataBytes.Length) {
                $templateBytes = $appDataBytes[$cursor..($appDataBytes.Length - 1)]
                # Strip the trailing null terminator (2 bytes of 0x00).
                if ($templateBytes.Length -ge 2 -and $templateBytes[-1] -eq 0 -and $templateBytes[-2] -eq 0) {
                    $templateBytes = $templateBytes[0..($templateBytes.Length - 3)]
                }
                if ($templateBytes.Length -gt 0) {
                    $templateOid = [System.Text.Encoding]::Unicode.GetString($templateBytes)
                }
            }
        }

        $aceTypeName = switch ($aceType) {
            9 { "ALLOW_CALLBACK" }
            10 { "DENY_CALLBACK" }
            default { "UNKNOWN($aceType)" }
        }

        $aces += [pscustomobject]@{
            AceType      = $aceTypeName
            OfficerSid   = $sidInfo.Sid
            AccessMask   = ('0x{0:X8}' -f $accessMask)
            Subjects     = ($subjectSids -join ', ')
            TemplateOid  = $templateOid
            AceSize      = $aceSize
        }
        $aceOffset += $aceSize
    }
    return $aces
}

# Main
$bytes = Get-OfficerRightsBytes $CaConfig
if ($null -eq $bytes) {
    Write-Output "OfficerRights: (absent -- officer operations unrestricted, the default CA state)."
    exit 1
}

Write-Output ("OfficerRights: {0} byte(s) of security descriptor." -f $bytes.Length)
$aces = Parse-OfficerRightsSD $bytes
if ($null -eq $aces -or $aces.Count -eq 0) {
    Write-Output "OfficerRights: present but contains no callback ACEs."
    exit 1
}

Write-Output ("Found {0} OfficerRights ACE(s):" -f $aces.Count)
Write-Output ""
$aces | Format-Table -AutoSize -Property AceType, OfficerSid, AccessMask, Subjects, TemplateOid
Write-Output ""
Write-Output "Interpretation:"
Write-Output "  AccessMask 0x00010000 = per-officer callback mask (Manage Certificates, template-scoped)."
Write-Output "  Subjects = 'S-1-1-0' (Everyone) means all subjects (template-scoped, not subject-scoped)."
Write-Output "  TemplateOid is the allowed template; empty = all templates."
exit 0
