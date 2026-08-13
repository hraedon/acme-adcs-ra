<#
.SYNOPSIS
    Provision the CA's OfficerRights template-scoped restriction (WI-025).

.DESCRIPTION
    Productionizes the Plan-004 OfficerRights builder: a CA-enforced
    "Restrict Certificate Managers" restriction that scopes a certificate
    officer's power (issue + revoke) to a SINGLE certificate template. This is
    the boundary that makes automated revocation safe -- a compromised
    `gMSA-acme-revoker$` can revoke only `ACME-ServerAuth` certs, not DC /
    Machine / code-signing certs (proven live in Plan 004 / WI-021).

    The restriction lives in the CA registry value `OfficerRights`
    (REG_BINARY): a self-relative SECURITY_DESCRIPTOR whose DACL uses callback
    ACEs. Each ACE binds (officer SID, template OID) with an all-subjects
    scope. The exact byte-level format was reverse-engineered from GUI
    captures in Plan 004's live spike and is reproduced here:

      SD control 0x8004 (SE_SELF_RELATIVE | SE_DACL_PRESENT)
      Owner SID  S-1-5-32-544 (BUILTIN\Administrators) -- mandatory; an SD
                 with no owner is rejected by the CA (0x80070057).
      No group, no SACL.
      ACL revision 2.
      Per-officer callback ACE:
        AceType    9 (ACCESS_ALLOWED_CALLBACK_ACE_TYPE)
        AceFlags   0
        AccessMask 0x00010000 (the per-officer callback mask)
        Trustee    the officer's SID
        Opaque     [SidCount=1 u32 LE][Everyone S-1-1-0][template OID as
                   UTF-16LE + 2-byte null terminator]
      "All subjects" = SidCount 1 + Everyone S-1-1-0 (NOT SidCount 0 --
      that was one of the two bugs in the rejected Plan-004 blob).
      "All templates" = an Everyone entry with no template bytes (not used
      here; -TemplateOid is mandatory).
      Deny = AceType 10 (ACCESS_DENIED_CALLBACK_ACE_TYPE).

    Run ON THE CA HOST (certutil -getreg / -setreg read/write the local
    registry; there is no remote -config for -setreg). The -CaConfig string
    identifies the CA and is used for the registry-path fallback.

    After writing, the script restarts `certsvc` (required for the change to
    take effect) and verifies the value by readback. Run
    `Get-OfficerRights.ps1` to confirm the ACE landed before trusting it.

    Two hard provisioning constraints (from the live spike -- see
    docs/operations.md ## Automated revocation):
      1. The officer must NOT be a member of any broader certificate-manager
         group (officer rights are a union over the token -- a broader-manager
         membership silently defeats the restriction).
      2. The officer must be a member of `Certificate Service DCOM Access`
         (else revoke fails 0x8007000d INVALID_DATA).

.PARAMETER CaConfig
    The CA configuration string ("CA01\WORK-DOMAIN-CA" form). Identifies the
    CA; the CA name (after the backslash) is the registry subkey.

.PARAMETER OfficerSid
    The SID of the officer (e.g. the gMSA's SID). S-1-5-... form.

.PARAMETER TemplateOid
    The OID of the allowed template (e.g. the ACME-ServerAuth template OID).

.PARAMETER Remove
    Remove the OfficerRights ACE for this officer instead of adding it. If the
    officer was the last ACE, the OfficerRights value is deleted entirely
    (reverting to unrestricted -- logged visibly).

.EXAMPLE
    # Add the revoker gMSA scoped to the ACME-ServerAuth template:
    powershell -File .\scripts\Set-OfficerRights.ps1 `
        -CaConfig 'CA01\WORK-DOMAIN-CA' `
        -OfficerSid 'S-1-5-21-xxx-yyy-zzz' `
        -TemplateOid '1.3.6.1.4.1.311.21.8.x.y.z'

.EXAMPLE
    # Remove the officer restriction:
    powershell -File .\scripts\Set-OfficerRights.ps1 `
        -CaConfig 'CA01\WORK-DOMAIN-CA' `
        -OfficerSid 'S-1-5-21-xxx-yyy-zzz' `
        -TemplateOid '1.3.6.1.4.1.311.21.8.x.y.z' -Remove

.NOTES
    This is a one-time provisioning step (not the revoke loop). It touches
    CA configuration -- review carefully. No signing key, no enrollment --
    this is an operator CA-configuration tool only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CaConfig,
    [Parameter(Mandatory = $true)][string]$OfficerSid,
    [Parameter(Mandatory = $true)][string]$TemplateOid,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

. "$PSScriptRoot/lib/OfficerRightsLib.ps1"

function Die([string]$Message, [int]$Code) {
    [Console]::Error.WriteLine("ERROR: $Message")
    exit $Code
}

# --- OfficerRights I/O -------------------------------------------------------

# Read the current OfficerRights REG_BINARY. Returns a byte[], or $null if absent.
#
# The registry provider is tried FIRST and is authoritative: it returns the raw
# bytes. The `certutil -getreg` path recovers the value by regex-scanning hex
# pairs out of formatted console text, which also renders an ASCII gutter --
# a lossy parse that can pick up bytes that are not part of the value. That is
# fine as a last-resort fallback, but it must not be what a security control
# verifies itself against.
function Get-OfficerRightsBytes([string]$Config) {
    $caName = $Config.Split('\')[-1]
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName"
    if (Test-Path $regPath) {
        $props = Get-ItemProperty -Path $regPath -Name 'OfficerRights' -ErrorAction SilentlyContinue
        if ($null -ne $props -and $null -ne $props.OfficerRights) {
            return [byte[]]($props.OfficerRights)
        }
        # The key exists and the value does not: definitively absent.
        return $null
    }
    $out = & certutil -getreg CA\OfficerRights 2>&1
    if ($LASTEXITCODE -eq 0) {
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
    return $null
}

# Write the OfficerRights REG_BINARY via the registry provider, then verify by
# readback. We deliberately do NOT use `certutil -setreg CA\OfficerRights <hex>`:
# on some builds (observed on Server 2025) it stores the hex as a REG_SZ *string*
# rather than a REG_BINARY value, producing a malformed OfficerRights that the CA
# rejects fail-closed (ERROR_INVALID_PARAMETER) -- breaking officer operations
# for everyone. The registry provider writes the correct REG_BINARY type
# unambiguously (New-ItemProperty -Force creates or overwrites), and we read the
# raw bytes straight back to confirm the exact value landed.
function Set-OfficerRightsBytes([string]$Config, [byte[]]$Bytes) {
    $caName = $Config.Split('\')[-1]
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName"
    if (-not (Test-Path $regPath)) {
        Die ("CA configuration registry key not found: {0} (is the CA name in -CaConfig correct?)." -f $regPath) 1
    }

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        # Delete the value entirely (reverts to unrestricted, logged by caller).
        Remove-ItemProperty -Path $regPath -Name 'OfficerRights' -ErrorAction SilentlyContinue
        return
    }

    New-ItemProperty -Path $regPath -Name 'OfficerRights' -PropertyType Binary -Value $Bytes -Force | Out-Null

    # Verify by raw-bytes readback from the registry provider (authoritative --
    # not the certutil -getreg text parse).
    $readback = $null
    try { $readback = [byte[]](Get-ItemProperty -Path $regPath -Name 'OfficerRights' -ErrorAction Stop).OfficerRights } catch {}
    if ($null -eq $readback -or $readback.Length -ne $Bytes.Length) {
        $got = if ($null -eq $readback) { 0 } else { $readback.Length }
        Die ("OfficerRights readback mismatch after write: expected {0} bytes, got {1}." -f $Bytes.Length, $got) 1
    }
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
        if ($readback[$i] -ne $Bytes[$i]) {
            Die ("OfficerRights readback byte mismatch at offset {0} after write." -f $i) 1
        }
    }
}

# --- Main -------------------------------------------------------------------

# Validate the officer SID parses before doing anything.
try {
    $null = Convert-SidToBinary $OfficerSid
} catch {
    Die ("OfficerSid '{0}' is not a valid SID: {1}" -f $OfficerSid, $_.Exception.Message) 3
}

Write-Output ("CA config:     {0}" -f $CaConfig)
Write-Output ("Officer SID:   {0}" -f $OfficerSid)
Write-Output ("Template OID:  {0}" -f $TemplateOid)
Write-Output ("Mode:          {0}" -f $(if ($Remove) { "REMOVE" } else { "ADD" }))
Write-Output ""

# Read the current OfficerRights.
$currentBytes = Get-OfficerRightsBytes $CaConfig
# @() is load-bearing, not decoration: a single existing ACE arrives here as a
# bare [pscustomobject] whose .Count is $null under Windows PowerShell 5.1, so
# the count test below would report an in-force restriction as "absent".
$existingAces = @(Get-ExistingAces $currentBytes)
if ($existingAces.Count -gt 0) {
    Write-Output ("Current OfficerRights: {0} ACE(s)." -f $existingAces.Count)
    foreach ($a in $existingAces) {
        Write-Output ("  officer={0}" -f $a.OfficerSid)
    }
} else {
    Write-Output "Current OfficerRights: (absent -- unrestricted, the default)."
}
Write-Output ""

# Filter: keep ACEs whose trustee SID does NOT match the target officer.
# (For add: this implements replace semantics -- an existing ACE for this
# officer is removed and the new one added. For remove: it drops the
# officer's ACE.) Use List[byte[]] -- PowerShell's array += flattens nested
# byte arrays, which would corrupt the ACE structure.
$keptAces = [System.Collections.Generic.List[byte[]]]::new()
$removedCount = 0
foreach ($a in $existingAces) {
    if ($a.OfficerSid -eq $OfficerSid) {
        $removedCount++
        Write-Output ("Removing existing ACE for officer {0}." -f $OfficerSid)
    } else {
        $keptAces.Add([byte[]]$a.RawAce)
    }
}

if ($Remove) {
    if ($removedCount -eq 0) {
        Write-Output "No ACE found for officer $OfficerSid -- nothing to remove."
        exit 0
    }
    if ($keptAces.Count -eq 0) {
        Write-Output "Removing the last ACE -- deleting OfficerRights (reverts to unrestricted)."
        Set-OfficerRightsBytes $CaConfig $null
    } else {
        Write-Output ("Rebuilding OfficerRights with {0} remaining ACE(s)." -f $keptAces.Count)
        $newSd = Build-OfficerRightsSD $keptAces
        Set-OfficerRightsBytes $CaConfig $newSd
    }
} else {
    # Add: build the new ACE and append to the kept (non-matching) ACEs.
    $newAce = Build-CallbackAce $OfficerSid $TemplateOid
    $allAces = [System.Collections.Generic.List[byte[]]]::new()
    foreach ($k in $keptAces) { $allAces.Add($k) }
    $allAces.Add($newAce)
    Write-Output ("Building OfficerRights with {0} ACE(s)." -f $allAces.Count)
    $newSd = Build-OfficerRightsSD $allAces
    Set-OfficerRightsBytes $CaConfig $newSd
}

# Restart certsvc. This is NOT cosmetic: the CA reads OfficerRights at service
# start, so until certsvc has actually restarted the restriction on disk is not
# in force. Reporting success on a written-but-not-loaded restriction is the
# dangerous outcome -- the operator believes a compromised officer is bounded
# to one template when it is not. Every failure below is fatal.
Write-Output ""
Write-Output "Restarting certsvc (required for the change to take effect)..."

# Record the pre-restart start time so we can prove the process actually
# recycled, rather than trusting that a command reported success.
$priorStart = $null
try {
    $priorStart = (Get-Process -Name certsrv -ErrorAction Stop | Select-Object -First 1).StartTime
} catch {
    $priorStart = $null
}

$restarted = $false
try {
    Restart-Service -Name certsvc -Force -ErrorAction Stop
    $restarted = $true
    Write-Output "PASS: certsvc restarted."
} catch {
    Write-Warning "Restart-Service failed; attempting net stop/net start: $($_.Exception.Message)"
    & net stop certsvc 2>&1 | ForEach-Object { Write-Output $_ }
    $stopCode = $LASTEXITCODE
    & net start certsvc 2>&1 | ForEach-Object { Write-Output $_ }
    $startCode = $LASTEXITCODE
    # `net stop` returning non-zero is tolerable (the service may already have
    # been stopped); `net start` failing is not -- it means the CA is DOWN.
    if ($startCode -ne 0) {
        Die ("certsvc failed to start (net stop exit {0}, net start exit {1}). " -f $stopCode, $startCode +
             "The CA service may be STOPPED -- investigate immediately. The OfficerRights " +
             "value was written but is NOT in force.") 1
    }
    $restarted = $true
}

if (-not $restarted) {
    Die "certsvc was not restarted; the OfficerRights value is written but NOT in force." 1
}

# Prove the service is actually running now, and that it really recycled.
$svc = Get-Service -Name certsvc -ErrorAction SilentlyContinue
if ($null -eq $svc -or $svc.Status -ne 'Running') {
    $state = if ($null -eq $svc) { 'not found' } else { $svc.Status }
    Die ("certsvc is '{0}' after the restart attempt, not 'Running'. The CA is not " -f $state +
         "serving and the OfficerRights restriction is NOT in force.") 1
}
Write-Output ("PASS: certsvc service state is '{0}'." -f $svc.Status)

try {
    $newStart = (Get-Process -Name certsrv -ErrorAction Stop | Select-Object -First 1).StartTime
    if ($null -ne $priorStart -and $newStart -le $priorStart) {
        Die ("certsvc process start time did not advance ({0} -> {1}); the service did " -f $priorStart, $newStart +
             "not actually recycle, so the OfficerRights restriction is NOT loaded.") 1
    }
    Write-Output ("PASS: certsvc process restarted at {0}." -f $newStart)
} catch [System.Management.Automation.ActionPreferenceStopException] {
    Die "certsvc process not found after restart; the CA is not running." 1
} catch {
    # Some builds deny StartTime to a non-elevated caller; the Running state
    # above is still authoritative for "the service came back".
    Write-Warning ("Could not read the certsvc process start time ({0}); relying on " -f $_.Exception.Message +
                   "the service state above.")
}

# Verify by readback -- and ASSERT, do not merely print. A readback that lists
# ACEs without checking they are the ones we intended proved nothing: the same
# output appears whether the write landed, was overwritten, or was never made.
Write-Output ""
Write-Output "Verifying by readback..."
$verifyBytes = Get-OfficerRightsBytes $CaConfig

if ($Remove -and $keptAces.Count -eq 0) {
    if ($null -ne $verifyBytes) {
        Die "Readback: OfficerRights still present after removing the last ACE." 1
    }
    Write-Output "PASS: OfficerRights deleted (unrestricted)."
} else {
    if ($null -eq $verifyBytes) {
        Die "Readback: OfficerRights absent after write -- the set did not take effect." 1
    }
    $verifyAces = @(Get-ExistingAces $verifyBytes)
    Write-Output ("Readback: {0} ACE(s) present." -f $verifyAces.Count)
    foreach ($a in $verifyAces) {
        Write-Output ("  officer={0}" -f $a.OfficerSid)
    }

    $matching = @($verifyAces | Where-Object { $_.OfficerSid -eq $OfficerSid })
    if ($Remove) {
        if ($matching.Count -ne 0) {
            Die ("Readback: officer {0} still has an ACE after -Remove." -f $OfficerSid) 1
        }
        Write-Output ("PASS: officer {0} no longer has an OfficerRights ACE." -f $OfficerSid)
    } else {
        if ($matching.Count -ne 1) {
            Die ("Readback: expected exactly 1 ACE for officer {0}, found {1}. The " -f $OfficerSid, $matching.Count +
                 "restriction is NOT correctly in force.") 1
        }
        if ($verifyAces.Count -ne $allAces.Count) {
            Die ("Readback: expected {0} ACE(s), found {1}. The written value does not " -f $allAces.Count, $verifyAces.Count +
                 "match what this script built.") 1
        }
        Write-Output ("PASS: officer {0} is restricted to template {1}." -f $OfficerSid, $TemplateOid)
    }
}

Write-Output ""
Write-Output "Done. Run scripts/Get-OfficerRights.ps1 for the full human-readable view."
Write-Output "NOTE: confirm the two provisioning constraints (no broader cert-manager"
Write-Output "      group membership; Certificate Service DCOM Access) -- see"
Write-Output "      docs/operations.md ## Automated revocation."
exit 0
