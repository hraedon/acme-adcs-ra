<#
.SYNOPSIS
    Confirm that a certificate template can only be enrolled by the intended
    identity (the RA's gMSA) and NOT by any broad principal -- i.e. that a
    "normal" user cannot request the cert directly at the CA, bypassing the RA's
    EAB/SAN gating.

.DESCRIPTION
    acme-adcs-ra's whole security model assumes the gMSA is the *sole* gate to
    the server-auth template. If Everyone / Authenticated Users / Domain Users /
    Domain Computers / Users hold Enroll (or Autoenroll, or FullControl) on the
    template, that assumption is false and the template is an open issuance
    surface (an ESC-style condition -- what adcs-lens would flag).

    Reads the template's AD security descriptor over LDAP (a single hop -- works
    from a normal domain session; no CA admin rights needed) and reports every
    principal that can enroll. FAILS (exit 2) if any broad principal can, and
    (exit 3) if any principal outside -ExpectedEnrollee holds enroll rights.

.PARAMETER Template
    The certificate template CN (e.g. ACME-ServerAuth).

.PARAMETER ExpectedEnrollee
    Principal(s) that are *expected* to hold Enroll (e.g. WORK-DOMAIN\gMSA-acme-ra$).
    Listed as OK. Anything ELSE holding enroll rights fails the script (exit 3)
    unless -AllowAdditionalEnrollees is passed. The script's stated invariant is
    "the gMSA is the SOLE gate", so an unexpected enrollee is a failure, not a
    note: printing it and exiting 0 meant any automation gating on this script
    would report success against a template that had been widened.

.PARAMETER ConfigNC
    Configuration naming context DN. Default: read from RootDSE.

.EXAMPLE
    powershell -File .\scripts\Verify-TemplateEnrollment.ps1 `
        -Template ACME-ServerAuth -ExpectedEnrollee "WORK-DOMAIN\gMSA-acme-ra$"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Template,
    [string[]]$ExpectedEnrollee = @(),
    [string]$ConfigNC,
    [string]$BindUser,
    # Accept enrollees outside -ExpectedEnrollee (e.g. Domain Admins holding
    # FullControl). Deliberate and explicit; without it they fail the run.
    [switch]$AllowAdditionalEnrollees
)

$ErrorActionPreference = "Stop"

# Optional explicit bind credentials. The password is read from stdin so it is
# never a process argument. Without -BindUser the ambient session identity binds
# (the normal operator case on a domain-joined management box).
$BindPassword = $null
if ($BindUser) { $BindPassword = [Console]::In.ReadLine() }
function New-DE([string]$path) {
    if ($BindUser) { return New-Object System.DirectoryServices.DirectoryEntry($path, $BindUser, $BindPassword) }
    return New-Object System.DirectoryServices.DirectoryEntry($path)
}

if (-not $ConfigNC) { $ConfigNC = (New-DE "LDAP://RootDSE").configurationNamingContext }
$dn = "CN=$Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
$obj = New-DE "LDAP://$dn"
try { $null = $obj.Guid } catch { throw "Could not bind/read template '$Template' at ${dn}: $($_.Exception.Message)" }

# Extended-right GUIDs: Certificate-Enrollment and Autoenrollment. The all-zero
# GUID = "all extended rights" (so it counts too).
$enrollGuid = [GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
$autoGuid = [GUID]"a05b8cc2-17bc-4802-a710-e7c15ab866a2"
$allGuid = [GUID]"00000000-0000-0000-0000-000000000000"

$enrollees = @()
foreach ($ace in $obj.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
    if ($ace.AccessControlType -ne "Allow") { continue }
    $rights = $ace.ActiveDirectoryRights.ToString()
    $canEnroll = ($rights -match "GenericAll") -or
        (($rights -match "ExtendedRight") -and
         ($ace.ObjectType -in @($enrollGuid, $autoGuid, $allGuid)))
    if ($canEnroll) {
        $id = $ace.IdentityReference.Value
        $sid = $null
        try { $sid = (New-Object System.Security.Principal.NTAccount($id)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
        $enrollees += [pscustomobject]@{ Identity = $id; Sid = $sid; Rights = $rights }
    }
}

Write-Output "=== Principals that can enroll '$Template' ==="
$enrollees | ForEach-Object { Write-Output ("  {0}  [{1}]  {2}" -f $_.Identity, $_.Rights, $_.Sid) }

# Broad principals a normal user falls into.
function Test-Broad($e) {
    if ($e.Sid -eq "S-1-1-0" -or $e.Sid -eq "S-1-5-11" -or $e.Sid -eq "S-1-5-7") { return $true }   # Everyone, Authenticated Users, Anonymous
    if ($e.Sid -and ($e.Sid -match "-(513|515|545)$")) { return $true }                              # Domain Users, Domain Computers, BUILTIN\Users
    return $false
}

$bad = @($enrollees | Where-Object { Test-Broad $_ })
Write-Output ""
if ($bad.Count -gt 0) {
    Write-Output ("FAIL: a normal user CAN request '{0}' -- broad principal(s) hold enroll: {1}" -f $Template, (($bad | ForEach-Object { $_.Identity }) -join ", "))
    exit 2
}
Write-Output ("PASS: no broad principal can enroll '$Template' -- a normal user cannot request this cert directly.")

# Anything outside -ExpectedEnrollee is a FAILURE, not a note.
#
# This script exists to assert one thing: that the gMSA is the sole gate to the
# server-auth template. It used to compute this list, print it as a NOTE, and
# exit 0 -- so a template that had been widened to an extra service account
# still produced a green run, and any automation gating on the exit code
# reported the control as holding. That is the same defect class as the
# OfficerRights readback that printed without asserting (2026-08-13, finding 8).
#
# Domain/Enterprise Admins with FullControl genuinely are normal in most
# estates, which is why the escape hatch exists -- but it must be explicit and
# recorded in the runbook, not the silent default.
$unexpected = @($enrollees | Where-Object { $ExpectedEnrollee -notcontains $_.Identity })
if ($unexpected.Count -gt 0) {
    $names = ($unexpected | ForEach-Object { $_.Identity }) -join ", "
    if ($AllowAdditionalEnrollees) {
        Write-Output ("  NOTE: enrollees beyond -ExpectedEnrollee, allowed by -AllowAdditionalEnrollees: {0}" -f $names)
    } else {
        Write-Output ("FAIL: principals outside -ExpectedEnrollee hold enroll on '{0}': {1}" -f $Template, $names)
        Write-Output "      The gMSA is not the sole gate to this template. Either remove these"
        Write-Output "      grants, add them to -ExpectedEnrollee if they are intended, or pass"
        Write-Output "      -AllowAdditionalEnrollees to accept them deliberately."
        exit 3
    }
}
exit 0
