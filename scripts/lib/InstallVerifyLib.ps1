# Dot-sourceable library: authenticity checks for the prerequisite MSI the
# Windows installer runs as Administrator.
#
# 2026-08-17 F1. install-windows.ps1 hash-pins its entire Python runtime and
# build closure, and then accepted `-HttpPlatformHandlerMsi https://...` (or
# plain `http://...`), downloaded whatever bytes came back, and handed them
# straight to `msiexec /i` as Administrator. There was no digest and no
# publisher check anywhere on that path. An intercepted plaintext download, or a
# compromised accepted origin, is Administrator code execution on the issuance
# host -- the one place in this system where that is worth the most.
#
# The decision logic lives here, taking plain values rather than doing its own
# I/O, so it can be exercised on Linux by tests/pester/InstallVerify.Tests.ps1.
# The installer keeps the I/O (Invoke-WebRequest, Get-FileHash,
# Get-AuthenticodeSignature) and calls these to decide.

$script:IcaclsExe = if ($env:windir) {
    Join-Path $env:windir 'System32\icacls.exe'
} else {
    'icacls.exe'
}

# Where `icacls /save` dumps are written before being parsed back.
#
# That dump is not scratch, it is EVIDENCE: Get-InstallTreeViolations decides
# whether a tree is locked -- and Get-RootProvenance decides whether a
# pre-existing root is ours -- by reading it. It used to be written to the
# ambient TEMP directory, which is %windir%\Temp (Users-writable) when the
# installer runs as SYSTEM under configuration management. The installer sets
# this to its own administrator-only scratch directory before the first proof
# runs; the TEMP fallback is for the Pester suite and for any caller that
# dot-sources this library on its own.
$script:InstallVerifyScratchDir = $null

# Platform, read from the runtime rather than from $env:OS.
#
# The scratch guard below refuses to name a dump path on Windows when no
# protected directory is configured. Gating that on $env:OS -- an inherited,
# caller-settable environment variable -- meant anything starting the installer
# with OS unset silently got the ambient-TEMP fallback the guard exists to
# remove, in the one function whose whole thesis is not trusting the ambient
# environment. Overridable as a script variable so the Pester suite can drive
# both branches; that requires code execution in the session, which an
# environment variable does not.
$script:InstallVerifyIsWindows = ([System.Environment]::OSVersion.Platform -eq 'Win32NT')

function Get-InstallVerifyScratchPath {
    param([Parameter(Mandatory = $true)][string]$FileName)
    $dir = $script:InstallVerifyScratchDir
    if ([string]::IsNullOrWhiteSpace($dir) -or -not (Test-Path -LiteralPath $dir -PathType Container)) {
        # ON WINDOWS THIS THROWS rather than falling back.
        #
        # The first draft of this function fell back to ambient TEMP whenever no
        # scratch was configured -- which is the single path that reopens the
        # hole it was written to close, because %windir%\Temp is Users-writable
        # when the installer runs as SYSTEM. A fallback that silently restores
        # the unsafe behaviour is not a fallback, it is the bug with a longer
        # code path. Off Windows there is no such directory and no icacls, so
        # the Pester run keeps the TEMP path.
        if ($script:InstallVerifyIsWindows) {
            throw ("InstallVerify scratch directory is not configured or no longer exists " +
                   "('$dir'). The icacls read-back dump is the evidence every provenance " +
                   "verdict and lockdown proof is decided from; it is not written to an " +
                   "ambient TEMP directory. Set `$script:InstallVerifyScratchDir to a " +
                   "protected administrator-only directory before proving any tree.")
        }
        $dir = [System.IO.Path]::GetTempPath()
    }
    return (Join-Path $dir $FileName)
}

# Classify an -HttpPlatformHandlerMsi value: 'https', 'http', or 'local'.
function Get-MsiSourceKind {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Source)
    $s = $Source.Trim()
    if ($s -match '^(?i)https://') { return 'https' }
    if ($s -match '^(?i)http://')  { return 'http' }
    return 'local'
}

# Gate the source before a single byte is fetched.
#
# Plaintext HTTP is refused outright rather than "allowed but hashed": a digest
# supplied over the same channel an attacker controls proves nothing, and there
# is no reason for this artifact to arrive unauthenticated when HTTPS exists.
# A remote source additionally REQUIRES an out-of-band SHA-256, because TLS
# authenticates the origin, not the artifact -- a compromised or substituted
# mirror still serves a valid certificate.
#
# Throws on refusal (the installer runs with $ErrorActionPreference = 'Stop').
function Assert-MsiSourceAcceptable {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Source,
        [AllowEmptyString()][string]$Sha256 = ""
    )
    $kind = Get-MsiSourceKind $Source
    if ($kind -eq 'http') {
        throw ("Refusing to download the HttpPlatformHandler MSI over plaintext HTTP ({0}). " -f $Source) +
              "This artifact is executed by msiexec as Administrator on the issuance host. " +
              "Use an https:// URL with -HttpPlatformHandlerSha256, or pass a vetted local path."
    }
    if ([string]::IsNullOrWhiteSpace($Sha256)) {
        throw "Refusing to install the HttpPlatformHandler MSI without -HttpPlatformHandlerSha256. " +
              "The digest is required for local and remote sources because the elevated installer " +
              "stages and verifies one exact artifact before msiexec opens it. Supply the expected " +
              "SHA-256 out of band."
    }
    return $kind
}

# Compare two SHA-256 digests tolerantly of presentation, strictly of value.
#
# Operators paste digests from many places: Get-FileHash emits uppercase,
# sha256sum lowercase, some pages insert spaces or colons. None of that changes
# the value, and rejecting a correct digest for its spelling would push people
# toward skipping the check. A malformed or wrong-length digest is NOT tolerated
# -- it fails, rather than being padded or truncated into a comparison.
function Test-Sha256Match {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Actual,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Expected
    )
    $normalize = {
        param([string]$v)
        if ($null -eq $v) { return "" }
        ($v -replace '[\s:-]', '').Trim().ToUpperInvariant()
    }
    $a = & $normalize $Actual
    $e = & $normalize $Expected
    if ($a.Length -ne 64 -or $e.Length -ne 64) { return $false }
    if ($a -notmatch '^[0-9A-F]{64}$' -or $e -notmatch '^[0-9A-F]{64}$') { return $false }
    # Ordinal, case-insensitive already handled by the uppercase normalization.
    return [string]::Equals($a, $e, [System.StringComparison]::Ordinal)
}

# Decide whether an Authenticode signature is acceptable for this artifact.
#
# Takes the Status and signer Subject as strings rather than the signature
# object, so the matrix below is testable without a signed file on disk.
#
# Only 'Valid' passes. In particular 'UnknownError', 'NotSigned', and
# 'HashMismatch' do not, and neither does 'UnknownError' with a plausible
# subject -- a tampered MSI whose signature no longer verifies is exactly the
# case this exists to catch. The publisher must also match: a validly signed
# MSI from someone else is still not the artifact we asked for.
function Test-MsiSignatureAcceptable {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Status,
        [AllowEmptyString()][string]$SignerSubject = "",
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ExpectedPublisher
    )
    if ($Status -ne 'Valid') { return $false }
    if ([string]::IsNullOrWhiteSpace($SignerSubject)) { return $false }
    if ([string]::IsNullOrWhiteSpace($ExpectedPublisher)) { return $false }
    return $SignerSubject.IndexOf(
        $ExpectedPublisher, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}


# --- pip floor check (2026-08-14 live re-proof) ------------------------------
# `pip --version` writes one line plus a trailing empty one, so
# `(& $py -m pip --version) 2>&1` is a two-element Object[]. `-match` against an
# ARRAY filters the collection and never populates $Matches, so the inline
# version of this check read $Matches[1] as $null, made it 0, and threw
# "pip is too old" on pip 26.2.1 -- blocking every fresh install on Windows,
# the RA's only production platform. Taking the raw output as an object here
# keeps the flattening and the capture in one tested place.
#
# Returns the major version, or -1 when the output cannot be parsed (the caller
# warns rather than blocking on that: an unparseable banner is not evidence of
# an ancient pip).
function Get-PipMajorVersion {
    param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()]$PipVersionOutput)
    $text = (@($PipVersionOutput) | ForEach-Object { if ($null -eq $_) { "" } else { $_.ToString() } }) -join ' '
    if ($text -match 'pip\s+(\d+)\.') { return [int]$Matches[1] }
    return -1
}


# --- install-root trust (2026-08-19 F1) --------------------------------------
# The installer runs elevated against a PREDICTABLE path under ProgramData, and
# it used to prefer and EXECUTE `$InstallDir\python\python.exe` roughly 250
# lines before it created that directory or applied an ACL to it. A local user
# who pre-creates the tree plants an interpreter that then runs as
# Administrator on an issuance host (CWE-426).
#
# The ordering fix lives in install-windows.ps1; the two decisions worth
# testing in isolation live here.
#
# A reparse point is refused outright rather than followed: a junction placed at
# the install root redirects every subsequent write, ACL and probe somewhere the
# installer never checked, and "is the target safe" is not a question this
# script can answer cheaply or race-free.
function Test-InstallRootAttributesAcceptable {
    param([Parameter(Mandatory = $true)][AllowNull()]$Attributes)
    if ($null -eq $Attributes) { return $false }
    $a = [System.IO.FileAttributes]$Attributes
    if ($a.HasFlag([System.IO.FileAttributes]::ReparsePoint)) { return $false }
    if (-not $a.HasFlag([System.IO.FileAttributes]::Directory)) { return $false }
    return $true
}


# --- hostile-tree ACL lockdown (Daybreak 2026-08-15 review) -------------------
#
# The 2026-08-19 F1 fix "claimed" the predictable install root with
#     icacls $InstallDir /inheritance:r /grant:r <Admins/SYSTEM>
# before executing anything under it. That leaves two attacker holds intact,
# because /inheritance:r removes only INHERITED ACEs:
#
#   * every EXPLICIT ACE on a pre-created tree -- the attacker grants
#     themselves (or Everyone) write, the installer "secures" the root, and the
#     planted interpreter/venv stays writable and then runs elevated;
#   * OWNERSHIP: an owner has implicit WRITE_DAC, so an attacker-owned object
#     can have its DACL rewritten back at any time, whatever we set it to.
#
# The three mechanical steps below end with a proof (Assert-InstallTreeLocked),
# because "we ran icacls" is not evidence -- reading the tree back and
# comparing it against exactly the ACE set we intended is.

# Did an icacls run succeed COMPLETELY? (Daybreak 2026-08-15 second rescan F2.)
#
# Two ways an icacls failure used to pass unnoticed:
#
#   * `/c` (continue on error) makes icacls skip objects it could not process.
#     It still prints "Failed processing N files", but the exit code is not a
#     dependable signal in that mode -- so a tree where half the objects kept
#     their attacker ACEs could return 0.
#   * A localized Windows prints a translated summary line, so text matching
#     alone is not dependable either.
#
# So: `/c` is gone from every call (a single unprocessable object must abort the
# install, not be skipped), the exit code is authoritative, and the summary text
# is checked as a second, English-only belt-and-braces.
function Test-IcaclsOutputClean {
    param(
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [AllowNull()][AllowEmptyString()]$Output = ""
    )
    if ($ExitCode -ne 0) { return $false }
    $text = (@($Output) | ForEach-Object { if ($null -eq $_) { "" } else { $_.ToString() } }) -join "`n"
    if ($text -match '(?im)Failed\s+processing\s+([1-9]\d*)\s') { return $false }
    return $true
}

# The principals to try for `icacls /setowner`, in order.
#
# `*<SID>` is locale-independent and is what the rest of this script uses. The
# translated NTAccount name is the fallback for the (unlikely, but untestable
# from Linux) case where a Windows build's /setowner parser rejects the star
# form -- on a localized Windows Translate() yields the localized name, which
# icacls definitely accepts. Returns the star form alone when translation is
# unavailable (non-Windows, i.e. the Pester run on Linux).
function Get-AdministratorsOwnerCandidates {
    $candidates = @('*S-1-5-32-544')
    try {
        $name = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate(
            [System.Security.Principal.NTAccount]).Value
        if ($name -and $candidates -notcontains $name) { $candidates += $name }
    } catch {
        # No SID translation here (Linux/Pester): the star form is all we have,
        # and this function is not the thing under test in that environment.
    }
    return @($candidates)
}

# Take ownership of a whole tree for the Administrators group and discard every
# explicit ACE in it. Runs elevated; THROWS on any failure (fail closed: a
# partial reset leaves attacker ACEs behind, so partial is refused).
#
# 2026-08-15 SECOND rescan, F2: this used to run `takeown /f <root> /r`, and
# takeown has NO no-follow option. Assert-NoReparsePoints ran first, but a
# junction planted into the gap between that walk and takeown redirected an
# ELEVATED recursive ownership rewrite outside the install tree -- real damage
# to an external target that the post-walk could only detect, never undo.
#
# `icacls /setowner` does take /L, so ownership is now claimed without ever
# following a link, and no privileged operation in the claim path follows one.
#
# The trade is deliberate and is the point: unlike takeown, icacls /setowner
# does NOT force ownership (Microsoft's own documentation says so). It succeeds
# wherever we already hold WRITE_OWNER -- a directory we just created, a tree a
# previous install of ours locked down, a file the gMSA created inside it -- and
# it FAILS on a tree a local attacker pre-created and locked against us. That
# case now aborts the install with an instruction to remove the directory,
# instead of forcibly adopting a hostile namespace. Refusing to install is the
# correct outcome there; silently claiming it was how F2 and F3 existed.
function Reset-TreeToInherited {
    param([Parameter(Mandatory = $true)][string]$Path)
    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Reset-TreeToInherited: $Path does not exist; nothing to reset."
    }
    # /L everywhere: operate on links THEMSELVES, never their targets. The
    # caller still runs Assert-NoReparsePoints first (a link in the tree means
    # the namespace is not the closed one we are about to claim), and
    # Assert-InstallTreeLocked re-walks afterwards -- but neither is load-bearing
    # for containment any more, because nothing here can traverse a link.
    $ownerFailures = @()
    $owned = $false
    foreach ($principal in (Get-AdministratorsOwnerCandidates)) {
        $out = & $script:IcaclsExe $Path /setowner $principal /t /q /L 2>&1
        if (Test-IcaclsOutputClean -ExitCode $LASTEXITCODE -Output $out) { $owned = $true; break }
        $ownerFailures += ("{0} -> exit {1}: {2}" -f $principal, $LASTEXITCODE, (($out | Out-String).Trim()))
    }
    if (-not $owned) {
        throw ("Reset-TreeToInherited: could not claim ownership of $Path for the Administrators " +
               "group without following links.`n  " + ($ownerFailures -join "`n  ") + "`n" +
               "This installer no longer force-claims a namespace it does not own (takeown cannot " +
               "be told to skip junctions, so forcing it could rewrite ownership OUTSIDE the tree). " +
               "If $Path was not created by a previous run of this installer, treat it as hostile: " +
               "inspect it, move or delete it, and re-run.")
    }
    # /reset replaces each object's DACL with the default INHERITED one, which
    # discards every explicit ACE -- the attacker's included -- and clears DACL
    # protection tree-wide. Descendants become pure inheritors, so the caller's
    # protected root DACL propagates to all of them. We own every object by now,
    # so this cannot be denied.
    $out = & $script:IcaclsExe $Path /reset /t /q /L 2>&1
    if (-not (Test-IcaclsOutputClean -ExitCode $LASTEXITCODE -Output $out)) {
        throw ("Reset-TreeToInherited: icacls /reset failed on $Path (exit $LASTEXITCODE): " +
               (($out | Out-String).Trim()) +
               "`nExplicit ACEs may have survived; refusing to continue.")
    }
}

# Reset DESCENDANT subtrees only; the root itself is never passed to
# /setowner+/reset. A protected root that is /reset re-inherits the parent's
# create-class ACEs for the interval before /inheritance:r restores protection
# (%ProgramData% grants Users (CI)(WD,AD,WEA,WA); a looping standard-user
# process planted 3 entries into the state root through exactly that interval,
# live-proven 2026-08-16 during the round-6 re-proof -- caught by the post-claim
# proof, so nothing was adopted, but the write itself must be impossible).
# The root is instead re-asserted with Set-ObjectProtectedDacl -SkipReset,
# which never has an unprotected interval: it already carries exactly the
# protected grants (provenance verified it, or CreateDirectoryW set it), and
# /inheritance:r /grant:r re-applies that shape with no inherited-DACL window.
function Reset-TreeChildrenToInherited {
    param([Parameter(Mandatory = $true)][string]$Path)
    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Reset-TreeChildrenToInherited: $Path does not exist; nothing to reset."
    }
    foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force)) {
        Reset-TreeToInherited -Path $child.FullName
    }
}

# Give ONE object a deterministic, protected DACL: drop every explicit ACE it
# carries (/reset -- the same trap as the tree: /inheritance:r alone leaves
# explicit ACEs untouched), then protect it with EXACTLY the grants given.
# The caller must already own the object (Reset-TreeToInherited for anything
# under the install root). THROWS on failure.
#
# /L on both calls (second rescan F2): these run against the install root, the
# dotenv and the Python manifest, and a file symlink raced into any of those
# paths would otherwise redirect an elevated ACL rewrite onto its target.
#
# -SkipReset is for roots that ALREADY carry exactly the protected grants (a
# CreateDirectoryW birth DACL, or a tree the provenance verdict just accepted
# as 'ours'): their /reset would strip the protected DACL and re-inherit the
# parent's create-class ACEs until /inheritance:r re-protects -- the
# create-capable window this library exists never to open. /inheritance:r
# /grant:r alone re-asserts the same shape with no unprotected interval.
function Set-ObjectProtectedDacl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Grants,
        [switch]$SkipReset
    )
    $ErrorActionPreference = 'Stop'
    if (-not $SkipReset) {
        $out = & $script:IcaclsExe $Path /reset /q /L 2>&1
        if (-not (Test-IcaclsOutputClean -ExitCode $LASTEXITCODE -Output $out)) {
            throw ("Set-ObjectProtectedDacl: icacls /reset failed on $Path (exit $LASTEXITCODE): " +
                   (($out | Out-String).Trim()))
        }
    }
    $out = & $script:IcaclsExe $Path /inheritance:r /grant:r @Grants /L 2>&1
    if (-not (Test-IcaclsOutputClean -ExitCode $LASTEXITCODE -Output $out)) {
        throw ("Set-ObjectProtectedDacl: icacls /inheritance:r /grant:r failed on " +
               "$Path (exit $LASTEXITCODE) with grants: $($Grants -join ' ') : " +
               (($out | Out-String).Trim()))
    }
}

# Create one directory with its final protected DACL in the same kernel call.
# Create-then-icacls leaves a window in which a low-privilege process can open
# a create-capable handle and retain it after the DACL changes.
if (-not ('ACMERA.AtomicDirectory' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace ACMERA {
    public static class AtomicDirectory {
        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern bool CreateDirectoryW(string path, ref SECURITY_ATTRIBUTES attributes);
        public static int Create(string path, byte[] securityDescriptor) {
            GCHandle pinned = GCHandle.Alloc(securityDescriptor, GCHandleType.Pinned);
            try {
                SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
                attributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                attributes.lpSecurityDescriptor = pinned.AddrOfPinnedObject();
                attributes.bInheritHandle = 0;
                return CreateDirectoryW(path, ref attributes) ? 0 : Marshal.GetLastWin32Error();
            } finally { pinned.Free(); }
        }
    }
}
"@
}

function New-AtomicProtectedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Grants
    )
    $ErrorActionPreference = 'Stop'
    if (-not $script:InstallVerifyIsWindows) {
        throw 'New-AtomicProtectedDirectory is supported only on Windows.'
    }
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    foreach ($grant in $Grants) {
        if ($grant -notmatch '^(?<identity>.+):\(OI\)\(CI\)(?<rights>F|RX|M)$') {
            throw "New-AtomicProtectedDirectory: unsupported grant '$grant'."
        }
        $identity = $Matches['identity'].TrimStart('*')
        $rightsCode = $Matches['rights']
        try {
            $sid = if ($identity -match '^S-1-\d+(-\d+)+$') {
                New-Object System.Security.Principal.SecurityIdentifier($identity)
            } else {
                (New-Object System.Security.Principal.NTAccount($identity)).Translate(
                    [System.Security.Principal.SecurityIdentifier])
            }
        } catch {
            throw "New-AtomicProtectedDirectory: cannot resolve grant identity '$identity'."
        }
        $rights = switch ($rightsCode) {
            'F'  { [System.Security.AccessControl.FileSystemRights]::FullControl }
            'RX' { [System.Security.AccessControl.FileSystemRights]::ReadAndExecute }
            'M'  { [System.Security.AccessControl.FileSystemRights]::Modify }
        }
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, $rights,
            ([System.Security.AccessControl.InheritanceFlags]::ObjectInherit -bor
             [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }

    $errorCode = [ACMERA.AtomicDirectory]::Create(
        $Path, $security.GetSecurityDescriptorBinaryForm())
    if ($errorCode -eq 183) { return $false } # ERROR_ALREADY_EXISTS
    if ($errorCode -ne 0) {
        throw (New-Object ComponentModel.Win32Exception(
            $errorCode, "Could not create protected directory '$Path' atomically"))
    }

    # Administrator-created objects are normally owned by the individual
    # account. Normalize to the Administrators group while the final DACL is
    # already active; this operation cannot reopen low-privilege access.
    $owned = $false
    $ownerFailures = @()
    foreach ($principal in (Get-AdministratorsOwnerCandidates)) {
        $out = & $script:IcaclsExe $Path /setowner $principal /q /L 2>&1
        if (Test-IcaclsOutputClean -ExitCode $LASTEXITCODE -Output $out) {
            $owned = $true
            break
        }
        $ownerFailures += ("{0}: {1}" -f $principal, (($out | Out-String).Trim()))
    }
    if (-not $owned) {
        throw ("Protected directory '$Path' was created, but its owner could not be normalized " +
               "to Administrators: " + ($ownerFailures -join '; '))
    }
    return $true
}

# Support ordinary local DOS paths only. Win32 strips trailing spaces/periods
# and gives device/extended paths different alias rules; refusing those names
# is safer than trying to duplicate every consuming API's normalization.
function Assert-SafeLocalInstallPath {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path)
    if ($Path -notmatch '^[A-Za-z]:\\') {
        throw "Install paths must be absolute local drive paths; refusing '$Path'."
    }
    if ($Path -match '[/?*"<>|]' -or $Path.StartsWith('\\?\') -or $Path.StartsWith('\\.\')) {
        throw "Install path '$Path' uses an unsupported Win32 namespace or character."
    }
    $tail = $Path.Substring(3).TrimEnd('\')
    if (-not $tail) { throw "A drive root is not a safe install tree: '$Path'." }
    foreach ($component in ($tail -split '\\')) {
        if (-not $component -or $component -eq '.' -or $component -eq '..' -or
            $component.EndsWith('.') -or $component.EndsWith(' ') -or
            $component.Contains(':')) {
            throw "Install path '$Path' contains an ambiguous Win32 component '$component'."
        }
        $stem = ($component -split '\.')[0]
        if ($stem -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            throw "Install path '$Path' contains reserved device name '$component'."
        }
    }
}

# Read an `icacls <root> /save <file>` dump back as text.
#
# icacls /save writes UTF-16 LE **without a BOM** (observed on Windows 10.0.26100:
# 61 00 63 00 ... -- each ASCII byte followed by 00). `Get-Content -Raw` with no
# BOM decodes as ANSI on Windows PowerShell 5.1 and as UTF-8 on pwsh 7, and
# either way every other character becomes a NUL: no line starts with 'D:', the
# parser reads zero entries, and the proof fails closed on a healthy tree. That
# is exactly what the first live run of the two-tree installer did -- the Pester
# suite feeds SDDL strings straight to Test-AclDumpLocked and never exercised
# this read, so no environment had ever decoded a real /save file.
#
# The decode is decided from the BYTES, not from a parameter: a BOM is honoured,
# a BOM-less even-length file whose odd bytes are consistently 0x00 is UTF-16LE
# (an ASCII-dominated SDDL dump is decisive), and anything else is decoded with
# the platform default. Byte-sniffing rather than assuming: if some future
# icacls writes ANSI, the dump still decodes, and if it is ever ambiguous the
# parser below fails closed rather than passing a mangled tree.
function Get-IcaclsDumpText {
    param([Parameter(Mandatory = $true)][string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    $oddZeros = 0; $evenZeros = 0
    $probe = [Math]::Min($bytes.Length, 4096)
    for ($i = 0; $i -lt $probe; $i += 2) {
        if ($bytes[$i] -eq 0) { $evenZeros++ }
        if (($i + 1) -lt $probe -and $bytes[$i + 1] -eq 0) { $oddZeros++ }
    }
    if ($oddZeros -gt 0 -and $evenZeros -eq 0) {
        return [System.Text.Encoding]::Unicode.GetString($bytes)
    }
    return [System.Text.Encoding]::Default.GetString($bytes)
}

# Relation of two Windows path strings: 'equal', 'a-inside-b', 'b-inside-a'
# or 'disjoint'. Both inputs are CANONICALISED first (round 5): lexical
# normalisation catches dot segments, forward slashes and case everywhere
# (Linux Pester included), and on Windows the deepest existing ancestor is
# resolved through the kernel so junctions, symlinks and 8.3 short names
# cannot alias one physical tree as two "disjoint" strings -- which would let
# the state root's Modify grant land on runtime bytes. Used to refuse
# overlapping -RuntimeDir/-InstallDir: the ACL boundary between the two trees
# IS the code/state control.
function Get-PathRelation {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$A,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$B
    )
    Assert-SafeLocalInstallPath -Path $A
    Assert-SafeLocalInstallPath -Path $B
    $na = Get-CanonicalPathString -Path $A
    $nb = Get-CanonicalPathString -Path $B
    $na = (@($na -split '\\') | Where-Object { $_ }) -join '\'
    $nb = (@($nb -split '\\') | Where-Object { $_ }) -join '\'
    if ($na -eq $nb) { return 'equal' }
    if ($na.StartsWith($nb + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return 'a-inside-b' }
    if ($nb.StartsWith($na + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return 'b-inside-a' }
    return 'disjoint'
}

# Is $Path equal to or underneath $Tree? (Used for the preserved-web.config
# check: a processPath inside the state tree is a worker-writable interpreter.)
function Test-PathInsideTree {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Tree
    )
    if (-not $Path -or -not $Tree) { return $false }
    $rel = Get-PathRelation -A $Path -B $Tree
    return ($rel -eq 'equal' -or $rel -eq 'a-inside-b')
}

# Do two path strings name the same object? Canonicalised through the same
# machinery as Get-PathRelation, so case, trailing separators, dot segments,
# 8.3 names and junction aliases cannot make one object read as two. Used where
# "inside the right tree" is too weak an answer and only one exact path will do
# (the web.config processPath, the dotenv location).
function Test-PathsEquivalent {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$A,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$B
    )
    if (-not $A -or -not $B) { return $false }
    # Forward slashes are normalised, not refused.
    #
    # Assert-SafeLocalInstallPath rejects '/' outright, which is right for an
    # install ROOT the operator passes on the command line -- there, refusing an
    # ambiguous spelling is cheaper than normalising it. But this helper compares
    # paths read out of web.config, where both IIS and Python accept
    # `C:/ProgramData/...`; refusing it aborted the install of a live issuance
    # host with a message ("must be absolute local drive paths") about a path
    # that IS one. Get-CanonicalPathString already handles '^[A-Za-z]:[\\/]'.
    $na = $A -replace '/', '\'
    $nb = $B -replace '/', '\'
    return ((Get-PathRelation -A $na -B $nb) -eq 'equal')
}

# Pure decision function over an `icacls <root> /save <file> [/t]` dump: does
# the dump describe a LOCKED tree? Returns an array of violation strings --
# EMPTY means locked. No I/O, so tests/pester can drive it with fixture dumps
# on Linux.
#
#   Tree mode (default): the FIRST entry is the root and must be PROTECTED with
#   explicit ACEs for allowed trustees only; every other entry must NOT be
#   protected (it inherits the root's ACL), must hold no explicit ACE, no deny
#   ACE, no empty DACL, and no trustee outside the allowed set.
#
#   Single-object mode (-AllEntriesMustBeProtected): every entry must be
#   protected with explicit allowed ACEs (used for the dotenv, which carries
#   its own grant set).
#
#   -ExemptLeafNames: tree-mode entries whose leaf name matches one of these
#   are skipped here because they are verified separately in single-object mode.
#
# The trustee check runs on BOTH inherited and explicit ACEs: after the reset
# the only inheritable ACEs in existence are the root's, so an unexpected SID
# anywhere -- inherited or not -- is a survived or re-introduced attacker grant.
function Test-AclDumpLocked {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$DumpText,
        [Parameter(Mandatory = $true)][string[]]$AllowedTrustees,
        [switch]$AllEntriesMustBeProtected,
        [string[]]$ExemptLeafNames = @()
    )
    $violations = @()

    # --- parse: path line, then one or more consecutive SDDL lines ----------
    $entries = New-Object System.Collections.Generic.List[object]
    $currentPath = $null
    $currentSddl = ''
    foreach ($line in ($DumpText -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        # ORDINAL: a culture-sensitive StartsWith ignores NUL characters, so a
        # mangled (wrong-encoding) dump could partially parse on some platforms
        # and fail closed on others. Wrong-encoding must fail closed everywhere.
        if ($line.StartsWith('D:', [System.StringComparison]::Ordinal)) {
            if ($null -ne $currentPath) { $currentSddl += $line.Trim() }
            continue
        }
        # An entry whose SDDL line is MISSING used to be dropped silently: the
        # commit was guarded on `$currentSddl -ne ''`, so a dump naming a path
        # and then moving straight on to the next one left that object
        # unexamined and the tree "locked" with zero violations. Record it as an
        # entry with no DACL string instead; the check below turns that into a
        # violation naming the path, which is the fail-closed direction.
        if ($null -ne $currentPath) {
            $entries.Add(@{ Path = $currentPath; Sddl = $currentSddl })
        }
        $currentPath = $line.Trim()
        $currentSddl = ''
    }
    if ($null -ne $currentPath) {
        $entries.Add(@{ Path = $currentPath; Sddl = $currentSddl })
    }
    if ($entries.Count -eq 0) {
        return @('acl-dump: no entries parsed -- an unreadable dump fails closed')
    }

    $allowed = @($AllowedTrustees)
    $exempt = @($ExemptLeafNames) | Where-Object { $_ }
    $idx = 0
    foreach ($e in $entries) {
        $path = $e.Path
        $sddl = $e.Sddl
        $leaf = Split-Path -Leaf $path
        $skip = $false
        foreach ($x in $exempt) { if ($leaf -like $x) { $skip = $true } }
        if (-not $skip) {
            $mustBeProtected = $AllEntriesMustBeProtected -or ($idx -eq 0)

            if ($sddl -eq '') {
                $violations += "$path : no DACL line in the dump for this object -- an object that cannot be read back cannot be proven locked"
                $idx++
                continue
            }
            $firstParen = $sddl.IndexOf('(')
            if ($firstParen -lt 0) {
                # A DACL string with no ACE at all: either a deny-everyone
                # empty DACL or an unparsable dump -- both are tampering
                # signals, and both fail closed.
                $violations += "$path : DACL carries no ACEs ($sddl)"
            } else {
                $flagPart = $sddl.Substring(2, $firstParen - 2)
                $protected = $flagPart.Contains('P')
                if ($mustBeProtected -and -not $protected) {
                    $violations += "$path : expected a PROTECTED DACL (exactly our grants) but flags are '$flagPart'"
                }
                if (-not $mustBeProtected -and $protected) {
                    $violations += "$path : DACL is PROTECTED and does not inherit the install root's ACL ('$flagPart')"
                }

                foreach ($m in [regex]::Matches($sddl, '\(([^)]*)\)')) {
                    $fields = @($m.Groups[1].Value -split ';')
                    if ($fields.Count -lt 6) {
                        $violations += "$path : unparseable ACE '$($m.Value)'"
                        continue
                    }
                    $aceType = $fields[0]
                    $aceFlags = $fields[1]
                    $trustee = $fields[5]
                    if ($aceType -eq 'D') {
                        $violations += "$path : DENY ACE present '$($m.Value)'"
                    }
                    $inherited = $aceFlags.Contains('ID')
                    if ($mustBeProtected -and $inherited) {
                        $violations += "$path : INHERITED ACE on an object whose DACL should be exactly ours '$($m.Value)'"
                    }
                    if (-not $mustBeProtected -and -not $inherited) {
                        $violations += "$path : EXPLICIT ACE survived the tree reset '$($m.Value)'"
                    }
                    $known = $false
                    foreach ($a in $allowed) { if ($trustee -eq $a) { $known = $true; break } }
                    if (-not $known) {
                        $violations += "$path : unexpected trustee '$trustee' in '$($m.Value)'"
                    }
                }
            }
        }
        $idx++
    }
    return @($violations)
}

# Read the tree back and PROVE the lockdown, or throw. This is the step that
# turns "we ran icacls" into evidence:
#   * the root's owner must be Administrators or SYSTEM (any other owner can
#     rewrite the DACL whenever they like, so the ACEs alone prove nothing);
#   * the whole tree's DACLs must match Test-AclDumpLocked's locked shape for
#     exactly the allowed trustee set;
#   * each -ProtectedEntries item (leaf name -> allowed trustees) is verified
#     separately as a single protected object (the dotenv and its distinct
#     grant set).
#
# THROWS (with up to ten violations listed) when anything is off. Runs on
# Windows only -- it shells out to icacls; the decision logic it exercises
# lives in Test-AclDumpLocked, which is unit-tested on Linux.
# Read the tree back and collect every reason it is NOT locked. Returns an
# array of violation strings -- EMPTY means locked.
#
# 2026-08-15 rescan-3: this used to be the body of Assert-InstallTreeLocked and
# nothing else could call it. It is now shared by two callers with opposite
# reactions to the same evidence:
#
#   * Assert-InstallTreeLocked -- the POST-claim proof. Any violation throws;
#     the install has already mutated the tree and a violation means the
#     mutation did not achieve what it claimed.
#   * Get-RootProvenance -- the PRE-flight verdict. Any violation means "this
#     directory is not one of ours", and the installer refuses to adopt it
#     rather than force-claiming it.
#
# One implementation, so the two answers cannot drift: whatever "ours" means at
# the end of an install is exactly what is demanded of a tree at the start of
# the next one.
#
# Failures that would THROW inside the checks (an unreadable subtree, a reparse
# point) are converted to violations here, because a pre-flight caller needs a
# verdict rather than an exception.
function Get-InstallTreeViolations {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$AllowedTrustees,
        # Owners permitted on DESCENDANTS. The state directory legitimately
        # contains files the gMSA created (log lines, the SQLite journal), and
        # the creator owns them; the runtime directory permits no such thing,
        # because the gMSA has no write access there at all.
        [string[]]$AllowedOwnerSids = @('S-1-5-32-544', 'S-1-5-18'),
        # Owners permitted on the ROOT, always strict: a directory a
        # non-administrator created is owned by them, and that is the single
        # most reliable signal that a tree is not ours.
        [string[]]$RootOwnerSids = @('S-1-5-32-544', 'S-1-5-18'),
        [hashtable]$ProtectedEntries = @{},
        # Top-level entry names that must NOT exist under this root (state tree
        # only). The pre-split layout kept venv\, python\ and scripts\ in what
        # is now the state tree, and its trustee/owner/DACL shape otherwise
        # MATCHES ours -- same SIDs, plain inheritance -- so a clean legacy
        # tree passed the generic checks below as 'ours' (Daybreak round 4).
        # But the gMSA holds Modify on this tree, so an adopted interpreter
        # there is a worker-writable interpreter: exactly what the split exists
        # to end.
        [string[]]$ForbiddenTopLevelEntries = @()
    )
    $violations = @()

    # Reparse points anywhere in the tree are a refusal in their own right
    # (rescan F2): every recursive read or write below would either traverse
    # the link outside the tree (/L-less operations) or skip it (/L), and
    # either way the tree is not the closed namespace this proof is about to
    # claim it is.
    try {
        Assert-NoReparsePoints -Path $Root -Context 'tree proof'
    } catch {
        return @($_.Exception.Message)
    }

    # Known executable content at the root: refuse EARLY, before the owner walk
    # and the icacls dump -- the tree is not adoptable regardless of how clean
    # its ACLs are, and this stays decidable on Linux (no icacls needed), which
    # is how the Pester suite exercises it.
    foreach ($name in @($ForbiddenTopLevelEntries)) {
        if ($name -and (Test-Path -LiteralPath (Join-Path $Root $name))) {
            return @(("{0}\{1} : executable content at the state tree root -- the pre-split " -f $Root, $name) +
                     "single-tree layout put the interpreter, the venv and the operator scripts here, " +
                     "and the gMSA holds Modify on this tree, so nothing under it may be executed. " +
                     "A preserved web.config would keep launching a worker-writable interpreter. " +
                     "Migrate per docs/operator-requirements.md section 4; this tree is not adoptable.")
        }
    }

    # EVERY object's owner, not just the root's (rescan-2 F3). An owner holds
    # implicit WRITE_DAC, so one attacker-owned descendant can rewrite its own
    # DACL back at any time after this proof passes -- and the reset makes such
    # a child look perfectly clean, because its inherited ACL is ours.
    try {
        $violations += Get-TreeOwnerViolations -Root $Root `
            -AllowedOwnerSids $AllowedOwnerSids -RootOwnerSids $RootOwnerSids
    } catch {
        return @($_.Exception.Message)
    }

    $tmp = Get-InstallVerifyScratchPath -FileName ("ra-aclcheck-" + [guid]::NewGuid().ToString('N') + ".txt")
    try {
        # /L: dump the links themselves rather than following them, so the
        # read-back cannot be redirected any more than the writes can.
        $out = & $script:IcaclsExe $Root /save $tmp /t /q /L 2>&1
        if (-not (Test-IcaclsOutputClean -ExitCode $LASTEXITCODE -Output $out)) {
            return @("$Root : icacls /save failed (exit $LASTEXITCODE): " +
                     (($out | Out-String).Trim()) +
                     " -- the tree ACL could not be read back in full, so it cannot be trusted")
        }
        $dump = Get-IcaclsDumpText -Path $tmp
        $violations += Test-AclDumpLocked -DumpText $dump `
            -AllowedTrustees $AllowedTrustees -ExemptLeafNames @($ProtectedEntries.Keys)

        foreach ($leaf in @($ProtectedEntries.Keys)) {
            $entryPath = Join-Path $Root $leaf
            if (-not (Test-Path -LiteralPath $entryPath)) { continue }
            # A protected entry's OWNER is held to the strict set, never to the
            # looser descendant set (rescan-3 audit). The dotenv is the case
            # that matters: the gMSA holds Modify on the state ROOT, which
            # includes delete-child, so a compromised worker can delete
            # acme-ra.env and write its own -- becoming its owner. The DACL
            # check below would not notice, because the installer would then
            # re-protect the attacker's file; the owner check is what does.
            # That file carries ACME_RA_EAB_ALLOWLIST and ACME_RA_SAN_SCOPES.
            $entryOwner = $null
            try {
                $entryOwner = (Get-Acl -LiteralPath $entryPath).Owner
            } catch {
                $violations += "$entryPath : owner could not be read ($($_.Exception.Message))"
            }
            if ($null -ne $entryOwner -and
                -not (Test-OwnerAllowed -Owner $entryOwner -AllowedOwnerSids $RootOwnerSids)) {
                $violations += ("$entryPath : owner is '$entryOwner' (expected Administrators or " +
                                "SYSTEM) -- this file decides what the RA may issue, so an owner " +
                                "that can rewrite its DACL is an issuance-policy hole")
            }
            $tmpEntry = Get-InstallVerifyScratchPath -FileName ("ra-aclcheck-" + [guid]::NewGuid().ToString('N') + ".txt")
            $out = & $script:IcaclsExe $entryPath /save $tmpEntry /q /L 2>&1
            if (-not (Test-IcaclsOutputClean -ExitCode $LASTEXITCODE -Output $out)) {
                $violations += "$entryPath : icacls /save failed (exit $LASTEXITCODE): $(($out | Out-String).Trim())"
                continue
            }
            $violations += Test-AclDumpLocked -DumpText (Get-IcaclsDumpText -Path $tmpEntry) `
                -AllowedTrustees @($ProtectedEntries[$leaf]) -AllEntriesMustBeProtected
            Remove-Item -LiteralPath $tmpEntry -Force -ErrorAction SilentlyContinue
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }

    return @(@($violations) | Where-Object { $_ })
}

function Assert-InstallTreeLocked {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$AllowedTrustees,
        [string[]]$AllowedOwnerSids = @('S-1-5-32-544', 'S-1-5-18'),
        [string[]]$RootOwnerSids = @('S-1-5-32-544', 'S-1-5-18'),
        [hashtable]$ProtectedEntries = @{},
        [string[]]$ForbiddenTopLevelEntries = @()
    )
    $ErrorActionPreference = 'Stop'
    $violations = @(Get-InstallTreeViolations -Root $Root -AllowedTrustees $AllowedTrustees `
        -AllowedOwnerSids $AllowedOwnerSids -RootOwnerSids $RootOwnerSids `
        -ProtectedEntries $ProtectedEntries -ForbiddenTopLevelEntries $ForbiddenTopLevelEntries)
    if (@($violations).Count -gt 0) {
        $shown = @($violations) | Select-Object -First 10
        throw ("Install-tree ACL verification FAILED (" + @($violations).Count + " violation(s)); " +
               "the tree is NOT locked down:`n  " + ($shown -join "`n  "))
    }
}


# --- Daybreak 2026-08-15 rescan: link traversal + content authentication -------
#
# Two gaps in the first round of fixes:
#
#   F2 (medium): only the ROOT was checked for reparse status. takeown /r and
#   icacls /t traverse child junctions/symlinks (icacls needs /L to operate on
#   the link itself; takeown has no /L), so a child junction planted in a
#   pre-created tree redirected the elevated ownership/ACL rewrite OUTSIDE the
#   install directory.
#
#   F1 (high): the ACL lockdown bounds future WRITES, it does not authenticate
#   existing BYTES. A planted python\python.exe survived the claim, was the
#   PREFERRED launcher candidate, and was executed as Administrator; a planted
#   .pth/sitecustomize in an existing venv likewise survived `python -m venv`
#   (which, without --clear, keeps unknown files) and ran on every elevated
#   pip invocation. And the gMSA holds Modify over the tree, so even a
#   genuinely-ours interpreter can be rewritten between runs by a compromised
#   app pool and then "trusted" by the next install.
#
# Fixes: refuse any reparse point anywhere in the tree (walked without
# following links), give icacls /L so it never traverses one either, DELETE +
# rebuild the venv every run, and only ever execute a destination-local
# interpreter whose whole tree hashes match a manifest that is write-protected
# against the gMSA.

# Manual, non-following walk: returns the paths of every reparse point under
# (and including) $Path. Level-by-level .NET enumeration -- EnumerateFileSystem
# Entries never descends into anything itself, and we only push subdirectories
# that are NOT reparse points, so a junction is reported and never traversed.
# Get-ChildItem -Recurse cannot be used here: it follows junctions on Windows
# PowerShell 5.1, which is the exact behaviour this exists to avoid.
function Find-ReparsePoints {
    param([Parameter(Mandatory = $true)][string]$Path)
    $found = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push((Resolve-Path -LiteralPath $Path).Path)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $di = New-Object System.IO.DirectoryInfo($dir)
        # A subdirectory we cannot enumerate (deny ACE) is itself a refusal:
        # an uninspectable tree is not a tree we may operate on recursively.
        try {
            $entries = @($di.EnumerateFileSystemInfos())
        } catch {
            throw ("Find-ReparsePoints: cannot enumerate $dir ($($_.Exception.Message)); " +
                   "refusing to operate recursively on a tree that cannot be fully inspected.")
        }
        foreach ($e in $entries) {
            if ($e.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                $found.Add($e.FullName)
                continue
            }
            if ($e.Attributes -band [System.IO.FileAttributes]::Directory) {
                $stack.Push($e.FullName)
            }
        }
    }
    return @($found)
}

# Fail-closed wrapper: THROWS if any reparse point exists under $Path. Called
# before every recursive privileged operation on the tree (takeown, icacls /t,
# Remove-Item -Recurse) and again by Assert-InstallTreeLocked afterwards -- the
# pre-walk kills the static planted-link case outright; the post-walk catches a
# link planted into the TOCTOU window mid-sequence (takeown has no /L, so that
# residual window is documented in the review doc and detected, not prevented).
function Assert-NoReparsePoints {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Context = ""
    )
    $links = @(Find-ReparsePoints -Path $Path)
    if (@($links).Count -gt 0) {
        $shown = @($links) | Select-Object -First 5
        throw ("Assert-NoReparsePoints ($Context): " + @($links).Count + " reparse point(s) under " +
               "$Path -- a junction/symlink redirects privileged recursive operations outside " +
               "the install tree. Remove it and re-run. First offenders:`n  " + ($shown -join "`n  "))
    }
}

# Every path under (and including) $Root, from the same non-following walk, and
# THROWS on any reparse point rather than reporting it -- callers of this one
# are about to inspect each path individually, and a link would send that
# inspection somewhere else. Directories and files both, root first.
function Get-TreePaths {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $rootFull = (Resolve-Path -LiteralPath $Path).Path
    $all = New-Object System.Collections.Generic.List[string]
    $all.Add($rootFull)
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($rootFull)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $di = New-Object System.IO.DirectoryInfo($dir)
        try {
            $entries = @($di.EnumerateFileSystemInfos())
        } catch {
            throw ("Get-TreePaths: cannot enumerate $dir ($($_.Exception.Message)); " +
                   "an uninspectable subtree cannot be proven locked.")
        }
        foreach ($e in $entries) {
            if ($e.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw ("Get-TreePaths: reparse point at $($e.FullName) -- refusing to inspect a " +
                       "tree whose shape can redirect a per-object read.")
            }
            $all.Add($e.FullName)
            if ($e.Attributes -band [System.IO.FileAttributes]::Directory) {
                $stack.Push($e.FullName)
            }
        }
    }
    return @($all)
}

# Is this owner one of the allowed SIDs? Takes the owner as the string Get-Acl
# returns, which is a SID string on some objects and a DOMAIN\name on others.
# An owner that cannot be resolved to a SID is NOT allowed: "we could not tell"
# fails closed, because an owner can rewrite the DACL whenever it likes.
function Test-OwnerAllowed {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyString()][string]$Owner,
        [Parameter(Mandatory = $true)][string[]]$AllowedOwnerSids
    )
    if ([string]::IsNullOrWhiteSpace($Owner)) { return $false }
    $candidate = $Owner.Trim()
    $sid = $null
    if ($candidate -match '^(?i)S-1-\d+(-\d+)+$') {
        # Already a SID string. Matched textually rather than through
        # System.Security.Principal.SecurityIdentifier, whose constructor throws
        # PlatformNotSupportedException off Windows -- and this is the branch the
        # Linux Pester run exercises.
        $sid = $candidate
    } else {
        try {
            $sid = (New-Object System.Security.Principal.NTAccount($candidate)).Translate(
                [System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            $sid = $null
        }
    }
    if ($null -eq $sid) { return $false }
    foreach ($a in @($AllowedOwnerSids)) {
        if ([string]::Equals($a, $sid, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# Owner-check every object in the tree. Returns violation strings (EMPTY means
# every owner is allowed). Windows-only in practice -- Get-Acl has no owner on
# the Unix filesystem provider -- so the Linux Pester run exercises Get-TreePaths
# and Test-OwnerAllowed separately instead.
#
# COST: one Get-Acl per object, and both ACL passes call it, so a venv with a
# few thousand files adds tens of seconds to an install. That is the price of
# the proof; the root-only check it replaces was cheap and did not detect the
# case it existed for. If it ever becomes the dominant cost, measure before
# narrowing the scope -- descendants are exactly where the finding lived.
function Get-TreeOwnerViolations {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$AllowedOwnerSids,
        # The root is held to a stricter set than its descendants when given.
        # A directory created by a non-administrator is owned by them, and that
        # is the pre-flight's most reliable "this is not ours" signal -- while
        # descendants of the STATE tree are legitimately owned by the gMSA that
        # created them.
        [string[]]$RootOwnerSids = @()
    )
    $rootSids = if (@($RootOwnerSids).Count -gt 0) { @($RootOwnerSids) } else { @($AllowedOwnerSids) }
    $violations = New-Object System.Collections.Generic.List[string]
    $isRoot = $true
    foreach ($p in (Get-TreePaths -Path $Root)) {
        # Get-TreePaths returns the root first.
        $expected = if ($isRoot) { $rootSids } else { @($AllowedOwnerSids) }
        $isRoot = $false
        $owner = $null
        try {
            $owner = (Get-Acl -LiteralPath $p).Owner
        } catch {
            $violations.Add("$p : owner could not be read ($($_.Exception.Message))")
            continue
        }
        if (-not (Test-OwnerAllowed -Owner $owner -AllowedOwnerSids $expected)) {
            $violations.Add("$p : owner is '$owner' (permitted here: $($expected -join ', ')) -- an owner can rewrite the DACL at any time")
        }
    }
    return @($violations)
}

# SHA-256 every file under $Root, recursively, as an ordered map
# "<relpath with / separators>" -> "<UPPERCASE sha256>". Sorted by path so the
# manifest is reproducible. Cross-platform on purpose (Get-FileHash), so the
# --- 2026-08-15 rescan-3: never adopt a namespace, and never execute state ----
#
# Four review rounds went into making it safe to ADOPT a directory a local user
# could have created first. Each round added a layer -- an ACL claim, then an
# ownership claim, then a link walk, then a content manifest, then an
# out-of-tree anchor for the manifest -- and each layer was itself the next
# round's finding. The model was wrong, not the implementations.
#
# Two changes retire the model rather than reinforce it.
#
# FIRST, executable content moves out of %ProgramData%. The default ACL there
# grants Users "create folders / append data" with CREATOR OWNER inheritance,
# which is exactly why a non-administrator can pre-create
# ProgramData\acme-adcs-ra and own it. %ProgramFiles% grants Users read and
# execute only. The interpreter and venv now live there and the gMSA gets
# read+execute, never write; the database, logs and dotenv stay in ProgramData
# where the gMSA needs Modify, and nothing there is ever executed.
#
# SECOND, a pre-existing root is PROVEN ours or REFUSED. There is no
# force-claim path left. "Ours" is defined by the same function that proves the
# lockdown at the end of an install, so the two cannot disagree.
#
# What this deletes: the tree manifest, the HKLM anchor that authenticated it,
# and the destination-interpreter trust gate -- all of which existed only to
# answer "may I reuse the bytes already sitting there?", a question that no
# longer arises because the runtime is built fresh every run.
#
# What this keeps, and why: the ownership normalisation, the reparse walk and
# the read-back proof. They now run only against directories this installer
# created moments earlier -- so F2's raced junction and F3's hostile descendants
# have no premise -- but a proof of what we just built is still worth having,
# and it is what the next run's pre-flight consumes.

# Is $Path absent, provably ours, or foreign? Returns
# @{ State = 'absent'|'ours'|'foreign'; Reasons = @(...) }.
#
# 'foreign' is not an accusation, it is an absence of evidence: a tree from an
# older layout, a half-finished install, or an operator's own directory all
# land here, and all get the same answer -- this installer will not adopt it.
function Get-RootProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$AllowedTrustees,
        # Descendants: the state tree's log files and SQLite journal are
        # legitimately owned by the gMSA that created them.
        [string[]]$AllowedOwnerSids = @('S-1-5-32-544', 'S-1-5-18'),
        # The ROOT and every protected entry: always strict, and NOT derived
        # from $AllowedOwnerSids. Deriving it would mean a compromised gMSA
        # that recreated the state root -- or the dotenv inside it -- passed the
        # pre-flight as "ours" on the next install.
        [string[]]$RootOwnerSids = @('S-1-5-32-544', 'S-1-5-18'),
        [hashtable]$ProtectedEntries = @{},
        [string[]]$ForbiddenTopLevelEntries = @()
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return @{ State = 'absent'; Reasons = @() }
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or -not (Test-InstallRootAttributesAcceptable $item.Attributes)) {
        $attrs = if ($null -eq $item) { 'unreadable' } else { $item.Attributes }
        return @{
            State = 'foreign'
            Reasons = @("$Path is not an ordinary directory (attributes: $attrs). A reparse point here would redirect every write, ACL and probe.")
        }
    }
    $violations = @(Get-InstallTreeViolations -Root $Path -AllowedTrustees $AllowedTrustees `
        -AllowedOwnerSids $AllowedOwnerSids -RootOwnerSids $RootOwnerSids `
        -ProtectedEntries $ProtectedEntries -ForbiddenTopLevelEntries $ForbiddenTopLevelEntries)
    if (@($violations).Count -gt 0) {
        return @{ State = 'foreign'; Reasons = @($violations) }
    }
    return @{ State = 'ours'; Reasons = @() }
}

# Build the operator-facing refusal for a foreign root. Pure text, so the Pester
# suite can assert the operator is actually told what to do -- a refusal nobody
# can act on just gets worked around.
function Get-ForeignRootRefusal {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [string[]]$Reasons = @(),
        [string[]]$Preserve = @()
    )
    $shown = @($Reasons) | Select-Object -First 5
    $lines = @(
        "Refusing to install into $Path ($Purpose).",
        "",
        "This directory already exists and is NOT one this installer created: its",
        "ownership or permissions do not match what a completed install leaves behind.",
        "That is the same state a local user gets by pre-creating the path before the",
        "first install, so it is treated as untrusted rather than adopted -- earlier",
        "versions adopted it, and that was a privilege-escalation path on an issuance",
        "host.",
        "",
        "Why it did not qualify:"
    )
    foreach ($r in $shown) { $lines += "  - $r" }
    if (@($Reasons).Count -gt @($shown).Count) {
        $lines += ("  - ... and " + (@($Reasons).Count - @($shown).Count) + " more")
    }
    $lines += @(
        "",
        "What to do, as an administrator:"
    )
    if (@($Preserve).Count -gt 0) {
        $lines += "  1. Copy anything you need to keep to a safe location first:"
        foreach ($p in $Preserve) { $lines += "       $p" }
        $lines += "     Inspect them before reusing them -- if this directory was pre-created by"
        $lines += "     someone else, so were its contents."
        $lines += "  2. Remove or rename $Path"
        $lines += "  3. Re-run this installer. It will create the directory itself."
        $lines += "  4. Restore the files you kept, then re-check them against the runbook."
    } else {
        $lines += "  1. Inspect $Path and confirm nothing there is needed."
        $lines += "  2. Remove or rename it."
        $lines += "  3. Re-run this installer. It will create the directory itself."
    }
    return ($lines -join "`n")
}

# Prune leftover staging/retired runtimes from an interrupted previous run.
# Best-effort by design: these are ours and admin-only, and a stale one is
# clutter rather than a hazard, so a failure to remove must not block an
# install that is otherwise fine.
function Remove-StaleRuntimeDirectories {
    param([Parameter(Mandatory = $true)][string]$RuntimeDir)
    $removed = 0
    if (-not (Test-Path -LiteralPath $RuntimeDir)) { return 0 }
    foreach ($d in @(Get-ChildItem -LiteralPath $RuntimeDir -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($d.Name -notlike '.staging-*' -and $d.Name -notlike '.retired-*') { continue }
        try {
            Assert-NoReparsePoints -Path $d.FullName -Context 'stale runtime prune'
            Remove-Item -LiteralPath $d.FullName -Recurse -Force
            $removed++
        } catch {
            Write-Host "  [warn] could not remove stale runtime $($d.FullName): $($_.Exception.Message)"
        }
    }
    return $removed
}

# Retire the live runtime and return a fresh, EMPTY directory at the same final
# path. Returns @{ Current; Retired } -- Retired is $null when there was none.
#
# Build-in-place-after-retiring, rather than build-elsewhere-then-rename,
# because a Python venv is NOT relocatable: pyvenv.cfg records an absolute
# `home`, and every console-script .exe in Scripts\ embeds the absolute path of
# the interpreter that created it. Renaming a built venv yields a runtime whose
# python.exe cannot find its own stdlib -- an outage, discovered in production,
# of exactly the kind this rework exists to stop shipping.
#
# The window in which no runtime exists is safe because the app pool is stopped
# and proven dead before any of this runs, and the caller rolls back with
# Restore-RetiredRuntime if the build fails.
function Reset-RuntimeDirectory {
    param([Parameter(Mandatory = $true)][string]$RuntimeDir)
    $ErrorActionPreference = 'Stop'
    $current = Join-Path $RuntimeDir 'current'
    $retired = $null
    if (Test-Path -LiteralPath $current) {
        Assert-NoReparsePoints -Path $current -Context 'runtime retire'
        $retired = Join-Path $RuntimeDir ('.retired-' + [guid]::NewGuid().ToString('N'))
        # Directory.Move is a rename within one parent: it either happens or it
        # does not, and it refuses a cross-volume move rather than silently
        # degrading to copy-then-delete the way Move-Item can.
        [System.IO.Directory]::Move($current, $retired)
    }
    New-Item -ItemType Directory -Path $current -Force | Out-Null
    return @{ Current = $current; Retired = $retired }
}

# Put a retired runtime back after a failed build, so a failed upgrade leaves
# the host serving what it was serving before.
function Restore-RetiredRuntime {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeDir,
        [AllowNull()][AllowEmptyString()][string]$Retired
    )
    if ([string]::IsNullOrWhiteSpace($Retired)) { return $false }
    if (-not (Test-Path -LiteralPath $Retired)) { return $false }
    $current = Join-Path $RuntimeDir 'current'
    if (Test-Path -LiteralPath $current) {
        Assert-NoReparsePoints -Path $current -Context 'failed-build cleanup'
        Remove-Item -LiteralPath $current -Recurse -Force
    }
    [System.IO.Directory]::Move($Retired, $current)
    return $true
}


# --- Daybreak 2026-08-15 SECOND rescan, F3: kill the worker before claiming ---
#
# The app pool used to be stopped ~220 lines AFTER the install root was claimed
# and the destination interpreter was verified and executed. Windows evaluates
# access at handle-open time, so a compromised gMSA worker holding a write
# handle opened under the old (Modify) ACL keeps that write access straight
# through the /setowner + /reset pass -- and can therefore rewrite interpreter
# bytes between the hash check and the elevated execution of those bytes.
#
# The fix is ordering plus proof: stop the pool and confirm the worker process
# is GONE before anything under the install root is claimed, hashed or run.
# `appcmd list wp` enumerates live worker processes, so it is the direct
# evidence; "the pool says Stopped" is not, because the worker lingers while it
# drains.

# Does `appcmd list wp` still show a worker for this pool? Pure text decision so
# the Linux Pester run can drive it. Fails CLOSED on unparseable input: a line
# we cannot classify is treated as a live worker, not as an all-clear.
function Test-AppPoolWorkersGone {
    param(
        [AllowNull()][AllowEmptyString()]$AppcmdWpOutput,
        [Parameter(Mandatory = $true)][string]$AppPool
    )
    $text = (@($AppcmdWpOutput) | ForEach-Object { if ($null -eq $_) { "" } else { $_.ToString() } }) -join "`n"
    foreach ($line in ($text -split "`r?`n")) {
        $t = $line.Trim()
        if ($t -eq '') { continue }
        # appcmd prints: WP "1234" (applicationPool:SomePool)
        $m = [regex]::Match($t, '^WP\s+"[^"]*"\s+\(applicationPool:(?<pool>.*)\)\s*$')
        if (-not $m.Success) {
            # An error message, a localized banner, anything we do not recognise.
            return $false
        }
        if ($m.Groups['pool'].Value -eq $AppPool) { return $false }
    }
    return $true
}

# Stop $AppPool and WAIT for its worker to die. Returns $true when the pool was
# running and is now gone, $false when there was no such pool. THROWS if a
# worker is still alive after $TimeoutSeconds -- continuing would mean claiming
# and hashing a tree that a live gMSA process still holds handles into.
function Stop-AppPoolAndWait {
    param(
        [Parameter(Mandatory = $true)][string]$AppcmdExe,
        [Parameter(Mandatory = $true)][string]$AppPool,
        [int]$TimeoutSeconds = 60
    )
    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path -LiteralPath $AppcmdExe)) { return $false }
    # "appcmd said nothing" and "appcmd could not answer" are NOT the same thing.
    #
    # This used to be `& $AppcmdExe list apppool "$AppPool" 2>$null`, which
    # discards stderr and ignores the exit code, so an appcmd that FAILED --
    # a broken applicationHost.config, WAS not running, access denied -- was
    # indistinguishable from "no such pool". The installer then printed
    # "[ok] no such app pool yet (first install)" and went on to claim, reset and
    # rebuild trees that a live gMSA worker may hold write handles into. Windows
    # evaluates access at handle-open time, so those handles survive the ACL
    # reset: that is rescan-2 F3, reached through the check that exists to
    # prevent it. Test-AppPoolWorkersGone two lines below already fails closed on
    # unparseable input for exactly this reason.
    #
    # Deliberately keyed on STDERR rather than the exit code: appcmd's exit code
    # for a non-existent object is not something this can verify off Windows,
    # while "wrote nothing to stderr" cleanly separates the two cases either way.
    $probeEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $probe = & $AppcmdExe list apppool "$AppPool" 2>&1
    } finally {
        $ErrorActionPreference = $probeEap
    }
    $probeErr = (@($probe) |
        Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } |
        ForEach-Object { $_.ToString() }) -join "`n"
    # STDOUT only. Building this from every element folded the ErrorRecords back
    # in, so $exists was never empty whenever stderr had fired -- which made the
    # $probeErr clause below dead code that happened to produce the right answer.
    # A mutation removing that clause changed nothing, which is how it was found.
    $exists = (@($probe) |
        Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } |
        ForEach-Object { $_.ToString() }) -join "`n"
    # ONLY a clean, silent answer means "no such pool".
    #
    # The first version of this guard THREW on any stderr, which would have
    # aborted every first install: `appcmd list apppool <absent>` writes
    # `ERROR ( message:Cannot find APPPOOL object with identifier ... )` to
    # stderr and exits non-zero, and the installer does not create the pool until
    # ~800 lines below here, so on a first install the pool is absent BY
    # CONSTRUCTION. That is the same shape as the netsh catch-all defect: a guard
    # that only the untravelled path reaches.
    #
    # Ambiguity is resolved by doing MORE work rather than less. If anything
    # reached stderr we do not decide at all -- we fall through to stop the pool
    # and PROVE the worker is gone, which is the check that actually matters.
    # Test-AppPoolWorkersGone fails closed on output it cannot classify, so an
    # unanswerable appcmd ends in the timeout throw below rather than in a silent
    # "[ok] no such app pool yet". Nothing here depends on appcmd's exit code or
    # on the wording of a localizable message.
    if (-not $exists.Trim() -and -not $probeErr.Trim()) { return $false }
    & $AppcmdExe stop apppool /apppool.name:"$AppPool" 2>$null | Out-Null
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $wp = & $AppcmdExe list wp 2>$null
        if (Test-AppPoolWorkersGone -AppcmdWpOutput $wp -AppPool $AppPool) { return $true }
        if ((Get-Date) -ge $deadline) {
            throw ("Stop-AppPoolAndWait: app pool `"$AppPool`" still has a live worker process after " +
                   "$TimeoutSeconds s. Its identity (the gMSA) holds write handles into the install " +
                   "tree that survive the ACL reset, so the runtime cannot be claimed or verified " +
                   "safely. Stop the pool (or the w3wp process) by hand and re-run.")
        }
        Start-Sleep -Seconds 2
    }
}


# --- Daybreak round 5 (2026-08-15): five findings on the round-4 fixes -------
#
#   H   a file raced into a FRESHLY CREATED root while it still inherited the
#       parent's Users-create DACL rode the whole claim (the claim proof has no
#       -ProtectedEntries, so a plain inherited-DACL dotenv passes the tree
#       walk) and was then preserved by the no-clobber branch -- the round-4
#       collision fix closed the DIRECTORY race, not the FILE race.
#   M   Get-PathRelation compared raw strings: dot segments, forward slashes,
#       8.3 short names and junction aliases read as "disjoint" while Windows
#       resolves them to the same tree, collapsing the RX/Modify boundary.
#   M   PATH-resolved interpreter candidates executed elevated with no
#       provenance check on the file or its ancestor chain.
#   M   SitePath/web.config (the gMSA launch configuration) adopted whatever
#       was already on disk; the state-tree processPath check was warning-only
#       and unparseable XML bypassed even the warning.

# Kernel-resolved final path (junctions, symlinks, 8.3 names, case) for an
# EXISTING file or directory. Windows-only; returns $null when the handle or
# the query fails. Compiled once per session.
if (-not ('ACMERA.FinalPath' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text;
namespace ACMERA {
    public static class FinalPath {
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle hFile, StringBuilder sb, uint cap, uint flags);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
        public static string Resolve(string path) {
            using (SafeFileHandle h = CreateFileW(path, 0x80000000, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
                if (h.IsInvalid) { return null; }
                StringBuilder sb = new StringBuilder(1024);
                uint n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
                if (n == 0 || n >= (uint)sb.Capacity) { return null; }
                return sb.ToString();
            }
        }
    }
}
"@
}

# Canonical string form of a path, existing or not:
#   * drive-absolute and UNC inputs are normalised lexically (forward slashes,
#     dot segments, duplicate separators) so the same rules apply on any test
#     platform -- GetFullPath would treat a Windows path as RELATIVE on Linux;
#   * genuinely relative inputs are made absolute against the CWD (GetFullPath);
#   * on Windows, the deepest EXISTING ancestor is additionally resolved
#     through the kernel, so junctions, symlinks and 8.3 short names in the
#     middle of the path cannot alias one tree as two. The non-existent tail
#     cannot host a pre-made alias: if it existed, it would be the resolved
#     ancestor, and a reparse point planted there is a provenance refusal in
#     its own right before anything executes.
function Get-CanonicalPathString {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path)
    if (-not $Path) { return '' }
    if ($Path -match '^[A-Za-z]:[\\/]' -or $Path -match '^[A-Za-z]:$' -or $Path.StartsWith('\\')) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($seg in ($Path -split '[\\/]')) {
            if ($seg -eq '' -or $seg -eq '.') { continue }
            if ($seg -eq '..') {
                if ($parts.Count -gt 1) { $parts.RemoveAt($parts.Count - 1) }
                continue
            }
            $parts.Add($seg)
        }
        if ($parts.Count -eq 0) { return '' }
        $full = ($parts -join '\')
        if ($Path.StartsWith('\\') -and -not $full.StartsWith('\\')) { $full = '\\' + $full }
    } else {
        try { $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\') } catch { return $Path }
    }
    # Also off $env:OS: with it unset on a real Windows host this skipped kernel
    # final-path resolution entirely, so a junction, symlink or 8.3 alias would
    # not be collapsed and two spellings of one physical tree could read as
    # 'disjoint' -- which is the RX/Modify boundary between the code and state
    # roots. Fail-open in the same shape as the scratch guard, one function over.
    if ($script:InstallVerifyIsWindows) {
        $segs = @($full -split '\\') | Where-Object { $_ }
        for ($i = $segs.Count; $i -ge 1; $i--) {
            $prefix = ($segs[0..($i - 1)] -join '\')
            if ($i -eq 1 -and $segs[0] -match '^[A-Za-z]:$') { break }
            if (Test-Path -LiteralPath $prefix) {
                $resolved = [ACMERA.FinalPath]::Resolve($prefix)
                if ($resolved) {
                    $resolved = ($resolved -replace '^\\\\\?\\', '').TrimEnd('\')
                    $tail = if ($i -lt $segs.Count) { '\' + ($segs[$i..($segs.Count - 1)] -join '\') } else { '' }
                    return ($resolved + $tail)
                }
                throw "Kernel final-path resolution failed for existing path '$prefix'; refusing lexical fallback."
            }
        }
    }
    return $full
}

# Trustees whose WRITE-class access to executable content means "not
# administrator-only". CREATOR OWNER is deliberately absent: a CREATOR OWNER
# ACE only ever benefits whoever created the object (SYSTEM or TrustedInstaller
# for a real install), and it appears on %ProgramFiles% and %SystemDrive%
# roots, whose Users ACEs are read/execute or (IO)-flagged; flagging it would
# condemn every legitimate location. The gMSA and the running administrator
# are added by callers where appropriate.
function Resolve-IdentitySidValue {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $null }
    $candidate = $Identity.Trim().TrimStart('*')
    if ($candidate -match '^S-1-\d+(-\d+)+$') { return $candidate }
    $wellKnown = @{
        'Everyone' = 'S-1-1-0'
        'BUILTIN\Users' = 'S-1-5-32-545'
        'BUILTIN\Administrators' = 'S-1-5-32-544'
        'NT AUTHORITY\Authenticated Users' = 'S-1-5-11'
        'NT AUTHORITY\Interactive' = 'S-1-5-4'
        'NT AUTHORITY\Batch' = 'S-1-5-3'
        'NT AUTHORITY\SYSTEM' = 'S-1-5-18'
        'NT SERVICE\TrustedInstaller' = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    }
    foreach ($name in $wellKnown.Keys) {
        if ($candidate -ieq $name) { return $wellKnown[$name] }
    }
    try {
        return (New-Object System.Security.Principal.NTAccount($candidate)).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
}

# Pure decision over one ACE's raw fields (identity, rights, type, inheritance
# flags): does it endanger the BYTES of an object in the tree (create/replace/
# rewrite/re-ACL)? Taking primitives rather than a FileSystemAccessRule keeps
# it drivable from the Linux Pester run, which cannot construct ACL objects.
#
#   * WriteData on a directory is CreateFiles: an attacker can plant content.
#   * AppendData on a directory is only CreateDirectories UNLESS the ACE is
#     object-inherit, in which case it lands on files as byte-append.
#   * Delete / DeleteSubdirectoriesAndFiles allow replace-by-recreate.
#   * WriteDacl/WriteOwner/ChangePermissions/TakeOwnership allow re-ACL to
#     full control; FullControl/Modify/GenericWrite/GenericAll supersets.
function Test-AceEndangersBytes {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Identity,
        [Parameter(Mandatory = $true)][int]$Rights,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$AceType,
        [Parameter(Mandatory = $true)][int]$InheritanceFlags,
        [Parameter(Mandatory = $true)][int]$PropagationFlags,
        [Parameter(Mandatory = $true)][bool]$IsDirectory,
        [string[]]$AllowedWriterSids = @('S-1-5-32-544', 'S-1-5-18',
            'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    )
    if ($AceType -ne 'Allow') { return $false }
    # INHERIT_ONLY ACEs do not apply to THIS object (live-probed 2026-08-15:
    # C:\ carries Users (CI)(IO) CreateFiles -- it does not let anyone write
    # INTO C:\'s existing protected children, and where it does land -- a
    # freshly created first-level directory shows an APPLICABLE Users
    # CreateFiles -- the chain walk sees the landed copy on that child and
    # flags it there. Honouring IO here is what keeps C:\ itself clean
    # without whitewashing the directories the write actually reaches.
    if (($PropagationFlags -band [int][System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
        return $false
    }
    # The mask carries only bits that are dangerous ON THEIR OWN. FullControl
    # (0x1F01FF) and Modify (0x301BF) are deliberately NOT in it wholesale:
    # both contain AppendData, which is only CreateDirectories on a directory
    # unless it reaches files -- a real FullControl/Modify ACE always also
    # carries WriteData/Delete/DeleteChild, so it flags through those bits
    # without dragging AppendData (or the read bits) along.
    # Raw generic bits (observed from Get-Acl on the live host): GenericRead
    # 0x80000000, GenericWrite 0x40000000, GenericExecute 0x20000000,
    # GenericAll 0x10000000. Only the write/all two belong here -- the first
    # live run shipped 0x80000000 as "GenericAll" and flagged every %ProgramFiles%
    # Users GR,GE ACE as write-class.
    # ChangePermissions (0x40000) and TakeOwnership (0x80000) ARE WRITE_DAC and
    # WRITE_OWNER -- those are the FileSystemRights member names. The enum has no
    # WriteDacl and no WriteOwner member, so those spellings silently evaluate to
    # $null and contribute 0 to a -bor chain. This mask used to list both pairs;
    # the dead half has been removed because carrying it here is what made the
    # installer's inline bootstrap copy (which listed ONLY the dead half) look
    # correct while covering neither right.
    $mask = [int][System.Security.AccessControl.FileSystemRights]::WriteData -bor
             [int][System.Security.AccessControl.FileSystemRights]::Delete -bor
             [int][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
             [int][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
             [int][System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
             0x40000000 -bor 0x10000000      # GenericWrite, GenericAll raw bits
    $inheritObject = ($InheritanceFlags -band [int][System.Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0
    if ($inheritObject) {
        $mask = $mask -bor [int][System.Security.AccessControl.FileSystemRights]::AppendData
    }
    if (-not $IsDirectory) {
        # On a file, AppendData is byte-append: always dangerous.
        $mask = $mask -bor [int][System.Security.AccessControl.FileSystemRights]::AppendData
    }
    if (($Rights -band $mask) -eq 0) { return $false }

    # Provenance is an allowlist, not a list of familiar broad groups.  A
    # named low-privilege user or custom domain group with FullControl is just
    # as able to replace executable bytes as Everyone.  Resolve every identity
    # to a SID and fail closed when a dangerous ACE cannot be resolved.
    $sid = Resolve-IdentitySidValue -Identity $Identity
    if ($null -eq $sid) { return $true }
    foreach ($allowed in @($AllowedWriterSids)) {
        if ($sid -ieq $allowed) { return $false }
    }
    return $true
}

# Owners that may hold executable content or its containers, as SIDs
# (Test-OwnerAllowed compares SID-to-SID). The running administrator's own
# account owns their profile tree (AppData\Local), which no other local user
# can write, so it is allowed for that chain; TrustedInstaller owns the
# %ProgramFiles% roots a real machine-wide install lives under.
function Get-AllowedExecutableOwners {
    $names = @('S-1-5-32-544', 'S-1-5-18', 'NT SERVICE\TrustedInstaller',
               'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')
    try {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        if ($me) { $names += $me }
    } catch { }
    $sids = @()
    foreach ($n in $names) {
        if ($n -match '^S-1-\d+(-\d+)+$') { $sids += $n; continue }
        try {
            $sids += (New-Object System.Security.Principal.NTAccount($n)).Translate(
                [System.Security.Principal.SecurityIdentifier]).Value
        } catch { }
    }
    return $sids
}

# One object's owner + DACL as violations against the "administrator-only
# bytes" rule. Empty list = trusted. Every write-capable ACE is checked against
# the authorized-writer SID allowlist, so callers do not maintain a second
# denylist of principals that happen to be familiar.
function Test-ObjectDaclTrusted {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )
    $violations = @()
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $Path } catch { return @("$Path : ACL unreadable ($($_.Exception.Message))") }
    $isDir = (Test-Path -LiteralPath $Path -PathType Container)
    # NO ACE AT ALL IS A REFUSAL, not a pass.
    #
    # This function decided trust purely from inside the foreach below, so an
    # empty rule collection produced zero violations and the object was called
    # administrator-only. A NULL DACL -- SE_DACL_PRESENT clear -- means EVERYONE
    # HAS FULL CONTROL, and .NET surfaces it exactly like a deny-everyone empty
    # DACL: Access.Count is 0 either way. Sloppy third-party installers do
    # produce NULL DACLs, and one anywhere in the interpreter's ancestor chain
    # reopened round 5's finding: the chain reports clean, the installer runs
    # python.exe from it elevated, and every local user could rewrite those
    # bytes.
    #
    # Test-AclDumpLocked already treats this condition as tampering and fails
    # closed on it ("DACL carries no ACEs"), so the file disagreed with itself.
    # Both directions of the same question now give the same answer.
    if (@($acl.Access).Count -eq 0) {
        $violations += ("$Path : DACL carries no ACEs -- a NULL DACL grants EVERYONE full control " +
                        "and is indistinguishable here from a deny-everyone one; both fail closed")
    }
    if (-not (Test-OwnerAllowed -Owner $acl.Owner -AllowedOwnerSids @(Get-AllowedExecutableOwners))) {
        $violations += "$Path : owner is '$($acl.Owner)' (expected Administrators, SYSTEM or TrustedInstaller)"
    }
    foreach ($rule in $acl.Access) {
        $identity = ''
        try { $identity = $rule.IdentityReference.Value } catch { }
        $flag = Test-AceEndangersBytes -Identity $identity `
            -Rights ([int]$rule.FileSystemRights) `
            -AceType ([string]$rule.AccessControlType) `
            -InheritanceFlags ([int]$rule.InheritanceFlags) `
            -PropagationFlags ([int]$rule.PropagationFlags) `
            -IsDirectory $isDir `
            -AllowedWriterSids @(Get-AllowedExecutableOwners)
        if ($flag) {
            $violations += ("$Path : '$identity' holds write-class access " +
                            "('$($rule.FileSystemRights)') -- a non-administrator can replace or rewrite bytes here")
        }
    }
    return $violations
}

# The FULL provenance gate for a file we are about to execute elevated: the
# file itself plus every existing ancestor directory up to the drive root must
# be administrator-only. Observed-baseline semantics (live host, 2026-08-15):
# C:\ passes (its Users write ACEs are (IO)-only or CreateDirectories-only);
# C:\Program Files passes (Users RX); C:\ProgramData FAILS (non-IO
# Users CreateFiles on subdirectories); a user profile passes (owner+admins).
function Test-PathChainTrusted {
    param([Parameter(Mandatory = $true)][string]$Path)
    $violations = @()
    $p = $Path
    $guard = 0
    while ($p -and $guard -lt 32) {
        $guard++
        if (Test-Path -LiteralPath $p) {
            $violations += Test-ObjectDaclTrusted -Path $p
        }
        $parent = Split-Path -Parent $p
        if ($parent -eq $p) { break }
        $p = $parent
    }
    return @($violations | Where-Object { $_ })
}

# Fail-closed validation of the web.config the gMSA pool will launch from.
# web.config IS launch configuration: httpPlatform/@processPath names the
# executable IIS starts as the gMSA. Round 5: this used to be a warning whose
# XML parse failure was silently swallowed -- a pre-planted or half-migrated
# web.config kept launching an interpreter inside the gMSA-writable state
# tree. Now: unparseable/unreadable = refuse (we cannot prove it safe), a
# processPath inside the STATE tree = refuse, and a processPath outside the
# RUNTIME tree = refuse (the runtime tree is the only executed tree; that is
# the whole code/state control).
function Assert-WebConfigLaunchTrusted {
    param(
        [Parameter(Mandatory = $true)][string]$WebConfigPath,
        [Parameter(Mandatory = $true)][string]$InstallDir,
        [Parameter(Mandatory = $true)][string]$RuntimeDir,
        [Parameter(Mandatory = $true)][string]$ExpectedProcessPath
    )
    $ErrorActionPreference = 'Stop'
    $raw = ''
    try { $raw = Get-Content -LiteralPath $WebConfigPath -Raw } catch {
        throw ("$WebConfigPath could not be read ($($_.Exception.Message)). It is the gMSA launch " +
               "configuration; an unreadable launch configuration is refused, not adopted.")
    }
    $xml = $null
    try { $xml = [xml]$raw } catch {
        throw ("$WebConfigPath is not parseable XML ($($_.Exception.Message)). It is the gMSA " +
               "launch configuration; an unparseable launch configuration is refused, not adopted.")
    }
    # EVERY httpPlatform node, not the first one a dotted property lookup finds.
    #
    # `$xml.configuration.'system.webServer'.httpPlatform` reads exactly one
    # place in the document. A `<location>` element carrying its own
    # `<system.webServer><httpPlatform processPath="...">` is invisible to it, so
    # a web.config with a benign top-level processPath and a hostile
    # location-scoped override was accepted. SelectNodes('//httpPlatform') sees
    # all of them and the loop below holds each to the same rules.
    # local-name() so a default xmlns on <configuration> (VS and older tooling
    # emit .NetConfiguration/v2.0) does not make SelectNodes return zero nodes
    # and produce a 'there is no httpPlatform' diagnostic about a file that
    # plainly has one. Fail-closed either way, but the message must be true.
    $platformNodes = @($xml.SelectNodes("//*[local-name()='httpPlatform']"))
    if (@($platformNodes).Count -eq 0) {
        throw ("$WebConfigPath has no httpPlatform/@processPath. The gMSA launch configuration " +
               "must name an executable, and it must be the runtime venv: " +
               "`"$ExpectedProcessPath`".")
    }

    # Environment variable names that decide what the RA may ISSUE, or where it
    # reads that decision from. web.config <environmentVariables> reach the
    # worker's environment, and pydantic-settings ranks an environment variable
    # ABOVE the dotenv -- so an ACME_RA_EAB_ALLOWLIST here silently overrides the
    # one in acme-ra.env, the file this installer protects with its own DACL, a
    # strict owner check, a rollback re-protect and a dedicated -ProtectedEntries
    # proof. Redirecting ACME_RA_DOTENV achieves the same in one line.
    # ACME_RA_BASE_URL, ACME_RA_ADCS_* and the SIEM settings are deliberately NOT
    # here: those are the operator's to set in this file and the template ships
    # them.
    $forbiddenEnvNames = @(
        'ACME_RA_EAB_ALLOWLIST', 'ACME_RA_SAN_SCOPES', 'ACME_RA_ADMIN_TOKEN',
        'ACME_RA_REVOCATION_CONFIRM_TOKEN', 'ACME_RA_ALLOW_WEAK_CREDENTIALS',
        'ACME_RA_RATE_LIMIT_OVERRIDES',
        'ACME_RA_ALLOW_FAKE_ADCS_BACKENDS'
    )
    # Settings with exactly ONE defensible production value. Unlike the base URL,
    # the ADCS target or the SIEM host -- which are per-deployment and are the
    # operator's to set here -- turning these off only ever removes a control.
    # ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE is pinned-when-present,
    # not forbidden outright: absent, the worker defers to the dotenv/default
    # (the documented optional mode); PRESENT with any value but "true", the
    # only thing it can do is override a dotenv that turned the CRL proof ON
    # back to the weaker agent-asserted confirmation -- and this file outranks
    # the dotenv, so that override would be silent. The lab harness sets it to
    # true here, which is the one present-value that passes.
    $pinnedEnvValues = @{
        'ACME_RA_AUDIT_OFFBOX_REQUIRED' = 'true'
        'ACME_RA_REVOCATION_CONFIRM_REQUIRE_CRL_EVIDENCE' = 'true'
    }

    # <handlers> IS launch configuration too, and the installer itself is what
    # makes a site-level entry authoritative: it runs
    # `appcmd unlock config -section:system.webServer/handlers`. A handler with a
    # scriptProcessor executes an arbitrary binary as the app pool identity --
    # the gMSA -- which is the same primitive that pinning processPath removes,
    # reached through a section nothing looked at.
    foreach ($h in @($xml.SelectNodes("//*[local-name()='handlers']/*"))) {
        if ($h.LocalName -ieq 'clear' -or $h.LocalName -ieq 'remove') { continue }
        $sp = [string]$h.scriptProcessor
        if ($sp) {
            throw ("$WebConfigPath declares a handler with scriptProcessor `"$sp`". That runs " +
                   "an arbitrary executable as the gMSA, which is exactly what pinning " +
                   "httpPlatform/@processPath exists to prevent. Remove the handler entry.")
        }
        $mods = [string]$h.modules
        if ($mods -and ($mods.Trim() -ne 'httpPlatformHandler')) {
            throw ("$WebConfigPath declares a handler bound to modules `"$mods`". This site " +
                   "hands every request to httpPlatformHandler and nothing else; another " +
                   "module in the launch configuration is refused, not adopted.")
        }
    }
    foreach ($sectionName in @('modules', 'isapiFilters')) {
        $entries = @(@($xml.SelectNodes("//*[local-name()='$sectionName']/*")) |
            Where-Object { $_.LocalName -ine 'clear' -and $_.LocalName -ine 'remove' })
        if (@($entries).Count -gt 0) {
            throw ("$WebConfigPath declares a <$sectionName> entry. Native code loaded into " +
                   "the worker runs as the gMSA; the launch configuration may name the RA " +
                   "module and nothing else.")
        }
    }

    $sawDotenv = $false
    foreach ($node in $platformNodes) {
        $procPathRaw = [string]$node.processPath
        # Normalise separators ONCE, before any of the checks below: IIS and
        # Python both accept `C:/Program Files/...`, and Get-PathRelation ->
        # Assert-SafeLocalInstallPath refuses '/' outright, so a forward-slash
        # processPath aborted the install with "must be absolute local drive
        # paths" about a path that is one. Messages still quote what the operator
        # actually wrote.
        $procPath = $procPathRaw -replace '/', '\'
        if (-not $procPath) {
            throw ("$WebConfigPath has an httpPlatform element with no processPath. The gMSA " +
                   "launch configuration must name an executable, and it must be " +
                   "`"$ExpectedProcessPath`".")
        }
        if (Test-PathInsideTree -Path $procPath -Tree $InstallDir) {
            throw ("$WebConfigPath launches `"$procPathRaw`", which is INSIDE the state tree $InstallDir. " +
                   "The gMSA holds Modify on that tree: a worker-writable interpreter is exactly what " +
                   "the code/state split removes. Set processPath to `"$ExpectedProcessPath`" " +
                   "(docs/operator-requirements.md section 4, step 8).")
        }
        if (-not (Test-PathInsideTree -Path $procPath -Tree $RuntimeDir)) {
            throw ("$WebConfigPath launches `"$procPathRaw`", which is OUTSIDE the runtime tree $RuntimeDir. " +
                   "The runtime tree is the only tree whose bytes the gMSA never writes and the only " +
                   "tree permitted to hold executed content. Set processPath to " +
                   "`"$ExpectedProcessPath`" (docs/operator-requirements.md section 1).")
        }
        # "Inside the runtime tree" is not the same as "is the interpreter this
        # install built". $ExpectedProcessPath was a MANDATORY parameter that
        # appeared only inside these error strings and was never compared to
        # anything, so any executable anywhere under the runtime tree passed.
        if (-not (Test-PathsEquivalent -A $procPath -B $ExpectedProcessPath)) {
            throw ("$WebConfigPath launches `"$procPathRaw`", which is not the interpreter this " +
                   "install built. Set processPath to exactly `"$ExpectedProcessPath`" " +
                   "(docs/operator-requirements.md section 4, step 8).")
        }
        # `arguments` is the rest of the command line for that interpreter, so
        # leaving it unread meant `-c "<any python>"` launched as the gMSA with a
        # processPath that passed every check above. Only the module launch the
        # RA actually uses is accepted.
        $args = [string]$node.arguments
        # Collapse internal whitespace before comparing: `-m  acme_adcs_ra` runs the
        # same module, and aborting the install of a live issuance host over a
        # double space is not a security outcome.
        $argsNorm = ($args -replace '\s+', ' ').Trim()
        if ($argsNorm -ne '-m acme_adcs_ra') {
            $shownArgs = if ($args) { '"' + $args + '"' } else { 'no arguments at all' }
            throw ("$WebConfigPath launches the runtime interpreter with $shownArgs. The " +
                   "gMSA launch configuration must run the RA module and nothing else: set " +
                   "arguments to `"-m acme_adcs_ra`".")
        }
        # EVERY element child of <environmentVariables>, not only those literally
        # named <environmentVariable>. IIS collections commonly also honour
        # <add>/<clear>/<remove>, and reading one element name meant
        # `<environmentVariables><add name="ACME_RA_EAB_ALLOWLIST" .../></...>`
        # was never examined at all.
        foreach ($ev in @($node.SelectNodes(".//*[local-name()='environmentVariables']/*"))) {
            $name = [string]$ev.name
            if (-not $name) { continue }
            # SPLIT ON THE NESTED DELIMITER BEFORE MATCHING.
            #
            # config.py sets env_nested_delimiter='__', so pydantic-settings reads
            # ACME_RA_SAN_SCOPES__<kid>__DNS_PATTERNS as a path INTO san_scopes.
            # An exact-string match against the forbidden list walked straight
            # past it: verified live, a nested variable replaced the protected
            # dotenv's dns_patterns for an existing kid, which IS that kid's
            # issuance authorisation, while the installer printed
            # "[ok] launch configuration verified". Compare the FIRST segment.
            $upper = $name.ToUpperInvariant()
            $rootName = $upper
            if ($upper.StartsWith('ACME_RA_')) {
                $rootName = 'ACME_RA_' + (($upper.Substring(8) -split '__')[0])
            }
            if ($pinnedEnvValues.ContainsKey($rootName)) {
                $wantValue = $pinnedEnvValues[$rootName]
                if (([string]$ev.value).Trim().ToLowerInvariant() -ne $wantValue) {
                    throw ("$WebConfigPath sets `"$name`" to `"$($ev.value)`" in " +
                           "<environmentVariables>. That setting has one production value " +
                           "(`"$wantValue`") and this file is not a protected one; the only " +
                           "thing another value can do is remove a control.")
                }
                continue
            }
            if ($forbiddenEnvNames -contains $rootName) {
                throw ("$WebConfigPath sets `"$name`" in <environmentVariables>. An environment " +
                       "variable outranks the dotenv, so this silently overrides the value in " +
                       "the protected acme-ra.env -- which is what decides who may enrol and " +
                       "for which names. Remove it from web.config and set it in the dotenv.")
            }
            if ($rootName -match '^PYTHON(PATH|HOME|STARTUP)$') {
                throw ("$WebConfigPath sets `"$name`" in <environmentVariables>. That redirects " +
                       "what the gMSA interpreter imports, which makes the runtime tree's " +
                       "read-only DACL decorative. Remove it.")
            }
            if ($rootName -eq 'ACME_RA_DOTENV') {
                $sawDotenv = $true
                # String concat, not Join-Path: Join-Path is provider-aware and throws
                # "Cannot find drive" for a Windows path on a non-Windows host, which
                # would make this whole gate unrunnable from the Linux Pester job.
                $want = ($InstallDir.TrimEnd('\') + '\acme-ra.env')
                if (-not (Test-PathsEquivalent -A ([string]$ev.value) -B $want)) {
                    throw ("$WebConfigPath points ACME_RA_DOTENV at `"$($ev.value)`" rather than " +
                           "the protected `"$want`". The secret-bearing file is the one the " +
                           "installer locks and proves; a different path is neither.")
                }
            }
        }
    }
    # Declared, not merely correct-if-declared. With no ACME_RA_DOTENV the worker
    # falls back to `.env` resolved against its own working directory, so the
    # protected file this installer locks, owns, re-protects on rollback and
    # proves as a -ProtectedEntries item is simply not the file the RA reads.
    if (-not $sawDotenv) {
        $wantDotenv = ($InstallDir.TrimEnd('\') + '\acme-ra.env')
        throw ("$WebConfigPath does not set ACME_RA_DOTENV. Without it the RA resolves " +
               "`".env`" against the worker's own working directory instead of reading the " +
               "protected `"$wantDotenv`" -- the only file the installer locks and proves. " +
               "Add it to <environmentVariables>.")
    }
}

# Lock a root this run JUST created (New-Item already succeeded, no -Force):
# protect the DACL immediately, prove the directory is empty, normalise the
# root's owner -- all WITHOUT Reset-TreeToInherited, whose /reset would strip
# the DACL again and reopen the window this exists to close.
#
# The race this closes (round 5, high): between New-Item and the old claim's
# protect step sat a reparse walk and a recursive setowner/reset, during which
# the fresh directory still INHERITED the parent's Users-create rights. A file
# planted there rode the claim (the claim proof verifies shape, and a plain
# inherited-DACL dotenv has exactly the shape the tree walk expects of a
# descendant), survived setowner as Administrators-owned, and was then
# preserved by the no-clobber branch -- shipping an attacker-chosen EAB
# allowlist and SAN scope. Here the only writable interval is New-Item to the
# single atomic DACL swap, and the emptiness check catches anything that
# slipped through it: after the swap Users hold no create right, so nothing
# new can appear.
