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
    if ($kind -eq 'https' -and [string]::IsNullOrWhiteSpace($Sha256)) {
        throw "Refusing to download the HttpPlatformHandler MSI without -HttpPlatformHandlerSha256. " +
              "HTTPS authenticates the origin, not the bytes: supply the expected SHA-256 out of band " +
              "(Microsoft publishes it; or hash a copy you have already vetted)."
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

# Whether a destination-local interpreter may be trusted enough to execute.
#
# Only once the root is provably ours: the directory existed with acceptable
# attributes AND we have (re)asserted the restrictive ACL on it. `$RootSecured`
# is the installer's assertion that the second step completed. Passing $false
# means "we have not claimed this directory yet", and the answer is always no --
# which is precisely the window the finding exploited.
function Test-DestinationInterpreterTrusted {
    param(
        [Parameter(Mandatory = $true)][bool]$RootSecured,
        [Parameter(Mandatory = $true)][AllowNull()]$InterpreterAttributes
    )
    if (-not $RootSecured) { return $false }
    if ($null -eq $InterpreterAttributes) { return $false }
    $a = [System.IO.FileAttributes]$InterpreterAttributes
    if ($a.HasFlag([System.IO.FileAttributes]::ReparsePoint)) { return $false }
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

# Take ownership of a whole tree for the Administrators group and discard every
# explicit ACE in it. Runs elevated; THROWS on any failure (fail closed: a
# partial reset leaves attacker ACEs behind, so partial is refused).
#
# takeown is the only primitive that works on a hostile tree: the attacker's
# DACL can deny Administrators WRITE_DAC outright, but the elevated token holds
# SeTakeOwnership/SeRestore, which takeown enables itself. /a assigns the
# Administrators GROUP (not the invoking admin account) -- matching how the
# rest of the install addresses the ACEs. /d answers takeown's "directory you
# cannot list" prompt: the documented letter is Y (English locale); on a
# localized Windows the accepted letter can differ, and the exit-code check
# turns that into a loud abort rather than a silently partial reset.
function Reset-TreeToInherited {
    param([Parameter(Mandatory = $true)][string]$Path)
    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Reset-TreeToInherited: $Path does not exist; nothing to reset."
    }
    # /L (Daybreak 2026-08-15 rescan F2): operate on links THEMSELVES, never
    # their targets. takeown below has no /L, so the CALLER must have run
    # Assert-NoReparsePoints first -- and Assert-InstallTreeLocked re-walks
    # afterwards to catch anything planted into the window between the two.
    & takeown.exe /f $Path /r /a /d y | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw ("Reset-TreeToInherited: takeown failed on $Path (exit $LASTEXITCODE). " +
               "Ownership could not be established for the Administrators group; refusing to continue.")
    }
    # /reset replaces each object's DACL with the default INHERITED one, which
    # discards every explicit ACE -- the attacker's included -- and clears DACL
    # protection tree-wide. Descendants become pure inheritors, so the caller's
    # protected root DACL propagates to all of them.
    & icacls.exe $Path /reset /t /c /q /L | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw ("Reset-TreeToInherited: icacls /reset failed on $Path (exit $LASTEXITCODE). " +
               "Explicit ACEs may have survived; refusing to continue.")
    }
}

# Give ONE object a deterministic, protected DACL: drop every explicit ACE it
# carries (/reset -- the same trap as the tree: /inheritance:r alone leaves
# explicit ACEs untouched), then protect it with EXACTLY the grants given.
# The caller must already own the object (Reset-TreeToInherited for anything
# under the install root). THROWS on failure.
function Set-ObjectProtectedDacl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Grants
    )
    $ErrorActionPreference = 'Stop'
    & icacls.exe $Path /reset /q | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Set-ObjectProtectedDacl: icacls /reset failed on $Path (exit $LASTEXITCODE)."
    }
    & icacls.exe $Path /inheritance:r /grant:r @Grants | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw ("Set-ObjectProtectedDacl: icacls /inheritance:r /grant:r failed on " +
               "$Path (exit $LASTEXITCODE) with grants: $($Grants -join ' ').")
    }
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
        if ($line.StartsWith('D:')) {
            if ($null -ne $currentPath) { $currentSddl += $line.Trim() }
            continue
        }
        if ($null -ne $currentPath -and $currentSddl -ne '') {
            $entries.Add(@{ Path = $currentPath; Sddl = $currentSddl })
        }
        $currentPath = $line.Trim()
        $currentSddl = ''
    }
    if ($null -ne $currentPath -and $currentSddl -ne '') {
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
function Assert-InstallTreeLocked {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$AllowedTrustees,
        [hashtable]$ProtectedEntries = @{}
    )
    $ErrorActionPreference = 'Stop'
    $violations = @()

    # Reparse points anywhere in the tree are an abort in their own right
    # (rescan F2): every recursive read or write below would either traverse
    # the link outside the tree (/L-less operations) or skip it (/L), and
    # either way the tree is not the closed namespace the rest of this proof
    # is about to claim it is.
    Assert-NoReparsePoints -Path $Root -Context 'Assert-InstallTreeLocked'

    $acl = Get-Acl -LiteralPath $Root
    $owner = $acl.Owner
    $ownerSid = $null
    try {
        $ownerSid = (New-Object System.Security.Principal.SecurityIdentifier($owner)).Value
    } catch {
        try {
            $ownerSid = (New-Object System.Security.Principal.NTAccount($owner)).Translate(
                [System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            $ownerSid = $null
        }
    }
    if ($null -eq $ownerSid -or (@('S-1-5-32-544', 'S-1-5-18') -notcontains $ownerSid)) {
        $violations += "$Root : owner is '$owner' (expected Administrators or SYSTEM) -- an owner can rewrite the DACL at any time"
    }

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ra-aclcheck-" + [guid]::NewGuid().ToString('N') + ".txt")
    try {
        # /L: dump the links themselves rather than following them, so the
        # read-back cannot be redirected any more than the writes can.
        & icacls.exe $Root /save $tmp /t /c /q /L | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Assert-InstallTreeLocked: icacls /save failed on $Root (exit $LASTEXITCODE) -- the tree ACL could not be read back; refusing to trust it."
        }
        $dump = Get-Content -LiteralPath $tmp -Raw
        $violations += Test-AclDumpLocked -DumpText $dump `
            -AllowedTrustees $AllowedTrustees -ExemptLeafNames @($ProtectedEntries.Keys)

        foreach ($leaf in @($ProtectedEntries.Keys)) {
            $entryPath = Join-Path $Root $leaf
            if (-not (Test-Path -LiteralPath $entryPath)) { continue }
            $tmpEntry = Join-Path ([System.IO.Path]::GetTempPath()) ("ra-aclcheck-" + [guid]::NewGuid().ToString('N') + ".txt")
            & icacls.exe $entryPath /save $tmpEntry /q /L | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Assert-InstallTreeLocked: icacls /save failed on $entryPath (exit $LASTEXITCODE)."
            }
            $violations += Test-AclDumpLocked -DumpText (Get-Content -LiteralPath $tmpEntry -Raw) `
                -AllowedTrustees @($ProtectedEntries[$leaf]) -AllEntriesMustBeProtected
            Remove-Item -LiteralPath $tmpEntry -Force -ErrorAction SilentlyContinue
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }

    $violations = @($violations) | Where-Object { $_ }
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

# SHA-256 every file under $Root, recursively, as an ordered map
# "<relpath with / separators>" -> "<UPPERCASE sha256>". Sorted by path so the
# manifest is reproducible. Cross-platform on purpose (Get-FileHash), so the
# Pester suite can exercise create/verify round trips on Linux.
function Get-TreeFileHashes {
    param([Parameter(Mandatory = $true)][string]$Root)
    $rootFull = (Resolve-Path -LiteralPath $Root).Path
    $map = [ordered]@{}
    $paths = New-Object System.Collections.Generic.List[string]
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($rootFull)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $di = New-Object System.IO.DirectoryInfo($dir)
        foreach ($e in $di.EnumerateFileSystemInfos()) {
            if ($e.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
            if ($e.Attributes -band [System.IO.FileAttributes]::Directory) {
                $stack.Push($e.FullName)
            } else {
                $paths.Add($e.FullName)
            }
        }
    }
    foreach ($f in ($paths | Sort-Object)) {
        $rel = $f.Substring($rootFull.Length).TrimStart('\', '/') -replace '\\', '/'
        $map[$rel] = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
    }
    return $map
}

# Write the manifest JSON for $Root to $ManifestPath (UTF-8, no BOM). The
# CALLER protects the manifest's DACL immediately afterwards -- against the
# gMSA, which holds Modify over the tree and could otherwise rewrite both the
# interpreter and the manifest that vouches for it.
function Save-TreeManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )
    $map = Get-TreeFileHashes -Root $Root
    $json = $map | ConvertTo-Json -Compress
    [System.IO.File]::WriteAllText($ManifestPath, $json, (New-Object System.Text.UTF8Encoding $false))
    return $map.Count
}

# Strict set-equality verification of $Root against $ManifestPath: every file
# currently in the tree must be manifested with a matching hash, and every
# manifested file must still exist. A planted file, a tampered file, a deleted
# file, a corrupt/missing manifest -- all fail. Returns
# @{ Ok; Reason; Details } so callers can log the first few offenders.
function Test-TreeManifestMatches {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )
    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        return @{ Ok = $false; Reason = 'manifest missing'; Details = @() }
    }
    try {
        $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    } catch {
        return @{ Ok = $false; Reason = 'manifest unreadable/corrupt'; Details = @() }
    }
    $current = Get-TreeFileHashes -Root $Root
    $mflat = @{}
    if ($manifest) {
        foreach ($p in $manifest.PSObject.Properties) { $mflat[$p.Name] = [string]$p.Value }
    }
    $details = New-Object System.Collections.Generic.List[string]
    foreach ($k in $mflat.Keys) {
        if (-not $current.Contains($k)) { $details.Add("manifest entry missing from tree: $k") }
        elseif ($current[$k] -ne $mflat[$k]) { $details.Add("hash mismatch: $k") }
    }
    foreach ($k in $current.Keys) {
        if (-not $mflat.Contains($k)) { $details.Add("unmanifested file in tree: $k") }
    }
    if ($details.Count -gt 0) {
        return @{ Ok = $false; Reason = 'tree does not match manifest'; Details = @($details | Select-Object -First 5) }
    }
    return @{ Ok = $true; Reason = 'verified'; Details = @() }
}
