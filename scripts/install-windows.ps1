<#
STYLE (inherited from cert-watch's installer, same constraints): Never embed
single quotes inside double-quoted strings. PowerShell 5.1 reads this file via
the system ANSI codepage when the UTF-8 BOM is missing (e.g. GitHub zip
download), and multi-byte UTF-8 sequences corrupt the parser's quote-tracking.
Use `" `" (escaped double quotes) or restructure. This script must run on
PowerShell 5.1 (the Windows default): no ?? , no ternary, no && / || .

.SYNOPSIS
    Bootstrap acme-adcs-ra on Windows for hosting behind IIS, running the app
    pool AS A gMSA (passwordless enrollment identity).

.DESCRIPTION
    Adapted from cert-watch/scripts/install-windows.ps1 (same FastAPI/uvicorn
    deployment model on the same VM). When -ConfigureIIS is passed, also
    creates/updates the IIS site, app pool, web.config, and TLS binding.

    THE INSTALL IS SPLIT IN TWO, and the split is a security boundary:

      CODE  -RuntimeDir, default %ProgramFiles%\acme-adcs-ra
            The interpreter and virtualenv, under `current`, rebuilt from
            scratch on every run. The gMSA gets read + execute, never write.
      STATE -InstallDir, default C:\ProgramData\acme-adcs-ra
            Audit DB, logs, secret env file. The gMSA gets modify. Nothing
            here is ever executed.

    Neither root is ever ADOPTED. If a root already exists, it must match what
    a completed install of this RA leaves behind -- same ownership, same DACL
    shape, no reparse points -- or the install refuses and tells you what to
    do. Earlier versions force-claimed a pre-existing directory, and on a path
    a local user can create first, that was a privilege-escalation route.
    See docs/operator-requirements.md.

    THE CENTRAL DIFFERENCE FROM cert-watch: the IIS application pool identity is
    set to the gMSA you pass via -GmsaAccount. The uvicorn worker therefore runs
    as the gMSA, and that ambient Kerberos identity is what authenticates to
    /certsrv/ (Negotiate/SSPI, passwordless). The gMSA must already be installed
    on this host (Install-ADServiceAccount; Test-ADServiceAccount => True).

    Secrets (EAB MAC keys, SIEM HEC token) are NOT generated or taken on the
    command line. The script lays down a locked, no-clobber env file
    (acme-ra.env) that the operator fills with the EAB credential(s) pinned to
    the authorized ACME client. Re-running is safe: the env file and an existing
    web.config are preserved; IIS steps are idempotent.

.PARAMETER GmsaAccount
    The gMSA the app pool runs as, e.g. WORK-DOMAIN\gMSA-acme-ra$ (note the
    trailing $). Required.

.PARAMETER InstallDir
    STATE directory: audit DB, logs, and the secret env file. Nothing here is
    ever executed, and the gMSA has Modify on it because the worker must write
    the database and the log.
    Default: C:\ProgramData\acme-adcs-ra

.PARAMETER RuntimeDir
    CODE directory: the interpreter and the virtualenv, under a `current`
    subdirectory that is rebuilt from scratch on every run. The gMSA gets read
    and EXECUTE here, never write.

    This lives under %ProgramFiles% on purpose, and the split is a security
    boundary rather than tidiness. The default ACL on %ProgramData% grants
    Users "create folders / append data" with CREATOR OWNER inheritance, so any
    local user can pre-create C:\ProgramData\acme-adcs-ra and own it — which is
    how four review rounds' worth of findings began. %ProgramFiles% grants
    Users read and execute only, so the executable half of the install cannot
    be pre-planted at all.
    Default: %ProgramFiles%\acme-adcs-ra

.PARAMETER AppPool / SitePath / HostName / SharePort443 / TlsCertThumbprint
    As in cert-watch's installer. -SharePort443 -HostName lets the RA co-reside
    on port 443 by SNI alongside cert-watch / gpo-lens on this VM.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
        -GmsaAccount "WORK-DOMAIN\gMSA-acme-ra$" -ConfigureIIS `
        -HostName "acme-ra.work-domain.local" -SharePort443 `
        -TlsCertThumbprint "ABCDEF123456..."

.NOTES
    Not signed. Bypass execution policy per-invocation or sign with your org cert.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GmsaAccount,
    [string]$InstallDir = "C:\ProgramData\acme-adcs-ra",
    [string]$RuntimeDir = "$env:ProgramFiles\acme-adcs-ra",
    [string]$AppPool = "acme-adcs-ra",
    [switch]$ConfigureIIS,
    [string]$SitePath = "C:\inetpub\acme-adcs-ra",
    [string]$HostName = "",
    [int]$Port = 443,
    [switch]$SharePort443,
    [string]$TlsCertThumbprint = "",
    # Prerequisite handling. -InstallPrereqs installs the native IIS role and
    # features. Python must be installed separately; this elevated script never
    # runs PATH-selected py/python/winget.
    # HttpPlatformHandler is a third-party MSI with an unreliable download, so it
    # is NEVER auto-fetched from the internet: pass a vetted local path (or an
    # https:// URL plus -HttpPlatformHandlerSha256) via -HttpPlatformHandlerMsi
    # to have it installed. Whatever the source, the MSI is verified by digest
    # and Authenticode publisher before msiexec sees it -- it is the one
    # third-party executable this installer runs, and it runs elevated.
    [switch]$InstallPrereqs,
    [string]$HttpPlatformHandlerMsi = "",
    # Expected SHA-256 of the MSI. REQUIRED for every source. The installer
    # copies/downloads into protected staging, then verifies those exact bytes
    # before msiexec opens them as Administrator on the issuance host.
    [string]$HttpPlatformHandlerSha256 = "",
    # Expected Authenticode publisher, matched as a substring of the signer
    # certificate's Subject. HttpPlatformHandler is a Microsoft IIS module; a
    # deployment that repackages it under its own code-signing certificate
    # overrides this.
    [string]$HttpPlatformHandlerPublisher = "CN=Microsoft Corporation"
)

$ErrorActionPreference = "Stop"

# --- Must be elevated (we write under ProgramData, set ACLs, configure IIS) ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run from an elevated (Administrator) PowerShell."
}

# The installer script is the operator's trust anchor. Before it executes any
# sibling code, consumes a lock file, copies launch configuration, or asks PEP
# 517 to build the project, prove that every consumed repository input and its
# ancestor chain are owned and writable only by the invoking administrator,
# Administrators, SYSTEM, or TrustedInstaller. This bootstrap is deliberately
# inline: dot-sourcing the helper library before proving it would execute the
# very mutable repository input this gate exists to reject.
$repoRoot = (Resolve-Path "$PSScriptRoot\..").Path
function Resolve-BootstrapSid {
    param([Parameter(Mandatory = $true)][string]$Identity)
    $candidate = $Identity.Trim().TrimStart('*')
    if ($candidate -match '^S-1-\d+(-\d+)+$') { return $candidate }
    try {
        return (New-Object System.Security.Principal.NTAccount($candidate)).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
    } catch { return $null }
}
function Assert-BootstrapObjectTrusted {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$AllowedWriterSids,
        [switch]$AncestorOnly
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Installer source input '$Path' is a reparse point; refusing to execute or build from it."
    }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $ownerSid = Resolve-BootstrapSid -Identity $acl.Owner
    if ($null -eq $ownerSid -or $AllowedWriterSids -notcontains $ownerSid) {
        throw "Installer source input '$Path' has untrusted owner '$($acl.Owner)'."
    }
    # An empty rule collection is a REFUSAL, not a pass. A NULL DACL grants
    # everyone full control and .NET renders it exactly like a deny-everyone
    # empty DACL; deciding trust only from inside the loop below let both
    # through. Same rule as Test-ObjectDaclTrusted and Test-AclDumpLocked.
    if (@($acl.Access).Count -eq 0) {
        throw ("Installer source input '$Path' has a DACL with no ACEs. A NULL DACL grants " +
               "EVERYONE full control and cannot be told apart from a deny-everyone one here; " +
               "both are refused. Stage the release under an administrator-only local directory.")
    }
    # WRITE_DAC and WRITE_OWNER are spelled ChangePermissions and TakeOwnership
    # in FileSystemRights. There is NO WriteDacl and NO WriteOwner member: those
    # spellings resolve to $null, [int]$null is 0, and `-bor 0` is a silent
    # no-op -- so the round-6 version of this gate carried neither bit. An ACE
    # granting a named non-administrator nothing but the right to rewrite the
    # DACL and take ownership (icacls /grant user:(WDAC,WO)) passed it, and that
    # principal then owns the helper this bootstrap exists to prove, plus every
    # byte the elevated build consumes. Test-AceEndangersBytes in the library had
    # the correct pair all along; the two gates now agree.
    $dangerous = [int][System.Security.AccessControl.FileSystemRights]::WriteData -bor
                 [int][System.Security.AccessControl.FileSystemRights]::Delete -bor
                 [int][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                 [int][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                 [int][System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
                 0x40000000 -bor 0x10000000
    if (-not $AncestorOnly -or -not $item.PSIsContainer) {
        $dangerous = $dangerous -bor [int][System.Security.AccessControl.FileSystemRights]::AppendData
    }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if (([int]$rule.FileSystemRights -band $dangerous) -eq 0) { continue }
        $sid = Resolve-BootstrapSid -Identity $rule.IdentityReference.Value
        if ($null -eq $sid -or $AllowedWriterSids -notcontains $sid) {
            throw ("Installer source input '$Path' grants write-class access to " +
                   "'$($rule.IdentityReference.Value)'. Stage the release under an administrator-only " +
                   "local directory before running this elevated installer.")
        }
    }
}
function Assert-BootstrapTreeTrusted {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$AllowedWriterSids
    )
    $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-BootstrapObjectTrusted -Path $root.FullName -AllowedWriterSids $AllowedWriterSids
    if (-not $root.PSIsContainer) { return }
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($root.FullName)
    while ($stack.Count -gt 0) {
        $dir = New-Object System.IO.DirectoryInfo($stack.Pop())
        foreach ($entry in @($dir.EnumerateFileSystemInfos())) {
            Assert-BootstrapObjectTrusted -Path $entry.FullName -AllowedWriterSids $AllowedWriterSids
            if (($entry.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                $stack.Push($entry.FullName)
            }
        }
    }
}
# The directories BETWEEN the release-tree root and a consumed input decide
# whether that input can be swapped out: DeleteSubdirectoriesAndFiles on a parent
# is delete-and-recreate on the child WHATEVER the child's own DACL says, and the
# replacement lands in the window between this gate and the dot-source below. The
# ancestor loop walks UPWARD from the release root, so it never inspected
# `scripts\` or `scripts\lib\` -- the two directories holding the very helper this
# bootstrap exists to prove. Pure string work rather than Split-Path, so the
# Pester suite can drive it on Linux (Split-Path rewrites Windows separators
# there). Refuses, rather than skipping, anything that is not under the root.
function Get-BootstrapInteriorDirectories {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $rootKey = $Root.TrimEnd('\')
    $rootSegments = @($rootKey -split '\\')
    $segments = @(($Path.TrimEnd('\')) -split '\\')
    # A dot segment lexically escapes the root while still passing the prefix
    # test below ('C:\rel\..\evil\x.ps1' starts with 'C:\rel'), so the function
    # would have returned 'C:\rel\..' and 'C:\rel\..\evil' as "interior"
    # directories of the release tree. Not reachable today -- every input is
    # Join-Path'ed onto a Resolve-Path'ed root -- but the contract this function
    # advertises is "refuses anything not under the root", and it has to be true
    # for the reason it is true, not by luck of the call sites.
    foreach ($seg in $segments) {
        if ($seg -eq '.' -or $seg -eq '..') {
            throw "Installer source input '$Path' contains a dot segment; refusing to treat it as inside '$Root'."
        }
    }
    if ($segments.Count -le $rootSegments.Count) {
        throw "Installer source input '$Path' is not inside the release tree '$Root'."
    }
    $prefix = ($segments[0..($rootSegments.Count - 1)] -join '\')
    if (-not [string]::Equals($prefix, $rootKey, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Installer source input '$Path' is not inside the release tree '$Root'."
    }
    # Every component below the root except the input's own leaf: the leaf is
    # checked by the caller (as an object or as a whole tree).
    $dirs = @()
    for ($i = $rootSegments.Count; $i -lt ($segments.Count - 1); $i++) {
        $dirs += (($segments[0..$i]) -join '\')
    }
    return @($dirs)
}
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$bootstrapWriters = @(
    'S-1-5-32-544', 'S-1-5-18',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464',
    $currentSid
)
$sourceInputs = @(
    (Join-Path $PSScriptRoot 'lib\InstallVerifyLib.ps1'),
    (Join-Path $repoRoot 'pyproject.toml'),
    (Join-Path $repoRoot 'README.md'),
    (Join-Path $repoRoot 'src'),
    (Join-Path $repoRoot 'deploy')
)
$ancestor = $repoRoot
$isRepoRoot = $true
while ($ancestor) {
    Assert-BootstrapObjectTrusted -Path $ancestor -AllowedWriterSids $bootstrapWriters `
        -AncestorOnly:(-not $isRepoRoot)
    $isRepoRoot = $false
    $parent = Split-Path -Parent $ancestor
    if (-not $parent -or $parent -eq $ancestor) { break }
    $ancestor = $parent
}
foreach ($inputPath in $sourceInputs) {
    foreach ($interior in (Get-BootstrapInteriorDirectories -Root $repoRoot -Path $inputPath)) {
        Assert-BootstrapObjectTrusted -Path $interior -AllowedWriterSids $bootstrapWriters
    }
    Assert-BootstrapTreeTrusted -Path $inputPath -AllowedWriterSids $bootstrapWriters
}

# Artifact and filesystem decisions are now safe to load from the proven tree.
. "$PSScriptRoot/lib/InstallVerifyLib.ps1"

# Bare executable names handed to `cmd /c` resolve from the CURRENT DIRECTORY
# before PATH (Daybreak round 4). An elevated shell whose CWD is user-writable
# (a extracted source tree under %TEMP%, a share, a Downloads folder) would
# execute a planted python.exe/py.exe AS ADMINISTRATOR during the interpreter
# probe below. Defining this variable removes the CWD from the child-process
# search path for this process and everything it launches. PowerShell itself
# never searches the CWD for commands, so only the cmd /c call sites needed it.
$env:NoDefaultCurrentDirectoryInExePath = '1'

# CODE (RuntimeDir): rebuilt every run, gMSA read+execute, never written by the
# app. STATE (InstallDir): survives every run, gMSA modify, never executed.
# Keeping those two sets in one directory with one ACL is what made a
# compromised app pool able to rewrite the interpreter it runs as.
$runtimeCurrent = Join-Path $RuntimeDir "current"
$venv     = Join-Path $runtimeCurrent "venv"
$logs     = Join-Path $InstallDir "logs"
$envFile  = Join-Path $InstallDir "acme-ra.env"

# --- The two roots must be DISJOINT (Daybreak round 4) ------------------------
#
# The RX/Modify boundary between the trees IS the control. If the state root is
# inside the runtime tree, the state claim's recursive reset re-applies Modify
# over a code subtree; if they are the same directory, the two grant sets
# collapse onto one tree and the gMSA ends up with Modify over the interpreter
# it runs -- with every read-back proof green, because the proof checks SHAPE
# (trustees, protection, inheritance) and both grant sets have the same shape.
# Refuse before anything on the host is touched.
$rootRelation = Get-PathRelation -A $RuntimeDir -B $InstallDir
if ($rootRelation -ne 'disjoint') {
    throw ("-RuntimeDir `"$RuntimeDir`" and -InstallDir `"$InstallDir`" are not disjoint trees " +
           "(relation: $rootRelation). The ACL boundary between them is the entire control -- " +
           "gMSA read+execute on code, modify on state, never both on one tree -- and nested or " +
           "equal roots make one grant set apply to the other's subtree while the read-back " +
           "proofs stay green. Use two separate roots (see docs/operator-requirements.md section 1).")
}

# Round 5: the SITE tree is the third tree that decides what runs -- web.config
# is the gMSA launch configuration -- so it is held to the same disjointness
# rule even though it holds no interpreter bytes itself. A SitePath inside the
# state tree would put the launch configuration on gMSA-writable ground; a
# SitePath inside the runtime tree would let a site-content write land on
# executable bytes.
$rel = Get-PathRelation -A $SitePath -B $RuntimeDir
if ($rel -ne 'disjoint') {
    throw ("-SitePath `"$SitePath`" and -RuntimeDir `"$RuntimeDir`" are not disjoint trees " +
           "(relation: $rel). web.config under -SitePath is the gMSA launch configuration; " +
           "it must not live inside either managed tree (see docs/operator-requirements.md section 1).")
}
$rel = Get-PathRelation -A $SitePath -B $InstallDir
if ($rel -ne 'disjoint') {
    throw ("-SitePath `"$SitePath`" and -InstallDir `"$InstallDir`" are not disjoint trees " +
           "(relation: $rel). web.config under -SitePath is the gMSA launch configuration; " +
           "the gMSA holds Modify on the state tree, so the launch configuration must not " +
           "live there (see docs/operator-requirements.md section 1).")
}

# --- The protected installer scratch directory, created FIRST ----------------
#
# All transient installer inputs live in a fresh administrator-only directory
# under %ProgramFiles%, never in a shared/caller-selected TEMP directory or
# inside a managed tree whose next-run provenance a failed install could poison.
#
# It is created BEFORE the roots are claimed, not after, for one reason: the
# claim's pre-flight (Get-RootProvenance -> Get-InstallTreeViolations) writes an
# `icacls /save` dump and then decides whether a pre-existing root is ours by
# PARSING IT BACK. That dump is a privileged input -- it is the entire evidence
# for the provenance verdict -- and it was still being written to the ambient
# TEMP directory, which is %windir%\Temp (Users-writable) whenever the installer
# runs as SYSTEM from configuration management. Round 6's own rule is that
# privileged inputs live in a namespace with an explicit writer allowlist, so
# this one does too, from the first proof onward.
$installerScratch = Join-Path $env:ProgramFiles ('.acme-adcs-ra-installer-' + [guid]::NewGuid().ToString('N'))
function Remove-InstallerScratch {
    if ($installerScratch -and (Test-Path -LiteralPath $installerScratch)) {
        Assert-NoReparsePoints -Path $installerScratch -Context 'installer scratch cleanup'
        Remove-Item -LiteralPath $installerScratch -Recurse -Force
    }
}
trap {
    $originalError = $_
    # PowerShell registers a trap for the WHOLE scope at parse time, but a
    # function only exists once its definition has executed -- so a failure in
    # the path checks above enters this handler before Remove-InstallerScratch
    # is defined. Calling it there produced a CommandNotFoundException warning
    # about an empty scratch path, printed immediately before the real error the
    # operator needs to read. There is nothing to clean up in that window.
    if (Get-Command Remove-InstallerScratch -ErrorAction SilentlyContinue) {
        try { Remove-InstallerScratch } catch {
            Write-Warning "Could not remove protected installer scratch $installerScratch after failure: $($_.Exception.Message)"
        }
    }
    throw $originalError
}
$adminScratchGrants = @('*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F')
if (-not (New-AtomicProtectedDirectory -Path $installerScratch -Grants $adminScratchGrants)) {
    throw "Unexpected installer scratch collision at $installerScratch."
}
# Point the library's ACL read-back dumps here for the rest of the run.
$script:InstallVerifyScratchDir = $installerScratch

# --- Prerequisites -----------------------------------------------------------
# IIS features the installer relies on:
#   Web-Server          the IIS role itself
#   Web-Mgmt-Console    appcmd / IIS management
#   Web-Scripting-Tools the WebAdministration PowerShell module (IIS:\ drive)
#   Web-IP-Security     <ipSecurity> IP-and-Domain-Restrictions (the threat-model
#                       pilot condition: restrict the endpoint to the ACME client)
$RequiredIisFeatures = @("Web-Server", "Web-Mgmt-Console", "Web-Scripting-Tools", "Web-IP-Security")

function Test-HttpPlatformHandler {
    # HttpPlatformHandler is the IIS module that launches+supervises uvicorn and
    # reverse-proxies to it. It is a separate (third-party) install, NOT a Windows
    # feature. Detect it as a registered IIS global module; fall back to the DLL.
    #
    # 2026-08-23 finding 5: this used Get-Command as a truth test and then
    # invoked the bare name, so when the WebAdministration module is absent a
    # planted Get-WebGlobalModule.exe in a writable PATH entry satisfied
    # discovery and ran as Administrator. The cmdlet is resolved through the
    # trusted inbox-module gate (Get-TrustedInboxCommand) and invoked via its
    # resolved CommandInfo; when it is not safely available the DLL fallback
    # below still decides, and nothing name resolution found ever executes.
    try {
        $getWebGlobalModule = Get-TrustedInboxCommand -Name 'Get-WebGlobalModule' -ModuleName 'WebAdministration'
        if ($getWebGlobalModule) {
            $m = & $getWebGlobalModule -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq "httpPlatformHandler" }
            if ($m) { return $true }
        }
    } catch { }
    $dll = Join-Path $env:windir "System32\inetsrv\httpPlatformHandler.dll"
    return (Test-Path $dll)
}

function Install-Prerequisites {
    Write-Host ""
    Write-Host "Installing prerequisites (-InstallPrereqs) ..."

    # 1. IIS role + features (native, idempotent). Server only (Install-WindowsFeature).
    #
    # 2026-08-23 finding 5: the same Get-Command-as-truth-test plus bare-name
    # invocation as Test-HttpPlatformHandler. Both ServerManager cmdlets are
    # resolved through the trusted inbox-module gate and invoked via their
    # resolved CommandInfo; when they do not resolve (a client SKU, a server
    # without the module) the warn-and-continue branch below runs unchanged,
    # and a PATH-planted Install-WindowsFeature.exe is never executed.
    $getWindowsFeature = Get-TrustedInboxCommand -Name 'Get-WindowsFeature' -ModuleName 'ServerManager'
    $installWindowsFeature = Get-TrustedInboxCommand -Name 'Install-WindowsFeature' -ModuleName 'ServerManager'
    if ($getWindowsFeature -and $installWindowsFeature) {
        foreach ($f in $RequiredIisFeatures) {
            $state = & $getWindowsFeature -Name $f -ErrorAction SilentlyContinue
            if ($state -and $state.Installed) {
                Write-Host "  [ok]   IIS feature $f already installed."
            } else {
                Write-Host "  [..]   Installing IIS feature $f ..."
                $res = & $installWindowsFeature -Name $f -IncludeManagementTools -ErrorAction Continue
                if ($res -and $res.Success) { Write-Host "  [ok]   $f installed." }
                else { Write-Host "  [warn] Install-WindowsFeature $f did not report success; install it manually." }
            }
        }
    } else {
        Write-Host "  [warn] Install-WindowsFeature not available (not Windows Server?). Install the IIS"
        Write-Host "         role + features manually: $($RequiredIisFeatures -join ', ')."
    }

    # 2. HttpPlatformHandler -- only from a vetted MSI the operator points at.
    if (Test-HttpPlatformHandler) {
        Write-Host "  [ok]   HttpPlatformHandler already registered."
    } elseif ($HttpPlatformHandlerMsi) {
        # 2026-08-17 F1: nothing reaches msiexec unverified. This is the only
        # third-party executable the installer runs, it runs elevated, and it
        # runs on the host that holds the RA's gMSA context.
        $source = $HttpPlatformHandlerMsi
        $sourceKind = Assert-MsiSourceAcceptable -Source $source -Sha256 $HttpPlatformHandlerSha256
        $msi = Join-Path $installerScratch ('HttpPlatformHandler-' + [guid]::NewGuid().ToString('N') + '.msi')
        try {
            if ($sourceKind -eq 'https') {
                Write-Host "  [..]   Downloading HttpPlatformHandler from $source into protected staging ..."
                try { Invoke-WebRequest -Uri $source -OutFile $msi -UseBasicParsing } catch { throw "Download failed: $($_.Exception.Message)" }
            } else {
                if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                    throw "HttpPlatformHandler MSI not found: $source"
                }
                Copy-Item -LiteralPath $source -Destination $msi -ErrorAction Stop
            }

            # Verify the protected staged copy, not the caller-controlled source
            # path. No non-administrator can replace these bytes between this
            # check and msiexec reopening them.
            $actualHash = (Get-FileHash -Algorithm SHA256 -Path $msi).Hash
            if (-not (Test-Sha256Match -Actual $actualHash -Expected $HttpPlatformHandlerSha256)) {
                throw ("HttpPlatformHandler MSI SHA-256 mismatch. Expected {0}, got {1}. " -f
                       $HttpPlatformHandlerSha256, $actualHash) +
                      "NOT installing. Delete the downloaded copy and obtain the artifact again."
            }
            Write-Host "  [ok]   MSI SHA-256 matches the expected digest."

            # 2. Authenticode signature and publisher.
            $sig = Get-AuthenticodeSignature -FilePath $msi
            $signerSubject = ""
            if ($sig.SignerCertificate) { $signerSubject = $sig.SignerCertificate.Subject }
            if (-not (Test-MsiSignatureAcceptable -Status ([string]$sig.Status) `
                        -SignerSubject $signerSubject `
                        -ExpectedPublisher $HttpPlatformHandlerPublisher)) {
                throw ("HttpPlatformHandler MSI failed Authenticode verification. Status '{0}', signer '{1}', expected publisher '{2}'. " -f
                       $sig.Status, $signerSubject, $HttpPlatformHandlerPublisher) +
                      "NOT installing. If your deployment repackages this module, pass -HttpPlatformHandlerPublisher."
            }
            Write-Host ("  [ok]   MSI Authenticode signature valid, signed by {0}." -f $signerSubject)

            Write-Host "  [..]   Installing the verified staged HttpPlatformHandler MSI ..."
            $msiexec = Join-Path $env:windir 'System32\msiexec.exe'
            $p = Start-Process $msiexec -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru
            if ($p.ExitCode -ne 0) { throw "msiexec failed installing HttpPlatformHandler (exit $($p.ExitCode))." }
            if (Test-HttpPlatformHandler) { Write-Host "  [ok]   HttpPlatformHandler installed." }
            else { Write-Host "  [warn] HttpPlatformHandler MSI ran but the module is not detected; verify in IIS." }
        } finally {
            Remove-Item -LiteralPath $msi -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "  [warn] HttpPlatformHandler is MISSING and no -HttpPlatformHandlerMsi was given."
        Write-Host "         It is a separate Microsoft IIS module (the download has been unreliable, so"
        Write-Host "         it is not auto-fetched). Get the v1.2 amd64 MSI from"
        Write-Host "         https://www.iis.net/downloads/microsoft/httpplatformhandler and either run it"
        Write-Host "         by hand or re-run with -HttpPlatformHandlerMsi <path-to-msi>."
    }

    # Python is deliberately not installed here. Running a PATH-selected py,
    # python, or winget from an elevated bootstrapper turns a writable PATH
    # entry into Administrator code execution. The discovery step below accepts
    # only an exact executable whose complete ACL/owner chain is trusted; if no
    # such Python exists, install it separately and re-run.
    Write-Host "  [..]   Python is not auto-installed; trusted discovery runs below."
    Write-Host ""
}

# --- Stop the worker BEFORE the tree is claimed (2026-08-15 rescan-2 F3) -----
#
# This used to sit ~220 lines below, after the install root had been claimed and
# after the destination interpreter had been verified and EXECUTED. Windows
# checks access when a handle is opened, not when it is used: a compromised
# gMSA worker with a write handle opened under the steady-state Modify ACL
# keeps that write access straight through the ownership/ACL reset, and can
# rewrite interpreter bytes between the hash check and the elevated run of
# those bytes. Stopping the pool -- and proving the worker process is gone --
# has to come first, or none of the verification below binds anything.
$script:poolWasStopped = $false
$appcmdExe = "$env:windir\system32\inetsrv\appcmd.exe"
# Absolute System32 path, resolved ONCE at script scope. Round 6 moved the
# elevated native utilities off ambient PATH, but assigned this one twice in
# places that were not in scope where it was used: function-locally inside
# Ensure-SslCertBinding, and again inside the -SharePort443 branch. The
# catch-all branch's stale-SNI cleanup therefore invoked a null command --
# a RuntimeException under EAP=Stop, killing the install after the TLS binding
# was written and before the app pool was started. One script-scope variable,
# used everywhere.
$netshExe = Join-Path $env:windir 'System32\netsh.exe'
if (Test-Path $appcmdExe) {
    Write-Host "Stopping app pool `"$AppPool`" (and waiting for its worker) before touching $InstallDir ..."
    $script:poolWasStopped = Stop-AppPoolAndWait -AppcmdExe $appcmdExe -AppPool $AppPool
    if ($script:poolWasStopped) {
        Write-Host "  [ok]   app pool stopped and no worker process remains"
    } else {
        Write-Host "  [ok]   no such app pool yet (first install)"
    }
}

# --- Resolve the gMSA SID FIRST ----------------------------------------------
# Needed before either root is claimed, because both roots carry a gMSA ACE and
# the pre-flight below has to know what a completed install looks like in order
# to recognise one. This is a pure directory lookup; it touches nothing on disk.
if ($GmsaAccount -notmatch '\$$') {
    Write-Host "[warn] -GmsaAccount `"$GmsaAccount`" has no trailing `$ -- gMSA SAM names end in `$. Continuing, but verify."
}
try {
    $gmsaSid = (New-Object System.Security.Principal.NTAccount($GmsaAccount)).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    Write-Host "Resolved gMSA $GmsaAccount -> $gmsaSid"
} catch {
    throw "Could not resolve gMSA account `"$GmsaAccount`". Use DOMAIN\gMSA-name$ form and confirm it exists."
}

# The trustees permitted anywhere in either tree. Identity only -- the rights
# differ sharply between the two roots (execute vs write) and are set by the
# grant strings below.
$raTrustees = @(
    'S-1-5-32-544', 'S-1-5-18',
    'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', 'BA', 'SY',
    $gmsaSid, $GmsaAccount
)
$adminOnlyTrustees = @(
    'S-1-5-32-544', 'S-1-5-18',
    'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', 'BA', 'SY'
)
# CODE: read + execute for the worker, full for administrators. No write ACE
# for the gMSA anywhere in this tree -- a compromised app pool must not be able
# to rewrite the interpreter it is about to be relaunched with.
$runtimeGrants = @(
    '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', ('*' + $gmsaSid + ':(OI)(CI)RX')
)
# STATE: modify for the worker (it writes the database and the log), full for
# administrators. Nothing here is ever executed.
$stateGrants = @(
    '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', ('*' + $gmsaSid + ':(OI)(CI)M')
)
# The gMSA legitimately OWNS files it creates in the state tree (log lines, the
# SQLite journal). It can own nothing in the runtime tree, having no write
# access there at all.
$stateOwnerSids = @('S-1-5-32-544', 'S-1-5-18', $gmsaSid)

# --- Claim both roots: provably ours, or refused -----------------------------
#
# 2026-08-15 rescan-3. Every previous round tried to make it safe to ADOPT a
# directory a local user might have created first, and every round's mechanism
# became the next round's finding. There is no force-claim path any more: a
# pre-existing root either matches what a completed install of this RA leaves
# behind -- same ownership, same DACL shape, no reparse points, verified by the
# same function that proves the lockdown at the end of this script -- or the
# install stops and tells the operator exactly what to do.
#
# Refusing is the safe direction and it is also the honest one: this installer
# cannot tell a hostile pre-planted tree from a half-finished one, so it treats
# both as "not mine" rather than guessing.
function Initialize-SecuredRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][string[]]$Grants,
        [Parameter(Mandatory = $true)][string[]]$AllowedTrustees,
        [string[]]$AllowedOwnerSids = @('S-1-5-32-544', 'S-1-5-18'),
        [hashtable]$ProtectedEntries = @{},
        [string[]]$ForbiddenTopLevelEntries = @(),
        [string[]]$Preserve = @()
    )
    $ErrorActionPreference = 'Stop'
    Write-Host "Claiming $Purpose root $Path ..."
    $prov = Get-RootProvenance -Path $Path -AllowedTrustees $AllowedTrustees `
        -AllowedOwnerSids $AllowedOwnerSids -ProtectedEntries $ProtectedEntries `
        -ForbiddenTopLevelEntries $ForbiddenTopLevelEntries
    $fresh = $false
    switch ($prov.State) {
        'foreign' {
            throw (Get-ForeignRootRefusal -Path $Path -Purpose $Purpose `
                       -Reasons $prov.Reasons -Preserve $Preserve)
        }
        'absent' {
            # CreateDirectoryW receives the final protected DACL in the same
            # kernel call that creates the directory. Unlike create-then-icacls,
            # there is no inherited-DACL interval in which a local user can open
            # a create-capable handle and retain it after lockdown. A namespace
            # collision is reported separately and re-verified, never adopted.
            $created = New-AtomicProtectedDirectory -Path $Path -Grants $Grants
            if (-not $created) {
                Write-Host "  [!!]  $Path appeared between the absence check and creation -- re-verifying it"
                $prov = Get-RootProvenance -Path $Path -AllowedTrustees $AllowedTrustees `
                    -AllowedOwnerSids $AllowedOwnerSids -ProtectedEntries $ProtectedEntries `
                    -ForbiddenTopLevelEntries $ForbiddenTopLevelEntries
                if ($prov.State -ne 'ours') {
                    throw (Get-ForeignRootRefusal -Path $Path -Purpose $Purpose `
                               -Reasons $prov.Reasons -Preserve $Preserve)
                }
                Write-Host "  [ok]   $Path recognised as a previous install of this RA"
                break
            }
            $fresh = $true
            Write-Host "  [ok]   created $Path atomically with its final protected DACL"
        }
        default {
            Write-Host "  [ok]   $Path recognised as a previous install of this RA"
        }
    }
    # An existing tree: normalise ownership and discard every explicit ACE on
    # the DESCENDANTS, then re-assert exactly our grants on the root, then read
    # the whole tree back and prove it. The proof is not ceremony: "we ran
    # icacls" is not evidence, and this is the same evidence the NEXT run's
    # pre-flight will demand. The ROOT itself is never /reset: it already
    # carries exactly the protected grants (provenance just verified it), and a
    # /reset would re-inherit the parent's create-class ACEs for the interval
    # before /inheritance:r restores -- the create-capable window atomic
    # creation exists to eliminate (live-proven 2026-08-16). A FRESH tree has
    # nothing to normalise at all.
    if (-not $fresh) {
        Assert-NoReparsePoints -Path $Path -Context "$Purpose claim"
        Reset-TreeChildrenToInherited -Path $Path
        Set-ObjectProtectedDacl -Path $Path -Grants $Grants -SkipReset
    }
    Assert-InstallTreeLocked -Root $Path -AllowedTrustees $AllowedTrustees `
        -AllowedOwnerSids @('S-1-5-32-544', 'S-1-5-18') `
        -ForbiddenTopLevelEntries $ForbiddenTopLevelEntries
    Write-Host "  [ok]   $Purpose root secured (ownership + DACLs read back and proven)"
}

# Entry names that must never sit at the STATE root. 'venv' and 'python' are
# the pre-split layout's interpreter trees; 'scripts' was the operator-scripts
# copy. A legacy tree otherwise matches our trustee/owner/DACL shape, so these
# names are what distinguishes "old single-tree install" from "ours" (Daybreak
# round 4, medium -- a clean legacy tree passed the generic check as 'ours'
# while the preserved web.config kept launching the gMSA-writable ProgramData
# venv).
$stateForbiddenEntries = @('venv', 'python', 'scripts')

Initialize-SecuredRoot -Path $RuntimeDir -Purpose 'runtime (code)' `
    -Grants $runtimeGrants -AllowedTrustees $raTrustees

# Re-resolve after the runtime object exists and before any state grant is
# applied. If an alias escaped the lexical gate, fail before Modify can ever
# land on runtime bytes.
if ((Get-PathRelation -A $RuntimeDir -B $InstallDir) -ne 'disjoint') {
    throw 'Runtime and state roots resolve to overlapping filesystem trees.'
}
if ((Get-PathRelation -A $SitePath -B $RuntimeDir) -ne 'disjoint') {
    throw 'Site and runtime roots resolve to overlapping filesystem trees after runtime creation.'
}

Initialize-SecuredRoot -Path $InstallDir -Purpose 'state (database, logs, secrets)' `
    -Grants $stateGrants -AllowedTrustees $raTrustees `
    -AllowedOwnerSids $stateOwnerSids `
    -ProtectedEntries @{ 'acme-ra.env' = $raTrustees } `
    -ForbiddenTopLevelEntries $stateForbiddenEntries `
    -Preserve @("$InstallDir\acme_ra.db", "$InstallDir\acme-ra.env", "$InstallDir\logs")

if ((Get-PathRelation -A $SitePath -B $InstallDir) -ne 'disjoint') {
    throw 'Site and state roots resolve to overlapping filesystem trees after state creation.'
}

# The source snapshot makes PEP 517 consume an immutable namespace rather than
# repeatedly reopening the checkout after its provenance check. It lives inside
# the protected installer scratch directory created before the root claims.
$sourceSnapshot = Join-Path $installerScratch 'source'
if (-not (New-AtomicProtectedDirectory -Path $sourceSnapshot -Grants $adminScratchGrants)) {
    throw "Unexpected source-snapshot collision at $sourceSnapshot."
}
Copy-Item -LiteralPath (Join-Path $repoRoot 'pyproject.toml') -Destination $sourceSnapshot
Copy-Item -LiteralPath (Join-Path $repoRoot 'README.md') -Destination $sourceSnapshot
Copy-Item -LiteralPath (Join-Path $repoRoot 'src') -Destination $sourceSnapshot -Recurse
Copy-Item -LiteralPath (Join-Path $repoRoot 'deploy') -Destination $sourceSnapshot -Recurse
Assert-NoReparsePoints -Path $sourceSnapshot -Context 'protected source snapshot'
Write-Host "  [ok]   build inputs copied to protected snapshot $sourceSnapshot"

# The /reset inside the claim just stripped EVERY descendant's explicit DACL --
# including the dotenv's protected one. It is normally re-applied after the
# runtime build (~150 lines below), but any abort in between (a failed build --
# the documented rollback path -- or a failed runtime proof) would leave
# acme-ra.env inheriting gMSA MODIFY from the state root, and that file decides
# who may enrol and for which names. Found live: a deliberately failed build
# left exactly that state, and the NEXT install's pre-flight correctly refused
# the whole tree, bricking the install until manual ACL surgery. Re-protect it
# IMMEDIATELY, so the only unprotected window is the icacls call itself.
if (Test-Path -LiteralPath $envFile) {
    Set-ObjectProtectedDacl -Path $envFile -Grants @(
        '*S-1-5-32-544:F', '*S-1-5-18:F', ($GmsaAccount + ':R')
    )
    Write-Host "  [ok]   re-protected $envFile after the claim reset (gMSA read-only)"
}

if ($InstallPrereqs) { Install-Prerequisites }

# Read-only prerequisite report (always) -- a quick green/red of what the app pool
# needs, before we touch anything.
Write-Host "Prerequisite check:"
$iisRole = $null
# Finding 5 (2026-08-23): resolve through the trusted inbox-module gate, never
# by bare name -- a report line must not become an elevated execution either.
$getWindowsFeature = Get-TrustedInboxCommand -Name 'Get-WindowsFeature' -ModuleName 'ServerManager'
if ($getWindowsFeature) { $iisRole = & $getWindowsFeature -Name Web-Server -ErrorAction SilentlyContinue }
if ($iisRole) { Write-Host "  IIS Web-Server role .......... $(if ($iisRole.Installed) { 'present' } else { 'MISSING (install IIS or pass -InstallPrereqs)' })" }
$haveWebAdmin = [bool](Get-Module -ListAvailable WebAdministration -ErrorAction SilentlyContinue)
Write-Host "  WebAdministration module ..... $(if ($haveWebAdmin) { 'present' } else { 'MISSING (Web-Scripting-Tools)' })"
Write-Host "  HttpPlatformHandler module .... $(if (Test-HttpPlatformHandler) { 'present' } else { 'MISSING (see -HttpPlatformHandlerMsi / iis.net)' })"
# Finding 5 (2026-08-23): same trusted resolution for the RSAT cmdlet; a PATH
# application named Test-ADServiceAccount.exe must not turn the gMSA check
# into elevated execution of attacker bytes.
$testAdServiceAccount = Get-TrustedInboxCommand -Name 'Test-ADServiceAccount' -ModuleName 'ActiveDirectory'
$haveRsat = [bool]$testAdServiceAccount
Write-Host "  RSAT AD PowerShell ........... $(if ($haveRsat) { 'present' } else { 'absent (gMSA test will be skipped)' })"
Write-Host ""

# --- Confirm the gMSA is installed here (best-effort; the SID resolved above) -
# Strip the domain for Test-ADServiceAccount (it wants the SAM without DOMAIN\).
$gmsaSam = ($GmsaAccount -replace ".*\\", "") -replace '\$$', ""
if ($testAdServiceAccount) {
    try {
        if (& $testAdServiceAccount -Identity $gmsaSam) {
            Write-Host "Test-ADServiceAccount: gMSA is installed and usable on this host."
        } else {
            Write-Host "[warn] Test-ADServiceAccount returned False for $gmsaSam. The app pool will fail to start until the gMSA is installed here (Install-ADServiceAccount)."
        }
    } catch {
        Write-Host "[warn] Test-ADServiceAccount threw: $($_.Exception.Message). Verify the gMSA manually."
    }
} else {
    Write-Host "[warn] RSAT AD PowerShell not present; skipping Test-ADServiceAccount. Confirm the gMSA is installed on this host."
}

# --- Locate a Python 3.12+ interpreter ----------------------------------------
# Probing goes through cmd /c because Store stubs and argument mangling make
# PowerShell's & operator unreliable for version probes.
#
# The Windows 'py' launcher is deliberately NOT a candidate (2026-08-23
# finding 3 follow-up): probing it executes whichever interpreter it selects,
# and that interpreter's runtime tree could not be proven before the probe
# ran -- the probe IS execution. Only exact python.exe/python3.exe
# Application paths whose full runtime closure can be proven BEFORE the first
# probe are considered.
function Invoke-PyProbe {
    param([string]$Exe, [string[]]$Arguments)
    # Resolve a BARE name to the absolute path PowerShell discovered on PATH
    # (PowerShell never searches the CWD; cmd.exe does). The
    # NoDefaultCurrentDirectoryInExePath setting above closes the CWD lookup,
    # and this closes passing a bare name through to cmd at all -- belt and
    # braces, because the probe output decides which interpreter the elevated
    # install runs for the rest of the script (Daybreak round 4).
    if ($Exe -notmatch '[\\/]') {
        $resolved = Get-Command $Exe -ErrorAction SilentlyContinue
        if ($resolved -and $resolved.Source) { $Exe = $resolved.Source }
    }
    $argStr = ($Arguments | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
    $tmp = Join-Path $installerScratch ("ra-py-probe-" + [guid]::NewGuid().ToString('N') + ".txt")
    $cmdExe = Join-Path $env:windir 'System32\cmd.exe'
    & $cmdExe /d /c "`"$Exe`" $argStr > `"$tmp`" 2>&1"
    $exit = $LASTEXITCODE
    $out = ""
    if (Test-Path $tmp) { $out = (Get-Content $tmp -Raw); Remove-Item $tmp -Force }
    @{ ExitCode = $exit; Output = if ($out) { $out.Trim() } else { "" } }
}

# Candidate interpreters, in preference order. Note what is NOT here any more:
# `$InstallDir\python\python.exe`. Four review rounds were spent trying to make
# it safe to execute an interpreter found sitting in the destination -- an ACL
# claim, an ownership claim, a link walk, a content manifest, an out-of-tree
# anchor for that manifest -- and each mechanism was the next round's finding.
# The runtime is now built fresh, under %ProgramFiles%, on every run, so there
# is never a destination interpreter to decide about. That is the whole fix.
#
# The 'py' launcher is not here either, for the same reason it is not a
# candidate anywhere: `py --version` executes the interpreter the launcher
# selects before any gate can prove that interpreter's runtime tree, and no
# amount of proving py.exe itself closes that (2026-08-23 finding 3). Machine
# directories, the per-user Python manager layout, and PATH-discovered
# python.exe/python3.exe exact paths all CAN be proven pre-probe, so they stay.
$launchers = @()
$imRoot = Join-Path $env:LOCALAPPDATA "Python"
foreach ($pc in (Get-ChildItem $imRoot -Filter "pythoncore-*" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
    $p = Join-Path $pc.FullName "python.exe"
    if (Test-Path $p) { $launchers += @{ Exe = $p; Args = @() } }
}
foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if (-not $base) { continue }
    foreach ($d in (Get-ChildItem $base -Filter "Python3*" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
        $p = Join-Path $d.FullName "python.exe"
        if (Test-Path $p) { $launchers += @{ Exe = $p; Args = @() } }
    }
}
foreach ($n in @("python3.exe", "python.exe")) {
    $p = Join-Path (Join-Path $imRoot "bin") $n
    if (Test-Path $p) { $launchers += @{ Exe = $p; Args = @() } }
}
# Bare python/python3 names resolve to an exact rooted Application path in the
# Get-Command check below BEFORE anything is proven or probed; anything that is
# not an exact executable path is skipped there.
$launchers += @(
    @{ Exe = "python";  Args = @() },
    @{ Exe = "python3"; Args = @() }
)
$python = $null
$major = 0; $minor = 0
foreach ($l in $launchers) {
    $label = "$($l.Exe) $($l.Args -join `" `")"
    $cmd = Get-Command $l.Exe -ErrorAction SilentlyContinue
    if (-not $cmd) { Write-Host "  [skip] $label -- exe not found on PATH"; continue }
    if ($cmd.CommandType -ne [System.Management.Automation.CommandTypes]::Application -or
        -not $cmd.Source -or -not [System.IO.Path]::IsPathRooted($cmd.Source)) {
        Write-Host "  [skip] $label -- command is not an exact executable path ($($cmd.CommandType))"
        continue
    }
    if ($cmd.Source -and $cmd.Source -match "\\WindowsApps\\") {
        Write-Host "  [skip] $label -- Windows Store alias ($($cmd.Source)), unusable non-interactively"
        continue
    }
    # Round 5: prove the candidate AND its whole ancestor chain are
    # administrator-only BEFORE the first probe executes it elevated. The
    # version probe below IS execution; "it was on PATH" is not provenance
    # (C:\ProgramData, a loosened C:\Python3xx, or a writable PATH entry are
    # all places a low-privilege user can plant an interpreter that elevated
    # code would then run). The check's baseline semantics were surveyed on
    # the lab host: %ProgramFiles% chains pass, %ProgramData% fails (non-IO
    # Users CreateFiles), the running admin's profile passes (owner+admins).
    $chainProbePath = if ($cmd.Source) { $cmd.Source } else { $l.Exe }
    $chainViol = Test-PathChainTrusted -Path $chainProbePath
    if (@($chainViol).Count -gt 0) {
        Write-Host "  [skip] $label -- candidate or its ancestor chain is not administrator-only:"
        foreach ($v in @($chainViol | Select-Object -First 4)) { Write-Host "         $v" }
        continue
    }
    # Finding 3 (2026-08-23): python.exe is not the only bytes that run. The
    # version probe below IS execution, and before the first line of output
    # Python has already loaded python3*.dll / vcruntime140.dll from beside the
    # executable and executed Lib\site.py -- which processes every .pth and
    # imports sitecustomize.py it finds. Proving the executable and its
    # ancestors proved almost none of the executed closure: one
    # permissively-ACL'd sibling DLL, module or .pth rode the whole gate and ran
    # as Administrator. Prove the WHOLE runtime tree (plus the venv base a
    # pyvenv.cfg reaches through) BEFORE the first probe executes any of it.
    # NO EXEMPTIONS: a candidate whose closure cannot be proven without first
    # executing it (the py launcher) is not a candidate at all -- it is absent
    # from the list above for exactly this reason.
    $treeViol = @(Get-InterpreterRuntimeViolations -InterpreterPath $chainProbePath)
    if (@($treeViol).Count -gt 0) {
        Write-Host "  [skip] $label -- interpreter runtime tree is not administrator-only:"
        foreach ($v in @($treeViol | Select-Object -First 4)) { Write-Host "         $v" }
        continue
    }
    # Probe the EXACT path whose chain was just proven, not the bare name again.
    # Passing $l.Exe made Invoke-PyProbe re-resolve the name independently, so
    # the object that was checked and the object that was executed were two
    # separate lookups of the same string with a gap in between.
    $r = Invoke-PyProbe -Exe $chainProbePath -Arguments ($l.Args + @("--version"))
    if ($r.ExitCode -ne 0) { Write-Host "  [fail] $label -- exit $($r.ExitCode)"; continue }
    # `Select-Object -First 1` yields $null when nothing matches, and .Trim() on
    # $null THROWS -- which made the "output not recognised" branch below
    # unreachable and aborted the whole install on a candidate that should
    # simply have been skipped.
    $verLine = ($r.Output -split "`n" | Where-Object { $_ -match "^Python\s+\d" } | Select-Object -First 1)
    $ver = if ($null -eq $verLine) { "" } else { ([string]$verLine).Trim() }
    if ($ver -match "Python\s+(\d+)\.(\d+)") {
        $mj = [int]$Matches[1]; $mn = [int]$Matches[2]
        if ($mj -ge 3 -and $mn -ge 12) {
            $resolved = ""
            try {
                $selfProbe = Invoke-PyProbe -Exe $chainProbePath -Arguments ($l.Args + @("-c", "import sys; print(sys.executable)"))
                if ($selfProbe.ExitCode -eq 0) {
                    $candidate = ($selfProbe.Output -split "`n" | Select-Object -First 1).Trim()
                    if ($candidate -and (Test-Path $candidate -ErrorAction SilentlyContinue)) { $resolved = $candidate }
                }
            } catch { }
            if ($resolved) {
                # The executable the gates proved can still be a redirector
                # whose sys.executable names a DIFFERENT interpreter binary
                # (a shim python.exe; the py launcher is no longer a candidate
                # at all). Gate the self-resolved interpreter on its own chain
                # AND, finding 3 (2026-08-23), on its whole runtime tree: every
                # later elevated run (venv creation, the pip closure) executes
                # from that tree.
                $resolvedViol = Test-PathChainTrusted -Path $resolved
                if (@($resolvedViol).Count -gt 0) {
                    Write-Host "  [skip] $label -- resolved interpreter $resolved is not administrator-only:"
                    foreach ($v in @($resolvedViol | Select-Object -First 4)) { Write-Host "         $v" }
                    continue
                }
                $resolvedTreeViol = @(Get-InterpreterRuntimeViolations -InterpreterPath $resolved)
                if (@($resolvedTreeViol).Count -gt 0) {
                    Write-Host "  [skip] $label -- resolved interpreter $resolved has an untrusted runtime tree:"
                    foreach ($v in @($resolvedTreeViol | Select-Object -First 4)) { Write-Host "         $v" }
                    continue
                }
            }
            $major = $mj; $minor = $mn
            if ($resolved) {
                Write-Host "  [ok]   $label -- $ver (resolved: $resolved)"
                $python = @{ Exe = $resolved; Args = @() }
            } else {
                # The proven executable itself, never the bare name: adopting
                # $l would re-resolve "python" through PATH again at venv
                # creation, a second lookup the gates above never covered.
                Write-Host "  [ok]   $label -- $ver (using the proven interpreter directly)"
                $python = @{ Exe = $chainProbePath; Args = $l.Args }
            }
            break
        }
        Write-Host "  [fail] $label -- version $mj.$mn < 3.12"
    } else {
        Write-Host "  [fail] $label -- output not recognised: $ver"
    }
}
if (-not $python) {
    throw ("Python 3.12+ not found: no python.exe/python3.exe whose whole runtime tree is " +
           "administrator-only was discovered (the py launcher is deliberately not probed -- " +
           "probing it would execute an unproven interpreter). Install a machine-wide Python " +
           "3.12+ (winget install Python.Python.3.14) and re-run.")
}

# --- Build the runtime FRESH, in place, under %ProgramFiles% -----------------
#
# "In place" rather than "stage elsewhere then rename" for one concrete reason:
# a venv is not relocatable. pyvenv.cfg records an absolute `home`, and every
# console-script .exe under Scripts\ embeds the absolute path of the interpreter
# that built it. A built-then-renamed venv is a runtime whose python.exe cannot
# find its own stdlib.
#
# So: retire the live runtime with an atomic rename, build into a brand-new
# `current`, and roll the retired one back if anything throws. Nothing observes
# the gap -- the app pool was stopped and proven dead before any of this.
Remove-StaleRuntimeDirectories -RuntimeDir $RuntimeDir | Out-Null
Write-Host "Building the runtime at $runtimeCurrent (retiring any previous one) ..."
$reset = Reset-RuntimeDirectory -RuntimeDir $RuntimeDir
$retiredRuntime = $reset.Retired
if ($retiredRuntime) { Write-Host "  previous runtime retired to $retiredRuntime (removed once this build succeeds)" }

try {
    # A user-profile interpreter is unusable by the app pool -- the gMSA cannot
    # read another account's profile -- so it is copied into the runtime tree.
    # A machine-wide interpreter is left where it is and simply referenced: it
    # already lives somewhere non-administrators cannot write -- PROVEN now, not
    # assumed (finding 3): the whole runtime tree passed
    # Get-InterpreterRuntimeViolations before the first elevated probe ran, and
    # copying it would add bytes to verify for no gain.
    $runtimePy = Join-Path $runtimeCurrent "python"
    if ($python.Exe -like "*\AppData\*" -or $python.Exe -like "*\WindowsApps\*") {
        Write-Host "  Python is user-scoped ($($python.Exe)); copying it into the runtime ..."
        $pySrc = Split-Path $python.Exe
        # Finding 3 (2026-08-23): the copy does not launder bytes. Copying a
        # user runtime into the protected root preserves whatever the source
        # tree contained, so the trust decision belongs to the source-side tree
        # gate that already ran -- BEFORE the first probe executed anything
        # from this tree, and therefore before this copy. What is re-asserted
        # here is only the no-links half: a reparse point raced in since the
        # proof would redirect this recursive copy (or a later import) outside
        # the proven tree.
        Assert-NoReparsePoints -Path $pySrc -Context 'user-scoped Python copy source'
        if (Test-Path $pySrc) { Copy-Item -LiteralPath $pySrc -Destination $runtimePy -Recurse -Force }
        $runtimePyExe = Join-Path $runtimePy "python.exe"
        if (-not (Test-Path $runtimePyExe)) {
            $nested = Get-ChildItem -Path $runtimePy -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($nested) { $runtimePyExe = $nested.FullName }
        }
        if (-not (Test-Path $runtimePyExe)) {
            throw "Failed to copy Python into $runtimePy. Install a machine-wide Python 3.12+ and re-run."
        }
        foreach ($vl in @("Lib\venv\scripts\nt\venvlauncher.exe", "Lib\venv\scripts\nt\venvwlauncher.exe")) {
            $vlPath = Join-Path (Split-Path $runtimePyExe) $vl
            if (Test-Path $vlPath) { & (Join-Path $env:windir 'System32\attrib.exe') -H -S $vlPath 2>$null | Out-Null }
        }
        $python = @{ Exe = $runtimePyExe; Args = @() }
        Write-Host "  [ok]   runtime interpreter at $runtimePyExe"
    } else {
        Write-Host "  Using the machine-wide interpreter $($python.Exe) (not copied; runtime tree proven administrator-only)"
    }

    # Clear hidden/system attrs on venv launchers (Python 3.14 marks them) so
    # venv creation does not fail with "Unable to copy ... venvlauncher.exe".
    $pyPrefix = Split-Path $python.Exe
    foreach ($vl in @("Lib\venv\scripts\nt\venvlauncher.exe", "Lib\venv\scripts\nt\venvwlauncher.exe")) {
        $vlPath = Join-Path $pyPrefix $vl
        if (Test-Path $vlPath) { & (Join-Path $env:windir 'System32\attrib.exe') -H -S $vlPath 2>$null | Out-Null }
    }

    # No delete-before-create dance any more: `current` was created empty
    # moments ago, so a planted .pth or sitecustomize.py has nowhere to have
    # survived from. Executed bytes are minted by THIS run, by construction
    # rather than by cleanup.
    Write-Host "  Creating virtualenv at $venv ..."
    $venvOut = & $python.Exe @($python.Args + @("-m", "venv", $venv)) 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
        if ($venvOut) { Write-Host ($venvOut | Out-String) }
        throw "Failed to create virtualenv at $venv using $($python.Exe)."
    }
    $venvPy = Join-Path $venv "Scripts\python.exe"
    $venvProbe = & $venvPy -c "import sys; print(sys.executable)" 2>&1
    if ($LASTEXITCODE -ne 0) {
        if ($venvOut) { Write-Host ($venvOut | Out-String) }
        throw "venv created but python.exe is not functional (exit $LASTEXITCODE): $venvProbe"
    }
    Write-Host "  venv verified: $venvProbe"

Write-Host "Installing acme-adcs-ra ..."

# NO `pip install --upgrade pip` here, deliberately.
#
# It fetched and executed an unpinned, unhashed pip from a live index, as
# Administrator, on an issuance-path host — while the very next commands went to
# great lengths to hash-verify everything else. The venv's bundled pip is the one
# CI's flow uses and is sufficient; a floor check is enough to catch a genuinely
# ancient interpreter without reaching for the network.
# The parse lives in Get-PipMajorVersion (lib/InstallVerifyLib.ps1) because the
# inline version was wrong: `pip --version` emits a trailing empty line, the
# redirected output is therefore a two-element Object[], and `-match` against an
# ARRAY filters instead of capturing. $Matches stayed unset, $Matches[1] read as
# $null, [int]$null was 0, and 0 -lt 23 threw "pip is too old" on pip 26.2.1 --
# blocking every fresh install on Windows, the RA's only production platform.
$pipVerRaw  = (& $venvPy -m pip --version) 2>&1
$pipVerText = ((@($pipVerRaw) | ForEach-Object { $_.ToString() }) -join ' ').Trim()
$pipMajor   = Get-PipMajorVersion $pipVerRaw
if ($pipMajor -ge 0) {
    Write-Host "  pip: $pipVerText"
    if ($pipMajor -lt 23) {
        throw ("Bundled pip is too old for --require-hashes with modern wheels " +
               "(found: $pipVerText). Use a newer Python, or supply an approved pip " +
               "wheel offline and install it with --no-index. Do NOT upgrade pip " +
               "from a live index on an issuance-path host.")
    }
} else {
    Write-Host "  [warn] could not parse pip version: $pipVerText"
}

# Dependencies come from the hash-pinned closure, NOT from a live resolve.
#
# A bare `pip install <repoRoot>` re-resolves every dependency against the
# index at install time, so the closure landing on an issuance-path host was
# not the one CI tested (`uv sync --locked`), and nothing verified what came
# down the wire. deploy/requirements.lock.txt is exported from uv.lock and
# carries a hash for every artifact; --require-hashes makes pip refuse anything
# that does not match. The project itself is then installed --no-deps, so this
# file is the only thing that decides dependency versions.
$lockFile = Join-Path $sourceSnapshot "deploy\requirements.lock.txt"
if (Test-Path $lockFile) {
    Write-Host "  Installing pinned dependencies from deploy/requirements.lock.txt ..."
    & $venvPy -m pip install --require-hashes --only-binary :all: -r $lockFile
    if ($LASTEXITCODE -ne 0) {
        throw ("Pinned dependency install failed (exit $LASTEXITCODE). Do NOT fall back to " +
               "an unpinned install on an issuance-path host: regenerate the lock file " +
               "(uv export --locked ...) for this platform and Python version instead.")
    }
    # The BUILD closure is pinned too, not just the runtime one.
    #
    # `pip install <repoRoot>` builds through PEP 517 isolation by default,
    # which resolves `[build-system] requires = ["hatchling"]` from the index at
    # install time — unversioned, unhashed, running as Administrator. The
    # runtime pinning above made that easy to miss: everything in the install
    # log was hash-verified, and the build closure never appeared in the log.
    # Preinstall it by hash, then build with isolation OFF so nothing is fetched.
    $buildLock = Join-Path $sourceSnapshot "deploy\build-requirements.lock.txt"
    if (-not (Test-Path $buildLock)) {
        throw ("deploy/build-requirements.lock.txt is missing. It pins the PEP 517 " +
               "build closure by hash and is required for an issuance-path install. " +
               "Copy the full repository, or regenerate it (see the file header).")
    }
    Write-Host "  Installing pinned build closure from deploy/build-requirements.lock.txt ..."
    & $venvPy -m pip install --require-hashes --only-binary :all: -r $buildLock
    if ($LASTEXITCODE -ne 0) {
        throw ("Pinned build-closure install failed (exit $LASTEXITCODE). Do NOT fall " +
               "back to an isolated build on an issuance-path host: that resolves the " +
               "build backend from the index unpinned. Regenerate the lock for this " +
               "platform and Python version instead.")
    }
    & $venvPy -m pip install --no-deps --no-build-isolation --upgrade $sourceSnapshot
    if ($LASTEXITCODE -ne 0) { throw "pip install of acme-adcs-ra failed (exit $LASTEXITCODE)." }
} else {
    # The lock file ships with the repo; its absence means an incomplete copy.
    throw ("deploy/requirements.lock.txt is missing. It pins the production dependency " +
           "closure by hash and is required for an issuance-path install. Copy the full " +
           "repository, or regenerate it with: uv export --locked --format requirements-txt " +
           "--no-emit-project --no-dev -o deploy/requirements.lock.txt")
}
$installedVer = ((& $venvPy -m pip show acme-adcs-ra 2>$null | Select-String "^Version:") -replace "^Version:\s*", "").Trim()
Write-Host "  Installed acme-adcs-ra version: $installedVer"

    # The retired runtime goes NOW, before the proof, not after it.
    #
    # It sits inside $RuntimeDir, so leaving it in place would put an entire
    # second (old) venv inside the recursive ownership reset and the read-back
    # proof below -- doubling their cost, and letting anything odd in a tree we
    # are about to delete fail the proof of the tree we just built.
    #
    # The trade: past this line a rollback is no longer possible. That is the
    # right way round. A build failure is recoverable and rolls back; a PROOF
    # failure means the newly built tree's ownership or DACLs are not what this
    # installer set, which is a "something else on this host is interfering"
    # condition -- and the correct response to that is to stop with the pool
    # still down, not to quietly serve the old runtime.
    if ($retiredRuntime -and (Test-Path -LiteralPath $retiredRuntime)) {
        Assert-NoReparsePoints -Path $retiredRuntime -Context 'retired runtime removal'
        Remove-Item -LiteralPath $retiredRuntime -Recurse -Force
        $retiredRuntime = $null
    }

    # Normalise ownership across everything pip just created (files an
    # administrator creates are owned by that ACCOUNT, not the Administrators
    # group), re-assert the exact runtime DACL, and prove the whole tree. Only
    # now is the runtime allowed to be considered live. The ROOT keeps its
    # protected DACL throughout (children-only reset + SkipReset re-assert):
    # a root-level /reset would re-inherit the parent's create-class ACEs
    # until /inheritance:r restores (live-proven 2026-08-16).
    Write-Host "Securing and proving the runtime at $RuntimeDir ..."
    Assert-NoReparsePoints -Path $RuntimeDir -Context 'runtime proof'
    Reset-TreeChildrenToInherited -Path $RuntimeDir
    Set-ObjectProtectedDacl -Path $RuntimeDir -Grants $runtimeGrants -SkipReset
    Assert-InstallTreeLocked -Root $RuntimeDir -AllowedTrustees $raTrustees `
        -AllowedOwnerSids @('S-1-5-32-544', 'S-1-5-18')
    Write-Host "  [ok]   runtime verified (Administrators/SYSTEM own every object; gMSA read+execute only)"
} catch {
    # A failed build must not leave the host with no runtime. Put the retired
    # one back and re-throw, so the operator gets the real error and a machine
    # that still serves what it served before.
    if ($retiredRuntime) {
        Write-Host "  [!!] runtime build failed; restoring the previous runtime from $retiredRuntime"
        try {
            if (Restore-RetiredRuntime -RuntimeDir $RuntimeDir -Retired $retiredRuntime) {
                Write-Host "  [ok]   previous runtime restored"
            } else {
                Write-Host ("  [!!] nothing to restore -- $retiredRuntime is gone. This host has NO " +
                            "runtime at $runtimeCurrent until a successful re-run.")
            }
        } catch {
            Write-Host ("  [!!] restore ALSO failed: $($_.Exception.Message). The previous runtime is " +
                        "still at $retiredRuntime -- rename it to $runtimeCurrent by hand.")
        }
    } else {
        # Past the point of no rollback: the build got far enough that the old
        # runtime was already discarded. Say so plainly rather than letting the
        # operator assume the previous install is still serving.
        Write-Host ("  [!!] the runtime at $runtimeCurrent was built but did NOT pass verification, " +
                    "and there is no previous runtime to fall back to. The app pool has been left " +
                    "stopped deliberately. Fix the reported problem and re-run.")
    }
    # The runtime is only half the story. The state claim's /reset stripped the
    # dotenv's protected DACL at the top of this run and the re-protect below
    # was never reached -- without this, a failed build leaves acme-ra.env
    # (EAB allowlist + SAN scopes) inheriting gMSA MODIFY, and the next
    # install's pre-flight refuses the whole tree. Restore the protected DACL
    # and re-prove the state tree so the rollback is complete for BOTH trees.
    try {
        if (Test-Path -LiteralPath $envFile) {
            Set-ObjectProtectedDacl -Path $envFile -Grants @(
                '*S-1-5-32-544:F', '*S-1-5-18:F', ($GmsaAccount + ':R')
            )
            Assert-InstallTreeLocked -Root $InstallDir -AllowedTrustees $raTrustees `
                -AllowedOwnerSids $stateOwnerSids `
                -ProtectedEntries @{ 'acme-ra.env' = $raTrustees } `
                -ForbiddenTopLevelEntries $stateForbiddenEntries
            Write-Host "  [ok]   state tree re-protected and re-proven (dotenv gMSA read-only)"
        }
    } catch {
        Write-Host ("  [!!] state tree could NOT be re-proven after the rollback: " +
                    "$($_.Exception.Message). Fix the state tree by hand before re-running -- " +
                    "the next install's pre-flight will refuse it otherwise.")
    }
    throw
}

# --- State directory contents (never executed) -------------------------------
Write-Host "Creating state directories under $InstallDir ..."
foreach ($d in @($InstallDir, $logs)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

# --- Lay down the locked, no-clobber secret env file -------------------------
# Holds the EAB credential(s) + optional SIEM HEC token. NEVER taken on the
# command line (would hit shell history). The operator fills the EAB entries.
if (Test-Path $envFile) {
    Write-Host "Keeping existing $envFile (preserving operator EAB/secret settings)."
} else {
    Write-Host "Writing starter env file $envFile (fill in the EAB credential before first use) ..."
    $envTemplate = @"
# acme-adcs-ra secret-bearing config (loaded via ACME_RA_DOTENV).
# Readable only by the gMSA + Administrators. Do NOT commit. Non-secret settings
# live in web.config; put ONLY secrets / EAB here.
#
# EAB allowlist: one credential per authorized ACME client (e.g. Certify the
# Web), pinned by a high-entropy kid (UUID / >=128-bit). pydantic-settings parses
# this JSON env var into the EAB list. Replace the placeholder kid + mac_key:
ACME_RA_EAB_ALLOWLIST=[{"kid":"REPLACE-WITH-UUID","mac_key":"REPLACE-WITH-BASE64URL-KEY"}]
#
# Per-kid SAN scope (the critical control: in-scope SANs issue without domain
# proof). Restrict to the hostnames this client may request:
ACME_RA_SAN_SCOPES={"REPLACE-WITH-UUID":{"dns_patterns":["*.work-domain.local"]}}
#
# Optional SIEM HEC token (leave blank for the default jsonl sink):
# ACME_RA_SIEM_SINK=hec
# ACME_RA_SIEM_HEC_URL=https://splunk.work-domain.local:8088/services/collector
# ACME_RA_SIEM_HEC_TOKEN=
"@
    [System.IO.File]::WriteAllText($envFile, $envTemplate, (New-Object System.Text.UTF8Encoding $false))
}

# --- Re-assert and prove the STATE tree --------------------------------------
#
# The state root was claimed at the top of the run; this pass covers what the
# install itself created since (the logs directory, the dotenv) and normalises
# their ownership, because a file an administrator creates is owned by that
# ACCOUNT rather than the Administrators group. Same reset+protect+prove
# sequence as the claim, using the same grant strings, so the two cannot drift
# -- and the proof it leaves behind is exactly what the NEXT run's pre-flight
# will demand before it agrees this directory is ours.
#
# Note what this tree does NOT contain any more: the interpreter, the venv, and
# the manifest that used to vouch for them. Code lives under %ProgramFiles%
# with no gMSA write ACE at all, so the app pool can no longer rewrite what it
# is about to be relaunched with.
#
# The root keeps its protected DACL throughout this pass (children-only reset +
# SkipReset re-assert). A root-level /reset re-inherits %ProgramData%'s
# Users (CI)(WD,AD,WEA,WA) for the interval before /inheritance:r restores --
# a live standard-user loop planted entries through exactly that window
# (2026-08-16 re-proof; caught by this same proof, but the write must be
# impossible, not merely detected).
Write-Host "Securing and proving the state tree at $InstallDir ..."
Assert-NoReparsePoints -Path $InstallDir -Context 'post-install ACL pass'
Reset-TreeChildrenToInherited -Path $InstallDir
Set-ObjectProtectedDacl -Path $InstallDir -Grants $stateGrants -SkipReset
# The dotenv carries its own DACL: gMSA READ-ONLY. The worker must never be
# able to rewrite its own EAB credentials or SAN scope -- those decide what it
# is allowed to issue.
Set-ObjectProtectedDacl -Path $envFile -Grants @(
    '*S-1-5-32-544:F', '*S-1-5-18:F', ($GmsaAccount + ':R')
)
Assert-InstallTreeLocked -Root $InstallDir -AllowedTrustees $raTrustees `
    -AllowedOwnerSids @('S-1-5-32-544', 'S-1-5-18') `
    -ProtectedEntries @{ 'acme-ra.env' = $raTrustees } `
    -ForbiddenTopLevelEntries $stateForbiddenEntries
Write-Host "  [ok]   state tree verified locked (ownership + DACLs read back and proven)"

# --- The web.config the pool launches from is launch configuration ----------
#
# Daybreak round 5: this check used to be a warning with a swallowed parse
# failure, which meant a pre-planted or half-migrated web.config kept
# launching an interpreter inside the gMSA-writable state tree while the
# install stayed green. It is a refusal now, on every run: web.config names
# the executable IIS starts as the gMSA, so an unprovable launch
# configuration fails the install, on the exact commit being shipped.
$siteWcPath = Join-Path $SitePath 'web.config'
if (Test-Path -LiteralPath $siteWcPath) {
    Assert-WebConfigLaunchTrusted -WebConfigPath $siteWcPath -InstallDir $InstallDir `
        -RuntimeDir $RuntimeDir -ExpectedProcessPath "$venv\Scripts\python.exe"
    Write-Host "  [ok]   $siteWcPath launch configuration verified (processPath inside the runtime tree)"
}

# --- Grant the gMSA "Log on as a service" (best-effort) ----------------------
# An IIS app pool running as a gMSA needs SeServiceLogonRight, or the pool fails
# to start ("service did not respond in a timely fashion"). Best-effort via
# secedit; on failure we print the manual fix.
function Grant-ServiceLogonRight {
    param([string]$AccountSid)
    try {
        $tmpDir = Join-Path $installerScratch ("ra-secpol-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
        $cfg = Join-Path $tmpDir "secpol.cfg"
        $db  = Join-Path $tmpDir "secpol.sdb"
        $secedit = Join-Path $env:windir 'System32\secedit.exe'
        & $secedit /export /cfg $cfg /areas USER_RIGHTS | Out-Null
        $lines = Get-Content $cfg
        $rightLine = ($lines | Where-Object { $_ -match "^SeServiceLogonRight" } | Select-Object -First 1)
        if ($rightLine -and ($rightLine -match [regex]::Escape($AccountSid))) {
            Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
            return $true
        }
        if (-not $rightLine) { $rightLine = "SeServiceLogonRight =" }
        if ($rightLine -match "=\s*$") { $newLine = "$($rightLine.TrimEnd()) *$AccountSid" }
        else { $newLine = "$($rightLine.TrimEnd()),*$AccountSid" }
        $found = $false
        $out = foreach ($l in $lines) {
            if ($l -match "^SeServiceLogonRight") { $found = $true; $newLine } else { $l }
        }
        if (-not $found) {
            $out = foreach ($l in $lines) { $l; if ($l -match "^\[Privilege Rights\]") { $newLine } }
        }
        Set-Content -Path $cfg -Value $out -Encoding Unicode
        & $secedit /import /db $db /cfg $cfg /areas USER_RIGHTS | Out-Null
        & $secedit /configure /db $db /areas USER_RIGHTS | Out-Null
        Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        return $true
    } catch { return $false }
}

$script:iisActuallyConfigured = $false

if ($ConfigureIIS) {
    Write-Host ""
    Write-Host "Configuring IIS ..."
    # Finding 5 (2026-08-23): the IIS:\ provider everything below uses is
    # imported from the canonical inbox module root by absolute path, never by
    # name from PSModulePath (whose user-writable entries can carry a
    # same-named module). Unavailable-or-untrusted keeps the existing skip.
    if (-not (Import-TrustedInboxModule -ModuleName 'WebAdministration')) {
        Write-Host "  [skip] WebAdministration module not available from the trusted inbox module root; skipping IIS config. See deploy\iis\README.md."
    } else {

        # Round 5: SitePath is the third security-relevant tree -- web.config
        # inside it is the gMSA launch configuration. A pre-existing site tree
        # must PROVE itself (no reparse points, every object administrator-
        # owned, no write-class ACE for a broad trustee anywhere in it) or the
        # install refuses; a fresh one is created locked-at-birth exactly like
        # the managed roots. The earlier code adopted whatever was on disk.
        $siteGrants = @(
            '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', ('*' + $gmsaSid + ':(OI)(CI)RX')
        )
        $siteFresh = $false
        if (Test-Path -LiteralPath $SitePath) {
            Write-Host "  Proving the pre-existing site tree $SitePath ..."
            $siteRoot = Get-Item -LiteralPath $SitePath -Force -ErrorAction Stop
            if (-not (Test-InstallRootAttributesAcceptable $siteRoot.Attributes)) {
                throw "$SitePath is not an ordinary directory; a site-root reparse point is refused."
            }
            $reparse = @(Find-ReparsePoints -Path $SitePath)
            if ($reparse.Count -gt 0) {
                throw ("$SitePath contains reparse points ($($reparse -join ', ')). A link inside the " +
                       "launch-configuration tree can redirect what IIS reads as the gMSA launch " +
                       "configuration. Remove or rename the site directory and re-run.")
            }
            # WI-015: the ancestor chain, not only the tree itself. Round 2
            # deliberately WITHHELD this half pending a live DACL baseline,
            # because a default IIS install might legitimately have failed it.
            # Surveyed live on the lab IIS host 2026-08-17: C:\inetpub and
            # C:\inetpub\acme-adcs-ra are both CLEAN -- Users hold (RX) and
            # (OI)(CI)(IO)(GR,GE), read and execute, no write-class access
            # anywhere on the chain. The same survey discriminates rather than
            # passing everything: C:\ProgramData\acme-adcs-ra reports two
            # violations on the same function. So the refusal can be added
            # without breaking a default install, which is the evidence this
            # was waiting on.
            #
            # A writable directory ABOVE the site root is not a lesser problem
            # than a writable file inside it: it lets a local user rename the
            # tree aside and substitute their own, web.config included, and
            # web.config is what names the executable IIS starts as the gMSA.
            $siteViol = @(Get-TreeTrustViolations -Path $SitePath)
            if (@($siteViol).Count -gt 0) {
                throw ("The pre-existing site tree $SitePath is not administrator-only " +
                       "(the tree itself, its contents, or a directory above it):`n  " +
                       (($siteViol | Select-Object -First 8) -join "`n  ") +
                       "`nweb.config under it is the gMSA launch configuration: a tree a local user " +
                       "can write is a tree that decides what runs as the gMSA. Inspect the site " +
                       "directory, remove or rename it, and re-run so this installer creates it locked.")
            }
            Write-Host "  [ok]   site tree proven: administrator-only, no reparse points"
        } else {
            if (-not (New-AtomicProtectedDirectory -Path $SitePath -Grants $siteGrants)) {
                throw "$SitePath appeared during creation; refusing to adopt a raced site tree."
            }
            $siteFresh = $true
            Write-Host "  [ok]   created $SitePath atomically with its final protected DACL"
        }

        $webConfigSrc = Join-Path $sourceSnapshot "deploy\iis\web.config"
        $webConfigDst = Join-Path $SitePath "web.config"
        # Do NOT clobber an existing web.config -- it holds operator-set BASE_URL,
        # ADCS_HOST/TEMPLATE/CA_NAME, etc. Lay the template down only on a fresh
        # install; to reset, delete it and re-run.
        if (Test-Path $webConfigDst) {
            Write-Host "  Keeping existing web.config (preserving operator settings)."
        } else {
            Copy-Item $webConfigSrc $webConfigDst -Force
            # Two substitutions now, not one: processPath points into the
            # RUNTIME tree (%ProgramFiles%) and ACME_RA_DOTENV into the STATE
            # tree (%ProgramData%). The runtime one must be rewritten first --
            # the default runtime path contains the default state path nowhere,
            # but doing them in a fixed order keeps the result deterministic if
            # an operator ever nests one inside the other.
            $defaultRuntime = "C:\Program Files\acme-adcs-ra"
            $defaultState   = "C:\ProgramData\acme-adcs-ra"
            $wcContent = Get-Content $webConfigDst -Raw
            if ($RuntimeDir -ne $defaultRuntime) { $wcContent = $wcContent.Replace($defaultRuntime, $RuntimeDir) }
            if ($InstallDir -ne $defaultState)   { $wcContent = $wcContent.Replace($defaultState, $InstallDir) }
            try { $null = [xml]$wcContent } catch { throw "web.config rewrite produced invalid XML" }
            [System.IO.File]::WriteAllText($webConfigDst, $wcContent, (New-Object System.Text.UTF8Encoding $false))
            Write-Host "  Wrote template web.config -- EDIT ACME_RA_BASE_URL + ACME_RA_ADCS_* before first use."
        }

        # Round 5: validate the launch configuration BEFORE IIS is reconfigured
        # and before the pool starts -- preserved operator settings included.
        # Unparseable or missing processPath, or a processPath outside the
        # runtime tree (worst case inside the gMSA-writable state tree), is a
        # refusal, not a warning: this file decides which executable IIS
        # starts as the gMSA.
        Assert-WebConfigLaunchTrusted -WebConfigPath $webConfigDst -InstallDir $InstallDir `
            -RuntimeDir $RuntimeDir -ExpectedProcessPath "$venv\Scripts\python.exe"
        Write-Host "  [ok]   launch configuration verified (processPath inside the runtime tree)"

        Write-Host "  Unlocking system.webServer/handlers ..."
        & $appcmdExe unlock config -section:system.webServer/handlers
        if ($LASTEXITCODE -ne 0) { throw "Failed to unlock handlers. Run: appcmd unlock config -section:system.webServer/handlers" }

        $poolPath = "IIS:\AppPools\$AppPool"
        if (-not (Get-Item $poolPath -ErrorAction SilentlyContinue)) {
            Write-Host "  Creating app pool `"$AppPool`" ..."
            New-Item $poolPath | Out-Null
        }
        Set-ItemProperty $poolPath -Name managedRuntimeVersion -Value ""
        Set-ItemProperty $poolPath -Name startMode -Value "AlwaysRunning"
        Set-ItemProperty $poolPath -Name processModel.idleTimeout -Value "00:00:00"
        Set-ItemProperty $poolPath -Name recycling.periodicRestart.time -Value "00:00:00"
        # *** Run the pool AS THE gMSA (identityType 3 = SpecificUser, no password) ***
        Set-ItemProperty $poolPath -Name processModel.identityType -Value 3
        Set-ItemProperty $poolPath -Name processModel.userName -Value $GmsaAccount
        Set-ItemProperty $poolPath -Name processModel.password -Value ""
        Write-Host "  App pool configured (No Managed Code, AlwaysRunning, identity = $GmsaAccount)."

        Write-Host "  Granting $GmsaAccount the Log-on-as-a-service right ..."
        if (-not (Grant-ServiceLogonRight -AccountSid $gmsaSid)) {
            Write-Host "  [warn] Could not auto-grant SeServiceLogonRight. If the pool will not start, grant it manually:"
            Write-Host "         secpol.msc -> Local Policies -> User Rights Assignment -> Log on as a service -> add $GmsaAccount"
        }

        if ($SharePort443 -and -not $HostName) { throw "-SharePort443 requires -HostName so IIS can route by SNI." }

        $siteName = "acme-adcs-ra"
        $sitePathIIS = "IIS:\Sites\$siteName"
        $bindingInfo = "*:$($Port):$HostName"
        $sslFlagsValue = if ($SharePort443) { 1 } else { 0 }
        if (-not (Get-Item $sitePathIIS -ErrorAction SilentlyContinue)) {
            Write-Host "  Creating IIS site `"$siteName`" ..."
            New-Item $sitePathIIS -bindings @{protocol="https"; bindingInformation=$bindingInfo; sslFlags=$sslFlagsValue} -physicalPath $SitePath | Out-Null
            Set-ItemProperty $sitePathIIS -Name applicationPool -Value $AppPool
        } else {
            Set-ItemProperty $sitePathIIS -Name applicationPool -Value $AppPool
            Set-ItemProperty $sitePathIIS -Name physicalPath -Value $SitePath
            $siteBindings = Get-ItemProperty $sitePathIIS -Name bindings
            foreach ($b in $siteBindings.Collection) {
                if ($b.protocol -eq "https") {
                    $changed = $false
                    if ($b.bindingInformation -ne $bindingInfo) { $b.bindingInformation = $bindingInfo; $changed = $true }
                    if ($b.sslFlags -ne $sslFlagsValue) { $b.sslFlags = $sslFlagsValue; $changed = $true }
                    if ($changed) { Set-ItemProperty $sitePathIIS -Name bindings -Value $siteBindings }
                    break
                }
            }
        }

        # TLS binding (add-before-delete so HTTPS is never left unbound on a switch).
        function Ensure-SslCertBinding {
            param([string]$BindingArgument, [string]$Thumbprint, [string]$AppId)
            $show = & $netshExe http show sslcert $BindingArgument 2>&1 | Out-String
            if ($show -match [regex]::Escape($Thumbprint)) { Write-Host "    Certificate already bound to $BindingArgument."; return }
            & $netshExe http delete sslcert $BindingArgument 2>$null | Out-Null
            $addOut = & $netshExe http add sslcert $BindingArgument certhash="$Thumbprint" appid="$AppId" certstorename=MY 2>&1
            if ($LASTEXITCODE -ne 0) { Write-Host ($addOut | Out-String); throw "Failed to bind TLS cert to $BindingArgument (netsh exit $LASTEXITCODE)." }
            $show = & $netshExe http show sslcert $BindingArgument 2>&1 | Out-String
            if ($show -notmatch [regex]::Escape($Thumbprint)) { throw "TLS binding verification failed for $BindingArgument." }
        }

        if ($TlsCertThumbprint) {
            Write-Host "  Binding TLS certificate $TlsCertThumbprint ..."
            $appId = "{B2C3D4E5-F6A7-8901-BCDE-F23456789012}"
            $ipport = "0.0.0.0:$Port"
            $hostPort = "$HostName`:$Port"
            if ($SharePort443) {
                Ensure-SslCertBinding -BindingArgument "hostnameport=$hostPort" -Thumbprint $TlsCertThumbprint -AppId $appId
                $catchallShow = & $netshExe http show sslcert ipport="$ipport" 2>&1 | Out-String
                if ($catchallShow -match [regex]::Escape($TlsCertThumbprint)) {
                    & $netshExe http delete sslcert ipport="$ipport" 2>$null | Out-Null
                } elseif ($catchallShow -match "Certificate Hash") {
                    Write-Warning "A catch-all $ipport bound to a DIFFERENT cert (a sibling tool?) WILL shadow this SNI binding. Convert that tool to SNI or remove its catch-all."
                }
                Write-Host "    TLS bound to hostnameport=$hostPort (SNI)."
            } else {
                Ensure-SslCertBinding -BindingArgument "ipport=$ipport" -Thumbprint $TlsCertThumbprint -AppId $appId
                if ($HostName) { & $netshExe http delete sslcert hostnameport="$hostPort" 2>$null | Out-Null }
                Write-Host "    TLS bound to $ipport (catch-all)."
            }
        } else {
            Write-Host "  [warn] No -TlsCertThumbprint. HTTPS binding exists but no certificate is assigned."
        }

        # /L: the site path is as predictable as the install root, and this
        # grant runs elevated -- it must not be redirectable by a link either
        # (2026-08-15 rescan-2 F2). A site tree created THIS run already
        # carries the grant (New-AtomicProtectedDirectory), and a duplicate
        # /grant would add a second gMSA ACE to the protected DACL.
        if (-not $siteFresh) {
            $siteAclOut = & $script:IcaclsExe $SitePath /grant "${GmsaAccount}:(OI)(CI)R" /L 2>&1
            if (-not (Test-IcaclsOutputClean -ExitCode $LASTEXITCODE -Output $siteAclOut)) {
                throw ("Failed to grant the gMSA read access to $SitePath (exit $LASTEXITCODE): " +
                       (($siteAclOut | Out-String).Trim()))
            }
        }

        Write-Host "  Starting app pool `"$AppPool`" ..."
        & $appcmdExe start apppool /apppool.name:"$AppPool" 2>$null | Out-Null
        Start-Sleep -Seconds 2
        $poolState = (& $appcmdExe list apppool "$AppPool" /text:state) 2>$null
        Write-Host "    App pool state: $poolState"
        if ("$poolState" -ne "Started") {
            Write-Host "    [warn] App pool not Started -> the site returns HTTP 503. Most likely cause: the gMSA lacks Log-on-as-a-service, or is not installed on this host. See warnings above."
        }
        $script:iisActuallyConfigured = $true
    }
}

if ($script:poolWasStopped -and -not $script:iisActuallyConfigured) {
    Write-Host "Restarting app pool `"$AppPool`" (was stopped to release files) ..."
    & $appcmdExe start apppool /apppool.name:"$AppPool" 2>$null | Out-Null
}

Remove-InstallerScratch

Write-Host ""
Write-Host "Done. acme-adcs-ra is installed in two separate trees, on purpose:"
Write-Host ""
Write-Host "  CODE   $runtimeCurrent"
Write-Host "         Administrators/SYSTEM full; $GmsaAccount read + EXECUTE only."
Write-Host "         Rebuilt from scratch on every install. Never written by the app."
Write-Host "  STATE  $InstallDir"
Write-Host "         Administrators/SYSTEM full; $GmsaAccount modify."
Write-Host "         Audit DB: $InstallDir\acme_ra.db   Env file: $envFile"
Write-Host "         Nothing here is ever executed."
Write-Host ""
Write-Host "         Do not move code into the state tree or grant the gMSA write access"
Write-Host "         to the code tree. That separation is the control; see"
Write-Host "         docs/operator-requirements.md."
if ($script:iisActuallyConfigured) {
    Write-Host "IIS site: $SitePath   App pool: $AppPool (as $GmsaAccount)"
    $dispHost = if ($HostName) { $HostName } else { $env:COMPUTERNAME }
    $portSuffix = if ($Port -eq 443) { "" } else { ":$Port" }
    Write-Host "ACME directory: https://$dispHost$portSuffix/directory"
}
Write-Host ""
Write-Host "Before first use:"
Write-Host "  1. Fill the EAB credential + SAN scope in $envFile (pinned to your ACME client)."
Write-Host "  2. Set ACME_RA_BASE_URL + ACME_RA_ADCS_* in $SitePath\web.config."
Write-Host "  3. RESTRICT the endpoint to the ACME client (threat-model pilot condition): add"
Write-Host "     <ipSecurity> to web.config (needs the IP-and-Domain-Restrictions role) or a"
Write-Host "     scoped firewall rule. Port 443 may be SNI-shared with cert-watch on this VM."
Write-Host "  4. Confirm the Negotiate stack imports (Python $major.$minor): & `"$venvPy`" -c `"import spnego; import acme_adcs_ra.negotiate_auth`""
