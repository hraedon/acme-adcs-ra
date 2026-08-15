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
    # Prerequisite handling. -InstallPrereqs installs the safely-native prereqs
    # (IIS role + features via Install-WindowsFeature; Python 3.12+ via winget).
    # HttpPlatformHandler is a third-party MSI with an unreliable download, so it
    # is NEVER auto-fetched from the internet: pass a vetted local path (or an
    # https:// URL plus -HttpPlatformHandlerSha256) via -HttpPlatformHandlerMsi
    # to have it installed. Whatever the source, the MSI is verified by digest
    # and Authenticode publisher before msiexec sees it -- it is the one
    # third-party executable this installer runs, and it runs elevated.
    [switch]$InstallPrereqs,
    [string]$HttpPlatformHandlerMsi = "",
    # Expected SHA-256 of the MSI. REQUIRED when -HttpPlatformHandlerMsi is a
    # URL: TLS authenticates the origin, not the bytes, and this artifact is run
    # by msiexec as Administrator on the issuance host. Optional (but checked
    # when given) for a local path the operator has already vetted.
    [string]$HttpPlatformHandlerSha256 = "",
    # Expected Authenticode publisher, matched as a substring of the signer
    # certificate's Subject. HttpPlatformHandler is a Microsoft IIS module; a
    # deployment that repackages it under its own code-signing certificate
    # overrides this.
    [string]$HttpPlatformHandlerPublisher = "CN=Microsoft Corporation"
)

$ErrorActionPreference = "Stop"

# Artifact-authenticity decisions for the prerequisite MSI (2026-08-17 F1).
# Pure functions, so tests/pester/InstallVerify.Tests.ps1 covers the matrix
# without a signed file or a live download.
. "$PSScriptRoot/lib/InstallVerifyLib.ps1"

# Bare executable names handed to `cmd /c` resolve from the CURRENT DIRECTORY
# before PATH (Daybreak round 4). An elevated shell whose CWD is user-writable
# (a extracted source tree under %TEMP%, a share, a Downloads folder) would
# execute a planted python.exe/py.exe AS ADMINISTRATOR during the interpreter
# probe below. Defining this variable removes the CWD from the child-process
# search path for this process and everything it launches. PowerShell itself
# never searches the CWD for commands, so only the cmd /c call sites needed it.
$env:NoDefaultCurrentDirectoryInExePath = '1'

# --- Must be elevated (we write under ProgramData, set ACLs, configure IIS) ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run from an elevated (Administrator) PowerShell."
}

$repoRoot = (Resolve-Path "$PSScriptRoot\..").Path
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
    try {
        if (Get-Command Get-WebGlobalModule -ErrorAction SilentlyContinue) {
            $m = Get-WebGlobalModule -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq "httpPlatformHandler" }
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
    if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
        foreach ($f in $RequiredIisFeatures) {
            $state = Get-WindowsFeature -Name $f -ErrorAction SilentlyContinue
            if ($state -and $state.Installed) {
                Write-Host "  [ok]   IIS feature $f already installed."
            } else {
                Write-Host "  [..]   Installing IIS feature $f ..."
                $res = Install-WindowsFeature -Name $f -IncludeManagementTools -ErrorAction Continue
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
        $msi = $HttpPlatformHandlerMsi
        $sourceKind = Assert-MsiSourceAcceptable -Source $msi -Sha256 $HttpPlatformHandlerSha256

        if ($sourceKind -eq 'https') {
            $dest = Join-Path $env:TEMP "HttpPlatformHandler.msi"
            Write-Host "  [..]   Downloading HttpPlatformHandler from $msi ..."
            try { Invoke-WebRequest -Uri $msi -OutFile $dest -UseBasicParsing } catch { throw "Download failed: $($_.Exception.Message)" }
            $msi = $dest
        }
        if (-not (Test-Path $msi)) { throw "HttpPlatformHandler MSI not found: $msi" }

        # 1. Digest, when one was supplied (always, for a downloaded artifact --
        #    Assert-MsiSourceAcceptable refuses a remote source without it).
        if ($HttpPlatformHandlerSha256) {
            $actualHash = (Get-FileHash -Algorithm SHA256 -Path $msi).Hash
            if (-not (Test-Sha256Match -Actual $actualHash -Expected $HttpPlatformHandlerSha256)) {
                throw ("HttpPlatformHandler MSI SHA-256 mismatch. Expected {0}, got {1}. " -f
                       $HttpPlatformHandlerSha256, $actualHash) +
                      "NOT installing. Delete the downloaded copy and obtain the artifact again."
            }
            Write-Host "  [ok]   MSI SHA-256 matches the expected digest."
        } else {
            Write-Host "  [..]   No -HttpPlatformHandlerSha256 given for this local MSI; relying on the Authenticode check below."
        }

        # 2. Authenticode signature and publisher. The digest proves the bytes
        #    are the ones the operator named; this proves who made them, which
        #    is what catches a wrong-but-consistently-hashed artifact.
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

        Write-Host "  [..]   Installing HttpPlatformHandler from $msi ..."
        $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "msiexec failed installing HttpPlatformHandler (exit $($p.ExitCode))." }
        if (Test-HttpPlatformHandler) { Write-Host "  [ok]   HttpPlatformHandler installed." }
        else { Write-Host "  [warn] HttpPlatformHandler MSI ran but the module is not detected; verify in IIS." }
    } else {
        Write-Host "  [warn] HttpPlatformHandler is MISSING and no -HttpPlatformHandlerMsi was given."
        Write-Host "         It is a separate Microsoft IIS module (the download has been unreliable, so"
        Write-Host "         it is not auto-fetched). Get the v1.2 amd64 MSI from"
        Write-Host "         https://www.iis.net/downloads/microsoft/httpplatformhandler and either run it"
        Write-Host "         by hand or re-run with -HttpPlatformHandlerMsi <path-to-msi>."
    }

    # 3. Python 3.12+ via winget (winget verifies its own packages). Best-effort.
    $havePy = $false
    foreach ($probe in @("py -3.12 --version", "py -3 --version", "python --version")) {
        $parts = $probe.Split(" ")
        if (Get-Command $parts[0] -ErrorAction SilentlyContinue) {
            $out = & cmd /c "$probe 2>&1"
            if ($out -match "Python\s+3\.(1[2-9]|[2-9]\d)") { $havePy = $true; break }
        }
    }
    if ($havePy) {
        Write-Host "  [ok]   Python 3.12+ already present."
    } elseif (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "  [..]   Installing Python 3.12 via winget ..."
        & winget install --id Python.Python.3.12 -e --source winget --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
        Write-Host "  [ok]   winget install attempted (the discovery step below confirms)."
    } else {
        Write-Host "  [warn] No Python 3.12+ and winget is unavailable. Install Python 3.12+ manually."
    }
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
    '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', ($GmsaAccount + ':(OI)(CI)RX')
)
# STATE: modify for the worker (it writes the database and the log), full for
# administrators. Nothing here is ever executed.
$stateGrants = @(
    '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', ($GmsaAccount + ':(OI)(CI)M')
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
    switch ($prov.State) {
        'foreign' {
            throw (Get-ForeignRootRefusal -Path $Path -Purpose $Purpose `
                       -Reasons $prov.Reasons -Preserve $Preserve)
        }
        'absent' {
            # TOCTOU (Daybreak round 4): between the provenance check above and
            # this creation, a local attacker can pre-create the predictable
            # path -- and -Force accepted their directory as if we had made it.
            # Everything downstream then worked FOR them: setowner /t
            # normalised their files to Administrators-owned, the reset and
            # proof passed, the re-protect protected their planted dotenv, and
            # "preserving operator EAB settings" shipped an attacker-chosen EAB
            # allowlist and SAN scope. The adoption finding, reopened by race.
            #
            # Create WITHOUT -Force -- on an existing path that THROWS -- and on
            # the collision, re-run the verdict on what actually appeared. A
            # non-administrator cannot set owner to Administrators, so their
            # tree can only re-verify as 'foreign' and hit the refusal above;
            # 'ours' is unreachable for them and the retry cannot loop.
            try {
                New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null
                Write-Host "  [ok]   created $Path"
            } catch {
                if (-not (Test-Path -LiteralPath $Path)) { throw }
                Write-Host "  [!!]  $Path appeared between the absence check and creation -- re-verifying it"
                $prov = Get-RootProvenance -Path $Path -AllowedTrustees $AllowedTrustees `
                    -AllowedOwnerSids $AllowedOwnerSids -ProtectedEntries $ProtectedEntries `
                    -ForbiddenTopLevelEntries $ForbiddenTopLevelEntries
                if ($prov.State -ne 'ours') {
                    throw (Get-ForeignRootRefusal -Path $Path -Purpose $Purpose `
                               -Reasons $prov.Reasons -Preserve $Preserve)
                }
                Write-Host "  [ok]   $Path recognised as a previous install of this RA"
            }
        }
        default {
            Write-Host "  [ok]   $Path recognised as a previous install of this RA"
        }
    }
    # Normalise ownership and discard every explicit ACE, then apply exactly our
    # grants, then read the whole tree back and prove it. The proof is not
    # ceremony: "we ran icacls" is not evidence, and this is the same evidence
    # the NEXT run's pre-flight will demand.
    Assert-NoReparsePoints -Path $Path -Context "$Purpose claim"
    Reset-TreeToInherited -Path $Path
    Set-ObjectProtectedDacl -Path $Path -Grants $Grants
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

Initialize-SecuredRoot -Path $InstallDir -Purpose 'state (database, logs, secrets)' `
    -Grants $stateGrants -AllowedTrustees $raTrustees `
    -AllowedOwnerSids $stateOwnerSids `
    -ProtectedEntries @{ 'acme-ra.env' = $raTrustees } `
    -ForbiddenTopLevelEntries $stateForbiddenEntries `
    -Preserve @("$InstallDir\acme_ra.db", "$InstallDir\acme-ra.env", "$InstallDir\logs")

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
if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) { $iisRole = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue }
if ($iisRole) { Write-Host "  IIS Web-Server role .......... $(if ($iisRole.Installed) { 'present' } else { 'MISSING (install IIS or pass -InstallPrereqs)' })" }
$haveWebAdmin = [bool](Get-Module -ListAvailable WebAdministration -ErrorAction SilentlyContinue)
Write-Host "  WebAdministration module ..... $(if ($haveWebAdmin) { 'present' } else { 'MISSING (Web-Scripting-Tools)' })"
Write-Host "  HttpPlatformHandler module .... $(if (Test-HttpPlatformHandler) { 'present' } else { 'MISSING (see -HttpPlatformHandlerMsi / iis.net)' })"
$haveRsat = [bool](Get-Command Test-ADServiceAccount -ErrorAction SilentlyContinue)
Write-Host "  RSAT AD PowerShell ........... $(if ($haveRsat) { 'present' } else { 'absent (gMSA test will be skipped)' })"
Write-Host ""

# --- Confirm the gMSA is installed here (best-effort; the SID resolved above) -
# Strip the domain for Test-ADServiceAccount (it wants the SAM without DOMAIN\).
$gmsaSam = ($GmsaAccount -replace ".*\\", "") -replace '\$$', ""
if (Get-Command Test-ADServiceAccount -ErrorAction SilentlyContinue) {
    try {
        if (Test-ADServiceAccount -Identity $gmsaSam) {
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

# --- Locate a Python 3.12+ launcher (lifted from cert-watch; same VM concerns) -
# The Windows 'py' launcher can fail through PowerShell's & operator (Store
# stubs, arg mangling). Probe via cmd /c, then resolve the real python.exe.
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
    $tmp = Join-Path $env:TEMP "ra-py-probe.txt"
    & cmd /c "`"$Exe`" $argStr > `"$tmp`" 2>&1"
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
$launchers += @(
    @{ Exe = "py";      Args = @("-3.14") },
    @{ Exe = "py";      Args = @("-3.12") },
    @{ Exe = "py";      Args = @("-3") },
    @{ Exe = "python";  Args = @() },
    @{ Exe = "python3"; Args = @() }
)
$python = $null
$major = 0; $minor = 0
foreach ($l in $launchers) {
    $label = "$($l.Exe) $($l.Args -join `" `")"
    $cmd = Get-Command $l.Exe -ErrorAction SilentlyContinue
    if (-not $cmd) { Write-Host "  [skip] $label -- exe not found on PATH"; continue }
    if ($cmd.Source -and $cmd.Source -match "\\WindowsApps\\") {
        Write-Host "  [skip] $label -- Windows Store alias ($($cmd.Source)), unusable non-interactively"
        continue
    }
    $r = Invoke-PyProbe -Exe $l.Exe -Arguments ($l.Args + @("--version"))
    if ($r.ExitCode -ne 0) { Write-Host "  [fail] $label -- exit $($r.ExitCode)"; continue }
    $ver = ($r.Output -split "`n" | Where-Object { $_ -match "^Python\s+\d" } | Select-Object -First 1).Trim()
    if ($ver -match "Python\s+(\d+)\.(\d+)") {
        $mj = [int]$Matches[1]; $mn = [int]$Matches[2]
        if ($mj -ge 3 -and $mn -ge 12) {
            $resolved = ""
            try {
                $selfProbe = Invoke-PyProbe -Exe $l.Exe -Arguments ($l.Args + @("-c", "import sys; print(sys.executable)"))
                if ($selfProbe.ExitCode -eq 0) {
                    $candidate = ($selfProbe.Output -split "`n" | Select-Object -First 1).Trim()
                    if ($candidate -and (Test-Path $candidate -ErrorAction SilentlyContinue)) { $resolved = $candidate }
                }
            } catch { }
            $major = $mj; $minor = $mn
            if ($resolved) {
                Write-Host "  [ok]   $label -- $ver (resolved: $resolved)"
                $python = @{ Exe = $resolved; Args = @() }
            } else {
                Write-Host "  [ok]   $label -- $ver (using launcher directly)"
                $python = $l
            }
            break
        }
        Write-Host "  [fail] $label -- version $mj.$mn < 3.12"
    } else {
        Write-Host "  [fail] $label -- output not recognised: $ver"
    }
}
if (-not $python) { throw "Python 3.12+ not found. Install it (winget install Python.Python.3.14) and re-run." }

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
    # already lives somewhere non-administrators cannot write, and copying it
    # would add bytes to verify for no gain.
    $runtimePy = Join-Path $runtimeCurrent "python"
    if ($python.Exe -like "*\AppData\*" -or $python.Exe -like "*\WindowsApps\*") {
        Write-Host "  Python is user-scoped ($($python.Exe)); copying it into the runtime ..."
        $r = Invoke-PyProbe -Exe "py" -Arguments @("install", "--target=$runtimePy", "$major.$minor")
        if ($r.ExitCode -ne 0) {
            $pySrc = Split-Path $python.Exe
            if (Test-Path $pySrc) { Copy-Item -Path $pySrc -Destination $runtimePy -Recurse -Force }
        }
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
            if (Test-Path $vlPath) { attrib -H -S $vlPath 2>$null | Out-Null }
        }
        $python = @{ Exe = $runtimePyExe; Args = @() }
        Write-Host "  [ok]   runtime interpreter at $runtimePyExe"
    } else {
        Write-Host "  Using the machine-wide interpreter $($python.Exe) (not copied; not user-writable)"
    }

    # Clear hidden/system attrs on venv launchers (Python 3.14 marks them) so
    # venv creation does not fail with "Unable to copy ... venvlauncher.exe".
    $pyPrefix = Split-Path $python.Exe
    foreach ($vl in @("Lib\venv\scripts\nt\venvlauncher.exe", "Lib\venv\scripts\nt\venvwlauncher.exe")) {
        $vlPath = Join-Path $pyPrefix $vl
        if (Test-Path $vlPath) { attrib -H -S $vlPath 2>$null | Out-Null }
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
$lockFile = Join-Path $repoRoot "deploy\requirements.lock.txt"
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
    $buildLock = Join-Path $repoRoot "deploy\build-requirements.lock.txt"
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
    & $venvPy -m pip install --no-deps --no-build-isolation --upgrade $repoRoot
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
    # now is the runtime allowed to be considered live.
    Write-Host "Securing and proving the runtime at $RuntimeDir ..."
    Assert-NoReparsePoints -Path $RuntimeDir -Context 'runtime proof'
    Reset-TreeToInherited -Path $RuntimeDir
    Set-ObjectProtectedDacl -Path $RuntimeDir -Grants $runtimeGrants
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
Write-Host "Securing and proving the state tree at $InstallDir ..."
Assert-NoReparsePoints -Path $InstallDir -Context 'post-install ACL pass'
Reset-TreeToInherited -Path $InstallDir
Set-ObjectProtectedDacl -Path $InstallDir -Grants $stateGrants
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

# --- A preserved web.config must not keep launching a STATE-TREE interpreter ---
#
# Daybreak round 4, second half of the legacy-layout finding: on a half-done
# section-4 migration (old venv directories removed, web.config untouched) the
# install succeeds and stays green while the pool keeps launching whatever
# processPath names -- and a processPath under %ProgramData% points the worker
# at an interpreter it can MODIFY. The path is usually gone by then (503,
# fail-closed), but refuse to be silent about it: name the exact line to fix.
$siteWcPath = Join-Path $SitePath 'web.config'
if (Test-Path -LiteralPath $siteWcPath) {
    try {
        [xml]$siteWcXml = (Get-Content -LiteralPath $siteWcPath -Raw)
        $procPath = $siteWcXml.configuration.'system.webServer'.httpPlatform.processPath
        if ($procPath -and (Test-PathInsideTree -Path $procPath -Tree $InstallDir)) {
            Write-Host ""
            Write-Host ("[!!] $siteWcPath launches `"$procPath`", which is INSIDE the state tree $InstallDir.")
            Write-Host "     The gMSA holds Modify on that tree: a worker-writable interpreter is exactly what"
            Write-Host "     the code/state split removes. The app pool will keep using it until you change"
            Write-Host "     processPath to:"
            Write-Host "       $venv\Scripts\python.exe"
            Write-Host "     (docs/operator-requirements.md section 4, step 8.)"
        }
    } catch { }
}

# --- Grant the gMSA "Log on as a service" (best-effort) ----------------------
# An IIS app pool running as a gMSA needs SeServiceLogonRight, or the pool fails
# to start ("service did not respond in a timely fashion"). Best-effort via
# secedit; on failure we print the manual fix.
function Grant-ServiceLogonRight {
    param([string]$AccountSid)
    try {
        $tmpDir = Join-Path $env:TEMP ("ra-secpol-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
        $cfg = Join-Path $tmpDir "secpol.cfg"
        $db  = Join-Path $tmpDir "secpol.sdb"
        & secedit /export /cfg $cfg /areas USER_RIGHTS | Out-Null
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
        & secedit /import /db $db /cfg $cfg /areas USER_RIGHTS | Out-Null
        & secedit /configure /db $db /areas USER_RIGHTS | Out-Null
        Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        return $true
    } catch { return $false }
}

$script:iisActuallyConfigured = $false

if ($ConfigureIIS) {
    Write-Host ""
    Write-Host "Configuring IIS ..."
    if (-not (Get-Module -ListAvailable WebAdministration -ErrorAction SilentlyContinue)) {
        Write-Host "  [skip] WebAdministration module not available; skipping IIS config. See deploy\iis\README.md."
    } else {
        Import-Module WebAdministration

        if (-not (Test-Path $SitePath)) { New-Item -ItemType Directory -Force -Path $SitePath | Out-Null }

        $webConfigSrc = Join-Path $repoRoot "deploy\iis\web.config"
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
            $show = & netsh http show sslcert $BindingArgument 2>&1 | Out-String
            if ($show -match [regex]::Escape($Thumbprint)) { Write-Host "    Certificate already bound to $BindingArgument."; return }
            & netsh http delete sslcert $BindingArgument 2>$null | Out-Null
            $addOut = & netsh http add sslcert $BindingArgument certhash="$Thumbprint" appid="$AppId" certstorename=MY 2>&1
            if ($LASTEXITCODE -ne 0) { Write-Host ($addOut | Out-String); throw "Failed to bind TLS cert to $BindingArgument (netsh exit $LASTEXITCODE)." }
            $show = & netsh http show sslcert $BindingArgument 2>&1 | Out-String
            if ($show -notmatch [regex]::Escape($Thumbprint)) { throw "TLS binding verification failed for $BindingArgument." }
        }

        if ($TlsCertThumbprint) {
            Write-Host "  Binding TLS certificate $TlsCertThumbprint ..."
            $appId = "{B2C3D4E5-F6A7-8901-BCDE-F23456789012}"
            $ipport = "0.0.0.0:$Port"
            $hostPort = "$HostName`:$Port"
            if ($SharePort443) {
                Ensure-SslCertBinding -BindingArgument "hostnameport=$hostPort" -Thumbprint $TlsCertThumbprint -AppId $appId
                $catchallShow = & netsh http show sslcert ipport="$ipport" 2>&1 | Out-String
                if ($catchallShow -match [regex]::Escape($TlsCertThumbprint)) {
                    & netsh http delete sslcert ipport="$ipport" 2>$null | Out-Null
                } elseif ($catchallShow -match "Certificate Hash") {
                    Write-Warning "A catch-all $ipport bound to a DIFFERENT cert (a sibling tool?) WILL shadow this SNI binding. Convert that tool to SNI or remove its catch-all."
                }
                Write-Host "    TLS bound to hostnameport=$hostPort (SNI)."
            } else {
                Ensure-SslCertBinding -BindingArgument "ipport=$ipport" -Thumbprint $TlsCertThumbprint -AppId $appId
                if ($HostName) { & netsh http delete sslcert hostnameport="$hostPort" 2>$null | Out-Null }
                Write-Host "    TLS bound to $ipport (catch-all)."
            }
        } else {
            Write-Host "  [warn] No -TlsCertThumbprint. HTTPS binding exists but no certificate is assigned."
        }

        # /L: the site path is as predictable as the install root, and this
        # grant runs elevated -- it must not be redirectable by a link either
        # (2026-08-15 rescan-2 F2).
        $siteAclOut = & icacls.exe $SitePath /grant "${GmsaAccount}:(OI)(CI)R" /L 2>&1
        if (-not (Test-IcaclsOutputClean -ExitCode $LASTEXITCODE -Output $siteAclOut)) {
            throw ("Failed to grant the gMSA read access to $SitePath (exit $LASTEXITCODE): " +
                   (($siteAclOut | Out-String).Trim()))
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
