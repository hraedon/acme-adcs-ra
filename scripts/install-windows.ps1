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
    deployment model on the same VM). Creates the data directory, a virtualenv,
    and installs acme-adcs-ra into it. When -ConfigureIIS is passed, also
    creates/updates the IIS site, app pool, web.config, and TLS binding.

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
    Base dir for data (audit DB), venv, env file, logs, shared Python.
    Default: C:\ProgramData\acme-adcs-ra

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
    [string]$AppPool = "acme-adcs-ra",
    [switch]$ConfigureIIS,
    [string]$SitePath = "C:\inetpub\acme-adcs-ra",
    [string]$HostName = "",
    [switch]$SharePort443,
    [string]$TlsCertThumbprint = ""
)

$ErrorActionPreference = "Stop"

# --- Must be elevated (we write under ProgramData, set ACLs, configure IIS) ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run from an elevated (Administrator) PowerShell."
}

$repoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$venv     = Join-Path $InstallDir "venv"
$logs     = Join-Path $InstallDir "logs"
$envFile  = Join-Path $InstallDir "acme-ra.env"

# --- Validate the gMSA: resolve its SID and (best-effort) confirm it installed -
if ($GmsaAccount -notmatch "\$$") {
    Write-Host "[warn] -GmsaAccount `"$GmsaAccount`" has no trailing `$ -- gMSA SAM names end in `$. Continuing, but verify."
}
try {
    $gmsaSid = (New-Object System.Security.Principal.NTAccount($GmsaAccount)).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    Write-Host "Resolved gMSA $GmsaAccount -> $gmsaSid"
} catch {
    throw "Could not resolve gMSA account `"$GmsaAccount`". Use DOMAIN\gMSA-name$ form and confirm it exists."
}
# Strip the domain for Test-ADServiceAccount (it wants the SAM without DOMAIN\).
$gmsaSam = ($GmsaAccount -replace ".*\\", "") -replace "\$$", ""
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
    $argStr = ($Arguments | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
    $tmp = Join-Path $env:TEMP "ra-py-probe.txt"
    & cmd /c "`"$Exe`" $argStr > `"$tmp`" 2>&1"
    $exit = $LASTEXITCODE
    $out = ""
    if (Test-Path $tmp) { $out = (Get-Content $tmp -Raw); Remove-Item $tmp -Force }
    @{ ExitCode = $exit; Output = if ($out) { $out.Trim() } else { "" } }
}

$launchers = @()
$sharedCandidate = Join-Path $InstallDir "python\python.exe"
if (Test-Path $sharedCandidate) { $launchers += @{ Exe = $sharedCandidate; Args = @() } }
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

# --- Ensure Python is in a shared (non-user-profile) location ----------------
# The IIS app pool identity (the gMSA) cannot read a user profile, so a
# user-scoped interpreter must be copied to a shared dir under InstallDir.
$sharedPyDir = Join-Path $InstallDir "python"
$sharedPyExe = Join-Path $sharedPyDir "python.exe"
if ($python.Exe -like "*\AppData\*" -or $python.Exe -like "*\WindowsApps\*") {
    if (Test-Path $sharedPyExe) {
        Write-Host "Using existing shared Python at $sharedPyDir"
    } else {
        Write-Host "Python is user-scoped ($($python.Exe)); copying to shared location ..."
        $r = Invoke-PyProbe -Exe "py" -Arguments @("install", "--target=$sharedPyDir", "$major.$minor")
        if ($r.ExitCode -ne 0) {
            $pySrc = Split-Path $python.Exe
            if (Test-Path $pySrc) { Copy-Item -Path $pySrc -Destination $sharedPyDir -Recurse -Force }
        }
        if (-not (Test-Path $sharedPyExe)) {
            $nested = Get-ChildItem -Path $sharedPyDir -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($nested) { $sharedPyDir = Split-Path $nested.FullName; $sharedPyExe = $nested.FullName }
        }
        if (-not (Test-Path $sharedPyExe)) { throw "Failed to create shared Python at $sharedPyDir. Copy $($python.Exe) manually." }
        foreach ($vl in @("Lib\venv\scripts\nt\venvlauncher.exe", "Lib\venv\scripts\nt\venvwlauncher.exe")) {
            $vlPath = Join-Path $sharedPyDir $vl
            if (Test-Path $vlPath) { attrib -H -S $vlPath 2>$null | Out-Null }
        }
        Write-Host "  Shared Python ready at $sharedPyExe"
    }
    $python = @{ Exe = $sharedPyExe; Args = @() }
}

Write-Host "Creating directories under $InstallDir ..."
foreach ($d in @($InstallDir, $logs)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

# Stop the app pool (if any) BEFORE touching the venv so the worker releases
# locked files (python.exe, loaded .pyd). appcmd is always present with IIS.
$script:poolWasStopped = $false
$appcmdExe = "$env:windir\system32\inetsrv\appcmd.exe"
if (Test-Path $appcmdExe) {
    $poolExists = & $appcmdExe list apppool "$AppPool" 2>$null
    if ($poolExists) {
        Write-Host "Stopping app pool `"$AppPool`" to release files before install ..."
        & $appcmdExe stop apppool /apppool.name:"$AppPool" 2>$null | Out-Null
        Start-Sleep -Seconds 3
        $script:poolWasStopped = $true
    }
}

# Clear hidden/system attrs on venv launchers (Python 3.14 marks them) so venv
# creation does not fail with "Unable to copy ... venvlauncher.exe".
$pyPrefix = Split-Path $python.Exe
foreach ($vl in @("Lib\venv\scripts\nt\venvlauncher.exe", "Lib\venv\scripts\nt\venvwlauncher.exe")) {
    $vlPath = Join-Path $pyPrefix $vl
    if (Test-Path $vlPath) { attrib -H -S $vlPath 2>$null | Out-Null }
}

Write-Host "Creating virtualenv at $venv ..."
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
& $venvPy -m pip install --upgrade pip | Out-Null
# Installs from the source tree on this host. The Windows-only SSPI deps
# (requests-negotiate-sspi) resolve here; confirm wheels exist for this Python
# (3.14 may lack prebuilt wheels). To install a prebuilt wheel instead, replace
# $repoRoot with the .whl path.
& $venvPy -m pip install --upgrade $repoRoot
if ($LASTEXITCODE -ne 0) { throw "pip install of acme-adcs-ra failed (exit $LASTEXITCODE)." }
$installedVer = ((& $venvPy -m pip show acme-adcs-ra 2>$null | Select-String "^Version:") -replace "^Version:\s*", "").Trim()
Write-Host "  Installed acme-adcs-ra version: $installedVer"

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

# --- ACLs: the worker runs AS THE gMSA, so grant the gMSA (not a virtual acct) -
Write-Host "Securing $InstallDir (Administrators/SYSTEM full; gMSA modify) ..."
icacls $InstallDir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${GmsaAccount}:(OI)(CI)M" | Out-Null
# The env file: gMSA read-only (it should never rewrite its own secrets).
icacls $envFile /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" "${GmsaAccount}:R" | Out-Null
if (Test-Path $sharedPyDir) { icacls $sharedPyDir /grant "${GmsaAccount}:(OI)(CI)RX" | Out-Null }

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
            $defaultDir = "C:\ProgramData\acme-adcs-ra"
            $wcContent = Get-Content $webConfigDst -Raw
            if ($InstallDir -ne $defaultDir) { $wcContent = $wcContent.Replace($defaultDir, $InstallDir) }
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
        $bindingInfo = "*:443:$HostName"
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
            $ipport = "0.0.0.0:443"
            $hostPort = "$HostName`:443"
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

        icacls $SitePath /grant "${GmsaAccount}:(OI)(CI)R" | Out-Null

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
Write-Host "Done. acme-adcs-ra installed to $venv"
Write-Host "Data dir: $InstallDir   Audit DB: $InstallDir\acme_ra.db   Env file: $envFile"
if ($script:iisActuallyConfigured) {
    Write-Host "IIS site: $SitePath   App pool: $AppPool (as $GmsaAccount)"
    if ($HostName) { Write-Host "ACME directory: https://$HostName/acme/directory" }
}
Write-Host ""
Write-Host "Before first use:"
Write-Host "  1. Fill the EAB credential + SAN scope in $envFile (pinned to your ACME client)."
Write-Host "  2. Set ACME_RA_BASE_URL + ACME_RA_ADCS_* in $SitePath\web.config."
Write-Host "  3. RESTRICT the endpoint to the ACME client (threat-model pilot condition): add"
Write-Host "     <ipSecurity> to web.config (needs the IP-and-Domain-Restrictions role) or a"
Write-Host "     scoped firewall rule. Port 443 may be SNI-shared with cert-watch on this VM."
Write-Host "  4. Confirm requests-negotiate-sspi imported (Python $major.$minor): & `"$venvPy`" -c `"import requests_negotiate_sspi`""
