# Hosting acme-adcs-ra on IIS (HttpPlatformHandler, app pool as a gMSA)

This mirrors cert-watch's Windows deployment (`../../../cert-watch/deploy/iis/`)
— same FastAPI/uvicorn-behind-IIS model on the same VM — with **one decisive
difference**: the IIS application pool runs **as the gMSA**, so the uvicorn
worker's ambient Kerberos identity is what authenticates to `/certsrv/`
(Negotiate/SSPI, passwordless). That is the whole reason this works without a
stored ADCS credential.

## Prerequisites

- **IIS** role + `Web-Mgmt-Console`, `Web-Scripting-Tools`, `Web-IP-Security`.
  `install-windows.ps1 -InstallPrereqs` installs these via `Install-WindowsFeature`.
- **HttpPlatformHandler** IIS module installed (Microsoft-signed). Not a Windows
  feature and not auto-downloaded (its download has been unreliable, and this is
  issuance-path infra) — install the v1.2 amd64 MSI by hand or pass
  `-HttpPlatformHandlerMsi <path>` to the installer.
- **Python 3.12+** on the host (the Windows-only `pyspnego` dep — used by the
  in-tree `negotiate_auth` for channel-bound Negotiate — must have a wheel for
  this Python; it ships abi3 wheels. This dep is the one part Linux CI never
  exercises). `-InstallPrereqs` installs Python via `winget` if missing.
- **The gMSA installed on this host**: `Install-ADServiceAccount` →
  `Test-ADServiceAccount` returns `True`. (See the project memory on the AES
  Kerberos-etype + group-membership gotchas if that fails.)

The installer prints a **prerequisite check** (IIS role, IIS module, Python,
RSAT) up front on every run, so you can see what is missing before it acts.

## Install

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
    -GmsaAccount "WORK-DOMAIN\gMSA-acme-ra$" -ConfigureIIS `
    -HostName "acme-ra.work-domain.local" -SharePort443 `
    -TlsCertThumbprint "<thumbprint in LocalMachine\My>"
```

`-SharePort443 -HostName` lets the RA share port 443 by SNI with cert-watch /
gpo-lens on this VM. Omit them for a single-site catch-all binding.

## What the installer sets up

- venv + `pip install` of the RA; shared (non-profile) Python so the gMSA can read it.
- `web.config` (no-clobber) — non-secret config only.
- Locked `acme-ra.env` (no-clobber) — **EAB MAC keys + SIEM HEC token live here**,
  readable only by the gMSA + Administrators. Fill the EAB credential before use.
- App pool: No Managed Code, AlwaysRunning, no idle/recycle, **identity = the gMSA**.
- Best-effort grant of **Log on as a service** to the gMSA (the usual "pool won't
  start" cause if missing — fix manually via `secpol.msc` if the script couldn't).
- TLS binding (SNI or catch-all), add-before-delete so HTTPS never drops.

## Two things the installer deliberately does NOT do

1. **Restrict the endpoint to the ACME client.** A threat-model pilot condition.
   Add `<ipSecurity>` to `web.config` (needs the *IP and Domain Restrictions*
   role service) scoped to the Certify the Web host, or a scoped firewall rule.
   Don't blanket-firewall port 443 — it may be SNI-shared with cert-watch.
2. **Take any secret on the command line.** EAB keys go into `acme-ra.env` by hand.

## Why a gMSA app pool (and not a scheduled task)

A scheduled-task uvicorn would work, but IIS/HttpPlatformHandler gives TLS
termination, the reverse-proxy/IP-allowlist layer the threat model requires, and
supervised process lifecycle — and an app pool is a first-class gMSA identity
host (no "Log on as a batch job" dance, no app-level TLS dependency). It also
reuses cert-watch's already-hardened installer instead of a parallel one.
