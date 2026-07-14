# Spike runbook — WI-1, Mode A enrollment round-trip

> **RESULT: WI-1 PASSED (2026-06-20).** Proven on the lab **not** via the
> standalone `lab/spike_mode_a.py` script (now superseded — it still uses the old
> auth + strict parsing and would fail) but via the **deployed RA itself**: an IIS
> app pool running as the gMSA, driven by an ACME client, issued a real cert
> through `finalize` — serverAuth-only EKU, SAN from the CSR, off the existing CA,
> chaining to the existing root. The layered issues found are in the
> troubleshooting table; the durable fixes live in the RA (`negotiate_auth.py`,
> `enrollment.py`) and `scripts/install-windows.ps1`.

This runbook proves the `/certsrv/` enrollment round-trip against the CA. It was
the project's **feasibility gate** — the one step whose physics was unproven.

> Placeholders: `CA01` = issuing CA host; `WORK-DOMAIN.local` = AD domain;
> `gMSA-acme-ra$` = the RA's gMSA. Set real values via env / gitignored config at
> run time — **never commit them.**

## What runs

`lab/spike_mode_a.py` — a standalone script (outside the `src/` no-signing-key
scan scope) that generates a throwaway CSR + key, POSTs it to `/certsrv/
certfnsh.asp` over **Negotiate/SSPI** using the process's ambient identity,
fetches the issued cert + the CA chain, parses them, and **verifies the
requester in the CA database is the gMSA**. On success it prints `SUCCESS`.

## Prerequisites (do these first, via `docs/certsrv-setup.md` Mode A)

1. **Web Enrollment** installed on the CA (`Install-WindowsFeature ADCS-Web-Enrollment` + `Install-AdcsWebEnrollment`).
2. **`ACME-ServerAuth` template** published: Server Authentication EKU *only*; subject supplied in the request; **no manager approval**; `gMSA-acme-ra$` granted Read + Enroll only.
3. **gMSA installed on the RA host**: `Install-ADServiceAccount -Identity "gMSA-acme-ra"`; `Test-ADServiceAccount` green.
4. **`/certsrv/` locked down** (IIS on the CA): Windows Authentication enabled, Anonymous disabled, HTTPS required, **EPA = Require** (the RA channel-binds, so the hardened setting works), IP-restricted to the RA host.
5. **`/certsrv/` presents a proper serverAuth TLS cert** — NOT the CA's own certificate (a CA cert as a TLS leaf is rejected by the RA/OpenSSL as "unsuitable purpose"). Issue a server cert for the CA's FQDN and bind it; an **SNI binding** works without disturbing the catch-all. The RA verifies it against `ACME_RA_ADCS_CA_BUNDLE` = the enterprise **root** PEM (Python uses certifi, not the Windows store).

## Step 1 — Python env on the RA host

The RA package's platform-gated deps (`requests` base + `pyspnego` on win32) are
pulled automatically. **In practice the canonical deployment is
`scripts/install-windows.ps1`** (IIS + HttpPlatformHandler, app pool as the gMSA);
the manual venv below is just for an ad-hoc check. On the RA host, as an admin:

```powershell
# Python 3.12+ on the RA host
py -m venv C:\acme-ra\venv
C:\acme-ra\venv\Scripts\python -m pip install -U pip
# Install the RA package from your private remote / a drop, editable:
C:\acme-ra\venv\Scripts\python -m pip install -e .      # pulls requests + pyspnego on win32
C:\acme-ra\venv\Scripts\python -m pip install cryptography   # already a dep; belt-and-braces for the spike
```

## Step 2 — run the spike **as the gMSA**

A gMSA cannot be `runas`'d interactively. Run it via a **Scheduled Task** whose
principal is the gMSA, triggered on demand. Register and run it (as a human
admin with permission to create tasks under the gMSA principal):

```powershell
$env:ACME_RA_SPIKE_HOST     = "CA01.WORK-DOMAIN.local"   # your CA FQDN — real value via env, do not commit
$env:ACME_RA_SPIKE_TEMPLATE = "ACME-ServerAuth"
$env:ACME_RA_SPIKE_SAN      = "spike.acme-ra.test"
# If ADCS TLS uses a private CA the host doesn't trust, point at the chain:
# $env:ACME_RA_SPIKE_CA_BUNDLE = "C:\acme-ra\ca-chain.pem"
$env:ACME_RA_SPIKE_OUT      = "C:\acme-ra\spike-out"

$action   = New-ScheduledTaskAction  `
             -Execute "C:\acme-ra\venv\Scripts\python.exe" `
             -Argument "C:\acme-ra\acme-adcs-ra\lab\spike_mode_a.py"
$principal = New-ScheduledTaskPrincipal `
             -UserId "WORK-DOMAIN\gMSA-acme-ra$" -LogonType Passwordless
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable
Register-ScheduledTask -TaskName "acme-ra-spike" `
  -Action $action -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName "acme-ra-spike"

# Tail the output (the script logs to stderr; capture it):
Start-Sleep -Seconds 10
Get-Content "C:\acme-ra\spike-out\spike-run.log" -Wait -ErrorAction SilentlyContinue
# Or re-run capturing: (Start-ScheduledTask … then read the task's last result)
```

> A gMSA's negotiable identity is its **ambient** process identity — that is
> exactly what the in-tree `negotiate_auth.NegotiateAuth` (pyspnego, with channel
> binding) uses. No password is read or stored. This is the same posture the
> production RA app pool uses.

## Step 3 — read the result

**Pass** (the gate closes) when the script prints:

```
SUCCESS - enrollment round-trip complete.
```

plus a log line:

```
CA database confirms Requester = WORK-DOMAIN\gMSA-acme-ra$ (matches the gMSA)
```

and the printed CA chain subjects are the **existing** CA chain (no new
intermediate).

**If `Requester` is anything other than the gMSA**, Mode A is *not* behaving as
local enrollment — stop and investigate before relying on it. The script warns
loudly and falls back to printing the manual `certutil -view` command.

### Acceptance criteria (WI-1) — tick all

- [ ] A server-auth cert was issued from the CSR with the requested SAN.
- [ ] The cert **chains to the existing root** (the printed chain is the one already distributed).
- [ ] The CA database shows **Requester = `WORK-DOMAIN\gMSA-acme-ra$`** (auto-confirmed, or manually via `certutil -view`).
- [ ] `docs/certsrv-setup.md` Mode A is **corrected from reality** where this run differed.

## Step 4 — after the gate passes

- The production `CertsrvEnrollmentLeg` (`src/acme_adcs_ra/enrollment.py`) uses
  the **same** `certfnsh.asp` / `certnew.cer` / `certnew.p7b` payload as this
  spike. Nothing more needs to be filled for enrollment — the RA selects it
  automatically on win32 (`__main__.py`). The WI-1 enrollment gate has since
  been **confirmed** live (WI-015 re-proof, 2026-07-13, on `mvmcitest01`).
- **Revocation is out of scope for this spike** (WI-1 covered enrollment only).
  ADCS Web Enrollment exposes no revocation endpoint; the out-of-band path
  shipped in WI-010 (`scripts/Revoke-Cert.ps1`, operator-run, keeping the gMSA
  least-privileged — see `docs/threat-model.md` §E) and was lab-validated in
  WI-015 (reason=1 revoked; reason=7 rejected).

## Troubleshooting — the actual issues hit getting WI-1 to pass

| Symptom | Cause / fix |
|---|---|
| TLS verify "unable to get local issuer" | Python verifies against certifi, not the Windows store. Set `ACME_RA_ADCS_CA_BUNDLE` to the enterprise **root** PEM (export from the box's store). |
| TLS verify "unsuitable certificate purpose" | `/certsrv/` is serving the **CA's own cert** as its TLS leaf. Bind a real serverAuth cert for the CA FQDN (an SNI binding leaves the catch-all intact). |
| `SEC_E_INVALID_TOKEN` on auth | `/certsrv/` has **EPA=Require** and the client didn't channel-bind. The in-tree `NegotiateAuth` (pyspnego) binds via `tls-server-end-point`; confirm it's in use. |
| `'error' object is not subscriptable` | Still on `requests-negotiate-sspi` on Python 3.14 — it crashes logging the real SSPI error. Use the in-tree `NegotiateAuth`. |
| `template ... is not supported` (`0x80094800`) | `ACME-ServerAuth` isn't **published** on the CA (`Add-CATemplate`), even if it exists in AD. |
| `unexpected content-type ... text/html` / "no PKCS7 tag" | ADCS returns `certnew.cer` as `text/html` and `certnew.p7b` as PKCS7-in-CERTIFICATE-markers; the leg already tolerates this — extend it if a new variant appears. |
| "Certificate Pending" | Manager approval is still on for the template — turn it off (the RA is the gate). |
| 401 / "denied" disposition | Not running as the gMSA, or the gMSA lacks Enroll on the template, or the SAN is out of template policy. |
| CA/AD op fails `ERROR_NOT_AUTHENTICATED` over PS-remoting | Kerberos double-hop — run the op in a **scheduled task** (full token), not directly in the WinRM session. |
