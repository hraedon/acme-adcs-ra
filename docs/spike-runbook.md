# Spike runbook — WI-1, Mode A enrollment round-trip

The project's **feasibility gate**. Execute this on the **domain-joined Windows
RA host, running as the gMSA**, to prove the `/certsrv/` enrollment round-trip
against the lab CA. This is the one step whose physics is unproven; everything
else in the plan is ordinary engineering.

> Placeholders: `CA01` = issuing CA host; `WORK-DOMAIN.local` = AD domain;
> `gMSA-acme-ra$` = the RA's gMSA. Set the real values via env vars at run
> time — **never commit them.** (The lab CA's real FQDN, `ca01…`, is set
> via `ACME_RA_SPIKE_HOST` in the Scheduled Task below.)

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
4. **`/certsrv/` locked down** (IIS on the CA): Windows Authentication enabled, Anonymous disabled, HTTPS required, EPA = Accept, IP-restricted to the RA host.

## Step 1 — Python env on the RA host

The RA package's platform-gated deps (`requests`, `requests-negotiate-sspi`) are
pulled automatically on Windows. On the RA host, as a human admin:

```powershell
# Python 3.12+ on the RA host
py -m venv C:\acme-ra\venv
C:\acme-ra\venv\Scripts\python -m pip install -U pip
# Install the RA package from your private remote / a drop, editable:
C:\acme-ra\venv\Scripts\python -m pip install -e .      # pulls requests + requests-negotiate-sspi on win32
C:\acme-ra\venv\Scripts\python -m pip install cryptography   # already a dep; belt-and-braces for the spike
```

## Step 2 — run the spike **as the gMSA**

A gMSA cannot be `runas`'d interactively. Run it via a **Scheduled Task** whose
principal is the gMSA, triggered on demand. Register and run it (as a human
admin with permission to create tasks under the gMSA principal):

```powershell
$env:ACME_RA_SPIKE_HOST     = "ca01.work-domain.local"   # the REAL lab CA FQDN — do not commit
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
> exactly what `requests-negotiate-sspi`'s `HttpNegotiateAuth()` uses. No
> password is read or stored. This is the same posture the production RA
> service uses.

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
  automatically on win32 (`__main__.py`). Update `docs/threat-model.md`'s STUB
  GATE from "implemented, pending live-CA confirmation" to **"confirmed
  (ReqID …, requester …, date …)"**.
- **Revocation is NOT covered by this spike.** ADCS Web Enrollment exposes no
  revocation endpoint; `revokeCert` remains a documented gap pending the
  mechanism decision (`docs/threat-model.md` §E). See the runbook follow-up.

## Troubleshooting (from the spike docstring)

| Symptom | Cause / fix |
|---|---|
| 401 loop / auth fail | Not running as the gMSA (check the task principal), or the host can't reach a DC. |
| TLS error | ADCS uses a private CA; set `ACME_RA_SPIKE_CA_BUNDLE` to the CA chain. |
| "Certificate Pending" | Manager approval is still on for the template — turn it off (the RA is the gate). |
| "denied" / disposition | gMSA lacks Enroll on the template, or the SAN falls outside template policy. |
| Kerberos fails, NTLM ok | In IIS Windows Auth set EPA to "Accept" (not "Required"); then drop NTLM once Kerberos is proven. |
