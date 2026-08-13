# acme-adcs-ra

An **ACME Registration Authority (RA)** for Active Directory Certificate Services.
It speaks ACME (RFC 8555) on the front, holds **no signing key of its own**, and
forwards each CSR to your existing ADCS issuing CA, which signs it with the
**existing chain**. Standard ACME clients — specifically an existing **Certify
the Web** install — can then auto-manage "traditional" certificates for
**ACME-blind apps (ADFS, Exchange, …)** off the trust you already run, with **no
new intermediate**.

## Why it exists

Modernization without rip-and-replace: ACME automation against the CA you
already own. The "you have to stand up a parallel CA / another intermediate"
problem people hit is an artifact of using ACME *CAs* (step-ca, Boulder, Caddy
internal). An **RA holds no signing key**, so it sidesteps that entirely — the
returned chain is your existing ADCS chain, already trusted by every
domain-joined machine.

## ⚠️ This is not a read-only tool — know the risk class

The sibling projects ([cert-watch](https://github.com/hraedon/cert-watch/), adcs-lens)
are read-only/observability — worst case they're *wrong*. **acme-adcs-ra is in
the certificate-issuance path.** It mints real certs and holds a standing ADCS
enrollment identity. Worst case it *mis-issues* or leaks that identity. It is
load-bearing production infrastructure and is engineered to a different, higher
bar. The read-only / air-gapped / "flag-don't-probe" family conventions **do not
apply here**; this project's hard rules (see `AGENTS.md`) replace them.

## Architecture at a glance

```
Certify the Web  ──ACME (RFC 8555, EAB-gated)──▶  acme-adcs-ra  (RA, runs as a gMSA)
                                                        │
                                          /certsrv/ POST, Negotiate/SSPI (passwordless)
                                                        ▼
                                                  ADCS issuing CA  ──signs──▶  existing chain
```

The RA never signs. It terminates ACME, authorizes the request, and submits the
CSR to ADCS via the **Web Enrollment** surface. Two transport deployments are
supported — **Mode A** (Web Enrollment on the CA itself) and **Mode C** (a
separate Web-Enrollment/CES host) — both documented in
[`docs/certsrv-setup.md`](docs/certsrv-setup.md).

## Scope

**In scope:**
- ACME server (RA role) — directory, accounts with **EAB** gating, orders,
  finalize, certificate retrieval.
- ADCS enrollment leg via `/certsrv/` with passwordless gMSA/Negotiate auth.
- Both transport modes (A and C) with setup runbooks.
- Audit emission for every issuance.

**Out of scope / non-goals:**
- **Being a CA / holding any signing key — ever.** If a change would make this
  sign certificates itself, it's the wrong change. This is the cardinal guardrail.
- Endpoint TLS lifecycle ([cert-watch](https://github.com/hraedon/cert-watch/)'s job).
- CA posture / misconfiguration analysis (adcs-lens's job).
- Public-CA / Let's Encrypt-style domain-control as the trust model — gating here
  is enterprise identity (EAB + network), not public DV.

## Design principles (derived for issuance infra)

- **No signing key, ever.** RA, not CA.
- **Deterministic issuance policy.** The decision to issue — which template, which
  SANs are permitted — is explicit policy code. No LLM anywhere in the issuance
  path.
- **Passwordless.** Authenticate to ADCS as a **gMSA** over Negotiate/SSPI; no
  stored ADCS credentials. Secrets (EAB keys) are never committed.
- **Least-privilege chokepoint.** One **server-authentication-only** template,
  subject/SAN supplied from the CSR. Concentrating SAN-capable enrollment in one
  hardened, audited identity beats distributing it across app servers — *and*
  buys auditability.
- **Audit every issuance.** Recorded in the RA's own store and the ADCS CA
  database; emitted to SIEM (reusing cert-watch's export pattern).
- **Stack:** FastAPI + SQLite (the family stack), `cryptography` for CSR/JWS.

## Boundary vs. the PKI family

cert-watch watches cert lifecycle; adcs-lens analyzes CA posture; **acme-adcs-ra
automates issuance off that CA**. Note that the RA's own enrollment identity is
itself an ESC surface — adcs-lens would analyze it. That coherence is also a
warning: get the template scope right (see `AGENTS.md`).

## Status

> **Released at v1.9.0 (2026-08-13).** Feature-complete for its charter and
> maintained deliberately rather than passively: security reports (see
> `SECURITY.md`) and bug reports are welcome, but there is no response-time
> commitment.

The full pipeline works and has been proven against a real CA: an RA running as
the gMSA behind IIS drives `/certsrv/` and returns a **serverAuth-only**
certificate with the **SAN from the CSR**, issued off the existing CA and
chaining to the **existing root** — no new intermediate.

### How it got here

| Release | What it added |
|---|---|
| **v1.0** | ACME server (RFC 8555 subset), deterministic issuance policy, the live ADCS enrollment leg |
| **v1.5–v1.6** | Automated CA-side revocation (two-identity default, opt-in single-identity), self-enforced serverAuth EKU verification, the enrollment-side bound (Finding E-1), a Pester suite, and the live re-proof runbook |
| **v1.7** | Security hardening — CA-capable CSR/cert rejection, CN→SAN binding, rate-limit TOCTOU, JWS streaming cap, algorithm exactness |
| **v1.8** | `base_url` URL binding, account eviction, serial re-padding to the CA database form |
| **v1.9** | The [2026-08-13 review](docs/security-review-2026-08-13.md) — ten findings, including separated revocation-confirm authority with optional CRL proof, certificate quarantine, and atomic issuance+audit |

Each release's live re-proof is recorded in the validation log in
[`docs/pre-pilot-checklist.md`](docs/pre-pilot-checklist.md).

### What "proven" means here, and what it does not

**Green CI is not ADCS verification.** Cloud CI cannot reach a CA, so a green
build proves the code and the operator scripts' *logic* — never that issuance or
CA-side revocation still work. Only the live re-proof
([`docs/live-reproof-runbook.md`](docs/live-reproof-runbook.md)) does, and it is
required at every release, before any pilot, after any change to the issuance
leg, and quarterly while deployed.

That distinction is not theoretical. The v1.9.0 re-proof found two defects Linux
CI **structurally could not see** — both Windows PowerShell 5.1 language
semantics that `pwsh` 7 on Linux silently differs on, one of them inside the
review's own fix. See the v1.9.0 entry in the validation log.

### Before you deploy

This is issuance-path infrastructure. Work through
[`docs/pre-pilot-checklist.md`](docs/pre-pilot-checklist.md) first. Five items
are load-bearing enough to call out here:

- **`base_url` is security configuration, not a display value.** Every JWS and
  EAB binding is validated against the URL derived from `ACME_RA_BASE_URL`, not
  the URL the request arrived on. Set it to the exact public origin — scheme,
  host, and port — or every legitimate request fail-closes on day 1. Mint
  **separate EAB kids per environment**; a kid shared with a staging RA no
  longer verifies against production.
- **An off-box audit sink is required, not recommended.** Set
  `ACME_RA_AUDIT_OFFBOX_REQUIRED=true` with syslog or HEC — the default `jsonl`
  sink dies with the host it is auditing. Since v1.9 the RA refuses to start if
  the configured sink cannot actually emit.
- **The network allowlist is required**, in front of the unauthenticated nonce
  endpoint.
- **`ACME_RA_REVOCATION_CONFIRM_TOKEN` is required** for the CA-side revocation
  loop, and the general admin token is deliberately refused there. Without it,
  serials revoke at the CA but stay on the RA's pending list.
- **Credentials have strength floors.** EAB MAC keys must decode to ≥ 32 bytes
  and admin/confirm tokens must be ≥ 32 characters; generate them with
  `python scripts/eab.py new`. Weak values refuse startup.

Apply the enrollment-side bound (Finding E-1) per your estate — move the
enrollment gMSA off the Domain Computers `Machine`-enroll path and verify it can
enroll only `ACME-ServerAuth`. See
[`docs/revocation-scope-validation.md`](docs/revocation-scope-validation.md).
If you use the two-identity topology, create the revoker gMSA with AES Kerberos
etypes (`-KerberosEncryptionType AES128,AES256`) — a gMSA created without them
gets RC4 added, which fails wherever DCs block RC4, and the symptom reads
misleadingly as a KDS or time-sync problem.

### How revocation works

ADCS Web Enrollment exposes no revocation endpoint, so revocation is a
first-class **out-of-band** path rather than a reason to widen the gMSA's rights
(WI-010, threat-model §E). `revokeCert` records the revocation in the RA store
and queues the serial; `scripts/Sync-Revocations.ps1`, running as a
template-scoped officer identity, revokes it at the CA and confirms back.
`scripts/Revoke-Cert.ps1` is the manual equivalent. Reason 7 is rejected by both
the RA and the scripts (RFC 5280 "unused"; `certutil` rejects it), so an accepted
reason can never silently break the loop.

Authentication to `/certsrv/` is the ambient **gMSA** identity over SPNEGO with
**channel binding** (RFC 5929 `tls-server-end-point`), via the in-tree
`negotiate_auth.NegotiateAuth` over `pyspnego` — so it works against a
`/certsrv/` hardened with **EPA=Require**. Deploy with
`scripts/install-windows.ps1` (IIS + HttpPlatformHandler, app pool as the gMSA,
on a configurable port).

## Installation

The RA runs on **Windows Server** behind **IIS** (HttpPlatformHandler), with the
application pool running **as a gMSA** — that ambient Kerberos identity is what
authenticates to `/certsrv/`. `scripts/install-windows.ps1` does the whole host
side; the CA side (Web Enrollment + the issuance template) is set up once per CA
via [`docs/certsrv-setup.md`](docs/certsrv-setup.md).

### Prerequisites

| Prerequisite | How to satisfy it |
|---|---|
| **IIS** role + `Web-Mgmt-Console`, `Web-Scripting-Tools`, `Web-IP-Security` | `install-windows.ps1 -InstallPrereqs` (uses `Install-WindowsFeature`) |
| **HttpPlatformHandler** (IIS module — third-party MSI) | Get the v1.2 amd64 MSI from [iis.net](https://www.iis.net/downloads/microsoft/httpplatformhandler); install by hand or pass `-HttpPlatformHandlerMsi <path>` (see note below) |
| **Python 3.12+** on the host | `install-windows.ps1 -InstallPrereqs` (uses `winget`), or `winget install Python.Python.3.12` |
| **A gMSA installed on this host** | `Install-ADServiceAccount`; `Test-ADServiceAccount` must return `True` |
| **CA: Web Enrollment + `ACME-ServerAuth` template** (server-auth-only EKU, subject from request, gMSA granted Enroll only) | one-time per CA — see [`docs/certsrv-setup.md`](docs/certsrv-setup.md) |

> **HttpPlatformHandler is never auto-downloaded.** It is a separate Microsoft
> module whose download has historically been unreliable, and this is
> issuance-path infrastructure — so the installer detects it and, if missing,
> installs it **only** from an MSI you point at (`-HttpPlatformHandlerMsi`),
> rather than fetching an unverified binary from the internet.

### Install

Run from an **elevated** PowerShell on the RA host, from the repo root:

```powershell
# 1. (optional) install the native prereqs first — IIS features + Python.
#    HttpPlatformHandler is installed too if you point at its MSI.
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
    -GmsaAccount "WORK-DOMAIN\gMSA-acme-ra$" -InstallPrereqs `
    -HttpPlatformHandlerMsi "C:\path\to\HttpPlatformHandler_amd64.msi"

# 2. install + configure IIS (app pool as the gMSA, TLS, site on :443 by SNI).
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
    -GmsaAccount "WORK-DOMAIN\gMSA-acme-ra$" -ConfigureIIS `
    -HostName "acme-ra.work-domain.local" -SharePort443 `
    -TlsCertThumbprint "<thumbprint in LocalMachine\My>"
```

Both can be combined in one invocation (`-InstallPrereqs -ConfigureIIS`). The
script always prints a **prerequisite check** up front (IIS role, IIS module,
Python, RSAT) so you see what is missing before it does anything. It is **safe to
re-run**: the secret env file and an existing `web.config` are never clobbered,
and the IIS steps are idempotent. `-SharePort443 -HostName` lets the RA share
port 443 by SNI with cert-watch / gpo-lens on the same VM; omit them for a
single-site catch-all binding. Full IIS detail is in
[`deploy/iis/README.md`](deploy/iis/README.md).

### After install — required before first use

1. **Fill the EAB credential + SAN scope** in `…\acme-ra.env` (laid down locked,
   readable by the gMSA + Administrators only), pinned to your ACME client.
2. **Set `ACME_RA_BASE_URL` + `ACME_RA_ADCS_*`** in the site's `web.config`
   (`BASE_URL` must be the *public* `https://host:port/` or every JWS is rejected
   on day 1).
3. **Restrict the endpoint to the ACME client** — add `<ipSecurity>` to
   `web.config` (needs `Web-IP-Security`, which `-InstallPrereqs` installs) or a
   scoped firewall rule. A threat-model pilot condition, deliberately not done
   for you. See [`docs/operations.md`](docs/operations.md) for the full network-
   allowlist snippet, reverse-proxy rate-limit guidance, EAB rotation runbook,
   scheduled-maintenance tasks, the admin-token + reclaim runbook,
   monitoring/SLOs, retention/archival, the revocation runbook, and
   backup/restore.

### Verify

```powershell
# ACME directory should return JSON:
Invoke-WebRequest https://acme-ra.work-domain.local/directory -UseBasicParsing
# The Negotiate stack imports (run as the venv python):
& C:\ProgramData\acme-adcs-ra\venv\Scripts\python.exe -c "import spnego; import acme_adcs_ra.negotiate_auth"
```

**Before going live, work through [`docs/pre-pilot-checklist.md`](docs/pre-pilot-checklist.md).**
Passing tests is necessary but not sufficient for issuance-path infra; the
checklist gates the operator-owned prerequisites (network allowlist, EAB
rotation, admin-token handling, monitoring, and a live re-issue against the
deployed commit).
