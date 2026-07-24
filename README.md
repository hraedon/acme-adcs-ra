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

> **Project status:** **released at v1.5.0** (2026-07-23) — feature-complete for
> its charter. v1.5 adds **automated CA-side revocation** (template-scoped officer
> restriction; recommended two-identity topology + an opt-in single-identity
> `-LocalMode` deployment) and **self-enforced serverAuth EKU verification**, on
> top of the v1.0 issuance path. The automated revocation loop was **live-reproven
> end-to-end on the lab** (WI-028). Maintained deliberately, not passively:
> security reports (see `SECURITY.md`) and bug reports are welcome, but there is no
> response-time commitment.
>
> **Known limitations before a production pilot** (a **v1.6 hardening sweep** is
> planned — see [`plans/007-v1.6-hardening-sweep.md`](plans/007-v1.6-hardening-sweep.md)):
>
> - **Enrollment-side bound (Finding E-1) — remediated on `main` (WI-035).** The
>   enrollment gMSA was moved off the Domain Computers `Machine`-enroll path and
>   verified to enroll only `ACME-ServerAuth`; apply the equivalent change per your
>   estate. See [`docs/revocation-scope-validation.md`](docs/revocation-scope-validation.md).
> - **Recommended topology proof — partial.** The two-identity (dedicated-revoker)
>   design's *compromise-independence* property is now proven live (WI-036); the
>   final revoke-*by*-revoker round-trip is deferred behind a lab DC-time/KDS fix.
> - **PowerShell test coverage — added on `main` (WI-037):** a Pester pure-logic
>   suite (golden-bytes OfficerRights blob, action-string builder, reason/requester
>   logic) runs in CI. Deploy the whole `scripts/` dir including `scripts/lib/`.
> - **CI ≠ ADCS-verified:** cloud CI cannot reach a CA, so a green build does not
>   confirm the enrollment/revocation legs still work — those rest on periodic live
>   re-proofs. See [`docs/live-reproof-runbook.md`](docs/live-reproof-runbook.md)
>   and the validation log in the checklist.
>
> Deploying this is issuance-path infrastructure: work through
> [`docs/pre-pilot-checklist.md`](docs/pre-pilot-checklist.md) before running it
> anywhere that matters.

**At the production-pilot bar — Plans 001–006 complete (v1.5 on `main`).** The
full pipeline — ACME server (RFC 8555 subset: directory, EAB-gated accounts,
orders, finalize, cert retrieval, revokeCert, keyChange), deterministic
issuance policy with **post-issuance SAN + EKU verification**, **automated
CA-side revocation** (template-scoped officer; two-identity default + opt-in
single-identity), in-app per-account order rate limiting, SIEM audit, and the
real ADCS **enrollment** leg — issues
a real certificate: a deployed RA running as the gMSA behind IIS drives
`/certsrv/` and returns a **serverAuth-only** cert with the **SAN from the
CSR**, issued off the existing CA and **chaining to the existing root** (no new
intermediate). See [`docs/architecture.md`](docs/architecture.md),
[`docs/threat-model.md`](docs/threat-model.md),
[`docs/certsrv-setup.md`](docs/certsrv-setup.md), and the result in
[`docs/spike-runbook.md`](docs/spike-runbook.md). **WI-015** (the live lab
re-proof against the exact piloted commit) **PASSED** 2026-07-13 — all 12 cases
green; see [`docs/pre-pilot-checklist.md`](docs/pre-pilot-checklist.md).
Plan 003 (WI-016–WI-020) added in-app rate limiting, RA-vs-CA revocation
reconciliation (read-only), an EAB scope audit view, `keyChange`
(RFC 8555 §7.3.5), and locale-robust `certfnsh.asp` parsing — see
[`docs/operations.md`](docs/operations.md).

Authentication to `/certsrv/` is the ambient **gMSA** identity over SPNEGO with
**channel binding** (RFC 5929 `tls-server-end-point`), via the in-tree
`negotiate_auth.NegotiateAuth` over `pyspnego` — so it works against a `/certsrv/`
hardened with **EPA=Require**. Deploy with `scripts/install-windows.ps1` (IIS +
HttpPlatformHandler, app pool as the gMSA, on a configurable port).

**CA-side revocation is handled by a first-class out-of-band path** — ADCS Web
Enrollment exposes no revocation endpoint, so the mechanism decision (WI-010,
2026-06-30) was to keep the gMSA least-privileged and ship revocation as an
operator tool rather than widening its rights (threat-model §E). The
out-of-band path (`scripts/Revoke-Cert.ps1`, operator-run) is the shipped
mechanism and was lab-validated in WI-015; `revokeCert` records the revocation
in the RA store only and surfaces an `out_of_band_revocation` hint. Reason 7 is
rejected by both the RA and `Revoke-Cert.ps1` (RFC 5280 "unused"; `certutil`
rejects it) so an accepted reason can never silently break the out-of-band loop.

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
