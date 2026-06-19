# AGENTS.md

Conventions and quick reference for agents (and humans) working on acme-adcs-ra.

## What this is

An **ACME Registration Authority** for ADCS: speaks ACME (RFC 8555) on the front,
holds **no signing key**, forwards CSRs to the existing ADCS issuing CA over the
Web Enrollment (`/certsrv/`) surface as a passwordless **gMSA**. It exists so
Certify the Web can renew ADFS/Exchange-class certs off the existing chain with
no new intermediate. See `README.md` for the charter.

## Orient

1. **Read `docs/architecture.md`** — the design spine: the RA model, the ACME
   surfaces, the enrollment leg, the transport modes, the security model.
2. **Read `docs/certsrv-setup.md`** — how to configure the ADCS Web Enrollment
   surface in Mode A and Mode C. The lab spike validates this.
3. The first plan is `plans/001-spike-and-mvp.md`.

## Hard rules (issuance infra — these REPLACE the read-only family rules)

- **No signing key. Ever.** This is an RA. It must never hold a CA/private signing
  key or sign a certificate itself. If a change moves toward that, stop. An
  architecture test asserts no signing primitive is invoked in the issuance path.
- **In the issuance path — treat every issue-capable code path as
  security-critical.** This is not read-only software; there is no "it's just
  analysis" safety margin.
- **Passwordless to ADCS.** Authenticate as a **gMSA** via Negotiate/SSPI
  (`requests-negotiate-sspi` / `winkerberos`, ambient process identity). **No
  stored ADCS passwords.** EAB keys and any secrets are never committed.
- **Deterministic issuance policy.** Which template, which SANs are permitted, who
  may request — explicit policy code. **No LLM in the issuance decision path.**
- **Least privilege.** One **server-authentication-only** template; subject/SAN
  from the CSR; the gMSA holds minimal Enroll rights. This bounds a compromise to
  TLS-service spoofing, short of client-auth/PKINIT domain-takeover.
- **Gate the ACME front.** EAB (External Account Binding) pinned to the
  authorized client(s) + network allowlist.
- **Audit every issuance.** RA store + emit (SIEM). No silent issuance.
- **No work-domain identifiers in committed files.** Real CA names, hostnames,
  template names, EAB keys, and configs live in gitignored local config /
  `samples/` — placeholders (`CA01`, `WORK-DOMAIN.local`) in committed docs.

## Stack / build

FastAPI + SQLite + `cryptography`. The Windows SSPI enrollment dependency is
platform-gated (`sys_platform == 'win32'`) so CI on Linux is unaffected; the
enrollment leg is exercised via the lab/Windows host.

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/mypy src
```

## Transport modes

- **Mode A** — Web Enrollment (`/certsrv/`) installed on the CA itself. Simplest;
  no Kerberos delegation needed (enrollment is local to the CA). Matches the
  production CA's existing posture.
- **Mode C** — a separate Web-Enrollment or CES host fronting the CA. Keeps the CA
  role-pure, but the enrollment host enrolls *on behalf of* the requester, which
  requires **Kerberos constrained delegation** to the CA. See `docs/certsrv-setup.md`.

## Boundary

[cert-watch](../cert-watch/) = cert lifecycle; [adcs-lens](../adcs-lens/) = CA
posture; this = automated issuance off the CA. The RA's gMSA/template is itself an
ESC surface adcs-lens would flag — scope it tightly.

## Status

ACME server (RFC 8555 subset) + EAB/policy + SIEM audit + revokeCert are built
and unit-tested; the real ADCS **enrollment** leg is implemented (real
`certfnsh.asp` payload, pending the live WI-1 spike confirmation — see
`docs/spike-runbook.md` and the STUB GATE in `docs/threat-model.md`). **CA-side
revocation is a documented gap**: ADCS Web Enrollment exposes no revocation
endpoint, so `CertsrvRevocationLeg` is an honest `NotImplementedError` stub
pending the mechanism decision (threat-model §E). The live spike is still the
feasibility gate before a production pilot.
