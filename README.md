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

The sibling projects ([cert-watch](../cert-watch/), [adcs-lens](../adcs-lens/))
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
- Endpoint TLS lifecycle ([cert-watch](../cert-watch/)'s job).
- CA posture / misconfiguration analysis ([adcs-lens](../adcs-lens/)'s job).
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

Built and unit-tested; **live-spike-gated.** The ACME server (RFC 8555 subset:
directory, EAB-gated accounts, orders, finalize, cert retrieval, revokeCert),
deterministic issuance policy, SIEM audit emission, and the real ADCS
**enrollment** leg (`/certsrv/` `certfnsh.asp` → issued cert + PKCS#7 chain,
passwordless gMSA/Negotiate) are implemented — see
[`docs/architecture.md`](docs/architecture.md),
[`docs/threat-model.md`](docs/threat-model.md) (note the **STUB GATE**), and
[`docs/certsrv-setup.md`](docs/certsrv-setup.md).

The single **live feasibility gate** remaining is the WI-1 lab spike
([`docs/spike-runbook.md`](docs/spike-runbook.md)): prove FastAPI-as-gMSA →
`/certsrv/` Negotiate → ADCS issuance with **requester = `gMSA-acme-ra$`** in the
CA database and the cert chaining to the existing root. **CA-side revocation is
a documented gap** — ADCS Web Enrollment exposes no revocation endpoint; the
mechanism + its gMSA privilege implication is an operator decision
(threat-model §E).
