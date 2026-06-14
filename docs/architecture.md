# Architecture & security model

The design spine. Everything downstream (the ACME server, the enrollment leg, the
policy) derives from the decisions here.

## The RA model (why no intermediate, no signing key)

acme-adcs-ra is a **Registration Authority**, not a CA. It authenticates and
authorizes certificate requests, then **forwards the CSR to the existing ADCS
issuing CA**, which signs with its existing key and chain. The RA holds no
signing key. Consequences:

- **No new intermediate / no parallel trust.** Certs come off the chain already
  distributed to every domain-joined machine.
- **The blast radius of compromising the RA is bounded by its enrollment
  rights**, not by possession of a CA key. That is why the template scope (below)
  is the load-bearing control.

## Component flow

```
Certify the Web ──ACME (RFC 8555)──▶ acme-adcs-ra ──/certsrv/ POST (Negotiate)──▶ ADCS CA ──▶ cert
        │                  EAB-gated         │  runs as gMSA (passwordless)            signs
        └──────────────── returns the ADCS-issued cert + existing chain ◀────────────────────┘
```

## ACME server responsibilities (RFC 8555 subset)

The minimum to serve an enterprise client:
- `directory`, `newNonce`, `newAccount` (JWS account-key verification) **with EAB**,
  `newOrder`, authorizations + challenge handling, `finalize` (accept the CSR),
  `certificate` retrieval, `revokeCert`.
- Trust model is **enterprise identity, not public domain control**: EAB binds the
  ACME account to an enterprise-issued credential; the network allowlist bounds
  who can reach the endpoint. (Challenge handling still runs per the RFC; EAB is
  the *who-is-allowed* gate, not the challenge.)

## Enrollment leg (RA → ADCS)

- Submit the CSR to `/certsrv/certfnsh.asp` with **Negotiate/SSPI**, authenticated
  as the service's ambient **gMSA** identity — no stored password.
- The **certificate template** governs validity, EKU, key rules, and subject
  handling. The RA does not set validity; the template does.
- **Reference implementation (read, do not depend on):** acme2certifier's
  `mscertsrv` CA handler in `auth_method=gssapi` mode is a working model of this
  exact call. We reuse the *approach*, not the package.
- Transport modes A and C differ only in *where* `/certsrv/` lives and whether
  Kerberos delegation is required — see `certsrv-setup.md`. The ACME server side
  is identical across modes.

## Security model

- **Server-authentication-only template, subject/SAN from the CSR.** Scoping the
  EKU to server-auth bounds a compromise to spoofing internal TLS services and
  keeps it short of client-auth / PKINIT (domain takeover). SAN-supply on a
  server-auth-only template is a categorically smaller risk than on an
  any-purpose or client-auth template.
- **One hardened gMSA chokepoint.** ADFS/Exchange need SAN certs; *something* must
  hold SAN-capable enrollment. Concentrating it in one audited, single-purpose,
  tier-0-adjacent identity reduces attack surface vs. distributing the right to
  every app server — and yields a complete, monitorable issuance record.
  **Condition:** the RA host/identity must be hardened *beyond* the app servers it
  replaces, or it is merely a single high-value target.
- **The RA's gMSA + template is itself an ESC surface.** adcs-lens would analyze
  it. Keep Enroll rights minimal and the template free of requester-supplied
  client-auth EKUs.
- **Gating:** EAB credential pinned to the authorized ACME client (Certify the
  Web) + network/IP allowlist at the reverse proxy.

## Audit model

Every issuance is recorded in **two independent places**: the RA's own SQLite
store (request, account, SANs, template, outcome) and the **ADCS CA database**
(with requester = the gMSA). The RA **emits** each issuance to SIEM, reusing
cert-watch's export pattern — satisfying "an audit trail for every cert."

## Deliberate deviation from the family

The read-only / air-gapped / flag-don't-probe conventions that govern cert-watch
and adcs-lens **do not apply** — this system writes to the world (it causes
issuance) and holds a standing identity. The compensating disciplines are the
hard rules in `AGENTS.md`: no signing key, deterministic policy, passwordless,
least-privilege template, audit-everything.
