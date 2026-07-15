# Security policy

## About this tool

acme-adcs-ra is an **ACME Registration Authority** for Active Directory
Certificate Services. It speaks ACME (RFC 8555) on the front, holds **no
signing key**, and forwards CSRs to the existing ADCS issuing CA over the Web
Enrollment surface as a passwordless gMSA.

Unlike the sibling projects (cert-watch, adcs-lens), this tool is **in the
certificate-issuance path** — it mints real certificates and holds a standing
ADCS enrollment identity. Its worst case is mis-issuance or leak of that
identity, not a wrong report. The read-only / air-gapped conventions that govern
the siblings **do not apply here**; the hard rules in `AGENTS.md` replace them.

## Reporting a vulnerability

Found a security issue in acme-adcs-ra itself (e.g. a SAN-scope bypass, an
EAB forgery, a signing-key introduction in the issuance path, or a revocation
CAS race that double-issues)?

Please report it **privately** rather than as a public issue: open a private
vulnerability report via GitHub's
[Security Advisories](https://github.com/hraedon/acme-adcs-ra/security/advisories/new)
(private vulnerability reporting is enabled on this repository).

Please include the affected version, a reproduction, and the expected vs. actual
behavior. The project is stable and passively maintained; reports are read and
acknowledged best-effort, with no committed response time.

## Scope

**In-scope:** vulnerabilities in acme-adcs-ra code that cause mis-issuance
(a cert with unauthorized SANs, a policy bypass, a signing-key introduction),
a revocation race that double-issues, an EAB forgery or scope-escalation, or
a crash that disrupts the issuance path.

**Out of scope (but welcome as regular issues):** ADCS CA misconfigurations
(those are operator-owned, documented in `docs/certsrv-setup.md`), and the
behavior of the ACME client (Certify the Web) or the ADCS CA itself.

## Security model summary

The full security model is in `docs/threat-model.md`. The load-bearing controls:

1. **No signing key, ever.** The RA never signs a certificate. An architecture
   test with positive and negative controls asserts no signing primitive is
   invoked in the issuance path.
2. **Passwordless to ADCS.** The RA authenticates as a gMSA via SPNEGO with
   channel binding (RFC 5929). No stored ADCS passwords.
3. **Server-authentication-only template.** One template, EKU scoped to
   server-auth only, subject/SAN from the CSR. This bounds a compromise to TLS-
   service spoofing, short of client-auth/PKINIT domain takeover.
4. **EAB + network allowlist + SAN scope.** The challenge is intentionally a
   no-op (enterprise trust model). EAB binds the ACME account to an enterprise-
   issued credential; the network allowlist bounds who can reach the endpoint;
   the SAN scope is the whole authorization surface.
5. **Post-issuance SAN verification (MED-1).** The issued cert's SANs are
   checked against the order's authorized set — a misconfigured template that
   appends an unauthorized SAN causes finalize to fail closed.
6. **Audit every issuance.** RA store + SIEM emission. No silent issuance.
7. **CA-side revocation is out-of-band.** The gMSA holds Enroll rights only,
   not CA-officer rights. Revocation at the CA is operator-run
   (`scripts/Revoke-Cert.ps1`), keeping the standing identity least-privileged.
