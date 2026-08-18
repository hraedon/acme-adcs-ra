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

## Recorded decisions

Findings that independent reviews keep re-raising, with the disposition and the
reasoning, so the cycle can stop. These are **accepted postures**, not open
defects — but they are postures, so a reviewer who disagrees is arguing about a
decision rather than reporting a bug, and that is a useful thing to be clear
about.

### The `<ipSecurity>` allowlist ships commented out (accepted)

`deploy/iis/web.config` carries the `<ipSecurity>` block inside an XML comment,
and neither the installer nor startup requires an allowlist to exist. Raised
independently by the 2026-08-11 review and again by the 2026-08-17 Daybreak
review; the observation is accurate both times.

**Why it stays that way.** The correct addresses are per-deployment — the RA
cannot know the operator's ACME client addresses, and inventing a default would
be worse than the comment. `<ipSecurity>` also needs the *IP and Domain
Restrictions* role service, so a hard startup refusal would break first-install
and lab flows on a feature the operator may not have installed yet. The
allowlist is therefore documented as **required rather than recommended**, and
owned by the operator:

- `docs/operator-requirements.md` lists it as an operator responsibility and a
  stated pilot condition in the threat model;
- `docs/pre-pilot-checklist.md` requires it before pilot;
- `docs/operations.md` → *Network allowlist* carries the full snippet and the
  SNI-shared-443 caveat;
- the comment in `web.config` says in as many words that it is commented
  because the IPs are per-deployment, **not** because it is optional.

**Compensating controls in code**, so the allowlist is not the only thing
standing in front of an unauthenticated peer: an in-process token bucket applied
*before* the unauthenticated nonce write (default 20/s, burst 100, added
2026-08-11), and per-account order rate limiting (WI-016). These bound the
unauthenticated SQLite writer that made the allowlist load-bearing in the first
place. They do not replace it — a network allowlist keeps unknown peers away
from the endpoint entirely, which no in-app ceiling can do.

**What would change this.** Making the installer refuse without an allowlist is
a coherent proposal, and it is a change of posture rather than a defect fix. If
the deployment model narrows to "always installed by an operator who already has
the role service", that trade reverses. Until then: accepted, documented, and
operator-owned.
