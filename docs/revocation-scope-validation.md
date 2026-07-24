# Revocation-scope & blast-radius validation (WI-030)

**Purpose.** Prove, with reproducible evidence, the blast radius of a compromise
of the RA's service accounts — the claim being: **the damage is bounded to
certificates of the `ACME-ServerAuth` template.** This is the officer-rights
counterpart to the `finalize.py` SAN/EKU tests; it makes the bound an *auditable,
reproduced* result rather than an assertion.

Validated live 2026-07-23 on the lab CA (placeholder `WORK-DOMAIN-CA`). All test
principals/certs were provisioned for the test and removed afterward; the CA was
returned to its original state (Security ACL, no `OfficerRights`, CRL republished).

## Two accounts, two different bounds

| account | what bounds it | result |
|---|---|---|
| **Revoker** (`gMSA-acme-revoker$`, a CA officer restricted to `ACME-ServerAuth`) | CA-enforced *Restrict Certificate Managers* (officer rights) | **Bounded to `ACME-ServerAuth` — PROVEN** |
| **Enrollment gMSA** (`gMSA-acme-ra$`, `Read`+`Enroll` on `ACME-ServerAuth`) | per-template enrollment ACLs | **NOT strictly bounded — see Finding E-1** |

## Method

A clean restricted-officer principal is provisioned exactly as WI-025 specifies:
CA-Security `ManageCertificates`, `OfficerRights` scoping it to `ACME-ServerAuth`
only (owner SID `S-1-5-32-544`, per-officer callback ACE mask `0x00010000`,
subject = Everyone `S-1-1-0`), and `Certificate Service DCOM Access`; it is a
member of **no** broader certificate-manager group. Each case runs
`certutil -revoke -config <CA> <serial> <reason>` **as that principal** (via a
scheduled task registered under it) and records the process exit / the
`ICertAdmin::RevokeCertificate` HRESULT.

**HRESULT interpretation:** `0x00000000` = permitted; `0x80094009`
`CERTSRV_E_RESTRICTEDOFFICER` = **template denial**; `0x80070005`
`E_ACCESSDENIED` = caller is not a certificate manager at all; `0x8007000d`
`ERROR_INVALID_DATA` = officer lacks `Certificate Service DCOM Access`;
`0x80070057` `ERROR_INVALID_PARAMETER` = malformed/absent `OfficerRights`
(management breaks — fail-closed — rather than silently unrestricting).

## Results — Revoker account (restricted officer)

### A. Template enforcement (blast radius across template classes)

| # | target template | expected | observed |
|---|---|---|---|
| A1 | `ACME-ServerAuth` (allowed) | permit | **`0x0` SUCCESS** |
| A2 | `Machine` | deny | **`0x80094009` RESTRICTEDOFFICER** |
| A3 | `DomainController` (highest-value) | deny | **`0x80094009` RESTRICTEDOFFICER** |
| A4 | `CAExchange` | deny | **`0x80094009` RESTRICTEDOFFICER** |

A compromised revoker can revoke **only** `ACME-ServerAuth` certs. It cannot touch
Domain Controller, Machine, or CA-Exchange certificates.

### A5. Causation control (before/after)

With `OfficerRights` **removed**, the *same* officer revoking the same `Machine`
cert → **`0x0` SUCCESS**. This proves the A2–A4 denials are caused by the
restriction, not by a broken/under-privileged account. (`OfficerRights` was
re-applied immediately after.)

### Escalation bound

Run as the revoker, `ICertAdmin2::GetMyRoles` returns **`Officer, Enroll`** — the
account holds **no `Administrator` (Manage CA) role**, and a Manage-CA operation
attempted as the revoker was blocked. It is also a plain domain principal, not a
local administrator on the CA. Therefore **a compromised revoker cannot edit CA
configuration or its own `OfficerRights` restriction** — the restriction cannot be
lifted from within the blast radius.

### Deployment constraints (both are load-bearing)

- **C-1 (union semantics).** Officer rights are evaluated across the caller's
  *entire* token. A restricted officer that is *also* a member of an unrestricted
  certificate-manager group can revoke anything (observed: adding the officer to
  such a group let it revoke a `Machine` cert). **The revoker must belong to no
  broader certificate-manager group.**
- **D-1 (DCOM access).** Without `Certificate Service DCOM Access` the revoke
  fails `ERROR_INVALID_DATA` — a visible failure, not a silent bypass.
- **D-2 (fail-closed).** A malformed/absent `OfficerRights` value causes officer
  operations to fail `ERROR_INVALID_PARAMETER` for everyone — the CA breaks
  management rather than silently reverting to unrestricted.

### Operation coverage

The `CERTSRV_E_RESTRICTEDOFFICER` denial occurs at the officer-rights **access
check**, which is evaluated against the *target certificate's template* and
precedes the specific revoke reason. It therefore gates every officer operation on
a disallowed-template cert (revoke, hold, remove-from-CRL/un-hold) identically;
the destructive reason codes need not be exercised against real certificates to
establish the bound.

## Results — Enrollment gMSA

### Finding E-1 — the enrollment gMSA is NOT strictly bounded to `ACME-ServerAuth`

Template enrollment ACLs (authoritative, read from AD):

| template | principals with `Enroll` |
|---|---|
| `ACME-ServerAuth` | Domain Admins, Enterprise Admins, **`gMSA-acme-ra$`** |
| `Machine` | Domain Admins, Enterprise Admins, **Domain Computers** |
| `DomainController` | Domain/Enterprise DCs, Domain Admins, Enterprise Admins |
| `WebServer` | Domain Admins, Enterprise Admins |

`gMSA-acme-ra$` has **`primaryGroupID = 515` (Domain Computers)** — a gMSA is a
computer-class object and is implicitly a member of Domain Computers. Because the
`Machine` template grants `Enroll` to **Domain Computers**, the enrollment gMSA
**holds enroll permission on the `Machine` template** (which issues
clientAuth-capable certificates), not only on `ACME-ServerAuth`.

**Implication.** The RA path is bounded (`WI-026` rejects any non-serverAuth
issuance), but a compromised gMSA that *bypasses the RA* and enrolls directly
against `/certsrv/` is **not** ACL-bounded to `ACME-ServerAuth` — it can request a
`Machine` certificate for its own identity. Whether issuance ultimately succeeds
depends on the `Machine` template's subject-construction rules (a live enrollment
attempt was not completed in this pass); the *permission* to attempt it exists.

**Recommended remediation (before pilot):** remove the enrollment gMSA from the
Domain Computers enrollment path — e.g. set its `primaryGroupID` to a group with
no template-enroll rights, or scope the `Machine`/other templates' enrollment ACLs
so Domain Computers membership does not confer them on this account — then re-run
this section to confirm the gMSA can enroll **only** `ACME-ServerAuth`.

### Finding E-1 — REMEDIATED + VERIFIED (2026-07-23, Plan 007 WI-035)

Remediated via the `primaryGroupID` approach: a dedicated global security group
(no certificate-template enroll rights) was created, the enrollment gMSA added to
it, and its `primaryGroupID` set to that group — which **removes the Domain
Computers membership** (changing `primaryGroupID` converts the old primary group
to an ordinary membership, which was then removed). Verified three ways:

1. **Template ACLs** — the `Machine` template grants Enroll to exactly
   {Domain Admins, Domain Computers, Enterprise Admins}; `ACME-ServerAuth` grants
   Enroll **explicitly** to the enrollment gMSA (so the change cannot break
   issuance).
2. **The gMSA's live Kerberos token** (read via a scheduled task running *as* the
   gMSA) — `Domain Computers` is **absent**; the gMSA is a member of none of the
   three `Machine`-enroll principals.
3. **Issuance regression** — a full ACME round-trip still issues a serverAuth-only
   cert after the change (no false-reject).

**Result:** the enrollment gMSA can now enroll **only** `ACME-ServerAuth`. The
"one template" bound holds for this account, closing the enrollment-side gap. The
change is reversible (`primaryGroupID` → 515, re-add to Domain Computers).

## Summary

- **Revoker compromise → bounded to `ACME-ServerAuth`.** Proven: allow on the one
  template, `CERTSRV_E_RESTRICTEDOFFICER` on all others (incl. DomainController),
  no self-escalation (Officer role only), fail-closed provisioning — subject to
  the union-membership and DCOM-access constraints.
- **Enrollment-gMSA compromise → bounded to `ACME-ServerAuth` (Finding E-1
  REMEDIATED, WI-035).** The gMSA's Domain Computers membership (which conferred
  `Machine`-template enroll) was removed via a `primaryGroupID` change; verified
  by template ACLs, the gMSA's live token (no Domain Computers), and an issuance
  regression pass. The "one template" bound now holds for this account too.
