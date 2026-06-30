# Plan 002 — Pilot readiness

**Status:** Proposed 2026-06-30.
**Author:** Opus 4.8 (forward plan after the WI-001..009 hardening cycle)
**Strategic role:** WI-1 is proven end-to-end on the lab and the codebase is
mature (ACME server + EAB/policy + SIEM audit + channel-bound gMSA enrollment,
317+ tests, mypy --strict, CI green, public under MIT). The remaining distance
is **not more features — it is the gap between "the code works" and "responsible
to run."** This plan closes that gap: the three open engineering WIs, the one
honest headline limitation (CA-side revocation), and the operator-enablement
artifacts the pre-pilot checklist names as actual blockers. The north star of
this plan is a *checked* `docs/pre-pilot-checklist.md`.

## Ground truth at time of writing

> **Update (2026-06-30):** Phase 1 is complete — **WI-006, WI-007, WI-009 are
> closed**. WI-007 was additionally hardened after a live lab re-proof (the
> pending/denied/issued paths are now regression-tested against *real* captured
> `certfnsh.asp` bodies, and a pending→denied misclassification was fixed). The
> snapshot below is preserved as the point-in-time state when this plan was
> written; cross-reference the work-item store for current status. The remaining
> objective is **WI-010 (out-of-band manual revocation)** — see Phase 2.

- `main` is green (ruff, mypy --strict, pytest, pip-audit on 3.12/3.13). Last
  live E2E re-issue against the deployed commit was 2026-06-24 (checklist §A
  cleared). The finalize decomposition + RFC 1123 DNS validation landed after.
- Open engineering work items in the regista store (`acme_adcs_ra`):
  - **WI-006** — `negotiate_auth._server_cert_der()` does an out-of-band TLS
    probe for the CBT and assumes a single backend host; breaks under NLB/ARR
    (not applicable to Mode A, but undocumented as a hard assumption).
  - **WI-007** — `enrollment.submit_csr()` detects pending/denied via hardcoded
    English `certfnsh.asp` strings ("Certificate Pending", "Your Request Id is",
    "The disposition message is"); silently misreads a non-English ADCS locale.
  - **WI-009** — `newOrder` accepts malformed DNS identifiers; the client only
    learns of rejection at finalize (wasted round-trip).
- The headline limitation: **CA-side revocation is a `NotImplementedError`
  stub** (threat-model §E, §8). `revokeCert` flips the RA store only; ADCS Web
  Enrollment exposes no revocation endpoint.
- Pre-pilot checklist §C–§F are operator-owned and unchecked: EAB rotation
  procedure, network allowlist, admin token, rate limiting, crons, monitoring,
  SIEM sink, retention, revocation runbook.

## Principles this plan must hold

- **No signing key, ever. Least privilege.** Nothing here moves the gMSA toward
  CA-admin rights without an explicit, recorded security decision (see Phase 2).
- **Issuance path = security-critical.** Every change to the enrollment leg
  earns an adversarial review and, where it touches issuance behavior, a live
  lab re-proof — not just a green unit run.
- **Honest checklist.** A box is checked only when the thing is true. This plan
  produces artifacts that *let* the operator check boxes; it does not check them
  on the operator's behalf.

---

## Phase 1 — Issuance-path correctness hardening

Small, high-confidence engineering fixes that remove latent foot-guns before
real traffic. All three are synthetic/unit-testable; WI-007 also wants a live
re-proof since it touches the enrollment leg.

### WI-007 — Locale-independent disposition parsing
- Replace the English-string detection in `enrollment.submit_csr()` with a
  parse that does not depend on OS locale: prefer the structured signals
  `certfnsh.asp` returns regardless of language — the **disposition code**
  (`certnew.cer?ReqID=…&Enc=…` vs the pending/denied redirect), the `ReqID`
  query param, and HTTP status — over prose substrings. Where a string is
  unavoidable, match the invariant token (e.g. the `ReqID=` parameter) not the
  sentence around it.
- **AC:** a fixture set of real `certfnsh.asp` response bodies (issued /
  pending / denied) — including at least one non-English locale body — parses to
  the correct `EnrollmentResult` state. The English-string path is gone or is a
  last-resort fallback behind the structured check. Re-prove one live issue +
  one live denial on the lab (the WI-009 denial path already exercises this).

### WI-009 — `newOrder` DNS identifier pre-check
- Call the existing `validate_dns_name` at order creation in `routes/acme.py`,
  rejecting malformed identifiers with `400 rejectedIdentifier` before the
  client wastes a finalize round-trip. Reuse the function already gating the CSR
  path — no new validation logic.
- **AC:** `newOrder` with `*.WORK-DOMAIN.local` / `web..WORK-DOMAIN.local` is
  rejected at order creation with `rejectedIdentifier`; a valid FQDN still
  creates the order. Underscore-label behavior matches the CSR gate (documented,
  fail-closed).

### WI-006 — Document (don't silently assume) the single-backend CBT model
- The fix here is honesty, not topology support. Add a module-level docstring +
  a startup assertion / config note in `negotiate_auth.py` stating the CBT probe
  is correct only for a single stable backend (Mode A) and naming the failure
  mode under NLB/ARR. If a multi-backend deployment is ever chosen, this becomes
  a real WI; for now it is a documented boundary.
- **AC:** the single-host assumption is stated in code and in `docs/architecture.md`
  (transport modes section); a Mode-C/NLB deployment is explicitly marked
  unsupported-without-work. No behavior change.

---

## Phase 2 — The revocation gap (headline limitation)

This is the one place the project's worst case (a mis-issued cert that cannot be
killed in-band) lives. The honest engineering question is **whether to close it
in-band or to make the out-of-band path operationally first-class.**

**The tradeoff (for the user to decide — recorded, not assumed):**
- **In-band revocation** requires a mechanism ADCS Web Enrollment does not
  offer: `ICertAdmin2::RevokeCertificate` over DCOM, or `certutil -revoke`. Both
  need **CA Officer / "Issue and Manage Certificates"** rights on the gMSA —
  which *widens the standing identity past least-privilege* (the gMSA today
  holds only Enroll on one server-auth template). That is a real expansion of
  blast radius and runs against the project's tightest security tenet.
- **First-class out-of-band** keeps the gMSA least-privileged and ships the
  revocation capability as an *operator* tool: a `scripts/Revoke-Cert.ps1`
  (certutil-based, run by a CA admin, takes the RA's stored serial/ReqID), a
  runbook section, and an RA store transition that records "revocation requested
  / performed out-of-band" so the audit trail stays coherent.

**DECIDED 2026-06-30 (user): ship the out-of-band path first-class (preserve
least privilege); keep in-band as a documented, deferred option behind an
explicit future privilege decision.** The RA exists to *not* hold dangerous
standing power; a revocation capability that re-introduces it is a deliberate,
separate choice, not the default. WI-010 below is the path.

### WI-010 (new) — First-class out-of-band revocation
- `scripts/Revoke-Cert.ps1`: takes a serial or ReqID (which the RA already
  stores), confirms the cert at the CA, runs `certutil -revoke`, prints the
  outcome. Run by a CA admin, not the gMSA. Mirrors `Verify-TemplateEnrollment.ps1`
  in style and the no-work-domain-identifier rule.
- `revokeCert` in the RA: stop returning a bare `NotImplementedError`; record an
  explicit `revocation_requested` state in the store + audit event, and return
  an ACME response that tells the client the cert is marked revoked in the RA
  and names the out-of-band step. The audit log must not imply the CA CRL was
  written when it was not.
- `docs/threat-model.md` §E + the checklist §F item: update from "stub" to
  "out-of-band, operator-runbook'd," with the privilege rationale recorded.
- **AC:** the revocation runbook exists and is referenced from §F; the RA store
  + audit distinguish "RA-revoked" from "CA-CRL-revoked" honestly; the helper
  script is lab-validated revoking a throwaway cert.

---

## Phase 3 — Operator-enablement artifacts (turn the checklist into shippables)

The checklist §C–§F items are "operator-owned," but most are blocked on an
artifact that does not exist yet. This phase ships those artifacts so the
operator's job becomes *apply + verify*, not *design from scratch*.

### WI-011 (new) — EAB lifecycle tooling + runbook (§C)
- A documented EAB rotation procedure (kid + MAC key + SAN scope) and a small
  helper (`scripts/eab.py` or an `acme-ra` admin subcommand) to mint a
  high-entropy kid + MAC key and print the `acme-ra.env` lines to paste by hand
  (never logged, never committed). Threat-model §B names this a precondition.
- **AC:** `docs/operations.md` (new) has an EAB rotation runbook; the helper
  mints a ≥128-bit kid + MAC key; checklist §C EAB items are *checkable*.

### WI-012 (new) — Deployment hardening snippets (§C, §E)
- Ship copy-paste-ready, placeholder-only artifacts: an `<ipSecurity>` /
  IP-and-Domain-Restrictions snippet for the network allowlist (with the
  SNI-shared-443 caveat called out), and reverse-proxy rate-limit guidance
  per-account/per-IP. The installer still does not restrict the endpoint by
  default — this gives the operator the exact thing to add.
- **AC:** `docs/operations.md` carries the allowlist + rate-limit snippets with
  placeholders; checklist §C network-allowlist and §E rate-limit items are
  actionable from the doc alone.

### WI-013 (new) — Scheduled maintenance units (§E)
- Ship the two crons the checklist requires as ready-to-install units: nonce GC
  (`DELETE /acme/admin/nonces`) and expired-order sweep
  (`DELETE /acme/admin/expired-orders`, RFC 8555 §7.1.6) — as a Windows
  Scheduled Task XML/PS (matches the deployment host) plus a documented cadence.
- **AC:** the units install and fire against the deployed RA on the lab;
  checklist §E cron item is checkable.

### WI-014 (new) — Monitoring + retention guidance (§D, §E)
- `docs/operations.md`: how to alert on time-in-`processing` p99 (using
  `GET /acme/admin/orders?status=processing`), the admin-token handling rule
  (high-entropy, ACL'd, rotatable, treated like an EAB MAC key), the reclaim
  runbook (confirm at the CA DB that no cert issued for the ReqID before
  reclaim→`ready`), the SIEM sink expectation, and an `audit_log`/cert-table
  retention decision.
- **AC:** checklist §D + §E monitoring/retention/admin-token items are each
  backed by a doc section an operator can follow.

---

## Phase 4 — Pilot gate

### WI-015 (new) — Live re-proof against current `main` + checklist sign-off
- Re-run a full ACME round-trip (new-account → new-order → challenge → finalize)
  through the deployed RA on the lab against the **exact commit to be piloted**
  (Phases 1–2 will have changed the enrollment + revocation paths since the
  2026-06-24 proof). Exercise one issue, one policy-denial, and one out-of-band
  revocation. Append to the checklist validation log.
- **AC:** checklist §A re-cleared on the new commit; §F revocation runbook
  acknowledged; the proven artifact == the shipped artifact (same SHA).

---

## Sequencing & notes

- **Phase 1 is independent and cheap** — land it first (one PR, adversarial
  review, lab re-proof for WI-007).
- **Phase 2 needs the user's revocation-strategy decision** before WI-010 code;
  the recommendation above is the default if no other direction is given.
- **Phase 3 is doc/artifact-heavy**, parallelizable, low code risk — but each
  artifact must be lab-verifiable, not just plausible.
- **Phase 4 is the gate**: it is the difference between "we think it's pilot-able"
  and "the proven commit is the deployed commit."
- Out of scope for this plan: Mode C / NLB topology support (WI-006 only
  documents the boundary), further `routes/acme.py` decomposition (premature),
  any move toward in-band revocation absent an explicit privilege decision.
