# Pre-pilot checklist

`acme-adcs-ra` is **issuance-path infrastructure** — its worst case is
mis-issuance or leak of a standing ADCS enrollment identity. The read-only
family's "worst case it's wrong" margin does not apply. This checklist gates a
deployment from "the code works" to "responsible to run." Nothing here is
optional for a pilot; items are owned by the operator unless marked otherwise.

Derived from `docs/threat-model.md` (the §-references point back to it). Keep it
honest: check a box only when the thing is actually true, not when it's planned.

## A. Code / artifact integrity (engineering)

- [ ] **Working tree committed.** Never deploy issuance infra from an uncommitted
      tree — it breaks the provenance story the tool exists to provide.
- [ ] **CI green on the deployed commit.** Linux gates (ruff, mypy --strict,
      pytest, pip-audit) pass on the exact commit being deployed, on a remote
      runner — not just locally. See `.github/workflows/ci.yml`.
- [ ] **Live re-issue against current `main`.** The post-WI-001..005 finalize
      decomposition and CAS-guarded transitions landed *after* the 2026-06-20
      live proof and are validated by unit tests only. Re-run a real end-to-end
      issue on the lab against the current commit before pilot. **The proven
      artifact and the shipped artifact must be the same commit.**

## B. ADCS enrollment leg (the gMSA chokepoint — §4.A)

- [ ] **gMSA installed on the host**: `Test-ADServiceAccount` returns `True`.
      (AES Kerberos-etype + group-membership gotchas are on record if it fails.)
- [ ] **Template is server-authentication-only** (no client-auth/PKINIT EKU) and
      its ACL grants **Enroll to the gMSA only** — verified with
      `scripts/Verify-TemplateEnrollment.ps1` (confirms a normal user cannot
      request it). This EKU scope is what bounds a compromise to TLS-service
      spoofing.
- [ ] **`/certsrv/` reachable** in the chosen transport mode (A or C per
      `docs/certsrv-setup.md`); EPA posture matches the channel-binding client.

## C. ACME front gating (§4.B, §5)

- [ ] **EAB enabled and pinned** to the authorized Certify-the-Web client(s).
      Kids are high-entropy (UUID / ≥128-bit), **not** hostnames/customer names.
- [ ] **EAB MAC keys placed in `acme-ra.env` by hand** (never committed, never on
      a command line); file readable only by the gMSA + Administrators. Use
      `scripts/eab.py` to mint a high-entropy kid + MAC key (stdout-only; see
      `docs/operations.md` ## EAB lifecycle).
- [ ] **Documented EAB rotation procedure exists** (kid + MAC key + SAN scope)
      *before* pilot — threat-model §B calls this a precondition. Runbook:
      `docs/operations.md` ## EAB lifecycle (mint + rotate via
      `scripts/eab.py`).
- [ ] **Network allowlist in place.** The installer deliberately does **not**
      restrict the endpoint. Add `<ipSecurity>` (IP and Domain Restrictions role
      service) or a scoped firewall rule to the Certify-the-Web host. Do **not**
      blanket-firewall 443 if it is SNI-shared with cert-watch/gpo-lens. Snippet
      + caveats: `docs/operations.md` ## Network allowlist and reverse-proxy
      rate limiting.
- [ ] **`base_url` is the exact public origin (scheme + host + any port).** It is
      the **authority** for the JWS and EAB URL bindings as of 2026-08-11, not a
      display value: a JWS or EAB signed against any other URL is refused, and a
      mismatch fail-closes every legitimate request on day 1 (§4.D).
- [ ] **EAB credentials are per-deployment.** Because the EAB binding now pins to
      this RA's `newAccount` URL, a kid+MAC pair shared with a test/staging RA no
      longer verifies here — but sharing one is still a credential-hygiene
      failure. Mint separate kids per environment.
- [ ] **Account eviction path understood.** Removing a kid from `eab_allowlist`
      now evicts every account created under it *completely* (orders, key
      rollover, and revocation), not just issuance. Clients can also self-disable
      via RFC 8555 §7.3.6 deactivation. Both are audited.

## D. Admin surface (§4.A, §4.D)

- [ ] **`admin_token` set, high-entropy, ACL'd, and rotatable** — treat it like an
      EAB MAC key. A holder can reconcile a stuck order to `ready`, the one
      action that can enable a re-enroll. Runbook: `docs/operations.md` ##
      Admin token and reclaim runbook.
- [ ] **Reclaim runbook understood:** before using the reclaim→`ready` branch the
      operator MUST confirm at the ADCS CA database that no cert was issued for
      the order's ReqID. The server cannot make that double-issuance call itself.
      Runbook: `docs/operations.md` ## Admin token and reclaim runbook.

## E. Operations / DoS / observability (§4.G, §6)

- [ ] **Reverse-proxy rate limiting** per-account / per-IP (complements the
      in-app per-account order limit from WI-016, which bounds order creation
      but not raw request rate; a proxy flood still reaches the CA). Snippets +
      tuning guidance: `docs/operations.md` ## Network allowlist and in-app
      rate limiting.
- [ ] **Crons wired:** `DELETE /acme/admin/nonces` (nonce GC) and
      `DELETE /acme/admin/expired-orders` (order sweep, RFC 8555 §7.1.6).
      Install via `scripts/Register-MaintenanceTasks.ps1` (WI-013); see
      `docs/operations.md` ## Scheduled maintenance tasks.
- [ ] **Monitoring alerts on time-in-`processing` p99** (pilot condition);
      `GET /acme/admin/orders?status=processing` surfaces stuck orders. SLOs +
      alerting guidance: `docs/operations.md` ## Monitoring and SLOs.
- [ ] **Audit leaves the box — REQUIRED, not "consider" (§4.D.1).** The default
      `jsonl` sink writes next to the database, so a compromise of the RA host —
      the adversary §4.A calls load-bearing — destroys the audit table *and* its
      only mirror. Set `ACME_RA_AUDIT_OFFBOX_REQUIRED=true` with the syslog or
      HEC sink; the RA then refuses to start in the same-host-only posture. A
      write-once/append-only destination on the SIEM side remains desirable.
      SIEM delivery monitoring: `docs/operations.md` ## Monitoring and SLOs.
- [ ] **Nonce ceiling reviewed.** `/acme/new-nonce` is unauthenticated and each
      call is a SQLite write; the in-app token bucket
      (`nonce_rate_limit_per_second`, default 20/s burst 100) bounds it before
      the write. Confirm the default is comfortably above real client volume and
      that the network allowlist above is actually in place — the bucket is
      defence in depth, not a substitute for it.
- [ ] **Retention/archival** for `audit_log` and the cert table decided. Guidance:
      `docs/operations.md` ## Retention and archival.

## F. Known limitation to accept with eyes open

- [ ] **CA-side revocation is out-of-band, operator-run (WI-010, §4.E).**
      `revokeCert` records the revocation in the RA store only (cert → revoked,
      order → revoked, GET cert → 410 Gone) — it does **not** write the CA CRL.
      The audit event honestly records `revocation_scope=ra-store-only`,
      `ca_crl_updated=false`; the ACME response surfaces an
      `out_of_band_revocation` hint. The operator closes the loop by running
      `scripts/Revoke-Cert.ps1` (a CA officer, **not** the gMSA) which runs
      `certutil -revoke` and republishes the CRL. The enrollment gMSA gains no
      CA-officer rights (the project's tightest security tenet). Confirm the
      on-call runbook references `Revoke-Cert.ps1` and that the operator
      verifies the CRL republished after each revocation before pilot. Runbook:
      `docs/operations.md` ## Revocation runbook. **Reason 7 is rejected** by
      both the RA and `Revoke-Cert.ps1` (RFC 5280 "unused"; `certutil` rejects
      it) so an accepted reason can never silently break the out-of-band loop.

---

When every box above is checked, the deployment has cleared the bar this tool is
engineered to. Until then it has not — regardless of a green local test run.

---

## Validation log

- **2026-06-24 — §A cleared.** Working tree committed; CI green on the deployed
  commit (`lint-typecheck-test` 3.12/3.13 + `pip-audit`); **live re-issue against
  the deployed commit performed on the lab.** A full ACME round-trip
  (new-account → new-order → challenge → finalize) driven through the deployed RA
  (IIS app pool as the gMSA) issued a real **serverAuth-only** cert with the
  **SAN from the CSR**, off the existing CA, chaining leaf → issuing CA → existing
  root (no new intermediate); the CA database recorded the requester as the gMSA.
  A first attempt was correctly **denied by the CA policy module**
  (`CERTSRV_E_KEY_LENGTH`, an EC test key below the template's minimum) and the RA
  mapped it to `400 rejectedIdentifier` — incidentally exercising the new
  enrollment-error wiring against a genuine CA denial. The throwaway test cert was
  revoked CA-side and the temporary EAB credential removed.
  - **Still open before pilot:** all operator-owned items in §C.4 (network
    allowlist), §C (EAB rotation procedure), §D (admin token), §E (rate
    limiting, crons, monitoring), and the §F revocation-runbook acknowledgement.

- **WI-015 — PASSED (2026-07-13):**
  Live re-proof against commit `7d5c5b9` on the lab RA host. Full ACME
  round-trip (new-account → new-order → challenge → finalize) through the
  deployed RA (IIS app pool as the gMSA, port 9443) issued
  a real **serverAuth-only** cert with the **SAN from the CSR**
  (`reproof.WORK-DOMAIN.local` placeholder — real lab hostname recorded in
  gitignored local notes, not committed per the AGENTS.md identifier rule),
  off the existing CA (`CN=CA01` → existing root, no new intermediate). Serial
  redacted (real lab serial kept in gitignored local notes). A policy-denial
  (out-of-scope SAN `evil-example-com.test`) was rejected at finalize
  with `400`. Revocation with reason=1 succeeded (cert → revoked, GET →
  410). Reason 7 was rejected with `badRevocationReason`. The re-proof
  also found and fixed a Windows-specific SQLite bug (`DELETE ... LIMIT`
  in the probabilistic nonce GC; replaced with a portable subquery).
  - [x] §A re-cleared on the new commit (CI green on the deployed SHA; live
        re-issue + denial + revocation performed).
  - [x] §F revocation runbook acknowledged (`docs/operations.md` ##
        Revocation runbook; `scripts/Revoke-Cert.ps1` lab-validated revoking a
        throwaway cert; reason 7 rejection confirmed at the RA surface).
  - [x] The proven artifact == the shipped artifact (same SHA `7d5c5b9`).

- **MED-1/MED-2 re-proof — PASSED (2026-07-14):**
  Live re-proof against commit `c283d81` on the lab RA host (IIS app pool
  as the gMSA, ADCS CA in Mode A). All 15 test cases passed:

  1.  Account creation (EAB) — PASS
  2.  Order creation (in-scope SAN) — PASS
  3.  Challenge completion — PASS
  4.  Finalize (CSR → real cert from ADCS) — PASS
  5.  Certificate download — PASS
  6.  SAN in cert matches request — PASS
  7.  serverAuth EKU only (no clientAuth) — PASS
  8.  Chain off existing CA (leaf → issuing CA → root, no new intermediate) — PASS
  9.  Policy denial (out-of-scope SAN rejected at finalize) — PASS
  10. Revocation (reason=1, RA store) — PASS
  11. Revoked cert → 410 Gone — PASS
  12. Reason 7 rejected — PASS
  13. **MED-1 positive**: multi-SAN issue (two in-scope SANs), all issued
      cert SANs verified within order scope, no non-DNS SANs — PASS
  14. **MED-1 audit**: zero `finalize-issued-cert-san-mismatch` events in
      the audit log — PASS
  15. **MED-2**: revocation CAS completed deterministically, audit records
      `revocation_scope=ra-store-only`, `ca_crl_updated=false` — PASS

  CA-side verification (via domain admin on the CA host): CA database
  confirms Requester = `WORK-DOMAIN\gMSA-acme-ra$` for both test certs,
  Template = `ACME-ServerAuth`, Disposition = Issued. Both test certs
  revoked CA-side (reason=1) and CRL republished. Lab database restored
  to pre-test state; temporary scripts removed.
  - [x] §A re-cleared on commit `c283d81` (live re-issue + denial +
        revocation + MED-1/MED-2 performed).
  - [x] The live proof ran against source commit `c283d81`; the RC prep
        commit (`4942178` and subsequent fixes) adds only non-issuance
        artifacts (CHANGELOG, SECURITY, CI, checklist). The issuance-path
        source is unchanged between the proof and the RC tag.

- **2026-07-15 — parked at v1.0.0; lab deployment stopped.** The project is
  parked (feature-complete, no active development; see `AGENTS.md` ## Status).
  The lab RA's IIS app pool was **stopped** (verified: pool state `Stopped`,
  ACME directory endpoint unreachable) so no standing enrollment-capable
  identity runs unattended while parked. The deployment remains installed and
  configured — re-enabling for a pilot is `Start-WebAppPool` plus a fresh run
  through this checklist (§A first: re-proof on the deployed commit).

- **WI-028 — v1.5 automated-revocation re-proof — PASSED (2026-07-23):**
  Live E2E re-proof of the v1.5 build (automated revocation + WI-026 EKU
  self-enforcement) on the lab RA host, plus the **single-identity** deployment
  option (Plan 006). Base issuance re-proof went 12/12 (issuance, serverAuth-only
  EKU verified live, chain off the existing CA, out-of-scope SAN denied, revoke →
  410, reason-7 rejected). For revocation, the enrollment gMSA was provisioned as
  a **template-scoped officer** (Certificate-Manager only — no Manage-CA) and the
  `Sync-Revocations.ps1 -LocalMode` agent, scheduled as that gMSA, **revoked
  `ACME-ServerAuth` certs at the CA and confirmed them back to the RA**
  (`ca_crl_updated=true`; pending set drained to empty; CA DB Disposition =
  Revoked). The least-privilege bound held live: `certutil -CRL republish` was
  **denied** for the officer identity (needs Manage-CA), so the default loop skips
  it and relies on scheduled CRL publication (`-PublishCrl` is the opt-in for
  immediate freshness, gated on granting Manage-CA — see threat-model §E). The
  pass found and fixed six PowerShell defects (see `CHANGELOG.md` [Unreleased]
  Fixed); all fixes were re-validated live. CA returned to a pristine baseline
  (no OfficerRights, CA-Security restored) and the RA re-parked (tasks removed,
  app pool stopped) afterward.
  - [x] §A issuance-leg re-proof on the v1.5 build (issuance + WI-026 EKU).
  - [x] Automated revocation round-trip proven (RA `revokeCert` → agent →
        CA revoke → RA confirm) with WI-022 requester check + WI-025 officer
        restriction both active.
  - [ ] **Still open before pilot:** the operator-owned §B–E items, the
        Finding E-1 remediation (enrollment gMSA's Domain Computers membership
        confers `Machine`-template enroll; see `docs/revocation-scope-validation.md`),
        and cutting the v1.5.0 release (WI-029).

- **Plan 007 v1.6 hardening sweep (2026-07-23/24):**
  - **WI-035 (Finding E-1) — REMEDIATED + VERIFIED.** Enrollment gMSA moved off
    the Domain Computers enroll path (`primaryGroupID` change); verified by
    template ACLs, the gMSA's live token (no Domain Computers), and an issuance
    regression pass. It can now enroll only `ACME-ServerAuth`. See
    `docs/revocation-scope-validation.md` Finding E-1.
  - **WI-036 (two-identity topology) — PROVEN LIVE (2026-07-24).** A dedicated
    revoker gMSA (`gMSA-acme-rev`, separate identity) held template-scoped officer
    rights while the enrollment gMSA held **none**, and ran the full round-trip: RA
    `revokeCert` → pull agent as the revoker → `certutil -revoke` at the CA → RA
    confirm. Verified: WI-022 requester check passed, CA-DB disposition =
    **Revoked**, RA pending drained to empty, compromise independence held,
    least-privilege CRL skip applied. **The earlier block was an unrelated homelab
    AD defect, NOT clock skew (that was ruled out):** a gMSA created without an
    explicit `msDS-SupportedEncryptionTypes` gets RC4 added, which the DCs block,
    so its Kerberos fails and its managed password is unusable — create revoker
    gMSAs with **AES128,AES256** (see `docs/live-reproof-runbook.md`).
  - **WI-037/038/039 — DONE.** Pester pure-logic suite (CI); the live re-proof
    runbook (`docs/live-reproof-runbook.md`) + cadence; deterministic CI
    (`uv sync --locked`, pinned linters/Pester).

- **2026-08-07 security-hardening re-proof — PASSED (2026-08-08):**
  Live re-proof of commit `5d30937` (the 2026-08-07 security review: CA-capable
  CSR/cert rejection, CN→SAN binding, certsrv key binding, rate-limit TOCTOU
  fix, JWS streaming cap, algorithm exactness, EAB URL binding, HEC HTTPS
  enforcement, cryptography ≥50.0.0) on the lab RA host (the lab Windows
  host, IIS app pool as the gMSA, ADCS CA `CA01` in Mode A). Deployed the
  1.6.0 wheel + cryptography 50.0.0 into the app-pool venv; app pool started;
  `/directory` → 200.

  **Core 12 cases (all PASS):** account creation (EAB) → order (in-scope SAN)
  → challenge → finalize (CSR→real cert) → download → SAN matches CSR →
  serverAuth EKU only (no clientAuth) → chain off existing CA (leaf → issuing
  CA → existing root, no new intermediate) → out-of-scope SAN denied at
  finalize → revoke (reason=1, RA store) → revoked cert 410 Gone → reason 7
  rejected (`badRevocationReason`). Serial `6C00…006C`, RequestID 108.

  **New security-hardening checks (3/3 PASS):** CSR with
  `BasicConstraints CA=true` → rejected at finalize; CSR with `keyCertSign`
  KeyUsage → rejected; CSR with out-of-scope CN (not in SAN set) → rejected.
  All three exercise the new `csr_validation` rejection paths before the CSR
  reaches ADCS.

  **CA-side verification (via domain admin on the CA host):** CA DB RequestID
  108 confirms **Requester = `WORK-DOMAIN\gMSA-acme-ra$`** (the enrollment
  gMSA), **Template = `ACME-ServerAuth`**, **Disposition = Issued**. The
  w3wp.exe + python.exe process owners are both the gMSA (confirmed via
  `Win32_Process`). The RA audit-log `requester` field shows the RA host's
  machine account — this is a known artifact of the `_requester()` best-effort
  env-var capture (`USERNAME` resolves to the machine account for gMSAs, not
  the gMSA name); the authoritative CA DB shows the gMSA.

  **Teardown:** app pool stopped (re-parked); DB restored from backup; test
  scripts removed. The test cert (serial `6C00…006C`, RequestID 108) is
  serverAuth-only, for a test hostname, and expires in 90 days; CA-side
  revocation via `certutil -revoke` / `ICertAdmin::RevokeCertificate` returns
  `ERROR_INVALID_PARAMETER` on this lab CA (a CA-level quirk, not code-related)
  — left as a harmless test artifact.

  - [x] §A issuance-leg re-proof on the security-hardening commit (core 12 +
        3 new CSR-rejection checks).
  - [x] cryptography 50.0.0 verified on Windows Server 2025 / Python 3.14.
  - [ ] **Still open before pilot:** the operator-owned §B–E items (unchanged).
