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
- [ ] **`base_url` is the public hostname.** A mismatch fail-closes every
      legitimate JWS on day 1 (URL binding) — deployment prerequisite, not
      optional (§4.D).

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

- [ ] **Reverse-proxy rate limiting** per-account / per-IP (the RA has none in
      code; a flood here becomes a flood at the CA). Snippets + tuning guidance:
      `docs/operations.md` ## Network allowlist and reverse-proxy rate limiting.
- [ ] **Crons wired:** `DELETE /acme/admin/nonces` (nonce GC) and
      `DELETE /acme/admin/expired-orders` (order sweep, RFC 8555 §7.1.6).
      Install via `scripts/Register-MaintenanceTasks.ps1` (WI-013); see
      `docs/operations.md` ## Scheduled maintenance tasks.
- [ ] **Monitoring alerts on time-in-`processing` p99** (pilot condition);
      `GET /acme/admin/orders?status=processing` surfaces stuck orders. SLOs +
      alerting guidance: `docs/operations.md` ## Monitoring and SLOs.
- [ ] **Audit/SIEM sink live** — every issuance is emitted; consider a
      write-once/append-only sink for `audit_log` (§6). SIEM delivery monitoring:
      `docs/operations.md` ## Monitoring and SLOs.
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

- **WI-015 (placeholder — pending live re-proof against current `main`):**
  Re-run a full ACME round-trip (new-account → new-order → challenge →
  finalize) through the deployed RA on the lab against the exact commit to be
  piloted (the M-1/M-2/M-3 security fixes + Phase 3 operator-enablement
  artifacts landed after the 2026-06-24 proof). Exercise one issue, one
  policy-denial, and one out-of-band revocation (the latter two confirm the
  WI-010 audit shape + the reason-7 rejection). Append the result here:
  - [ ] §A re-cleared on the new commit (CI green on the deployed SHA; live
        re-issue + denial + revocation performed).
  - [ ] §F revocation runbook acknowledged (`docs/operations.md` ##
        Revocation runbook; `scripts/Revoke-Cert.ps1` lab-validated revoking a
        throwaway cert; reason 7 rejection confirmed at the RA surface).
  - [ ] The proven artifact == the shipped artifact (same SHA).
